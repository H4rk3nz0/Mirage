//! Async tunnel orchestrators: client `connect`, bridge `accept`.
//!
//! The session layer's state machines ([`HandshakeInitiator`],
//! [`HandshakeResponder`]) produce and consume fixed-size wire
//! messages. A real deployment drives those state machines over a
//! byte stream - a TCP socket, an in-memory duplex pair, or any
//! [`tokio::io::AsyncRead`] + [`tokio::io::AsyncWrite`] pipe.
//!
//! This module wires those pieces together:
//!
//! - [`connect`] (client side): writes message 1, reads message 2,
//!   writes message 3, returns a [`SessionStream`] ready for
//!   application traffic.
//! - [`accept`] (bridge side): reads message 1, writes message 2,
//!   reads message 3, returns a [`SessionStream`].
//!
//! Both functions operate on the exact-size handshake messages
//! defined in [`wire`](crate::wire) - no length prefixes are needed
//! on the wire during handshake because every message's length is
//! constant per spec §3.
//!
//! # Threat-model notes
//!
//! - **No retry.** Handshake failures drop the stream on the floor.
//!   A mid-handshake reconnect would use a different Noise ephemeral
//!   anyway, so retry belongs one layer above (e.g. in
//!   [`mirage_discovery::BridgePool`] selection).
//! - **Timeouts live at the caller.** These functions block until
//!   the peer sends their next message. Wrap in
//!   [`tokio::time::timeout`] in production code - an adversarial
//!   peer that never sends message 2 would otherwise hold the socket
//!   open indefinitely.
//! - **Token verification is caller-controlled.** The bridge side
//!   passes a [`TokenVerifier`] that owns its replay set and clock;
//!   this keeps replay / expiry policy at the daemon level where
//!   it's tunable.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::SessionError;
use crate::frames::SessionFramer;
use crate::handshake::{HandshakeInitiator, HandshakeResponder, TokenVerifier};
use crate::stream::SessionStream;
use crate::wire::{
    MSG_1_LEN, MSG_2_LEN, MSG_3_LEN_WITH_FS_TOKEN, MSG_3_LEN_WITH_TOKEN, MSG_TYPE_3, MSG_TYPE_3_FS,
};
use crate::Role;
use mirage_discovery::token::CapabilityToken;
use mirage_discovery::token_fs::FsCapabilityToken;

/// Max random padding appended to each framed handshake message (review-1
/// finding). The Mirage handshake's fixed 1221/1189/203-byte triplet was a
/// constant size signature that survived the outer carrier (a censor sees the
/// carrier's record/frame/chunk SIZES even when it cannot read the bytes). Each
/// message is now wrapped as `be_u16(total) || msg || pad`, where `pad` is a fresh
/// CSPRNG draw in `0..=HS_PAD_MAX`. With a ~1 KB spread the three messages'
/// on-wire size bands overlap instead of forming a fixed, distinctive triplet.
/// The padding is stripped by the reader and never reaches the Noise/decode
/// layer, so the message formats in [`crate::wire`] are unchanged.
const HS_PAD_MAX: usize = 1023;

/// Write `msg` as a length-prefixed, randomly-padded handshake frame + flush.
///
/// Public so alternative handshake drivers (e.g. the circuit runtime's manual
/// initiator) frame the wire identically to [`connect`]/[`accept`] - a raw,
/// unframed message would be misread as a length prefix by the framed reader.
pub async fn write_padded_handshake<S>(stream: &mut S, msg: &[u8]) -> Result<(), SessionError>
where
    S: AsyncWrite + Unpin,
{
    write_padded_handshake_floor(stream, msg, 0).await
}

/// Like [`write_padded_handshake`] but pads so the on-wire total lands in
/// `[max(msg.len(), floor), max(msg.len(), floor) + HS_PAD_MAX]`. Used for
/// message 3 with `floor = MSG_3_LEN_WITH_FS_TOKEN` (315): the legacy (203) and
/// forward-secure (315) forms would otherwise occupy DIFFERENT padded windows
/// whose tails ([203,314] vs [1227,1338]) partition the client population by
/// token type even through an encrypting outer transport's record sizes
/// (red-team #18/#20). Padding both up from the common 315 floor makes their
/// size distributions identical. Backward compatible: an old client still pads
/// legacy m3 from 203, and the reader accepts either.
pub async fn write_padded_handshake_floor<S>(
    stream: &mut S,
    msg: &[u8],
    floor: usize,
) -> Result<(), SessionError>
where
    S: AsyncWrite + Unpin,
{
    let base = msg.len().max(floor);
    let mut pb = [0u8; 2];
    let pad_extra = match getrandom::fill(&mut pb) {
        Ok(()) => (u16::from_le_bytes(pb) as usize) % (HS_PAD_MAX + 1),
        Err(_) => 0,
    };
    let total = base + pad_extra;
    let pad_len = total - msg.len();
    let total_u16 =
        u16::try_from(total).map_err(|_| SessionError::Wire("handshake frame too large"))?;
    let mut frame = Vec::with_capacity(2 + total);
    frame.extend_from_slice(&total_u16.to_be_bytes());
    frame.extend_from_slice(msg);
    if pad_len > 0 {
        let pad_start = frame.len();
        frame.resize(pad_start + pad_len, 0u8);
        if let Some(tail) = frame.get_mut(pad_start..) {
            let _ = getrandom::fill(tail);
        }
    }
    stream.write_all(&frame).await.map_err(SessionError::Io)?;
    stream.flush().await.map_err(SessionError::Io)
}

/// Read a length-prefixed, randomly-padded handshake frame and return exactly
/// the first `expected_msg_len` message bytes (padding stripped). The claimed
/// total is bounded to `expected_msg_len ..= expected_msg_len + HS_PAD_MAX` so a
/// peer cannot force an oversized allocation.
pub async fn read_padded_handshake<S>(
    stream: &mut S,
    expected_msg_len: usize,
) -> Result<Vec<u8>, SessionError>
where
    S: AsyncRead + Unpin,
{
    let mut lb = [0u8; 2];
    stream.read_exact(&mut lb).await.map_err(SessionError::Io)?;
    let total = u16::from_be_bytes(lb) as usize;
    if total < expected_msg_len || total > expected_msg_len + HS_PAD_MAX {
        return Err(SessionError::Wire("handshake frame length out of range"));
    }
    let mut buf = vec![0u8; total];
    stream
        .read_exact(&mut buf)
        .await
        .map_err(SessionError::Io)?;
    buf.truncate(expected_msg_len);
    Ok(buf)
}

/// Read a length-prefixed, randomly-padded **message-3** frame, discriminating
/// the legacy (203-byte) vs forward-secure (315-byte) form by the cleartext
/// message-type byte, and return exactly the message bytes (padding stripped).
///
/// Message 3 is the only handshake message with two conformant lengths, and
/// their padded windows overlap (`HS_PAD_MAX` ~1 KB), so [`read_padded_handshake`]
/// (which needs the length up front) cannot handle it. Here we bound the
/// allocation by the largest legal frame, read it, then pick 203 vs 315 from
/// `buf[2]` ([`MSG_TYPE_3`] / [`MSG_TYPE_3_FS`], the byte after the `MI` magic).
pub async fn read_padded_handshake_m3<S>(stream: &mut S) -> Result<Vec<u8>, SessionError>
where
    S: AsyncRead + Unpin,
{
    let mut lb = [0u8; 2];
    stream.read_exact(&mut lb).await.map_err(SessionError::Io)?;
    let total = u16::from_be_bytes(lb) as usize;
    // Bound allocation by the largest legal m3 frame (FS + max padding). The
    // lower bound is the smallest token-bearing form (legacy 203); a 67-byte
    // no-token m3 is refused here, exactly as the old fixed-203 reader refused
    // it (R21: a conformant bridge never accepts the no-token form).
    if !(MSG_3_LEN_WITH_TOKEN..=MSG_3_LEN_WITH_FS_TOKEN + HS_PAD_MAX).contains(&total) {
        return Err(SessionError::Wire("m3 frame length out of range"));
    }
    let mut buf = vec![0u8; total];
    stream
        .read_exact(&mut buf)
        .await
        .map_err(SessionError::Io)?;
    // Discriminate on the cleartext type byte (offset 2, after the MI magic).
    // total >= 203 guarantees buf[2] exists.
    let msg_len = match buf[2] {
        MSG_TYPE_3_FS => MSG_3_LEN_WITH_FS_TOKEN,
        MSG_TYPE_3 => MSG_3_LEN_WITH_TOKEN,
        _ => return Err(SessionError::Wire("m3 unknown msg_type")),
    };
    // The frame must be at least as long as the message it claims (so the
    // truncation below is sound). The UPPER bound is the common allocation
    // window checked above ([203, 315+HS_PAD_MAX]) - NOT a per-type ceiling -
    // because new clients pad legacy m3 up from the common 315 floor, so a
    // legacy frame legitimately reaches totals a 203-based ceiling would reject
    // (red-team #18/#20). Old clients (legacy padded from 203) still satisfy
    // `total >= 203`, preserving backward compatibility.
    if total < msg_len {
        return Err(SessionError::Wire("m3 frame shorter than its message type"));
    }
    buf.truncate(msg_len);
    Ok(buf)
}

/// Client-side tunnel orchestrator.
///
/// Drives the three-message handshake over `stream` and returns a
/// [`SessionStream`] consuming the same underlying stream for
/// post-handshake traffic.
///
/// `client_x25519_sk` - client's X25519 ephemeral secret. Caller
/// generates fresh per connection.
///
/// `bridge_x25519_pk` - bridge's X25519 static public key, from
/// whichever `Announcement` the client decided to dial.
///
/// `token` - bootstrap or session-scoped capability token; the
/// bridge's [`TokenVerifier`] must accept it.
pub async fn connect<S>(
    mut stream: S,
    client_x25519_sk: &[u8; 32],
    bridge_x25519_pk: &[u8; 32],
    token: &CapabilityToken,
) -> Result<SessionStream<S>, SessionError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut initiator = HandshakeInitiator::new(client_x25519_sk, bridge_x25519_pk, token)?;

    // Message 1 -> bridge (length-prefixed + randomly padded; see HS_PAD_MAX).
    let m1 = initiator.write_message_1()?;
    debug_assert_eq!(m1.len(), MSG_1_LEN);
    write_padded_handshake(&mut stream, &m1).await?;

    // Message 2 <- bridge.
    let m2 = read_padded_handshake(&mut stream, MSG_2_LEN).await?;
    initiator.read_message_2(&m2)?;

    // Message 3 -> bridge.
    let (m3, keys) = initiator.write_message_3()?;
    debug_assert_eq!(m3.len(), MSG_3_LEN_WITH_TOKEN);
    // Pad from the common 315 floor so legacy (203) and FS (315) msg-3 share one
    // size window - no token-type size oracle (red-team #18/#20).
    write_padded_handshake_floor(&mut stream, &m3, MSG_3_LEN_WITH_FS_TOKEN).await?;

    let framer = SessionFramer::from_session_keys(keys, Role::Initiator)?;
    Ok(SessionStream::new(framer, stream))
}

/// Client-side tunnel orchestrator presenting a **forward-secure** capability
/// token.
///
/// Identical to [`connect`] except it drives [`HandshakeInitiator::new_fs`] and
/// emits the 315-byte FS form of message 3 (a distinct cleartext type byte lets
/// the bridge's [`read_padded_handshake_m3`] strip padding to the right length).
/// The client selects this over [`connect`] purely on whether the invite it
/// dialed carried a forward-secure token.
pub async fn connect_fs<S>(
    mut stream: S,
    client_x25519_sk: &[u8; 32],
    bridge_x25519_pk: &[u8; 32],
    token: &FsCapabilityToken,
) -> Result<SessionStream<S>, SessionError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut initiator = HandshakeInitiator::new_fs(client_x25519_sk, bridge_x25519_pk, token)?;

    // Message 1 -> bridge.
    let m1 = initiator.write_message_1()?;
    debug_assert_eq!(m1.len(), MSG_1_LEN);
    write_padded_handshake(&mut stream, &m1).await?;

    // Message 2 <- bridge.
    let m2 = read_padded_handshake(&mut stream, MSG_2_LEN).await?;
    initiator.read_message_2(&m2)?;

    // Message 3 -> bridge (315-byte FS form).
    let (m3, keys) = initiator.write_message_3()?;
    debug_assert_eq!(m3.len(), MSG_3_LEN_WITH_FS_TOKEN);
    // Pad from the common 315 floor so legacy (203) and FS (315) msg-3 share one
    // size window - no token-type size oracle (red-team #18/#20).
    write_padded_handshake_floor(&mut stream, &m3, MSG_3_LEN_WITH_FS_TOKEN).await?;

    let framer = SessionFramer::from_session_keys(keys, Role::Initiator)?;
    Ok(SessionStream::new(framer, stream))
}

/// Bridge-side tunnel orchestrator.
///
/// Reads message 1, writes message 2, reads + verifies message 3,
/// returns a [`SessionStream`] over `stream` for post-handshake
/// traffic.
///
/// `bridge_x25519_sk` - bridge's X25519 static secret.
/// `bridge_ed25519_pk` - bridge's Ed25519 identity (named in tokens).
/// `operator_ed25519_pk` - trust anchor; every token must carry a
/// signature by this key.
/// `verifier` - caller-owned replay-set + clock; mutably borrowed
/// for the duration of this call.
pub async fn accept<S>(
    stream: S,
    bridge_x25519_sk: &[u8; 32],
    bridge_ed25519_pk: &[u8; 32],
    operator_ed25519_pk: &[u8; 32],
    verifier: &mut TokenVerifier<'_>,
) -> Result<SessionStream<S>, SessionError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    accept_with_peer_static(
        stream,
        bridge_x25519_sk,
        bridge_ed25519_pk,
        operator_ed25519_pk,
        verifier,
    )
    .await
    .map(|(session, _peer_static)| session)
}

/// Like [`accept`] but ALSO returns the authenticated initiator's X25519 static
/// public key (learned from the Noise-XX `s` token in message 3).
///
/// A bridge uses this to distinguish a RELAY leg (dialed by another bridge that
/// authenticates with its stable identity - see
/// `mirage_bridge::next_hop_link::SessionNextHopDialer`) from a direct-client
/// session, by matching the returned key against its relay-peer allowlist. The
/// key is confidential on the wire (encrypted inside Noise message 3), so this
/// leaks nothing to a passive observer.
pub async fn accept_with_peer_static<S>(
    mut stream: S,
    bridge_x25519_sk: &[u8; 32],
    bridge_ed25519_pk: &[u8; 32],
    operator_ed25519_pk: &[u8; 32],
    verifier: &mut TokenVerifier<'_>,
) -> Result<(SessionStream<S>, [u8; 32]), SessionError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut responder =
        HandshakeResponder::new(bridge_x25519_sk, bridge_ed25519_pk, operator_ed25519_pk)?;

    // Message 1 <- client (length-prefixed + randomly padded; padding stripped).
    let m1 = read_padded_handshake(&mut stream, MSG_1_LEN).await?;
    responder.read_message_1(&m1)?;

    // Message 2 -> client.
    let m2 = responder.write_message_2()?;
    debug_assert_eq!(m2.len(), MSG_2_LEN);
    write_padded_handshake(&mut stream, &m2).await?;

    // Message 3 <- client. Either the 203-byte legacy or 315-byte forward-
    // secure token form; the reader discriminates on the cleartext type byte
    // and strips padding accordingly. Conformant bridges refuse the 67-byte
    // no-token form (R21); read_message_3 then length-dispatches to the legacy
    // or FS verification path.
    let m3 = read_padded_handshake_m3(&mut stream).await?;
    let keys = responder.read_message_3(&m3, verifier)?;

    // The initiator's static public key, revealed (under encryption) in msg 3.
    let peer_static: [u8; 32] = keys
        .transport
        .get_remote_static()
        .and_then(|s| <[u8; 32]>::try_from(s).ok())
        .ok_or(SessionError::State("no remote static after handshake"))?;

    let framer = SessionFramer::from_session_keys(keys, Role::Responder)?;
    Ok((SessionStream::new(framer, stream), peer_static))
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;
    use mirage_crypto::ed25519_dalek::SigningKey;
    use mirage_crypto::x25519_dalek::{PublicKey, StaticSecret};
    use mirage_discovery::replay::ReplaySet;
    use mirage_discovery::token::{sign_token, CapabilityToken};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn rand_seed() -> [u8; 32] {
        let mut s = [0u8; 32];
        getrandom::fill(&mut s).unwrap();
        s
    }

    /// review-1: a framed handshake message round-trips exactly, its on-wire
    /// total varies across connections, and it always sits in the bounded
    /// `[msg_len, msg_len + HS_PAD_MAX]` window.
    #[tokio::test]
    async fn padded_handshake_roundtrips_and_size_varies() {
        use tokio::io::duplex;
        let msg = vec![0xABu8; MSG_1_LEN];
        let mut totals = std::collections::HashSet::new();
        for _ in 0..40 {
            let (mut a, mut b) = duplex(8192);
            let m = msg.clone();
            let writer = tokio::spawn(async move { write_padded_handshake(&mut a, &m).await });
            // Peek the length prefix, then read the frame back through the API.
            let mut lb = [0u8; 2];
            b.read_exact(&mut lb).await.unwrap();
            let total = u16::from_be_bytes(lb) as usize;
            totals.insert(total);
            assert!(
                (MSG_1_LEN..=MSG_1_LEN + HS_PAD_MAX).contains(&total),
                "total {total} out of bounds"
            );
            // Drain the padded body so the writer completes.
            let mut body = vec![0u8; total];
            b.read_exact(&mut body).await.unwrap();
            writer.await.unwrap().unwrap();
            assert_eq!(&body[..MSG_1_LEN], &msg[..], "message bytes recovered");
        }
        assert!(
            totals.len() > 1,
            "framed handshake size must vary across connections (got {totals:?})"
        );
    }

    /// The reader rejects a length prefix outside the padding window without
    /// allocating (DoS guard).
    #[tokio::test]
    async fn padded_handshake_rejects_out_of_range_length() {
        use tokio::io::duplex;
        // Claim a total far larger than msg + HS_PAD_MAX.
        let (mut a, mut b) = duplex(64);
        let bogus = (MSG_1_LEN + HS_PAD_MAX + 5000) as u16;
        tokio::spawn(async move {
            let _ = a.write_all(&bogus.to_be_bytes()).await;
        });
        let res = read_padded_handshake(&mut b, MSG_1_LEN).await;
        assert!(
            matches!(res, Err(SessionError::Wire(_))),
            "must reject oversize"
        );
    }

    struct Keys {
        client_x_sk: [u8; 32],
        bridge_x_sk: [u8; 32],
        bridge_x_pk: [u8; 32],
        bridge_ed_pk: [u8; 32],
        op_sk: SigningKey,
        op_pk: [u8; 32],
    }

    fn fresh_keys() -> Keys {
        let client_x_sk = StaticSecret::from(rand_seed()).to_bytes();
        let bsk = StaticSecret::from(rand_seed());
        let bridge_x_pk = *PublicKey::from(&bsk).as_bytes();
        let bridge_x_sk = bsk.to_bytes();
        let bridge_id_sk = SigningKey::from_bytes(&rand_seed());
        let bridge_ed_pk = bridge_id_sk.verifying_key().to_bytes();
        let op_sk = SigningKey::from_bytes(&rand_seed());
        let op_pk = op_sk.verifying_key().to_bytes();
        Keys {
            client_x_sk,
            bridge_x_sk,
            bridge_x_pk,
            bridge_ed_pk,
            op_sk,
            op_pk,
        }
    }

    fn issue_token(k: &Keys, now: u64) -> CapabilityToken {
        sign_token([0xCC; 32], k.bridge_ed_pk, now + 3600, &k.op_sk)
    }

    #[tokio::test]
    async fn connect_accept_full_roundtrip() {
        let k = fresh_keys();
        let now = 1_700_000_000;
        let token = issue_token(&k, now);

        let (a, b) = tokio::io::duplex(4096);

        let client_fut = tokio::spawn({
            let client_sk = k.client_x_sk;
            let bridge_pk = k.bridge_x_pk;
            let token = token.clone();
            async move {
                let mut s = connect(a, &client_sk, &bridge_pk, &token).await?;
                s.write_all(b"hello bridge").await.unwrap();
                s.flush().await.unwrap();
                let mut got = vec![0u8; b"hi client".len()];
                s.read_exact(&mut got).await.unwrap();
                assert_eq!(&got, b"hi client");
                Ok::<_, SessionError>(())
            }
        });

        let bridge_fut = tokio::spawn({
            let bridge_sk = k.bridge_x_sk;
            let bridge_ed = k.bridge_ed_pk;
            let op_pk = k.op_pk;
            async move {
                let mut rs = ReplaySet::new(16);
                let mut v = TokenVerifier::new(&mut rs, now);
                let mut s = accept(b, &bridge_sk, &bridge_ed, &op_pk, &mut v).await?;
                let mut got = vec![0u8; b"hello bridge".len()];
                s.read_exact(&mut got).await.unwrap();
                assert_eq!(&got, b"hello bridge");
                s.write_all(b"hi client").await.unwrap();
                s.flush().await.unwrap();
                Ok::<_, SessionError>(())
            }
        });

        client_fut.await.unwrap().unwrap();
        bridge_fut.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn accept_with_peer_static_returns_initiator_key() {
        // The relay-peer discriminator: the bridge learns the authenticated
        // initiator's X25519 static (encrypted in Noise msg 3), so it can match
        // it against a relay-peer allowlist.
        let k = fresh_keys();
        let now = 1_700_000_000;
        let token = issue_token(&k, now);
        let client_pk = *PublicKey::from(&StaticSecret::from(k.client_x_sk)).as_bytes();

        let (a, b) = tokio::io::duplex(4096);
        let client_fut = tokio::spawn({
            let client_sk = k.client_x_sk;
            let bridge_pk = k.bridge_x_pk;
            let token = token.clone();
            async move {
                let _s = connect(a, &client_sk, &bridge_pk, &token).await?;
                // Hold the session open until the bridge finishes accept.
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                Ok::<_, SessionError>(())
            }
        });
        let bridge_fut = tokio::spawn({
            let bridge_sk = k.bridge_x_sk;
            let bridge_ed = k.bridge_ed_pk;
            let op_pk = k.op_pk;
            async move {
                let mut rs = ReplaySet::new(16);
                let mut v = TokenVerifier::new(&mut rs, now);
                let (_s, peer) =
                    accept_with_peer_static(b, &bridge_sk, &bridge_ed, &op_pk, &mut v).await?;
                Ok::<[u8; 32], SessionError>(peer)
            }
        });
        let peer = bridge_fut.await.unwrap().unwrap();
        client_fut.await.unwrap().unwrap();
        assert_eq!(
            peer, client_pk,
            "accept must surface the initiator's static key"
        );
    }

    #[tokio::test]
    async fn m3_floor_padding_gives_legacy_and_fs_a_common_size_window() {
        use crate::wire::{MAGIC, MSG_TYPE_3, MSG_TYPE_3_FS};
        use tokio::io::duplex;
        // Craft minimal legacy (203) and FS (315) msg-3 wire forms.
        let mut legacy = vec![0u8; MSG_3_LEN_WITH_TOKEN];
        legacy[0..2].copy_from_slice(&MAGIC);
        legacy[2] = MSG_TYPE_3;
        let mut fs = vec![0u8; MSG_3_LEN_WITH_FS_TOKEN];
        fs[0..2].copy_from_slice(&MAGIC);
        fs[2] = MSG_TYPE_3_FS;

        let mut legacy_totals = std::collections::HashSet::new();
        let mut fs_totals = std::collections::HashSet::new();
        for _ in 0..64 {
            for (msg, totals) in [(&legacy, &mut legacy_totals), (&fs, &mut fs_totals)] {
                let (mut a, mut b) = duplex(4096);
                let m = msg.clone();
                let w = tokio::spawn(async move {
                    write_padded_handshake_floor(&mut a, &m, MSG_3_LEN_WITH_FS_TOKEN).await
                });
                let mut lb = [0u8; 2];
                b.read_exact(&mut lb).await.unwrap();
                let total = u16::from_be_bytes(lb) as usize;
                totals.insert(total);
                // Both forms MUST land in the SAME window - no size oracle.
                assert!(
                    (MSG_3_LEN_WITH_FS_TOKEN..=MSG_3_LEN_WITH_FS_TOKEN + HS_PAD_MAX)
                        .contains(&total),
                    "total {total} outside the common floor window"
                );
                let mut body = vec![0u8; total];
                b.read_exact(&mut body).await.unwrap();
                w.await.unwrap().unwrap();
                // The reader recovers the exact message and its type.
                let recovered = read_padded_handshake_m3(&mut &body_prefixed(&lb, &body)[..])
                    .await
                    .unwrap();
                assert_eq!(&recovered, msg, "reader must recover the original m3");
            }
        }
        // Distributions occupy the SAME window (every draw was asserted in
        // [315, 1338] above), so the tails can't partition the population by
        // token type. Both mins sit at/above the common 315 floor and both vary.
        let win = MSG_3_LEN_WITH_FS_TOKEN..=MSG_3_LEN_WITH_FS_TOKEN + HS_PAD_MAX;
        assert!(legacy_totals.iter().all(|t| win.contains(t)));
        assert!(fs_totals.iter().all(|t| win.contains(t)));
        assert!(*legacy_totals.iter().min().unwrap() >= MSG_3_LEN_WITH_FS_TOKEN);
        assert!(*fs_totals.iter().min().unwrap() >= MSG_3_LEN_WITH_FS_TOKEN);
        assert!(legacy_totals.len() > 1 && fs_totals.len() > 1, "sizes vary");
    }

    // Re-prefix a stripped (len, body) back into a single framed buffer so
    // read_padded_handshake_m3 can parse it in the test above.
    fn body_prefixed(len_prefix: &[u8; 2], body: &[u8]) -> Vec<u8> {
        let mut v = Vec::with_capacity(2 + body.len());
        v.extend_from_slice(len_prefix);
        v.extend_from_slice(body);
        v
    }

    fn issue_fs_token(k: &Keys, now: u64) -> FsCapabilityToken {
        use mirage_discovery::token_fs::EpochSigner;
        // Colocated: operator root certifies an epoch subkey that signs the token.
        let signer = EpochSigner::generate(&k.op_sk, 1, now + 86_400).unwrap();
        signer.sign_token([0xEE; 32], k.bridge_ed_pk, now + 3600)
    }

    /// The forward-secure path end-to-end THROUGH the padded-frame layer -
    /// exactly the seam the handshake-only FS unit tests bypass. Proves the
    /// 315-byte FS msg 3 survives write_padded_handshake -> read_padded_handshake_m3
    /// (type-byte discrimination) -> read_message_3's FS branch, and that the
    /// resulting session carries application data both ways.
    #[tokio::test]
    async fn fs_connect_accept_full_roundtrip() {
        let k = fresh_keys();
        let now = 1_700_000_000;
        let token = issue_fs_token(&k, now);

        let (a, b) = tokio::io::duplex(4096);

        let client_fut = tokio::spawn({
            let client_sk = k.client_x_sk;
            let bridge_pk = k.bridge_x_pk;
            let token = token.clone();
            async move {
                let mut s = connect_fs(a, &client_sk, &bridge_pk, &token).await?;
                s.write_all(b"hello bridge").await.unwrap();
                s.flush().await.unwrap();
                let mut got = vec![0u8; b"hi client".len()];
                s.read_exact(&mut got).await.unwrap();
                assert_eq!(&got, b"hi client");
                Ok::<_, SessionError>(())
            }
        });

        let bridge_fut = tokio::spawn({
            let bridge_sk = k.bridge_x_sk;
            let bridge_ed = k.bridge_ed_pk;
            let op_pk = k.op_pk;
            async move {
                let mut rs = ReplaySet::new(16);
                let mut v = TokenVerifier::new(&mut rs, now);
                let mut s = accept(b, &bridge_sk, &bridge_ed, &op_pk, &mut v).await?;
                // The bridge accepted the FS token via the pinned operator (root) key.
                assert_eq!(v.last_accepted_token_id, Some([0xEE; 32]));
                let mut got = vec![0u8; b"hello bridge".len()];
                s.read_exact(&mut got).await.unwrap();
                assert_eq!(&got, b"hello bridge");
                s.write_all(b"hi client").await.unwrap();
                s.flush().await.unwrap();
                Ok::<_, SessionError>(())
            }
        });

        client_fut.await.unwrap().unwrap();
        bridge_fut.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn wrong_bridge_pubkey_fails_handshake() {
        let k = fresh_keys();
        let now = 1_700_000_000;
        let token = issue_token(&k, now);

        // Client dials bridge_x_pk = something nonsense.
        let (a, b) = tokio::io::duplex(4096);
        let wrong_bridge_pk = [0x42u8; 32];

        let client_fut = tokio::spawn({
            let client_sk = k.client_x_sk;
            let token = token.clone();
            async move { connect(a, &client_sk, &wrong_bridge_pk, &token).await }
        });
        let bridge_fut = tokio::spawn({
            let bridge_sk = k.bridge_x_sk;
            let bridge_ed = k.bridge_ed_pk;
            let op_pk = k.op_pk;
            async move {
                let mut rs = ReplaySet::new(16);
                let mut v = TokenVerifier::new(&mut rs, now);
                accept(b, &bridge_sk, &bridge_ed, &op_pk, &mut v).await
            }
        });
        // At least one side rejects. Both sides consuming the duplex
        // makes the exact error somewhat timing-dependent; either an
        // I/O error (peer closed mid-handshake) or an auth-level error
        // is acceptable.
        let c = client_fut.await.unwrap();
        let b = bridge_fut.await.unwrap();
        assert!(
            c.is_err() || b.is_err(),
            "mismatched bridge pubkey must produce an error somewhere"
        );
    }

    #[tokio::test]
    async fn expired_token_is_rejected_by_bridge() {
        let k = fresh_keys();
        let now = 1_700_000_000;
        // Expired by 1 hour - comfortably beyond TOKEN_GRACE_SECONDS (60).
        let expired = sign_token([0xDD; 32], k.bridge_ed_pk, now - 3600, &k.op_sk);

        let (a, b) = tokio::io::duplex(4096);

        let client_fut = tokio::spawn({
            let client_sk = k.client_x_sk;
            let bridge_pk = k.bridge_x_pk;
            async move { connect(a, &client_sk, &bridge_pk, &expired).await }
        });
        let bridge_fut = tokio::spawn({
            let bridge_sk = k.bridge_x_sk;
            let bridge_ed = k.bridge_ed_pk;
            let op_pk = k.op_pk;
            async move {
                let mut rs = ReplaySet::new(16);
                let mut v = TokenVerifier::new(&mut rs, now);
                accept(b, &bridge_sk, &bridge_ed, &op_pk, &mut v).await
            }
        });
        // Bridge rejects on read_message_3; client sees EOF on the way
        // to completing or on the next read/write.
        let c = client_fut.await.unwrap();
        let b = bridge_fut.await.unwrap();
        assert!(b.is_err(), "bridge must reject expired token");
        // Client may or may not error depending on whether it's still
        // in the write phase; either way it produced an outcome.
        let _ = c;
    }

    #[tokio::test]
    async fn token_replayed_second_attempt_fails() {
        let k = fresh_keys();
        let now = 1_700_000_000;
        let token = issue_token(&k, now);

        let mut rs = ReplaySet::new(16);

        // First session: should succeed.
        let (a1, b1) = tokio::io::duplex(4096);
        let c_fut = tokio::spawn({
            let cs = k.client_x_sk;
            let bp = k.bridge_x_pk;
            let t = token.clone();
            async move { connect(a1, &cs, &bp, &t).await }
        });
        let b_fut = {
            let bs = k.bridge_x_sk;
            let be = k.bridge_ed_pk;
            let op = k.op_pk;
            let mut v = TokenVerifier::new(&mut rs, now);

            accept(b1, &bs, &be, &op, &mut v).await
        };
        c_fut.await.unwrap().unwrap();
        b_fut.unwrap();

        // Second session with the same token: bridge rejects on replay.
        let (a2, b2) = tokio::io::duplex(4096);
        let c_fut = tokio::spawn({
            let cs = k.client_x_sk;
            let bp = k.bridge_x_pk;
            let t = token.clone();
            async move { connect(a2, &cs, &bp, &t).await }
        });
        let b_fut = {
            let bs = k.bridge_x_sk;
            let be = k.bridge_ed_pk;
            let op = k.op_pk;
            let mut v = TokenVerifier::new(&mut rs, now);
            accept(b2, &bs, &be, &op, &mut v).await
        };
        assert!(b_fut.is_err(), "bridge must reject replayed token");
        let _ = c_fut.await;
    }
}
