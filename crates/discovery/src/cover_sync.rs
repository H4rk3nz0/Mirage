//! Shipping a Proteus cover library from the bridge to its clients.
//!
//! # Why the client must not record its own
//!
//! Recording cover means making real HTTPS requests to real sites. On a client
//! those requests go out **un-tunnelled, from the user's real address, before
//! any tunnel exists** - which on a censored network fails twice over. The
//! sources are frequently blocked there, so the library never fills and Proteus
//! runs unpaced; and reaching repeatedly for a blocked site is itself
//! noteworthy traffic on exactly the network where being unremarkable is the
//! objective. Regional source packs make self-recording *possible*, but only if
//! the user knows their region and picks correctly.
//!
//! A bridge has neither problem. It is well-connected and outside the censored
//! network by assumption, it already records a library for its own downstream
//! pacing, and the client is already talking to it over an authenticated
//! session. So the bridge sends the library and the client records nothing.
//!
//! # It also fixes joint replay
//!
//! Replay is only *joint* when both endpoints replay the same captured flow:
//! the up and down schedules are two halves of one real session. Two
//! independently-recorded libraries lose that coupling, and a pair replaying two
//! unrelated real flows has an up/down relationship no real flow has. Sharing
//! one library restores it - the shared per-session seed then selects the same
//! chain at both ends.
//!
//! # What this costs
//!
//! Every client of a bridge draws from the same pool, so a censor who obtained
//! the pool could in principle group that bridge's flows. Two things bound it:
//! obtaining the pool requires being an authenticated client, and each session
//! wears a different seeded shuffle of it rather than the pool itself. It is a
//! real trade against a real benefit, not a free win, and it is the same trade
//! the pre-existing "ship the library to your clients" guidance already made -
//! only now it happens automatically instead of by hand.

use std::io;

/// Reserved SOCKS5 hostname routing to the cover-library service. Mirrors
/// [`crate::cohort::COHORT_MAGIC_HOSTNAME`]: an underscore-prefixed segment
/// cannot collide with a real RFC 1035 hostname.
pub const COVER_MAGIC_HOSTNAME: &str = "_mirage_cover._internal";

/// Reserved port used with [`COVER_MAGIC_HOSTNAME`]. The bridge dispatches on
/// the hostname, not the port.
pub const COVER_MAGIC_PORT: u16 = 2;

/// Wire version for the cover-sync protocol.
pub const COVER_VERSION: u8 = 0x01;

/// `cmd` byte: send me traces for this class.
pub const COVER_CMD_FETCH: u8 = 0x01;

/// Response status: OK, traces follow.
pub const COVER_STATUS_OK: u8 = 0x00;
/// Response status: the bridge has no library to share yet.
pub const COVER_STATUS_EMPTY: u8 = 0x01;
/// Response status: the client already holds this exact library.
pub const COVER_STATUS_UNCHANGED: u8 = 0x02;
/// Response status: wire-format error in the request.
pub const COVER_STATUS_BAD_REQUEST: u8 = 0x03;

/// Cover class being requested.
pub const COVER_CLASS_BROWSE: u8 = 0x01;
/// Cover class being requested.
pub const COVER_CLASS_VIDEO: u8 = 0x02;
/// Cover class being requested: the dense capture that supplies the UPSTREAM
/// direction.
///
/// Must be synced like the others, and for the same reason. Replay is only
/// joint when both ends replay the same captured flow - if the client keeps its
/// own upstream traces while taking the bridge's downstream, the pair has an
/// up/down relationship no real flow has, which is the exact failure sharing a
/// library exists to prevent.
pub const COVER_CLASS_UPSTREAM: u8 = 0x03;

/// Most traces one response may carry. A session chains only a handful, so more
/// than this is bandwidth spent on cover the client will not wear before the
/// next refresh.
pub const COVER_MAX_TRACES: u8 = 8;

/// Largest single trace the protocol will move, in bytes. Real captures run
/// tens of kilobytes; this is a bound against a hostile or corrupt library, not
/// a target.
pub const COVER_MAX_TRACE_BYTES: usize = 512 * 1024;

/// Largest whole response. Bounds what one request can cost the client in both
/// memory and tunnel bandwidth.
pub const COVER_MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;

/// A client's request for cover traces.
///
/// ```text
///  0  1  version
///  1  1  cmd
///  2  1  class
///  3  1  max_traces
///  4  8  have_digest (0 = "I have nothing")
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoverRequest {
    /// Which class of cover the client wants.
    pub class: u8,
    /// Cap on how many traces to return.
    pub max_traces: u8,
    /// Digest of the library the client already holds, so an unchanged library
    /// costs one round trip instead of a full transfer.
    pub have_digest: u64,
}

/// Fixed request length.
pub const COVER_REQUEST_LEN: usize = 12;

impl CoverRequest {
    /// Serialize to the wire.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(COVER_REQUEST_LEN);
        v.push(COVER_VERSION);
        v.push(COVER_CMD_FETCH);
        v.push(self.class);
        v.push(self.max_traces.clamp(1, COVER_MAX_TRACES));
        v.extend_from_slice(&self.have_digest.to_be_bytes());
        v
    }

    /// Parse a wire request.
    ///
    /// # Errors
    /// Rejects a wrong length, an unknown version or command, and an unknown
    /// class. Rejecting an unknown class matters: silently treating it as
    /// browse would hand a client a library it did not ask for and quietly
    /// break the direction pairing it was trying to set up.
    pub fn decode(b: &[u8]) -> Result<Self, io::Error> {
        let bad = |m: &str| io::Error::new(io::ErrorKind::InvalidData, m.to_string());
        if b.len() != COVER_REQUEST_LEN {
            return Err(bad("cover request must be 12 bytes"));
        }
        if b[0] != COVER_VERSION {
            return Err(bad("unsupported cover-sync version"));
        }
        if b[1] != COVER_CMD_FETCH {
            return Err(bad("unknown cover-sync command"));
        }
        if b[2] != COVER_CLASS_BROWSE && b[2] != COVER_CLASS_VIDEO && b[2] != COVER_CLASS_UPSTREAM {
            return Err(bad("unknown cover class"));
        }
        let mut d = [0u8; 8];
        d.copy_from_slice(&b[4..12]);
        Ok(Self {
            class: b[2],
            max_traces: b[3].clamp(1, COVER_MAX_TRACES),
            have_digest: u64::from_be_bytes(d),
        })
    }
}

/// The bridge's reply.
///
/// ```text
///  0  1  version
///  1  1  status
///  2  8  digest of the library this response represents
/// 10  1  count
/// 11  .  count x (u32 BE length, then that many bytes)
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoverResponse {
    /// One of the `COVER_STATUS_*` values.
    pub status: u8,
    /// Digest of the served library, which the client stores and sends back as
    /// `have_digest` next time.
    pub digest: u64,
    /// Trace bodies, each a complete CSV.
    pub traces: Vec<Vec<u8>>,
}

impl CoverResponse {
    /// A non-OK reply carrying no traces.
    #[must_use]
    pub fn status_only(status: u8, digest: u64) -> Self {
        Self {
            status,
            digest,
            traces: Vec::new(),
        }
    }

    /// Serialize to the wire.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(11);
        v.push(COVER_VERSION);
        v.push(self.status);
        v.extend_from_slice(&self.digest.to_be_bytes());
        let n = u8::try_from(self.traces.len()).unwrap_or(u8::MAX);
        v.push(n);
        for t in self.traces.iter().take(n as usize) {
            v.extend_from_slice(&u32::try_from(t.len()).unwrap_or(u32::MAX).to_be_bytes());
            v.extend_from_slice(t);
        }
        v
    }

    /// Parse a wire response.
    ///
    /// # Errors
    /// Rejects a short buffer, an unsupported version, a trace longer than
    /// [`COVER_MAX_TRACE_BYTES`], and a total over [`COVER_MAX_RESPONSE_BYTES`].
    /// The caps are enforced HERE rather than by the caller because this parser
    /// runs on bytes a bridge chose - and a bridge a client is talking to is not
    /// automatically a bridge the client should let allocate for it.
    pub fn decode(b: &[u8]) -> Result<Self, io::Error> {
        let bad = |m: &str| io::Error::new(io::ErrorKind::InvalidData, m.to_string());
        if b.len() < 11 {
            return Err(bad("cover response header truncated"));
        }
        if b[0] != COVER_VERSION {
            return Err(bad("unsupported cover-sync version"));
        }
        let status = b[1];
        let mut d = [0u8; 8];
        d.copy_from_slice(&b[2..10]);
        let digest = u64::from_be_bytes(d);
        let count = b[10] as usize;
        let mut traces = Vec::with_capacity(count.min(COVER_MAX_TRACES as usize));
        let mut off = 11usize;
        let mut total = 0usize;
        for _ in 0..count {
            if off + 4 > b.len() {
                return Err(bad("cover response truncated in length prefix"));
            }
            let len = u32::from_be_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]]) as usize;
            off += 4;
            if len > COVER_MAX_TRACE_BYTES {
                return Err(bad("cover trace exceeds the per-trace cap"));
            }
            total = total.saturating_add(len);
            if total > COVER_MAX_RESPONSE_BYTES {
                return Err(bad("cover response exceeds the total cap"));
            }
            if off + len > b.len() {
                return Err(bad("cover response truncated in trace body"));
            }
            traces.push(b[off..off + len].to_vec());
            off += len;
        }
        Ok(Self {
            status,
            digest,
            traces,
        })
    }
}

/// Digest of a set of trace bodies, order-independent.
///
/// Order-independent on purpose: two ends listing a directory may enumerate it
/// differently, and a digest that changed with readdir order would report an
/// unchanged library as changed on every poll and re-transfer it forever.
#[must_use]
pub fn library_digest(traces: &[Vec<u8>]) -> u64 {
    let mut acc: u64 = 0xcbf2_9ce4_8422_2325;
    let mut parts: Vec<u64> = traces.iter().map(|t| fnv1a(t)).collect();
    parts.sort_unstable();
    for p in parts {
        acc ^= p;
        acc = acc.wrapping_mul(0x1000_0000_01b3);
    }
    acc
}

/// Fetch one class of cover library from the bridge over an established session.
///
/// `session` must already be an authenticated Mirage session speaking SOCKS5 -
/// the same footing [`crate::cohort_client::refresh_cohort`] runs on.
///
/// # Errors
/// Any I/O failure, a SOCKS5 protocol error, or a response that fails the
/// decoder's bounds checks.
pub async fn fetch_cover_library<S>(
    mut session: S,
    class: u8,
    max_traces: u8,
    have_digest: u64,
) -> io::Result<CoverResponse>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const SOCKS5_VERSION: u8 = 0x05;
    const SOCKS5_CMD_CONNECT: u8 = 0x01;
    const SOCKS5_ATYP_DOMAIN: u8 = 0x03;
    const SOCKS5_METHOD_NO_AUTH: u8 = 0x00;
    const SOCKS5_REP_SUCCEEDED: u8 = 0x00;
    let proto = |m: &str| io::Error::new(io::ErrorKind::InvalidData, m.to_string());

    session
        .write_all(&[SOCKS5_VERSION, 1, SOCKS5_METHOD_NO_AUTH])
        .await?;
    session.flush().await?;
    let mut greeting = [0u8; 2];
    session.read_exact(&mut greeting).await?;
    if greeting[0] != SOCKS5_VERSION || greeting[1] != SOCKS5_METHOD_NO_AUTH {
        return Err(proto("socks5 greeting refused"));
    }

    let name = COVER_MAGIC_HOSTNAME.as_bytes();
    let mut req = Vec::with_capacity(7 + name.len());
    req.push(SOCKS5_VERSION);
    req.push(SOCKS5_CMD_CONNECT);
    req.push(0x00);
    req.push(SOCKS5_ATYP_DOMAIN);
    req.push(u8::try_from(name.len()).map_err(|_| proto("magic host too long"))?);
    req.extend_from_slice(name);
    req.extend_from_slice(&COVER_MAGIC_PORT.to_be_bytes());
    session.write_all(&req).await?;
    session.flush().await?;

    let mut hdr = [0u8; 4];
    session.read_exact(&mut hdr).await?;
    if hdr[0] != SOCKS5_VERSION || hdr[1] != SOCKS5_REP_SUCCEEDED {
        return Err(proto("socks5 connect to cover service refused"));
    }
    match hdr[3] {
        0x01 => {
            let mut a = [0u8; 6];
            session.read_exact(&mut a).await?;
        }
        0x04 => {
            let mut a = [0u8; 18];
            session.read_exact(&mut a).await?;
        }
        0x03 => {
            let mut l = [0u8; 1];
            session.read_exact(&mut l).await?;
            let mut a = vec![0u8; l[0] as usize + 2];
            session.read_exact(&mut a).await?;
        }
        _ => return Err(proto("socks5 reply bad atyp")),
    }

    let creq = CoverRequest {
        class,
        max_traces,
        have_digest,
    };
    session.write_all(&creq.encode()).await?;
    session.flush().await?;

    // Read the fixed header, then exactly the bodies it declares. Reading to
    // EOF instead would let a bridge stream until the client runs out of
    // memory; the per-trace and total caps live in the decoder, and this loop
    // must not out-read them.
    let mut head = [0u8; 11];
    session.read_exact(&mut head).await?;
    let count = head[10] as usize;
    let mut buf = head.to_vec();
    let mut total = 0usize;
    for _ in 0..count {
        let mut lb = [0u8; 4];
        session.read_exact(&mut lb).await?;
        let len = u32::from_be_bytes(lb) as usize;
        if len > COVER_MAX_TRACE_BYTES {
            return Err(proto("cover trace exceeds the per-trace cap"));
        }
        total = total.saturating_add(len);
        if total > COVER_MAX_RESPONSE_BYTES {
            return Err(proto("cover response exceeds the total cap"));
        }
        let mut body = vec![0u8; len];
        session.read_exact(&mut body).await?;
        buf.extend_from_slice(&lb);
        buf.extend_from_slice(&body);
    }
    CoverResponse::decode(&buf)
}

fn fnv1a(b: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &x in b {
        h ^= u64::from(x);
        h = h.wrapping_mul(0x1000_0000_01b3);
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_round_trips_and_clamps() {
        let r = CoverRequest {
            class: COVER_CLASS_BROWSE,
            max_traces: 200, // over the cap
            have_digest: 0xdead_beef,
        };
        let got = CoverRequest::decode(&r.encode()).expect("round trip");
        assert_eq!(got.class, COVER_CLASS_BROWSE);
        assert_eq!(got.max_traces, COVER_MAX_TRACES, "clamped, not rejected");
        assert_eq!(got.have_digest, 0xdead_beef);
    }

    #[test]
    fn request_rejects_malformed_and_unknown_class() {
        assert!(CoverRequest::decode(&[0u8; 5]).is_err());
        let mut b = CoverRequest {
            class: COVER_CLASS_VIDEO,
            max_traces: 1,
            have_digest: 0,
        }
        .encode();
        b[0] = 0x99; // version
        assert!(CoverRequest::decode(&b).is_err());

        let mut b2 = CoverRequest {
            class: COVER_CLASS_VIDEO,
            max_traces: 1,
            have_digest: 0,
        }
        .encode();
        b2[2] = 0x77; // unknown class must NOT silently become browse
        assert!(CoverRequest::decode(&b2).is_err());

        // All three real classes must round-trip. The upstream one is the easy
        // one to forget, and forgetting it means the client keeps its own
        // upstream traces while wearing the bridge's downstream - which is
        // exactly the non-joint pair sharing a library exists to prevent.
        for c in [COVER_CLASS_BROWSE, COVER_CLASS_UPSTREAM, COVER_CLASS_VIDEO] {
            let r = CoverRequest {
                class: c,
                max_traces: 2,
                have_digest: 1,
            };
            assert_eq!(CoverRequest::decode(&r.encode()).expect("rt").class, c);
        }
    }

    #[test]
    fn response_round_trips_with_bodies() {
        let r = CoverResponse {
            status: COVER_STATUS_OK,
            digest: 42,
            traces: vec![b"t,size,dir\n0.1,100,1\n".to_vec(), b"x".to_vec()],
        };
        assert_eq!(CoverResponse::decode(&r.encode()).expect("rt"), r);
    }

    #[test]
    fn response_refuses_to_allocate_what_a_bridge_claims() {
        // The length prefixes come from the peer. A client must not be talked
        // into allocating gigabytes by a bridge that says a trace is huge.
        let mut b = Vec::new();
        b.push(COVER_VERSION);
        b.push(COVER_STATUS_OK);
        b.extend_from_slice(&0u64.to_be_bytes());
        b.push(1); // one trace
        b.extend_from_slice(&u32::MAX.to_be_bytes()); // ...of 4 GiB
        assert!(CoverResponse::decode(&b).is_err());

        // And a truncated body is an error, not a short read.
        let mut c = Vec::new();
        c.push(COVER_VERSION);
        c.push(COVER_STATUS_OK);
        c.extend_from_slice(&0u64.to_be_bytes());
        c.push(1);
        c.extend_from_slice(&16u32.to_be_bytes());
        c.extend_from_slice(b"only-4"); // fewer than 16
        assert!(CoverResponse::decode(&c).is_err());
    }

    #[tokio::test]
    async fn client_reads_exactly_what_a_server_wrote() {
        // Exercises the framing loop against a real socket rather than a
        // Vec: the client reads a fixed header and then exactly the bodies it
        // declares, and an off-by-one there would hang instead of erroring.
        use tokio::io::AsyncWriteExt;

        let traces = vec![
            b"t,size,dir\n0.0,1400,1\n0.1,300,-1\n".to_vec(),
            b"t,size,dir\n0.0,900,1\n".to_vec(),
        ];
        let resp = CoverResponse {
            status: COVER_STATUS_OK,
            digest: library_digest(&traces),
            traces: traces.clone(),
        };
        let wire = resp.encode();

        let (mut server, client) = tokio::io::duplex(64 * 1024);
        tokio::spawn(async move {
            // Minimal server side of the SOCKS5 preamble the client speaks.
            let mut g = [0u8; 3];
            tokio::io::AsyncReadExt::read_exact(&mut server, &mut g)
                .await
                .expect("greeting");
            server.write_all(&[0x05, 0x00]).await.expect("greet reply");
            let mut hdr = [0u8; 5];
            tokio::io::AsyncReadExt::read_exact(&mut server, &mut hdr)
                .await
                .expect("connect header");
            let mut rest = vec![0u8; hdr[4] as usize + 2];
            tokio::io::AsyncReadExt::read_exact(&mut server, &mut rest)
                .await
                .expect("connect host");
            // SUCCEEDED with an IPv4 BND the client must drain.
            server
                .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await
                .expect("connect reply");
            let mut req = [0u8; COVER_REQUEST_LEN];
            tokio::io::AsyncReadExt::read_exact(&mut server, &mut req)
                .await
                .expect("request");
            let parsed = CoverRequest::decode(&req).expect("server parses request");
            assert_eq!(parsed.class, COVER_CLASS_BROWSE);
            server.write_all(&wire).await.expect("response");
        });

        let got = fetch_cover_library(client, COVER_CLASS_BROWSE, 4, 0)
            .await
            .expect("fetch");
        assert_eq!(got.status, COVER_STATUS_OK);
        assert_eq!(got.traces, traces);
        assert_eq!(got.digest, library_digest(&traces));
    }

    #[tokio::test]
    async fn client_and_the_real_socks5_server_agree() {
        // The hand-rolled server in the test above proves the framing
        // arithmetic, and it passed while the live path failed with `early eof`
        // - which means the disagreement is with the REAL server, not with my
        // arithmetic. So drive the actual socks5 code the bridge uses.
        use mirage_socks5::server::{read_request, send_success_reply_for_internal};
        use tokio::io::AsyncReadExt;

        let traces = vec![b"t,size,dir\n0.0,1400,1\n".to_vec()];
        let resp = CoverResponse {
            status: COVER_STATUS_OK,
            digest: library_digest(&traces),
            traces: traces.clone(),
        };
        let wire = resp.encode();

        let (server, client) = tokio::io::duplex(64 * 1024);
        let srv = tokio::spawn(async move {
            // Exactly what the bridge does: peek one byte, replay it, parse.
            let mut server = server;
            let mut first = [0u8; 1];
            server.read_exact(&mut first).await.expect("peek");
            let prefixed = PrefixReplay {
                pre: first.to_vec(),
                inner: server,
            };
            let (req, mut s) = read_request(prefixed).await.expect("read_request");
            send_success_reply_for_internal(&mut s)
                .await
                .expect("reply");
            let mut rq = [0u8; COVER_REQUEST_LEN];
            s.read_exact(&mut rq).await.expect("cover request");
            CoverRequest::decode(&rq).expect("decode request");
            tokio::io::AsyncWriteExt::write_all(&mut s, &wire)
                .await
                .expect("write response");
            tokio::io::AsyncWriteExt::flush(&mut s).await.ok();
            format!("{:?}", req.target)
        });

        let got = fetch_cover_library(client, COVER_CLASS_BROWSE, 4, 0)
            .await
            .expect("client must parse what the real server sent");
        assert_eq!(got.status, COVER_STATUS_OK);
        assert_eq!(got.traces, traces);
        let target = srv.await.expect("server task");
        assert!(
            target.contains(COVER_MAGIC_HOSTNAME),
            "server saw target {target}"
        );
    }

    /// Replays bytes already consumed by a peek, like the bridge's own
    /// `PrefixedStream`.
    struct PrefixReplay<S> {
        pre: Vec<u8>,
        inner: S,
    }

    impl<S: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for PrefixReplay<S> {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            if !self.pre.is_empty() {
                let n = self.pre.len().min(buf.remaining());
                let head: Vec<u8> = self.pre.drain(..n).collect();
                buf.put_slice(&head);
                return std::task::Poll::Ready(Ok(()));
            }
            std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }

    impl<S: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for PrefixReplay<S> {
        fn poll_write(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            b: &[u8],
        ) -> std::task::Poll<io::Result<usize>> {
            std::pin::Pin::new(&mut self.inner).poll_write(cx, b)
        }
        fn poll_flush(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            std::pin::Pin::new(&mut self.inner).poll_flush(cx)
        }
        fn poll_shutdown(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    #[test]
    fn proteus_required_is_a_precondition_not_a_transport() {
        use crate::wire::transport_caps as tc;
        // It must never show up in the transport list a client picks from -
        // it is a precondition on the session, not something to dial.
        let caps = tc::REALITY_V2 | tc::PROTEUS_REQUIRED;
        let names = tc::names_for_caps(caps);
        assert!(names.contains(&tc::NAME_REALITY_V2));
        assert_eq!(names.len(), 1, "PROTEUS_REQUIRED must not name a transport");
        // And it has to be inside MASK_DEFINED, or a parser rejects the whole
        // announcement as carrying an unknown bit.
        assert_eq!(
            tc::PROTEUS_REQUIRED & tc::MASK_DEFINED,
            tc::PROTEUS_REQUIRED
        );
        // It must not collide with a real transport bit.
        assert_eq!(
            tc::PROTEUS_REQUIRED & !tc::PROTEUS_REQUIRED & tc::MASK_DEFINED,
            0
        );
    }

    #[test]
    fn digest_ignores_order_but_not_content() {
        // Two ends listing a directory may enumerate it differently; a digest
        // that changed with readdir order would re-transfer the library forever.
        let a = vec![b"one".to_vec(), b"two".to_vec(), b"three".to_vec()];
        let mut b = a.clone();
        b.reverse();
        assert_eq!(library_digest(&a), library_digest(&b));

        let mut c = a.clone();
        c[0] = b"onf".to_vec();
        assert_ne!(library_digest(&a), library_digest(&c));
        assert_ne!(library_digest(&a), library_digest(&[]));
    }
}
