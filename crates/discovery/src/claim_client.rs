//! Client-side invite-claim helper (v0.1e).
//!
//! Runs inside an established Mirage session: speaks SOCKS5 to
//! reach the bridge's [`crate::claim::CLAIM_MAGIC_HOSTNAME`], sends
//! a [`ClaimRequest`] carrying the invite's claim id, and reads the
//! [`ClaimResponse`]. Any refresh tokens the bridge piggybacks are
//! verified against the bridge's Ed25519 identity pubkey before
//! being returned.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::claim::{
    ClaimRequest, ClaimResponse, CLAIM_MAGIC_HOSTNAME, CLAIM_MAGIC_PORT, CLAIM_REQUEST_LEN,
    CLAIM_VERSION,
};
use crate::error::DiscoveryError;
use crate::refresh::{SessionRefreshToken, REFRESH_MAX_PER_REQUEST};
use crate::token::TOKEN_LEN;
use crate::wire::ED25519_PK_LEN;

/// SOCKS5 constants we need (mirrored to avoid a `mirage-socks5`
/// dep from `mirage-discovery`).
const SOCKS5_VERSION: u8 = 0x05;
const SOCKS5_METHOD_NO_AUTH: u8 = 0x00;
const SOCKS5_CMD_CONNECT: u8 = 0x01;
const SOCKS5_ATYP_DOMAIN: u8 = 0x03;
const SOCKS5_REP_SUCCEEDED: u8 = 0x00;

/// Outcome of a CLAIM exchange.
#[derive(Debug, Clone)]
pub struct ClaimOutcome {
    /// Bridge status byte.
    pub status: u8,
    /// Refresh tokens piggybacked on the claim response. Each is
    /// signature-verified against the bridge's identity pubkey
    /// before being handed back.
    pub tokens: Vec<SessionRefreshToken>,
}

/// Error surface for the client-side claim call.
#[derive(Debug, thiserror::Error)]
pub enum ClaimClientError {
    /// Underlying byte-stream I/O failure.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// Bridge rejected SOCKS5 or closed the stream.
    #[error("socks5: {0}")]
    Socks5(&'static str),
    /// Claim wire parse failure.
    #[error("claim wire: {0}")]
    Wire(&'static str),
    /// A piggybacked token failed signature verification.
    #[error("bad signature at index {0}")]
    BadSignature(usize),
    /// A piggybacked token was not bound to the bridge we're talking to.
    #[error("bridge pin mismatch at index {0}")]
    PinMismatch(usize),
}

impl From<DiscoveryError> for ClaimClientError {
    fn from(e: DiscoveryError) -> Self {
        match e {
            DiscoveryError::Wire(m) => ClaimClientError::Wire(m),
            DiscoveryError::Signature(m) => ClaimClientError::Wire(m),
            _ => ClaimClientError::Wire("other"),
        }
    }
}

/// Redeem the invite's `claim_id` against the currently-connected
/// bridge, asking for `refresh_count` piggybacked refresh tokens.
///
/// `bridge_ed25519_pk` is taken from the announcement the client
/// used to reach this bridge. Piggybacked tokens must sign-verify
/// against this key AND be bound to it, or the call errors.
pub async fn redeem_invite_claim<S>(
    mut session: S,
    bridge_ed25519_pk: &[u8; ED25519_PK_LEN],
    claim_id: [u8; 32],
    refresh_count: u8,
) -> Result<ClaimOutcome, ClaimClientError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // --- SOCKS5 method selection ---
    session
        .write_all(&[SOCKS5_VERSION, 1, SOCKS5_METHOD_NO_AUTH])
        .await?;
    session.flush().await?;
    let mut greeting = [0u8; 2];
    session.read_exact(&mut greeting).await?;
    if greeting[0] != SOCKS5_VERSION {
        return Err(ClaimClientError::Socks5("bad version in greeting"));
    }
    if greeting[1] != SOCKS5_METHOD_NO_AUTH {
        return Err(ClaimClientError::Socks5("no-auth refused"));
    }

    // --- SOCKS5 CONNECT to the magic hostname ---
    let name = CLAIM_MAGIC_HOSTNAME.as_bytes();
    let mut req = Vec::with_capacity(7 + name.len());
    req.push(SOCKS5_VERSION);
    req.push(SOCKS5_CMD_CONNECT);
    req.push(0x00); // RSV
    req.push(SOCKS5_ATYP_DOMAIN);
    req.push(name.len() as u8);
    req.extend_from_slice(name);
    req.extend_from_slice(&CLAIM_MAGIC_PORT.to_be_bytes());
    session.write_all(&req).await?;
    session.flush().await?;

    let mut reply_hdr = [0u8; 4];
    session.read_exact(&mut reply_hdr).await?;
    if reply_hdr[0] != SOCKS5_VERSION {
        return Err(ClaimClientError::Socks5("bad version in reply"));
    }
    if reply_hdr[1] != SOCKS5_REP_SUCCEEDED {
        return Err(ClaimClientError::Socks5("reply not succeeded"));
    }
    match reply_hdr[3] {
        0x01 => {
            let mut a = [0u8; 6];
            session.read_exact(&mut a).await?;
        }
        0x04 => {
            let mut a = [0u8; 18];
            session.read_exact(&mut a).await?;
        }
        0x03 => {
            let mut len = [0u8; 1];
            session.read_exact(&mut len).await?;
            let l = len[0] as usize;
            let mut a = vec![0u8; l + 2];
            session.read_exact(&mut a).await?;
        }
        _ => return Err(ClaimClientError::Socks5("reply bad atyp")),
    }

    // --- CLAIM request ---
    let creq = ClaimRequest::redeem(claim_id, refresh_count);
    debug_assert_eq!(creq.encode().len(), CLAIM_REQUEST_LEN);
    session.write_all(&creq.encode()).await?;
    session.flush().await?;

    // --- Response ---
    let mut resp_hdr = [0u8; 3];
    session.read_exact(&mut resp_hdr).await?;
    if resp_hdr[0] != CLAIM_VERSION {
        return Err(ClaimClientError::Wire("response version"));
    }
    let status = resp_hdr[1];
    let count = resp_hdr[2] as usize;
    if count > REFRESH_MAX_PER_REQUEST as usize {
        return Err(ClaimClientError::Wire("response count over cap"));
    }
    let mut body = vec![0u8; count * TOKEN_LEN];
    if !body.is_empty() {
        session.read_exact(&mut body).await?;
    }
    let mut full = Vec::with_capacity(3 + body.len());
    full.extend_from_slice(&resp_hdr);
    full.extend_from_slice(&body);
    let parsed = ClaimResponse::decode(&full).map_err(ClaimClientError::from)?;

    for (i, t) in parsed.tokens.iter().enumerate() {
        if !t.is_for_bridge(bridge_ed25519_pk) {
            return Err(ClaimClientError::PinMismatch(i));
        }
        t.verify_signature(bridge_ed25519_pk)
            .map_err(|_| ClaimClientError::BadSignature(i))?;
    }

    Ok(ClaimOutcome {
        status,
        tokens: parsed.tokens,
    })
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;
    use crate::claim::{ClaimResponse, CLAIM_STATUS_ALREADY_CLAIMED, CLAIM_STATUS_OK};
    use crate::refresh::sign_refresh_token;
    use mirage_crypto::ed25519_dalek::SigningKey;

    fn bridge_key() -> SigningKey {
        let mut s = [0u8; 32];
        getrandom::fill(&mut s).unwrap();
        SigningKey::from_bytes(&s)
    }

    async fn mock_bridge(mut stream: tokio::io::DuplexStream, response: Vec<u8>) {
        let mut hdr = [0u8; 2];
        stream.read_exact(&mut hdr).await.unwrap();
        let mut methods = vec![0u8; hdr[1] as usize];
        stream.read_exact(&mut methods).await.unwrap();
        stream
            .write_all(&[SOCKS5_VERSION, SOCKS5_METHOD_NO_AUTH])
            .await
            .unwrap();

        let mut rh = [0u8; 4];
        stream.read_exact(&mut rh).await.unwrap();
        let mut l = [0u8; 1];
        stream.read_exact(&mut l).await.unwrap();
        let mut name = vec![0u8; l[0] as usize];
        stream.read_exact(&mut name).await.unwrap();
        let mut port = [0u8; 2];
        stream.read_exact(&mut port).await.unwrap();

        stream
            .write_all(&[SOCKS5_VERSION, 0, 0, 0x01, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();

        let mut creq = [0u8; CLAIM_REQUEST_LEN];
        stream.read_exact(&mut creq).await.unwrap();

        stream.write_all(&response).await.unwrap();
        stream.flush().await.unwrap();
        drop(stream);
    }

    #[tokio::test]
    async fn happy_path_with_tokens() {
        let sk = bridge_key();
        let pk = sk.verifying_key().to_bytes();
        let tokens = vec![sign_refresh_token([0x55u8; 32], &sk, 1_700_000_000)];
        let resp = ClaimResponse::ok(tokens);
        let wire = resp.encode();
        let (client, server) = tokio::io::duplex(8 * 1024);
        tokio::spawn(mock_bridge(server, wire));
        let out = redeem_invite_claim(client, &pk, [0xABu8; 32], 1)
            .await
            .unwrap();
        assert_eq!(out.status, CLAIM_STATUS_OK);
        assert_eq!(out.tokens.len(), 1);
    }

    #[tokio::test]
    async fn already_claimed_returns_status() {
        let sk = bridge_key();
        let pk = sk.verifying_key().to_bytes();
        let resp = ClaimResponse::empty(CLAIM_STATUS_ALREADY_CLAIMED);
        let wire = resp.encode();
        let (client, server) = tokio::io::duplex(8 * 1024);
        tokio::spawn(mock_bridge(server, wire));
        let out = redeem_invite_claim(client, &pk, [0u8; 32], 0)
            .await
            .unwrap();
        assert_eq!(out.status, CLAIM_STATUS_ALREADY_CLAIMED);
        assert!(out.tokens.is_empty());
    }

    #[tokio::test]
    async fn token_pin_mismatch_rejected_at_client() {
        let real_sk = bridge_key();
        let real_pk = real_sk.verifying_key().to_bytes();
        let imposter_sk = bridge_key();
        let t = sign_refresh_token([0x01u8; 32], &imposter_sk, 1_700_000_000);
        let resp = ClaimResponse::ok(vec![t]);
        let wire = resp.encode();
        let (client, server) = tokio::io::duplex(8 * 1024);
        tokio::spawn(mock_bridge(server, wire));
        let err = redeem_invite_claim(client, &real_pk, [0u8; 32], 1)
            .await
            .unwrap_err();
        assert!(matches!(err, ClaimClientError::PinMismatch(0)));
    }
}
