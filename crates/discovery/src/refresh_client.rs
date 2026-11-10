//! Client-side refresh-token request helper.
//!
//! Runs inside an established Mirage session stream: speaks SOCKS5
//! to the bridge requesting the magic refresh hostname, then sends
//! a [`RefreshRequest`] and reads the [`RefreshResponse`]. Every
//! returned token is signature-verified against the bridge's
//! long-term Ed25519 identity (the same pubkey that appears in the
//! bridge's signed announcement) before being returned to the
//! caller - so a compromised bridge cannot hand back tokens signed
//! by some other key.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::DiscoveryError;
use crate::refresh::{
    RefreshRequest, RefreshResponse, SessionRefreshToken, REFRESH_MAGIC_HOSTNAME,
    REFRESH_MAGIC_PORT, REFRESH_MAX_PER_REQUEST, REFRESH_VERSION,
};
use crate::token::TOKEN_LEN;
use crate::wire::ED25519_PK_LEN;

/// SOCKS5 constants we need (mirrored to avoid a `mirage-socks5`
/// dep from `mirage-discovery`).
const SOCKS5_VERSION: u8 = 0x05;
const SOCKS5_METHOD_NO_AUTH: u8 = 0x00;
const SOCKS5_CMD_CONNECT: u8 = 0x01;
const SOCKS5_ATYP_DOMAIN: u8 = 0x03;
const SOCKS5_REP_SUCCEEDED: u8 = 0x00;

/// Result of a successful refresh request.
#[derive(Debug, Clone)]
pub struct RefreshBatch {
    /// Tokens the bridge minted, each verified against
    /// `bridge_ed25519_pk`. Empty on `status != OK`.
    pub tokens: Vec<SessionRefreshToken>,
    /// Status byte from the bridge's response.
    pub status: u8,
}

/// Error surface for the client-side refresh call.
#[derive(Debug, thiserror::Error)]
pub enum RefreshClientError {
    /// Underlying byte-stream I/O failure.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// Bridge rejected SOCKS5 or closed the stream.
    #[error("socks5: {0}")]
    Socks5(&'static str),
    /// Refresh wire parse failure.
    #[error("refresh wire: {0}")]
    Wire(&'static str),
    /// A returned token failed signature verification.
    #[error("bad signature at index {0}")]
    BadSignature(usize),
    /// A returned token was not bound to the bridge we're talking to.
    #[error("bridge pin mismatch at index {0}")]
    PinMismatch(usize),
}

impl From<DiscoveryError> for RefreshClientError {
    fn from(e: DiscoveryError) -> Self {
        match e {
            DiscoveryError::Wire(m) => RefreshClientError::Wire(m),
            DiscoveryError::Signature(m) => RefreshClientError::Wire(m),
            _ => RefreshClientError::Wire("other"),
        }
    }
}

/// Ask the bridge for up to `count` new refresh tokens over
/// `session`, verifying every returned token against
/// `bridge_ed25519_pk`.
///
/// `count` is clamped to [`REFRESH_MAX_PER_REQUEST`].
pub async fn refresh_session_tokens<S>(
    mut session: S,
    bridge_ed25519_pk: &[u8; ED25519_PK_LEN],
    count: u8,
) -> Result<RefreshBatch, RefreshClientError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let count = count.clamp(1, REFRESH_MAX_PER_REQUEST);

    // --- SOCKS5 method selection ---
    session
        .write_all(&[SOCKS5_VERSION, 1, SOCKS5_METHOD_NO_AUTH])
        .await?;
    session.flush().await?;
    let mut greeting = [0u8; 2];
    session.read_exact(&mut greeting).await?;
    if greeting[0] != SOCKS5_VERSION {
        return Err(RefreshClientError::Socks5("bad version in greeting"));
    }
    if greeting[1] != SOCKS5_METHOD_NO_AUTH {
        return Err(RefreshClientError::Socks5("no-auth refused"));
    }

    // --- SOCKS5 CONNECT to the magic hostname ---
    let name = REFRESH_MAGIC_HOSTNAME.as_bytes();
    let mut req = Vec::with_capacity(7 + name.len());
    req.push(SOCKS5_VERSION);
    req.push(SOCKS5_CMD_CONNECT);
    req.push(0x00); // RSV
    req.push(SOCKS5_ATYP_DOMAIN);
    req.push(name.len() as u8);
    req.extend_from_slice(name);
    req.extend_from_slice(&REFRESH_MAGIC_PORT.to_be_bytes());
    session.write_all(&req).await?;
    session.flush().await?;

    let mut reply_hdr = [0u8; 4];
    session.read_exact(&mut reply_hdr).await?;
    if reply_hdr[0] != SOCKS5_VERSION {
        return Err(RefreshClientError::Socks5("bad version in reply"));
    }
    if reply_hdr[1] != SOCKS5_REP_SUCCEEDED {
        return Err(RefreshClientError::Socks5("reply not succeeded"));
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
        _ => return Err(RefreshClientError::Socks5("reply bad atyp")),
    }

    // --- Refresh ISSUE request ---
    let rreq = RefreshRequest::issue(count).map_err(|_| RefreshClientError::Wire("count"))?;
    session.write_all(&rreq.encode()).await?;
    session.flush().await?;

    // --- Refresh response ---
    // Header is exactly 3 bytes; body is `count x TOKEN_LEN`. Fixed
    // size means we can read the whole response in two read_exact
    // calls without any "grow-until-parseable" loop.
    let mut resp_hdr = [0u8; 3];
    session.read_exact(&mut resp_hdr).await?;
    if resp_hdr[0] != REFRESH_VERSION {
        return Err(RefreshClientError::Wire("response version"));
    }
    let status = resp_hdr[1];
    let count = resp_hdr[2] as usize;
    if count > REFRESH_MAX_PER_REQUEST as usize {
        return Err(RefreshClientError::Wire("response count over cap"));
    }
    let mut body = vec![0u8; count * TOKEN_LEN];
    if !body.is_empty() {
        session.read_exact(&mut body).await?;
    }
    // Reassemble full wire frame and hand to the decoder to reuse
    // the single source of truth for the wire format.
    let mut full = Vec::with_capacity(3 + body.len());
    full.extend_from_slice(&resp_hdr);
    full.extend_from_slice(&body);
    let parsed = RefreshResponse::decode(&full).map_err(RefreshClientError::from)?;

    // Verify every token's signature + bridge pin.
    for (i, t) in parsed.tokens.iter().enumerate() {
        if !t.is_for_bridge(bridge_ed25519_pk) {
            return Err(RefreshClientError::PinMismatch(i));
        }
        t.verify_signature(bridge_ed25519_pk)
            .map_err(|_| RefreshClientError::BadSignature(i))?;
    }

    Ok(RefreshBatch {
        tokens: parsed.tokens,
        status,
    })
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;
    use crate::refresh::{sign_refresh_token, RefreshResponse, REFRESH_STATUS_OK};
    use mirage_crypto::ed25519_dalek::SigningKey;

    fn bridge_key() -> SigningKey {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).unwrap();
        SigningKey::from_bytes(&seed)
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

        let mut rreq = [0u8; 3];
        stream.read_exact(&mut rreq).await.unwrap();

        stream.write_all(&response).await.unwrap();
        stream.flush().await.unwrap();
        drop(stream);
    }

    #[tokio::test]
    async fn happy_path_single_token() {
        let sk = bridge_key();
        let pk = sk.verifying_key().to_bytes();
        let t = sign_refresh_token([0x77u8; 32], &sk, 1_700_000_000);
        let resp = RefreshResponse::ok(vec![t]);
        let wire = resp.encode();
        let (client, server) = tokio::io::duplex(8 * 1024);
        tokio::spawn(mock_bridge(server, wire));
        let batch = refresh_session_tokens(client, &pk, 1).await.unwrap();
        assert_eq!(batch.status, REFRESH_STATUS_OK);
        assert_eq!(batch.tokens.len(), 1);
        assert_eq!(batch.tokens[0].inner.token_id, [0x77u8; 32]);
    }

    #[tokio::test]
    async fn bad_signature_rejected_at_client() {
        let real_sk = bridge_key();
        let real_pk = real_sk.verifying_key().to_bytes();
        let imposter_sk = bridge_key();
        // Token signed by the imposter, bound to... the imposter's
        // own pubkey (so `is_for_bridge(real_pk)` fails first).
        // That's the natural MitM case: attacker bridge tries to
        // hand the client its OWN refresh tokens; the pin check
        // catches it before signature verification.
        let t = sign_refresh_token([0x99u8; 32], &imposter_sk, 1_700_000_000);
        let resp = RefreshResponse::ok(vec![t]);
        let wire = resp.encode();
        let (client, server) = tokio::io::duplex(8 * 1024);
        tokio::spawn(mock_bridge(server, wire));
        let err = refresh_session_tokens(client, &real_pk, 1)
            .await
            .unwrap_err();
        assert!(matches!(err, RefreshClientError::PinMismatch(0)));
    }

    #[tokio::test]
    async fn empty_response_returns_ok_no_tokens() {
        let sk = bridge_key();
        let pk = sk.verifying_key().to_bytes();
        let resp = RefreshResponse::empty(crate::refresh::REFRESH_STATUS_EXHAUSTED);
        let wire = resp.encode();
        let (client, server) = tokio::io::duplex(8 * 1024);
        tokio::spawn(mock_bridge(server, wire));
        let batch = refresh_session_tokens(client, &pk, 2).await.unwrap();
        assert_eq!(batch.status, crate::refresh::REFRESH_STATUS_EXHAUSTED);
        assert!(batch.tokens.is_empty());
    }
}
