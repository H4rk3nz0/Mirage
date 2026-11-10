//! Client-side cohort request helper.
//!
//! Run inside an established Mirage session stream: speaks SOCKS5
//! to the bridge asking for the magic cohort hostname, then sends
//! the [`CohortRequest`] and reads the [`CohortResponse`]. Every
//! announcement in the response is signature-verified against the
//! invite-bound operator pubkey before being returned; a bridge
//! cannot hand over a forged announcement under this API.

use mirage_crypto::ed25519_dalek::VerifyingKey;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::cohort::{
    CohortRequest, CohortResponse, COHORT_MAGIC_HOSTNAME, COHORT_MAGIC_PORT,
    COHORT_MAX_N_PER_REQUEST,
};
use crate::error::DiscoveryError;
use crate::wire::{Announcement, ED25519_PK_LEN};

/// SOCKS5 constants we need (mirrored to avoid a `mirage-socks5`
/// dep from `mirage-discovery`).
const SOCKS5_VERSION: u8 = 0x05;
const SOCKS5_METHOD_NO_AUTH: u8 = 0x00;
const SOCKS5_CMD_CONNECT: u8 = 0x01;
const SOCKS5_ATYP_DOMAIN: u8 = 0x03;
const SOCKS5_REP_SUCCEEDED: u8 = 0x00;

/// Result of a successful cohort refresh.
#[derive(Debug, Clone)]
pub struct CohortRefresh {
    /// Announcements the bridge returned, every one operator-signature verified.
    pub announcements: Vec<Announcement>,
    /// Status byte from the bridge's response.
    pub status: u8,
}

/// Error surface for the client-side cohort refresh.
#[derive(Debug, thiserror::Error)]
pub enum CohortClientError {
    /// Underlying byte-stream I/O failure.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// Bridge rejected SOCKS5 or closed the stream.
    #[error("socks5: {0}")]
    Socks5(&'static str),
    /// Cohort-layer parse failure.
    #[error("cohort wire: {0}")]
    Wire(&'static str),
    /// An announcement in the response did not pass operator-sig
    /// verification. Contains the index of the first bad entry so
    /// operators can diagnose a compromised bridge.
    #[error("bad signature at index {0}")]
    BadSignature(usize),
}

impl From<DiscoveryError> for CohortClientError {
    fn from(e: DiscoveryError) -> Self {
        match e {
            DiscoveryError::Wire(m) => CohortClientError::Wire(m),
            DiscoveryError::Signature(m) => CohortClientError::Wire(m),
            _ => CohortClientError::Wire("other"),
        }
    }
}

/// Issue one cohort LIST request over `session` and return what the
/// bridge handed back, with every announcement verified against
/// `operator_ed25519_pk`.
///
/// `max_n` is capped at [`COHORT_MAX_N_PER_REQUEST`].
pub async fn refresh_cohort<S>(
    mut session: S,
    operator_ed25519_pk: &[u8; ED25519_PK_LEN],
    max_n: u8,
) -> Result<CohortRefresh, CohortClientError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let max_n = max_n.clamp(1, COHORT_MAX_N_PER_REQUEST);

    // --- SOCKS5 method selection ---
    session
        .write_all(&[SOCKS5_VERSION, 1, SOCKS5_METHOD_NO_AUTH])
        .await?;
    session.flush().await?;
    let mut greeting = [0u8; 2];
    session.read_exact(&mut greeting).await?;
    if greeting[0] != SOCKS5_VERSION {
        return Err(CohortClientError::Socks5("bad version in greeting"));
    }
    if greeting[1] != SOCKS5_METHOD_NO_AUTH {
        return Err(CohortClientError::Socks5("no-auth refused"));
    }

    // --- SOCKS5 CONNECT to the magic hostname ---
    let name = COHORT_MAGIC_HOSTNAME.as_bytes();
    let mut req = Vec::with_capacity(7 + name.len());
    req.push(SOCKS5_VERSION);
    req.push(SOCKS5_CMD_CONNECT);
    req.push(0x00); // RSV
    req.push(SOCKS5_ATYP_DOMAIN);
    req.push(name.len() as u8);
    req.extend_from_slice(name);
    req.extend_from_slice(&COHORT_MAGIC_PORT.to_be_bytes());
    session.write_all(&req).await?;
    session.flush().await?;

    let mut reply_hdr = [0u8; 4];
    session.read_exact(&mut reply_hdr).await?;
    if reply_hdr[0] != SOCKS5_VERSION {
        return Err(CohortClientError::Socks5("bad version in reply"));
    }
    if reply_hdr[1] != SOCKS5_REP_SUCCEEDED {
        return Err(CohortClientError::Socks5("reply not succeeded"));
    }
    // Drain the BND address + port based on atyp.
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
        _ => return Err(CohortClientError::Socks5("reply bad atyp")),
    }

    // --- Cohort LIST request ---
    let creq = CohortRequest::list(max_n).map_err(|_| CohortClientError::Wire("max_n"))?;
    session.write_all(&creq.encode()).await?;
    session.flush().await?;

    // --- Cohort response ---
    // Read header (4 B) then body incrementally. Since response
    // total length can be computed from the header (count x avg
    // announcement size), we just read "as much as the peer sends"
    // up to a hard cap and then decode.
    let mut resp_hdr = [0u8; 4];
    session.read_exact(&mut resp_hdr).await?;
    let version = resp_hdr[0];
    let status = resp_hdr[1];
    let count = u16::from_be_bytes([resp_hdr[2], resp_hdr[3]]) as usize;
    if version != crate::cohort::COHORT_VERSION {
        return Err(CohortClientError::Wire("response version"));
    }

    // Each announcement is at most ~500 B (spec §5.1 caps plaintext
    // at 768 B). Cap total body at 4 KiB and error if the bridge
    // promised more than we can accept.
    const MAX_BODY: usize = 4 * 1024;
    if count > COHORT_MAX_N_PER_REQUEST as usize {
        return Err(CohortClientError::Wire("response count over cap"));
    }
    let mut body = Vec::new();
    let mut tmp = [0u8; 1024];
    while body.len() < MAX_BODY {
        // Stop when we can decode the expected count of
        // announcements from what we've got. We try once per
        // successful read.
        match session.read(&mut tmp).await {
            Ok(0) => break,
            Ok(n) => {
                body.extend_from_slice(&tmp[..n]);
                // Attempt a decode at the current body length.
                let mut full = Vec::with_capacity(4 + body.len());
                full.extend_from_slice(&resp_hdr);
                full.extend_from_slice(&body);
                if let Ok(r) = CohortResponse::decode(&full) {
                    // Successfully parsed; verify every signature.
                    let vk = VerifyingKey::from_bytes(operator_ed25519_pk)
                        .map_err(|_| CohortClientError::Wire("operator pubkey invalid"))?;
                    for (i, a) in r.announcements.iter().enumerate() {
                        a.verify(&vk.to_bytes())
                            .map_err(|_| CohortClientError::BadSignature(i))?;
                    }
                    return Ok(CohortRefresh {
                        announcements: r.announcements,
                        status: r.status,
                    });
                }
            }
            Err(e) => return Err(CohortClientError::Io(e)),
        }
    }
    // If we got here the bridge sent more bytes than we expected
    // OR the announcement count was fewer than we predicted and
    // the peer closed the stream. Handle the "0 announcements, peer
    // closed" case cleanly.
    if count == 0 {
        return Ok(CohortRefresh {
            announcements: Vec::new(),
            status,
        });
    }
    Err(CohortClientError::Wire("response body exceeded cap"))
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cohort::COHORT_STATUS_OK;
    use crate::wire::{transport_caps, Endpoint, SIG_LEN};
    use mirage_crypto::ed25519_dalek::{Signer, SigningKey};

    fn op_keypair() -> SigningKey {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).unwrap();
        SigningKey::from_bytes(&seed)
    }

    fn sign_ann(mut a: Announcement, op: &SigningKey) -> Announcement {
        let mut prefix = Vec::new();
        a.encode_signed_prefix(&mut prefix);
        a.signature = op.sign(&prefix).to_bytes();
        a
    }

    fn sample_ann(tag: u8) -> Announcement {
        Announcement {
            issued_at: 1,
            expires_at: 1_000_000,
            bridge_ed25519_pk: [tag; 32],
            bridge_x25519_pk: [tag.wrapping_add(1); 32],
            transport_caps: transport_caps::REALITY_V2,
            endpoint: Endpoint::Ipv4 {
                addr: [192, 0, 2, tag],
                port: 443,
            },
            extra_endpoints: Vec::new(),
            signature: [0u8; SIG_LEN],
        }
    }

    /// Spawn a tiny mock bridge inside a duplex pair. Responds to
    /// the SOCKS5 handshake and a cohort LIST request, returning a
    /// hard-coded response body.
    async fn mock_bridge(mut stream: tokio::io::DuplexStream, response: Vec<u8>) {
        // Read greeting: ver + nmethods + methods
        let mut hdr = [0u8; 2];
        stream.read_exact(&mut hdr).await.unwrap();
        let mut methods = vec![0u8; hdr[1] as usize];
        stream.read_exact(&mut methods).await.unwrap();
        stream
            .write_all(&[SOCKS5_VERSION, SOCKS5_METHOD_NO_AUTH])
            .await
            .unwrap();

        // Read CONNECT
        let mut rh = [0u8; 4];
        stream.read_exact(&mut rh).await.unwrap();
        // atyp = domain
        let mut l = [0u8; 1];
        stream.read_exact(&mut l).await.unwrap();
        let mut name = vec![0u8; l[0] as usize];
        stream.read_exact(&mut name).await.unwrap();
        let mut port = [0u8; 2];
        stream.read_exact(&mut port).await.unwrap();

        // Reply: success + ipv4 BND 0.0.0.0:0
        stream
            .write_all(&[SOCKS5_VERSION, 0, 0, 0x01, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();

        // Read the 3-byte cohort request
        let mut creq = [0u8; 3];
        stream.read_exact(&mut creq).await.unwrap();

        // Write the prepared response
        stream.write_all(&response).await.unwrap();
        stream.flush().await.unwrap();
        // Close.
        drop(stream);
    }

    #[tokio::test]
    async fn happy_path_multi_announcement() {
        let op = op_keypair();
        let op_pk = op.verifying_key().to_bytes();
        let a1 = sign_ann(sample_ann(1), &op);
        let a2 = sign_ann(sample_ann(2), &op);
        let response = CohortResponse {
            status: COHORT_STATUS_OK,
            announcements: vec![a1.clone(), a2.clone()],
        };
        let wire = response.encode();

        let (client, server) = tokio::io::duplex(8 * 1024);
        tokio::spawn(mock_bridge(server, wire));

        let r = refresh_cohort(client, &op_pk, 3).await.unwrap();
        assert_eq!(r.status, COHORT_STATUS_OK);
        assert_eq!(r.announcements.len(), 2);
        assert_eq!(r.announcements[0].bridge_ed25519_pk, a1.bridge_ed25519_pk);
    }

    #[tokio::test]
    async fn empty_response_returns_ok_no_anns() {
        let op = op_keypair();
        let op_pk = op.verifying_key().to_bytes();
        let response = CohortResponse::empty(crate::cohort::COHORT_STATUS_EMPTY);
        let wire = response.encode();
        let (client, server) = tokio::io::duplex(8 * 1024);
        tokio::spawn(mock_bridge(server, wire));
        let r = refresh_cohort(client, &op_pk, 3).await.unwrap();
        assert_eq!(r.status, crate::cohort::COHORT_STATUS_EMPTY);
        assert!(r.announcements.is_empty());
    }

    #[tokio::test]
    async fn bad_signature_rejected_at_client() {
        let op = op_keypair();
        let wrong_op = op_keypair();
        let op_pk = op.verifying_key().to_bytes();
        // Announcement signed by the WRONG operator; we verify
        // against `op_pk`, so decode succeeds but verify fails.
        let bad = sign_ann(sample_ann(7), &wrong_op);
        let response = CohortResponse::ok(vec![bad]);
        let wire = response.encode();
        let (client, server) = tokio::io::duplex(8 * 1024);
        tokio::spawn(mock_bridge(server, wire));
        let err = refresh_cohort(client, &op_pk, 3).await.unwrap_err();
        assert!(matches!(err, CohortClientError::BadSignature(0)));
    }

    #[tokio::test]
    async fn over_cap_count_rejected() {
        let op = op_keypair();
        let op_pk = op.verifying_key().to_bytes();
        // Manually forge a response with a count field over cap.
        let mut wire = Vec::new();
        wire.push(crate::cohort::COHORT_VERSION);
        wire.push(COHORT_STATUS_OK);
        wire.extend_from_slice(&((COHORT_MAX_N_PER_REQUEST + 1) as u16).to_be_bytes());
        // No bodies.
        let (client, server) = tokio::io::duplex(8 * 1024);
        tokio::spawn(mock_bridge(server, wire));
        let err = refresh_cohort(client, &op_pk, 3).await.unwrap_err();
        assert!(matches!(err, CohortClientError::Wire(_)));
    }
}
