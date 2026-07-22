//! QUIC packet obfuscation for Mirage's QUIC carriers (hysteria2 + h3).
//!
//! # Why
//!
//! Mirage's QUIC carriers use `quinn` + `rustls` defaults, so their QUIC Initial
//! ClientHello, transport parameters, version, and connection IDs form a
//! **non-browser QUIC fingerprint** a state DPI can match - and the raw QUIC
//! long-header structure is visible on the wire. This crate hides it.
//!
//! # Salamander (implemented here)
//!
//! Each outgoing UDP datagram is prefixed with a random `SALT_LEN`-byte salt and
//! XORed with a keyed-BLAKE3 keystream derived from `(key, salt)`. On the wire
//! every datagram is indistinguishable from random bytes - no QUIC header, no
//! version, no fingerprint. Both peers derive the same `key` from a shared obfs
//! password, so the receiver de-obfuscates before handing the datagram to quinn.
//! This is the same idea as Hysteria2's "Salamander" obfuscation.
//!
//! # Gecko (fragmentation - [`gecko`] layer)
//!
//! Salamander alone leaves the QUIC handshake datagrams clustered near ~1200 B,
//! which statistical DPI can still flag. The [`gecko`] layer fragments large
//! (long-header) datagrams into 2-8 random-sized, randomly-padded pieces - each
//! its own Salamander-wrapped datagram - randomising the packet-size
//! distribution. Short-header (data-phase) packets pass through unfragmented.
//!
//! # Usage
//!
//! [`client_endpoint`] / [`server_endpoint`] build a `quinn::Endpoint` whose UDP
//! socket is wrapped in the obfuscator. The transports call these instead of
//! `quinn::Endpoint::client` / `::server` when an obfs password is configured.

#![forbid(unsafe_code)]
// Byte-level packet framing with explicit length checks throughout; indexing is
// intentional and guarded. Docs reference many protocol terms (QUIC, GSO/GRO,
// ClientHello, Salamander) that would otherwise trip doc_markdown.
#![allow(clippy::indexing_slicing, clippy::doc_markdown)]

use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use quinn::udp::RecvMeta;
use quinn::{AsyncUdpSocket, UdpPoller};
use tokio::io::ReadBuf;

pub mod gecko;
pub mod h3_probe;

/// Random salt prepended to every obfuscated datagram.
pub const SALT_LEN: usize = 8;

/// Largest UDP datagram we will receive + de-obfuscate. QUIC keeps datagrams
/// well under this; the extra headroom covers the salt + any Gecko framing.
const RECV_BUF: usize = 2048;

/// Derive the 32-byte obfuscation key from a shared password. Both peers must
/// use the same password (out-of-band / from the invite), exactly like
/// Hysteria2's `obfs.password`.
pub fn key_from_password(password: &[u8]) -> [u8; 32] {
    *blake3::hash(password).as_bytes()
}

/// Derive a per-bridge DEFAULT obfuscation key from the bridge's X25519 static
/// public key. Used when no explicit `quic_obfs_password` is configured so that
/// hysteria2 / h3 obfuscate BY DEFAULT and never put a parseable QUIC handshake
/// on the wire. Client and bridge derive the same key from public material both
/// already hold (the invite carries the bridge pubkey), exactly like the
/// per-bridge cover-SNI derivation (F9-L).
///
/// This defeats generic QUIC-classifying / protocol-fingerprinting DPI. It is
/// NOT a secret against an adversary who already knows the bridge's public key
/// (e.g. holds the invite); set `quic_obfs_password` for a secrecy-grade shared
/// key. Domain-separated (BLAKE3 derive-key mode) from [`key_from_password`] and
/// from the hysteria2 knock token so the three never collide.
pub fn default_obfs_key(bridge_static_pk: &[u8; 32]) -> [u8; 32] {
    blake3::derive_key(
        "mirage quic-obfs default per-bridge key v1",
        bridge_static_pk,
    )
}

/// Fill `out` with keyed-BLAKE3 keystream for `(key, salt)`.
fn keystream(key: &[u8; 32], salt: &[u8], out: &mut [u8]) {
    let mut h = blake3::Hasher::new_keyed(key);
    h.update(salt);
    h.finalize_xof().fill(out);
}

/// Obfuscate `payload` -> `out` = `salt || (payload XOR keystream(key,salt))`.
pub fn salamander_wrap(key: &[u8; 32], payload: &[u8], out: &mut Vec<u8>) {
    out.clear();
    out.resize(SALT_LEN + payload.len(), 0);
    getrandom::fill(&mut out[..SALT_LEN]).expect("OS CSPRNG");
    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&out[..SALT_LEN]);
    // Generate the keystream directly into the output region, then XOR the
    // payload in place - no separate per-datagram keystream allocation.
    keystream(key, &salt, &mut out[SALT_LEN..]);
    for i in 0..payload.len() {
        out[SALT_LEN + i] ^= payload[i];
    }
}

/// De-obfuscate a received datagram IN PLACE. `buf` starts as `salt || xored`;
/// on success `buf[..returned_len]` holds the recovered payload. Returns `None`
/// if the datagram is shorter than the salt (malformed / not ours).
pub fn salamander_unwrap(key: &[u8; 32], buf: &mut [u8]) -> Option<usize> {
    if buf.len() < SALT_LEN {
        return None;
    }
    let plen = buf.len() - SALT_LEN;
    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&buf[..SALT_LEN]);
    // XOR the keystream in fixed stack-sized chunks, moving plaintext down to
    // buf[0..] - no per-datagram heap keystream allocation. Writing buf[off+i]
    // while reading buf[SALT_LEN+off+i] is safe: every absolute index is read
    // (SALT_LEN iterations) before it is later overwritten.
    let mut h = blake3::Hasher::new_keyed(key);
    h.update(&salt);
    let mut reader = h.finalize_xof();
    let mut chunk = [0u8; 1024];
    let mut off = 0;
    while off < plen {
        let n = (plen - off).min(chunk.len());
        reader.fill(&mut chunk[..n]);
        for i in 0..n {
            buf[off + i] = buf[SALT_LEN + off + i] ^ chunk[i];
        }
        off += n;
    }
    Some(plen)
}

/// A `quinn::AsyncUdpSocket` that Salamander-obfuscates every datagram.
///
/// GSO/GRO batching is disabled (`max_*_segments = 1`) so obfuscation is a
/// clean per-datagram transform. quinn stays at a conservative MTU
/// (`may_fragment` defaults true) which absorbs the salt overhead.
pub struct ObfsSocket {
    io: tokio::net::UdpSocket,
    key: [u8; 32],
    /// Gecko reassembly state (interior-mutable: `poll_recv` takes `&self`).
    reasm: std::sync::Mutex<gecko::Reassembler>,
}

impl fmt::Debug for ObfsSocket {
    // The obfuscation `key` is deliberately omitted so it never lands in logs.
    #[allow(clippy::missing_fields_in_debug)]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ObfsSocket")
            .field("local", &self.io.local_addr().ok())
            .finish_non_exhaustive()
    }
}

impl ObfsSocket {
    /// Wrap a bound std UDP socket in the Gecko obfuscator (Salamander XOR +
    /// handshake-packet fragmentation).
    pub fn wrap(std_sock: std::net::UdpSocket, key: [u8; 32]) -> io::Result<Arc<Self>> {
        std_sock.set_nonblocking(true)?;
        let io = tokio::net::UdpSocket::from_std(std_sock)?;
        Ok(Arc::new(Self {
            io,
            key,
            reasm: std::sync::Mutex::new(gecko::Reassembler::new()),
        }))
    }

    /// Salamander-wrap `frame` and send it as one UDP datagram. Returns the
    /// raw `try_send_to` result so the caller can react to `WouldBlock`.
    fn send_frame(&self, frame: &[u8], dest: SocketAddr) -> io::Result<usize> {
        let mut obf = Vec::with_capacity(SALT_LEN + frame.len());
        salamander_wrap(&self.key, frame, &mut obf);
        self.io.try_send_to(&obf, dest)
    }
}

#[derive(Debug)]
struct ObfsPoller(Arc<ObfsSocket>);

impl UdpPoller for ObfsPoller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        self.get_mut().0.io.poll_send_ready(cx)
    }
}

impl AsyncUdpSocket for ObfsSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(ObfsPoller(self))
    }

    fn try_send(&self, transmit: &quinn::udp::Transmit) -> io::Result<()> {
        // GSO is disabled, so `transmit` is a single QUIC datagram.
        let dest = transmit.destination;
        if gecko::should_fragment(transmit.contents) {
            // Long-header (handshake) packet: fragment into 2-8 padded pieces,
            // each Salamander-wrapped as its own datagram - randomises sizes.
            let frames = gecko::fragment(transmit.contents);
            for (i, frame) in frames.iter().enumerate() {
                if let Err(e) = self.send_frame(frame, dest) {
                    if i == 0 {
                        // Nothing sent yet - clean retry of the whole transmit.
                        return Err(e);
                    }
                    // Some fragments already went out; dropping the rest just
                    // costs a QUIC retransmit of this (loss-tolerant) handshake
                    // packet. Report success so quinn doesn't re-fragment+dupe.
                    break;
                }
            }
            Ok(())
        } else {
            // Short-header (data) packet: send whole, single datagram.
            self.send_frame(&gecko::whole(transmit.contents), dest)
                .map(|_| ())
        }
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [std::io::IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        if bufs.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let mut tmp = [0u8; RECV_BUF];
        loop {
            let mut rb = ReadBuf::new(&mut tmp);
            match self.io.poll_recv_from(cx, &mut rb) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(addr)) => {
                    let n = rb.filled().len();
                    let Some(plen) = salamander_unwrap(&self.key, &mut tmp[..n]) else {
                        // Malformed / not-ours datagram - skip, keep polling.
                        continue;
                    };
                    // De-salamandered plaintext is a Gecko frame (WHOLE or a
                    // FRAGMENT). Reassemble; only deliver a completed datagram.
                    let datagram = {
                        let mut r = self.reasm.lock().expect("reassembler mutex");
                        r.accept(&tmp[..plen])
                    };
                    let Some(dg) = datagram else {
                        // Partial fragment group - wait for the rest.
                        continue;
                    };
                    let out = &mut bufs[0];
                    let take = dg.len().min(out.len());
                    out[..take].copy_from_slice(&dg[..take]);
                    meta[0] = RecvMeta {
                        addr,
                        len: take,
                        stride: take,
                        ecn: None,
                        dst_ip: None,
                    };
                    return Poll::Ready(Ok(1));
                }
            }
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.io.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        1
    }

    fn max_receive_segments(&self) -> usize {
        1
    }
}

/// Build a QUIC **client** endpoint whose socket Salamander-obfuscates traffic.
pub fn client_endpoint(bind: SocketAddr, key: [u8; 32]) -> io::Result<quinn::Endpoint> {
    let std_sock = std::net::UdpSocket::bind(bind)?;
    let socket = ObfsSocket::wrap(std_sock, key)?;
    quinn::Endpoint::new_with_abstract_socket(
        quinn::EndpointConfig::default(),
        None,
        socket,
        Arc::new(quinn::TokioRuntime),
    )
}

/// Build a QUIC **server** endpoint whose socket Salamander-obfuscates traffic.
pub fn server_endpoint(
    bind: SocketAddr,
    server_config: quinn::ServerConfig,
    key: [u8; 32],
) -> io::Result<quinn::Endpoint> {
    let std_sock = std::net::UdpSocket::bind(bind)?;
    let socket = ObfsSocket::wrap(std_sock, key)?;
    quinn::Endpoint::new_with_abstract_socket(
        quinn::EndpointConfig::default(),
        Some(server_config),
        socket,
        Arc::new(quinn::TokioRuntime),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn salamander_roundtrips() {
        let key = key_from_password(b"correct horse battery staple");
        for payload in [
            &b""[..],
            &b"a"[..],
            &b"the quick brown fox jumps over the lazy dog"[..],
            &vec![0x42u8; 1200][..],
        ] {
            let mut wire = Vec::new();
            salamander_wrap(&key, payload, &mut wire);
            assert_eq!(wire.len(), SALT_LEN + payload.len());
            // The obfuscated body must not equal the plaintext. Only assert this
            // for payloads long enough that a keystream-equals-zero coincidence
            // is negligible (1/256 per byte): a 1-byte payload would flake ~0.4%
            // of runs otherwise. At >= 8 bytes the collision probability is 2^-64.
            if payload.len() >= 8 {
                assert_ne!(&wire[SALT_LEN..], payload, "payload left in cleartext");
            }
            let mut buf = wire.clone();
            let plen = salamander_unwrap(&key, &mut buf).unwrap();
            assert_eq!(&buf[..plen], payload, "roundtrip mismatch");
        }
    }

    #[test]
    fn distinct_salts_across_wraps() {
        let key = key_from_password(b"pw");
        let mut a = Vec::new();
        let mut b = Vec::new();
        salamander_wrap(&key, b"same payload", &mut a);
        salamander_wrap(&key, b"same payload", &mut b);
        // Random salt => two wraps of the same payload differ on the wire.
        assert_ne!(a, b, "salt not randomised - replayable/linkable");
    }

    #[test]
    fn wrong_key_does_not_recover() {
        let k1 = key_from_password(b"one");
        let k2 = key_from_password(b"two");
        let mut wire = Vec::new();
        salamander_wrap(&k1, b"secret quic packet", &mut wire);
        let mut buf = wire.clone();
        let plen = salamander_unwrap(&k2, &mut buf).unwrap();
        assert_ne!(&buf[..plen], b"secret quic packet");
    }

    #[test]
    fn default_obfs_key_is_deterministic_and_domain_separated() {
        let pk = [0x42u8; 32];
        // Client and bridge derive the SAME key from the (public) bridge pubkey.
        assert_eq!(default_obfs_key(&pk), default_obfs_key(&pk));
        // Different bridges -> different default keys.
        let mut pk2 = pk;
        pk2[0] ^= 0x01;
        assert_ne!(default_obfs_key(&pk), default_obfs_key(&pk2));
        // Domain-separated from a password that happens to equal the pubkey bytes
        // (derive-key mode vs plain hash), so the two derivations never collide.
        assert_ne!(default_obfs_key(&pk), key_from_password(&pk));
    }

    // ---- end-to-end QUIC over the obfuscated socket ----

    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use std::time::Duration;

    #[derive(Debug)]
    struct SkipVerify(Arc<rustls::crypto::CryptoProvider>);
    impl rustls::client::danger::ServerCertVerifier for SkipVerify {
        fn verify_server_cert(
            &self,
            _e: &CertificateDer<'_>,
            _i: &[CertificateDer<'_>],
            _s: &rustls::pki_types::ServerName<'_>,
            _o: &[u8],
            _n: rustls::pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            _m: &[u8],
            _c: &CertificateDer<'_>,
            _d: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }
        fn verify_tls13_signature(
            &self,
            _m: &[u8],
            _c: &CertificateDer<'_>,
            _d: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }
        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            self.0.signature_verification_algorithms.supported_schemes()
        }
    }

    /// Full QUIC connection over TWO obfuscated endpoints, transferring 50 KiB.
    /// Exercises: handshake-packet fragmentation (long-header), the Salamander
    /// XOR, and reassembly - end to end through real quinn.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn quic_roundtrip_over_gecko_socket() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let key = key_from_password(b"shared-obfs-password");

        // Server config: self-signed cert + ALPN h3.
        let ck = rcgen::generate_simple_self_signed(vec!["obfs.test".into()]).unwrap();
        let cert = CertificateDer::from(ck.cert);
        let sk: PrivateKeyDer = PrivatePkcs8KeyDer::from(ck.key_pair.serialize_der()).into();
        let mut stls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert], sk)
            .unwrap();
        stls.alpn_protocols = vec![b"h3".to_vec()];
        let scfg = quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(stls).unwrap(),
        ));
        let server = server_endpoint("127.0.0.1:0".parse().unwrap(), scfg, key).unwrap();
        let addr = server.local_addr().unwrap();

        // Client config: skip-verify + ALPN h3.
        let mut ctls = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(SkipVerify(provider)))
            .with_no_client_auth();
        ctls.alpn_protocols = vec![b"h3".to_vec()];
        let mut client = client_endpoint("127.0.0.1:0".parse().unwrap(), key).unwrap();
        client.set_default_client_config(quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(ctls).unwrap(),
        )));

        let payload: Vec<u8> = (0..50_000u32).map(|i| (i % 251) as u8).collect();
        let payload_c = payload.clone();

        let server_task = tokio::spawn(async move {
            let conn = server.accept().await.unwrap().await.unwrap();
            let (mut send, mut recv) = conn.accept_bi().await.unwrap();
            let got = recv.read_to_end(200_000).await.unwrap();
            send.write_all(&got).await.unwrap();
            send.finish().unwrap();
            tokio::time::sleep(Duration::from_millis(300)).await;
        });

        let conn = client.connect(addr, "obfs.test").unwrap().await.unwrap();
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        send.write_all(&payload_c).await.unwrap();
        send.finish().unwrap();
        let echoed = recv.read_to_end(200_000).await.unwrap();
        assert_eq!(
            echoed, payload,
            "payload did not survive the obfuscated QUIC path"
        );
        server_task.await.unwrap();
    }
}
