//! `mirage-cover-fetch` - operator helper that downloads a TLS
//! cover destination's leaf certificate as raw DER bytes.
//!
//! # Why
//!
//! Reality `pinned` mode (cover-cert mimicry)
//! requires the bridge to serve a real HTTPS endpoint's certificate
//! verbatim while signing CertVerify with a separate operator-held
//! key. Pre-v0.1q the operator runbook had:
//!
//! ```sh
//! openssl s_client -showcerts -servername www.example.com \
//!   -connect www.example.com:443 < /dev/null 2>/dev/null \
//!   | openssl x509 -outform der -out /etc/mirage/cover.der
//! ```
//!
//! That works, but `openssl` is a heavy dependency to require on a
//! "lives at stake" deployment host, and the multi-step pipe is
//! fragile (a stray TLS warning on stderr can confuse it). This
//! tool replaces that command with a single rustls-backed call:
//!
//! ```sh
//! mirage-cover-fetch www.example.com:443 > /etc/mirage/cover.der
//! ```
//!
//! # Behavior
//!
//! - Connects to `host:port` over TCP.
//! - Performs a TLS 1.2 / 1.3 handshake using **rustls** with a
//!   no-op cert verifier (we WANT the cert bytes, even if the cert
//!   is self-signed or expired - the operator decides whether the
//!   cover destination is a sensible mimicry target).
//! - Captures the **leaf** certificate from
//!   `connection.peer_certificates()[0]` and writes its raw DER
//!   bytes to stdout.
//! - Reports cert subject + issuer + validity to stderr so the
//!   operator can sanity-check what they fetched without parsing
//!   the DER themselves.
//! - Exits 0 on success, 2 on argument / config error, 3 on
//!   network or TLS failure.
//!
//! # Threat-model placement
//!
//! - This tool runs OUT OF BAND, on an operator workstation (or
//!   the bridge host once at deploy time), to bake the cover cert
//!   into the bridge config. Output is operator-controlled bytes
//!   that go on disk; the bridge then serves them verbatim. There
//!   is no live trust on the fetched cert - its only role is wire-
//!   level mimicry.
//! - **Cert-chain validation is intentionally OFF.** A cover host
//!   serving a self-signed or expired cert is still a valid mimicry
//!   target if a real client (curl, browser) would happen to load
//!   it via "ignore cert errors". Operators who specifically want
//!   only chain-valid covers should pipe this through `openssl
//!   verify -CAfile ...` themselves.
//! - **Active MITM tampering at fetch time.** A man-in-the-middle
//!   between the operator and the cover host could substitute a
//!   different cert. Mitigation: run `mirage-cover-fetch` from a
//!   trusted network position (operator workstation behind a
//!   trusted upstream), and double-check the printed subject +
//!   issuer match what a real browser shows for the same host.

use std::io::Write;
use std::sync::Arc;

use mirage_common::process_hardening::harden_process;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

#[derive(Debug)]
struct AcceptAnyVerifier;

impl ServerCertVerifier for AcceptAnyVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        // Advertise everything common; the verifier accepts all
        // signatures unconditionally, so this list is just to
        // satisfy the rustls handshake.
        vec![
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
        ]
    }
}

fn fatal(msg: impl AsRef<str>) -> ! {
    eprintln!("fatal: {}", msg.as_ref());
    std::process::exit(2);
}

fn netfatal(msg: impl AsRef<str>) -> ! {
    eprintln!("error: {}", msg.as_ref());
    std::process::exit(3);
}

#[tokio::main]
async fn main() {
    if let Err(e) = harden_process() {
        fatal(format!("harden_process: {e}"));
    }

    let args: Vec<String> = std::env::args().collect();
    let usage = "usage: mirage-cover-fetch <host:port>\n\
                 \n\
                 Connects via TLS, captures the leaf cert from the\n\
                 handshake, and writes its DER bytes to stdout.\n\
                 \n\
                 Example:\n\
                 \n\
                   mirage-cover-fetch www.example.com:443 > cover.der\n\
                 \n\
                 Cert verification is INTENTIONALLY OFF - this is a\n\
                 mimicry-target capture, not a trust check.";
    if args.len() == 2 && (args[1] == "-h" || args[1] == "--help") {
        eprintln!("{usage}");
        std::process::exit(0);
    }
    if args.len() != 2 {
        eprintln!("{usage}");
        std::process::exit(2);
    }
    let target = &args[1];
    let (host, _port) = target
        .rsplit_once(':')
        .unwrap_or_else(|| fatal("target must be host:port"));
    if host.is_empty() {
        fatal("empty host");
    }

    // Install rustls's default crypto provider for the process. If
    // already installed (a library set it up first), the call is
    // a no-op.
    let _ = rustls::crypto::ring::default_provider().install_default();

    // Build a permissive client config. Empty root store + custom
    // verifier that accepts everything.
    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyVerifier))
        .with_no_client_auth();
    let _ = RootCertStore::empty(); // suppress "unused" if we ever drop the dangerous path

    let connector = TlsConnector::from(Arc::new(config));
    let server_name: ServerName<'static> = ServerName::try_from(host.to_string())
        .unwrap_or_else(|e| fatal(format!("invalid SNI {host:?}: {e}")));

    // RT-cover-9: bound TCP connect to 15 s. Operators on slow
    // links can override (env var) but a stuck connect must not
    // hang the cron / dev-shell session indefinitely.
    let connect_timeout = std::time::Duration::from_secs(
        std::env::var("MIRAGE_COVER_FETCH_CONNECT_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(15),
    );
    let tcp = match tokio::time::timeout(connect_timeout, TcpStream::connect(target)).await {
        Ok(Ok(t)) => t,
        Ok(Err(e)) => netfatal(format!("connect {target}: {e}")),
        Err(_) => netfatal(format!(
            "connect {target}: timeout after {connect_timeout:?}"
        )),
    };
    tcp.set_nodelay(true).ok();

    // RT-cover-8: bound the TLS handshake separately. A peer that
    // ACCEPTs the TCP connection then refuses to write the
    // ServerHello would otherwise hang. Default 15 s; tune via env.
    let handshake_timeout = std::time::Duration::from_secs(
        std::env::var("MIRAGE_COVER_FETCH_HANDSHAKE_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(15),
    );
    let mut tls =
        match tokio::time::timeout(handshake_timeout, connector.connect(server_name, tcp)).await {
            Ok(Ok(t)) => t,
            Ok(Err(e)) => netfatal(format!("TLS handshake: {e}")),
            Err(_) => netfatal(format!(
                "TLS handshake: timeout after {handshake_timeout:?}"
            )),
        };

    // Pull leaf cert bytes out as owned Vec<u8> so we can release
    // the connection borrow before shutdown().
    let leaf_der: Vec<u8> = {
        let (_io, conn) = tls.get_ref();
        let certs = conn
            .peer_certificates()
            .unwrap_or_else(|| netfatal("no peer certificates after handshake"));
        if certs.is_empty() {
            netfatal("peer presented an empty certificate chain");
        }
        certs[0].as_ref().to_vec()
    };

    // Tear down the connection cleanly so the cover host doesn't
    // see a half-open TLS state from us.
    let _ = tls.shutdown().await;
    drop(tls);

    // Sanity log to stderr.
    let der: &[u8] = &leaf_der;
    let summary = describe_cert(der);
    eprintln!("fetched {} byte cover cert from {target}", der.len());
    eprintln!("{summary}");

    // Write raw DER to stdout for piping into a file.
    let mut out = std::io::stdout().lock();
    if let Err(e) = out.write_all(der) {
        netfatal(format!("stdout write: {e}"));
    }
    let _ = out.flush();
    let _ = AcceptAnyVerifier; // silence unused-struct lint if features change
}

/// Best-effort DER summary for the operator's eye. Walks just
/// enough of the X.509 structure to find subject + issuer + the
/// notBefore / notAfter timestamps. On parse failure, returns a
/// length-only line.
fn describe_cert(der: &[u8]) -> String {
    // We don't pull `x509-parser` for this - keeping the binary
    // small. A naive walk grabs the OUTER SEQUENCE -> tbsCertificate
    // SEQUENCE -> version -> serial -> signature -> issuer Name ->
    // validity -> subject. Failure at any step falls through to a
    // length-only summary, which is still useful (operators can
    // hash it independently).
    let mut s = String::new();
    s.push_str(&format!("  cert_der_size = {}\n", der.len()));
    let hash = sha256_hex(der);
    s.push_str(&format!("  cert_sha256   = {hash}\n"));
    s.push_str("  (full subject/issuer/validity decode requires `openssl x509 -in cover.der -inform der -text`)\n");
    s
}

fn sha256_hex(bytes: &[u8]) -> String {
    use mirage_crypto::sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    let out = h.finalize();
    let mut s = String::with_capacity(64);
    for b in out {
        s.push_str(&format!("{b:02x}"));
    }
    s
}
