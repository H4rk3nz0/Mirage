//! Cover-flight size profiling for the Reality authenticated path.
//!
//! # The tell this closes
//!
//! On the authenticated path the bridge synthesises its own TLS 1.3 server
//! flight - `EncryptedExtensions || Certificate || CertificateVerify ||
//! Finished` - and ships it as a single encrypted `application_data` record.
//! With a minimal self-signed leaf that flight is ~600 bytes on the wire. A
//! *real* cover destination serves a CA-issued chain (leaf + one or two
//! intermediates, SCTs, sometimes an OCSP staple): its flight is 3-6 KB.
//!
//! Although the flight is encrypted, each `TLSCiphertext` record carries a
//! cleartext 5-byte header whose length field is in the clear. A passive censor
//! who also fetches the real cover therefore measures two very different
//! encrypted-flight sizes - a reliable authenticated-path distinguisher that
//! survives the byte-exact ClientHello/ServerHello parroting.
//!
//! # The fix
//!
//! Learn the cover's real flight size once (this module) and pad the bridge's
//! own flight up to it with TLS 1.3 record padding (RFC 8446 §5.4 - zero bytes
//! after the inner content-type, explicitly sanctioned for traffic-analysis
//! defence). Padding only grows a record, and the bridge's natural flight is
//! always smaller than a real chain, so a single padded record matches the
//! cover's total size exactly. The Mirage client strips the padding
//! transparently (see [`crate::tls_handshake_flight::strip_inner_content_type`]),
//! so no wire-format change is visible to it.
//!
//! Residual: this matches the cover's *total* encrypted-flight bytes with one
//! record. A cover that fragments its flight into several records leaves a
//! weaker record-*count* signal; a single sub-16 KB flight record is itself
//! common (nginx and many CDNs coalesce the flight), so this is a minor,
//! stack-dependent residual next to the order-of-magnitude size tell it closes.
//!
//! # How the size is measured
//!
//! The probe opens a real connection to the cover, sends a browser-parrot
//! ClientHello (the same generator [`crate::reality_connect`] uses), and reads
//! records until the server goes idle waiting for the client's Finished. It
//! sums the wire length of every `application_data` (0x17) record - the
//! encrypted flight - and ignores the cleartext ServerHello (0x16) and
//! middlebox-compat ChangeCipherSpec (0x14). The probe never completes the
//! handshake: eliciting the flight needs nothing but a well-formed ClientHello.
//!
//! It is best-effort. Any failure (cover down, TLS 1.2 fallback, timeout)
//! yields [`CoverFlightProfile::DEFAULT`], whose generic ~3.5 KB target is
//! still far closer to a real cover than the un-padded ~600-byte flight.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::tls_client_hello_gen::{build_client_hello, ClientHelloInputs};
use crate::tls_fingerprint::{self, GreaseValues};

/// Fallback target for the encrypted server-flight wire size (bytes) when a
/// cover cannot be probed. ~3.5 KB approximates a mainstream CDN's ECDSA leaf
/// plus one intermediate. Still vastly more plausible than an un-padded
/// ~600-byte self-signed flight.
pub const DEFAULT_COVER_FLIGHT_WIRE_LEN: usize = 3500;

/// Idle gap after which the server's flight is considered complete. Records
/// within a flight arrive back-to-back (one server write); once the flight is
/// done the server blocks waiting for our Finished, which we never send, so a
/// read that stalls this long means "flight over". Also bounds the first-read
/// wait for the ServerHello (a full RTT plus server processing).
const IDLE_GAP: Duration = Duration::from_millis(1200);

/// Hard cap on total bytes read from a cover during profiling. A cooperative
/// TLS 1.3 flight is a few KB; this only guards against a hostile/broken peer
/// streaming forever.
const TOTAL_READ_CAP: usize = 128 * 1024;

/// Largest plausible `TLSCiphertext` record on the wire: 2^14 payload + 256
/// AEAD/expansion slack + the 5-byte header (RFC 8446 §5.2).
const MAX_RECORD_WIRE: usize = 5 + 16_384 + 256;

/// TLS record content types we classify while profiling.
const REC_CHANGE_CIPHER_SPEC: u8 = 0x14;
const REC_ALERT: u8 = 0x15;
const REC_HANDSHAKE: u8 = 0x16;
const REC_APPLICATION_DATA: u8 = 0x17;

/// Measured size profile of a cover destination's TLS 1.3 server flight.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoverFlightProfile {
    /// Total wire bytes of the cover's post-ServerHello encrypted flight - the
    /// sum of its `application_data` record wire lengths (headers and AEAD tags
    /// included). This is exactly what a passive censor measures, and what the
    /// bridge pads its own flight to match.
    pub flight_wire_len: usize,
    /// The cover's per-`application_data`-record wire sizes, in order (M1). Lets
    /// the bridge reproduce the cover's record FRAMING (count + sizes), not just
    /// the total, when it can do so without breaking its own handshake. Empty
    /// when unprofiled (the [`DEFAULT`](Self::DEFAULT) fallback).
    pub record_wire_lens: Vec<usize>,
}

impl CoverFlightProfile {
    /// Generic fallback used when a cover cannot be profiled.
    pub const DEFAULT: Self = Self {
        flight_wire_len: DEFAULT_COVER_FLIGHT_WIRE_LEN,
        record_wire_lens: Vec::new(),
    };
}

/// Profile `cover_addr`'s TLS 1.3 server flight, returning its wire size + the
/// per-record framing.
///
/// Best-effort and time-bounded by `overall_timeout`: on any error, TLS 1.2
/// fallback, or timeout it returns [`CoverFlightProfile::DEFAULT`] so a flaky
/// cover never stalls bridge startup or leaves the flight un-padded.
pub async fn probe_cover_flight(
    cover_addr: SocketAddr,
    server_name: &str,
    overall_timeout: Duration,
) -> CoverFlightProfile {
    match tokio::time::timeout(overall_timeout, measure_flight(cover_addr, server_name)).await {
        Ok(Ok((len, records))) if len > 0 => CoverFlightProfile {
            flight_wire_len: len,
            record_wire_lens: records,
        },
        _ => CoverFlightProfile::DEFAULT,
    }
}

/// One measurement attempt: connect, send a parrot ClientHello, and sum the
/// wire length of the cover's encrypted-flight records. Also returns the
/// per-`application_data`-record wire sizes (M1: so the bridge can reproduce the
/// cover's record FRAMING, not just its total).
async fn measure_flight(
    cover_addr: SocketAddr,
    server_name: &str,
) -> std::io::Result<(usize, Vec<usize>)> {
    let mut stream = TcpStream::connect(cover_addr).await?;
    stream.set_nodelay(true).ok();

    let ch = build_probe_client_hello(server_name)
        .map_err(|_| std::io::Error::other("build ClientHello"))?;
    stream.write_all(&ch).await?;
    stream.flush().await?;

    let mut flight_wire = 0usize;
    let mut record_wires: Vec<usize> = Vec::new();
    let mut total_read = 0usize;
    loop {
        // Read the 5-byte record header. A stall here means the server has sent
        // its whole flight and is waiting for our Finished => flight complete.
        let mut hdr = [0u8; 5];
        match tokio::time::timeout(IDLE_GAP, read_full(&mut stream, &mut hdr)).await {
            Ok(Ok(())) => {}
            _ => break,
        }
        let rec_type = hdr[0];
        let len = ((hdr[3] as usize) << 8) | hdr[4] as usize;
        let wire = 5 + len;
        if wire > MAX_RECORD_WIRE {
            break; // malformed / not a TLS peer we can profile
        }

        let mut body = vec![0u8; len];
        match tokio::time::timeout(IDLE_GAP, read_full(&mut stream, &mut body)).await {
            Ok(Ok(())) => {}
            _ => break,
        }
        total_read += wire;

        match rec_type {
            // Encrypted flight (EncryptedExtensions..Finished, and any 0.5-RTT
            // records the server emits before our Finished). This is the tell.
            REC_APPLICATION_DATA => {
                flight_wire += wire;
                record_wires.push(wire);
            }
            // Fatal alert (e.g. the cover rejected our ClientHello): stop.
            REC_ALERT => break,
            // Cleartext ServerHello and middlebox-compat CCS are not part of the
            // encrypted flight the censor measures; skip without counting.
            REC_HANDSHAKE | REC_CHANGE_CIPHER_SPEC => {}
            // Unknown record type: not a TLS 1.3 flight we understand.
            _ => break,
        }
        if total_read > TOTAL_READ_CAP {
            break;
        }
    }
    Ok((flight_wire, record_wires))
}

/// Read exactly `buf.len()` bytes or fail. Wraps [`AsyncReadExt::read_exact`],
/// mapping a clean EOF to an error so the caller treats it as "flight over".
async fn read_full(stream: &mut TcpStream, buf: &mut [u8]) -> std::io::Result<()> {
    stream.read_exact(buf).await.map(|_| ())
}

/// Build a browser-parrot ClientHello for the probe: a fresh ephemeral X25519
/// share, a random session id, a population-weighted fingerprint template, and
/// a real hybrid ML-KEM key_share - byte-shaped like a real client so the
/// bridge's outbound startup probes are themselves indistinguishable from a
/// browser opening the cover site.
fn build_probe_client_hello(server_name: &str) -> Result<Vec<u8>, crate::error::RealityError> {
    let mut random = [0u8; 32];
    let mut session_id = [0u8; 32];
    let mut sk_bytes = [0u8; 32];
    getrandom::fill(&mut random).map_err(|_| crate::error::RealityError::ZeroPoint)?;
    getrandom::fill(&mut session_id).map_err(|_| crate::error::RealityError::ZeroPoint)?;
    getrandom::fill(&mut sk_bytes).map_err(|_| crate::error::RealityError::ZeroPoint)?;

    let sk = mirage_crypto::x25519_dalek::StaticSecret::from(sk_bytes);
    let pk = *mirage_crypto::x25519_dalek::PublicKey::from(&sk).as_bytes();

    let (mlkem_ek_obj, _mlkem_dk) = mirage_crypto::hybrid_kem::generate_keypair();
    let mlkem_ek = mlkem_ek_obj.to_bytes();

    build_client_hello(&ClientHelloInputs {
        random: &random,
        session_id: &session_id,
        x25519_key_share: &pk,
        server_name,
        include_alpn: true,
        fingerprint: tls_fingerprint::pick_weighted_template(),
        grease: Some(GreaseValues::random()),
        mlkem_ek: Some(&mlkem_ek),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    // The default must sit in the multi-KB CA-chain range, never the tiny
    // self-signed-flight size it replaces. Enforced at compile time.
    const _: () = assert!(DEFAULT_COVER_FLIGHT_WIRE_LEN >= 2000);

    #[test]
    fn default_profile_is_plausible_chain_size() {
        assert_eq!(
            CoverFlightProfile::DEFAULT.flight_wire_len,
            DEFAULT_COVER_FLIGHT_WIRE_LEN
        );
    }

    #[test]
    fn probe_client_hello_is_a_valid_parseable_clienthello() {
        // The probe must emit a ClientHello a real server accepts; parse it back
        // through our own parser as a proxy for well-formedness.
        let ch = build_probe_client_hello("cover.example.com").unwrap();
        let parsed = crate::tls_client_hello::parse_client_hello_record(&ch).unwrap();
        assert_eq!(parsed.x25519_key_share.len(), 32);
        assert_eq!(parsed.session_id.len(), 32);
    }

    #[tokio::test]
    async fn unreachable_cover_yields_default() {
        // Port 1 on loopback: connection refused ~instantly. Best-effort probe
        // must fall back to DEFAULT rather than error out.
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let prof = probe_cover_flight(addr, "cover.example.com", Duration::from_secs(2)).await;
        assert_eq!(prof, CoverFlightProfile::DEFAULT);
    }

    #[tokio::test]
    async fn counts_application_data_records_only() {
        // Stand up a fake "cover" that, after receiving a ClientHello, emits a
        // cleartext handshake record (ServerHello-like, 0x16), a CCS (0x14), and
        // two application_data records (0x17) that are the "flight", then goes
        // idle. The probe must sum ONLY the two 0x17 records' wire sizes.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            // Drain the ClientHello (best-effort; one read is enough for a test).
            let mut scratch = [0u8; 4096];
            let _ = sock.read(&mut scratch).await;
            // 0x16 handshake record, body 40 bytes (NOT counted).
            let mut sh = vec![0x16, 0x03, 0x03, 0x00, 40];
            sh.extend(std::iter::repeat_n(0xAB, 40));
            sock.write_all(&sh).await.unwrap();
            // 0x14 CCS record, body 1 byte (NOT counted).
            sock.write_all(&[0x14, 0x03, 0x03, 0x00, 0x01, 0x01])
                .await
                .unwrap();
            // Two 0x17 application_data records, bodies 100 and 60 bytes. Wire
            // sizes = 105 and 65 => flight total 170.
            let mut f1 = vec![0x17, 0x03, 0x03, 0x00, 100];
            f1.extend(std::iter::repeat_n(0xCD, 100));
            sock.write_all(&f1).await.unwrap();
            let mut f2 = vec![0x17, 0x03, 0x03, 0x00, 60];
            f2.extend(std::iter::repeat_n(0xEF, 60));
            sock.write_all(&f2).await.unwrap();
            sock.flush().await.unwrap();
            // Go idle (hold the socket open) so the probe's idle-gap fires.
            tokio::time::sleep(Duration::from_secs(3)).await;
        });

        let prof = probe_cover_flight(addr, "cover.example.com", Duration::from_secs(5)).await;
        assert_eq!(
            prof.flight_wire_len, 170,
            "must count only the two 0x17 records"
        );
        server.abort();
    }
}
