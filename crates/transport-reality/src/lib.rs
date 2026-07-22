//! REALITY-v2 transport for Mirage.
//!
//! This crate currently ships the **auth-probe cryptographic layer**:
//! deterministic probe construction + constant-time verification + the
//! bridge-side replay-probe set. TLS ClientHello parsing and the async
//! I/O that splices bytes to the cover destination are deliberately NOT
//! in this commit - they land in a follow-up once the probe layer is
//! stable and thoroughly tested.
//!
//! # Why this split
//!
//! The probe layer is pure crypto and pure data transforms. It can be
//! fully tested without a TCP stack, a TLS parser, or a cover service.
//! Any issue here is a protocol-level bug that affects every deployment.
//!
//! The I/O layer (TLS parsing + destination-side lifecycle per spec §5)
//! is complex and requires integration-level testing against real TLS
//! stacks. Shipping it half-done invites operator error. Shipping the
//! crypto layer first, tested and red-teamed, gives us a stable
//! foundation.
//!
//! # Threat context
//!
//! The core purpose is **bridge-enumeration resistance**. Without
//! REALITY-v2, a scanner can probe any IP with a Mirage ClientHello and
//! see distinctive behavior confirming "bridge here." With REALITY-v2:
//!
//! - Scanners without the bridge's X25519 static pubkey cannot craft a
//!   valid auth probe -> bridge silently proxies their traffic to the
//!   cover destination -> scanner's session is indistinguishable from a
//!   session with the cover destination itself.
//! - Scanners WITH a leaked bridge pubkey can craft valid probes but
//!   still face the session-layer capability-token check; burned probes
//!   also cost them the `(nonce, timestamp)` slot in the replay set.
//!
//! # Module layout
//!
//! - [`probe`] - Probe construction + verification (the 32-byte `session_id` payload)
//! - [`replay`] - Bridge-side replay-probe set
//! - [`error`] - Error types; spec §4 mandates all probe errors MUST fall
//!   through to cover-service forwarding without leaking to the wire

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod carrier;
pub mod cover_probe;
pub mod error;
pub mod paced;
pub mod pacer;
pub mod probe;
pub mod record;
pub mod record_cipher;
pub mod replay;
pub mod shaper;
pub mod tls_cert;
pub mod tls_client_hello;
pub mod tls_client_hello_gen;
pub mod tls_fingerprint;
pub mod tls_handshake_flight;
pub mod tls_keyschedule;
pub mod tls_server_hello;

pub use carrier::{
    reality_accept, reality_connect, AcceptOutcome, BridgeCarrierInputs, CarrierError,
    ClientCarrierInputs, RealityStream, TlsIdentity,
};
pub use cover_probe::{probe_cover_flight, CoverFlightProfile, DEFAULT_COVER_FLIGHT_WIRE_LEN};
pub use error::RealityError;
pub use paced::{
    maybe_pace, maybe_pace_stream, pace_schedule, set_pace_override, MaybePaced, PacedChannel,
    PACE_ENV, PACE_PROFILE_ENV,
};
pub use pacer::{MeasuredProfile, ScheduleStream};
pub use probe::{
    build_probe, derive_probe_root, probe_epoch, verify_probe, BridgeProbeInputs,
    ClientProbeInputs, Probe, NONCE_LEN, PROBE_EPOCH_SECONDS, PROBE_ROOT_DISABLED, SESSION_ID_LEN,
    TAG_LEN, TIMESTAMP_WINDOW_SECONDS,
};
pub use record::{unwrap_app_data, wrap_app_data, Unwrapped, MAX_INNER_PAYLOAD, RECORD_HEADER_LEN};
pub use replay::ReplayProbeSet;
pub use shaper::{
    MarkovProfile, RecordShaper, SplitSource, TrafficProfile, MAX_RECORD_JITTER_MS,
    RECORD_SPLIT_THRESHOLD,
};
pub use tls_client_hello::{parse_client_hello_record, ParsedClientHello, MAX_CLIENT_HELLO_SIZE};
pub use tls_client_hello_gen::{build_client_hello, ClientHelloInputs};
pub use tls_server_hello::{
    build_server_hello, parse_server_hello_record, ServerHelloInputs, ServerHelloParts,
};
