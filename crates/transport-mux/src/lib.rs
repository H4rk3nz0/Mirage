//! Protocol multiplexer for Mirage: single-port dispatch across all
//! supported transports.
//!
//! # Overview
//!
//! A Mirage bridge listens on a **single TCP port** (typically 443).
//! Every incoming TCP connection is handed to [`ProtocolMux::accept`],
//! which:
//!
//! 1. **Peeks** the first 8 bytes without consuming them.
//! 2. **Classifies** the connection as TLS, HTTP, or opaque.
//! 3. For **TLS / HTTP**: returns the stream immediately with bytes
//!    still in the kernel socket buffer (non-consuming peek).
//! 4. For **opaque** connections: peeks 64 bytes and attempts
//!    transport-level auth (obfs-tcp BLAKE3, then SS-2022 AEAD).
//! 5. Returns [`MuxResult::Unknown`] if nothing matched; the bridge
//!    should proxy the connection to a cover destination.
//!
//! # Protocol priority
//!
//! ```text
//! peek(8 bytes)
//!  +-- 0x16 0x03 ...  -> TLS        -> Reality / TLS handler
//!  +-- GET/POST/...   -> HTTP       -> WebSocket / meek handler
//!  +-- opaque       -> peek(64 B)
//!       +-- obfs-tcp BLAKE3 ok   -> session::accept  [consumes 64 B]
//!       +-- SS-2022 AEAD ok      -> SS-2022 framing  [bytes in buffer]
//!       +-- VLESS UUID ok        -> session::accept  [consumes 26 B + sends 2 B response]
//!       +-- no match             -> cover proxy
//! ```
//!
//! # Quick start
//!
//! ```rust,no_run
//! use std::time::Duration;
//! use mirage_transport_mux::{MuxConfig, MuxResult, ProtocolMux};
//!
//! # async fn example(stream: tokio::net::TcpStream) {
//! let mux = ProtocolMux::new(MuxConfig {
//!     bridge_static_pk: [0u8; 32],
//!     obfs_secret: None,
//!     bridge_static_sk: [0u8; 32],
//!     ss_psk: None,
//!     relay_ss_psk: None,
//!     obfs_enabled: true,
//!     vless_uuid: None,
//! });
//!
//! // A process-wide salt-replay set shared across accepts; rejects a replayed
//! // SS-2022 handshake salt so an active prober can't confirm the bridge.
//! let seen = mirage_transport::SeenNonceSet::new(Duration::from_secs(300));
//! match mux.accept(stream, Duration::from_secs(5), &seen).await {
//!     Ok(MuxResult::Tls(s))                  => { /* REALITY accept */ let _ = s; }
//!     Ok(MuxResult::Http(s))                 => { /* WebSocket / meek */ let _ = s; }
//!     Ok(MuxResult::AuthenticatedObfsTcp(s)) => { /* session::accept */ let _ = s; }
//!     Ok(MuxResult::AuthenticatedShadowsocks(s, _seed)) => { /* SS-2022 session */ let _ = s; }
//!     Ok(MuxResult::AuthenticatedVless(s))   => { /* VLESS session */ let _ = s; }
//!     Ok(MuxResult::Unknown(s))              => { /* proxy to cover */ let _ = s; }
//!     Err(e) => eprintln!("I/O error: {e}"),
//! }
//! # }
//! ```
//!
//! # Crate structure
//!
//! - [`mux`] - [`ProtocolMux`], [`MuxConfig`], [`MuxResult`],
//!   [`ProtocolKind`], and the [`detect_kind`] classification function.
//! - [`prefix`] - [`PrefixedStream`] utility adapter.
//! - [`ss2022`] - internal SS-2022 peek-auth helper (not re-exported).

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod mux;
mod prefix;

pub use mux::{detect_kind, MuxConfig, MuxResult, ProtocolKind, ProtocolMux};
pub use prefix::PrefixedStream;
