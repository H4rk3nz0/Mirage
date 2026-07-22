//! Minimal RFC 1928 SOCKS5 server.
//!
//! Scope: just enough to make a Mirage bridge a general outbound
//! proxy. A client app (curl, a browser, a Tor-like tool) speaks
//! SOCKS5 to the mirage-client daemon, which forwards raw bytes over
//! an encrypted Mirage session to a bridge; the bridge runs THIS
//! module over the decrypted stream and opens a TCP connection to
//! the destination the client named.
//!
//! # Supported
//!
//! - Version: 5 only.
//! - Auth methods: `NO AUTHENTICATION REQUIRED` (0x00).
//! - Commands: `CONNECT` (0x01) only. `BIND` and `UDP ASSOCIATE` are
//!   rejected with `Command not supported` (0x07).
//! - Address types: IPv4 (0x01), IPv6 (0x04), DOMAIN (0x03).
//!
//! # Deliberately NOT supported
//!
//! - Username/password auth (RFC 1929). If a Mirage operator wants
//!   per-user access control, the capability-token layer is the
//!   right place, not SOCKS5 auth.
//! - UDP relay. Mirage sessions are TCP-like; UDP-over-Mirage lives
//!   in a separate transport in v0.2.
//! - GSSAPI. Out of scope.
//!
//! # Threat-model notes
//!
//! - **The client is a black box to us.** Nothing the SOCKS5 client
//!   asserts about itself is authenticated - the capability-token
//!   layer already authenticated the Mirage peer. If an attacker
//!   has already reached our SOCKS5 handler, they have a valid
//!   token. Access control below the auth boundary is coarse.
//! - **Destination filtering is policy, not protocol.** Operators
//!   may want to block SSRF targets (link-local, loopback, RFC 1918)
//!   or rate-limit per-session destination count. The module exposes
//!   [`AllowlistPolicy`] for callers; it defaults to "block
//!   loopback + link-local + RFC 1918" to keep a fresh deployment
//!   from being trivially weaponized as an internal-network
//!   scanner.
//! - **DNS resolution happens on the bridge.** A DOMAIN request
//!   name is resolved via the OS resolver on the bridge. Operators
//!   who don't trust their upstream resolver should configure DoT /
//!   DoH at the OS level; this crate doesn't carry its own.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod copy;
pub mod server;
pub mod udp_dgram;

pub use copy::copy_bidirectional_idle;
pub use server::{
    connect_and_reply, connect_target, read_request, send_success_reply_for_internal,
    serve_one_connect, AllowlistPolicy, ConnectRequest, ConnectTarget, Socks5Error,
};
pub use udp_dgram::{
    decode as decode_udp_dgram, decode_owned as decode_udp_dgram_owned, encode as encode_udp_dgram,
    Socks5UdpDest, Socks5UdpDgram, Socks5UdpDgramError, MAX_UDP_DOMAIN_BYTES,
};

/// SOCKS5 version byte. Only `5` is accepted.
pub const VERSION: u8 = 0x05;

/// Auth method: no authentication required (RFC 1928 §3).
pub const METHOD_NO_AUTH: u8 = 0x00;

/// Auth method sentinel: no acceptable methods (RFC 1928 §3).
pub const METHOD_NO_ACCEPTABLE: u8 = 0xFF;

/// SOCKS5 command: CONNECT.
pub const CMD_CONNECT: u8 = 0x01;
/// SOCKS5 command: BIND (unsupported).
pub const CMD_BIND: u8 = 0x02;
/// SOCKS5 command: UDP ASSOCIATE (unsupported).
pub const CMD_UDP: u8 = 0x03;

/// Address type: IPv4.
pub const ATYP_IPV4: u8 = 0x01;
/// Address type: domain name.
pub const ATYP_DOMAIN: u8 = 0x03;
/// Address type: IPv6.
pub const ATYP_IPV6: u8 = 0x04;

/// Reply byte: success.
pub const REP_SUCCEEDED: u8 = 0x00;
/// Reply byte: general SOCKS server failure.
pub const REP_GENERAL_FAILURE: u8 = 0x01;
/// Reply byte: connection not allowed by ruleset.
pub const REP_NOT_ALLOWED: u8 = 0x02;
/// Reply byte: network unreachable.
pub const REP_NET_UNREACHABLE: u8 = 0x03;
/// Reply byte: host unreachable.
pub const REP_HOST_UNREACHABLE: u8 = 0x04;
/// Reply byte: connection refused.
pub const REP_CONN_REFUSED: u8 = 0x05;
/// Reply byte: TTL expired.
pub const REP_TTL_EXPIRED: u8 = 0x06;
/// Reply byte: command not supported.
pub const REP_CMD_NOT_SUPPORTED: u8 = 0x07;
/// Reply byte: address type not supported.
pub const REP_ATYP_NOT_SUPPORTED: u8 = 0x08;
