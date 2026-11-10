//! Full DNS-tunnel (dnstt-style) transport for Mirage.
//!
//! # Why
//!
//! When a network permits *only* DNS (port 53 to the local resolver) - the
//! hardest censorship case - every other Mirage carrier is blocked, but a DNS
//! tunnel still works: the client encodes upstream bytes into DNS **query
//! names** (base32 labels under a tunnel domain) and reads downstream bytes out
//! of **TXT answers**. Because these are real DNS questions, a recursive
//! resolver forwards them to the authoritative name server for the tunnel
//! domain - the Mirage bridge - so the bridge needs no reachable IP of its own,
//! only an NS delegation. This is the model of David Fifield's `dnstt`.
//!
//! # Layers
//!
//! 1. [`dns`] - real DNS wire-format codec (query-name/TXT encode+decode).
//! 2. `arq` (next) - a reliable, ordered byte stream over the lossy,
//!    reordering, request-response DNS channel: sequence numbers, ACKs,
//!    retransmission, and client-side polling (DNS can't push).
//! 3. The transport (next) - a client dialer + bridge handler presenting an
//!    `AsyncRead + AsyncWrite` carrier that the Mirage session rides on. The
//!    Mirage session already provides the Noise + PQ crypto, so this tunnel
//!    only needs to move bytes reliably.
//!
//! Status: DNS codec landed + tested; ARQ + transport are being built.

#![forbid(unsafe_code)]
// Byte-level DNS/packet framing with explicit length checks; indexing and
// integer byte-arithmetic are intentional. Docs reference protocol terms
// (DNS, TXT, base32, dnstt, ARQ, EDNS) that would otherwise trip doc_markdown.
#![allow(
    clippy::indexing_slicing,
    clippy::doc_markdown,
    clippy::integer_division
)]

pub mod arq;
pub mod dns;
pub mod stream;
pub mod transport;

/// Default DNS record-data budget per response before EDNS(0) is needed. Plain
/// DNS/UDP caps a message at 512 bytes; the tunnel stays under this until EDNS
/// negotiation lands.
pub const DNS_UDP_MAX: usize = 512;
