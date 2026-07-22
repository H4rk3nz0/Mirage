//! Mirage hidden services: addressing + service descriptors +
//! rendezvous wire formats.
//!
//! # Why hidden services
//!
//! A hidden service is a destination addressed by its long-term
//! public key, NOT by an IP address. The service is reachable only
//! through the Mirage circuit network; its actual network location
//! is never disclosed. Tor onion services are the canonical
//! reference; Mirage's design follows Tor v3 conceptually with
//! these adaptations:
//!
//! 1. **PQ-hardened identity.** Tor v3 uses Ed25519 for service
//!    identity; we use the same primitive for backward conceptual
//!    parity, with the caveat that PQ signatures are a v0.2 spec
//!    item (roadmap A6) and will replace the identity scheme then.
//! 2. **Multi-channel descriptor publication.** Tor uses HSDIR
//!    (a designated hidden-service-directory subset of relays).
//!    Mirage publishes service descriptors through the existing
//!    [`mirage_discovery`] channel mesh - reuse, not new infra.
//! 3. **Per-epoch info-hash for descriptors.** Same epoch-rolled
//!    pseudorandom info-hash design as bridge announcements.
//!
//! # Address format
//!
//! `<base32(public_key) || base32(checksum)>.mirage`
//!
//! - 32-byte Ed25519 public key + 2-byte checksum (BLAKE3-keyed
//!   over the pk + a fixed label, truncated to 16 bits).
//! - base32 encoding (RFC 4648 lowercase, no padding).
//! - 56 base32 chars total.
//!
//! Tor v3 used `<pk||cksum||version>.onion`; we omit the version
//! byte because the `.mirage` TLD already implies v1 of this scheme.
//!
//! # Service descriptor
//!
//! See [`descriptor`] for the wire format. The service signs a
//! descriptor with its long-term key; the descriptor lists
//! introduction-point bridges and a rendezvous protocol version.
//! Clients fetch via `info_hash = BLAKE3(b"mirage-onion-desc-v1" ||
//! service_pk || epoch_be)`.
//!
//! # [warn] PARTIAL - descriptor plane sealed + wired; rendezvous NOT live yet
//!
//! The descriptor PUBLICATION plane is now safe to wire: [`publish_descriptor`]
//! seals every descriptor before it touches a channel and [`resolve_descriptor`]
//! unseals on the way back (see below). What is still NOT built is the
//! interactive RENDEZVOUS plane - the introduction-point + rendezvous-point
//! bridge roles, the service-side responder daemon, and the client `.mirage`
//! resolver/SOCKS interception. Until those land, a service cannot actually be
//! reached; this crate delivers the address, descriptor, sealing, and info-hash
//! wire formats (pinned by in-crate vectors) plus the safe publish/resolve path.
//!
//! ## Descriptor sealing - DONE (the former hard prerequisite)
//!
//! [`OnionDescriptor::encode`] emits a **cleartext** structure that begins with
//! the fixed ASCII magic `"MI"` followed by a fixed-layout header (see
//! [`descriptor`]). Published verbatim, that magic + structure is a
//! content-agnostic fingerprint for "this blob is a Mirage onion descriptor" -
//! signatures stop forgery but do nothing to hide it from a passive scraper.
//! [`seal`] closes this: [`seal_descriptor`] wraps the encoded bytes in a
//! ChaCha20-Poly1305 seal keyed by `BLAKE3-keyed(service_pk, epoch)`, so the
//! published blob is indistinguishable from random to anyone who does not
//! already hold the `.mirage` address (the info-hash location is a one-way
//! function of `service_pk`, so a scraper cannot derive the seal key). A
//! resolving client re-derives both the info-hash and the seal key from the
//! address it is looking up. [`publish_descriptor`] / [`resolve_descriptor`]
//! seal / unseal automatically - the publication plane no longer leaks the
//! `MI` magic. Per-CLIENT authorization (only specific clients may resolve) is
//! a separate additive layer, deliberately out of scope.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod address;
pub mod descriptor;
pub mod introduce;
pub mod publish;
pub mod seal;

pub use address::{onion_address_to_pk, pk_to_onion_address, AddressError, ONION_ADDRESS_SUFFIX};
pub use descriptor::{
    onion_descriptor_info_hash, IntroPoint, OnionDescriptor, ServiceDescError, MAX_INTRO_POINTS,
};
pub use introduce::{IntroduceCell, IntroduceError};
pub use publish::{publish_descriptor, resolve_descriptor, OnionDiscoveryError};
pub use seal::{seal_descriptor, unseal_descriptor, SealError};
