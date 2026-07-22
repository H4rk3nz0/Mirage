//! Nostr channel adapter for the Mirage discovery layer.
//!
//! Implements the wire-level protocol side of the Nostr discovery channel:
//!
//! - NIP-01 event wire format (`kind` = per-epoch derived in the
//!   `30000`-`39999` parametric-replaceable window; see `mirage_event_kind`).
//! - NIP-40 event expiration.
//! - BIP-340 Schnorr signing/verification over secp256k1.
//! - Mirage sealed-blob <-> Nostr event conversion.
//!
//! This crate is **I/O-free**: no WebSocket client, no async relay loop.
//! The network layer ships separately (planned as `mirage-discovery-nostr-async`
//! or added here behind a feature flag) once the `DiscoveryChannel` trait
//! is stabilized.
//!
//! # Module layout
//!
//! - [`event`] - `NostrEvent`, canonical ID computation (NIP-01)
//! - [`signing`] - BIP-340 Schnorr keypair + sign/verify
//! - [`wrap`] - publish / unpack Mirage-announcement events
//! - [`error`] - `NostrError`

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod error;
pub mod event;
pub mod relay;
pub mod signing;
pub mod wrap;

pub use error::NostrError;
pub use event::{NostrEvent, NostrEventParts, MIRAGE_EVENT_KIND};
pub use signing::{
    sign_event_id, verify_schnorr, NostrSigningKey, NOSTR_PUBKEY_LEN, NOSTR_SIG_LEN,
};
pub use wrap::{
    build_announcement_event, unpack_announcement_event, UnpackedAnnouncement, TAG_D,
    TAG_EXPIRATION,
};
