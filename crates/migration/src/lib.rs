//! Connection-migration primitives for Mirage.
//!
//! # Why
//!
//! A laptop user crossing the Wi-Fi -> cell handoff today forces
//! Mirage to re-handshake the entire tunnel: fresh transport dial,
//! fresh Mirage session, fresh circuit if multi-hop. That's
//! several round-trips of latency (5-10 seconds in practice) for
//! what's mechanically just an IP-address change.
//!
//! QUIC (RFC 9000 §5) solves this with **Connection IDs (CIDs)**:
//! every QUIC packet carries an opaque CID; the server matches by
//! CID, not by 5-tuple. When a client moves to a new IP, the
//! server sees the same CID from a new (`src_ip`, `src_port`) tuple
//! and migrates the connection - no re-handshake.
//!
//! Mirage adopts the same primitive. This crate ships:
//!
//! - [`Cid`] - random 16-byte connection identifier.
//! - [`PathChallenge`] / [`PathResponse`] - anti-spoofing
//!   handshake before fully migrating to a new path.
//! - [`MigrationState`] - tracks current and alternate paths,
//!   manages the validation state machine.
//! - [`MigrationPolicy`] - operator-tunable thresholds
//!   (validation timeout, max-migration-rate, etc).
//!
//! # [warn] SUPERSEDED - do not wire this; QUIC already does it
//!
//! **This crate is a complete, tested state machine that should not be
//! wired, because the thing it implements already works.** Nothing depends
//! on it and nothing constructs a [`MigrationState`] on a live path.
//!
//! The v0.2 task this crate was written for - "key inbound datagrams by
//! [`Cid`] instead of by 5-tuple, then validate the new path" - is
//! precisely what QUIC does natively, and Mirage's QUIC carriers get it
//! from `quinn` for free. Checked, rather than assumed:
//!
//! - `ObfsSocket::poll_recv` passes the REAL source address through to
//!   quinn in `RecvMeta.addr`, so obfuscation does not hide a path change
//!   from the layer that handles it.
//! - No `.migration(false)` call exists anywhere in the workspace, so
//!   quinn's default - migration ENABLED, with its own `PATH_CHALLENGE`
//!   validation and rate limiting - is what runs.
//!
//! So wiring this crate into hysteria2 or h3/MASQUE would build a second,
//! weaker path-validation stack underneath one that already works. And for
//! the TCP carriers (Reality, WebSocket, SS-2022) it cannot help at all: a
//! TCP connection is bound to its 5-tuple and cannot migrate by any means.
//!
//! ## What WOULD be worth building, and is not this
//!
//! The genuinely missing capability is one layer up: resuming a **Mirage
//! session** across a fresh carrier connection without a full re-handshake,
//! so a Wi-Fi -> cell handoff costs one round trip instead of a fresh
//! Noise/ML-KEM exchange on a new TCP socket. QUIC does not provide that,
//! because the session is Mirage's, not QUIC's.
//!
//! That is a different design - session resumption keyed on a
//! resumption secret, with replay defence - and these types
//! ([`Cid`], [`PathChallenge`]) are a reasonable starting point for it, but
//! it is not what this crate implements today. Until someone builds it,
//! treat this crate as reference material rather than pending work.
//!
//! # Threat-model fit
//!
//! - **Path-spoofing attack**: an attacker on the new path
//!   sending a forged Mirage packet with the correct CID
//!   convinces the bridge to migrate. Mitigation: `PATH_CHALLENGE`
//!   forces the new path to prove it can receive (anti-spoof,
//!   like QUIC's path validation).
//! - **Migration-flood `DoS`**: an attacker rapidly migrates the
//!   connection across many fake IPs to spend bridge resources.
//!   Mitigation: `max_migrations_per_minute` rate cap.
//! - **CID linkability**: a CID that's stable for a connection's
//!   lifetime lets a network-vantage observer correlate flows
//!   across the migration. Mitigation: per-epoch CID rotation
//!   (the receiver issues fresh CIDs via a control message; old
//!   CID retired after a grace window). Spec'd here, integration
//!   in v0.2.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod challenge;
pub mod cid;
pub mod policy;
pub mod state;

pub use challenge::{PathChallenge, PathResponse, CHALLENGE_LEN};
pub use cid::{Cid, CidPair, CID_LEN};
pub use policy::{MigrationPolicy, DEFAULT_VALIDATION_TIMEOUT_MS};
pub use state::{MigrationDecision, MigrationError, MigrationState, PathState};
