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
//! # [warn] NOT ON A LIVE PATH - pre-integration (connection migration is NOT live)
//!
//! **This crate is a complete, tested state machine that is wired
//! into nothing.** No crate depends on `mirage-migration`, and
//! nothing anywhere constructs a [`MigrationState`] on a live path
//! (verified by grep - the only references outside this crate are
//! doc-comment mentions). Release notes and readers MUST NOT assume
//! Mirage performs live connection migration: today a Wi-Fi -> cell
//! handoff still forces a full tunnel re-handshake.
//!
//! v0.1w ships the data types + state machine only. Wiring requires a
//! UDP/MASQUE transport that keys received datagrams by [`Cid`]
//! instead of by 5-tuple; that transport is scaffolded but does not
//! yet ship live I/O.
//!
//! **Exact wiring step (the documented v0.2 task):** in the
//! UDP/MASQUE transport's accept/receive loop, on each inbound
//! datagram (1) parse its [`Cid`], (2) look up the connection by CID
//! rather than by source 5-tuple, and (3) when the CID arrives from a
//! new `(src_ip, src_port)`, drive [`MigrationState`] - emit a
//! [`PathChallenge`] to the new path and only migrate once the
//! matching [`PathResponse`] validates it (anti-spoof), subject to
//! the [`MigrationPolicy`] rate cap. Until that accept loop exists
//! and calls into this state machine, this crate is inert.
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
