//! Traffic-class routing for Mirage.
//!
//! # Why
//!
//! Tor's UX problem is that every byte gets the same treatment: a
//! 3-hop circuit, identical padding, identical transport selection,
//! whether you're loading a search page or trying to stream a video
//! call. Mirage's intelligent-routing layer instead picks a circuit
//! profile **per stream** from a small catalogue of profiles, each
//! making a different anonymity-vs-performance tradeoff.
//!
//! Six classes:
//! - [`Class::Metadata`] - DNS, captcha, `IdP`, well-known fetches.
//! - [`Class::Interactive`] - web, SSH, REST API.
//! - [`Class::Bulk`] - file downloads, package updates, large media.
//! - [`Class::Realtime`] - voice, video, gaming. **2 hops by default**
//!   to meet sub-150 ms latency budget.
//! - [`Class::OnionService`] - `.mirage` destinations.
//! - [`Class::Background`] - sync / updates / cover-traffic carriers.
//!
//! # Property
//!
//! **No silent anonymity downgrade.** A stream is never routed on a
//! profile weaker than its class default unless the user (or an
//! explicit application hint) requested it. Defaults trend toward
//! more anonymity, never less.
//!
//! # Modules
//!
//! - [`class`] - [`Class`] enum + [`ClassHint`] application-hint API.
//! - [`profile`] - [`CircuitProfile`], [`TransportBias`],
//!   [`PaddingProfile`], [`CoverProfile`]; default profiles per class.
//! - [`classifier`] - [`Classifier`] with TCP/UDP port-heuristic
//!   tables and hint override.
//! - [`pool`] - [`CircuitPool`] generic I/O-free state machine that
//!   emits [`PoolAction`]s (build, retire, drain) for the runtime to
//!   execute.
//! - [`policy`] - [`PoolPolicy`] tunables (caps, refresh jitter).
//!
//! # I/O-free
//!
//! Every state machine in this crate is pure logic, mirroring the
//! discipline used in `mirage-mux::state`, `mirage-migration::state`,
//! and `mirage-circuit::split_exit`. The runtime drives I/O and feeds
//! results back via `record_*` methods.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod class;
pub mod classifier;
pub mod policy;
pub mod pool;
pub mod profile;
pub mod selector;

pub use class::{Class, ClassHint};
pub use classifier::{Classifier, Protocol};
pub use policy::{PolicyError, PoolPolicy, RouterPolicy};
pub use pool::{AcquireOutcome, CircuitPool, EntryState, PoolAction, PoolEntry, PoolError};
pub use profile::{
    CircuitProfile, CoverProfile, PaddingProfile, ProfileError, ProfileOverrides, TransportBias,
};
pub use selector::{filter_fresh, BridgeCandidate, HopSelector, SelectorError};
