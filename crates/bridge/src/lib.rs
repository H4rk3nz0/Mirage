//! `mirage-bridge` library surface - Phase 2H additions.
//!
//! The crate's binary entry point (`main.rs`) is the production
//! Reality-v2 / obfs-tcp Mirage bridge that does direct SOCKS5
//! exit; it is unchanged. This library target exposes the new
//! circuit-aware `SessionTask` that wraps a `BridgeCircuitState`
//! around a real `mirage_session::SessionStream` and drives the
//! state machine against actual I/O - the building block the
//! daemon needs once it learns to handle multi-hop circuits.
//!
//! # Phase 2H scope
//!
//! - [`session_task::SessionTask`] - one tokio task per accepted
//!   prev-hop session. Owns a `BridgeCircuitState`, reads cells
//!   off the session, dispatches to the state machine, executes
//!   `BridgeAction`s against next-hop transports.
//! - [`next_hop_pool::NextHopPool`] - outbound link cache keyed
//!   by `(next_hop_static_pk, transport_name)`. Multiplexes many
//!   circuits over one bridge-to-bridge `SessionStream`.
//! - [`session_task::DaemonError`] - error taxonomy.
//!
//! # Out of scope (Phase 2H)
//!
//! - Real-traffic proof: the daemon currently forwards raw bytes
//!   for `RelayPayloadAtExit`. Stream dispatch (BEGIN / DATA /
//!   END -> TCP socket) lands in Phase 2I.
//! - Discovery integration: bridges still rely on operator-side
//!   announcements published out-of-band. Phase 3C wires this up.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod circuit_executor;
pub mod cohort_distress;
pub mod cohort_membership;
pub mod cohort_replay;
pub mod leak_detector;
pub mod next_hop_link;
pub mod next_hop_pool;
pub mod probe_defense;
pub mod session_task;
pub mod stream_dispatcher;

pub use circuit_executor::{BridgeCircuitExecutor, BridgeCircuitKeys};
pub use cohort_distress::{
    spawn_gossip_to_distress_map, CohortDistressMonitor, DistressMonitorConfig, DistressSensor,
    ManualDistressSensor, PeerDistressMap,
};
pub use cohort_membership::{
    spawn_gossip_to_live_tracker, CohortHeartbeat, HeartbeatConfig, LivePeerTracker,
};
pub use cohort_replay::{
    spawn_gossip_to_replay_set, CohortReplayCoordinator, MAX_GOSSIP_REPLAY_TTL_SECS,
};
pub use leak_detector::{
    spawn_gossip_to_leak_detector, LeakAlert, LeakDetector, DEFAULT_LEAK_DETECTOR_CAPACITY,
    DEFAULT_LEAK_WINDOW, LEAK_PUBLISHER_THRESHOLD,
};
pub use next_hop_link::{NextHopDialer, NextHopLink, SessionNextHopDialer, SessionStreamLink};
pub use next_hop_pool::{NextHopKey, NextHopPool};
pub use probe_defense::{
    spawn_gossip_to_softblock, ConnectionGatekeeper, GatekeeperConfig, ProbeDetector,
    ProbeDetectorConfig, SoftBlockList,
};
pub use session_task::{DaemonError, SessionTask, SessionTaskConfig};
pub use stream_dispatcher::{
    BeginBody, DataBody, EndBody, StreamDispatcher, StreamError, StreamEvent, StreamId,
    TcpStreamDispatcher, TcpStreamDispatcherConfig,
};
