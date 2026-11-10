//! Probe-scan detection + cohort-wide soft-block enforcement.
//!
//! # Why
//!
//! A censor's prober makes contact with a suspected Mirage
//! bridge, sends a malformed / unauthenticated message, and
//! measures the response. If the response looks Mirage-shaped
//! (specific timing or error pattern), the censor adds the IP to
//! a block list. The defense - once a bridge sees a probe
//! pattern from a source IP - is to **stop responding** to that
//! IP for a cool-down window so the prober can't gather signal.
//!
//! Without cohort cooperation, each bridge runs its detector
//! independently: a scanner hammering 3 cohort bridges sees
//! the same "first-time-this-IP" response from each. With this
//! module + [`mirage_discovery::CohortGossip`], a probe detected
//! at entry A propagates to B and C within gossip latency, and
//! the scanner immediately hits soft-block at every cohort
//! member.
//!
//! # Components
//!
//! - [`ProbeDetector`] - sliding-window auth-failure counter per
//!   source IP. Bridge calls
//!   [`ProbeDetector::record_auth_failure`] on each failed
//!   handshake; when an IP exceeds the threshold within the
//!   window, [`ProbeDetector::is_probe`] returns true.
//! - [`SoftBlockList`] - IP -> expiry map. Bridge calls
//!   [`SoftBlockList::should_block`] before doing real work; if
//!   hit, the bridge tarpits / fast-closes the connection.
//!
//! Wiring (caller's responsibility - kept out of these
//! primitives to remain transport-agnostic):
//!
//! 1. On accept: check [`SoftBlockList::should_block`].
//!    If true, close immediately.
//! 2. On handshake fail:
//!    [`ProbeDetector::record_auth_failure`].
//! 3. If the detector signals a new probe IP, publish a
//!    `ProbeScanDetected` event via `CohortGossip`.
//! 4. Subscriber task on `CohortGossip` adds incoming
//!    `ProbeScanDetected` IPs to the local `SoftBlockList`.

use mirage_crypto::ed25519_dalek::SigningKey;
use mirage_discovery::cohort_gossip::{CohortGossip, GossipEvent, SignedGossipEvent};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

/// Detector configuration.
#[derive(Debug, Clone)]
pub struct ProbeDetectorConfig {
    /// Sliding window over which auth failures are counted.
    pub window: Duration,
    /// Number of failures within `window` that mark the IP as
    /// a probe.
    pub threshold: u32,
    /// How long to keep an IP flagged as a probe after the
    /// detection. Probe-flag expiry is separate from `window`
    /// so a brief burst still keeps the IP flagged longer than
    /// the burst's tail.
    pub probe_flag_duration: Duration,
    /// Maximum number of distinct source IPs tracked. Closes
    /// RT-PD-1: a scanner with many distinct source IPs
    /// (botnet / IPv6) would otherwise grow `failures` without
    /// bound. When the cap is reached, the oldest-touched
    /// entry is evicted before a new one is inserted.
    pub max_tracked_ips: usize,
    /// Maximum number of failure timestamps kept per IP. A
    /// scanner that sends 10000 failures from one IP would
    /// otherwise grow this Vec without bound; capping it
    /// preserves the threshold semantics (we only need
    /// `threshold` entries to make a decision) without
    /// allocating beyond that.
    pub max_failures_per_ip: usize,
}

impl Default for ProbeDetectorConfig {
    fn default() -> Self {
        Self {
            window: Duration::from_secs(60),
            threshold: 5,
            probe_flag_duration: Duration::from_secs(60 * 60),
            max_tracked_ips: 8192,
            max_failures_per_ip: 16,
        }
    }
}

/// Upper bound on entries scanned when evicting from a full tracking
/// map (RT-PD-2). Keeps the auth-failure path O(1) under a distinct-IP
/// flood instead of O(tracked_ips). Mirrors `rate_limit::EVICT_SAMPLE`.
const EVICT_SAMPLE: usize = 32;

/// Sliding-window probe detector. Records auth failures per
/// source IP; an IP that hits `threshold` failures within
/// `window` is flagged as a probe for `probe_flag_duration`.
pub struct ProbeDetector {
    inner: Arc<Mutex<ProbeDetectorInner>>,
    config: ProbeDetectorConfig,
}

struct ProbeDetectorInner {
    /// IP -> most-recent failure timestamps.
    failures: HashMap<IpAddr, Vec<Instant>>,
    /// IPs flagged as probes, with their most-recent flag time.
    flagged: HashMap<IpAddr, Instant>,
}

impl std::fmt::Debug for ProbeDetector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProbeDetector")
            .field("config", &self.config)
            .field("inner", &"<locked>")
            .finish()
    }
}

impl ProbeDetector {
    /// Construct.
    pub fn new(config: ProbeDetectorConfig) -> Self {
        Self {
            inner: Arc::new(Mutex::new(ProbeDetectorInner {
                failures: HashMap::new(),
                flagged: HashMap::new(),
            })),
            config,
        }
    }

    /// Record an auth failure from `ip`. Returns true iff this
    /// failure pushed the IP over threshold and flagged it as a
    /// probe for the first time (transition edge). The caller
    /// SHOULD publish a `ProbeScanDetected` gossip event only on
    /// the edge - not on every subsequent failure from an
    /// already-flagged IP.
    pub async fn record_auth_failure(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let window = self.config.window;
        let max_tracked = self.config.max_tracked_ips;
        let max_per_ip = self.config.max_failures_per_ip;
        let mut g = self.inner.lock().await;

        // RT-PD-1: enforce the global IP cap. When at capacity
        // and the IP isn't already tracked, evict the entry
        // with the oldest most-recent failure (approximate LRU
        // using the existing timestamps - no separate access
        // log).
        if !g.failures.contains_key(&ip) && g.failures.len() >= max_tracked {
            // RT-PD-2 (mirrors rate_limit RT #18): bound the eviction scan. A
            // full `min_by_key` over the whole map ran on EVERY new-IP failure
            // once full - i.e. O(n) under a distinct-IP flood, the exact
            // scenario that fills the map, amplifying lock-hold time on the
            // auth-failure path. Approximate-LRU: examine only the first
            // EVICT_SAMPLE entries and evict the oldest among them. Any entry
            // is a valid victim here, so no full-scan fallback is needed.
            if let Some(victim) = g
                .failures
                .iter()
                .take(EVICT_SAMPLE)
                .min_by_key(|(_, ts)| ts.last().copied().unwrap_or_else(Instant::now))
                .map(|(k, _)| *k)
            {
                g.failures.remove(&victim);
            }
        }
        let entry = g.failures.entry(ip).or_default();
        entry.retain(|t| now.saturating_duration_since(*t) <= window);
        entry.push(now);
        // RT-PD-1: cap per-IP failure history; only the most
        // recent `max_per_ip` entries are needed since
        // threshold is checked by len.
        if entry.len() > max_per_ip {
            let excess = entry.len() - max_per_ip;
            entry.drain(0..excess);
        }
        let count = entry.len() as u32;
        if count < self.config.threshold {
            return false;
        }
        let already_flagged = match g.flagged.get(&ip) {
            Some(t) => now.saturating_duration_since(*t) <= self.config.probe_flag_duration,
            None => false,
        };
        // RT-PD-1: cap the flagged set the same way.
        if !g.flagged.contains_key(&ip) && g.flagged.len() >= max_tracked {
            // RT-PD-2: same bounded approximate-LRU as the failures map above.
            if let Some(victim) = g
                .flagged
                .iter()
                .take(EVICT_SAMPLE)
                .min_by_key(|(_, t)| **t)
                .map(|(k, _)| *k)
            {
                g.flagged.remove(&victim);
            }
        }
        g.flagged.insert(ip, now);
        !already_flagged
    }

    /// True iff `ip` is currently flagged as a probe.
    pub async fn is_probe(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let g = self.inner.lock().await;
        match g.flagged.get(&ip) {
            Some(t) => now.saturating_duration_since(*t) <= self.config.probe_flag_duration,
            None => false,
        }
    }

    /// Sweep stale entries.
    pub async fn reap(&self) -> usize {
        let now = Instant::now();
        let window = self.config.window;
        let flag_dur = self.config.probe_flag_duration;
        let mut g = self.inner.lock().await;
        let before = g.failures.len() + g.flagged.len();
        g.failures.retain(|_, ts| {
            ts.retain(|t| now.saturating_duration_since(*t) <= window);
            !ts.is_empty()
        });
        g.flagged
            .retain(|_, t| now.saturating_duration_since(*t) <= flag_dur);
        let after = g.failures.len() + g.flagged.len();
        before - after
    }

    /// Number of currently-flagged IPs (diagnostic).
    pub async fn flagged_count(&self) -> usize {
        let g = self.inner.lock().await;
        g.flagged.len()
    }
}

/// Default cap on the SoftBlockList - see [`SoftBlockList::with_capacity`].
/// 16384 blocked IPs uses ~600 KiB of HashMap and is well above
/// any legitimate cohort gossip rate (RT-PD-2).
pub const DEFAULT_SOFTBLOCK_CAPACITY: usize = 16_384;

/// A list of soft-blocked source IPs with expiries. The bridge
/// consults this on accept; if hit, it tarpits / fast-closes
/// the connection so the prober can't gather signal.
pub struct SoftBlockList {
    inner: Arc<Mutex<HashMap<IpAddr, Instant>>>,
    capacity: usize,
}

impl std::fmt::Debug for SoftBlockList {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SoftBlockList")
            .field("capacity", &self.capacity)
            .field("inner", &"<locked>")
            .finish()
    }
}

impl Default for SoftBlockList {
    fn default() -> Self {
        Self::new()
    }
}

impl SoftBlockList {
    /// Construct with the default capacity
    /// ([`DEFAULT_SOFTBLOCK_CAPACITY`]).
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_SOFTBLOCK_CAPACITY)
    }

    /// Construct with explicit max entry cap. When `add` would
    /// exceed `capacity`, the entry with the soonest expiry is
    /// evicted first. Closes RT-PD-2 - a malicious authorized
    /// peer can no longer poison unbounded entries.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            capacity,
        }
    }

    /// Add `ip` to the block list, expiring after `expire_in`.
    /// If a longer-lived entry already exists for this IP, the
    /// later expiry wins. If adding would push the list past
    /// `capacity`, evicts the soonest-expiring existing entry
    /// first (RT-PD-2). Uses `checked_add` so a maliciously
    /// large `expire_in` saturates at `Instant::now() +
    /// MAX_PROBE_SOFTBLOCK_SECS` rather than panicking.
    pub async fn add(&self, ip: IpAddr, expire_in: Duration) {
        let now = Instant::now();
        let expire_in = expire_in.min(Duration::from_secs(MAX_PROBE_SOFTBLOCK_SECS as u64));
        let expires_at = now
            .checked_add(expire_in)
            .unwrap_or_else(|| now + Duration::from_secs(60));
        let mut g = self.inner.lock().await;
        if !g.contains_key(&ip) && g.len() >= self.capacity {
            if let Some(victim) = g.iter().min_by_key(|(_, t)| **t).map(|(k, _)| *k) {
                g.remove(&victim);
            }
        }
        match g.get_mut(&ip) {
            Some(existing) if *existing >= expires_at => {} // keep longer
            _ => {
                g.insert(ip, expires_at);
            }
        }
    }

    /// True iff `ip` is currently blocked (entry exists AND
    /// expiry is in the future).
    pub async fn should_block(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let g = self.inner.lock().await;
        match g.get(&ip) {
            Some(expires_at) => *expires_at > now,
            None => false,
        }
    }

    /// Sweep expired entries.
    pub async fn reap(&self) -> usize {
        let now = Instant::now();
        let mut g = self.inner.lock().await;
        let before = g.len();
        g.retain(|_, expires_at| *expires_at > now);
        before - g.len()
    }

    /// Count of currently-blocked IPs (diagnostic).
    pub async fn len(&self) -> usize {
        self.inner.lock().await.len()
    }

    /// True iff the list is empty.
    pub async fn is_empty(&self) -> bool {
        self.inner.lock().await.is_empty()
    }
}

/// Spawn a subscriber that listens on `gossip` and adds every
/// inbound [`GossipEvent::ProbeScanDetected`] source IP to
/// `list` with the event's `expire_secs` TTL. Other events are
/// dropped silently (this helper is single-purpose; callers
/// wanting `TokenBurned` or `EntryDistressed` listeners spawn
/// their own subscriber).
///
/// Returns the [`JoinHandle`] so the caller can abort on
/// shutdown. The task exits when the gossip channel is closed
/// or when the returned handle is aborted.
/// Hard cap on the `expire_secs` field of an inbound
/// `ProbeScanDetected` event. A malicious authorized peer could
/// otherwise send `expire_secs = u32::MAX` (~136 years) to
/// poison the cohort's soft-block list permanently against
/// arbitrary IPs. 24 hours is the longest legitimate block
/// duration we accept (RT-PD-2).
pub const MAX_PROBE_SOFTBLOCK_SECS: u32 = 24 * 3600;

/// Distinct authorized cohort bridges that must INDEPENDENTLY report the
/// same source IP (within [`PROBE_REPORT_WINDOW`]) before a *gossiped*
/// `ProbeScanDetected` soft-blocks it cohort-wide.
///
/// A single compromised/coerced bridge can sign a `ProbeScanDetected` for
/// any victim IP; without a quorum that one event would soft-block an
/// arbitrary client across the whole cohort for up to 24 h, turning a
/// defensive primitive into a censorship lever (RT #14). Requiring
/// agreement from >= this many distinct publishers keeps it cooperative -
/// the same distinct-publisher discipline the leak detector already uses.
/// (A bridge's OWN locally-observed probe still soft-blocks ITS OWN accepts
/// immediately via `observe_auth_failure`; that is first-party evidence and
/// is not gated here.)
pub const PROBE_SOFTBLOCK_QUORUM: usize = 2;

/// Window over which distinct-publisher reports for one IP are counted
/// toward [`PROBE_SOFTBLOCK_QUORUM`].
pub const PROBE_REPORT_WINDOW: Duration = Duration::from_secs(600);

/// Cap on source IPs being voted on, bounding memory if a hostile peer
/// gossips reports for a flood of distinct victim IPs.
const PROBE_QUORUM_CAPACITY: usize = 4096;

/// Tracks distinct-publisher agreement on gossiped probe reports.
struct ProbeReportQuorum {
    reports: std::sync::Mutex<HashMap<IpAddr, HashMap<[u8; 32], Instant>>>,
    window: Duration,
    quorum: usize,
    capacity: usize,
}

impl ProbeReportQuorum {
    fn new(window: Duration, quorum: usize, capacity: usize) -> Self {
        Self {
            reports: std::sync::Mutex::new(HashMap::new()),
            window,
            quorum,
            capacity: capacity.max(1),
        }
    }

    /// Record that `publisher` reported `source_ip`; returns true iff, after
    /// pruning reports older than the window, >= `quorum` DISTINCT publishers
    /// have reported this IP. One publisher replaying cannot reach quorum
    /// (the map keys on the authenticated publisher pk).
    fn record(&self, source_ip: IpAddr, publisher: [u8; 32]) -> bool {
        let now = Instant::now();
        let Ok(mut g) = self.reports.lock() else {
            return false;
        };
        if !g.contains_key(&source_ip) && g.len() >= self.capacity {
            if let Some(victim) = g
                .iter()
                .min_by_key(|(_, pubs)| pubs.values().max().copied())
                .map(|(k, _)| *k)
            {
                g.remove(&victim);
            }
        }
        let pubs = g.entry(source_ip).or_default();
        pubs.retain(|_, t| now.saturating_duration_since(*t) <= self.window);
        pubs.insert(publisher, now);
        pubs.len() >= self.quorum
    }
}

/// Subscribe to `gossip` and apply incoming `ProbeScanDetected` events
/// to `list`, blocking the offending IP for the soft-block duration -
/// but only once [`PROBE_SOFTBLOCK_QUORUM`] distinct publishers agree.
pub fn spawn_gossip_to_softblock(
    gossip: Arc<dyn CohortGossip>,
    list: Arc<SoftBlockList>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut rx = gossip.subscribe().await;
        let quorum = ProbeReportQuorum::new(
            PROBE_REPORT_WINDOW,
            PROBE_SOFTBLOCK_QUORUM,
            PROBE_QUORUM_CAPACITY,
        );
        loop {
            match rx.recv().await {
                Ok(signed) => {
                    // Defense-in-depth: re-verify even though the transport
                    // should only deliver verified events.
                    if signed.verify(&signed.publisher_ed_pk).is_err() {
                        continue;
                    }
                    let publisher = signed.publisher_ed_pk;
                    if let GossipEvent::ProbeScanDetected {
                        source_ip,
                        expire_secs,
                        ..
                    } = signed.event
                    {
                        // RT #14: require a distinct-publisher quorum before a
                        // gossiped report soft-blocks cohort-wide.
                        if !quorum.record(source_ip, publisher) {
                            tracing::debug!(
                                %source_ip,
                                "cohort gossip: probe report below quorum; not blocking yet"
                            );
                            continue;
                        }
                        let clamped = expire_secs.min(MAX_PROBE_SOFTBLOCK_SECS);
                        list.add(source_ip, Duration::from_secs(clamped as u64))
                            .await;
                        tracing::debug!(
                            %source_ip,
                            expire_secs = clamped,
                            "cohort gossip: soft-blocking probe source (quorum reached)"
                        );
                    }
                }
                // RT-PD-5: don't die silently when a slow
                // subscriber falls behind the broadcast channel
                // - log and continue. A censor that floods
                // gossip can no longer disable this defense by
                // outrunning us.
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    tracing::warn!(skipped = n, "gossip subscriber lagged; some events skipped");
                    continue;
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
            }
        }
    })
}

/// Configuration for a [`ConnectionGatekeeper`].
#[derive(Debug, Clone)]
pub struct GatekeeperConfig {
    /// Probe detector tuning.
    pub detector: ProbeDetectorConfig,
    /// How long peers (and the local bridge) should soft-block
    /// a freshly-detected probe IP. Defaults to 1 hour.
    pub probe_block_duration: Duration,
    /// How often the background ticker reaps stale entries.
    /// Defaults to 60 s.
    pub reap_interval: Duration,
    /// Set when the bridge has a shadow/cover posture (a `shadow_target`,
    /// `http_shadow_target`, or Reality cover is configured) so that every
    /// rejected connection is byte-faithfully answered like a decoy.
    ///
    /// When `true`, soft-blocking is DISABLED (RT #9): the accept-time bare
    /// drop that a soft-block triggers happens *before* the mux/shadow/cover
    /// logic, so a soft-blocked IP's subsequent connections get a bare
    /// RST/close instead of the decoy response - exactly the distinguisher
    /// the shadow path exists to remove. Soft-blocking (bare-drop) and
    /// shadow-forwarding are mutually exclusive: with a shadow configured,
    /// auth failures fall through to the decoy and never feed the
    /// soft-block list. Probe detection still *counts* for metrics.
    pub shadow_active: bool,
}

impl Default for GatekeeperConfig {
    fn default() -> Self {
        Self {
            detector: ProbeDetectorConfig::default(),
            probe_block_duration: Duration::from_secs(60 * 60),
            reap_interval: Duration::from_secs(60),
            shadow_active: false,
        }
    }
}

/// One-call API the bridge daemon uses on every accept +
/// every failed handshake. Wires [`ProbeDetector`] +
/// [`SoftBlockList`] + a [`CohortGossip`] publisher / subscriber
/// pair into a single composable object so individual bridges
/// don't have to re-implement the cooperation glue.
///
/// Owns a [`SigningKey`] (the bridge's identity) so it can sign
/// outbound `ProbeScanDetected` events without exposing the key.
pub struct ConnectionGatekeeper {
    detector: Arc<ProbeDetector>,
    softblock: Arc<SoftBlockList>,
    gossip: Arc<dyn CohortGossip>,
    signing_key: SigningKey,
    config: GatekeeperConfig,
    _subscriber: JoinHandle<()>,
    _reaper: JoinHandle<()>,
}

impl std::fmt::Debug for ConnectionGatekeeper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectionGatekeeper")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl ConnectionGatekeeper {
    /// Build. Spawns a background gossip->softblock subscriber
    /// task AND a periodic reaper task. Both are aborted when
    /// the gatekeeper is dropped.
    pub fn new(
        gossip: Arc<dyn CohortGossip>,
        signing_key: SigningKey,
        config: GatekeeperConfig,
    ) -> Self {
        let detector = Arc::new(ProbeDetector::new(config.detector.clone()));
        let softblock = Arc::new(SoftBlockList::new());
        let subscriber = spawn_gossip_to_softblock(gossip.clone(), softblock.clone());
        let reaper = {
            let detector = detector.clone();
            let softblock = softblock.clone();
            let interval = config.reap_interval;
            tokio::spawn(async move {
                let mut ticker = tokio::time::interval(interval);
                ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                ticker.tick().await; // skip the first immediate tick
                loop {
                    ticker.tick().await;
                    let det_reaped = detector.reap().await;
                    let sb_reaped = softblock.reap().await;
                    if det_reaped + sb_reaped > 0 {
                        tracing::debug!(
                            det_reaped,
                            sb_reaped,
                            "ConnectionGatekeeper reaper swept stale entries"
                        );
                    }
                }
            })
        };
        Self {
            detector,
            softblock,
            gossip,
            signing_key,
            config,
            _subscriber: subscriber,
            _reaper: reaper,
        }
    }

    /// Pre-accept check. Returns true iff the bridge should
    /// proceed with handshake for `peer_ip`. Call this before
    /// touching the wire.
    ///
    /// With a shadow/cover posture (`shadow_active`) this ALWAYS returns
    /// true: a bare accept-time drop would be a distinguisher vs. the decoy
    /// the bridge otherwise presents, so rejected/probed connections must
    /// instead flow on to the mux->shadow/cover path (RT #9).
    pub async fn should_accept(&self, peer_ip: IpAddr) -> bool {
        if self.config.shadow_active {
            return true;
        }
        !self.softblock.should_block(peer_ip).await
    }

    /// Post-handshake-failure callback. Records the failure;
    /// if this is the threshold-crossing edge, publishes a
    /// signed `ProbeScanDetected` and adds the IP to the local
    /// soft-block list (so the next accept from this IP
    /// fast-closes without waiting for the gossip echo).
    pub async fn observe_auth_failure(&self, peer_ip: IpAddr) {
        let edge = self.detector.record_auth_failure(peer_ip).await;
        // Shadow posture: never soft-block (and never gossip a block). A
        // soft-block would bare-drop this IP's future connections before the
        // shadow/cover path runs, re-introducing the very bridge-vs-decoy
        // distinguisher the shadow removes (RT #9). Detection still counted
        // above for metrics; the action is suppressed.
        if self.config.shadow_active {
            return;
        }
        if !edge {
            return;
        }
        // Local soft-block first (lockstep with our own
        // detection - no dependency on gossip propagation).
        self.softblock
            .add(peer_ip, self.config.probe_block_duration)
            .await;
        // Then publish so peers can match.
        let event = GossipEvent::ProbeScanDetected {
            source_ip: peer_ip,
            expire_secs: self.config.probe_block_duration.as_secs() as u32,
            detected_at: unix_now(),
        };
        let signed = SignedGossipEvent::sign(event, &self.signing_key);
        self.gossip.publish(signed).await;
        tracing::info!(
            %peer_ip,
            expire_secs = self.config.probe_block_duration.as_secs(),
            "ConnectionGatekeeper: probe detected, published ProbeScanDetected"
        );
    }

    /// Diagnostic snapshot: (probe_flag_count, softblock_count).
    pub async fn snapshot(&self) -> (usize, usize) {
        (
            self.detector.flagged_count().await,
            self.softblock.len().await,
        )
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(n: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, n))
    }

    #[tokio::test]
    async fn detector_flags_after_threshold() {
        let det = ProbeDetector::new(ProbeDetectorConfig {
            threshold: 3,
            ..Default::default()
        });
        assert!(!det.record_auth_failure(ip(1)).await);
        assert!(!det.record_auth_failure(ip(1)).await);
        // Third failure crosses threshold -> edge returns true.
        assert!(det.record_auth_failure(ip(1)).await);
        // Fourth: already flagged.
        assert!(!det.record_auth_failure(ip(1)).await);
        assert!(det.is_probe(ip(1)).await);
    }

    #[tokio::test]
    async fn detector_isolates_per_ip() {
        let det = ProbeDetector::new(ProbeDetectorConfig {
            threshold: 2,
            ..Default::default()
        });
        det.record_auth_failure(ip(1)).await;
        det.record_auth_failure(ip(1)).await;
        det.record_auth_failure(ip(2)).await;
        assert!(det.is_probe(ip(1)).await);
        assert!(!det.is_probe(ip(2)).await);
    }

    #[tokio::test]
    async fn detector_reap_drops_old_entries() {
        let det = ProbeDetector::new(ProbeDetectorConfig {
            threshold: 100,
            window: Duration::from_millis(50),
            probe_flag_duration: Duration::from_millis(50),
            ..Default::default()
        });
        det.record_auth_failure(ip(1)).await;
        det.record_auth_failure(ip(2)).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        let reaped = det.reap().await;
        assert!(reaped >= 2, "expected to reap stale entries, got {reaped}");
    }

    #[tokio::test]
    async fn softblock_blocks_then_expires() {
        let list = SoftBlockList::new();
        assert!(!list.should_block(ip(1)).await);
        list.add(ip(1), Duration::from_millis(50)).await;
        assert!(list.should_block(ip(1)).await);
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(!list.should_block(ip(1)).await);
    }

    #[tokio::test]
    async fn softblock_reap_drops_expired_entries() {
        let list = SoftBlockList::new();
        list.add(ip(1), Duration::from_millis(20)).await;
        list.add(ip(2), Duration::from_secs(60)).await;
        tokio::time::sleep(Duration::from_millis(60)).await;
        let reaped = list.reap().await;
        assert_eq!(reaped, 1);
        assert!(!list.should_block(ip(1)).await);
        assert!(list.should_block(ip(2)).await);
    }

    #[tokio::test]
    async fn softblock_add_keeps_longer_expiry() {
        let list = SoftBlockList::new();
        list.add(ip(1), Duration::from_secs(60)).await;
        // Shorter add MUST NOT shorten the existing entry.
        list.add(ip(1), Duration::from_millis(10)).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(list.should_block(ip(1)).await);
    }

    #[tokio::test]
    async fn softblock_add_extends_to_later_expiry() {
        let list = SoftBlockList::new();
        list.add(ip(1), Duration::from_millis(10)).await;
        list.add(ip(1), Duration::from_secs(60)).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(list.should_block(ip(1)).await);
    }

    #[tokio::test]
    async fn gossip_subscriber_populates_softblock() {
        use mirage_crypto::ed25519_dalek::SigningKey;
        use mirage_discovery::cohort_gossip::{MemoryGossip, SignedGossipEvent};

        let mg = Arc::new(MemoryGossip::new());
        let list = Arc::new(SoftBlockList::new());
        let _task = spawn_gossip_to_softblock(mg.clone() as Arc<dyn CohortGossip>, list.clone());

        // Two distinct authorized publishers (RT #14 quorum = 2).
        let mk = || {
            let mut seed = [0u8; 32];
            getrandom::fill(&mut seed).unwrap();
            SigningKey::from_bytes(&seed)
        };
        let sk_a = mk();
        let sk_b = mk();
        mg.authorize(sk_a.verifying_key().to_bytes()).await;
        mg.authorize(sk_b.verifying_key().to_bytes()).await;

        // Give the subscriber a moment to wire up.
        tokio::time::sleep(Duration::from_millis(10)).await;

        let report = |sk: &SigningKey| {
            SignedGossipEvent::sign(
                GossipEvent::ProbeScanDetected {
                    source_ip: ip(42),
                    expire_secs: 3600,
                    detected_at: unix_now(),
                },
                sk,
            )
        };

        // One report from publisher A is BELOW quorum - must NOT block.
        mg.publish(report(&sk_a)).await;
        tokio::time::sleep(Duration::from_millis(40)).await;
        assert!(
            !list.should_block(ip(42)).await,
            "a single publisher's report must not reach quorum (RT #14)"
        );

        // A second DISTINCT publisher reaches quorum -> soft-block.
        mg.publish(report(&sk_b)).await;
        for _ in 0..50 {
            if list.should_block(ip(42)).await {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(
            list.should_block(ip(42)).await,
            "subscriber should soft-block once a distinct-publisher quorum is reached"
        );

        // Non-ProbeScanDetected events do NOT pollute the list.
        let unrelated = GossipEvent::TokenBurned {
            token_id: [0xCC; 32],
            burned_at: unix_now(),
        };
        let signed_unrelated = SignedGossipEvent::sign(unrelated, &sk_a);
        mg.publish(signed_unrelated).await;
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(list.len().await, 1, "unrelated events must not add IPs");
    }

    fn fresh_sk() -> SigningKey {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).unwrap();
        SigningKey::from_bytes(&seed)
    }

    #[tokio::test]
    async fn gatekeeper_flags_then_blocks_locally() {
        use mirage_discovery::cohort_gossip::MemoryGossip;
        let gossip = Arc::new(MemoryGossip::new());
        let sk = fresh_sk();
        gossip.authorize(sk.verifying_key().to_bytes()).await;
        let gk = ConnectionGatekeeper::new(
            gossip.clone() as Arc<dyn CohortGossip>,
            sk,
            GatekeeperConfig {
                detector: ProbeDetectorConfig {
                    threshold: 3,
                    ..Default::default()
                },
                probe_block_duration: Duration::from_secs(60),
                reap_interval: Duration::from_secs(60),
                shadow_active: false,
            },
        );
        let bad = ip(7);
        assert!(gk.should_accept(bad).await);
        for _ in 0..3 {
            gk.observe_auth_failure(bad).await;
        }
        // After the 3rd failure (edge), local softblock fires.
        assert!(!gk.should_accept(bad).await);
        let (flagged, blocked) = gk.snapshot().await;
        assert_eq!(flagged, 1);
        assert_eq!(blocked, 1);
    }

    #[tokio::test]
    async fn gatekeeper_publishes_probe_event_on_edge() {
        use mirage_discovery::cohort_gossip::MemoryGossip;
        let gossip = Arc::new(MemoryGossip::new());
        let sk = fresh_sk();
        gossip.authorize(sk.verifying_key().to_bytes()).await;
        let gk = ConnectionGatekeeper::new(
            gossip.clone() as Arc<dyn CohortGossip>,
            sk.clone(),
            GatekeeperConfig {
                detector: ProbeDetectorConfig {
                    threshold: 2,
                    ..Default::default()
                },
                probe_block_duration: Duration::from_secs(60),
                reap_interval: Duration::from_secs(60),
                shadow_active: false,
            },
        );
        let mut rx = gossip.subscribe().await;
        gk.observe_auth_failure(ip(9)).await; // pre-edge
        gk.observe_auth_failure(ip(9)).await; // edge
        let signed = tokio::time::timeout(Duration::from_millis(100), rx.recv())
            .await
            .expect("gatekeeper should publish")
            .expect("channel open");
        match signed.event {
            GossipEvent::ProbeScanDetected { source_ip, .. } => {
                assert_eq!(source_ip, ip(9));
            }
            other => panic!("expected ProbeScanDetected, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn detector_evicts_oldest_when_at_cap() {
        // RT-PD-1: distinct IPs beyond max_tracked_ips force
        // eviction of the oldest-touched entry.
        let det = ProbeDetector::new(ProbeDetectorConfig {
            threshold: 100,
            max_tracked_ips: 3,
            window: Duration::from_secs(60),
            probe_flag_duration: Duration::from_secs(60),
            max_failures_per_ip: 16,
        });
        for n in 1..=10u8 {
            det.record_auth_failure(IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, n)))
                .await;
        }
        // Map must never exceed the cap.
        assert!(det.inner.lock().await.failures.len() <= 3);
    }

    #[tokio::test]
    async fn detector_caps_per_ip_failure_history() {
        let det = ProbeDetector::new(ProbeDetectorConfig {
            threshold: 1000,
            max_tracked_ips: 1024,
            window: Duration::from_secs(60),
            probe_flag_duration: Duration::from_secs(60),
            max_failures_per_ip: 4,
        });
        let bad = ip(99);
        for _ in 0..20 {
            det.record_auth_failure(bad).await;
        }
        let g = det.inner.lock().await;
        let v = g.failures.get(&bad).unwrap();
        assert_eq!(v.len(), 4, "per-IP history must be capped");
    }

    #[tokio::test]
    async fn softblock_evicts_when_at_capacity() {
        // RT-PD-2: gossip-driven adds can't exceed capacity.
        let list = SoftBlockList::with_capacity(3);
        for n in 1..=10u8 {
            list.add(
                IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, n)),
                Duration::from_secs(60),
            )
            .await;
        }
        assert!(list.len().await <= 3);
    }

    #[tokio::test]
    async fn softblock_clamps_expire_secs_via_gossip_subscriber() {
        // RT-PD-2: malicious peer sends expire_secs = u32::MAX.
        // Subscriber must clamp to MAX_PROBE_SOFTBLOCK_SECS.
        use mirage_discovery::cohort_gossip::MemoryGossip;
        let mg = Arc::new(MemoryGossip::new());
        let sk_a = fresh_sk();
        let sk_b = fresh_sk();
        mg.authorize(sk_a.verifying_key().to_bytes()).await;
        mg.authorize(sk_b.verifying_key().to_bytes()).await;
        let list = Arc::new(SoftBlockList::with_capacity(8));
        let _t = spawn_gossip_to_softblock(mg.clone() as Arc<dyn CohortGossip>, list.clone());
        tokio::time::sleep(Duration::from_millis(10)).await;
        let evt = |sk: &SigningKey| {
            SignedGossipEvent::sign(
                GossipEvent::ProbeScanDetected {
                    source_ip: ip(13),
                    expire_secs: u32::MAX,
                    detected_at: unix_now(),
                },
                sk,
            )
        };
        // Two distinct publishers to clear the quorum (RT #14).
        mg.publish(evt(&sk_a)).await;
        mg.publish(evt(&sk_b)).await;
        // Wait for delivery + verify the entry exists.
        for _ in 0..50 {
            if list.should_block(ip(13)).await {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(list.should_block(ip(13)).await);
        // Internal: confirm expiry is clamped (not Instant + 136yr).
        let g = list.inner.lock().await;
        let expires = g.get(&ip(13)).copied().unwrap();
        let max = Instant::now() + Duration::from_secs(MAX_PROBE_SOFTBLOCK_SECS as u64 + 1);
        assert!(
            expires <= max,
            "expire must be clamped to <= MAX_PROBE_SOFTBLOCK_SECS"
        );
    }

    #[tokio::test]
    async fn gatekeeper_does_not_double_publish_after_edge() {
        use mirage_discovery::cohort_gossip::MemoryGossip;
        let gossip = Arc::new(MemoryGossip::new());
        let sk = fresh_sk();
        gossip.authorize(sk.verifying_key().to_bytes()).await;
        let gk = ConnectionGatekeeper::new(
            gossip.clone() as Arc<dyn CohortGossip>,
            sk,
            GatekeeperConfig {
                detector: ProbeDetectorConfig {
                    threshold: 2,
                    ..Default::default()
                },
                probe_block_duration: Duration::from_secs(60),
                reap_interval: Duration::from_secs(60),
                shadow_active: false,
            },
        );
        let mut rx = gossip.subscribe().await;
        gk.observe_auth_failure(ip(1)).await;
        gk.observe_auth_failure(ip(1)).await; // edge
        gk.observe_auth_failure(ip(1)).await; // post-edge
        gk.observe_auth_failure(ip(1)).await; // post-edge

        // First recv: the edge event.
        let _ = tokio::time::timeout(Duration::from_millis(100), rx.recv())
            .await
            .expect("edge publish")
            .unwrap();
        // Second recv: should time out - no more publishes for
        // the same already-flagged IP.
        let second = tokio::time::timeout(Duration::from_millis(50), rx.recv()).await;
        assert!(second.is_err(), "must not publish again post-edge");
    }
}
