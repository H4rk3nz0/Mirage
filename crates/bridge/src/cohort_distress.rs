//! Cohort-wide load-signaling.
//!
//! # Why
//!
//! A bridge under load (CPU saturation, connection-count cap,
//! mem-pressure) historically had two options: serve degraded
//! responses, or drop new connections. With cohort cooperation,
//! a third option: **tell peers**. A bridge near saturation
//! emits [`mirage_discovery::GossipEvent::EntryDistressed`];
//! cohort peers who CAN take more load now know to absorb
//! flow that would have gone to the distressed entry - for
//! example, an upstream race-driver routing new sessions to
//! cohort members with low recent-distress.
//!
//! # Model
//!
//! - **Local load sensor**: a generic
//!   [`DistressSensor::current_severity()`] the operator
//!   implements (CPU sampler, connection-count, mem reading,
//!   whatever's relevant). 0 = healthy, 255 = saturated.
//! - **Publishing**: [`CohortDistressMonitor`] polls the
//!   sensor every `sample_interval`; when severity crosses
//!   `publish_threshold` it publishes one `EntryDistressed`.
//!   While severity remains above threshold it republishes at
//!   `republish_interval` so peers' staleness windows don't
//!   expire mid-incident.
//! - **Consuming**: subscribers populate a
//!   [`PeerDistressMap`]: `peer_pk -> severity, observed_at`.
//!   Decisions consult it to pick the least-stressed peer.
//!
//! # Threat model
//!
//! - **Freshness**: the underlying `CohortGossip` enforces a
//!   5-minute window; a captured "I'm distressed!" event
//!   can't be replayed forever to push traffic away from a
//!   healthy entry.
//! - **Authorisation**: only authorized publishers' events
//!   are processed.
//! - **Memory cap**: `PeerDistressMap` is keyed by
//!   `publisher_ed_pk` (32 B). The set of authorized peers is
//!   bounded by the operator's cohort size - typically < 100.
//!   No attacker-controlled growth.

use mirage_crypto::ed25519_dalek::SigningKey;
use mirage_discovery::cohort_gossip::{CohortGossip, GossipEvent, SignedGossipEvent};
use std::collections::HashMap;
use std::panic::AssertUnwindSafe;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::task::JoinHandle;

/// Operator-supplied local-load sensor. The monitor polls this
/// on a tick; implementors return 0 (healthy) - 255 (saturated).
pub trait DistressSensor: Send + Sync + 'static {
    /// Read the current load severity.
    fn current_severity(&self) -> u8;
}

/// Reference [`DistressSensor`] that holds an `AtomicU8` so
/// tests / synthetic workloads can drive severity manually.
#[derive(Debug, Default)]
pub struct ManualDistressSensor {
    severity: std::sync::atomic::AtomicU8,
}

impl ManualDistressSensor {
    /// Construct with initial severity 0.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the reported severity.
    pub fn set(&self, severity: u8) {
        self.severity
            .store(severity, std::sync::atomic::Ordering::Relaxed);
    }
}

impl DistressSensor for ManualDistressSensor {
    fn current_severity(&self) -> u8 {
        self.severity.load(std::sync::atomic::Ordering::Relaxed)
    }
}

/// Configuration for [`CohortDistressMonitor`].
#[derive(Debug, Clone)]
pub struct DistressMonitorConfig {
    /// How often to poll the sensor.
    pub sample_interval: Duration,
    /// Severity threshold (inclusive) at which we publish.
    pub publish_threshold: u8,
    /// While severity stays above threshold, how often to
    /// republish so peer freshness windows don't lapse.
    pub republish_interval: Duration,
    /// How long peer-side `PeerDistressMap` entries are
    /// considered valid before they're treated as "stale ->
    /// peer recovered". Should be >= `republish_interval` x
    /// some factor (default factor 3).
    pub peer_entry_ttl: Duration,
    /// Minimum interval between any two outbound publishes -
    /// rising, republish, OR recovery edges all share this
    /// throttle. Closes RT-CD-3 (flapping sensor flood).
    pub min_publish_interval: Duration,
}

impl Default for DistressMonitorConfig {
    fn default() -> Self {
        Self {
            sample_interval: Duration::from_secs(2),
            publish_threshold: 200,
            republish_interval: Duration::from_secs(30),
            peer_entry_ttl: Duration::from_secs(90),
            min_publish_interval: Duration::from_millis(500),
        }
    }
}

/// Local sensor -> outbound `EntryDistressed` publisher. Owns a
/// background ticker that consults the sensor and publishes
/// signed events on transitions / republish-deadlines.
pub struct CohortDistressMonitor {
    _ticker: JoinHandle<()>,
}

impl std::fmt::Debug for CohortDistressMonitor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CohortDistressMonitor")
            .finish_non_exhaustive()
    }
}

impl CohortDistressMonitor {
    /// Construct + start polling the sensor.
    pub fn new<S: DistressSensor>(
        gossip: Arc<dyn CohortGossip>,
        signing_key: SigningKey,
        sensor: Arc<S>,
        config: DistressMonitorConfig,
    ) -> Self {
        let publisher_pk = signing_key.verifying_key().to_bytes();
        let min_publish_interval = config.min_publish_interval;
        let ticker = tokio::spawn(async move {
            let mut last_publish_at: Option<Instant> = None;
            let mut last_actual_publish: Option<Instant> = None;
            let mut last_severity = 0u8;
            let mut ticker = tokio::time::interval(config.sample_interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                ticker.tick().await;
                // RT-CD-1: a panicking operator-supplied sensor
                // would otherwise kill the monitor silently.
                // Catch and treat as saturated (fail-pessimistic).
                let severity =
                    std::panic::catch_unwind(AssertUnwindSafe(|| sensor.current_severity()))
                        .unwrap_or_else(|_| {
                            tracing::error!("DistressSensor panicked; treating as saturated");
                            255
                        });
                let above_threshold = severity >= config.publish_threshold;
                let should_publish = match last_publish_at {
                    // First time above threshold (rising edge).
                    None if above_threshold => true,
                    // Republish deadline while still above.
                    Some(t) if above_threshold => t.elapsed() >= config.republish_interval,
                    // Recovery (falling edge): publish a "severity = 0"
                    // so peers refresh their map proactively rather
                    // than waiting for entry TTL to lapse. We're
                    // generous to peers.
                    Some(_) if !above_threshold && last_severity >= config.publish_threshold => {
                        true
                    }
                    _ => false,
                };
                // RT-CD-3: throttle ALL publishes - including
                // rising / recovery edges - to one per
                // `min_publish_interval`. Prevents a flapping
                // sensor (199 / 201 / 199 / ...) from flooding
                // the cohort gossip channel.
                let throttled = match last_actual_publish {
                    Some(t) => t.elapsed() < min_publish_interval,
                    None => false,
                };
                if should_publish && !throttled {
                    let event = GossipEvent::EntryDistressed {
                        publisher_ed_pk: publisher_pk,
                        severity,
                        observed_at: unix_now_secs(),
                    };
                    let signed = SignedGossipEvent::sign(event, &signing_key);
                    gossip.publish(signed).await;
                    last_publish_at = if above_threshold {
                        Some(Instant::now())
                    } else {
                        None
                    };
                    last_actual_publish = Some(Instant::now());
                    tracing::debug!(
                        severity,
                        republish = last_publish_at.is_some(),
                        "CohortDistressMonitor published EntryDistressed"
                    );
                }
                last_severity = severity;
            }
        });
        Self { _ticker: ticker }
    }
}

/// Default cap on the number of peers tracked in a
/// [`PeerDistressMap`]. The authorized set is operator-defined
/// and typically small, but a misconfigured transport that lets
/// non-authorized publisher pks through would otherwise grow
/// the map unboundedly. Closes RT-CD-5.
pub const DEFAULT_PEER_DISTRESS_CAPACITY: usize = 256;

/// Inbound-distress receiver. Subscribers populate a `peer_pk ->
/// (severity, observed_at)` map; callers consult it to pick the
/// least-stressed peer for new flow.
///
/// Uses `std::sync::Mutex` (not `tokio::sync::Mutex`) per
/// RT-CD-4 - every critical section is sync HashMap ops with
/// no `.await`.
pub struct PeerDistressMap {
    inner: Mutex<HashMap<[u8; 32], (u8, Instant)>>,
    ttl: Duration,
    capacity: usize,
}

impl std::fmt::Debug for PeerDistressMap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerDistressMap")
            .field("ttl", &self.ttl)
            .field("capacity", &self.capacity)
            .finish_non_exhaustive()
    }
}

impl PeerDistressMap {
    /// Construct with the supplied entry TTL and the default
    /// capacity ([`DEFAULT_PEER_DISTRESS_CAPACITY`]).
    pub fn new(ttl: Duration) -> Self {
        Self::with_capacity(ttl, DEFAULT_PEER_DISTRESS_CAPACITY)
    }

    /// Construct with explicit cap on tracked peers. Evicts the
    /// oldest-touched entry when full.
    pub fn with_capacity(ttl: Duration, capacity: usize) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            ttl,
            capacity,
        }
    }

    /// Record a peer's reported severity.
    pub fn record(&self, peer_pk: [u8; 32], severity: u8) {
        let Ok(mut g) = self.inner.lock() else {
            return;
        };
        if !g.contains_key(&peer_pk) && g.len() >= self.capacity {
            if let Some(victim) = g.iter().min_by_key(|(_, (_, t))| *t).map(|(k, _)| *k) {
                g.remove(&victim);
            }
        }
        g.insert(peer_pk, (severity, Instant::now()));
    }

    /// Current severity for `peer_pk`, or `None` if no fresh
    /// entry exists.
    pub fn severity(&self, peer_pk: &[u8; 32]) -> Option<u8> {
        let g = self.inner.lock().ok()?;
        g.get(peer_pk).and_then(|(sev, t)| {
            if t.elapsed() <= self.ttl {
                Some(*sev)
            } else {
                None
            }
        })
    }

    /// Sweep expired entries.
    pub fn reap(&self) -> usize {
        let Ok(mut g) = self.inner.lock() else {
            return 0;
        };
        let now = Instant::now();
        let before = g.len();
        g.retain(|_, (_, t)| now.saturating_duration_since(*t) <= self.ttl);
        before - g.len()
    }

    /// Diagnostic.
    pub fn len(&self) -> usize {
        self.inner.lock().map(|g| g.len()).unwrap_or(0)
    }

    /// True iff empty.
    pub fn is_empty(&self) -> bool {
        self.inner.lock().map(|g| g.is_empty()).unwrap_or(true)
    }
}

impl Default for PeerDistressMap {
    fn default() -> Self {
        Self::new(Duration::from_secs(60))
    }
}

/// Subscriber that listens on `gossip` and populates `map` from
/// every inbound `EntryDistressed` event. Other variants are
/// ignored. Returns the JoinHandle so callers can abort on
/// shutdown.
pub fn spawn_gossip_to_distress_map(
    gossip: Arc<dyn CohortGossip>,
    map: Arc<PeerDistressMap>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut rx = gossip.subscribe().await;
        loop {
            match rx.recv().await {
                Ok(signed) => {
                    // RT-CR-4: defense-in-depth verify.
                    if signed.verify(&signed.publisher_ed_pk).is_err() {
                        tracing::debug!("distress subscriber: bad sig (transport bug?); dropping");
                        continue;
                    }
                    if let GossipEvent::EntryDistressed {
                        publisher_ed_pk,
                        severity,
                        ..
                    } = signed.event
                    {
                        map.record(publisher_ed_pk, severity);
                        tracing::debug!(severity, "cohort gossip: peer distress recorded");
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    tracing::warn!(skipped = n, "gossip distress subscriber lagged");
                    continue;
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
            }
        }
    })
}

fn unix_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mirage_discovery::cohort_gossip::MemoryGossip;

    fn fresh_sk() -> SigningKey {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).unwrap();
        SigningKey::from_bytes(&seed)
    }

    #[tokio::test]
    async fn monitor_publishes_on_rising_edge() {
        let gossip = Arc::new(MemoryGossip::new());
        let sk = fresh_sk();
        let pk = sk.verifying_key().to_bytes();
        gossip.authorize(pk).await;
        let mut rx = gossip.subscribe().await;
        let sensor = Arc::new(ManualDistressSensor::new());
        let _mon = CohortDistressMonitor::new(
            gossip.clone() as Arc<dyn CohortGossip>,
            sk,
            sensor.clone(),
            DistressMonitorConfig {
                sample_interval: Duration::from_millis(20),
                publish_threshold: 200,
                republish_interval: Duration::from_secs(60),
                peer_entry_ttl: Duration::from_secs(90),
                min_publish_interval: Duration::from_millis(0),
            },
        );
        // Crank severity above threshold.
        sensor.set(250);
        let received = tokio::time::timeout(Duration::from_millis(200), rx.recv())
            .await
            .expect("publish should fire")
            .unwrap();
        match received.event {
            GossipEvent::EntryDistressed { severity, .. } => assert!(severity >= 200),
            other => panic!("unexpected {:?}", other),
        }
    }

    #[tokio::test]
    async fn monitor_does_not_publish_when_healthy() {
        let gossip = Arc::new(MemoryGossip::new());
        let sk = fresh_sk();
        gossip.authorize(sk.verifying_key().to_bytes()).await;
        let mut rx = gossip.subscribe().await;
        let sensor = Arc::new(ManualDistressSensor::new());
        let _mon = CohortDistressMonitor::new(
            gossip.clone() as Arc<dyn CohortGossip>,
            sk,
            sensor,
            DistressMonitorConfig {
                sample_interval: Duration::from_millis(20),
                ..Default::default()
            },
        );
        // Severity stays 0. No publish should fire.
        let r = tokio::time::timeout(Duration::from_millis(100), rx.recv()).await;
        assert!(r.is_err(), "monitor must not publish when healthy");
    }

    #[tokio::test]
    async fn monitor_publishes_recovery() {
        let gossip = Arc::new(MemoryGossip::new());
        let sk = fresh_sk();
        gossip.authorize(sk.verifying_key().to_bytes()).await;
        let mut rx = gossip.subscribe().await;
        let sensor = Arc::new(ManualDistressSensor::new());
        let _mon = CohortDistressMonitor::new(
            gossip.clone() as Arc<dyn CohortGossip>,
            sk,
            sensor.clone(),
            DistressMonitorConfig {
                sample_interval: Duration::from_millis(20),
                publish_threshold: 200,
                republish_interval: Duration::from_secs(60),
                peer_entry_ttl: Duration::from_secs(90),
                min_publish_interval: Duration::from_millis(0),
            },
        );
        sensor.set(250);
        // Rising-edge publish.
        let first = tokio::time::timeout(Duration::from_millis(200), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            first.event,
            GossipEvent::EntryDistressed { severity, .. } if severity == 250
        ));
        // Recover.
        sensor.set(50);
        let second = tokio::time::timeout(Duration::from_millis(200), rx.recv())
            .await
            .expect("recovery publish")
            .unwrap();
        assert!(matches!(
            second.event,
            GossipEvent::EntryDistressed { severity: 50, .. }
        ));
    }

    #[tokio::test]
    async fn monitor_throttle_rejects_flapping_sensor() {
        // RT-CD-3: a sensor oscillating across the threshold
        // must not flood gossip.
        let gossip = Arc::new(MemoryGossip::new());
        let sk = fresh_sk();
        let pk = sk.verifying_key().to_bytes();
        gossip.authorize(pk).await;
        let mut rx = gossip.subscribe().await;
        let sensor = Arc::new(ManualDistressSensor::new());
        let _mon = CohortDistressMonitor::new(
            gossip.clone() as Arc<dyn CohortGossip>,
            sk,
            sensor.clone(),
            DistressMonitorConfig {
                sample_interval: Duration::from_millis(10),
                publish_threshold: 200,
                republish_interval: Duration::from_secs(60),
                peer_entry_ttl: Duration::from_secs(90),
                min_publish_interval: Duration::from_millis(200),
            },
        );
        // Flap severity for ~200ms - many edge transitions.
        for _ in 0..20 {
            sensor.set(250);
            tokio::time::sleep(Duration::from_millis(10)).await;
            sensor.set(50);
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        // Drain whatever was published. We expect << one event per
        // edge - the throttle limits to ~1/200ms ~ 1 publish.
        let mut count = 0;
        while let Ok(Ok(_)) = tokio::time::timeout(Duration::from_millis(50), rx.recv()).await {
            count += 1;
        }
        assert!(
            count <= 3,
            "throttle must limit to ~1 publish/window, got {count}"
        );
    }

    #[tokio::test]
    async fn distress_map_caps_at_capacity() {
        // RT-CD-5: PeerDistressMap with_capacity evicts oldest.
        let map = PeerDistressMap::with_capacity(Duration::from_secs(60), 3);
        for i in 0u8..10 {
            let mut pk = [0u8; 32];
            pk[0] = i;
            map.record(pk, 100);
        }
        assert!(map.len() <= 3, "map must be capped at 3, got {}", map.len());
    }

    #[tokio::test]
    async fn distress_map_records_and_expires() {
        let map = PeerDistressMap::new(Duration::from_millis(50));
        map.record([0x77; 32], 200);
        assert_eq!(map.severity(&[0x77; 32]), Some(200));
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(map.severity(&[0x77; 32]), None);
        assert_eq!(map.reap(), 1);
    }

    #[tokio::test]
    async fn end_to_end_distress_propagates() {
        let gossip = Arc::new(MemoryGossip::new());
        let sk_a = fresh_sk();
        let pk_a = sk_a.verifying_key().to_bytes();
        gossip.authorize(pk_a).await;

        let map = Arc::new(PeerDistressMap::new(Duration::from_secs(60)));
        let _sub =
            spawn_gossip_to_distress_map(gossip.clone() as Arc<dyn CohortGossip>, map.clone());

        let sensor = Arc::new(ManualDistressSensor::new());
        let _mon = CohortDistressMonitor::new(
            gossip.clone() as Arc<dyn CohortGossip>,
            sk_a,
            sensor.clone(),
            DistressMonitorConfig {
                sample_interval: Duration::from_millis(20),
                publish_threshold: 200,
                republish_interval: Duration::from_secs(60),
                peer_entry_ttl: Duration::from_secs(90),
                min_publish_interval: Duration::from_millis(0),
            },
        );
        sensor.set(220);
        for _ in 0..50 {
            if map.severity(&pk_a).is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(map.severity(&pk_a), Some(220));
    }
}
