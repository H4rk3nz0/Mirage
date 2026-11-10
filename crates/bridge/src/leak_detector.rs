//! Cross-bridge leaked-invite attribution.
//!
//! # Why
//!
//! Each Mirage invite carries a one-time **claim id** (see
//! [`mirage_discovery::claim`]). A legitimate client redeems it once,
//! at the first bridge it reaches. The single-bridge claim set already
//! catches a second redemption *at the same bridge*. What it cannot
//! catch - and what [`mirage_discovery::claim`] explicitly documents as
//! a gap - is the same invite being redeemed at *different* bridges:
//! an attacker who obtains a leaked invite simply claims at bridge B
//! while the legitimate user claims at bridge A. Both succeed locally;
//! neither bridge sees a collision.
//!
//! This module closes that gap with cohort gossip. When a bridge
//! accepts a first-use claim it publishes a
//! [`mirage_discovery::cohort_gossip::GossipEvent::ClaimObserved`]
//! carrying only a cohort-keyed **tag** of the claim id (never the id
//! itself - see [`mirage_discovery::claim::claim_observation_tag`]).
//! The [`LeakDetector`] correlates those tags: a tag seen from **two or
//! more distinct cohort bridges** within a window is cross-bridge claim
//! equivocation - strong evidence the invite was leaked or shared.
//!
//! # STATUS: dormant under per-bridge claim ids (#2)
//!
//! As of the #2 fix, the client no longer sends one invariant `claim_id` to
//! every bridge; it sends a *per-bridge* id
//! ([`mirage_discovery::claim::derive_claim_id`]) so hostile bridges cannot use
//! the raw id as a cross-mesh tracking cookie. A direct consequence is that the
//! same invite now yields a DIFFERENT claim id (and therefore a different
//! observation tag) at each bridge, so this cross-bridge correlator will not
//! fire for a legitimately roaming user OR a leaked invite - the invariant it
//! keyed on is deliberately gone. That was the correct privacy tradeoff (an
//! invariant, cohort-wide-recognisable claim id IS the tracking cookie). The
//! code is retained because the mechanism is still correct: restoring
//! cross-bridge leak detection WITHOUT reintroducing the cookie needs an
//! invite-invariant tag that only cohort-key holders can correlate (e.g. an
//! asymmetric cohort key so the client can seal a correlation tag to the
//! cohort). Until that exists, treat this detector as inactive.
//!
//! # Detection, not prevention
//!
//! The detector NEVER blocks. Its output is a [`LeakAlert`] for
//! operator review, for two reasons:
//!
//! - **Benign false positive.** A roaming user who legitimately
//!   re-claims on a new device, or after a bridge failover, also
//!   produces cross-bridge observations. The time window narrows this
//!   (concurrent misuse fires; a re-claim weeks later does not), but
//!   cannot eliminate it - so a human decides.
//! - **Trust boundary.** A `ClaimObserved` is signed by a cohort
//!   member. The detector counts only **distinct** publisher keys, so a
//!   single rogue cohort node cannot self-trigger an alert by replaying
//!   one tag (it would need a *second* cohort key). But two colluding
//!   keyholders could forge an alert; since the output is advisory,
//!   that costs the attacker an operator review, nothing more.
//!
//! # Robustness
//!
//! - **Window uses receive time, not the event's claimed timestamp.**
//!   The publisher's `observed_at` is advisory (it could lie within the
//!   gossip freshness window); the equivocation window is measured from
//!   when *we* received each observation (a monotonic [`Instant`]), so a
//!   crafted timestamp can neither evade nor force the window.
//! - **Bounded memory.** Tracked tags are capped
//!   ([`DEFAULT_LEAK_DETECTOR_CAPACITY`]); the oldest-created entry is
//!   evicted when full, and [`LeakDetector::reap`] sweeps tags whose
//!   observations have all aged out of the window.

use mirage_discovery::cohort_gossip::{CohortGossip, GossipEvent};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::task::JoinHandle;

/// Default equivocation window: 24 hours. A tag must be observed from
/// `>=` [`LEAK_PUBLISHER_THRESHOLD`] distinct bridges within this span
/// to alert. Wider -> catches slow-spreading leaks but raises the
/// roaming false-positive rate; narrower -> only near-concurrent misuse.
pub const DEFAULT_LEAK_WINDOW: Duration = Duration::from_secs(86_400);

/// Default cap on the number of distinct claim tags tracked at once.
/// At ~100 B/entry this is a few MiB. When full, the oldest-created
/// entry is evicted (it has had the longest chance to alert already).
pub const DEFAULT_LEAK_DETECTOR_CAPACITY: usize = 65_536;

/// Number of distinct publishers that must observe one tag (within the
/// window) for the detector to raise a [`LeakAlert`]. Two is the floor:
/// a single bridge claiming a tag is the normal case.
pub const LEAK_PUBLISHER_THRESHOLD: usize = 2;

/// A cross-bridge claim-equivocation alert - one claim tag observed at
/// two or more distinct cohort bridges within the window. **For
/// operator review only**; the detector never blocks (see the module
/// docs on benign roaming false positives).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeakAlert {
    /// The cohort-keyed claim tag seen at multiple bridges. The
    /// operator can match this against their mint records (recompute
    /// the tag for each issued invite) to attribute the leak to a
    /// specific invite - without the raw claim id ever transiting the
    /// gossip channel.
    pub claim_tag: [u8; 32],
    /// The distinct cohort-bridge Ed25519 public keys that observed
    /// this tag within the window.
    pub publishers: Vec<[u8; 32]>,
    /// Unix-second timestamp of the observation that triggered the
    /// alert (the publisher's claimed `observed_at`).
    pub observed_secs: u64,
}

impl LeakAlert {
    /// How many distinct bridges observed the tag.
    pub fn publisher_count(&self) -> usize {
        self.publishers.len()
    }

    /// A short hex prefix of the tag, for log lines (the full 32-byte
    /// tag is rarely needed and clutters logs).
    pub fn tag_hex_prefix(&self) -> String {
        let mut s = String::with_capacity(16);
        for b in &self.claim_tag[..8] {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }
}

/// Per-tag observation state.
struct TagState {
    /// Distinct publisher pk -> the [`Instant`] we received its most
    /// recent observation of this tag. Pruned against the window.
    publishers: HashMap<[u8; 32], Instant>,
    /// When this tag entry was first created (capacity eviction key).
    created: Instant,
    /// Distinct-publisher count at which we last alerted, so a repeat
    /// observation from an already-counted publisher does not re-alert.
    /// Reset downward by [`LeakDetector::reap`] if publishers age out.
    alerted_at_count: usize,
    /// Most recent observation's claimed unix timestamp (for the alert).
    last_observed_secs: u64,
}

/// Correlates [`GossipEvent::ClaimObserved`] tags across the cohort to
/// detect a single invite claimed at multiple bridges.
///
/// Uses a `std::sync::Mutex` (not the async one): every critical
/// section is sync `HashMap` work with no `.await`.
pub struct LeakDetector {
    inner: Mutex<HashMap<[u8; 32], TagState>>,
    window: Duration,
    capacity: usize,
}

impl std::fmt::Debug for LeakDetector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LeakDetector")
            .field("window", &self.window)
            .field("capacity", &self.capacity)
            .finish_non_exhaustive()
    }
}

impl LeakDetector {
    /// Construct with the supplied equivocation window and the default
    /// capacity ([`DEFAULT_LEAK_DETECTOR_CAPACITY`]).
    pub fn new(window: Duration) -> Self {
        Self::with_capacity(window, DEFAULT_LEAK_DETECTOR_CAPACITY)
    }

    /// Construct with an explicit window and tag-tracking capacity.
    pub fn with_capacity(window: Duration, capacity: usize) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            window,
            // A zero capacity would make the detector inert and also
            // trip the eviction logic; clamp to at least 1.
            capacity: capacity.max(1),
        }
    }

    /// Record an observation of `claim_tag` by cohort bridge
    /// `publisher_pk`, with the publisher's claimed `observed_secs`.
    ///
    /// Returns `Some(LeakAlert)` iff this observation pushes the count
    /// of *distinct* publishers (within the window) to a new high at or
    /// above [`LEAK_PUBLISHER_THRESHOLD`]. Repeat observations from an
    /// already-counted publisher return `None` (the distinct count is
    /// unchanged), so one node replaying a tag cannot raise an alert.
    pub fn record(
        &self,
        claim_tag: [u8; 32],
        publisher_pk: [u8; 32],
        observed_secs: u64,
    ) -> Option<LeakAlert> {
        let now = Instant::now();
        let mut g = self.inner.lock().ok()?;

        // Capacity guard: if this is a brand-new tag and we're full,
        // evict one entry. A naive "evict oldest" is exploitable - a
        // single rogue cohort member could flood unique tags to evict
        // the *pending* single-observer entries that are one honest
        // observation away from alerting, suppressing a real leak
        // (RT-LD-1). `evict_one` defeats that: it makes a flooding
        // publisher churn its OWN singleton entries, and never evicts a
        // multi-observer (already-correlated) entry while any singleton
        // remains.
        if !g.contains_key(&claim_tag) && g.len() >= self.capacity {
            evict_one(&mut g, &publisher_pk);
        }

        let st = g.entry(claim_tag).or_insert_with(|| TagState {
            publishers: HashMap::new(),
            created: now,
            alerted_at_count: 0,
            last_observed_secs: observed_secs,
        });
        st.last_observed_secs = observed_secs;

        // Prune this tag's publishers that have aged out of the window
        // (measured from our receive time), then record this one.
        let window = self.window;
        st.publishers
            .retain(|_, seen| now.saturating_duration_since(*seen) <= window);
        st.publishers.insert(publisher_pk, now);

        // If observations aged out below the prior alert level, allow a
        // fresh alert when the count climbs back up.
        let distinct = st.publishers.len();
        if st.alerted_at_count > distinct {
            st.alerted_at_count = distinct;
        }

        if distinct >= LEAK_PUBLISHER_THRESHOLD && distinct > st.alerted_at_count {
            st.alerted_at_count = distinct;
            let mut publishers: Vec<[u8; 32]> = st.publishers.keys().copied().collect();
            // Deterministic order for stable logs/tests.
            publishers.sort_unstable();
            return Some(LeakAlert {
                claim_tag,
                publishers,
                observed_secs: st.last_observed_secs,
            });
        }
        None
    }

    /// Sweep every tag, dropping publisher observations older than the
    /// window and removing tags left with no live observation. Returns
    /// the number of tags dropped. Call periodically from a ticker.
    pub fn reap(&self) -> usize {
        let Ok(mut g) = self.inner.lock() else {
            return 0;
        };
        let now = Instant::now();
        let window = self.window;
        let before = g.len();
        g.retain(|_, st| {
            st.publishers
                .retain(|_, seen| now.saturating_duration_since(*seen) <= window);
            if st.alerted_at_count > st.publishers.len() {
                st.alerted_at_count = st.publishers.len();
            }
            !st.publishers.is_empty()
        });
        before - g.len()
    }

    /// Number of distinct claim tags currently tracked.
    pub fn len(&self) -> usize {
        self.inner.lock().map(|g| g.len()).unwrap_or(0)
    }

    /// True iff no tags are tracked.
    pub fn is_empty(&self) -> bool {
        self.inner.lock().map(|g| g.is_empty()).unwrap_or(true)
    }

    /// Distinct publishers currently associated with `claim_tag` (after
    /// window pruning is applied lazily on `record`/`reap`). Diagnostic.
    pub fn observer_count(&self, claim_tag: &[u8; 32]) -> usize {
        self.inner
            .lock()
            .ok()
            .and_then(|g| g.get(claim_tag).map(|st| st.publishers.len()))
            .unwrap_or(0)
    }
}

impl Default for LeakDetector {
    fn default() -> Self {
        Self::new(DEFAULT_LEAK_WINDOW)
    }
}

/// Evict exactly one entry from a full table to make room for a new
/// tag from `incoming_pk`. Flood-resistant eviction order (RT-LD-1):
///
/// 1. The **incoming publisher's own oldest singleton** (an entry it is
///    the sole observer of). This is the key defense: a publisher that
///    floods unique tags evicts only *its own* prior entries once it
///    holds any singleton, so it cannot displace another bridge's
///    pending entry - the one observation away from a real alert.
/// 2. Otherwise the **globally oldest singleton**, so a brand-new
///    publisher's first insert still finds room without touching a
///    multi-observer entry.
/// 3. Otherwise (every entry already has multiple observers - these are
///    the valuable, near/at-alert correlations) the globally oldest
///    entry. Reached only in pathological saturation.
fn evict_one(map: &mut HashMap<[u8; 32], TagState>, incoming_pk: &[u8; 32]) {
    // 1. Incoming publisher's own oldest singleton.
    let own_oldest = map
        .iter()
        .filter(|(_, st)| st.publishers.len() == 1 && st.publishers.contains_key(incoming_pk))
        .min_by_key(|(_, st)| st.created)
        .map(|(k, _)| *k);
    if let Some(victim) = own_oldest {
        map.remove(&victim);
        return;
    }
    // 2. Globally oldest singleton.
    let oldest_singleton = map
        .iter()
        .filter(|(_, st)| st.publishers.len() == 1)
        .min_by_key(|(_, st)| st.created)
        .map(|(k, _)| *k);
    if let Some(victim) = oldest_singleton {
        map.remove(&victim);
        return;
    }
    // 3. Globally oldest entry (all are multi-observer).
    if let Some(victim) = map.iter().min_by_key(|(_, st)| st.created).map(|(k, _)| *k) {
        map.remove(&victim);
    }
}

/// Subscriber that listens on `gossip` and feeds every inbound
/// [`GossipEvent::ClaimObserved`] into `detector`. On a cross-bridge
/// equivocation it emits a `warn!` for operator review (the detector
/// never blocks). Other event variants are ignored. Returns the
/// `JoinHandle` so callers can abort on shutdown.
pub fn spawn_gossip_to_leak_detector(
    gossip: Arc<dyn CohortGossip>,
    detector: Arc<LeakDetector>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut rx = gossip.subscribe().await;
        loop {
            match rx.recv().await {
                Ok(signed) => {
                    // Defense-in-depth: re-verify even though the
                    // transport should only deliver verified events.
                    if signed.verify(&signed.publisher_ed_pk).is_err() {
                        tracing::debug!("leak detector: bad sig (transport bug?); dropping");
                        continue;
                    }
                    if let GossipEvent::ClaimObserved {
                        claim_tag,
                        observed_at,
                    } = signed.event
                    {
                        if let Some(alert) =
                            detector.record(claim_tag, signed.publisher_ed_pk, observed_at)
                        {
                            tracing::warn!(
                                tag = %alert.tag_hex_prefix(),
                                bridges = alert.publisher_count(),
                                "cohort leak detector: an invite was claimed at multiple \
                                 cohort bridges (cross-bridge equivocation) - likely a \
                                 leaked or shared invite. Review against mint records; this \
                                 is advisory (a roaming re-claim can also trigger it)."
                            );
                        }
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    tracing::warn!(skipped = n, "gossip leak-detector subscriber lagged");
                    continue;
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use mirage_crypto::ed25519_dalek::SigningKey;
    use mirage_discovery::cohort_gossip::{MemoryGossip, SignedGossipEvent};

    fn pk(seed: u8) -> [u8; 32] {
        SigningKey::from_bytes(&[seed; 32])
            .verifying_key()
            .to_bytes()
    }

    fn now_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    #[test]
    fn single_bridge_observation_does_not_alert() {
        let d = LeakDetector::new(DEFAULT_LEAK_WINDOW);
        let tag = [0x11u8; 32];
        assert!(d.record(tag, pk(1), now_secs()).is_none());
        assert_eq!(d.observer_count(&tag), 1);
    }

    #[test]
    fn second_distinct_bridge_alerts() {
        let d = LeakDetector::new(DEFAULT_LEAK_WINDOW);
        let tag = [0x22u8; 32];
        assert!(d.record(tag, pk(1), now_secs()).is_none());
        let alert = d.record(tag, pk(2), now_secs()).expect("must alert");
        assert_eq!(alert.publisher_count(), 2);
        assert_eq!(alert.claim_tag, tag);
        assert!(alert.publishers.contains(&pk(1)));
        assert!(alert.publishers.contains(&pk(2)));
    }

    #[test]
    fn one_bridge_replaying_cannot_self_trigger() {
        // The load-bearing guarantee: distinct publishers, not raw
        // observation count. A single rogue node replaying one tag a
        // thousand times must never raise an alert.
        let d = LeakDetector::new(DEFAULT_LEAK_WINDOW);
        let tag = [0x33u8; 32];
        for _ in 0..1000 {
            assert!(d.record(tag, pk(7), now_secs()).is_none());
        }
        assert_eq!(d.observer_count(&tag), 1);
    }

    #[test]
    fn distinct_tags_are_independent() {
        let d = LeakDetector::new(DEFAULT_LEAK_WINDOW);
        assert!(d.record([0xA0u8; 32], pk(1), now_secs()).is_none());
        // A different tag from a different bridge must NOT correlate
        // with the first tag.
        assert!(d.record([0xB0u8; 32], pk(2), now_secs()).is_none());
        assert_eq!(d.len(), 2);
    }

    #[test]
    fn does_not_re_alert_for_same_publisher_set() {
        let d = LeakDetector::new(DEFAULT_LEAK_WINDOW);
        let tag = [0x44u8; 32];
        d.record(tag, pk(1), now_secs());
        assert!(d.record(tag, pk(2), now_secs()).is_some());
        // Repeat observations from the same two bridges: no new alert.
        assert!(d.record(tag, pk(1), now_secs()).is_none());
        assert!(d.record(tag, pk(2), now_secs()).is_none());
    }

    #[test]
    fn third_distinct_bridge_re_alerts_with_higher_count() {
        let d = LeakDetector::new(DEFAULT_LEAK_WINDOW);
        let tag = [0x55u8; 32];
        d.record(tag, pk(1), now_secs());
        assert_eq!(
            d.record(tag, pk(2), now_secs()).unwrap().publisher_count(),
            2
        );
        // A *new* distinct bridge raises a fresh, higher-degree alert.
        assert_eq!(
            d.record(tag, pk(3), now_secs()).unwrap().publisher_count(),
            3
        );
    }

    #[test]
    fn roaming_outside_window_does_not_alert() {
        // Zero-length window: the first observation is already aged out
        // by the time the second arrives, so no correlation - models a
        // re-claim long after the window (a roaming user).
        let d = LeakDetector::new(Duration::from_nanos(0));
        let tag = [0x66u8; 32];
        assert!(d.record(tag, pk(1), now_secs()).is_none());
        // Second distinct bridge, but the first has aged out -> count 1.
        assert!(d.record(tag, pk(2), now_secs()).is_none());
        assert_eq!(d.observer_count(&tag), 1);
    }

    #[test]
    fn capacity_evicts_oldest() {
        let d = LeakDetector::with_capacity(DEFAULT_LEAK_WINDOW, 2);
        d.record([0x01u8; 32], pk(1), now_secs());
        d.record([0x02u8; 32], pk(1), now_secs());
        // Third distinct tag evicts the oldest (tag 0x01).
        d.record([0x03u8; 32], pk(1), now_secs());
        assert_eq!(d.len(), 2);
        assert_eq!(d.observer_count(&[0x01u8; 32]), 0);
        assert_eq!(d.observer_count(&[0x03u8; 32]), 1);
    }

    #[test]
    fn flood_from_one_publisher_cannot_evict_a_pending_entry() {
        // RT-LD-1 regression: a rogue cohort member floods unique tags
        // to try to evict an honest bridge's pending (count-1) entry
        // before a second honest observation can alert. The flood-
        // resistant eviction makes the attacker churn ONLY its own
        // entries, so the pending entry survives and still alerts.
        let d = LeakDetector::with_capacity(DEFAULT_LEAK_WINDOW, 8);
        let leak_tag = [0xEEu8; 32];
        let honest = pk(1);
        // Honest bridge records the first observation of the leaked tag.
        assert!(d.record(leak_tag, honest, now_secs()).is_none());

        // Attacker floods 1000 unique tags from ONE key (>> capacity).
        let attacker = pk(2);
        for i in 0..1000u32 {
            let mut t = [0u8; 32];
            t[..4].copy_from_slice(&i.to_be_bytes());
            t[31] = 0xAA; // never collides with leak_tag (all 0xEE)
            d.record(t, attacker, now_secs());
        }

        // The pending honest entry must NOT have been evicted.
        assert_eq!(
            d.observer_count(&leak_tag),
            1,
            "flood must not evict the honest pending entry"
        );
        // A second honest bridge observing the same tag still fires.
        assert!(
            d.record(leak_tag, pk(3), now_secs()).is_some(),
            "real cross-bridge equivocation must survive a flood attack"
        );
    }

    #[test]
    fn reap_drops_aged_tags() {
        let d = LeakDetector::new(Duration::from_nanos(0));
        d.record([0x77u8; 32], pk(1), now_secs());
        assert_eq!(d.len(), 1);
        // Everything is instantly stale under a zero window.
        let dropped = d.reap();
        assert_eq!(dropped, 1);
        assert!(d.is_empty());
    }

    #[tokio::test]
    async fn end_to_end_through_gossip_channel() {
        // Two cohort bridges publish ClaimObserved for the SAME tag;
        // the detector, fed via a real gossip subscription, sees both.
        let gossip = MemoryGossip::new();
        let sk_a = SigningKey::from_bytes(&[0xA1; 32]);
        let sk_b = SigningKey::from_bytes(&[0xB2; 32]);
        gossip.authorize(sk_a.verifying_key().to_bytes()).await;
        gossip.authorize(sk_b.verifying_key().to_bytes()).await;

        let detector = Arc::new(LeakDetector::new(DEFAULT_LEAK_WINDOW));
        let gossip_arc: Arc<dyn CohortGossip> = Arc::new(gossip);
        let _h = spawn_gossip_to_leak_detector(gossip_arc.clone(), detector.clone());

        let tag = [0x9Cu8; 32];
        let ev = |t| GossipEvent::ClaimObserved {
            claim_tag: tag,
            observed_at: t,
        };
        // The spawned task subscribes asynchronously, and a broadcast
        // channel only delivers messages sent *after* a receiver
        // exists. Re-publish each round until the subscriber catches a
        // pair; the detector dedupes repeats by publisher, so the
        // observer count caps at 2 regardless of how many rounds run.
        for _ in 0..100 {
            gossip_arc
                .publish(SignedGossipEvent::sign(ev(now_secs()), &sk_a))
                .await;
            gossip_arc
                .publish(SignedGossipEvent::sign(ev(now_secs()), &sk_b))
                .await;
            if detector.observer_count(&tag) >= 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(
            detector.observer_count(&tag),
            2,
            "detector should have correlated the tag across both bridges"
        );
    }
}
