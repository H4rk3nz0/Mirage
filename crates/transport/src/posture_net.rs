//! **Censorship Weather** - a poisoning-robust, collaborative estimate of what
//! the local network is doing to each transport bearer class.
//!
//! # The idea
//!
//! The routing engine ([`crate::adaptive`]) is only as good as its read of the
//! network. On its own, a client learns the censor's posture through *its own
//! eyes* - one failure at a time. But Mirage clients on the same network share
//! a censor. If they pool observations, the swarm maps the censor's blocking in
//! near-real-time: the instant one client discovers UDP is throttled, every
//! other client can route around it *before* wasting a single probe. That is a
//! qualitative shift - the network out-adapts the censor collectively.
//!
//! The obvious objection is the obvious attack: a censor runs fake clients
//! (Sybils) that **lie** - "UDP works!" to lure you onto a dead/honeypot bearer,
//! or "TLS is blocked!" to steer you off a working one. A naive "average what
//! peers report" system is trivially poisoned. So the whole engineering problem
//! is **Byzantine robustness**: fold in peer intelligence *without* letting a
//! minority of liars move your belief.
//!
//! # How robustness is achieved
//!
//! Five mutually-reinforcing mechanisms (see the tests, which attack each):
//!
//! 1. **Trust your own eyes.** First-hand local observations carry weight far
//!    above any single peer ([`PostureNet::SELF_BASE`]); hearsay only supplements
//!    what you have not yet measured yourself.
//! 2. **Weighted-median aggregation.** The class viability is the *weighted
//!    median* of `{ self, peers }`, not the mean. To move a median an adversary
//!    must control **more than half of the total weight** - a mean can be
//!    dragged arbitrarily by one liar; a median cannot.
//! 3. **Earned trust; cheap identities start poor.** A fresh source begins at
//!    [`PostureNet::NEW_TRUST`] (low). Reputation is *earned* only by claims that
//!    later match the client's own first-hand truth - so a Sybil *flood of new
//!    identities* carries almost no aggregate weight (the classic Sybil defence
//!    that does not need a global identity system).
//! 4. **Liars are punished by reality.** Every time the client observes a class
//!    first-hand, it scores peers' recent claims for that class: agree -> trust
//!    up; contradict -> trust down hard. A source that lured you loses its future
//!    voice.
//! 5. **Never blind.** Peers can only *supplement* - with any first-hand data,
//!    self weight dominates until a *large, trusted* majority disagrees, which is
//!    exactly the case where collective correction is legitimately right.
//!
//! # Privacy
//!
//! Observations are coarse: `(network fingerprint, bearer class, viability)` -
//! never a destination, a bridge key, or a stream. A censor learning "clients
//! believe UDP is blocked here" learns nothing it did not already do. Sources
//! are pseudonymous per-epoch ids assigned by the gossip layer, aggregate-only,
//! carried on Mirage's existing anonymised discovery gossip. See
//! [`PostureNet::local_report`] / [`PostureNet::ingest_peer`] - the seam the
//! discovery layer wires to.
//!
//! # Purity
//!
//! Like the rest of `mirage-transport`, this is pure + I/O-free; it produces a
//! plain [`Posture`] that the router consumes unchanged.

use crate::adaptive::{Posture, TransportClass};
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// One peer's claim about a class's viability, with the source and when it
/// arrived (for recency weighting + reputation scoring).
#[derive(Debug, Clone, Copy)]
struct PeerSample {
    source: u64,
    class: TransportClass,
    viable: f64,
    at: Instant,
}

/// The client's own first-hand belief about one class: an EWMA of outcomes plus
/// an observation count that saturates into a confidence.
#[derive(Debug, Clone, Copy)]
struct LocalBelief {
    ewma: f64,
    count: u32,
    at: Instant,
}

/// Tunables for [`PostureNet`].
#[derive(Debug, Clone, Copy)]
pub struct WeatherParams {
    /// How long a peer sample / local belief stays relevant.
    pub window: Duration,
    /// EWMA weight for a fresh first-hand outcome.
    pub local_alpha: f64,
    /// Reputation of a never-before-seen source (kept low -> Sybil resistance).
    pub new_trust: f64,
    /// Reputation gained (toward 1) when a peer claim matches first-hand truth.
    pub trust_reward: f64,
    /// Fraction of reputation LOST when a peer claim contradicts first-hand truth
    /// (heavier than the reward - lying is punished asymmetrically).
    pub trust_penalty: f64,
}

impl Default for WeatherParams {
    fn default() -> Self {
        Self {
            window: Duration::from_secs(300),
            local_alpha: 0.3,
            new_trust: 0.1,
            trust_reward: 0.25,
            trust_penalty: 0.5,
        }
    }
}

/// The collaborative, poisoning-robust posture estimator ("censorship weather").
///
/// One per client. Feed it first-hand outcomes with [`PostureNet::ingest_local`]
/// and peer reports with [`PostureNet::ingest_peer`]; read the robust aggregate
/// the router should use with [`PostureNet::posture`].
pub struct PostureNet {
    params: WeatherParams,
    local: HashMap<TransportClass, LocalBelief>,
    peers: Vec<PeerSample>,
    trust: HashMap<u64, f64>,
}

impl Default for PostureNet {
    fn default() -> Self {
        Self::new()
    }
}

impl PostureNet {
    /// Baseline weight of a fully-confident first-hand belief - deliberately far
    /// above any single peer's max weight (`1.0`), so your own eyes dominate.
    pub const SELF_BASE: f64 = 8.0;

    /// Observation count at which first-hand confidence is ~half-saturated.
    const CONF_K: f64 = 3.0;

    /// A peer claim within this of a first-hand outcome is "agreement".
    const AGREE_TOL: f64 = 0.5;

    /// Create a tracker with default [`WeatherParams`].
    #[must_use]
    pub fn new() -> Self {
        Self::with_params(WeatherParams::default())
    }

    /// Create a tracker with the given [`WeatherParams`].
    #[must_use]
    pub fn with_params(params: WeatherParams) -> Self {
        Self {
            params,
            local: HashMap::new(),
            peers: Vec::new(),
            trust: HashMap::new(),
        }
    }

    /// Fold a first-hand dial outcome for `class` into the local belief, and use
    /// it as ground truth to score every peer that recently claimed something
    /// about this class (agreement -> trust up, contradiction -> trust down).
    pub fn ingest_local(&mut self, class: TransportClass, success: bool, now: Instant) {
        let target = if success { 1.0 } else { 0.0 };
        let entry = self.local.entry(class).or_insert(LocalBelief {
            ewma: target,
            count: 0,
            at: now,
        });
        entry.ewma =
            (1.0 - self.params.local_alpha) * entry.ewma + self.params.local_alpha * target;
        entry.count = entry.count.saturating_add(1);
        entry.at = now;
        self.score_peers(class, target, now);
        self.prune(now);
    }

    /// Ingest a peer's claim that `class` had viability `viable  in  [0,1]`.
    /// Unknown sources are admitted at [`WeatherParams::new_trust`] - low, so a
    /// flood of fresh identities carries little weight until any of them earns
    /// trust by being right.
    pub fn ingest_peer(&mut self, source: u64, class: TransportClass, viable: f64, now: Instant) {
        self.trust.entry(source).or_insert(self.params.new_trust);
        self.peers.push(PeerSample {
            source,
            class,
            viable: viable.clamp(0.0, 1.0),
            at: now,
        });
        self.prune(now);
    }

    /// The robust aggregate posture the router should use: for each class, the
    /// **weighted median** of the first-hand belief (high, confidence-scaled
    /// weight) and the in-window peer samples (trust x recency weight). A class
    /// with no evidence at all defaults to fully viable (optimistic - never
    /// gate a bearer we have no reason to distrust).
    #[must_use]
    pub fn posture(&self, now: Instant) -> Posture {
        let mut p = Posture::open();
        for &class in &TransportClass::ALL {
            if let Some(v) = self.aggregate_class(class, now) {
                p.set(class, v);
            }
        }
        p
    }

    /// The client's own first-hand beliefs, to be broadcast to peers by the
    /// gossip layer. Only classes the client has actually measured are reported
    /// (no echoing hearsay - that would amplify poison).
    #[must_use]
    pub fn local_report(&self, now: Instant) -> Vec<(TransportClass, f64)> {
        self.local
            .iter()
            .filter(|(_, b)| now.duration_since(b.at) <= self.params.window)
            .map(|(&c, b)| (c, b.ewma))
            .collect()
    }

    /// Current reputation of `source` in `[0,1]` (observability / tests).
    #[must_use]
    pub fn trust_of(&self, source: u64) -> f64 {
        self.trust
            .get(&source)
            .copied()
            .unwrap_or(self.params.new_trust)
    }

    // -- internals --

    /// Weighted median of `{ self, peers }` viability for one class, or `None`
    /// if there is no evidence.
    fn aggregate_class(&self, class: TransportClass, now: Instant) -> Option<f64> {
        let mut samples: Vec<(f64, f64)> = Vec::new(); // (value, weight)

        if let Some(b) = self.local.get(&class) {
            if now.duration_since(b.at) <= self.params.window {
                // Confidence saturates with observation count.
                let conf = b.count as f64 / (b.count as f64 + Self::CONF_K);
                samples.push((b.ewma, Self::SELF_BASE * conf));
            }
        }
        for s in self.peers.iter().filter(|s| s.class == class) {
            let age = now.duration_since(s.at);
            if age > self.params.window {
                continue;
            }
            let rec = 1.0 - (age.as_secs_f64() / self.params.window.as_secs_f64()).min(1.0);
            // Weight is trust **squared** x recency. Squaring is the Sybil
            // defence: unearned trust (a fresh source at `new_trust` = 0.1)
            // contributes ~0.01 - so even a flood of 100 fresh identities sums
            // to ~1.0, below a single confident first-hand observation, while an
            // ally that has *earned* trust (0.7 -> 0.49) still carries real
            // weight. Influence is thus super-linear in earned reputation and
            // negligible for the cheap-to-mint many.
            let w = self.trust_of(s.source).powi(2) * rec;
            if w > 0.0 {
                samples.push((s.viable, w));
            }
        }
        weighted_median(&mut samples)
    }

    /// Reward/punish peers whose recent claims for `class` (dis)agree with a
    /// first-hand `truth` (1.0 viable / 0.0 blocked).
    fn score_peers(&mut self, class: TransportClass, truth: f64, now: Instant) {
        for s in &self.peers {
            if s.class != class || now.duration_since(s.at) > self.params.window {
                continue;
            }
            let agrees = (s.viable - truth).abs() < Self::AGREE_TOL;
            let rep = self.trust.entry(s.source).or_insert(self.params.new_trust);
            if agrees {
                *rep += self.params.trust_reward * (1.0 - *rep);
            } else {
                *rep *= 1.0 - self.params.trust_penalty;
            }
            *rep = rep.clamp(0.0, 1.0);
        }
    }

    fn prune(&mut self, now: Instant) {
        let window = self.params.window;
        self.peers.retain(|s| now.duration_since(s.at) <= window);
        self.local.retain(|_, b| now.duration_since(b.at) <= window);
    }
}

// Gossip wire format - the seam the discovery layer carries

/// A gossip-able posture report: one client's first-hand class beliefs for one
/// network, tagged with a per-epoch pseudonymous `source`. This is exactly what
/// [`PostureNet::local_report`] produces and what a receiver folds in via
/// [`PostureNet::ingest_peer`] - so the discovery/gossip layer only has to carry
/// these opaque bytes between clients that share a [`crate::success_rate::NetworkFingerprint`].
///
/// Wire layout (little-endian): `network[16] || source[8] || count[1] ||
/// countx(class_tag[1] || viability[1])`, where `viability` is the `[0,1]` value
/// quantised to a byte. Coarse + non-identifying by construction (no
/// destinations, keys, or streams).
#[derive(Debug, Clone, PartialEq)]
pub struct PostureReport {
    /// The network fingerprint digest this report is about.
    pub network: [u8; 16],
    /// Per-epoch pseudonymous source id (assigned by the gossip layer).
    pub source: u64,
    /// First-hand `(class, viability)` beliefs.
    pub entries: Vec<(TransportClass, f64)>,
}

impl PostureReport {
    /// Maximum classes in one report (there are only [`TransportClass::ALL`]).
    const MAX_ENTRIES: usize = 8;

    /// Encode to the compact wire form.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let n = self.entries.len().min(Self::MAX_ENTRIES);
        let mut out = Vec::with_capacity(16 + 8 + 1 + n * 2);
        out.extend_from_slice(&self.network);
        out.extend_from_slice(&self.source.to_le_bytes());
        out.push(n as u8);
        for &(class, v) in self.entries.iter().take(n) {
            out.push(class.as_u8());
            out.push((v.clamp(0.0, 1.0) * 255.0).round() as u8);
        }
        out
    }

    /// Decode from the wire form; `None` on malformed input (unknown class tags
    /// are skipped rather than failing the whole report).
    #[must_use]
    pub fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() < 25 {
            return None;
        }
        let mut network = [0u8; 16];
        network.copy_from_slice(buf.get(0..16)?);
        let source = u64::from_le_bytes(buf.get(16..24)?.try_into().ok()?);
        let count = *buf.get(24)? as usize;
        if count > Self::MAX_ENTRIES || buf.len() < 25 + count * 2 {
            return None;
        }
        let mut entries = Vec::with_capacity(count);
        for i in 0..count {
            let off = 25 + i * 2;
            let tag = *buf.get(off)?;
            let vq = *buf.get(off + 1)?;
            if let Some(class) = TransportClass::from_u8(tag) {
                entries.push((class, f64::from(vq) / 255.0));
            }
        }
        Some(Self {
            network,
            source,
            entries,
        })
    }
}

impl PostureNet {
    /// Build a [`PostureReport`] for broadcast: the client's first-hand beliefs
    /// tagged with `network` + the per-epoch `source` pseudonym. Returns `None`
    /// if there is nothing measured worth sharing.
    #[must_use]
    pub fn build_report(
        &self,
        network: [u8; 16],
        source: u64,
        now: Instant,
    ) -> Option<PostureReport> {
        let entries = self.local_report(now);
        if entries.is_empty() {
            return None;
        }
        Some(PostureReport {
            network,
            source,
            entries,
        })
    }

    /// Fold every `(class, viability)` in a decoded peer [`PostureReport`] into
    /// this client's estimate. The discovery layer calls this on each received,
    /// same-network report.
    pub fn ingest_report(&mut self, report: &PostureReport, now: Instant) {
        for &(class, viable) in &report.entries {
            self.ingest_peer(report.source, class, viable, now);
        }
    }
}

/// Weighted median: the value at which cumulative sorted weight first reaches
/// half the total. Robust - an adversary must control > 50% of the weight to
/// move it. `None` if there are no samples.
fn weighted_median(samples: &mut [(f64, f64)]) -> Option<f64> {
    let total: f64 = samples.iter().map(|&(_, w)| w).sum();
    if samples.is_empty() || total <= 0.0 {
        return None;
    }
    samples.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal));
    let half = total / 2.0;
    let mut acc = 0.0;
    for &(v, w) in samples.iter() {
        acc += w;
        if acc >= half {
            return Some(v);
        }
    }
    samples.last().map(|&(v, _)| v)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now0() -> Instant {
        Instant::now()
    }

    // ---- weighted median ----

    #[test]
    fn weighted_median_ignores_low_weight_outliers() {
        // One heavy sample at 0.9, three light liars at 0.0 -> median stays high.
        let mut s = vec![(0.9, 10.0), (0.0, 1.0), (0.0, 1.0), (0.0, 1.0)];
        assert!(weighted_median(&mut s).unwrap() > 0.5);
        // Flip the weights -> the 0.0 side now owns > half -> median drops.
        let mut s2 = vec![(0.9, 1.0), (0.0, 10.0)];
        assert!(weighted_median(&mut s2).unwrap() < 0.5);
        assert!(weighted_median(&mut []).is_none());
    }

    // ---- first-hand dominance ----

    #[test]
    fn first_hand_beats_contradicting_hearsay() {
        // The client has measured UDP dead. A handful of fresh peers insist it
        // works. Self must win.
        let mut w = PostureNet::new();
        let t = now0();
        for _ in 0..5 {
            w.ingest_local(TransportClass::Udp, false, t); // first-hand: blocked
        }
        for src in 0..5u64 {
            w.ingest_peer(src, TransportClass::Udp, 1.0, t); // liars: "works!"
        }
        let p = w.posture(t);
        assert!(
            p.viability(TransportClass::Udp) < Posture::GATE_THRESHOLD,
            "first-hand block must survive fresh-peer lies: {}",
            p.viability(TransportClass::Udp)
        );
    }

    // ---- Sybil resistance ----

    #[test]
    fn sybil_flood_of_fresh_identities_cannot_flip_belief() {
        // 100 brand-new Sybils all shout "UDP works". Against a single first-hand
        // "blocked", their aggregate weight (100 x new_trust) must still not move
        // the weighted median off the client's own measurement.
        let mut w = PostureNet::new();
        let t = now0();
        w.ingest_local(TransportClass::Udp, false, t);
        for src in 0..100u64 {
            w.ingest_peer(src, TransportClass::Udp, 1.0, t);
        }
        let p = w.posture(t);
        assert!(
            p.viability(TransportClass::Udp) < 0.5,
            "a Sybil flood of untrusted identities must not flip belief: {}",
            p.viability(TransportClass::Udp)
        );
    }

    #[test]
    fn a_lying_source_loses_its_trust() {
        // A peer repeatedly claims UDP works; the client repeatedly measures it
        // blocked. The liar's reputation must crater toward zero.
        let mut w = PostureNet::new();
        let t = now0();
        let liar = 42u64;
        let start_trust = {
            w.ingest_peer(liar, TransportClass::Udp, 1.0, t);
            w.trust_of(liar)
        };
        for _ in 0..8 {
            w.ingest_peer(liar, TransportClass::Udp, 1.0, t); // "works!"
            w.ingest_local(TransportClass::Udp, false, t); // reality: blocked
        }
        assert!(
            w.trust_of(liar) < start_trust * 0.25,
            "a caught liar must lose trust: {} -> {}",
            start_trust,
            w.trust_of(liar)
        );
    }

    // ---- the collaborative speedup (the whole point) ----

    #[test]
    fn trusted_peers_warn_before_first_hand_failure() {
        // The client has NO first-hand data on UDP. Several peers that have
        // EARNED trust (by being right about TcpTls) now warn UDP is blocked.
        // The client should believe them and gate UDP *before* wasting its own
        // probe - the collective early-warning that makes the swarm out-adapt
        // the censor.
        let mut w = PostureNet::new();
        let t = now0();
        let allies: Vec<u64> = (10..16).collect();
        // Earn trust: allies correctly report TcpTls viable, client confirms.
        for &a in &allies {
            w.ingest_peer(a, TransportClass::TcpTls, 1.0, t);
        }
        for _ in 0..4 {
            w.ingest_local(TransportClass::TcpTls, true, t); // confirms allies
        }
        assert!(
            w.trust_of(allies[0]) > 0.4,
            "allies should have earned trust"
        );
        // Now allies warn UDP is dead; client has never tried UDP.
        for &a in &allies {
            w.ingest_peer(a, TransportClass::Udp, 0.0, t);
        }
        let p = w.posture(t);
        assert!(
            p.viability(TransportClass::Udp) < Posture::GATE_THRESHOLD,
            "trusted-peer corroboration must gate UDP pre-emptively: {}",
            p.viability(TransportClass::Udp)
        );
    }

    #[test]
    fn earned_trust_can_correct_a_stale_first_hand_belief() {
        // The client saw UDP work ONCE long-signal ago (low count -> low self
        // weight). Many high-trust allies now agree it is blocked. A legitimate
        // collective correction should be allowed to win - this is NOT poisoning
        // (the allies earned trust and agree), it is the swarm being right.
        let mut w = PostureNet::new();
        let t = now0();
        w.ingest_local(TransportClass::Udp, true, t); // single stale "worked"
        let allies: Vec<u64> = (20..40).collect();
        // Earn strong trust on a different class first.
        for &a in &allies {
            w.ingest_peer(a, TransportClass::Http, 1.0, t);
        }
        for _ in 0..6 {
            w.ingest_local(TransportClass::Http, true, t);
        }
        // Now a large trusted majority reports UDP blocked.
        for &a in &allies {
            w.ingest_peer(a, TransportClass::Udp, 0.0, t);
        }
        let p = w.posture(t);
        assert!(
            p.viability(TransportClass::Udp) < 0.5,
            "a large earned-trust majority should correct a weak stale belief: {}",
            p.viability(TransportClass::Udp)
        );
    }

    // ---- neutrality / defaults ----

    #[test]
    fn unknown_classes_default_viable() {
        let w = PostureNet::new();
        let p = w.posture(now0());
        for c in TransportClass::ALL {
            assert!(p.viability(c) > 0.9, "no evidence => optimistic (viable)");
        }
    }

    // ---- wire codec + end-to-end collaborative loop ----

    #[test]
    fn posture_report_round_trips() {
        let r = PostureReport {
            network: [9u8; 16],
            source: 0xABCD_1234_5678_9F01,
            entries: vec![
                (TransportClass::Udp, 0.0),
                (TransportClass::TcpTls, 1.0),
                (TransportClass::Http, 0.5),
            ],
        };
        let decoded = PostureReport::decode(&r.encode()).expect("decode");
        assert_eq!(decoded.network, r.network);
        assert_eq!(decoded.source, r.source);
        assert_eq!(decoded.entries.len(), 3);
        // Viability survives the byte quantisation to within 1/255.
        for ((c1, v1), (c2, v2)) in r.entries.iter().zip(decoded.entries.iter()) {
            assert_eq!(c1, c2);
            assert!((v1 - v2).abs() < 0.01, "{v1} vs {v2}");
        }
        // Malformed input is rejected, not panicked.
        assert!(PostureReport::decode(&[0u8; 3]).is_none());
    }

    #[test]
    fn collaborative_loop_over_the_wire_warns_a_peer() {
        // The full swarm loop at the protocol level: client A measures UDP dead
        // and TLS fine; A's report is encoded, carried (opaque bytes), decoded,
        // and folded into client B. After B independently confirms A was right
        // about TLS (earning A trust), A's UDP warning gates UDP on B *without B
        // ever probing UDP*. This is the collective early-warning, end-to-end.
        let t = now0();
        let net = [7u8; 16];
        let a_source = 1001u64;

        // Client A's first-hand experience.
        let mut a = PostureNet::new();
        a.ingest_local(TransportClass::TcpTls, true, t);
        a.ingest_local(TransportClass::Udp, false, t);

        // Serialize -> carry -> deserialize (what the gossip layer does).
        let wire = a.build_report(net, a_source, t).expect("report").encode();
        let received = PostureReport::decode(&wire).expect("decode");

        // Client B folds it in.
        let mut b = PostureNet::new();
        b.ingest_report(&received, t);
        // B confirms A's TLS claim first-hand -> A earns trust on B.
        for _ in 0..5 {
            b.ingest_local(TransportClass::TcpTls, true, t);
        }
        assert!(b.trust_of(a_source) > 0.4, "A should have earned B's trust");

        // A's UDP warning must now gate UDP on B, with no first-hand B probe.
        let p = b.posture(t);
        assert!(
            p.viability(TransportClass::Udp) < Posture::GATE_THRESHOLD,
            "a trusted peer's UDP warning must pre-emptively gate UDP on B: {}",
            p.viability(TransportClass::Udp)
        );
    }

    #[test]
    fn local_report_only_emits_measured_classes() {
        let mut w = PostureNet::new();
        let t = now0();
        w.ingest_local(TransportClass::Http, true, t);
        // Peer hearsay about UDP must NOT appear in our own report (no poison echo).
        w.ingest_peer(1, TransportClass::Udp, 0.0, t);
        let report = w.local_report(t);
        assert_eq!(report.len(), 1);
        assert_eq!(report[0].0, TransportClass::Http);
    }
}
