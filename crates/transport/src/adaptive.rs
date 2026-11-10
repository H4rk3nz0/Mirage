//! Adversarial, network-aware adaptive routing - the **routing-entropy engine**.
//!
//! # Why this exists (and why it is not just [`crate::select`])
//!
//! [`crate::select::rank`] already turns the [`SuccessRateMap`] into a *decision* -
//! but a **deterministic** one: best-first order, sticky to the last winner.
//! Determinism is the flaw. A censor watching a client that *always* tries
//! Reality, then Hysteria2, then ss2022 learns that order and blocks down the
//! list; and a client that sticks to one winning bridge *hammers* it, making
//! that bridge enumerable and cheap to block. A fixed policy is a fixed target.
//!
//! The censor is not noise - it is an **adaptive adversary** that changes the
//! payoff of a route the moment you rely on it. That is exactly the setting of
//! the **adversarial multi-armed bandit** ([EXP3], Auer-Cesa-Bianchi-Freund-
//! Schapire 2002), which - unlike UCB/Thompson sampling, whose guarantees
//! assume a *stationary* reward distribution - bounds regret against an
//! adversary who may choose rewards *after* seeing your strategy. EXP3 makes
//! exploration (unpredictability) a first-class, tunable quantity: every arm is
//! played with probability at least `γ/K`, so the client's transport choice is a
//! *distribution*, never a fixed sequence - the "routing entropy" a censor
//! cannot pre-empt.
//!
//! Three ideas compose here:
//! 1. **[`Exp3`]** - the adversarial bandit over transport arms. Warm-started
//!    from the [`SuccessRateMap`] so past learning is not thrown away, updated
//!    online with an importance-weighted, EXP3.S-flavoured recovery floor so a
//!    *blocked* arm can climb back when the environment shifts (a censor lifts a
//!    block, or the user moves to a new network).
//! 2. **[`DiversityGuard`]** - caps any single transport's share of recent
//!    selections, so load spreads across arms/bridges. Anti-enumeration *and*
//!    extra entropy, as a hard constraint rather than a hope.
//! 3. **[`Posture`]** - a censorship-posture read that gates whole transport
//!    *classes* at once (UDP throttled -> down-weight every QUIC carrier
//!    immediately, rather than re-learning each one from failures).
//!
//! # Purity
//!
//! Like the rest of `mirage-transport`, this module is **I/O-free and
//! dependency-free**. Randomness is a caller-seeded [`SplitMix64`] (seed from
//! the OS CSPRNG at the client edge), so the whole engine is deterministically
//! testable - including the adversarial-adaptation and convergence properties.
//!
//! [EXP3]: https://doi.org/10.1137/S0097539701398375

use crate::success_rate::{NetworkFingerprint, SuccessRateMap};
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

// SplitMix64 - dependency-free, deterministically seedable PRNG

/// A tiny [SplitMix64] generator. Not cryptographic - used only to sample the
/// selection distribution; the *security* of routing comes from the entropy of
/// the distribution, not from the PRNG being unpredictable to an observer (a
/// censor never sees the draws, only the resulting traffic). Seed it from the
/// OS CSPRNG in production; seed it with a fixed value in tests.
///
/// [SplitMix64]: https://prng.di.unimi.it/splitmix64.c
#[derive(Debug, Clone)]
pub struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    /// Construct from a 64-bit seed.
    #[must_use]
    pub fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Uniform `f64` in `[0, 1)`.
    pub fn next_f64(&mut self) -> f64 {
        // 53 significant bits -> uniform in [0,1).
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }
}

// Transport classes + censorship posture

/// The network-layer class a transport rides on. A censor rarely blocks one
/// carrier in isolation; it blocks a *bearer* - all UDP, all plaintext HTTP,
/// poisons DNS - so gating by class reacts far faster than re-learning each
/// carrier from individual failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransportClass {
    /// TCP + a real TLS 1.3 record layer (Reality, VLESS-over-Reality).
    TcpTls,
    /// UDP + QUIC (Hysteria2, HTTP/3 / MASQUE).
    Udp,
    /// TCP + HTTP request/response (meek, WebSocket, DoH-over-HTTP).
    Http,
    /// DNS bearer (dnstt).
    Dns,
    /// Opaque bytes over TCP (Shadowsocks-2022, raw/obfs).
    TcpOpaque,
}

impl TransportClass {
    /// Every bearer class, for iteration (e.g. building an aggregate posture).
    pub const ALL: [TransportClass; 5] = [
        TransportClass::TcpTls,
        TransportClass::Udp,
        TransportClass::Http,
        TransportClass::Dns,
        TransportClass::TcpOpaque,
    ];

    /// Stable 1-byte wire tag (for the collaborative posture gossip codec).
    #[must_use]
    pub fn as_u8(self) -> u8 {
        match self {
            TransportClass::TcpTls => 0,
            TransportClass::Udp => 1,
            TransportClass::Http => 2,
            TransportClass::Dns => 3,
            TransportClass::TcpOpaque => 4,
        }
    }

    /// Inverse of [`TransportClass::as_u8`]; `None` on an unknown tag.
    #[must_use]
    pub fn from_u8(b: u8) -> Option<Self> {
        Some(match b {
            0 => TransportClass::TcpTls,
            1 => TransportClass::Udp,
            2 => TransportClass::Http,
            3 => TransportClass::Dns,
            4 => TransportClass::TcpOpaque,
            _ => return None,
        })
    }
}

/// Map a transport name (as [`crate::success_rate`] records them / the client's
/// `describe_mode`) to its bearer class. Unknown names default to `TcpTls` -
/// the most conservative (widely-reachable) bearer.
#[must_use]
pub fn class_of(transport: &str) -> TransportClass {
    match transport {
        "hysteria2" | "h3" => TransportClass::Udp,
        "meek" | "websocket" | "ws" | "doh" => TransportClass::Http,
        "dnstt" => TransportClass::Dns,
        "ss2022" | "shadowsocks" | "raw" | "obfs" | "obfs-tcp" => TransportClass::TcpOpaque,
        // "reality", "vless", "invite", "explicit-hex", and anything unknown.
        _ => TransportClass::TcpTls,
    }
}

/// A live read of what the local network is doing to each bearer class, each in
/// `[0, 1]` (1 = fully viable, 0 = dead). Fed by observation (see
/// [`Posture::observe_outcome`]) and/or explicit probes at the client edge.
///
/// The posture gates the bandit: an arm whose class viability is below
/// [`Posture::GATE_THRESHOLD`] is masked out of the selection distribution
/// (but never permanently - see [`AdaptiveRouter::select`]).
#[derive(Debug, Clone, Copy)]
pub struct Posture {
    tcp_tls: f64,
    udp: f64,
    http: f64,
    dns: f64,
    tcp_opaque: f64,
}

impl Default for Posture {
    fn default() -> Self {
        Self::open()
    }
}

impl Posture {
    /// A class scoring below this is considered blocked and gated out.
    pub const GATE_THRESHOLD: f64 = 0.15;

    /// EWMA weight for a fresh observation folded into a class score.
    const OBS_ALPHA: f64 = 0.25;

    /// Everything reachable - the optimistic prior before any observation.
    #[must_use]
    pub fn open() -> Self {
        Self {
            tcp_tls: 1.0,
            udp: 1.0,
            http: 1.0,
            dns: 1.0,
            tcp_opaque: 1.0,
        }
    }

    /// Viability score for `class` in `[0, 1]`.
    #[must_use]
    pub fn viability(&self, class: TransportClass) -> f64 {
        match class {
            TransportClass::TcpTls => self.tcp_tls,
            TransportClass::Udp => self.udp,
            TransportClass::Http => self.http,
            TransportClass::Dns => self.dns,
            TransportClass::TcpOpaque => self.tcp_opaque,
        }
    }

    fn slot_mut(&mut self, class: TransportClass) -> &mut f64 {
        match class {
            TransportClass::TcpTls => &mut self.tcp_tls,
            TransportClass::Udp => &mut self.udp,
            TransportClass::Http => &mut self.http,
            TransportClass::Dns => &mut self.dns,
            TransportClass::TcpOpaque => &mut self.tcp_opaque,
        }
    }

    /// Fold a single dial outcome for `transport` into its class score via an
    /// EWMA (success -> toward 1, block/timeout -> toward 0). Cheap online
    /// posture estimation with no extra probes.
    pub fn observe_outcome(&mut self, transport: &str, success: bool) {
        let class = class_of(transport);
        let target = if success { 1.0 } else { 0.0 };
        let slot = self.slot_mut(class);
        *slot = (1.0 - Self::OBS_ALPHA) * *slot + Self::OBS_ALPHA * target;
    }

    /// Directly set a class score (for an explicit active probe: e.g. a UDP
    /// echo test sets `Udp`, a DNS-integrity check sets `Dns`).
    pub fn set(&mut self, class: TransportClass, viability: f64) {
        *self.slot_mut(class) = viability.clamp(0.0, 1.0);
    }
}

// Exp3 - the adversarial multi-armed bandit

/// [EXP3] over `K` arms, with an EXP3.S-flavoured recovery floor.
///
/// State is a weight per arm. The play distribution mixes the weight-
/// proportional distribution with the uniform distribution by the exploration
/// rate `γ`:
///
/// ```text
///   p_i = (1 - γ) * w_i / sum _j w_j  +  γ / K
/// ```
///
/// so every arm keeps probability >= `γ/K` (the entropy floor). After playing
/// arm `a` and observing `reward  in  [0,1]`, the weight is updated with an
/// **importance-weighted** estimate (`reward / p_a`, unbiased because only the
/// played arm is observed) exponentiated by `γ`:
///
/// ```text
///   w_a <- w_a * exp(γ * (reward / p_a) / K)
/// ```
///
/// Two engineering additions keep it robust for circumvention:
/// - **renormalisation** to keep `sum  w` near `K` (numerical stability across
///   long-lived sessions), and
/// - a **recovery floor** `w_i >= recovery * (sum w)/K`, so a heavily-blocked arm
///   never decays past a seed it can grow back from when the environment shifts
///   (a censor lifts a block, or the user changes networks). Standard EXP3 lets
///   a beaten arm decay to ~0 and is slow to recover - fatal in a setting where
///   what is blocked today is often reachable tomorrow.
///
/// [EXP3]: https://doi.org/10.1137/S0097539701398375
#[derive(Debug, Clone)]
pub struct Exp3 {
    weights: Vec<f64>,
    gamma: f64,
    recovery: f64,
}

impl Exp3 {
    /// `k` arms, exploration rate `gamma  in  (0, 1]`, recovery floor fraction
    /// `recovery  in  [0, 1)`. Weights start uniform (`1.0`).
    #[must_use]
    pub fn new(k: usize, gamma: f64, recovery: f64) -> Self {
        Self {
            weights: vec![1.0; k.max(1)],
            gamma: gamma.clamp(1e-3, 1.0),
            recovery: recovery.clamp(0.0, 0.5),
        }
    }

    /// Number of arms.
    #[must_use]
    pub fn arms(&self) -> usize {
        self.weights.len()
    }

    /// Overwrite arm `i`'s weight (used for warm-starting from history).
    fn set_weight(&mut self, i: usize, w: f64) {
        if let Some(slot) = self.weights.get_mut(i) {
            *slot = w.max(1e-9);
        }
    }

    /// Write the current play distribution into `out` (resized to `K`).
    pub fn probs_into(&self, out: &mut Vec<f64>) {
        let k = self.weights.len();
        out.clear();
        out.resize(k, 0.0);
        if k == 0 {
            return;
        }
        let sum: f64 = self.weights.iter().sum();
        let unif = self.gamma / k as f64;
        if sum <= 0.0 || !sum.is_finite() {
            out.iter_mut().for_each(|p| *p = 1.0 / k as f64);
            return;
        }
        for (o, &w) in out.iter_mut().zip(self.weights.iter()) {
            *o = (1.0 - self.gamma) * (w / sum) + unif;
        }
    }

    /// The play probability of a single arm.
    #[must_use]
    pub fn prob(&self, arm: usize) -> f64 {
        let mut p = Vec::new();
        self.probs_into(&mut p);
        p.get(arm).copied().unwrap_or(0.0)
    }

    /// Sample an arm from the play distribution given a uniform draw
    /// `r01  in  [0,1)`. Inverse-CDF; returns the last arm on rounding overflow.
    #[must_use]
    pub fn select(&self, r01: f64) -> usize {
        let mut probs = Vec::new();
        self.probs_into(&mut probs);
        let mut acc = 0.0;
        for (i, &p) in probs.iter().enumerate() {
            acc += p;
            if r01 < acc {
                return i;
            }
        }
        self.weights.len().saturating_sub(1)
    }

    /// EXP3 update after playing `arm` and observing `reward  in  [0,1]`.
    /// `p_arm` is the probability with which `arm` was actually played (as
    /// returned by [`Exp3::prob`] at selection time - importance weighting needs
    /// the *realised* selection probability, which posture/diversity masking may
    /// have changed from the bare EXP3 probability).
    pub fn update(&mut self, arm: usize, reward: f64, p_arm: f64) {
        let k = self.weights.len();
        if k == 0 || arm >= k {
            return;
        }
        let reward = reward.clamp(0.0, 1.0);
        let p = p_arm.max(1e-6); // guard divide-by-zero
        let estimated = reward / p; // unbiased importance-weighted estimate
        let factor = (self.gamma * estimated / k as f64).exp();
        if let Some(w) = self.weights.get_mut(arm) {
            *w *= factor;
            if !w.is_finite() {
                *w = f64::MAX / 2.0;
            }
        }
        self.stabilise();
    }

    /// Renormalise to `sum w ~ K` and apply the recovery floor.
    fn stabilise(&mut self) {
        let k = self.weights.len();
        if k == 0 {
            return;
        }
        let sum: f64 = self.weights.iter().sum();
        if sum > 0.0 && sum.is_finite() {
            let scale = k as f64 / sum;
            for w in &mut self.weights {
                *w *= scale;
            }
        } else {
            self.weights.iter_mut().for_each(|w| *w = 1.0);
        }
        // Recovery floor: no arm below `recovery * (sum w)/K` = `recovery` (sum w==K).
        let floor = self.recovery;
        if floor > 0.0 {
            for w in &mut self.weights {
                if *w < floor {
                    *w = floor;
                }
            }
        }
    }
}

// DiversityGuard - anti-enumeration share cap

/// Tracks recent selections per arm within a sliding time window and reports
/// which arms have exceeded their allowed share. Spreading selections defeats
/// bridge/transport enumeration (a client that always picks the same bridge
/// makes it the cheapest thing in the world to block) and adds entropy on top
/// of EXP3's `γ/K` floor.
#[derive(Debug, Clone)]
struct DiversityGuard {
    window: Duration,
    max_share: f64,
    recent: VecDeque<(usize, Instant)>,
}

impl DiversityGuard {
    fn new(window: Duration, max_share: f64) -> Self {
        Self {
            window,
            max_share: max_share.clamp(0.05, 1.0),
            recent: VecDeque::new(),
        }
    }

    fn prune(&mut self, now: Instant) {
        while let Some(&(_, t)) = self.recent.front() {
            if now.duration_since(t) > self.window {
                self.recent.pop_front();
            } else {
                break;
            }
        }
    }

    fn record(&mut self, arm: usize, now: Instant) {
        self.prune(now);
        self.recent.push_back((arm, now));
    }

    /// `true` if `arm`'s share of the window already meets/exceeds `max_share`.
    /// Below `MIN_SAMPLES` observations nothing is capped (too little data to
    /// judge a share meaningfully).
    fn over_share(&mut self, arm: usize, now: Instant) -> bool {
        const MIN_SAMPLES: usize = 4;
        self.prune(now);
        let total = self.recent.len();
        if total < MIN_SAMPLES {
            return false;
        }
        let count = self.recent.iter().filter(|&&(a, _)| a == arm).count();
        (count as f64 / total as f64) >= self.max_share
    }
}

// AdaptiveRouter - the engine

/// Per-network bandit + diversity state.
struct NetState {
    /// Arm index -> transport name (stable order for this network).
    arms: Vec<&'static str>,
    exp3: Exp3,
    diversity: DiversityGuard,
    /// Realised selection probabilities from the most recent [`select`], indexed
    /// by arm - importance weighting in [`record`] needs the probability the arm
    /// was *actually* played with (post posture/diversity masking).
    last_probs: Vec<f64>,
}

/// Tunable parameters for [`AdaptiveRouter`].
#[derive(Debug, Clone, Copy)]
pub struct RouterParams {
    /// EXP3 exploration rate `γ  in  (0,1]`. Higher = more entropy / faster to
    /// discover a newly-viable path, at some cost to short-term optimality.
    pub gamma: f64,
    /// EXP3.S recovery floor fraction - the minimum share of `sum w/K` any arm
    /// keeps, so a blocked arm can recover.
    pub recovery: f64,
    /// Diversity window: no arm may exceed `max_share` of selections within it.
    pub diversity_window: Duration,
    /// Max share of recent selections any single arm may take.
    pub max_share: f64,
    /// Strength of the warm-start from history: initial weight is
    /// `exp(warm_start * rate)`, so a historically-successful transport starts
    /// ahead but never so far that exploration can't correct it.
    pub warm_start: f64,
}

impl Default for RouterParams {
    fn default() -> Self {
        Self {
            gamma: 0.12,
            recovery: 0.03,
            diversity_window: Duration::from_secs(120),
            max_share: 0.6,
            warm_start: 1.5,
        }
    }
}

/// The network-aware, adversarially-adaptive routing engine.
///
/// One instance per client. Call [`AdaptiveRouter::select`] to choose the
/// transport to try (sampled from an entropy-controlled, posture-gated,
/// diversity-constrained distribution), then [`AdaptiveRouter::record`] the
/// outcome so the next selection adapts. Reuses the client's existing
/// [`SuccessRateMap`] as the warm-start substrate - no telemetry is duplicated.
pub struct AdaptiveRouter {
    params: RouterParams,
    per_net: HashMap<[u8; 16], NetState>,
    rng: SplitMix64,
}

impl AdaptiveRouter {
    /// Construct with `seed` (draw it from the OS CSPRNG) and default params.
    #[must_use]
    pub fn new(seed: u64) -> Self {
        Self::with_params(seed, RouterParams::default())
    }

    /// Construct with explicit tunables.
    #[must_use]
    pub fn with_params(seed: u64, params: RouterParams) -> Self {
        Self {
            params,
            per_net: HashMap::new(),
            rng: SplitMix64::new(seed),
        }
    }

    /// Ensure a [`NetState`] exists for `network` whose arm set equals
    /// `candidates`, (re)building it warm-started from `history` when the
    /// candidate set changes.
    fn ensure_net(
        &mut self,
        network: &NetworkFingerprint,
        candidates: &[&'static str],
        history: &SuccessRateMap,
    ) {
        let key = network.digest;
        let rebuild = match self.per_net.get(&key) {
            Some(st) => st.arms != candidates,
            None => true,
        };
        if !rebuild {
            return;
        }
        let mut exp3 = Exp3::new(candidates.len(), self.params.gamma, self.params.recovery);
        for (i, &name) in candidates.iter().enumerate() {
            let stats = history.lookup(network, name);
            // Warm start: weight proportional to exp(warm_start * empirical rate). A transport
            // with no history uses rate()'s Laplace prior (~0.5), so it starts
            // near the middle - explored, not written off.
            exp3.set_weight(i, (self.params.warm_start * stats.rate()).exp());
        }
        exp3.stabilise();
        self.per_net.insert(
            key,
            NetState {
                arms: candidates.to_vec(),
                exp3,
                diversity: DiversityGuard::new(self.params.diversity_window, self.params.max_share),
                last_probs: vec![0.0; candidates.len()],
            },
        );
    }

    /// Select the transport to try for `network` from `candidates`.
    ///
    /// The selection distribution is: EXP3 play distribution -> **posture gate**
    /// (mask arms whose bearer class is blocked) -> **diversity cap** (mask arms
    /// over their recent share) -> renormalise -> sample. If every arm is masked
    /// (whole-network blackout, or all classes down), it falls back to the raw
    /// EXP3 distribution and finally to uniform - **never** returning `None`
    /// while candidates exist, because censorship is not assumed permanent and
    /// the client must keep a path to re-probe.
    ///
    /// Returns `None` only when `candidates` is empty.
    pub fn select(
        &mut self,
        network: &NetworkFingerprint,
        candidates: &[&'static str],
        history: &SuccessRateMap,
        posture: &Posture,
        now: Instant,
    ) -> Option<&'static str> {
        if candidates.is_empty() {
            return None;
        }
        self.ensure_net(network, candidates, history);
        let draw = self.rng.next_f64();
        let key = network.digest;
        let st = self.per_net.get_mut(&key)?;

        // 1. Base EXP3 play distribution.
        let mut probs = Vec::new();
        st.exp3.probs_into(&mut probs);

        // 2. Posture gate: zero arms whose bearer class is blocked.
        let mut masked = probs.clone();
        for (i, &name) in st.arms.iter().enumerate() {
            if posture.viability(class_of(name)) < Posture::GATE_THRESHOLD {
                masked[i] = 0.0;
            }
        }
        // 3. Diversity cap: zero arms over their recent share.
        for (i, m) in masked.iter_mut().enumerate() {
            if *m > 0.0 && st.diversity.over_share(i, now) {
                *m = 0.0;
            }
        }

        // 4. Choose the effective distribution with graceful fallback.
        let eff = pick_effective(&masked, &probs);

        // 5. Sample.
        let arm = sample(&eff, draw);

        // Stash realised probabilities for the importance-weighted update, then
        // record the pick for the diversity window.
        st.last_probs = eff;
        st.diversity.record(arm, now);
        st.arms.get(arm).copied()
    }

    /// Feed a dial outcome back: `reward  in  [0,1]` (1 = clean success, 0 =
    /// blocked/timeout; scale by latency in between). Updates the per-network
    /// EXP3 weights with the probability the arm was actually played with.
    pub fn record(&mut self, network: &NetworkFingerprint, transport: &str, reward: f64) {
        let key = network.digest;
        let Some(st) = self.per_net.get_mut(&key) else {
            return;
        };
        let Some(arm) = st.arms.iter().position(|&a| a == transport) else {
            return;
        };
        let p_arm = st
            .last_probs
            .get(arm)
            .copied()
            .unwrap_or_else(|| st.exp3.prob(arm));
        st.exp3.update(arm, reward, p_arm);
    }

    /// The current play distribution for `network` as `(transport, probability)`
    /// pairs - for logging / observability / tests. Empty if the network is
    /// unseen.
    #[must_use]
    pub fn distribution(&self, network: &NetworkFingerprint) -> Vec<(&'static str, f64)> {
        let key = network.digest;
        let Some(st) = self.per_net.get(&key) else {
            return Vec::new();
        };
        let mut probs = Vec::new();
        st.exp3.probs_into(&mut probs);
        st.arms.iter().copied().zip(probs).collect()
    }
}

/// Map a dial outcome to an EXP3 reward in `[0,1]`. A clean, fast success earns
/// the most; a slow success still beats a block; a block/timeout earns `0`.
/// `latency` is only consulted on success.
#[must_use]
pub fn outcome_reward(success: bool, latency: Option<Duration>) -> f64 {
    if !success {
        return 0.0;
    }
    match latency {
        None => 0.85,
        Some(l) => {
            // 1.0 at <=100 ms, decaying to a 0.5 floor by ~2 s - a working-but-slow
            // path is still strongly preferred over a blocked one.
            let ms = l.as_secs_f64() * 1000.0;
            let scaled = 1.0 - ((ms - 100.0).max(0.0) / 1900.0).min(1.0) * 0.5;
            scaled.clamp(0.5, 1.0)
        }
    }
}

/// Pick the effective distribution: prefer `masked` if it has positive mass,
/// else fall back to the raw EXP3 `base` (whole-network blackout - keep
/// probing), each renormalised.
fn pick_effective(masked: &[f64], base: &[f64]) -> Vec<f64> {
    let msum: f64 = masked.iter().sum();
    let src = if msum > 0.0 { masked } else { base };
    let sum: f64 = src.iter().sum();
    let k = src.len();
    if sum > 0.0 && sum.is_finite() {
        src.iter().map(|p| p / sum).collect()
    } else if k > 0 {
        vec![1.0 / k as f64; k]
    } else {
        Vec::new()
    }
}

/// Inverse-CDF sample from a normalised distribution.
fn sample(dist: &[f64], r01: f64) -> usize {
    let mut acc = 0.0;
    for (i, &p) in dist.iter().enumerate() {
        acc += p;
        if r01 < acc {
            return i;
        }
    }
    dist.len().saturating_sub(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net() -> NetworkFingerprint {
        NetworkFingerprint::from_digest([7u8; 16])
    }

    // ---- SplitMix64 ----

    #[test]
    fn splitmix_is_deterministic_and_in_range() {
        let mut a = SplitMix64::new(42);
        let mut b = SplitMix64::new(42);
        for _ in 0..1000 {
            let x = a.next_f64();
            assert_eq!(x, b.next_f64());
            assert!((0.0..1.0).contains(&x));
        }
        // Different seeds diverge.
        let mut c = SplitMix64::new(43);
        assert_ne!(SplitMix64::new(42).next_f64(), c.next_f64());
    }

    // ---- Exp3 core ----

    #[test]
    fn probs_sum_to_one_and_respect_entropy_floor() {
        let e = Exp3::new(5, 0.2, 0.0);
        let mut p = Vec::new();
        e.probs_into(&mut p);
        let sum: f64 = p.iter().sum();
        assert!((sum - 1.0).abs() < 1e-9, "probs sum to 1, got {sum}");
        // Every arm >= γ/K.
        for &pi in &p {
            assert!(pi >= 0.2 / 5.0 - 1e-9, "arm below entropy floor: {pi}");
        }
    }

    #[test]
    fn converges_toward_best_arm_stationary() {
        // Arm 0 always rewards 1, others always 0. EXP3 should push arm 0's
        // probability high (but never above 1-γ+γ/K, the exploration ceiling).
        let mut e = Exp3::new(4, 0.1, 0.0);
        for _ in 0..500 {
            let p0 = e.prob(0);
            e.update(0, 1.0, p0);
        }
        let p0 = e.prob(0);
        let ceiling = 1.0 - 0.1 + 0.1 / 4.0;
        assert!(p0 > 0.7, "best arm should dominate, got {p0}");
        assert!(
            p0 <= ceiling + 1e-9,
            "cannot exceed exploration ceiling {ceiling}, got {p0}"
        );
    }

    #[test]
    fn adapts_when_best_arm_is_blocked_adversarial() {
        // THE property: arm 0 is best, then a censor blocks it (reward->0) and
        // arm 1 becomes the good one. The bandit must shift its mass to arm 1.
        let mut e = Exp3::new(3, 0.15, 0.03);
        // Phase 1: arm 0 good.
        for _ in 0..300 {
            let p0 = e.prob(0);
            e.update(0, 1.0, p0);
        }
        assert!(e.prob(0) > 0.6, "arm 0 should lead after phase 1");
        // Phase 2: arm 0 blocked, arm 1 now good.
        for _ in 0..300 {
            let p0 = e.prob(0);
            e.update(0, 0.0, p0); // blocked
            let p1 = e.prob(1);
            e.update(1, 1.0, p1); // now the winner
        }
        assert!(
            e.prob(1) > e.prob(0),
            "mass must move to arm 1 after arm 0 is blocked: p0={} p1={}",
            e.prob(0),
            e.prob(1)
        );
        assert!(
            e.prob(1) > 0.5,
            "arm 1 should now dominate, got {}",
            e.prob(1)
        );
    }

    #[test]
    fn blocked_arm_can_recover_when_unblocked() {
        // Non-stationarity: an arm crushed to the floor climbs back when it
        // starts winning again (the recovery floor keeps a seed alive).
        let mut e = Exp3::new(3, 0.15, 0.05);
        for _ in 0..400 {
            let p0 = e.prob(0);
            e.update(0, 0.0, p0); // arm 0 blocked hard
            let p1 = e.prob(1);
            e.update(1, 1.0, p1);
        }
        let low = e.prob(0);
        // Now arm 0 is reachable again and best.
        for _ in 0..400 {
            let p0 = e.prob(0);
            e.update(0, 1.0, p0);
            let p1 = e.prob(1);
            e.update(1, 0.0, p1);
        }
        assert!(
            e.prob(0) > low + 0.2,
            "recovered arm must climb: {low} -> {}",
            e.prob(0)
        );
        assert!(e.prob(0) > e.prob(1), "recovered arm should overtake");
    }

    // ---- Posture ----

    #[test]
    fn posture_observe_drives_class_score_down_on_failures() {
        let mut p = Posture::open();
        assert!(p.viability(TransportClass::Udp) > 0.9);
        for _ in 0..20 {
            p.observe_outcome("hysteria2", false); // UDP class failing
        }
        assert!(
            p.viability(TransportClass::Udp) < Posture::GATE_THRESHOLD,
            "UDP should be gated after sustained failures: {}",
            p.viability(TransportClass::Udp)
        );
        // Other classes untouched.
        assert!(p.viability(TransportClass::TcpTls) > 0.9);
    }

    #[test]
    fn class_mapping() {
        assert_eq!(class_of("hysteria2"), TransportClass::Udp);
        assert_eq!(class_of("h3"), TransportClass::Udp);
        assert_eq!(class_of("meek"), TransportClass::Http);
        assert_eq!(class_of("dnstt"), TransportClass::Dns);
        assert_eq!(class_of("ss2022"), TransportClass::TcpOpaque);
        assert_eq!(class_of("reality"), TransportClass::TcpTls);
        assert_eq!(class_of("something-new"), TransportClass::TcpTls); // conservative default
    }

    // ---- AdaptiveRouter integration ----

    fn cands() -> Vec<&'static str> {
        vec!["reality", "hysteria2", "ss2022", "meek"]
    }

    #[test]
    fn selection_is_not_deterministic_the_entropy_property() {
        // Even with a strong favourite, selection is a DISTRIBUTION - over many
        // draws we must see >=2 distinct transports (a censor can't pin a fixed
        // order). This is the core "routing entropy" guarantee.
        let mut r = AdaptiveRouter::new(1);
        let history = SuccessRateMap::new();
        let n = net();
        let posture = Posture::open();
        // Make reality the clear winner.
        for _ in 0..50 {
            r.record(&n, "reality", 1.0);
            let _ = r.select(&n, &cands(), &history, &posture, Instant::now());
        }
        let mut seen = std::collections::HashSet::new();
        for _ in 0..200 {
            if let Some(t) = r.select(&n, &cands(), &history, &posture, Instant::now()) {
                seen.insert(t);
            }
        }
        assert!(
            seen.len() >= 2,
            "selection must retain entropy, only saw {seen:?}"
        );
    }

    #[test]
    fn posture_gate_excludes_blocked_class_from_selection() {
        let mut r = AdaptiveRouter::new(2);
        let history = SuccessRateMap::new();
        let n = net();
        let mut posture = Posture::open();
        posture.set(TransportClass::Udp, 0.0); // UDP dead -> hysteria2 gated
        let mut seen = std::collections::HashSet::new();
        for _ in 0..300 {
            if let Some(t) = r.select(&n, &cands(), &history, &posture, Instant::now()) {
                seen.insert(t);
            }
        }
        assert!(
            !seen.contains("hysteria2"),
            "UDP-class arm must be gated out: {seen:?}"
        );
        assert!(
            seen.contains("reality"),
            "viable arms must still be selected"
        );
    }

    #[test]
    fn engine_shifts_away_from_a_blocked_transport() {
        // End-to-end: reality wins, then gets blocked; the engine must move its
        // selection mass to a still-working transport.
        let mut r = AdaptiveRouter::new(3);
        let history = SuccessRateMap::new();
        let n = net();
        let posture = Posture::open();
        // Phase 1: reality works.
        for _ in 0..80 {
            let t = r
                .select(&n, &cands(), &history, &posture, Instant::now())
                .unwrap();
            r.record(&n, t, if t == "reality" { 1.0 } else { 0.2 });
        }
        // Phase 2: reality blocked, ss2022 now the only good one.
        for _ in 0..200 {
            let t = r
                .select(&n, &cands(), &history, &posture, Instant::now())
                .unwrap();
            let reward = match t {
                "reality" => 0.0, // blocked
                "ss2022" => 1.0,
                _ => 0.1,
            };
            r.record(&n, t, reward);
        }
        let dist: std::collections::HashMap<_, _> = r.distribution(&n).into_iter().collect();
        assert!(
            dist["ss2022"] > dist["reality"],
            "engine must prefer the working transport: {dist:?}"
        );
    }

    #[test]
    fn diversity_guard_caps_a_single_arm_share() {
        // With a fixed clock and a runaway favourite, the diversity guard must
        // stop any one arm from taking the whole window.
        let mut g = DiversityGuard::new(Duration::from_secs(60), 0.5);
        let t0 = Instant::now();
        // Feed arm 0 heavily.
        for _ in 0..10 {
            g.record(0, t0);
        }
        assert!(g.over_share(0, t0), "arm 0 should be over its 50% share");
        assert!(!g.over_share(1, t0), "an unused arm is never over share");
    }

    #[test]
    fn warm_start_prefers_historically_good_transport() {
        // A transport with a strong record should start with more selection mass
        // than an unknown one, before any online learning this session.
        let history = SuccessRateMap::new();
        let n = net();
        for _ in 0..20 {
            history.record(&n, "ss2022", true); // strong history
        }
        let mut r = AdaptiveRouter::new(4);
        // Trigger warm-start by selecting once.
        let _ = r.select(&n, &cands(), &history, &Posture::open(), Instant::now());
        let dist: std::collections::HashMap<_, _> = r.distribution(&n).into_iter().collect();
        assert!(
            dist["ss2022"] > dist["meek"],
            "warm start should favour the historically-good transport: {dist:?}"
        );
    }

    #[test]
    fn empty_candidates_returns_none() {
        let mut r = AdaptiveRouter::new(5);
        assert!(r
            .select(
                &net(),
                &[],
                &SuccessRateMap::new(),
                &Posture::open(),
                Instant::now()
            )
            .is_none());
    }

    fn argmax_prob(e: &Exp3) -> usize {
        let mut p = Vec::new();
        e.probs_into(&mut p);
        p.iter()
            .enumerate()
            .max_by(|a, b| a.1.partial_cmp(b.1).unwrap_or(std::cmp::Ordering::Equal))
            .map_or(0, |(i, _)| i)
    }

    #[test]
    fn entropy_beats_a_deterministic_policy_against_a_reactive_censor() {
        // The thesis, in one test. A *reactive* censor blocks, each round, the
        // arm the policy is MOST likely to pick. A deterministic policy always
        // picks its single favourite -> the censor blocks exactly that -> it is
        // pinned at ~zero working rate. The EXP3 engine spreads probability, so
        // the censor can only ever block ONE arm and the engine keeps a working
        // path a majority of the time. Entropy defeats a reactive adversary -
        // which UCB/Thompson (stationary-optimal, low-entropy) would NOT.
        const K: usize = 5;
        const ROUNDS: usize = 2000;
        let mut rng = SplitMix64::new(0xDEAD_BEEF);
        let mut exp3 = Exp3::new(K, 0.15, 0.03);
        let mut greedy = Exp3::new(K, 0.15, 0.03); // same learner; picked GREEDILY
        let (mut exp3_ok, mut greedy_ok) = (0usize, 0usize);

        for _ in 0..ROUNDS {
            let exp3_block = argmax_prob(&exp3);
            let greedy_block = argmax_prob(&greedy);

            // EXP3: sample from the distribution (entropy).
            let a = exp3.select(rng.next_f64());
            let ra = if a == exp3_block { 0.0 } else { 1.0 };
            if ra > 0.0 {
                exp3_ok += 1;
            }
            exp3.update(a, ra, exp3.prob(a));

            // Greedy: always take the argmax (no entropy) -> the censor blocks
            // exactly it, every round.
            let g = greedy_block;
            let rg = if g == greedy_block { 0.0 } else { 1.0 };
            if rg > 0.0 {
                greedy_ok += 1;
            }
            greedy.update(g, rg, greedy.prob(g));
        }

        let exp3_rate = exp3_ok as f64 / ROUNDS as f64;
        let greedy_rate = greedy_ok as f64 / ROUNDS as f64;
        assert!(
            greedy_rate < 0.05,
            "a deterministic policy is pinned by a reactive censor: {greedy_rate}"
        );
        assert!(
            exp3_rate > 0.5,
            "the entropy policy keeps a working path a majority of rounds: {exp3_rate}"
        );
        assert!(
            exp3_rate > greedy_rate * 5.0,
            "entropy must dominate a reactive censor: exp3={exp3_rate} greedy={greedy_rate}"
        );
    }

    #[test]
    fn outcome_reward_shape() {
        assert_eq!(outcome_reward(false, None), 0.0);
        assert_eq!(outcome_reward(false, Some(Duration::from_millis(10))), 0.0);
        assert!(outcome_reward(true, Some(Duration::from_millis(50))) > 0.99);
        let slow = outcome_reward(true, Some(Duration::from_secs(3)));
        assert!(
            (0.5..0.6).contains(&slow),
            "slow success floored near 0.5, got {slow}"
        );
        // Fast success beats slow success beats block.
        assert!(
            outcome_reward(true, Some(Duration::from_millis(50)))
                > outcome_reward(true, Some(Duration::from_secs(3)))
        );
    }
}
