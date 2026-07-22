//! Cover-traffic engine.
//!
//! # Why
//!
//! An idle Mirage tunnel is fingerprintable: a flow that's been
//! quiet for 30 s and then bursts to a destination is correlated
//! across hops more easily than one that maintains a steady byte
//! cadence. Cover traffic - real bytes flowing through the tunnel
//! when the application is idle - keeps the cadence steady.
//!
//! # Design
//!
//! Two modes:
//!
//! 1. **In-tunnel keepalive** (default OFF). Periodic small
//!    Padme-sized writes through the existing session. Defeats
//!    "is the user idle right now" inference but doesn't ride
//!    real cover content.
//! 2. **Cover-fetch driver** (RECOMMENDED for hostile-network
//!    deployments). The CLIENT, when its tunnel is idle for >=
//!    `idle_threshold_secs`, fetches real HTTPS content from a
//!    list of cover destinations (the same fronted tenants the
//!    bridge advertises as cover) THROUGH the tunnel. The bridge
//!    sees normal HTTPS-CONNECT egress to a popular CDN; the
//!    network observer sees normal byte cadence.
//!
//! The contract:
//! "decoy traffic, when enabled, fetches real HTTPS content from
//! the same fronted tenant. Never synthesizes dummy ciphertext."
//! This module ships a synchronous scheduler interface; the
//! actual HTTPS fetcher is the caller's concern (typically wired
//! into the client's tokio runtime).
//!
//! # Threat-model fit
//!
//! - **Defeats idle-vs-active flow classification.** ML
//!   classifiers that distinguish "idle Mirage" from "active
//!   Mirage" lose discriminating signal.
//! - **Does NOT defeat correlation attacks** that observe BOTH
//!   client ingress AND bridge egress. Cover traffic adds noise
//!   to one side; an adversary who sees the same noise on both
//!   ends correlates trivially.
//! - **Cost cap**: <= 5% of session traffic by volume. Larger
//!   ratios make cover-traffic detectable as itself a signal.
//!
//! # NOT ON THE LIVE PATH - status
//!
//! **The schedulers in this module ([`CoverScheduler`],
//! [`CbrCoverScheduler`]) are NOT constructed on any live path.**
//! Nothing outside this module's own unit tests instantiates them;
//! the client and bridge runtimes do not drive `tick()`. Do not
//! mistake this module for active cover-traffic coverage.
//!
//! What DOES ship on the live path is transport-*layer* shaping via
//! `mirage-transport-pad`: its `PaddedStream` emits **chaff frames**
//! (zero-payload padded frames at a fixed `chaff_interval_ms`
//! cadence, and an optional CBR mode) so idle periods keep a steady
//! wire cadence. That transport-layer chaff is the shipped defense
//! against idle-vs-active flow classification.
//!
//! These session-layer schedulers are a *distinct, higher-level*
//! capability and are tracked WIP for v0.2:
//!
//! - [`CoverScheduler`] is the **cover-*fetch* driver** - it decides
//!   WHEN the client should fetch *real* HTTPS content from a decoy
//!   destination *through the tunnel* (it fetches real HTTPS
//!   content ... never synthesizes dummy ciphertext). That is
//!   materially stronger than transport-pad's synthetic chaff and is
//!   not provided anywhere else.
//! - [`CbrCoverScheduler`] is an I/O-free constant-bitrate framing
//!   oracle for a media pump; it overlaps transport-pad's CBR mode
//!   but at the session-frame granularity.
//!
//! **Exact wiring step (v0.2):** in the client's tokio runtime
//! (`crates/client`), spawn a task that (1) calls
//! [`CoverScheduler::record_activity`] on every session-frame
//! send/recv, (2) ticks [`CoverScheduler::tick`] on a ~1 s interval,
//! and (3) on [`CoverDecision::Fetch`] issues a real HTTPS GET to
//! `policy.destinations[destination_idx]` *through the established
//! tunnel*, feeding the byte cost back via
//! [`CoverScheduler::record_cover`]. Until that task exists, this
//! module is inert.

use std::time::{Duration, Instant};

/// Operator-tuned policy for the cover-traffic scheduler.
#[derive(Debug, Clone)]
pub struct CoverPolicy {
    /// Tunnel idle time after which cover traffic engages.
    /// Default 60 s.
    pub idle_threshold: Duration,
    /// Inter-cover-fetch interval mean. Drawn from a Poisson
    /// distribution at runtime; this is the rate parameter
    /// expressed as mean inter-arrival time. Default 30 s.
    pub mean_inter_fetch: Duration,
    /// Hard cap on the cover-traffic share of session bytes.
    /// `0.05` = 5%. Cover-fetch decisions check against an
    /// EWMA of recent traffic and skip if cover-share exceeds
    /// this cap.
    pub max_cover_fraction: f64,
    /// Cover-destination URLs. Each entry is a `host[:port]/path`
    /// the client will fetch THROUGH the tunnel. Operators
    /// typically point at the same fronted tenant the bridge
    /// uses for Reality cover, so the wire pattern is consistent.
    pub destinations: Vec<String>,
}

impl Default for CoverPolicy {
    fn default() -> Self {
        Self {
            idle_threshold: Duration::from_secs(60),
            mean_inter_fetch: Duration::from_secs(30),
            max_cover_fraction: 0.05,
            destinations: Vec::new(),
        }
    }
}

/// Decision the scheduler emits per tick.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoverDecision {
    /// Tunnel is busy or below idle threshold; skip cover.
    Skip,
    /// Tunnel is idle past threshold; fetch a cover destination.
    /// `destination_idx` indexes into `policy.destinations`.
    Fetch {
        /// Index into the policy's destination list.
        destination_idx: usize,
    },
    /// Cover-share would exceed the policy cap; skip.
    OverCap,
    /// Policy declares zero destinations; cover is disabled.
    Disabled,
}

/// Stateless scheduler: given the current time, last activity time,
/// recent byte counts, and the policy, decide what to do this
/// tick.
///
/// Caller drives this on a periodic interval (typically every
/// second). Cover-fetch decisions are committed to the tunnel by
/// the caller; this module doesn't own the network I/O.
pub struct CoverScheduler {
    policy: CoverPolicy,
    /// Wall-clock time the last application byte was sent OR
    /// received. The scheduler treats both directions equally for
    /// idleness.
    last_activity: Option<Instant>,
    /// Last cover-fetch attempt, for spacing.
    last_cover: Option<Instant>,
    /// EWMA of (cover_bytes / session_bytes). Nudges the
    /// scheduler away from cover-fetch when the ratio is climbing.
    cover_share_ewma: f64,
    /// Total non-cover bytes observed since EWMA reset.
    session_bytes_since_reset: u64,
    /// Total cover bytes since EWMA reset.
    cover_bytes_since_reset: u64,
    /// The NEXT inter-fetch interval, freshly drawn from an exponential
    /// distribution (mean = `policy.mean_inter_fetch`) after every fetch. A real
    /// Poisson process has memoryless, exponentially-distributed gaps; a fixed
    /// floor would make cover fire on a regular cadence a timing classifier can
    /// lock onto.
    next_interval: Duration,
}

impl CoverScheduler {
    /// New scheduler with the given policy. Starts in "idle from
    /// process start" mode - the first tick will not fetch cover
    /// because [`Self::record_activity`] hasn't been called yet
    /// and the scheduler interprets "no activity ever" as not
    /// idle (the user hasn't sent anything; there's nothing to
    /// hide).
    pub fn new(policy: CoverPolicy) -> Self {
        let next_interval = Self::sample_inter_fetch(policy.mean_inter_fetch);
        Self {
            policy,
            last_activity: None,
            last_cover: None,
            cover_share_ewma: 0.0,
            session_bytes_since_reset: 0,
            cover_bytes_since_reset: 0,
            next_interval,
        }
    }

    /// Draw an inter-fetch gap from an exponential distribution with the given
    /// mean (a Poisson arrival process): `gap = -mean * ln(U)`, `U  in  (0, 1]`.
    /// Clamped to `[0.1*mean, 6*mean]` so a rare tail draw can neither stall cover
    /// for minutes (itself a fingerprint) nor hammer it. Uses the OS CSPRNG.
    fn sample_inter_fetch(mean: Duration) -> Duration {
        let mut buf = [0u8; 8];
        let u = match getrandom::fill(&mut buf) {
            // Map the 64-bit draw to (0, 1] so ln() is finite.
            Ok(()) => (u64::from_le_bytes(buf) as f64 + 1.0) / (u64::MAX as f64 + 2.0),
            // CSPRNG unavailable: fall back to the median gap (ln 0.5) rather than
            // stall. Reachable only if the kernel CSPRNG is broken.
            Err(_) => 0.5,
        };
        let mean_s = mean.as_secs_f64();
        let gap = mean_s * -(u.ln());
        Duration::from_secs_f64(gap.clamp(mean_s * 0.1, mean_s * 6.0))
    }

    /// Record application activity. Caller invokes on every
    /// session-frame send/recv with the byte count.
    pub fn record_activity(&mut self, bytes: u64, now: Instant) {
        self.last_activity = Some(now);
        self.session_bytes_since_reset = self.session_bytes_since_reset.saturating_add(bytes);
        self.update_share();
    }

    /// Record a cover-fetch's byte cost.
    pub fn record_cover(&mut self, bytes: u64, now: Instant) {
        self.last_cover = Some(now);
        self.cover_bytes_since_reset = self.cover_bytes_since_reset.saturating_add(bytes);
        // Draw the NEXT gap now, so spacing is a fresh exponential each round.
        self.next_interval = Self::sample_inter_fetch(self.policy.mean_inter_fetch);
        self.update_share();
    }

    fn update_share(&mut self) {
        let total = self.session_bytes_since_reset + self.cover_bytes_since_reset;
        if total == 0 {
            self.cover_share_ewma = 0.0;
            return;
        }
        let instant_share = self.cover_bytes_since_reset as f64 / total as f64;
        // EWMA with alpha = 0.2 - smooths over short bursts.
        self.cover_share_ewma = 0.2 * instant_share + 0.8 * self.cover_share_ewma;
    }

    /// Reset EWMA accounting (typically on session restart or
    /// epoch boundary). Diagnostics only; doesn't affect policy.
    pub fn reset_share_window(&mut self) {
        self.session_bytes_since_reset = 0;
        self.cover_bytes_since_reset = 0;
        self.cover_share_ewma = 0.0;
    }

    /// Decide what to do at `now`. Stateless beyond the scheduler's
    /// own counters; the caller drives this on a fixed cadence.
    pub fn tick(&self, now: Instant) -> CoverDecision {
        if self.policy.destinations.is_empty() {
            return CoverDecision::Disabled;
        }
        // No activity ever -> user hasn't sent anything; nothing to
        // hide. Scheduler stays quiet so we don't generate suspicious
        // baseline traffic from a freshly-started client.
        let last_active = match self.last_activity {
            Some(t) => t,
            None => return CoverDecision::Skip,
        };
        if now.duration_since(last_active) < self.policy.idle_threshold {
            return CoverDecision::Skip;
        }
        // Spacing: the gap to the previous fetch must exceed this round's
        // exponential draw (a memoryless Poisson process, re-sampled after each
        // fetch), NOT a fixed floor that would produce a regular, classifiable
        // cadence.
        if let Some(last) = self.last_cover {
            if now.duration_since(last) < self.next_interval {
                return CoverDecision::Skip;
            }
        }
        if self.cover_share_ewma > self.policy.max_cover_fraction {
            return CoverDecision::OverCap;
        }
        // Pick a destination uniformly at random from the OS CSPRNG.
        // A predictable (counter-derived) pick would let an observer
        // who models the byte counters anticipate which decoy the
        // client fetches next - a correlation handle. If the CSPRNG
        // is momentarily unavailable we fall back to index 0 rather
        // than stall cover traffic (itself a fingerprint); this path
        // is only reachable if the kernel CSPRNG is broken.
        let idx = {
            let mut buf = [0u8; 8];
            match getrandom::fill(&mut buf) {
                Ok(()) => (u64::from_le_bytes(buf) as usize) % self.policy.destinations.len(),
                Err(_) => 0,
            }
        };
        CoverDecision::Fetch {
            destination_idx: idx,
        }
    }

    /// Snapshot the cover-share EWMA. Diagnostics-only.
    pub fn cover_share(&self) -> f64 {
        self.cover_share_ewma
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy_with(destinations: Vec<&str>) -> CoverPolicy {
        CoverPolicy {
            idle_threshold: Duration::from_millis(50),
            mean_inter_fetch: Duration::from_millis(100),
            max_cover_fraction: 0.05,
            destinations: destinations.into_iter().map(String::from).collect(),
        }
    }

    #[test]
    fn no_destinations_disables_cover() {
        let s = CoverScheduler::new(policy_with(vec![]));
        let d = s.tick(Instant::now());
        assert_eq!(d, CoverDecision::Disabled);
    }

    #[test]
    fn fresh_scheduler_with_no_activity_skips() {
        // No activity has ever been recorded; scheduler stays
        // quiet (nothing to hide).
        let s = CoverScheduler::new(policy_with(vec!["example.com"]));
        let d = s.tick(Instant::now());
        assert_eq!(d, CoverDecision::Skip);
    }

    #[test]
    fn busy_tunnel_skips_cover() {
        let mut s = CoverScheduler::new(policy_with(vec!["example.com"]));
        let now = Instant::now();
        s.record_activity(1000, now);
        // Below idle threshold.
        let d = s.tick(now + Duration::from_millis(10));
        assert_eq!(d, CoverDecision::Skip);
    }

    #[test]
    fn idle_past_threshold_emits_fetch() {
        let mut s = CoverScheduler::new(policy_with(vec!["a.example", "b.example"]));
        let t0 = Instant::now();
        s.record_activity(1000, t0);
        let t1 = t0 + Duration::from_millis(80); // > idle_threshold
        let d = s.tick(t1);
        match d {
            CoverDecision::Fetch { destination_idx } => {
                assert!(destination_idx < 2);
            }
            other => panic!("expected Fetch, got {other:?}"),
        }
    }

    #[test]
    fn over_cap_skips_cover() {
        let mut s = CoverScheduler::new(policy_with(vec!["a.example"]));
        let t0 = Instant::now();
        // Force cover_share_ewma above the policy cap by recording
        // a lot of cover bytes vs little session.
        s.record_activity(100, t0);
        for i in 0..50 {
            s.record_cover(1000, t0 + Duration::from_millis(i));
        }
        // `tick` checks the (random, exponential) spacing gate BEFORE the
        // over-cap gate, so we must tick past the MAXIMUM possible spacing window
        // or the over-cap branch is sometimes preempted by a Skip (the source of
        // an old ~1-in-5 flake). The last `record_cover` was at t0+49ms and the
        // spacing draw is clamped to at most 6*mean = 600ms, so any tick after
        // t0+649ms is guaranteed past the window; t0+800ms leaves ample margin.
        let t1 = t0 + Duration::from_millis(800);
        let d = s.tick(t1);
        assert_eq!(d, CoverDecision::OverCap);
    }

    #[test]
    fn spacing_prevents_back_to_back_fetches() {
        let mut s = CoverScheduler::new(policy_with(vec!["a.example"]));
        let t0 = Instant::now();
        s.record_activity(100, t0);
        let t_fetch = t0 + Duration::from_millis(80);
        // First fetch should be allowed.
        match s.tick(t_fetch) {
            CoverDecision::Fetch { .. } => {}
            other => panic!("expected Fetch, got {other:?}"),
        }
        // Record the fetch; the next inter-fetch gap is now a random exponential
        // draw clamped to at least 0.1*mean (= 10 ms for the test's 100 ms mean),
        // so a tick 5 ms later is ALWAYS inside the spacing window and must skip -
        // deterministic regardless of the random draw.
        s.record_cover(50, t_fetch);
        let t_too_soon = t_fetch + Duration::from_millis(5);
        let d = s.tick(t_too_soon);
        assert_eq!(d, CoverDecision::Skip);
    }

    #[test]
    fn reset_share_window_clears_ewma() {
        let mut s = CoverScheduler::new(policy_with(vec!["a.example"]));
        s.record_cover(100, Instant::now());
        s.record_activity(50, Instant::now());
        assert!(s.cover_share() > 0.0);
        s.reset_share_window();
        assert_eq!(s.cover_share(), 0.0);
    }

    #[test]
    fn share_ewma_smooths_burstiness() {
        let mut s = CoverScheduler::new(policy_with(vec!["a.example"]));
        let now = Instant::now();
        // 90% session bytes, 10% cover bytes - well below cap.
        for _ in 0..90 {
            s.record_activity(10, now);
        }
        for _ in 0..10 {
            s.record_cover(10, now);
        }
        assert!(s.cover_share() < 0.15);
    }
}

// CBR (constant-bitrate) cover scheduler - RT-M3 closure

/// Tunables for the constant-bitrate cover scheduler.
///
/// Configures a fixed wire-shape: a frame of size `frame_size`
/// emitted every `cadence` (+/- `jitter`) regardless of whether
/// the application has real bytes to send.
///
/// Calibrate for the traffic class you're mimicking. VOIP at 50
/// frames/sec x 1.5 KiB ~ 600 kbps. Video at 30 fps x 4 KiB ~
/// 1 Mbps. Match the class's typical bitrate so flow-shape
/// classifiers can't discriminate Mirage cover from real media.
#[derive(Debug, Clone)]
pub struct CbrCoverPolicy {
    /// Target frame interval. e.g., 20ms for 50 fps.
    pub cadence: Duration,
    /// Bytes per emitted frame (real bytes filled from the
    /// outbound queue + cover top-up to reach this size).
    pub frame_size: usize,
    /// Per-frame jitter window. Each emit fires at
    /// `last_emit + cadence +/- uniform([0, jitter])`. Set to
    /// `Duration::ZERO` for strict CBR (best for shape mimicry).
    pub jitter: Duration,
}

impl Default for CbrCoverPolicy {
    fn default() -> Self {
        Self {
            cadence: Duration::from_millis(20),
            frame_size: 1500,
            jitter: Duration::ZERO,
        }
    }
}

/// One tick decision for the CBR scheduler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CbrTickDecision {
    /// Caller MUST emit `frame_size` bytes now. The caller's
    /// outbound pump pulls real bytes from the application queue
    /// (up to `frame_size`) and pads any remainder with cover
    /// bytes (random fill from CSPRNG, AEAD-protected).
    Emit {
        /// Bytes the wire frame MUST contain (real + cover).
        frame_size: usize,
    },
    /// Cadence window hasn't elapsed. Caller sleeps until the
    /// returned instant, then ticks again.
    Wait {
        /// Wall-clock instant of the next emit deadline.
        until: Instant,
    },
}

/// I/O-free constant-bitrate scheduler.
///
/// Closes [RT-M3]: the existing [`CoverScheduler`] emits cover
/// only on idle, leaving real-traffic gaps for a flow-shape
/// classifier. CBR mode emits at a fixed cadence regardless of
/// real-traffic state, with the application's bytes filling the
/// frame and cover topping up the rest. Wire shape is identical
/// for "real call" vs "silent call" - the classifier discriminator
/// vanishes.
///
/// Suitable for [`crate::FrameKind::Media`] traffic on
/// `PaddingPolicy::BypassMedia` circuits - the per-frame Padme
/// rounding is replaced by CBR's fixed `frame_size`. Control
/// frames stay on the existing Padme path.
#[derive(Debug, Clone)]
pub struct CbrCoverScheduler {
    policy: CbrCoverPolicy,
    last_emit: Option<Instant>,
    real_bytes_total: u64,
    cover_bytes_total: u64,
    /// Counter for deterministic jitter; production callers swap
    /// in a CSPRNG-backed picker via [`Self::set_jitter_picker`].
    jitter_seq: u64,
    jitter_picker: fn(seq: u64, max: Duration) -> Duration,
    /// Absolute next-emit deadline, sampled ONCE per cycle in
    /// [`Self::record_emit`] (RT #30). Re-rolling jitter on every `tick`
    /// (the previous behaviour) biased emit times toward the cadence floor:
    /// whenever a poll happened to draw a small jitter the frame went out
    /// early, so observed inter-emit gaps clustered low - a timing
    /// distinguisher. Caching the deadline makes each cycle's jitter a single
    /// fixed draw.
    next_deadline_cached: Option<Instant>,
}

impl CbrCoverScheduler {
    /// Construct with the production-default CSPRNG-backed jitter
    /// picker. Callers who need exact timing for tests should call
    /// [`Self::set_jitter_picker`] with [`cbr_zero_jitter`] or
    /// [`cbr_deterministic_jitter`] immediately after construction.
    /// Closes [RT-S3] (Phase 2E re-scan): the prior default was
    /// deterministic, leaking predictable cover-traffic timing.
    pub fn new(policy: CbrCoverPolicy) -> Self {
        Self {
            policy,
            last_emit: None,
            real_bytes_total: 0,
            cover_bytes_total: 0,
            jitter_seq: 0,
            jitter_picker: cbr_csprng_jitter,
            next_deadline_cached: None,
        }
    }

    /// Override the jitter picker. Tests pin to
    /// [`cbr_zero_jitter`]; production swaps in a CSPRNG-backed
    /// callback (see `mirage-router::pool::csprng_jitter` for the
    /// pattern).
    pub fn set_jitter_picker(&mut self, picker: fn(seq: u64, max: Duration) -> Duration) {
        self.jitter_picker = picker;
    }

    /// Tick. Returns either `Emit` (cadence elapsed; frame goes
    /// out now) or `Wait { until }` (cadence still ticking).
    pub fn tick(&mut self, now: Instant) -> CbrTickDecision {
        let next_deadline = self.next_deadline(now);
        if now >= next_deadline {
            CbrTickDecision::Emit {
                frame_size: self.policy.frame_size,
            }
        } else {
            CbrTickDecision::Wait {
                until: next_deadline,
            }
        }
    }

    /// The next emit deadline. Returns the deadline cached at the last
    /// [`Self::record_emit`] (a single fixed jitter draw per cycle), or `now`
    /// before the first emit so the first tick fires immediately. Does NOT
    /// re-roll jitter (RT #30).
    pub fn next_deadline(&self, now: Instant) -> Instant {
        self.next_deadline_cached.unwrap_or(now)
    }

    /// Caller has emitted a frame. Records `real_bytes` of real
    /// data and `cover_bytes` of cover top-up (which together
    /// equal `policy.frame_size`).
    pub fn record_emit(&mut self, real_bytes: usize, cover_bytes: usize, now: Instant) {
        self.last_emit = Some(now);
        self.real_bytes_total = self.real_bytes_total.saturating_add(real_bytes as u64);
        self.cover_bytes_total = self.cover_bytes_total.saturating_add(cover_bytes as u64);
        self.jitter_seq = self.jitter_seq.wrapping_add(1);
        // Sample this cycle's jitter EXACTLY ONCE and cache the absolute
        // deadline (RT #30). `tick`/`next_deadline` read it without re-rolling.
        let jitter = (self.jitter_picker)(self.jitter_seq, self.policy.jitter);
        self.next_deadline_cached =
            Some(now.checked_add(self.policy.cadence + jitter).unwrap_or(now));
    }

    /// Total real bytes emitted (diagnostics).
    pub fn total_real_bytes(&self) -> u64 {
        self.real_bytes_total
    }

    /// Total cover bytes emitted (diagnostics).
    pub fn total_cover_bytes(&self) -> u64 {
        self.cover_bytes_total
    }

    /// Cover share - fraction of emitted bytes that were cover.
    /// Useful for operator dashboards: a healthy "real call"
    /// trends toward 0.0; a silent line trends toward 1.0.
    pub fn cover_share(&self) -> f64 {
        let total = self.real_bytes_total.saturating_add(self.cover_bytes_total);
        if total == 0 {
            return 0.0;
        }
        self.cover_bytes_total as f64 / total as f64
    }

    /// Policy snapshot.
    pub fn policy(&self) -> &CbrCoverPolicy {
        &self.policy
    }
}

/// Deterministic jitter picker for the CBR scheduler.
///
/// **Test-only.** Production callers MUST install
/// [`cbr_csprng_jitter`] (or a stronger source) via
/// [`CbrCoverScheduler::set_jitter_picker`]. A passive observer
/// who learns the seed (which is just `seq`, monotonic from 0)
/// can predict every future jitter value, defeating the cover
/// traffic's traffic-analysis resistance. Closes [RT-S3]
/// (Phase 2E re-scan): the previous default was deterministic;
/// callers who didn't read the doc shipped predictable timing.
pub fn cbr_deterministic_jitter(seq: u64, max: Duration) -> Duration {
    if max.is_zero() {
        return Duration::ZERO;
    }
    const PHI_FIX: u64 = 0x9E37_79B9_7F4A_7C15;
    let mix = seq.wrapping_mul(PHI_FIX);
    let max_micros = max.as_micros() as u64;
    if max_micros == 0 {
        return Duration::ZERO;
    }
    Duration::from_micros(mix % max_micros)
}

/// Zero-jitter picker. Tests use this for exact timing assertions.
pub fn cbr_zero_jitter(_seq: u64, _max: Duration) -> Duration {
    Duration::ZERO
}

/// CSPRNG-backed jitter picker. Pulls fresh randomness from the
/// OS RNG on every call; ignores `seq`. This is the production
/// default installed by [`CbrCoverScheduler::new`] (closes
/// [RT-S3]). On the rare case OS entropy is unavailable, falls
/// back to a deterministic mix of `seq` so the scheduler never
/// stalls on cover-traffic emission - but that fallback path is
/// observable only if every prior `getrandom` call also failed,
/// which on Linux/macOS/Windows requires the kernel CSPRNG to be
/// fundamentally broken.
pub fn cbr_csprng_jitter(seq: u64, max: Duration) -> Duration {
    if max.is_zero() {
        return Duration::ZERO;
    }
    let max_micros = max.as_micros() as u64;
    if max_micros == 0 {
        return Duration::ZERO;
    }
    let mut buf = [0u8; 8];
    let r = match getrandom::fill(&mut buf) {
        Ok(()) => u64::from_le_bytes(buf),
        Err(_) => {
            // Last-ditch: deterministic mix. We log at warn so
            // operators see the entropy failure; the scheduler
            // keeps running rather than stalling cover traffic
            // (which would itself be a fingerprint).
            tracing::warn!(
                "cbr_csprng_jitter: getrandom failed, falling back to deterministic mix"
            );
            const PHI_FIX: u64 = 0x9E37_79B9_7F4A_7C15;
            seq.wrapping_mul(PHI_FIX)
        }
    };
    Duration::from_micros(r % max_micros)
}

#[cfg(test)]
mod cbr_tests {
    use super::*;

    fn voip_policy() -> CbrCoverPolicy {
        CbrCoverPolicy {
            cadence: Duration::from_millis(20),
            frame_size: 1500,
            jitter: Duration::ZERO,
        }
    }

    fn scheduler() -> CbrCoverScheduler {
        let mut s = CbrCoverScheduler::new(voip_policy());
        s.set_jitter_picker(cbr_zero_jitter);
        s
    }

    #[test]
    fn first_tick_emits_immediately() {
        // No prior emit -> first tick fires now (so the wire
        // shape starts as soon as the scheduler is engaged).
        let mut s = scheduler();
        let outcome = s.tick(Instant::now());
        match outcome {
            CbrTickDecision::Emit { frame_size: 1500 } => {}
            other => panic!("expected immediate Emit, got {other:?}"),
        }
    }

    #[test]
    fn second_tick_within_cadence_waits() {
        let mut s = scheduler();
        let t0 = Instant::now();
        s.tick(t0);
        s.record_emit(1000, 500, t0);
        // 5ms later: still within 20ms cadence.
        match s.tick(t0 + Duration::from_millis(5)) {
            CbrTickDecision::Wait { until } => {
                assert_eq!(until, t0 + Duration::from_millis(20));
            }
            other => panic!("expected Wait, got {other:?}"),
        }
    }

    #[test]
    fn second_tick_at_cadence_emits() {
        let mut s = scheduler();
        let t0 = Instant::now();
        s.tick(t0);
        s.record_emit(1000, 500, t0);
        // 20ms later: cadence elapsed, emit again.
        match s.tick(t0 + Duration::from_millis(20)) {
            CbrTickDecision::Emit { frame_size: 1500 } => {}
            other => panic!("expected Emit at cadence, got {other:?}"),
        }
    }

    #[test]
    fn cover_share_during_silent_call_trends_to_one() {
        // A silent voice call emits all cover bytes; cover_share
        // should approach 1.0.
        let mut s = scheduler();
        let mut t = Instant::now();
        for _ in 0..100 {
            s.tick(t);
            // 0 real bytes, all cover.
            s.record_emit(0, 1500, t);
            t += Duration::from_millis(20);
        }
        assert_eq!(s.cover_share(), 1.0);
    }

    #[test]
    fn cover_share_during_full_call_trends_to_zero() {
        let mut s = scheduler();
        let mut t = Instant::now();
        for _ in 0..100 {
            s.tick(t);
            // All real bytes; no cover top-up needed.
            s.record_emit(1500, 0, t);
            t += Duration::from_millis(20);
        }
        assert_eq!(s.cover_share(), 0.0);
    }

    #[test]
    fn frame_size_is_constant_regardless_of_content_mix() {
        // The wire-shape invariant: every emit produces a frame
        // of exactly `frame_size` bytes regardless of whether
        // it's all-real, all-cover, or any mix.
        let mut s = scheduler();
        let mut t = Instant::now();
        for (real, cover) in [(0, 1500), (500, 1000), (1500, 0), (750, 750)] {
            s.tick(t);
            // Total = frame_size always.
            assert_eq!(real + cover, 1500);
            s.record_emit(real, cover, t);
            t += Duration::from_millis(20);
        }
    }

    #[test]
    fn jitter_window_bounds_next_deadline() {
        // With non-zero jitter, the next deadline is in
        // `[cadence, cadence + jitter)` past last_emit.
        let mut policy = voip_policy();
        policy.jitter = Duration::from_millis(2);
        let mut s = CbrCoverScheduler::new(policy);
        // Use deterministic jitter for reproducibility.
        s.set_jitter_picker(cbr_deterministic_jitter);
        let t0 = Instant::now();
        s.tick(t0);
        s.record_emit(1500, 0, t0);
        let next = s.next_deadline(t0);
        let elapsed = next.saturating_duration_since(t0);
        assert!(elapsed >= Duration::from_millis(20));
        assert!(elapsed < Duration::from_millis(22));
    }

    #[test]
    fn zero_jitter_is_strict_cbr() {
        let mut s = scheduler();
        let t0 = Instant::now();
        s.tick(t0);
        s.record_emit(1500, 0, t0);
        let next = s.next_deadline(t0);
        // Exactly cadence, no slop.
        assert_eq!(next, t0 + Duration::from_millis(20));
    }

    #[test]
    fn deterministic_jitter_stays_within_bounds() {
        let max = Duration::from_millis(5);
        for seq in 0u64..1000 {
            let j = cbr_deterministic_jitter(seq, max);
            assert!(j < max);
        }
    }

    #[test]
    fn cbr_zero_jitter_returns_zero() {
        assert_eq!(
            cbr_zero_jitter(123, Duration::from_secs(60)),
            Duration::ZERO
        );
    }

    #[test]
    fn cbr_csprng_jitter_within_bounds_and_varies() {
        // RT-S3 closure: the CSPRNG picker must (a) stay below
        // the max bound and (b) actually produce varying outputs
        // call-to-call (the deterministic mixer's predictability
        // was the failure mode).
        let max = Duration::from_millis(5);
        let mut samples = std::collections::HashSet::new();
        for seq in 0u64..200 {
            let j = cbr_csprng_jitter(seq, max);
            assert!(j < max, "jitter {j:?} >= max {max:?}");
            samples.insert(j.as_micros());
        }
        // Should see many distinct values; the deterministic mixer
        // produces exactly 200 (one per seq), but those values
        // depend on multiplicative-mod patterns that may collide
        // or alias. CSPRNG should give us substantially more
        // unique micro values across 200 draws on a 5ms window
        // (5000 micros possible). 100+ unique is a safe lower
        // bound; if we see less, randomness is broken.
        assert!(
            samples.len() >= 100,
            "expected >= 100 distinct CSPRNG jitter values across 200 draws, got {}",
            samples.len()
        );
    }

    #[test]
    fn cbr_csprng_jitter_zero_max_is_zero() {
        // Avoid divide-by-zero on a zero jitter window.
        assert_eq!(cbr_csprng_jitter(0, Duration::ZERO), Duration::ZERO);
    }

    #[test]
    fn default_scheduler_uses_csprng_jitter() {
        // RT-S3 regression guard: a freshly-constructed scheduler
        // (no explicit set_jitter_picker call) must NOT use the
        // deterministic picker, since callers who skip the setup
        // step would otherwise leak predictable timing.
        let mut policy = voip_policy();
        policy.jitter = Duration::from_millis(2);
        let s = CbrCoverScheduler::new(policy);
        // Function pointers compare by address; the default must
        // not equal the deterministic picker.
        let det: fn(u64, Duration) -> Duration = cbr_deterministic_jitter;
        let zero: fn(u64, Duration) -> Duration = cbr_zero_jitter;
        assert!(s.jitter_picker as usize != det as usize);
        assert!(s.jitter_picker as usize != zero as usize);
    }
}
