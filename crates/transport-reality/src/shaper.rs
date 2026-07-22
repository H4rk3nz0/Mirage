//! Record-size shaper + inter-record jitter for the REALITY-v2 data path.
//!
//! # Why
//!
//! `RealityStream::poll_write` historically emitted exactly one TLS record per
//! `write` call - a 1:1 plaintext->record mapping that leaks the application's
//! write-size distribution to a passive observer, and back-to-back records with
//! no inter-record delay. The bridge/client must emit an
//! `application_data` length distribution + record cadence that resembles the
//! cover (a real browser<->CDN flow), not a 1:1 echo.
//!
//! This module is the **sizing + timing owner for the Reality path**
//! (exactly one size-transform layer per transport). When it is wired into
//! `poll_write`, the `PaddedStream`
//! size-bucketing MUST be retired from the Reality path, and Padme MUST NOT be
//! applied to Reality session frames - either would be a second, correlated
//! size transform (the "compounding" the roadmap forbids).
//!
//! # Integration status
//!
//! The **split** logic is wired into the Reality data path: `RealityStream`
//! holds a [`RecordShaper`] ([`crate::carrier`]) and `poll_write` calls
//! [`RecordShaper::split_plan`] to fan a write into per-sub-record AEAD units
//! (regression: `handshake_and_roundtrip_large_payload_record_split`). By default
//! the stream shapes to a **calibrated record-size distribution** (i.i.d. draws
//! from [`TrafficProfile::browser_https`] via [`RecordShaper::from_profile`]).
//! Inter-record timing jitter is NOT applied (#18): a uniform-[0,50] ms draw
//! was removed because it masked nothing it claimed and was itself a tell.
//! Capture-calibrated inter-record cadence is deferred (see [`carrier`]).
//!
//! # Split policy
//!
//! - **Calibrated CDF** ([`SplitSource::Cdf`], the default): record sizes sampled
//!   i.i.d. from a [`TrafficProfile`]'s marginal distribution, so the on-wire
//!   size histogram tracks a real browser<->CDN flow rather than the app's write
//!   sizes. It matches the *marginal* but NOT the length *sequence*.
//! - **Markov process** ([`SplitSource::Markov`], OPT-IN only): a first-order
//!   Markov chain over a [`MarkovProfile`]'s buckets that additionally correlates
//!   consecutive sizes into runs, addressing the length-sequence structure Xue
//!   et al.'s TLS-in-TLS detectors key on. IMPORTANT (measured, not assumed): this
//!   only helps against a cover whose run-length law the process is CALIBRATED to.
//!   Real TLS flows are *bimodal* (short interactive record bursts + long bulk-
//!   transfer runs), which a first-order single-stickiness chain cannot express;
//!   against such a cover it is measurably WORSE than the i.i.d. draw (see
//!   `mirage_adversary::flow_classifier::first_order_markov_does_not_beat_iid_against_bimodal_cover`).
//!   So it is NOT the default - only a deployment that has calibrated a
//!   [`MarkovProfile`] to a capture of its cover should opt in. Closing the
//!   sequence gap for real traffic needs a phase-state model, not this.
//! - **Fixed-policy fallback** ([`SplitSource::FixedPolicy`]): plaintext
//!   `> RECORD_SPLIT_THRESHOLD` (4096 B) split into 2-3 CSPRNG-chosen
//!   sub-records; retained for deterministic tests and as a profile-free
//!   fallback.
//!
//! **AEAD-boundary rule:** splitting happens on PLAINTEXT before
//! encryption - each sub-record is an independent AEAD unit with its own nonce.
//! Padding/splitting MUST NOT cross a record's AEAD boundary. The integration
//! therefore encrypts each sub-slice separately; this module only computes the
//! plaintext sub-slice lengths.

/// Reserved bound for a future capture-calibrated inter-record delay. NOT
/// currently applied (#18): the earlier uniform-`[0, MAX_RECORD_JITTER_MS]`
/// draw was removed because a uniform law masks no real cover cadence and was
/// itself a distinguishable timing tell. Retained as the documented ceiling for
/// a distribution-fitted delay once a cover capture exists to calibrate one.
pub const MAX_RECORD_JITTER_MS: u64 = 50;

/// Plaintext sizes at or below this are emitted as a single record; larger
/// writes are split (v0.1 fixed policy).
pub const RECORD_SPLIT_THRESHOLD: usize = 4096;

/// Largest TLS-1.3 inner plaintext a single record may carry (RFC 8446
/// §5.2: 2^14). Every sub-record length is bounded by this.
pub const MAX_RECORD_PLAINTEXT: usize = 16384;

/// Source of record-split boundaries.
#[derive(Debug, Clone)]
pub enum SplitSource {
    /// Fixed-policy fallback (2-3 sub-records over the threshold). Retained for
    /// deterministic tests and profile-free callers.
    FixedPolicy,
    /// Calibrated record-size CDF - `(record_len, weight)` buckets, from a real
    /// capture or a [`TrafficProfile`]. The default for the live Reality stream.
    Cdf(Vec<(u16, f32)>),
    /// Conditional record-length **process**: a first-order Markov chain over
    /// size buckets. Unlike [`Self::Cdf`] (which draws each record size i.i.d.),
    /// consecutive sizes are *correlated* into runs - adding length-SEQUENCE
    /// structure (autocorrelation) an i.i.d. draw has none of, which is the axis
    /// TLS-in-TLS detectors (Xue et al. USENIX '22/'24) key on - while preserving
    /// the SAME marginal size distribution.
    ///
    /// OPT-IN ONLY, not the default: a first-order chain's *geometric* runs match
    /// a real TLS flow's *bimodal* runs (interactive bursts + bulk runs) only when
    /// CALIBRATED to it; uncalibrated, it is measurably worse than i.i.d. against
    /// bimodal traffic. See [`MarkovProfile`].
    Markov(MarkovProfile),
    /// Two-phase (interactive/bulk) record-length process - the **phase-state
    /// model** the [`MarkovProfile`] docs call for. Two states with DIFFERENT
    /// self-transition rates express real TLS's BIMODAL run structure (short
    /// interactive bursts + long bulk runs) that a single-stickiness Markov
    /// cannot, while [`PhaseProfile::from_cdf`] preserves the size marginal.
    ///
    /// OPT-IN ONLY (i.i.d. [`Self::Cdf`] remains the default). IMPORTANT, measured:
    /// against a synthetic bimodal cover this does NOT beat i.i.d. - the bulk-run
    /// structure that a sequence classifier keys on is driven by the APPLICATION's
    /// large writes (which [`cdf_split`] already fragments into runs of max-size
    /// records, identically for every source), not by the sub-max shaping. A
    /// faithful certification (marginal AND the continuous partial-record
    /// structure) requires a real cover pcap; until a deployment has one and has
    /// certified this profile against `mirage_adversary::flow_classifier`, prefer
    /// the default. See `flow_classifier::phase_state_preserves_marginal`.
    PhaseState(PhaseProfile),
}

/// A conditional record-length process for the Reality data path: a first-order
/// Markov chain over discrete size buckets.
///
/// # Why (over an i.i.d. CDF draw)
///
/// [`SplitSource::Cdf`] reproduces the *marginal* record-size histogram but
/// draws each record independently, so the length **sequence** has ~zero
/// autocorrelation and run length ~1 - which no real TLS flow shows (a bulk
/// response is a long run of 2^14 records; an interactive burst is a run of
/// small ones). Length-sequence detectors exploit exactly that. This chain makes
/// consecutive sizes cluster into runs, matching the sequence structure while
/// keeping the marginal.
///
/// # Marginal preservation (why runs don't move the histogram)
///
/// The transition kernel is `P[i][j] = (1 - a)*pi[j] + a*[i==j]` where `pi` is
/// [`Self::stationary`] and `a` is [`Self::stickiness`]: with probability `a`
/// keep the previous bucket, else redraw from `pi`. `P` is a convex combination
/// of the rank-1 `pi`-kernel (rows all `pi`) and the identity, both of which fix
/// `pi`, so `pi*P = pi` **exactly** for any `a in [0,1)`. Stickiness therefore
/// tunes autocorrelation / run length WITHOUT moving the **drawn-bucket** marginal.
/// `a = 0` recovers the i.i.d. `Cdf` draw; higher `a` lengthens runs (mean run
/// between fresh redraws ~ `1/(1-a)`).
///
/// NOTE: `pi*P=pi` is the marginal of the DRAWN buckets. The EMITTED wire marginal
/// additionally reflects the carrier's write-boundary handling (each write's tail
/// record is truncated to the remainder, and bulk-filling writes are emitted as
/// max-size records at the carrier layer), so it is not exactly `pi`. This is the
/// same as for the i.i.d. `Cdf` source and is not specific to the Markov chain.
///
/// CAVEAT: a *wrong* process is itself a new fingerprint. Before trusting a
/// profile, certify it against the flow-shape distinguisher
/// (`mirage_adversary::flow_classifier`) on a real cover capture - the marginal
/// AND the run structure must match. [`Self::browser_https`] is a structured
/// default, not a calibrated one.
#[derive(Debug, Clone)]
pub struct MarkovProfile {
    /// Human-readable profile name (for logs / diagnostics).
    pub name: &'static str,
    /// Size buckets = the chain's state space (bytes). Index-aligned with
    /// [`Self::stationary`].
    pub buckets: Vec<u16>,
    /// Stationary marginal weight per bucket. The chain preserves THIS as its
    /// drawn-bucket stationary distribution, matching a [`SplitSource::Cdf`]
    /// profile built from the same `(bucket, weight)` pairs (modulo the carrier's
    /// write-boundary emission - see the type docs).
    pub stationary: Vec<f32>,
    /// Run "stickiness" in `[0, 1)`: probability the next record keeps the
    /// previous bucket (else redraw from `stationary`). Tunes run length /
    /// autocorrelation without moving the marginal (see type docs).
    pub stickiness: f32,
}

impl MarkovProfile {
    /// Structured analogue of [`TrafficProfile::browser_https`]: identical
    /// marginal bucket weights, with a single moderate run stickiness. This is a
    /// DEMONSTRATION profile, NOT a calibrated or shippable one - a single
    /// stickiness produces unimodal geometric runs, which do not match real TLS's
    /// bimodal (interactive + bulk) run-length structure, so against real traffic
    /// it is worse than the i.i.d. default (measured; see the flow-shape
    /// distinguisher's bimodal counter-test). A real deployment must fit BOTH the
    /// marginal AND the run-length structure to a pcap of its cover (a phase-state
    /// model, not this first-order chain) and certify it before use.
    pub fn browser_https() -> Self {
        let cdf = TrafficProfile::browser_https().record_size_cdf;
        Self {
            name: "browser-https-markov",
            buckets: cdf.iter().map(|(s, _)| *s).collect(),
            stationary: cdf.iter().map(|(_, w)| *w).collect(),
            // Mean run ~ 1/(1-0.5) = 2 between fresh redraws; a moderate,
            // clearly-non-i.i.d. default. Calibrate to the cover's runs.
            stickiness: 0.5,
        }
    }
}

/// A two-phase (interactive / bulk) record-length process for the Reality data
/// path - the phase-state model the module + [`MarkovProfile`] docs call for.
///
/// Real TLS is BIMODAL: interactive request/response records (small, clustered
/// into short bursts) alternate with bulk-transfer records (max-size, in long
/// runs). [`SplitSource::Cdf`] reproduces the size MARGINAL but draws i.i.d., so
/// its length SEQUENCE has ~zero autocorrelation and unit run length; a
/// single-stickiness [`SplitSource::Markov`] chain gives ONE geometric run scale,
/// matching neither mode. This model has two states (SMALL, LARGE), each with
/// its own size distribution and its own self-transition stickiness, so SMALL and
/// LARGE runs have DIFFERENT mean lengths - the bimodal run structure a sequence
/// classifier (Xue et al.) keys on.
///
/// # Marginal preservation
/// The two-state stationary occupancy is `pi_small = q / (p + q)` (p = P[SMALL->
/// LARGE], q = P[LARGE->SMALL]). [`Self::from_cdf`] partitions the source CDF at
/// a size threshold, draws WITHIN each state from that state's renormalized
/// conditional marginal, and sets `(p, q)` so the occupancy equals the
/// small/large weight split - so the overall drawn-size marginal equals the
/// source CDF for any run lengths. Stickiness moves the SEQUENCE, not the
/// histogram.
#[derive(Debug, Clone)]
pub struct PhaseProfile {
    /// Human-readable name (logs / diagnostics).
    pub name: &'static str,
    /// SMALL-state size buckets `(len, weight)`, weights renormalized to sum 1.
    pub small: Vec<(u16, f32)>,
    /// LARGE-state size buckets `(len, weight)`, weights renormalized to sum 1.
    pub large: Vec<(u16, f32)>,
    /// `P[SMALL -> LARGE]` per record; mean SMALL run = `1 / p_small_to_large`.
    pub p_small_to_large: f32,
    /// `P[LARGE -> SMALL]` per record; mean LARGE run = `1 / p_large_to_small`.
    pub p_large_to_small: f32,
}

impl PhaseProfile {
    /// Derive a marginal-preserving phase profile from a size CDF: buckets
    /// `< threshold` bytes form the SMALL state, `>= threshold` the LARGE state.
    /// `mean_large_run` sets the bulk-run scale; the SMALL-run scale is then fixed
    /// by requiring the stationary occupancy to equal the small/large weight
    /// split (so the marginal is preserved).
    #[must_use]
    pub fn from_cdf(
        name: &'static str,
        cdf: &[(u16, f32)],
        threshold: u16,
        mean_large_run: f32,
    ) -> Self {
        let mut small: Vec<(u16, f32)> = cdf
            .iter()
            .copied()
            .filter(|(s, _)| *s < threshold)
            .collect();
        let mut large: Vec<(u16, f32)> = cdf
            .iter()
            .copied()
            .filter(|(s, _)| *s >= threshold)
            .collect();
        let ws: f32 = small.iter().map(|(_, w)| w.max(0.0)).sum();
        let wl: f32 = large.iter().map(|(_, w)| w.max(0.0)).sum();
        if ws > 0.0 {
            for (_, w) in &mut small {
                *w /= ws;
            }
        }
        if wl > 0.0 {
            for (_, w) in &mut large {
                *w /= wl;
            }
        }
        // Occupancy target = the true weight split (preserves the marginal).
        let target_small = if ws + wl > 0.0 { ws / (ws + wl) } else { 0.5 };
        // pi_small = Ls/(Ls+Ll)  =>  Ls = Ll * pi_small / (1 - pi_small).
        let ll = mean_large_run.max(1.0);
        let ls = (ll * target_small / (1.0 - target_small).max(1e-6)).max(1.0);
        Self {
            name,
            small,
            large,
            p_small_to_large: 1.0 / ls,
            p_large_to_small: 1.0 / ll,
        }
    }

    /// Default from the browser-HTTPS CDF, split at 2048 B (interactive vs bulk),
    /// with a mean bulk run of 3 max-size records.
    #[must_use]
    pub fn browser_https() -> Self {
        Self::from_cdf(
            "browser-https-phase",
            &TrafficProfile::browser_https().record_size_cdf,
            2048,
            3.0,
        )
    }
}

/// Computes record-split boundaries for the Reality data path. Pure with respect
/// to injected entropy (so it is deterministically testable); production callers
/// feed CSPRNG bytes via [`Self::split_plan`]. (Inter-record timing jitter is
/// not applied - see the module-level note on #18.)
#[derive(Debug, Clone)]
pub struct RecordShaper {
    split: SplitSource,
    /// Last Markov bucket index, threaded across [`Self::split_plan`] calls so
    /// record-size runs span write boundaries (a run of bulk records isn't reset
    /// to a fresh draw at every `write`). `None` until the first Markov record;
    /// unused by the non-Markov sources.
    markov_state: Option<usize>,
    /// Current phase for [`SplitSource::PhaseState`] (`Some(true)` = LARGE/bulk),
    /// threaded across [`Self::split_plan`] calls so bimodal runs span writes.
    /// `None` until the first phase record; unused by the other sources.
    phase_state: Option<bool>,
}

impl RecordShaper {
    /// The shipping v0.1 shaper (fixed-policy split).
    pub fn fixed_policy() -> Self {
        Self {
            split: SplitSource::FixedPolicy,
            markov_state: None,
            phase_state: None,
        }
    }

    /// Construct with an explicit split source.
    pub fn new(split: SplitSource) -> Self {
        Self {
            split,
            markov_state: None,
            phase_state: None,
        }
    }

    /// Construct a shaper from a [`MarkovProfile`]: the data-phase record sizes
    /// follow a first-order Markov chain (correlated runs) instead of i.i.d.
    /// CDF draws, so the on-wire length SEQUENCE - not just its marginal -
    /// resembles a real TLS flow. See [`MarkovProfile`] for the marginal-
    /// preservation guarantee.
    pub fn from_markov_profile(profile: &MarkovProfile) -> Self {
        Self {
            split: SplitSource::Markov(profile.clone()),
            markov_state: None,
            phase_state: None,
        }
    }

    /// Construct a shaper from a [`PhaseProfile`]: sub-max record sizes follow a
    /// two-state (interactive/bulk) process whose bimodal run structure matches
    /// real TLS, closing the length-SEQUENCE gap the i.i.d. CDF leaves open.
    #[must_use]
    pub fn from_phase_profile(profile: &PhaseProfile) -> Self {
        Self {
            split: SplitSource::PhaseState(profile.clone()),
            markov_state: None,
            phase_state: None,
        }
    }

    /// Plaintext sub-record lengths for a `pt_len`-byte write, given CSPRNG
    /// `entropy`. The returned lengths are all `> 0`, each `<= MAX_RECORD_PLAINTEXT`,
    /// and **sum to exactly `pt_len`** (no bytes added or dropped - sizing here
    /// is pure framing; actual padding, if any, lives in a different layer).
    ///
    /// - `pt_len == 0` -> empty (nothing to send).
    /// - `pt_len <= RECORD_SPLIT_THRESHOLD` -> a single record `[pt_len]`.
    /// - otherwise (`FixedPolicy`) -> 2 or 3 sub-records chosen from `entropy`.
    ///
    /// `entropy` should be at least 4 bytes; shorter slices are zero-extended
    /// (degraded determinism, not unsafe).
    pub fn split_boundaries(&self, pt_len: usize, entropy: &[u8]) -> Vec<usize> {
        if pt_len == 0 {
            return Vec::new();
        }
        let e = |i: usize| -> usize { *entropy.get(i).unwrap_or(&0) as usize };

        match &self.split {
            SplitSource::FixedPolicy => {
                if pt_len <= RECORD_SPLIT_THRESHOLD {
                    return chunk_to_max(pt_len);
                }
                // 2 or 3 sub-records.
                let n = 2 + (e(0) % 2); // 2 or 3
                                        // Choose n-1 interior cut points in 1..pt_len, drawn from entropy
                                        // and clamped so every resulting piece is >= 1 byte.
                let mut cuts: Vec<usize> = Vec::with_capacity(n - 1);
                for k in 0..(n - 1) {
                    // Spread cuts across the range using independent entropy
                    // bytes; bias toward roughly-even thirds/halves.
                    let frac = (e(1 + k) as f64 + 0.5) / 256.0; // (0,1)
                    let base = ((k + 1) as f64) / (n as f64); // even split target
                                                              // Blend even-split with a +/-1/(2n) jitter from entropy.
                    let pos = base + (frac - 0.5) / (n as f64);
                    let cut = ((pos * pt_len as f64) as usize).clamp(1, pt_len - 1);
                    cuts.push(cut);
                }
                cuts.sort_unstable();
                cuts.dedup();
                // Derive lengths from sorted unique cut points.
                let mut lens = Vec::with_capacity(n);
                let mut prev = 0usize;
                for &c in &cuts {
                    if c > prev {
                        lens.push(c - prev);
                        prev = c;
                    }
                }
                lens.push(pt_len - prev); // final piece
                                          // Enforce the per-record max (a piece could exceed 16384 only if
                                          // pt_len does; callers cap `take`, but be defensive).
                let mut out = Vec::with_capacity(lens.len() + 1);
                for l in lens {
                    out.extend_from_slice(&chunk_to_max(l));
                }
                debug_assert_eq!(out.iter().sum::<usize>(), pt_len);
                out
            }
            SplitSource::Cdf(cdf) => cdf_split(cdf, pt_len, entropy),
            // Stateless (fresh chain/phase per call): deterministic in `entropy`
            // for testing. The live path ([`Self::split_plan`]) threads the last
            // bucket/phase across calls so runs span writes.
            SplitSource::Markov(p) => markov_split(p, pt_len, entropy, None).0,
            SplitSource::PhaseState(p) => phase_split(p, pt_len, entropy, None).0,
        }
    }

    /// Construct a shaper from a capture-calibrated [`TrafficProfile`]: the
    /// data-phase record-size distribution is sampled from the profile's CDF
    /// instead of the fixed 2-3-way split.
    pub fn from_profile(profile: &TrafficProfile) -> Self {
        Self {
            split: SplitSource::Cdf(profile.record_size_cdf.clone()),
            markov_state: None,
            phase_state: None,
        }
    }

    /// Production split: draws CSPRNG entropy and returns the sub-record lengths.
    /// Draws a generous seed so the CDF sampler has independent entropy per
    /// sub-record (the fixed policy uses only the first few bytes).
    pub fn split_plan(&mut self, pt_len: usize) -> Vec<usize> {
        let mut buf = [0u8; 32];
        let _ = getrandom::fill(&mut buf);
        self.split_plan_with_entropy(pt_len, &buf)
    }

    /// Stateful split with caller-supplied `entropy` (the deterministic core of
    /// [`Self::split_plan`]). Threads the Markov last-bucket state across calls
    /// so record-size runs span writes. Callers MUST vary `entropy` per write
    /// (e.g. a fresh CSPRNG draw, as [`Self::split_plan`] does), else every write
    /// reproduces the same record sequence. Exposed for reproducible
    /// tests/certification against the flow-shape distinguisher.
    pub fn split_plan_with_entropy(&mut self, pt_len: usize, entropy: &[u8]) -> Vec<usize> {
        match &self.split {
            // Markov threads the last-bucket state across writes so record-size
            // runs are not reset on every `write` (a bulk download stays a run of
            // max-size records across many poll_write calls).
            SplitSource::Markov(p) => {
                let (plan, new_state) = markov_split(p, pt_len, entropy, self.markov_state);
                self.markov_state = new_state;
                plan
            }
            // PhaseState threads the SMALL/LARGE phase across writes so bimodal
            // runs (a bulk download stays LARGE; an interactive burst stays
            // SMALL) are not reset on every `write`.
            SplitSource::PhaseState(p) => {
                let (plan, new_state) = phase_split(p, pt_len, entropy, self.phase_state);
                self.phase_state = new_state;
                plan
            }
            SplitSource::FixedPolicy | SplitSource::Cdf(_) => {
                self.split_boundaries(pt_len, entropy)
            }
        }
    }

    // NOTE (#18): NO inter-record timing jitter is applied on the Reality path.
    // The carrier previously drew a uniform `[0, MAX_RECORD_JITTER_MS]` delay per
    // handshake record; it was removed because a uniform law masks no real cover
    // cadence (a true network gap is floor-plus-tail, not uniform) and, on the
    // client, produced an unnatural uniform Finished->request gap that is itself a
    // tell. This module previously also carried `next_jitter_ms`/`jitter_ms` dead
    // code, likewise removed. If a shaper-owned pacing layer is ever wired into
    // the data path, introduce a capture-calibrated (distribution-fitted) delay
    // here as the single source of truth - never a uniform draw.
}

/// Hard cap on sub-records produced from a single write, so a small-record-heavy
/// CDF cannot fragment a large write into a pathological flood of tiny records
/// (AEAD overhead + an unrealistic burst). When hit, the final record absorbs
/// the remainder. 32 comfortably covers a full 16 KB write drawn from realistic
/// (few-hundred-byte-and-up) record sizes.
const MAX_SUBRECORDS: usize = 32;

/// Deterministic pseudo-uniform draw in `[0, 1)` from seed `entropy` plus a
/// per-draw `counter` (FNV-1a over the bytes, top 24 bits). Shaping-grade
/// spreading, not cryptographic - the split pattern is not a secret.
fn sample_unit(entropy: &[u8], counter: usize) -> f32 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in entropy {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    for &b in &counter.to_le_bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    ((h >> 40) as f32) / ((1u64 << 24) as f32)
}

/// Split `pt_len` into sub-record lengths whose sizes are sampled from the
/// calibrated CDF (`(record_len, weight)` pairs), preserving the total.
///
/// Each iteration draws a target record size from the CDF and emits
/// `min(target, remaining)`; the loop ends when the payload is consumed or the
/// [`MAX_SUBRECORDS`] cap forces the remainder into one final record. The result
/// is a per-session record-size distribution that tracks the cover's rather than
/// the application's write sizes.
fn cdf_split(cdf: &[(u16, f32)], pt_len: usize, entropy: &[u8]) -> Vec<usize> {
    if pt_len == 0 {
        return Vec::new();
    }
    // Bulk-write handling (red-team #14): a write at/above the max record size is
    // a bulk transfer. Real TLS fragments it into a RUN of max-size (16 KB)
    // records + one partial - the signature of any large HTTPS download. Sampling
    // the cover CDF here instead would emit i.i.d.-sized records that no real TLS
    // bulk transfer produces, so above the max we mirror real TLS and emit
    // max-size records. Sub-max (interactive) writes keep the cover-CDF shaping.
    if pt_len >= MAX_RECORD_PLAINTEXT {
        return chunk_to_max(pt_len);
    }
    let total: f32 = cdf.iter().map(|(_, w)| w.max(0.0)).sum();
    if cdf.is_empty() || total <= 0.0 {
        return chunk_to_max(pt_len);
    }

    let mut out = Vec::new();
    let mut rem = pt_len;
    let mut counter = 0usize;
    while rem > 0 {
        if out.len() + 1 >= MAX_SUBRECORDS {
            // Final record absorbs everything left (bounds the record count).
            out.extend_from_slice(&chunk_to_max(rem));
            return out;
        }
        let r = sample_unit(entropy, counter) * total;
        counter += 1;
        // Locate the record size at cumulative position `r`.
        let mut acc = 0.0f32;
        let mut chosen = cdf[cdf.len() - 1].0 as usize;
        for (len, w) in cdf {
            acc += w.max(0.0);
            if r < acc {
                chosen = *len as usize;
                break;
            }
        }
        let take = chosen.clamp(1, MAX_RECORD_PLAINTEXT).min(rem);
        out.push(take);
        rem -= take;
    }
    debug_assert_eq!(out.iter().sum::<usize>(), pt_len);
    out
}

/// Draw a record size from `buckets` (`(len, weight)`, weights need not be
/// normalized) using entropy `counter`. Mirrors [`cdf_split`]'s inner draw.
fn draw_bucket_size(buckets: &[(u16, f32)], entropy: &[u8], counter: usize) -> usize {
    let total: f32 = buckets.iter().map(|(_, w)| w.max(0.0)).sum();
    if buckets.is_empty() || total <= 0.0 {
        return MAX_RECORD_PLAINTEXT;
    }
    let r = sample_unit(entropy, counter) * total;
    let mut acc = 0.0f32;
    for (len, w) in buckets {
        acc += w.max(0.0);
        if r < acc {
            return *len as usize;
        }
    }
    buckets[buckets.len() - 1].0 as usize
}

/// Two-phase (interactive/bulk) split for a `pt_len` write. Threads the phase in
/// `state` (`Some(true)` = LARGE) across calls so bimodal runs span writes; returns
/// the sub-record lengths (summing to `pt_len`) and the new phase.
///
/// - `pt_len >= MAX_RECORD_PLAINTEXT` -> a run of max records (real TLS bulk),
///   and we are now in the LARGE phase.
/// - otherwise -> walk the two-state machine, drawing each record size from the
///   current phase's bucket set and transitioning with that phase's rate.
fn phase_split(
    p: &PhaseProfile,
    pt_len: usize,
    entropy: &[u8],
    state: Option<bool>,
) -> (Vec<usize>, Option<bool>) {
    if pt_len == 0 {
        return (Vec::new(), state);
    }
    if pt_len >= MAX_RECORD_PLAINTEXT {
        return (chunk_to_max(pt_len), Some(true));
    }
    // Seed the phase from the stationary occupancy on the first-ever record.
    let denom = (p.p_small_to_large + p.p_large_to_small).max(1e-6);
    let pi_large = p.p_small_to_large / denom;
    let mut large = state.unwrap_or_else(|| sample_unit(entropy, 0) < pi_large);

    let mut out = Vec::new();
    let mut rem = pt_len;
    let mut ctr = 1usize;
    while rem > 0 {
        if out.len() + 1 >= MAX_SUBRECORDS {
            // Final record absorbs the remainder (bounds the record count).
            out.extend_from_slice(&chunk_to_max(rem));
            return (out, Some(large));
        }
        let buckets = if large { &p.large } else { &p.small };
        let target = draw_bucket_size(buckets, entropy, ctr);
        let take = target.clamp(1, MAX_RECORD_PLAINTEXT).min(rem);
        out.push(take);
        rem -= take;
        // Transition with the current phase's switch rate.
        let switch_p = if large {
            p.p_large_to_small
        } else {
            p.p_small_to_large
        };
        if sample_unit(entropy, ctr + 4096) < switch_p {
            large = !large;
        }
        ctr += 1;
    }
    debug_assert_eq!(out.iter().sum::<usize>(), pt_len);
    (out, Some(large))
}

/// Sample the next bucket index for the Markov chain given the previous bucket
/// (`prev`), the stationary weights, the stickiness, and two unit draws in
/// `[0,1)`. With probability `stickiness` keep `prev`; otherwise redraw a fresh
/// bucket from `stationary`. The `(1-a)*pi + a*I` kernel preserves `pi` as the
/// stationary distribution (see [`MarkovProfile`]).
fn markov_next(
    stationary: &[f32],
    stickiness: f32,
    prev: Option<usize>,
    u_stick: f32,
    u_draw: f32,
) -> usize {
    if let Some(p) = prev {
        if u_stick < stickiness && p < stationary.len() {
            return p;
        }
    }
    let total: f32 = stationary.iter().map(|w| w.max(0.0)).sum();
    if total <= 0.0 {
        return 0;
    }
    let r = u_draw * total;
    let mut acc = 0.0f32;
    for (i, w) in stationary.iter().enumerate() {
        acc += w.max(0.0);
        if r < acc {
            return i;
        }
    }
    stationary.len().saturating_sub(1)
}

/// Split `pt_len` into sub-record lengths whose SIZES follow the first-order
/// Markov chain in `profile`, threading `in_state` (the last bucket index) so
/// runs span write boundaries. Returns the plan plus the final bucket index for
/// the next call. The total is preserved exactly; bulk writes
/// (`>= MAX_RECORD_PLAINTEXT`) mirror real TLS (a run of max-size records) like
/// [`cdf_split`], and the returned state is left on the max bucket so a
/// following write continues the bulk run.
fn markov_split(
    profile: &MarkovProfile,
    pt_len: usize,
    entropy: &[u8],
    in_state: Option<usize>,
) -> (Vec<usize>, Option<usize>) {
    if pt_len == 0 {
        return (Vec::new(), in_state);
    }
    // Malformed profile -> safe framing fallback (mirrors cdf_split).
    if profile.buckets.is_empty() || profile.buckets.len() != profile.stationary.len() {
        return (chunk_to_max(pt_len), in_state);
    }
    if pt_len >= MAX_RECORD_PLAINTEXT {
        let plan = chunk_to_max(pt_len);
        // Continue any bulk run: leave state on the largest bucket if present.
        let bulk_state = profile
            .buckets
            .iter()
            .enumerate()
            .filter(|(_, &b)| b as usize >= MAX_RECORD_PLAINTEXT)
            .map(|(i, _)| i)
            .next()
            .or(in_state);
        return (plan, bulk_state);
    }
    let mut out = Vec::new();
    let mut rem = pt_len;
    let mut state = in_state;
    let mut counter = 0usize;
    while rem > 0 {
        if out.len() + 1 >= MAX_SUBRECORDS {
            out.extend_from_slice(&chunk_to_max(rem));
            return (out, state);
        }
        // Two independent unit draws per step (stay-vs-redraw, and the redraw).
        let u_stick = sample_unit(entropy, counter);
        let u_draw = sample_unit(entropy, counter.wrapping_add(0x1000));
        counter += 1;
        let bucket = markov_next(
            &profile.stationary,
            profile.stickiness,
            state,
            u_stick,
            u_draw,
        );
        // Advance the chain to the DRAWN bucket (not the possibly-clamped emitted
        // size), so a write-boundary tail record doesn't derail the run.
        state = Some(bucket);
        let chosen = profile.buckets[bucket] as usize;
        let take = chosen.clamp(1, MAX_RECORD_PLAINTEXT).min(rem);
        out.push(take);
        rem -= take;
    }
    debug_assert_eq!(out.iter().sum::<usize>(), pt_len);
    (out, state)
}

/// A capture-calibrated record-size distribution for the Reality data path.
///
/// The `record_size_cdf` is a list of `(record_len_bytes, weight)` buckets; the
/// [`RecordShaper`] samples record sizes from it so Mirage's on-wire
/// `application_data` length distribution tracks a real browser<->CDN flow
/// instead of echoing the application's write sizes.
///
/// [`Self::browser_https`] ships a documented approximation of TLS 1.3 HTTPS
/// record sizes (small interactive/control records through MSS-influenced
/// response chunks up to full 2^14 bulk records). A deployment with a real
/// packet capture can build a `TrafficProfile` with the measured CDF and pass it
/// to [`RecordShaper::from_profile`] - the plug-in point is the same.
#[derive(Debug, Clone)]
pub struct TrafficProfile {
    /// Human-readable profile name (for logs / diagnostics).
    pub name: &'static str,
    /// Record-size CDF buckets: `(record_len_bytes, relative_weight)`.
    pub record_size_cdf: Vec<(u16, f32)>,
}

impl TrafficProfile {
    /// TLS 1.3 HTTPS `application_data` record-size distribution, CALIBRATED to a
    /// real packet capture (tcpdump + tshark `tls.record.length`, server->client
    /// direction) of a representative browsing mix - Wikipedia/BBC/GitHub content
    /// pages, JSON APIs, an image, and a modest download, over Cloudflare/CDN
    /// TLS 1.3, 420 records (2026-07-20). The earlier hand-picked profile was
    /// materially wrong: it put 28% at 1024 B (measured 2%) and only 10% at the
    /// full 2^14 record (measured 26%) - real CDN HTTPS is far more large-record-
    /// heavy. Guarded by `flow_classifier::reality_cdf_matches_real_capture`.
    ///
    /// Bucket sizes are the nearest representative of the measured modes (the
    /// wire 16401/4246/1386 map to plaintext 16384/4096/1460). A deployment whose
    /// cover differs (a specific CDN, HTTP/2 vs /3) SHOULD re-capture and build
    /// its own [`TrafficProfile`]; the plug-in point is [`RecordShaper::from_profile`].
    pub fn browser_https() -> Self {
        Self {
            name: "browser-https",
            record_size_cdf: vec![
                (64, 0.11),    // tiny control/interactive records (measured 11%)
                (256, 0.10),   // small headers / short responses
                (1024, 0.02),  // (rare in the capture)
                (1460, 0.14),  // MSS-sized records (measured 1386 B)
                (4096, 0.25),  // common medium chunk (measured 4246 B)
                (8192, 0.12),  // large chunk
                (16384, 0.26), // full-size bulk record (measured 16401 B on wire)
            ],
        }
    }
}

/// Split a length into consecutive chunks each `<= MAX_RECORD_PLAINTEXT`,
/// preserving the total. (A single TLS record cannot carry more than 2^14 B.)
fn chunk_to_max(len: usize) -> Vec<usize> {
    if len == 0 {
        return Vec::new();
    }
    let mut out = Vec::with_capacity(len / MAX_RECORD_PLAINTEXT + 1);
    let mut rem = len;
    while rem > MAX_RECORD_PLAINTEXT {
        out.push(MAX_RECORD_PLAINTEXT);
        rem -= MAX_RECORD_PLAINTEXT;
    }
    out.push(rem);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_write_no_records() {
        let s = RecordShaper::fixed_policy();
        assert!(s.split_boundaries(0, &[0; 4]).is_empty());
    }

    #[test]
    fn under_threshold_single_record() {
        let s = RecordShaper::fixed_policy();
        for len in [1usize, 100, 1000, RECORD_SPLIT_THRESHOLD] {
            assert_eq!(s.split_boundaries(len, &[0x55; 4]), vec![len]);
        }
    }

    #[test]
    fn over_threshold_splits_2_or_3_and_preserves_total() {
        let s = RecordShaper::fixed_policy();
        // Sweep entropy + lengths; every plan must sum to pt_len, have 2..=3
        // pieces (within the <=16384 single-record regime), each piece > 0
        // and <= MAX_RECORD_PLAINTEXT.
        for pt_len in [4097usize, 8000, 12000, 16384] {
            for seed in 0u16..=255 {
                let entropy = [seed as u8, (seed >> 1) as u8, (seed >> 2) as u8, 0xA5];
                let plan = s.split_boundaries(pt_len, &entropy);
                assert_eq!(plan.iter().sum::<usize>(), pt_len, "total preserved");
                assert!(
                    (2..=3).contains(&plan.len()),
                    "pt_len {pt_len} seed {seed}: expected 2-3 records, got {}",
                    plan.len()
                );
                assert!(plan.iter().all(|&l| l > 0), "no empty record");
                assert!(
                    plan.iter().all(|&l| l <= MAX_RECORD_PLAINTEXT),
                    "record within 2^14"
                );
            }
        }
    }

    #[test]
    fn deterministic_in_entropy() {
        let s = RecordShaper::fixed_policy();
        let e = [0x12, 0x34, 0x56, 0x78];
        assert_eq!(s.split_boundaries(10000, &e), s.split_boundaries(10000, &e));
    }

    #[test]
    fn oversize_plaintext_chunked_to_record_max() {
        // Defensive: a >16384 length (shouldn't happen - callers cap take) is
        // still framed into valid <=16384 records summing to the total.
        let s = RecordShaper::fixed_policy();
        let plan = s.split_boundaries(40000, &[1, 2, 3, 4]);
        assert_eq!(plan.iter().sum::<usize>(), 40000);
        assert!(plan.iter().all(|&l| l <= MAX_RECORD_PLAINTEXT));
    }

    #[test]
    fn cdf_split_preserves_total_and_bounds_records() {
        let s = RecordShaper::from_profile(&TrafficProfile::browser_https());
        for pt_len in [1usize, 500, 4096, 16384, 40000] {
            for seed in 0u16..64 {
                let entropy = [
                    seed as u8,
                    (seed >> 4) as u8,
                    0x5A,
                    0xC3,
                    0x11,
                    0x22,
                    0x33,
                    0x44,
                ];
                let plan = s.split_boundaries(pt_len, &entropy);
                assert_eq!(plan.iter().sum::<usize>(), pt_len, "total preserved");
                assert!(plan.iter().all(|&l| l > 0 && l <= MAX_RECORD_PLAINTEXT));
                assert!(
                    plan.len() <= MAX_SUBRECORDS,
                    "pt_len {pt_len} seed {seed}: {} records exceeds cap",
                    plan.len()
                );
            }
        }
    }

    #[test]
    fn cdf_split_is_deterministic_in_entropy() {
        let s = RecordShaper::from_profile(&TrafficProfile::browser_https());
        let e = [0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0];
        assert_eq!(s.split_boundaries(9000, &e), s.split_boundaries(9000, &e));
    }

    #[test]
    fn cdf_split_samples_from_profile_sizes() {
        // For SUB-max (interactive) writes the produced record sizes are drawn
        // from the profile's buckets (varied), not a single monolithic record.
        let profile = TrafficProfile::browser_https();
        let s = RecordShaper::from_profile(&profile);
        let mut sizes = std::collections::BTreeSet::new();
        for seed in 0u16..200 {
            let e = [seed as u8, (seed >> 3) as u8, 0xAA, 0x55, 1, 2, 3, 4];
            // 9000 < MAX_RECORD_PLAINTEXT -> CDF (interactive) path.
            for l in s.split_boundaries(9000, &e) {
                sizes.insert(l);
            }
        }
        assert!(
            sizes.len() > 3,
            "CDF sampling must yield varied record sizes for interactive writes"
        );
    }

    #[test]
    fn bulk_writes_emit_max_size_record_runs() {
        // red-team #14: a write at/above the max record size is bulk; real TLS
        // fragments it into a RUN of 16 KB records + one partial. The shaper must
        // mirror that instead of CDF-sampling varied sizes (which no real TLS
        // bulk transfer shows).
        let s = RecordShaper::from_profile(&TrafficProfile::browser_https());
        let plan = s.split_boundaries(40_000, &[9, 9, 9, 9, 9, 9, 9, 9]);
        assert_eq!(plan.iter().sum::<usize>(), 40_000, "total preserved");
        // 40000 = 16384 + 16384 + 7232.
        assert_eq!(plan[0], MAX_RECORD_PLAINTEXT);
        assert_eq!(plan[1], MAX_RECORD_PLAINTEXT);
        assert!(*plan.last().unwrap() < MAX_RECORD_PLAINTEXT);
        // Deterministic regardless of entropy (bulk is a fixed shape).
        assert_eq!(plan, s.split_boundaries(40_000, &[1, 2, 3, 4, 5, 6, 7, 8]));
    }

    #[test]
    fn empty_cdf_falls_back_to_chunking() {
        let s = RecordShaper::new(SplitSource::Cdf(Vec::new()));
        let plan = s.split_boundaries(20000, &[1, 2, 3, 4]);
        assert_eq!(plan.iter().sum::<usize>(), 20000);
        assert!(plan.iter().all(|&l| l <= MAX_RECORD_PLAINTEXT));
    }

    #[test]
    fn profile_cdf_weights_are_positive_and_sizes_valid() {
        let p = TrafficProfile::browser_https();
        assert!(!p.record_size_cdf.is_empty());
        for (len, w) in &p.record_size_cdf {
            assert!(*len as usize <= MAX_RECORD_PLAINTEXT && *len > 0);
            assert!(*w > 0.0);
        }
    }

    // ---- conditional record-length process (Markov, #1) ----

    /// Mean length of maximal runs of EQUAL consecutive values (1.0 if all
    /// distinct). Mirrors the adversary's `mean_run_length` sequential feature.
    fn mean_run_length(v: &[usize]) -> f64 {
        if v.len() < 2 {
            return 1.0;
        }
        let transitions = v.windows(2).filter(|w| w[0] != w[1]).count();
        v.len() as f64 / (transitions + 1) as f64
    }

    #[test]
    fn markov_split_preserves_total_and_bounds_records() {
        let s = RecordShaper::from_markov_profile(&MarkovProfile::browser_https());
        for pt_len in [1usize, 500, 4096, 16383, 16384, 40000] {
            for seed in 0u16..64 {
                let e = [
                    seed as u8,
                    (seed >> 4) as u8,
                    0x5A,
                    0xC3,
                    0x11,
                    0x22,
                    0x33,
                    0x44,
                ];
                let plan = s.split_boundaries(pt_len, &e);
                assert_eq!(plan.iter().sum::<usize>(), pt_len, "total preserved");
                assert!(plan.iter().all(|&l| l > 0 && l <= MAX_RECORD_PLAINTEXT));
                assert!(plan.len() <= MAX_SUBRECORDS, "record count capped");
            }
        }
    }

    #[test]
    fn markov_chain_marginal_matches_stationary() {
        // The chain's empirical bucket frequency must converge to `stationary`
        // (the marginal-preservation guarantee), independent of stickiness.
        let p = MarkovProfile::browser_https();
        let total_w: f32 = p.stationary.iter().sum();
        let mut counts = vec![0usize; p.buckets.len()];
        let mut state: Option<usize> = None;
        let n = 300_000usize;
        // A cheap LCG for independent-ish unit draws (decoupled from sample_unit).
        let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut unit = || {
            x = x.wrapping_mul(6364136223846793005).wrapping_add(1);
            ((x >> 40) as f32) / ((1u64 << 24) as f32)
        };
        for _ in 0..n {
            let b = markov_next(&p.stationary, p.stickiness, state, unit(), unit());
            counts[b] += 1;
            state = Some(b);
        }
        for (i, &c) in counts.iter().enumerate() {
            let emp = c as f32 / n as f32;
            let want = p.stationary[i] / total_w;
            assert!(
                (emp - want).abs() < 0.01,
                "bucket {i}: empirical {emp:.4} vs stationary {want:.4}"
            );
        }
    }

    #[test]
    fn markov_threaded_runs_longer_than_iid() {
        // The Markov process (state threaded across writes) must produce longer
        // same-size runs than the i.i.d. CDF draw - the sequential structure it
        // adds. Uses an explicit SMALL-bucket profile (decoupled from the shipped
        // browser_https CDF, whose calibration is large-record-heavy) so a
        // 4000-byte write splits into several records and the run-length contrast
        // is between the two PROCESSES, not an artifact of the size distribution.
        let mp = MarkovProfile {
            name: "runtest",
            buckets: vec![256, 512, 1024, 1460],
            stationary: vec![0.25, 0.25, 0.25, 0.25],
            stickiness: 0.6,
        };
        let cdf: Vec<(u16, f32)> = mp
            .buckets
            .iter()
            .zip(&mp.stationary)
            .map(|(&b, &w)| (b, w))
            .collect();

        let ent = |k: u32| {
            let mut e = [0u8; 8];
            for (j, b) in e.iter_mut().enumerate() {
                *b = (k.wrapping_mul(2654435761).wrapping_add(j as u32)) as u8;
            }
            e
        };

        // Markov: thread state across 600 writes.
        let mut mk = Vec::new();
        let mut state = None;
        for k in 0..600u32 {
            let (plan, ns) = markov_split(&mp, 4000, &ent(k), state);
            state = ns;
            mk.extend(plan);
        }
        // i.i.d.: stateless cdf draws.
        let mut ii = Vec::new();
        for k in 0..600u32 {
            ii.extend(cdf_split(&cdf, 4000, &ent(k)));
        }

        let m = mean_run_length(&mk);
        let i = mean_run_length(&ii);
        assert!(
            m > i * 1.3,
            "markov run length {m:.2} must clearly exceed i.i.d. {i:.2}"
        );
    }

    #[test]
    fn markov_zero_stickiness_matches_iid_runs() {
        // Alpha = 0 recovers the i.i.d. draw: run structure indistinguishable
        // from cdf_split (both ~1, from bucket collisions only).
        let mut mp = MarkovProfile::browser_https();
        mp.stickiness = 0.0;
        let cdf: Vec<(u16, f32)> = mp
            .buckets
            .iter()
            .zip(&mp.stationary)
            .map(|(&b, &w)| (b, w))
            .collect();
        let ent = |k: u32| [(k * 7) as u8, (k * 13) as u8, 0x5A, 0xA5, 1, 2, 3, 4];
        let mut mk = Vec::new();
        let mut state = None;
        for k in 0..600u32 {
            let (plan, ns) = markov_split(&mp, 4000, &ent(k), state);
            state = ns;
            mk.extend(plan);
        }
        let mut ii = Vec::new();
        for k in 0..600u32 {
            ii.extend(cdf_split(&cdf, 4000, &ent(k)));
        }
        let m = mean_run_length(&mk);
        let i = mean_run_length(&ii);
        assert!(
            (m - i).abs() < 0.35,
            "alpha=0 markov run length {m:.2} must match i.i.d. {i:.2}"
        );
    }

    #[test]
    fn markov_bulk_writes_emit_max_size_record_runs() {
        // A >= 2^14 write is bulk: a run of max-size records + a partial, like
        // real TLS (not CDF/Markov-sampled varied sizes).
        let mp = MarkovProfile::browser_https();
        let (plan, state) = markov_split(&mp, 40_000, &[9; 8], None);
        assert_eq!(plan.iter().sum::<usize>(), 40_000);
        assert_eq!(plan[0], MAX_RECORD_PLAINTEXT);
        assert_eq!(plan[1], MAX_RECORD_PLAINTEXT);
        assert!(*plan.last().unwrap() < MAX_RECORD_PLAINTEXT);
        // State left on the max bucket so a following write continues the run.
        assert_eq!(
            state,
            Some(mp.buckets.iter().position(|&b| b == 16384).unwrap())
        );
    }

    #[test]
    fn markov_split_plan_threads_state_across_calls() {
        // The live entry (split_plan, &mut self) must carry Markov state so a
        // record-size run isn't reset every write.
        let mut s = RecordShaper::from_markov_profile(&MarkovProfile::browser_https());
        // Bulk write leaves state on the max bucket.
        let _ = s.split_plan(40_000);
        assert!(
            s.markov_state.is_some(),
            "state persists after a Markov split"
        );
    }
}
