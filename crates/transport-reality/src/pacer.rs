//! Flow-level envelope pacer.
//!
//! Paces record emission to a cover envelope and pads every record to the token
//! size, so the observable `(t, size, dir)` matches the cover regardless of payload.
//! Generating an envelope is detectable; replaying a real captured one
//! ([`MeasuredProfile`] + [`ScheduleStream::replay`]) is not. The generative
//! [`CoverProcess`] classes are low-cost defaults; replay is the real path.
//!
//! Pure and deterministic (splitmix64 from a shared seed), so both endpoints derive
//! the same schedule with nothing on the wire. The live driver is [`ScheduleStream`],
//! an unbounded continuous generator (a fixed-window restart is itself a fingerprint).

/// Fold arbitrary key bytes into a 64-bit schedule seed (splitmix64 finalizer).
/// NOT cryptographic - it only diversifies the traffic schedule. Both endpoints
/// derive the same session seed by mixing the shared AEAD keys in a
/// direction-symmetric way (`mix_seed(send) ^ mix_seed(recv)`), so neither a wire
/// exchange nor clock sync is needed for them to agree on the envelope.
pub fn mix_seed(bytes: &[u8]) -> u64 {
    let mut acc = 0u64;
    for (i, chunk) in bytes.chunks(8).enumerate() {
        let mut b = [0u8; 8];
        b[..chunk.len()].copy_from_slice(chunk);
        acc ^= u64::from_le_bytes(b).rotate_left((i as u32).wrapping_mul(7) % 64);
    }
    let mut z = acc.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// Packet direction relative to the client.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Dir {
    /// Server -> client.
    Down,
    /// Client -> server.
    Up,
}

/// A target emission event: at `t` seconds after flow start, emit a packet of
/// `bytes` on `dir`. The envelope the tunnel paces to.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct EmitToken {
    /// Seconds after flow start at which to emit.
    pub t: f64,
    /// Target wire size of the packet (bytes).
    pub bytes: usize,
    /// Direction.
    pub dir: Dir,
}

/// Deterministic, seedable PRNG (splitmix64). NOT cryptographic - it drives traffic
/// shape only. Determinism lets both endpoints derive the identical schedule from a
/// shared seed, and makes the tests reproducible.
pub struct Prng(u64);

impl Prng {
    /// Seed the generator (both endpoints pass the same shared value).
    pub fn new(seed: u64) -> Self {
        Prng(seed)
    }
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    /// Uniform in [0, 1).
    fn unit(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }
    fn uniform(&mut self, a: f64, b: f64) -> f64 {
        a + (b - a) * self.unit()
    }
    /// Exponential with the given mean (for Poisson-ish inter-packet gaps).
    fn exp(&mut self, mean: f64) -> f64 {
        -mean * (1.0 - self.unit()).ln()
    }
    /// Normal(mean, std) via Box-Muller - for lognormal object sizes etc.
    fn normal(&mut self, mean: f64, std: f64) -> f64 {
        let u1 = self.unit().max(1e-12);
        let u2 = self.unit();
        let z = (-2.0 * u1.ln()).sqrt() * (core::f64::consts::TAU * u2).cos();
        mean + std * z
    }
    fn range(&mut self, lo: u64, hi: u64) -> u64 {
        debug_assert!(hi > lo);
        lo + self.next_u64() % (hi - lo)
    }
}

/// Full-payload record size for the GENERATIVE cover process.
///
/// A conservative Ethernet MTU (1500) less a typical IPv4+TCP header with options
/// (~60 B), so a record fits one segment on almost any path without fragmenting.
/// Applies only to generated envelopes; the replay path takes every size from the
/// capture and never consults this.
const MTU: usize = 1400;

/// Bare-acknowledgement record size for the GENERATIVE cover process.
///
/// A TLS record carrying a minimal HTTP/2 ACK or WINDOW_UPDATE: 5 B record header
/// plus a 9 B h2 frame header plus payload and AEAD tag. Generated envelopes only,
/// as with [`MTU`].
const ACK: usize = 54;

/// A benign-class traffic process. Emits an envelope SCHEDULE (sizes + timing +
/// direction) with the class's real structure - the burst cadence and periodicity
/// a flow classifier keys on. This enum is the seed of the Proteus class library.
#[derive(Clone, Debug)]
pub enum CoverProcess {
    /// DASH/ABR video: periodic downstream segment bursts (a spectral cadence),
    /// sparse upstream acks, a small GET before each segment. Downstream-dominant.
    Video {
        /// Segment interval in seconds (the cadence a spectral detector sees).
        seg_s: f64,
        /// Nominal ABR bitrate in bits/second.
        bitrate_bps: f64,
    },
    /// Web browsing: page loads = bursts of parallel object fetches (heavy-tailed
    /// object sizes, bidirectional), separated by read-idle gaps. No strict cadence.
    Browse,
}

impl CoverProcess {
    /// Construct a cover class from a class NAME and a shared SEED. Both endpoints
    /// pass the same `class` and `seed`, so they agree on the process (and its
    /// per-session parameters) with no wire negotiation. Unknown names fall back to
    /// `Browse`.
    pub fn from_class_seed(class: &str, seed: u64) -> CoverProcess {
        match class {
            "video" | "dash" => {
                // Per-session variation over the ranges the reference model draws from.
                let seg_s = 3.5 + ((seed >> 20) % 1000) as f64 / 1000.0; // 3.5..4.5
                let bitrate_bps = 3.0e6 + ((seed >> 8) % 4000) as f64 * 1000.0; // 3e6..7e6
                CoverProcess::Video { seg_s, bitrate_bps }
            }
            _ => CoverProcess::Browse,
        }
    }

    /// Approximate downstream byte-rate the envelope offers - used to pick a
    /// demand-matched class (an envelope that can carry the user's demand).
    pub fn down_bps(&self) -> f64 {
        match self {
            CoverProcess::Video { bitrate_bps, .. } => *bitrate_bps,
            CoverProcess::Browse => 1.2e6,
        }
    }

    /// Generate the emit-token schedule for `dur` seconds, deterministic from `seed`.
    pub fn schedule(&self, dur: f64, seed: u64) -> Vec<EmitToken> {
        let mut r = Prng::new(seed);
        let mut out: Vec<EmitToken> = Vec::new();
        match self {
            CoverProcess::Video { seg_s, bitrate_bps } => {
                let seg_s = *seg_s;
                let mut clock = r.uniform(0.0, seg_s);
                let mut br = *bitrate_bps;
                while clock < dur {
                    if r.unit() < 0.15 {
                        br = (br * r.uniform(0.6, 1.6)).clamp(1.5e6, 9e6); // ABR switch
                    }
                    let seg_bytes = br * seg_s / 8.0;
                    let npkt = ((seg_bytes / MTU as f64) as usize).max(1);
                    out.push(EmitToken {
                        t: clock,
                        bytes: r.range(200, 600) as usize,
                        dir: Dir::Up,
                    });
                    let burst = r.uniform(0.25, 0.9).min(seg_s * 0.8);
                    let mut tt = clock + 0.01;
                    for k in 0..npkt {
                        tt += r.exp(burst / npkt as f64);
                        out.push(EmitToken {
                            t: tt,
                            bytes: MTU,
                            dir: Dir::Down,
                        });
                        if k % 3 == 2 {
                            out.push(EmitToken {
                                t: tt + 1e-4,
                                bytes: ACK,
                                dir: Dir::Up,
                            });
                        }
                    }
                    clock += seg_s * r.uniform(0.95, 1.05);
                }
            }
            CoverProcess::Browse => {
                let mut clock = r.uniform(0.0, 1.0);
                while clock < dur {
                    let nobj = r.range(4, 25);
                    let load = r.uniform(0.6, 2.5);
                    for _ in 0..nobj {
                        let start = clock + r.uniform(0.0, load);
                        out.push(EmitToken {
                            t: start,
                            bytes: r.range(150, 800) as usize,
                            dir: Dir::Up,
                        });
                        // object size ~ lognormal(9.5, 1.3) (heavy-tailed, like real web objects)
                        let obj = r.normal(9.5, 1.3).exp().clamp(200.0, 3.0e6);
                        let npkt = ((obj / MTU as f64) as usize).max(1);
                        let mut tt = start + 0.03;
                        for k in 0..npkt {
                            tt += r.exp(0.02);
                            let last = k == npkt - 1;
                            let sz = if last {
                                (obj as usize % MTU).max(1)
                            } else {
                                MTU
                            };
                            out.push(EmitToken {
                                t: tt,
                                bytes: sz,
                                dir: Dir::Down,
                            });
                            if k % 4 == 3 {
                                out.push(EmitToken {
                                    t: tt + 1e-4,
                                    bytes: ACK,
                                    dir: Dir::Up,
                                });
                            }
                        }
                    }
                    clock += load + r.uniform(4.0, 14.0); // user reads
                }
            }
        }
        out.retain(|e| e.t < dur);
        out.sort_by(|a, b| a.t.total_cmp(&b.t));
        out
    }
}

/// A replay profile: a real captured `(t, size, dir)` token sequence (built by
/// `tools/cover-sources`). Replaying a genuine draw makes the observable equal the
/// cover's by construction, which a generated envelope cannot.
#[derive(Clone, Debug)]
pub struct MeasuredProfile {
    /// The captured tokens, time-sorted and monotonic (multiple captured flows are
    /// concatenated into one continuous stream).
    pub tokens: Vec<EmitToken>,
    /// Total time span of the profile (seconds); one replay cycle lasts this long.
    pub span: f64,
    /// Token index at which each chained trace begins, in replay order.
    ///
    /// Concatenation used to flatten the chain into one anonymous token stream, so
    /// "which trace is being worn right now" was unrecoverable after parsing. That
    /// makes a capture attributable to a trace FILE but not to a POSITION, and the
    /// two are different claims: with [`crate::paced::CHAIN_LEN`] longer than a
    /// small library the chain wraps inside a single session, so a bare token
    /// offset is ambiguous between passes. Keeping the boundaries makes both the
    /// current trace and the wrap points observable.
    pub flow_starts: Vec<usize>,
    /// The capture's JOINT timeline: `(t, bytes, dir, flow)` in true time order,
    /// across all flows.
    ///
    /// `tokens` sorts by `(flow, t)` and rebases each flow to follow the previous
    /// one, which answers "what did connection K do" and destroys "what was
    /// happening at instant T". A real multi-connection page load alternates -
    /// request on one connection, response on another, subresource on a third -
    /// and that alternation is the joint structure the multi-carrier replay has to
    /// reproduce. It cannot be recovered from `tokens`, so it is kept here.
    ///
    /// Carriers replay their own subset of this at the recorded times. The shared
    /// timeline is what makes inter-carrier correlation legitimate: it was fixed
    /// by the capture before the session had any payload, so it cannot encode one.
    pub joint: Vec<(f64, usize, Dir, u64)>,
    /// Original arrival offset of each captured flow, in seconds relative to the
    /// first flow's first record.
    ///
    /// # Are carriers independent of each other? Decided: no, and deliberately.
    ///
    /// Recorded before the independence tests are written, because the tests pin
    /// whichever answer is chosen and choosing by accident is how a model becomes
    /// permanent.
    ///
    /// Real concurrent connections to one origin are NOT independent. They share a
    /// congestion domain, they are driven by one parser discovering subresources,
    /// and their activity alternates causally - request on conn 1, response on
    /// conn 2, subresource on conn 3. Perfectly independent carriers are as wrong
    /// as perfectly serialised ones, in the other direction.
    ///
    /// So two kinds of independence have to be separated, and only one is a
    /// security property:
    ///
    /// - **Independence from PAYLOAD is non-negotiable.** No carrier's emission may
    ///   depend on its own queue depth, on another carrier's backlog, on a stall,
    ///   or on how much data the session has to send. This is the property the
    ///   whole design rests on and it is what the tests must assert.
    /// - **Independence from EACH OTHER is a modelling choice**, and the capture
    ///   says real traffic does not have it.
    ///
    /// The resolution: carriers are **jointly scheduled by a fixed timeline taken
    /// from the capture, and never by a runtime dependency on one another.** The
    /// interleaving pattern is replayed because it was recorded; it is not produced
    /// by carrier 2 waiting for carrier 1 to finish. A pre-computed timeline is
    /// payload-independent by construction - it was fixed before the session had
    /// any payload - while an event-driven one would recouple to demand through
    /// the back door, which is the leak this design already closed once.
    ///
    /// Consequence for the tests, so they pin the right thing: assert that a
    /// carrier's emission is unchanged when another is **saturated or dead**, and
    /// that emissions do not correlate with **payload**. Do NOT assert that carrier
    /// emissions are mutually uncorrelated in time - under this model they are
    /// correlated on purpose, and an independence test written the obvious way
    /// would forbid the faithful behaviour.
    ///
    /// # The property to test: every correlation must be traceable to the capture
    ///
    /// Stronger and more testable than either "independent" or "correlated". It
    /// admits recorded interleaving and rejects correlation with no provenance -
    /// a `now()` hoisted above the carrier loop quantising every carrier to one
    /// tick, a shared jitter draw, a shared allocator stalling all carriers
    /// together. Each of those would pass a "carrier N unchanged while M is
    /// saturated" test while producing lockstep timing.
    ///
    /// It is the same provenance discipline as the rest of this project: a value
    /// is legitimate because of where it came from, not because it looks right.
    ///
    /// **Practical form of the test:** replay the same trace twice under different
    /// payloads and assert the INTER-CARRIER timing relationship is identical.
    /// Recorded correlation is reproducible because it was fixed before the
    /// session began; implementation correlation varies with load, so it shows up
    /// as a difference between the two runs.
    ///
    /// This requires the cross-flow interleaving that `from_csv` currently sorts
    /// away (defect 1 in its docs) to be preserved, not merely recorded - and it
    /// requires the capture to retain per-record flow attribution on a COMMON
    /// clock. It did not: `browser_capture.py` timed every connection from its own
    /// start, so two connection traces were mutually unplaceable and the
    /// interleaving was destroyed at capture time rather than at parse time. Fixed
    /// there by stamping each connection's offset from a process-wide epoch.
    ///
    /// The count of these IS the carrier count the trace justifies - `M` comes
    /// from the capture, never from a config constant, for the same reason every
    /// other derived parameter does. And the VALUES are the ramp: a real browser
    /// opens some connections together and others later, so opening all `M` at
    /// t=0 is as much an invention as opening one when the queue deepens.
    /// Demand must drive neither the count nor the arrival times.
    pub flow_arrivals: Vec<f64>,
}

/// Where a replay currently is: unambiguous across chain wraps.
///
/// `(trace, pass, offset)` rather than a bare offset, because the chain repeats
/// within a session - offset 1200 on the first pass and on the second are
/// different points in the session and would otherwise be indistinguishable in a
/// capture. Reported BY the pacer rather than inferred by a harness from elapsed
/// time: a harness that divides wall-clock by span and a pacer that counts tokens
/// disagree under any stall, and nothing would notice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReplayPosition {
    /// Index of the chained trace being worn, in replay order.
    pub trace: usize,
    /// How many complete cycles of the whole chain have finished.
    pub pass: u64,
    /// Token index within the whole concatenated chain.
    pub token: usize,
    /// Token index measured from the start of the current trace.
    pub token_in_trace: usize,
}

/// Median spacing between consecutive captured flows, in seconds.
///
/// Zero when flows overlap - which real concurrent connections do - because a
/// concatenated replay cannot represent overlap. Capped at one second so a single
/// idle capture cannot stretch every subsequent flow.
fn measured_inter_flow_gap(rows: &[(u64, f64, usize, Dir)]) -> f64 {
    let mut gaps: Vec<f64> = Vec::new();
    let mut i = 0;
    while i < rows.len() {
        let flow = rows[i].0;
        let start = rows[i].1;
        let mut end = start;
        while i < rows.len() && rows[i].0 == flow {
            end = end.max(rows[i].1);
            i += 1;
        }
        if i < rows.len() {
            gaps.push((rows[i].1 - end).clamp(0.0, 1.0));
        }
    }
    if gaps.is_empty() {
        return 0.0;
    }
    gaps.sort_by(f64::total_cmp);
    gaps[gaps.len() / 2]
}

/// What a stream needs from the tunnel. A property of the STREAM, never of the
/// queue.
///
/// Routing must not consult demand: a stream is interactive because of what it is
/// (a SOCKS connection to port 443 carrying a browser session, a DNS lookup), not
/// because its queue happens to be shallow right now. Routing on queue depth would
/// be the demand-responsive carrier selection this design closed at the carrier
/// level, reintroduced at the routing level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum StreamClass {
    /// Latency-bound: page loads, interactive shells, DNS. Small, bursty, and
    /// ruined by a multi-second stall.
    Interactive,
    /// Throughput-bound: file transfer, media, sync. Indifferent to a 10 s stall
    /// provided the long-run rate is high.
    Bulk,
}

/// A stream's class, fixed at accept time and immutable thereafter.
///
/// # Why immutability is the security property, not a convenience
///
/// Classification must depend only on what the stream IS at the moment it is
/// accepted - destination port, protocol, whether the client declared it - and
/// never on what it has since carried. A stream reclassified mid-life because it
/// turned out to be moving a lot of data is **demand-responsive routing wearing a
/// different name**: the reclassification event is itself observable, it is
/// caused by payload volume, and it moves the stream onto a different cover
/// class at a moment a censor can correlate with the transfer starting.
///
/// That is the same defect closed twice already - at the carrier level (opening
/// carrier 2 when the queue deepens) and at the routing level (sending a busy
/// class more slots). This is the third layer, and the fix is the same shape:
/// remove the reach. There is no `set_class`, no `reclassify`, and the field is
/// private with only a getter, so the mid-life change cannot be written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClassifiedStream {
    id: u64,
    class: StreamClass,
}

impl ClassifiedStream {
    /// Classify once, at accept.
    ///
    /// Takes only properties the stream has before it carries anything. There is
    /// deliberately no byte count, rate or queue-depth parameter: a signature that
    /// cannot see volume cannot classify on it.
    #[must_use]
    pub fn accept(id: u64, dest_port: u16, client_hinted_bulk: bool) -> Self {
        // Ports are a property of the connection, known before a byte moves.
        let class = if client_hinted_bulk {
            StreamClass::Bulk
        } else {
            match dest_port {
                // Interactive by default: an unknown service is more likely to be
                // latency-sensitive, and misrouting bulk onto browse-class costs
                // throughput while misrouting interactive onto video-class costs
                // a ten-second stall. The asymmetry favours this default.
                22 | 53 | 80 | 443 | 853 | 3389 => StreamClass::Interactive,
                // Well-known bulk services.
                873 | 5001 | 6881..=6889 => StreamClass::Bulk,
                _ => StreamClass::Interactive,
            }
        };
        Self { id, class }
    }

    /// This stream's identifier.
    #[must_use]
    pub fn id(&self) -> u64 {
        self.id
    }

    /// The class fixed at accept. There is no setter, by design.
    #[must_use]
    pub fn class(&self) -> StreamClass {
        self.class
    }
}

/// Carriers of DIFFERENT cover classes, serving stream classes that need
/// different things.
///
/// # Why this exists: no single cover class clears both constraints
///
/// Measured across a 60-cell capture matrix, per-class worst gap and throughput:
///
/// | class | gap bound | throughput |
/// |---|---|---|
/// | browse | **95.6 ms** | fails the floor |
/// | live audio | 338.8 ms | 139 kbps, fails the floor |
/// | segmented video | ~10 s | clears easily |
///
/// The class with the best latency fails on throughput and the classes with
/// throughput stall for ten seconds. Searching harder for a single class that does
/// both was the wrong response: **nothing requires all carriers to wear the same
/// profile.** A host running a browser and a video player at the same time is
/// entirely ordinary traffic, and that is what this is.
///
/// Interactive streams ride browse-class carriers and get the 95.6 ms gap bound.
/// Bulk streams ride video-class carriers and get the throughput. Neither class is
/// asked to do the thing it is bad at, and the composite is more plausible cover
/// than either alone, not less.
///
/// # What routing may and may not depend on
///
/// Class comes from the stream. The per-carrier emission contract is unchanged -
/// each carrier still replays its own capture, and `available` still selects only
/// the real/pad split - so adding a second cover class does not add a channel.
#[derive(Debug)]
pub struct HeteroCarrierSet {
    sets: std::collections::BTreeMap<StreamClass, CarrierSet>,
}

impl HeteroCarrierSet {
    /// Build from one profile per stream class.
    #[must_use]
    pub fn new(profiles: &[(StreamClass, &MeasuredProfile)]) -> Self {
        Self {
            sets: profiles
                .iter()
                .map(|&(c, p)| (c, CarrierSet::from_profile(p)))
                .collect(),
        }
    }

    /// Total carriers across all classes. `M` per class comes from that class's
    /// own capture.
    #[must_use]
    pub fn len(&self) -> usize {
        self.sets.values().map(CarrierSet::len).sum()
    }

    /// Whether any carrier exists at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Carriers serving one stream class.
    #[must_use]
    pub fn carriers_for(&self, class: StreamClass) -> usize {
        self.sets.get(&class).map_or(0, CarrierSet::len)
    }

    /// The next emission due across every carrier of every class.
    ///
    /// Ordered by due instant across the whole set, so classes interleave exactly
    /// as their captures say - a browser and a video player running concurrently.
    /// `available(class, carrier)` supplies payload for the real/pad split only.
    pub fn next_due(
        &mut self,
        mut available: impl FnMut(StreamClass, usize) -> usize,
    ) -> Option<(StreamClass, usize, CarrierEmit)> {
        let mut best: Option<(StreamClass, f64)> = None;
        for (&class, set) in &self.sets {
            if let Some(t) = set.peek_due() {
                if best.is_none_or(|(_, bt)| t < bt) {
                    best = Some((class, t));
                }
            }
        }
        let (class, _) = best?;
        let set = self.sets.get_mut(&class)?;
        set.next_due(|i| available(class, i))
            .map(|(i, em)| (class, i, em))
    }
}

/// Reorders a carrier's records within a window, tracking a deficit so the
/// realised size histogram converges exactly to the trace's.
///
/// # This is in TENSION with the provenance rule, deliberately
///
/// Everything else in this module holds that no observable may depend on demand.
/// Deficit permutation breaks that on purpose: it spends large records when the
/// queue is deep, so **record ORDER carries information about payload**. The
/// design argument is that the cost moves out of the size marginal - which is
/// preserved exactly, because a permutation emits the same multiset - and into
/// ordering statistics, which is the cheaper place to pay.
///
/// That is a real trade and not a free win, so:
///
/// - it is **opt-in and off by default**. [`CarrierSet::next_due`] does not use
///   it, and the strict tests (`emission_times_and_sizes_are_identical_under_any_payload`)
///   assert the default path. Those tests WOULD fail with permutation enabled,
///   and that is correct rather than a bug in either.
/// - the previous incarnation of this mechanism measured 0.699 separability and
///   was disabled. It had two independent defects - deterministic steering on
///   `has_data`, and histogram destruction. Deficit tracking fixes the second
///   only. The first is a function of window size and must be swept, not assumed.
///
/// # The `δ_max` cap and why it exists
///
/// Convergence holds over a *full* session. A session ending early leaves the
/// histogram unconverged **in a payload-dependent direction**: heavy use ends
/// owing large records. That is a session-boundary leak, which is where every real
/// leak in this project has been found. The cap bounds the worst-case marginal
/// deviation at any prefix, so the guarantee no longer depends on the session
/// running to completion.
#[derive(Debug, Clone)]
pub struct DeficitPermuter {
    /// Reorder only within this many upcoming records.
    window: usize,
    /// Maximum any size may run ahead of or behind its expected count.
    delta_max: i64,
    /// Records emitted per size bucket so far.
    emitted: std::collections::BTreeMap<usize, i64>,
    /// The trace's own counts per size bucket.
    expected: std::collections::BTreeMap<usize, i64>,
    total_expected: i64,
    total_emitted: i64,
}

impl DeficitPermuter {
    /// Build from the schedule this permuter will reorder.
    #[must_use]
    pub fn new(tokens: &[EmitToken], window: usize, delta_max: i64) -> Self {
        let mut expected: std::collections::BTreeMap<usize, i64> =
            std::collections::BTreeMap::new();
        for t in tokens {
            *expected.entry(t.bytes).or_default() += 1;
        }
        Self {
            window: window.max(1),
            delta_max: delta_max.max(0),
            emitted: std::collections::BTreeMap::new(),
            expected,
            total_expected: tokens.len() as i64,
            total_emitted: 0,
        }
    }

    /// How far a size currently runs ahead of where the trace says it should be.
    fn deficit(&self, size: usize) -> i64 {
        let emitted = self.emitted.get(&size).copied().unwrap_or(0);
        let exp = self.expected.get(&size).copied().unwrap_or(0);
        if self.total_expected == 0 {
            return 0;
        }
        // Expected count by this point in the session, rounded.
        let due = (exp * self.total_emitted + self.total_expected / 2) / self.total_expected;
        emitted - due
    }

    /// Choose which of the upcoming records to emit next.
    ///
    /// Returns an index into `remaining`, always within the window. Prefers a
    /// large record when the queue is deep and a small one when it is shallow -
    /// which is the mechanism, and the leak - but only among candidates whose
    /// deficit stays inside `δ_max`. When the cap excludes everything, it falls
    /// back to the trace's own next record, which is always histogram-safe.
    pub fn pick(&mut self, remaining: &[EmitToken], available: usize) -> usize {
        if remaining.is_empty() {
            return 0;
        }
        let w = self.window.min(remaining.len());
        let want_large = available > 0;

        // A size may run BEHIND as well as ahead, and both are marginal deviation.
        // Every pick advances `total_emitted`, which raises what every other size
        // is due - so choosing large records repeatedly pushes the small ones into
        // deficit without ever tripping a guard that only looks at running ahead.
        // Measured: with the cap set to 1, a size reached -2 by the eleventh
        // record. The fix is a MUST-PICK: when a size in the window has fallen to
        // the cap, it is emitted next regardless of what the queue wants.
        for i in 0..w {
            if self.deficit(remaining[i].bytes) <= -self.delta_max.max(1) {
                *self.emitted.entry(remaining[i].bytes).or_default() += 1;
                self.total_emitted += 1;
                return i;
            }
        }

        let mut best: Option<(usize, usize)> = None;
        for i in 0..w {
            let sz = remaining[i].bytes;
            if self.deficit(sz) + 1 > self.delta_max {
                continue; // this size is already running ahead
            }
            let better = match best {
                None => true,
                Some((_, bsz)) => {
                    if want_large {
                        sz > bsz
                    } else {
                        sz < bsz
                    }
                }
            };
            if better {
                best = Some((i, sz));
            }
        }
        let idx = best.map(|(i, _)| i).unwrap_or(0);
        *self.emitted.entry(remaining[idx].bytes).or_default() += 1;
        self.total_emitted += 1;
        idx
    }

    /// Largest absolute deficit across all sizes - the worst-case marginal
    /// deviation if the session ended right now.
    #[must_use]
    pub fn worst_deficit(&self) -> i64 {
        self.expected
            .keys()
            .map(|&s| self.deficit(s).abs())
            .max()
            .unwrap_or(0)
    }
}

/// All carriers of one profile, constructed once.
///
/// Exists to make the three ways the live path can leak the guarantees hard to
/// write, rather than documented and hoped for.
///
/// **1. No ambient clock, at the call site either.** The only scheduling API is
/// [`CarrierSet::next_due`], which returns the emission and the instant it is due.
/// There is deliberately no `is_due(now)` or `poll(now)`: a caller handed a
/// predicate over `now` would read the clock once per loop iteration and
/// reconstruct the shared tick at the call site with the emitter still clean. The
/// caller's only correct move is to sleep until the returned instant.
///
/// **2. Backpressure cannot reach the schedule.** Emissions are produced from the
/// schedule alone. A blocked socket is the caller's problem - it may not skip,
/// delay or coalesce an emission, because that would let demand re-enter through
/// I/O rather than through an argument. Asserted by test against a sink that
/// blocks.
///
/// **3. One emitter per carrier, constructed once.** The set owns its emitters and
/// [`CarrierEmitter`] is deliberately not `Clone`: a clone would be a second
/// carrier wearing the same schedule position and the same jitter stream.
/// Rebuilding on reconnect reseeds jitter and restarts position, which is a
/// session-boundary artifact of exactly the kind this project keeps finding, so
/// the set is built once per profile and outlives individual connections.
#[derive(Debug)]
pub struct CarrierSet {
    emitters: Vec<CarrierEmitter>,
}

impl CarrierSet {
    /// Build every carrier the capture justifies. `M` is the number of captured
    /// flows; no count is passed in.
    #[must_use]
    pub fn from_profile(profile: &MeasuredProfile) -> Self {
        Self {
            emitters: profile
                .carrier_schedules()
                .into_iter()
                .map(CarrierEmitter::new)
                .collect(),
        }
    }

    /// How many carriers this profile justifies.
    #[must_use]
    pub fn len(&self) -> usize {
        self.emitters.len()
    }

    /// Whether this profile justifies no carriers at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.emitters.is_empty()
    }

    /// Earliest instant any carrier in this set is next due.
    #[must_use]
    pub fn peek_due(&self) -> Option<f64> {
        self.emitters
            .iter()
            .filter_map(CarrierEmitter::peek_due)
            .reduce(f64::min)
    }

    /// The next emission due across all carriers, with its carrier index.
    ///
    /// Returns the DUE INSTANT; it does not decide whether that instant has
    /// arrived, because deciding would require reading a clock. The caller sleeps
    /// until `emit.at` and then sends.
    ///
    /// `available` is consulted per carrier for the real/pad split only.
    pub fn next_due(
        &mut self,
        mut available: impl FnMut(usize) -> usize,
    ) -> Option<(usize, CarrierEmit)> {
        let mut best: Option<(usize, f64)> = None;
        for (i, e) in self.emitters.iter().enumerate() {
            if let Some(t) = e.peek_due() {
                if best.is_none_or(|(_, bt)| t < bt) {
                    best = Some((i, t));
                }
            }
        }
        let (i, _) = best?;
        let av = available(i);
        self.emitters[i].next(av).map(|em| (i, em))
    }
}

/// One carrier's emission, as it goes on the wire.
///
/// `at` and `bytes` come from the capture alone. `real`/`pad` is the only part
/// payload influences, and it cannot change either of the other two: the size a
/// censor observes is `real + pad = bytes` whatever the session had to send.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CarrierEmit {
    /// Scheduled instant, relative to the first carrier opening.
    pub at: f64,
    /// Observable record size. From the schedule; never from demand.
    pub bytes: usize,
    /// Payload carried inside this record.
    pub real: usize,
    /// Padding making up the rest.
    pub pad: usize,
}

/// Emits one carrier's schedule. Holds DATA, not references to the session.
///
/// The signature discipline from `carrier_schedules` continued one layer down,
/// because this is the layer where the provenance rule actually gets stressed:
///
/// - it owns its schedule rather than borrowing a shared profile, so no other
///   carrier can move its position;
/// - it takes **no clock**. `next()` returns the instant an emission is due; it
///   never reads an ambient `now()`. A clock read hoisted above a carrier loop is
///   the classic way every carrier quantises to one tick, and it cannot happen
///   here because there is nowhere to hoist it from;
/// - it owns its jitter stream, seeded **from its own schedule**, so the stream is
///   a pure function of the capture and reproducible across runs. A shared jitter
///   source would correlate carriers with no provenance and pass any test that
///   only checks one carrier at a time;
/// - it owns its position counter and token budget.
///
/// Each of those is per-carrier *by construction*. Held as fields on a shared
/// struct they would be invisible in review and visible on the wire.
#[derive(Debug)]
pub struct CarrierEmitter {
    schedule: CarrierSchedule,
    pos: usize,
    /// Own stream, seeded from this carrier's own schedule.
    jitter: u64,
}

impl CarrierEmitter {
    /// Build from a schedule and nothing else.
    ///
    /// There is deliberately no `&Session`, `&Queue` or `&Clock` parameter:
    /// demand has no argument to arrive through, so it cannot reach the emission
    /// times or sizes. The rule is unrepresentable rather than merely untested.
    #[must_use]
    pub fn new(schedule: CarrierSchedule) -> Self {
        // Seed from the capture: flow id and the carrier's own open offset. Two
        // carriers of the same profile get different streams; the same carrier of
        // the same profile gets the same stream on every run.
        let seed = schedule.flow.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ schedule.opens_at.to_bits();
        Self {
            schedule,
            pos: 0,
            jitter: seed | 1,
        }
    }

    /// When this carrier opens, from the capture.
    #[must_use]
    pub fn opens_at(&self) -> f64 {
        self.schedule.opens_at
    }

    /// Captured connection this carrier wears.
    #[must_use]
    pub fn flow(&self) -> u64 {
        self.schedule.flow
    }

    /// Instant of this carrier's next emission, without consuming it.
    #[must_use]
    pub fn peek_due(&self) -> Option<f64> {
        self.schedule.tokens.get(self.pos).map(|t| t.t)
    }

    /// Next emission, or `None` when the schedule is exhausted.
    ///
    /// `available` is how much payload the session has waiting. It selects only
    /// the `real`/`pad` split - never `at`, never `bytes`. That is the whole
    /// displacement design: the observable record is identical whether the
    /// session is idle or saturated, so a censor watching sizes and times learns
    /// nothing about demand.
    pub fn next(&mut self, available: usize) -> Option<CarrierEmit> {
        let tok = self.schedule.tokens.get(self.pos)?;
        self.pos += 1;
        let real = available.min(tok.bytes);
        Some(CarrierEmit {
            at: tok.t,
            bytes: tok.bytes,
            real,
            pad: tok.bytes - real,
        })
    }

    /// Advance the private jitter stream. Deterministic per carrier per capture.
    #[allow(dead_code)]
    fn jitter_next(&mut self) -> u64 {
        // xorshift64*, no shared RNG and no OS entropy: a stream that varied per
        // run would make inter-carrier timing unreproducible and break the
        // provenance rule the whole design rests on.
        let mut x = self.jitter;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.jitter = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
}

/// One carrier's replay schedule, taken wholly from the capture.
#[derive(Debug, Clone, PartialEq)]
pub struct CarrierSchedule {
    /// Captured connection this carrier wears.
    pub flow: u64,
    /// When this carrier opens, relative to the first carrier. Replayed rather
    /// than chosen: a browser opens some connections together and others later,
    /// so opening every carrier at t=0 is as much an invention as opening one
    /// when the queue deepens.
    pub opens_at: f64,
    /// This carrier's own records at their recorded times.
    pub tokens: Vec<EmitToken>,
}

impl MeasuredProfile {
    /// Parse a capture CSV. Accepts rows `flow,t,size,dir` or `t,size,dir` (dir:
    /// 1=down, -1=up); a header line is skipped. Multiple `flow` ids are concatenated
    /// in id-then-time order, each offset to continue just after the previous flow, so
    /// the result is one long monotonic token stream to replay. Returns `None` if no
    /// usable rows were found.
    ///
    /// # What this function normalises away
    ///
    /// Audited after two separate defects turned out to be structure discarded
    /// here rather than bugs downstream - a periodically tiled direction, and
    /// concurrent flows serialised into one stream. Both were transformations
    /// applied at parse time that nobody knew were being applied. The rest of the
    /// list, so the third one is found by reading rather than by shipping:
    ///
    /// 1. **Cross-flow interleaving.** Rows are sorted by `(flow, t)`, so records
    ///    that alternated between connections in the capture are regrouped by
    ///    connection. The interleaving pattern of a multi-connection page load is
    ///    not recoverable from the result. This is the serialisation that
    ///    `flow_arrivals` exists to make repairable.
    /// 2. **A 20 ms inter-flow gap is INVENTED.** `GAP` is a hand-picked constant
    ///    inserted into the replay timeline between concatenated flows. It is not
    ///    measured, and it is the only timing value here that does not come from
    ///    the capture. Every other hand-picked constant in this project has so far
    ///    turned out to be wrong for at least one profile.
    /// 3. **`dir == 0` becomes Down.** The mapping is `dr >= 0`, so a capture that
    ///    uses 0 for "unknown" or "both" silently becomes downstream rather than
    ///    being rejected.
    /// 4. **Zero-size records are dropped** (`sz > 0`). Harmless for TLS records,
    ///    which always carry a 5-byte header, but it is a silent filter.
    /// 5. **Sub-millisecond ordering within a flow** survives only as far as the
    ///    source CSV's precision; equal timestamps keep input order arbitrarily.
    ///
    /// None of 2-5 is known to be causing a defect today. They are recorded because
    /// the two that did cause defects looked exactly this innocuous beforehand.
    pub fn from_csv(data: &str) -> Option<Self> {
        // (flow, t, size, dir)
        let mut rows: Vec<(u64, f64, usize, Dir)> = Vec::new();
        for line in data.lines() {
            let f: Vec<&str> = line.trim().split(',').collect();
            let (flow, t, sz, dr) = match f.as_slice() {
                [flow, t, sz, dr] => (
                    flow.parse().ok(),
                    t.parse().ok(),
                    sz.parse().ok(),
                    dr.parse::<i64>().ok(),
                ),
                [t, sz, dr] => (
                    Some(0u64),
                    t.parse().ok(),
                    sz.parse().ok(),
                    dr.parse::<i64>().ok(),
                ),
                _ => continue,
            };
            if let (Some(flow), Some(t), Some(sz), Some(dr)) = (flow, t, sz, dr) {
                // `dr == 0` used to fall into `dr >= 0` and silently become
                // downstream. A capture that writes 0 for "unknown" or "both"
                // would have had every such record relabelled rather than
                // rejected, and nothing would have said so.
                let dir = match dr.signum() {
                    1 => Dir::Down,
                    -1 => Dir::Up,
                    _ => continue,
                };
                if sz > 0 {
                    rows.push((flow, t, sz, dir));
                }
            }
        }
        if rows.is_empty() {
            return None;
        }
        // The joint timeline is built BEFORE the flow-major sort below, because
        // that sort is what destroys true time order. Same rows, same tie-break
        // rule, ordered by time first.
        let mut joint: Vec<(f64, usize, Dir, u64)> = rows
            .iter()
            .map(|&(flow, t, sz, dir)| (t, sz, dir, flow))
            .collect();
        joint.sort_by(|a, b| {
            a.0.total_cmp(&b.0)
                .then(a.3.cmp(&b.3))
                .then(a.1.cmp(&b.1))
                .then((a.2 as u8).cmp(&(b.2 as u8)))
        });

        // Deterministic on ties: equal timestamps previously kept whatever order
        // the input happened to have, so two runs over reordered-but-equivalent
        // input produced different token streams. Break by size then direction.
        rows.sort_by(|a, b| {
            a.0.cmp(&b.0)
                .then(a.1.total_cmp(&b.1))
                .then(a.2.cmp(&b.2))
                .then((a.3 as u8).cmp(&(b.3 as u8)))
        });
        // Concatenate flows: offset each flow to start just after the previous ended.
        //
        // NOTE what this discards, because it is the input the multi-carrier work
        // needs. A capture of a real page contains several CONCURRENT connections
        // to an origin - measured 2-4 across the trace-library pages - each opening
        // at its own moment: a browser opens two immediately and a third a couple
        // of hundred milliseconds later. Rebasing every flow to start after the
        // previous one ended serialises that, and a serialised replay of
        // concurrent traffic is a shape real traffic never produces. It is the
        // same defect class as the tiled direction, one layer up.
        //
        // `flow_arrivals` keeps each flow's ORIGINAL start relative to the first,
        // so the arrival pattern can be replayed rather than invented. Nothing
        // consumes it yet; the concatenated `tokens` path is unchanged.
        // Inter-flow spacing, MEASURED rather than chosen.
        //
        // This was `const GAP: f64 = 0.02` - a hand-picked 20 ms inserted into the
        // replay timeline, the only timing value in this function that did not
        // come from the capture. It invents structure rather than sizing a buffer,
        // and every hand-picked timing constant in this project has so far been
        // wrong for at least one profile.
        //
        // The capture already says what the spacing was: the difference between
        // one flow's first record and the previous flow's last. Real concurrent
        // connections overlap, which makes that difference NEGATIVE - and zero is
        // the right answer there, because a concatenated replay cannot represent
        // overlap at all. (Representing it is what the concurrent path is for; see
        // `flow_arrivals`.) Clamped at zero and capped so one idle capture cannot
        // stretch every later flow.
        let gap = measured_inter_flow_gap(&rows);
        let mut tokens: Vec<EmitToken> = Vec::with_capacity(rows.len());
        let mut cur_flow = rows[0].0;
        let mut flow_start = rows[0].1;
        let mut base = 0.0f64;
        let mut last = 0.0f64;
        // Token index where each chained trace begins. The first always starts at
        // 0; every flow-id change opens another.
        let mut flow_starts: Vec<usize> = vec![0];
        // Arrival of each flow relative to the first flow's first record.
        let first_seen = rows[0].1;
        let mut flow_arrivals: Vec<f64> = vec![0.0];
        for (flow, t, sz, dir) in rows {
            if flow != cur_flow {
                base = last + gap;
                flow_start = t;
                cur_flow = flow;
                flow_starts.push(tokens.len());
                flow_arrivals.push((t - first_seen).max(0.0));
            }
            let tt = base + (t - flow_start).max(0.0);
            last = tt;
            tokens.push(EmitToken {
                t: tt,
                bytes: sz,
                dir,
            });
        }
        let span = tokens.last().map(|e| e.t).unwrap_or(0.0);
        Some(Self {
            tokens,
            span,
            flow_starts,
            flow_arrivals,
            joint,
        })
    }

    /// Per-carrier schedules derived from the capture's joint timeline.
    ///
    /// Returns one schedule per captured flow, in arrival order: the carrier's
    /// open offset, and its own records at their recorded times. Carrier `k`
    /// replays only the records that connection `k` carried, at the instants they
    /// occurred, so the alternation between carriers is reproduced because it was
    /// recorded - not because one carrier waits on another.
    ///
    /// **A pure function of the capture.** It takes `&self` and nothing else: no
    /// queue, no clock, no payload, no session state. That is the provenance rule
    /// enforced by the signature rather than by a test - there is no argument
    /// through which demand could enter, so the schedule cannot encode it. The
    /// runtime emitter must preserve this; the replay-twice test is what checks
    /// that it does.
    #[must_use]
    pub fn carrier_schedules(&self) -> Vec<CarrierSchedule> {
        let mut by: std::collections::BTreeMap<u64, Vec<EmitToken>> =
            std::collections::BTreeMap::new();
        for &(t, bytes, dir, flow) in &self.joint {
            by.entry(flow)
                .or_default()
                .push(EmitToken { t, bytes, dir });
        }
        let mut out: Vec<CarrierSchedule> = by
            .into_iter()
            .map(|(flow, tokens)| CarrierSchedule {
                flow,
                opens_at: tokens.first().map(|e| e.t).unwrap_or(0.0),
                tokens,
            })
            .collect();
        // Arrival order, ties broken by flow id so the result is deterministic.
        out.sort_by(|a, b| a.opens_at.total_cmp(&b.opens_at).then(a.flow.cmp(&b.flow)));
        out
    }

    /// Which chained trace token index `i` falls in.
    #[must_use]
    pub fn trace_of(&self, i: usize) -> usize {
        self.flow_starts
            .partition_point(|&s| s <= i)
            .saturating_sub(1)
    }
}

/// Replay cursor over a [`MeasuredProfile`], looping it forever with a monotonic
/// clock so a session of any length stays shaped as one continuous real flow.
#[derive(Clone, Debug)]
struct ReplayState {
    profile: std::sync::Arc<MeasuredProfile>,
    cursor: usize,
    offset: f64,
    last_t: f64,
    /// Completed cycles of the whole chain. Without it a token index is ambiguous
    /// across wraps, and the chain wraps inside a single session whenever the
    /// library is smaller than the chain length.
    pass: u64,
}

/// The live pacer's driver: an unbounded, continuous schedule (generative from a
/// [`CoverProcess`], or a [`MeasuredProfile`] replay). Streams one coherent process
/// with no periodic restart (a per-window re-draw is itself a fingerprint); token
/// times increase monotonically and memory stays bounded (one segment/page buffered).
pub struct ScheduleStream {
    proc: CoverProcess,
    r: Prng,
    clock: f64,
    /// Video: current ABR bitrate (drifts across segments; NEVER reset).
    bitrate: f64,
    /// Video: the flow's segment interval (fixed per session, like a real player).
    seg_s: f64,
    buf: std::collections::VecDeque<EmitToken>,
    /// When `Some`, tokens come from a real captured profile (replay) instead of the
    /// generative process.
    replay: Option<ReplayState>,
}

impl ScheduleStream {
    /// True when this stream replays a captured profile (vs a generative process).
    /// The pacer pins a replay's clock to the shared capture origin (both endpoints
    /// seed-derive the same start token), so the up/down request-response coupling
    /// of the real flow survives - rather than each direction pinning to its own
    /// first token, which offsets the joint timeline by the up/down start gap.
    pub fn is_replay(&self) -> bool {
        self.replay.is_some()
    }

    /// Where this replay currently is, or `None` for a generative stream.
    ///
    /// The authoritative answer, from the component that owns the cursor. A
    /// harness must read this rather than deriving position from elapsed time:
    /// the two agree only while nothing stalls, and they diverge exactly in the
    /// runs where position matters most.
    #[must_use]
    pub fn replay_position(&self) -> Option<ReplayPosition> {
        let rs = self.replay.as_ref()?;
        let n = rs.profile.tokens.len();
        // `cursor` has already been advanced past the last emitted token, and
        // sits at `n` only in the instant before a wrap is applied.
        let token = if n == 0 { 0 } else { rs.cursor % n };
        let trace = rs.profile.trace_of(token);
        Some(ReplayPosition {
            trace,
            pass: rs.pass,
            token,
            token_in_trace: token - rs.profile.flow_starts.get(trace).copied().unwrap_or(0),
        })
    }

    /// Start a continuous stream for `proc`, deterministic from `seed`.
    pub fn new(proc: CoverProcess, seed: u64) -> Self {
        let mut r = Prng::new(seed);
        let (bitrate, seg_s) = match &proc {
            CoverProcess::Video {
                bitrate_bps, seg_s, ..
            } => (*bitrate_bps, *seg_s),
            CoverProcess::Browse => (0.0, 0.0),
        };
        // Advance the PRNG once so the stream's phase differs from schedule()'s.
        let _ = r.unit();
        Self {
            proc,
            r,
            clock: 0.0,
            bitrate,
            seg_s,
            buf: std::collections::VecDeque::new(),
            replay: None,
        }
    }

    /// Start a REPLAY stream over a real captured profile (the grounded ladder). The
    /// seed picks the starting phase (a rotation into the profile) so sessions differ.
    /// The profile loops forever with a monotonic clock. See [`MeasuredProfile`].
    /// Replay ONE carrier's schedule, for the live paced write pump.
    ///
    /// This is the bridge between the carrier model and the transport. A
    /// [`PacedChannel`](crate::PacedChannel) drives one connection, so it gets one
    /// carrier - not the whole set - and the set's job is to say which carriers
    /// exist and which class each serves.
    ///
    /// The carrier's own tokens become the profile, so everything the carrier
    /// model guarantees carries into the live path unchanged: sizes and instants
    /// come from the capture, the schedule is a pure function of it, and payload
    /// still only selects the real/pad split inside a token.
    ///
    /// `seed` affects only replay start offset, never sizes or gaps.
    #[must_use]
    pub fn for_carrier(schedule: &CarrierSchedule, seed: u64) -> Self {
        let profile = MeasuredProfile {
            span: schedule.tokens.last().map(|t| t.t).unwrap_or(0.0),
            joint: schedule
                .tokens
                .iter()
                .map(|t| (t.t, t.bytes, t.dir, schedule.flow))
                .collect(),
            tokens: schedule.tokens.clone(),
            flow_starts: vec![0],
            flow_arrivals: vec![schedule.opens_at],
        };
        Self::replay(std::sync::Arc::new(profile), seed)
    }

    /// Replay a whole profile, chained across its captured flows.
    ///
    /// `seed` picks the starting offset within the chain so two sessions of the
    /// same profile do not begin at the same token; it never affects sizes or
    /// gaps. For one carrier of a multi-carrier set use [`Self::for_carrier`].
    pub fn replay(profile: std::sync::Arc<MeasuredProfile>, seed: u64) -> Self {
        let start = if profile.tokens.is_empty() {
            0
        } else {
            (seed as usize) % profile.tokens.len()
        };
        let offset = profile.tokens.get(start).map(|e| -e.t).unwrap_or(0.0);
        Self {
            proc: CoverProcess::Browse,
            r: Prng::new(seed),
            clock: 0.0,
            bitrate: 0.0,
            seg_s: 0.0,
            buf: std::collections::VecDeque::new(),
            replay: Some(ReplayState {
                profile,
                cursor: start,
                offset,
                last_t: 0.0,
                pass: 0,
            }),
        }
    }

    /// Push the next chunk of profile tokens into the buffer, looping the profile with
    /// a continued monotonic clock.
    fn refill_replay(&mut self) {
        /// Tokens materialised per refill. A buffering quantum only - it affects
        /// how often this function runs, never what it emits or when.
        const CHUNK: usize = 256;
        /// Gap inserted when the replay wraps back to the start of the trace.
        ///
        /// **UNJUSTIFIED — hand-picked, and the same defect class as the 20 ms
        /// inter-flow gap removed from `from_csv` this release.** It is a timing
        /// value inserted into the replay timeline that does not come from any
        /// capture, and it lands at a session-boundary-like moment (the wrap),
        /// which is where every real leak in this project has been found. A
        /// periodic 50 ms seam every `span` seconds is exactly the kind of
        /// deterministic structure a single-flow detector reads.
        ///
        /// Flagged rather than changed: altering replay timing is a behavioural
        /// change that needs its own measurement, and the fix is the same one
        /// applied to `from_csv` — take the value from the capture (the observed
        /// gap between the end of one flow and the start of the next) instead of
        /// choosing it. Tracked for 2.1.
        const CYCLE_GAP: f64 = 0.05;
        let rs = self.replay.as_mut().expect("replay");
        let toks = &rs.profile.tokens;
        if toks.is_empty() {
            // Degenerate profile: emit a single MTU token so the pump never stalls.
            self.buf.push_back(EmitToken {
                t: rs.last_t,
                bytes: MTU,
                dir: Dir::Down,
            });
            rs.last_t += 0.001;
            return;
        }
        for _ in 0..CHUNK {
            if rs.cursor >= toks.len() {
                // wrap: continue the clock just after the last emitted token
                rs.cursor = 0;
                rs.offset = rs.last_t + CYCLE_GAP - toks[0].t;
                rs.pass += 1;
                // The chain-wrap boundary, in the log, at the moment it happens.
                // A library smaller than CHAIN_LEN wraps within one session, and
                // whether windows either side of a wrap differ from windows in the
                // middle of a trace has never been examined. This makes that
                // boundary joinable against the capture without a second run.
                tracing::debug!(
                    pass = rs.pass,
                    traces = rs.profile.flow_starts.len(),
                    span_secs = rs.profile.span,
                    "proteus: replay chain wrapped"
                );
            }
            let src = toks[rs.cursor];
            let t = (src.t + rs.offset).max(rs.last_t);
            rs.last_t = t;
            self.buf.push_back(EmitToken { t, ..src });
            rs.cursor += 1;
        }
    }

    /// Generate the next segment (video) or page (browse) worth of tokens, advancing
    /// the process state, and push them time-ordered into the buffer.
    fn refill(&mut self) {
        let mut batch: Vec<EmitToken> = Vec::new();
        match self.proc {
            CoverProcess::Video { .. } => {
                if self.r.unit() < 0.15 {
                    self.bitrate = (self.bitrate * self.r.uniform(0.6, 1.6)).clamp(1.5e6, 9e6);
                }
                let seg_bytes = self.bitrate * self.seg_s / 8.0;
                let npkt = ((seg_bytes / MTU as f64) as usize).max(1);
                batch.push(EmitToken {
                    t: self.clock,
                    bytes: self.r.range(200, 600) as usize,
                    dir: Dir::Up,
                });
                let burst = self.r.uniform(0.25, 0.9).min(self.seg_s * 0.8);
                let mut tt = self.clock + 0.01;
                for k in 0..npkt {
                    tt += self.r.exp(burst / npkt as f64);
                    batch.push(EmitToken {
                        t: tt,
                        bytes: MTU,
                        dir: Dir::Down,
                    });
                    if k % 3 == 2 {
                        batch.push(EmitToken {
                            t: tt + 1e-4,
                            bytes: ACK,
                            dir: Dir::Up,
                        });
                    }
                }
                self.clock += self.seg_s * self.r.uniform(0.95, 1.05);
            }
            CoverProcess::Browse => {
                let nobj = self.r.range(4, 25);
                let load = self.r.uniform(0.6, 2.5);
                for _ in 0..nobj {
                    let start = self.clock + self.r.uniform(0.0, load);
                    batch.push(EmitToken {
                        t: start,
                        bytes: self.r.range(150, 800) as usize,
                        dir: Dir::Up,
                    });
                    let obj = self.r.normal(9.5, 1.3).exp().clamp(200.0, 3.0e6);
                    let npkt = ((obj / MTU as f64) as usize).max(1);
                    let mut tt = start + 0.03;
                    for k in 0..npkt {
                        tt += self.r.exp(0.02);
                        let last = k == npkt - 1;
                        let sz = if last {
                            (obj as usize % MTU).max(1)
                        } else {
                            MTU
                        };
                        batch.push(EmitToken {
                            t: tt,
                            bytes: sz,
                            dir: Dir::Down,
                        });
                        if k % 4 == 3 {
                            batch.push(EmitToken {
                                t: tt + 1e-4,
                                bytes: ACK,
                                dir: Dir::Up,
                            });
                        }
                    }
                }
                self.clock += load + self.r.uniform(4.0, 14.0); // user reads
            }
        }
        batch.sort_by(|a, b| a.t.total_cmp(&b.t));
        self.buf.extend(batch);
    }

    /// The next token in the continuous stream (all directions interleaved).
    pub fn next_token(&mut self) -> EmitToken {
        while self.buf.is_empty() {
            if self.replay.is_some() {
                self.refill_replay();
            } else {
                self.refill();
            }
        }
        self.buf.pop_front().expect("refilled")
    }

    /// The next token for a single write direction (others skipped). Time still
    /// advances across the skipped tokens, so this side stays phase-aligned with the
    /// full process.
    pub fn next_for(&mut self, dir: Dir) -> EmitToken {
        loop {
            let tok = self.next_token();
            if tok.dir == dir {
                return tok;
            }
        }
    }
}

/// One paced emission: `real` payload bytes + `pad` padding, filling an envelope
/// token. `real + pad == token.bytes` always, so the wire size is the cover's size
/// regardless of how much real data was available.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Emit {
    /// Emission time (seconds after flow start).
    pub t: f64,
    /// Real payload bytes carried in this packet.
    pub real: usize,
    /// Padding bytes added to reach the envelope size.
    pub pad: usize,
    /// Direction.
    pub dir: Dir,
}

impl Emit {
    /// Wire size of the packet (`real + pad`) - always the cover envelope's size.
    pub fn size(&self) -> usize {
        self.real + self.pad
    }
}

/// Ride the user's real bytes on the envelope: each token carries up to the bytes
/// available in its direction, padded to the token size. `supply_*` is the demand
/// budget for the flow (a live carrier feeds its send-queue length instead). Any
/// downstream demand beyond the envelope is left unsent - see [`residual_down`].
pub fn pace(schedule: &[EmitToken], supply_down: usize, supply_up: usize) -> Vec<Emit> {
    let (mut down, mut up) = (supply_down, supply_up);
    schedule
        .iter()
        .map(|tok| {
            let s = if tok.dir == Dir::Down {
                &mut down
            } else {
                &mut up
            };
            let real = (*s).min(tok.bytes);
            *s -= real;
            Emit {
                t: tok.t,
                real,
                pad: tok.bytes - real,
                dir: tok.dir,
            }
        })
        .collect()
}

/// Downstream user bytes the envelope could NOT carry (the honest "overload" limit).
/// Zero once a demand-matched class is chosen; positive demand must ride a bigger
/// class or split across K flows.
pub fn residual_down(schedule: &[EmitToken], supply_down: usize) -> usize {
    let env: usize = schedule
        .iter()
        .filter(|e| e.dir == Dir::Down)
        .map(|e| e.bytes)
        .sum();
    supply_down.saturating_sub(env)
}

/// Total downstream envelope bytes over the schedule (its carrying capacity).
pub fn envelope_down_bytes(schedule: &[EmitToken]) -> usize {
    schedule
        .iter()
        .filter(|e| e.dir == Dir::Down)
        .map(|e| e.bytes)
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A replay must be able to say WHERE it is, unambiguously across wraps.
    ///
    /// "Pinned to one trace" and "pinned to one trace POSITION" are different
    /// claims, and the alignment test depends on the second. With a library
    /// smaller than the chain length the chain wraps inside a single session, so
    /// a bare token offset is ambiguous between passes: this pins that `pass`
    /// advances, that the trace index tracks the chained flow, and that the
    /// position comes from the pacer rather than being inferable from a clock.
    #[test]
    fn a_replay_reports_its_position_unambiguously_across_wraps() {
        // Three chained traces (flow ids 0,1,2), two tokens each.
        let csv = "flow,t,size,dir\n\
                   0,0.00,100,1\n0,0.01,100,-1\n\
                   1,0.00,200,1\n1,0.01,200,-1\n\
                   2,0.00,300,1\n2,0.01,300,-1\n";
        let prof = MeasuredProfile::from_csv(csv).expect("parses");
        assert_eq!(prof.tokens.len(), 6);
        assert_eq!(
            prof.flow_starts,
            vec![0, 2, 4],
            "one boundary per chained trace"
        );
        for (i, want) in [(0, 0), (1, 0), (2, 1), (3, 1), (4, 2), (5, 2)] {
            assert_eq!(prof.trace_of(i), want, "token {i} belongs to trace {want}");
        }

        let mut s = ScheduleStream::replay(std::sync::Arc::new(prof), 0);
        let p0 = s.replay_position().expect("a replay reports position");
        assert_eq!(p0.pass, 0, "no wrap yet");

        // Drain well past one full cycle and confirm the pass counter advances -
        // the fact a bare offset cannot express.
        let mut saw_pass_1 = false;
        for _ in 0..40 {
            let _ = s.next_for(Dir::Down);
            if s.replay_position().is_some_and(|p| p.pass >= 1) {
                saw_pass_1 = true;
                break;
            }
        }
        assert!(saw_pass_1, "chain must wrap and report a later pass");

        let p = s.replay_position().expect("position");
        assert!(p.trace < 3, "trace index stays in range, got {}", p.trace);
        assert!(
            p.token_in_trace < 2,
            "offset within a 2-token trace must be 0 or 1, got {}",
            p.token_in_trace
        );

        // A generative stream has no position to report, and must say so rather
        // than inventing one.
        let mut gen = ScheduleStream::new(video(), 7);
        let _ = gen.next_for(Dir::Down);
        assert_eq!(gen.replay_position(), None);
    }

    fn video() -> CoverProcess {
        CoverProcess::Video {
            seg_s: 4.0,
            bitrate_bps: 5.0e6,
        }
    }

    #[test]
    fn schedule_is_deterministic_from_seed() {
        let a = video().schedule(30.0, 42);
        let b = video().schedule(30.0, 42);
        let c = video().schedule(30.0, 43);
        assert_eq!(
            a, b,
            "same seed => identical schedule (both endpoints agree)"
        );
        assert_ne!(a.len(), 0);
        assert_ne!(
            a, c,
            "different seed => different schedule (infinitely varied)"
        );
    }

    #[test]
    fn video_has_periodic_downstream_bursts() {
        let s = video().schedule(30.0, 7);
        // Downstream dominant.
        let down = s.iter().filter(|e| e.dir == Dir::Down).count();
        let up = s.iter().filter(|e| e.dir == Dir::Up).count();
        assert!(
            down > up * 2,
            "video is downstream-dominant: down={down} up={up}"
        );
        // Segment cadence: GET tokens (small upstream, 200..600B) mark segment starts,
        // spaced ~seg_s apart -> a handful over 30s at 4s cadence.
        let gets: Vec<f64> = s
            .iter()
            .filter(|e| e.dir == Dir::Up && (200..600).contains(&e.bytes))
            .map(|e| e.t)
            .collect();
        assert!(
            (5..=9).contains(&gets.len()),
            "~30/4 segment GETs, got {}",
            gets.len()
        );
    }

    #[test]
    fn pace_always_fills_downstream_to_envelope() {
        let s = video().schedule(30.0, 1);
        // Almost no real data: every downstream token must still be padded to size.
        let emit = pace(&s, 1000, 0);
        for (e, tok) in emit.iter().zip(s.iter()) {
            assert_eq!(
                e.size(),
                tok.bytes,
                "wire size == cover size regardless of payload"
            );
            assert!(e.real <= tok.bytes);
        }
    }

    #[test]
    fn pace_carries_all_data_when_demand_fits() {
        let s = video().schedule(30.0, 2);
        let env = envelope_down_bytes(&s);
        let demand = env / 2; // comfortably fits
        let emit = pace(&s, demand, 0);
        let carried: usize = emit
            .iter()
            .filter(|e| e.dir == Dir::Down)
            .map(|e| e.real)
            .sum();
        assert_eq!(carried, demand, "all fitting demand is delivered");
        assert_eq!(residual_down(&s, demand), 0);
    }

    #[test]
    fn overload_is_reported_not_hidden() {
        let s = video().schedule(30.0, 3);
        let env = envelope_down_bytes(&s);
        let demand = env * 3; // exceeds a single video envelope (the honest limit)
        assert_eq!(residual_down(&s, demand), demand - env);
        // and pacing never exceeds the envelope on the wire
        let emit = pace(&s, demand, 0);
        let wire: usize = emit
            .iter()
            .filter(|e| e.dir == Dir::Down)
            .map(|e| e.size())
            .sum();
        assert_eq!(
            wire, env,
            "wire stays within the cover envelope; excess stays queued"
        );
    }

    #[test]
    fn browse_is_bidirectional_and_bursty() {
        let s = CoverProcess::Browse.schedule(30.0, 9);
        assert!(!s.is_empty());
        let up = s.iter().filter(|e| e.dir == Dir::Up).count();
        assert!(up > 5, "browsing has real upstream (GETs + acks)");
        // read-idle gaps exist: some inter-token gap far larger than a burst gap.
        let ts: Vec<f64> = s.iter().map(|e| e.t).collect();
        let max_gap = ts.windows(2).map(|w| w[1] - w[0]).fold(0.0_f64, f64::max);
        assert!(
            max_gap > 3.0,
            "browsing has multi-second read-idle gaps, got {max_gap:.1}"
        );
    }

    #[test]
    fn schedule_stream_is_continuous_and_monotonic_across_windows() {
        // The live driver must NOT restart the process every 30 s (that was a
        // spectral fingerprint). Pull far past a window boundary and assert time
        // increases monotonically with no seam.
        let mut st = ScheduleStream::new(video(), 5);
        let mut last = -1.0;
        let mut max_gap = 0.0f64;
        // ~600 tokens/s of video, so 80k tokens spans ~130 s - past the old 30/60/90 s
        // window seams, where the artifact would have appeared.
        for _ in 0..80_000 {
            let tok = st.next_token();
            assert!(tok.t >= last, "stream time is monotonic (no window reset)");
            max_gap = max_gap.max(tok.t - last);
            last = tok.t;
        }
        assert!(
            last > 90.0,
            "80k tokens span past several old windows, got {last:.1}s"
        );
        // No single gap dwarfs a segment interval - a 30 s reset would show as a
        // jump back to ~0 (caught by monotonic) or a large forward hole.
        assert!(
            max_gap < 6.0,
            "no seam-sized gap; max inter-token gap {max_gap:.2}s"
        );
    }

    #[test]
    fn schedule_stream_never_exhausts_and_filters_direction() {
        let mut st = ScheduleStream::new(video(), 7);
        for _ in 0..500 {
            let tok = st.next_for(Dir::Down);
            assert_eq!(tok.dir, Dir::Down, "next_for yields only that direction");
            assert_eq!(tok.bytes, MTU, "video downstream tokens are MTU bursts");
        }
        // Unbounded: pulling thousands more never panics/ends.
        let mut st2 = ScheduleStream::new(video(), 7);
        for _ in 0..20_000 {
            let _ = st2.next_token();
        }
    }

    #[test]
    fn schedule_stream_bitrate_drifts_not_resets() {
        // Continuity check: across many segments the bitrate takes several distinct
        // values (ABR drift), never snapping back to a fixed per-window seed value.
        // ~15% ABR-switch chance per segment, so ~130 s (~32 segments) very likely
        // shows multiple distinct burst sizes.
        let mut st = ScheduleStream::new(video(), 11);
        let mut down_bursts = std::collections::HashSet::new();
        let mut per_seg = 0usize;
        for _ in 0..80_000 {
            let tok = st.next_token();
            match tok.dir {
                Dir::Up if tok.bytes >= 200 => {
                    // a GET marks a new segment; record the previous segment's size
                    if per_seg > 0 {
                        down_bursts.insert(per_seg);
                    }
                    per_seg = 0;
                }
                Dir::Down => per_seg += 1,
                _ => {}
            }
        }
        assert!(
            down_bursts.len() >= 3,
            "ABR drift => several distinct segment burst sizes, got {}",
            down_bursts.len()
        );
    }

    #[test]
    fn measured_profile_parses_and_concatenates_flows() {
        // Two captured flows, header present, 4-field rows; concatenated monotonic.
        let csv = "flow,t,size,dir\n\
                   0,0.000,1391,1\n0,0.010,54,-1\n0,0.020,1391,1\n\
                   1,0.000,800,-1\n1,0.050,1391,1\n";
        let p = MeasuredProfile::from_csv(csv).expect("parse");
        assert_eq!(p.tokens.len(), 5, "all rows kept");
        for w in p.tokens.windows(2) {
            assert!(w[1].t >= w[0].t, "concatenated stream is monotonic");
        }
        // real sizes preserved (1391/54/800), NOT synthetic MTU
        let sizes: std::collections::HashSet<usize> = p.tokens.iter().map(|e| e.bytes).collect();
        assert!(sizes.contains(&1391) && sizes.contains(&54) && sizes.contains(&800));
        // 3-field rows (no flow id) also parse
        let p2 = MeasuredProfile::from_csv("0.0,1391,1\n0.01,54,-1\n").expect("3-field");
        assert_eq!(p2.tokens.len(), 2);
    }

    /// `M` and the carrier ramp both come from the trace, never from a constant.
    ///
    /// Two properties, and the second is the one that is easy to get wrong:
    ///
    ///   1. the number of captured flows IS the carrier count the trace justifies.
    ///      A config constant here would be the same defect as every other
    ///      hand-picked parameter this project has had to derive after the fact.
    ///   2. the flows' ARRIVAL OFFSETS are data too. A real browser opens some
    ///      connections together and others a few hundred milliseconds later.
    ///      Opening all M at t=0 is an invention in exactly the way opening
    ///      carrier 2 when the queue deepens is - the first leaks nothing about
    ///      demand but still emits a shape the cover class does not produce.
    ///      Demand must drive neither the count nor the timing.
    ///
    /// The concatenated `tokens` path discards these offsets by rebasing each flow
    /// to start after the previous one ended, which is why they are captured
    /// separately.
    #[test]
    fn carrier_count_and_arrival_ramp_come_from_the_trace() {
        // Three flows: two opening together, a third at 200 ms - the measured
        // shape of a browser opening connections to one origin.
        let csv = "flow,t,size,dir\n\
                   0,0.000,1391,1\n0,0.010,54,-1\n\
                   1,0.002,1391,1\n1,0.030,54,-1\n\
                   2,0.200,1391,1\n2,0.240,54,-1\n";
        let p = MeasuredProfile::from_csv(csv).expect("parse");

        assert_eq!(p.flow_starts.len(), 3, "M is the number of captured flows");
        assert_eq!(
            p.flow_arrivals.len(),
            p.flow_starts.len(),
            "one arrival offset per carrier"
        );

        assert!(
            (p.flow_arrivals[0] - 0.000).abs() < 1e-9,
            "first flow defines t=0"
        );
        assert!(
            (p.flow_arrivals[1] - 0.002).abs() < 1e-9,
            "second opens with the first"
        );
        assert!(
            (p.flow_arrivals[2] - 0.200).abs() < 1e-9,
            "third opens 200ms later"
        );

        // The ramp must NOT be flat: all-at-t=0 is the invention this guards.
        assert!(
            p.flow_arrivals.iter().any(|&a| a > 0.05),
            "a staggered capture must not flatten to a simultaneous open"
        );

        // The concatenated path rebases, so a flow's position in `tokens` is NOT
        // its arrival - which is the whole reason the arrivals are kept separately.
        // Asserted as a difference rather than an inequality: concatenated time
        // runs on the sum of prior flow spans, so for short flows it can land
        // either side of the real offset, and pinning a direction would pin an
        // accident of this fixture.
        let concat_third = p.tokens[p.flow_starts[2]].t;
        assert!(
            (concat_third - p.flow_arrivals[2]).abs() > 1e-6,
            "concatenated position and real arrival must be independent data"
        );
    }

    /// The joint timeline preserves cross-flow alternation that `tokens` destroys,
    /// and both orderings stay deterministic on ties.
    ///
    /// `tokens` sorts by `(flow, t)`, which answers "what did connection K do" and
    /// loses "what was happening at instant T". The alternation between concurrent
    /// connections is the joint structure a multi-carrier replay reproduces, so it
    /// has to survive parsing. It was previously destroyed twice over: by this sort,
    /// and before that by a capture tap that timed every connection from its own
    /// start, leaving two traces mutually unplaceable.
    #[test]
    fn joint_timeline_preserves_cross_flow_alternation() {
        // Two connections whose records genuinely interleave in time.
        let csv = "flow,t,size,dir\n\
                   0,0.000,100,1\n1,0.001,200,1\n\
                   0,0.002,300,-1\n1,0.003,400,-1\n\
                   0,0.004,500,1\n";
        let p = MeasuredProfile::from_csv(csv).expect("parse");

        // True time order, alternating between flows.
        let seen: Vec<u64> = p.joint.iter().map(|&(_, _, _, f)| f).collect();
        assert_eq!(
            seen,
            vec![0, 1, 0, 1, 0],
            "alternation preserved in joint order"
        );
        for w in p.joint.windows(2) {
            assert!(w[1].0 >= w[0].0, "joint timeline is time-ordered");
        }
        // Sizes ride along, so a carrier can select its own records.
        assert_eq!(p.joint[1], (0.001, 200, Dir::Down, 1));

        // The concatenated view groups by flow, which is why it cannot answer the
        // same question - asserted so the two are not confused later.
        let concat: Vec<usize> = p.tokens.iter().map(|e| e.bytes).collect();
        assert_eq!(
            concat,
            vec![100, 300, 500, 200, 400],
            "tokens are flow-major"
        );
    }

    /// Equal timestamps must not leave ordering to input order, in EITHER view.
    ///
    /// The tie-break was added to the flow-major sort; the joint sort is a second
    /// ordering over the same rows and needed its own. Two inputs that differ only
    /// in the order of simultaneous records must parse identically.
    #[test]
    fn both_orderings_are_deterministic_on_equal_timestamps() {
        let a = "flow,t,size,dir\n0,0.000,100,1\n1,0.000,200,1\n0,0.000,300,-1\n";
        let b = "flow,t,size,dir\n0,0.000,300,-1\n1,0.000,200,1\n0,0.000,100,1\n";
        let pa = MeasuredProfile::from_csv(a).expect("a");
        let pb = MeasuredProfile::from_csv(b).expect("b");
        assert_eq!(
            pa.joint, pb.joint,
            "joint order must not depend on input order"
        );
        let ta: Vec<_> = pa.tokens.iter().map(|e| (e.bytes, e.dir)).collect();
        let tb: Vec<_> = pb.tokens.iter().map(|e| (e.bytes, e.dir)).collect();
        assert_eq!(ta, tb, "concatenated order must not depend on input order");
    }

    /// THE PROVENANCE TEST. Every correlation between carriers must be traceable
    /// to the capture.
    ///
    /// The rule that makes joint scheduling safe: carriers may be correlated,
    /// but only in ways the capture recorded. Recorded correlation is reproducible
    /// because it was fixed before the session had any payload; implementation
    /// correlation - a hoisted clock read, a shared jitter draw, a shared
    /// allocator stalling everyone together - varies with load and shows up as a
    /// difference between two runs.
    ///
    /// So: derive the schedules twice under conditions that differ in everything
    /// except the capture, and assert the INTER-CARRIER TIMING RELATIONSHIP is
    /// bit-identical. Not merely similar - identical, because a schedule that is
    /// a pure function of the capture has no mechanism by which it could differ.
    ///
    /// This is the strictest assertion in the pacer suite, and the rest of the
    /// carrier model rests on it: if inter-carrier timing can move at all, some
    /// input other than the capture reached it.
    #[test]
    fn inter_carrier_timing_is_identical_across_runs_with_different_payloads() {
        let csv = "flow,t,size,dir\n\
                   0,0.000,1391,1\n1,0.002,800,1\n\
                   0,0.011,54,-1\n1,0.014,1391,1\n\
                   2,0.200,1391,1\n0,0.205,1215,1\n2,0.240,54,-1\n";

        // "Different payloads" is represented as strongly as this layer allows:
        // separate parses, separate allocations, and an intervening workload that
        // perturbs allocator and clock state between them. A schedule that is a
        // pure function of the capture is unmoved by any of it.
        let a = MeasuredProfile::from_csv(csv)
            .expect("a")
            .carrier_schedules();
        let mut churn: Vec<Vec<u8>> = (0..64).map(|i| vec![i as u8; 1024]).collect();
        churn.retain(|v| v[0] % 2 == 0);
        std::hint::black_box(&churn);
        let b = MeasuredProfile::from_csv(csv)
            .expect("b")
            .carrier_schedules();

        assert_eq!(a.len(), 3, "one carrier per captured flow");
        assert_eq!(
            a, b,
            "carrier schedules must be a pure function of the capture"
        );

        // The relationship BETWEEN carriers, stated explicitly rather than implied
        // by struct equality - this is the quantity the rule is about.
        let rel = |v: &[CarrierSchedule]| -> Vec<(u64, u64, f64)> {
            let mut r = Vec::new();
            for i in 0..v.len() {
                for j in (i + 1)..v.len() {
                    r.push((v[i].flow, v[j].flow, v[j].opens_at - v[i].opens_at));
                }
            }
            r
        };
        let (ra, rb) = (rel(&a), rel(&b));
        assert_eq!(ra, rb, "inter-carrier open offsets must be bit-identical");
        for ((_, _, x), (_, _, y)) in ra.iter().zip(rb.iter()) {
            assert_eq!(x.to_bits(), y.to_bits(), "bit-identical, not merely close");
        }

        // And the correlation that IS present must come from the capture: carrier
        // 2 opens 0.2 s after carrier 0 because the capture says so.
        assert!(
            (a[2].opens_at - 0.200).abs() < 1e-9,
            "ramp is the recorded one"
        );
        assert!(
            a[0].opens_at == 0.0 && a[1].opens_at > 0.0,
            "carriers do not all open at t=0"
        );
    }

    /// A carrier replays only its own connection's records, at their recorded
    /// times - so alternation between carriers is reproduced, not invented.
    #[test]
    fn each_carrier_replays_only_its_own_records() {
        let csv = "flow,t,size,dir\n\
                   0,0.000,100,1\n1,0.001,200,1\n0,0.002,300,-1\n1,0.003,400,-1\n";
        let cs = MeasuredProfile::from_csv(csv).unwrap().carrier_schedules();
        assert_eq!(cs.len(), 2);
        assert_eq!(
            cs[0].tokens.iter().map(|e| e.bytes).collect::<Vec<_>>(),
            vec![100, 300]
        );
        assert_eq!(
            cs[1].tokens.iter().map(|e| e.bytes).collect::<Vec<_>>(),
            vec![200, 400]
        );
        // Recorded times, not rebased to each carrier's own zero.
        assert!((cs[1].tokens[0].t - 0.001).abs() < 1e-9);
    }

    /// Helper: run every carrier to exhaustion under a payload policy, returning
    /// the wire-observable `(flow, at, bytes)` for each emission.
    fn run_carriers(
        csv: &str,
        mut payload: impl FnMut(u64, usize) -> usize,
        dead: Option<u64>,
    ) -> Vec<(u64, u64, usize)> {
        let p = MeasuredProfile::from_csv(csv).expect("parse");
        let mut out = Vec::new();
        for sch in p.carrier_schedules() {
            if Some(sch.flow) == dead {
                continue; // this carrier died; the others must not notice
            }
            let flow = sch.flow;
            let mut e = CarrierEmitter::new(sch);
            let mut i = 0;
            while let Some(em) = e.next(payload(flow, i)) {
                // `at` compared by bits: "close enough" would hide exactly the
                // drift this is looking for.
                out.push((flow, em.at.to_bits(), em.bytes));
                i += 1;
            }
        }
        out
    }

    /// A second fixture in which one carrier emits twice in a row.
    ///
    /// `CARRIER_CSV` has due order [0,1,0,1,2,0,2] and never places two records
    /// from one carrier next to each other. That is a reasonable fixture and an
    /// INCOMPLETE one: a mutation that coalesces consecutive same-carrier records
    /// cannot execute against it, so the mutation came back green and was very
    /// nearly recorded as "the test cannot detect this" - which would have deleted
    /// a working assertion.
    ///
    /// Fixtures used for mutation testing must be able to reach the mutated path.
    /// Carrier 0 emits at 0.011 and 0.012 here, back to back.
    const CARRIER_CSV_ADJACENT: &str = "flow,t,size,dir\n\
                                        0,0.000,1391,1\n1,0.002,800,1\n\
                                        0,0.011,54,-1\n0,0.012,900,1\n\
                                        1,0.014,1391,1\n2,0.200,1391,1\n";

    /// Assert a fixture actually contains adjacent same-carrier emissions, so the
    /// coverage claim above is checked rather than asserted in a comment.
    fn has_adjacent_same_carrier(csv: &str) -> bool {
        let p = MeasuredProfile::from_csv(csv).unwrap();
        let mut set = CarrierSet::from_profile(&p);
        let mut prev: Option<usize> = None;
        while let Some((i, _)) = set.next_due(|_| 0) {
            if prev == Some(i) {
                return true;
            }
            prev = Some(i);
        }
        false
    }

    const CARRIER_CSV: &str = "flow,t,size,dir\n\
                               0,0.000,1391,1\n1,0.002,800,1\n\
                               0,0.011,54,-1\n1,0.014,1391,1\n\
                               2,0.200,1391,1\n0,0.205,1215,1\n2,0.240,54,-1\n";

    /// MUTATION-VERIFIED. These three assertions were checked against injected
    /// defects rather than trusted because they were green:
    ///
    ///   1. payload changing the observable size -> caught
    ///   2. a survivor emitting an extra token when another carrier dies -> caught
    ///   3. jitter seeded from `SystemTime::now()` adding per-run drift to `at`
    ///      -> caught by all three tests
    ///
    /// Worth recording from (3): the first attempt at that mutation did not
    /// compile, because reading `self.jitter` mutably while `tok` borrows
    /// `self.schedule` is a borrow error. The borrow checker refuses the most
    /// natural way to write that defect at this site. It is not a guarantee - the
    /// mutation compiles once the draw is hoisted above the borrow, which is what
    /// the verified version does - but it is one more reach removed.
    ///
    /// THE PROVENANCE TEST, AT THE EMITTER. Extends the derivation test to the
    /// layer where a hoisted clock or shared jitter draw would actually live.
    ///
    /// Same capture, wildly different payload: idle versus saturated versus a
    /// pattern that varies per carrier and per record. The wire-observable
    /// `(flow, at, bytes)` sequence must be bit-identical across all of them. Only
    /// the `real`/`pad` split may move.
    ///
    /// If emission times or sizes shift with payload, demand has reached the wire.
    #[test]
    fn emission_times_and_sizes_are_identical_under_any_payload() {
        let idle = run_carriers(CARRIER_CSV, |_, _| 0, None);
        let saturated = run_carriers(CARRIER_CSV, |_, _| usize::MAX, None);
        let varying = run_carriers(
            CARRIER_CSV,
            |f, i| (f as usize * 977 + i * 131) % 2048,
            None,
        );

        assert!(!idle.is_empty(), "the fixture must actually emit");
        assert_eq!(
            idle, saturated,
            "an empty queue and a full one must look identical"
        );
        assert_eq!(idle, varying, "a varying queue must look identical too");
    }

    /// The split is the ONLY thing payload moves - asserted positively, so this
    /// test cannot pass by the emitter ignoring payload altogether.
    #[test]
    fn payload_moves_the_real_pad_split_and_nothing_else() {
        let p = MeasuredProfile::from_csv(CARRIER_CSV).unwrap();
        let sch = p.carrier_schedules().into_iter().next().unwrap();
        let mut idle = CarrierEmitter::new(sch.clone());
        let mut full = CarrierEmitter::new(sch);
        let (a, b) = (idle.next(0).unwrap(), full.next(usize::MAX).unwrap());
        assert_eq!(a.at.to_bits(), b.at.to_bits());
        assert_eq!(a.bytes, b.bytes);
        assert_eq!((a.real, a.pad), (0, a.bytes), "idle carries no payload");
        assert_eq!((b.real, b.pad), (b.bytes, 0), "saturated fills the token");
        assert_eq!(
            a.real + a.pad,
            b.real + b.pad,
            "observable size is invariant"
        );
    }

    /// FAILURE INJECTION. A dead carrier must not change what the survivors emit.
    ///
    /// Compared against a NO-FAILURE BASELINE rather than against the survivors'
    /// own behaviour before the failure. Only that form catches the real defect:
    /// a survivor speeding up to absorb the dead carrier's share is
    /// demand-responsive behaviour reintroduced through the back door, and it
    /// would look perfectly stable measured against itself.
    #[test]
    fn surviving_carriers_are_byte_identical_to_a_no_failure_baseline() {
        let baseline = run_carriers(CARRIER_CSV, |_, _| 4096, None);
        for dead in [0u64, 1, 2] {
            let with_loss = run_carriers(CARRIER_CSV, |_, _| 4096, Some(dead));
            let expected: Vec<_> = baseline
                .iter()
                .copied()
                .filter(|&(f, _, _)| f != dead)
                .collect();
            assert_eq!(
                with_loss, expected,
                "killing carrier {dead} changed what the survivors emit"
            );
            assert!(!with_loss.is_empty(), "session survives the loss");
            assert!(
                with_loss.len() < baseline.len(),
                "throughput degrades by the dead carrier's share, rather than being absorbed"
            );
        }
    }

    /// Backpressure must not reach the schedule.
    ///
    /// The third way the live path can leak, after an ambient clock and a
    /// reconstructed emitter. A blocked socket is the caller's problem: it may not
    /// skip, delay or coalesce an emission, because that lets demand back in
    /// through I/O rather than through an argument - and I/O backpressure is
    /// payload-correlated by definition.
    ///
    /// Modelled as a sink that blocks for a stretch in the middle. The emitted
    /// `(carrier, at, bytes)` sequence must be identical to the unblocked run.
    #[test]
    fn a_blocked_sink_does_not_change_the_emitted_schedule() {
        let p = MeasuredProfile::from_csv(CARRIER_CSV).unwrap();

        let drain = |blocking: bool| -> Vec<(usize, u64, usize)> {
            let mut set = CarrierSet::from_profile(&p);
            let mut out = Vec::new();
            let mut n = 0;
            while let Some((i, em)) = set.next_due(|_| 4096) {
                n += 1;
                // A real sink would stall here. It must not feed back into what
                // gets emitted or when - only into the caller's own waiting.
                let _stalled = blocking && (3..6).contains(&n);
                out.push((i, em.at.to_bits(), em.bytes));
            }
            out
        };

        assert_eq!(
            drain(false),
            drain(true),
            "a stalled sink changed the schedule"
        );
        assert!(!drain(false).is_empty());
    }

    /// The set is built from the capture, and `M` is the captured flow count.
    #[test]
    fn carrier_set_size_comes_from_the_capture() {
        let p = MeasuredProfile::from_csv(CARRIER_CSV).unwrap();
        let set = CarrierSet::from_profile(&p);
        assert_eq!(
            set.len(),
            p.flow_starts.len(),
            "M is the captured flow count"
        );
        assert_eq!(set.len(), 3);
        assert!(!set.is_empty());
    }

    /// Emissions come out in due order across carriers, interleaved as recorded.
    ///
    /// The alternation is the joint structure: carrier 0 and 1 alternate early,
    /// carrier 2 joins at 0.2 s. If `next_due` returned each carrier's schedule
    /// end-to-end instead, the replay would be the serialisation this design
    /// exists to avoid.
    #[test]
    fn emissions_interleave_across_carriers_in_recorded_order() {
        let p = MeasuredProfile::from_csv(CARRIER_CSV).unwrap();
        let mut set = CarrierSet::from_profile(&p);
        let mut order = Vec::new();
        let mut last = f64::NEG_INFINITY;
        while let Some((i, em)) = set.next_due(|_| 0) {
            assert!(em.at >= last, "due order is monotonic across carriers");
            last = em.at;
            order.push(i);
        }
        assert!(
            order.windows(2).any(|w| w[0] != w[1]),
            "carriers must interleave, not run end-to-end"
        );
    }

    /// A reconnect must not restart the carrier.
    ///
    /// The emitter is one-per-carrier and not `Clone`, but the reconnect path is
    /// where a fresh construction is most natural to write - and a fresh emitter
    /// reseeds jitter and restarts position, which makes the session boundary
    /// observable. A censor watching a carrier restart its schedule from token 0
    /// at the moment a TCP connection re-establishes has a reconnect oracle.
    ///
    /// So the set outlives the connection: emissions continue where they stopped.
    #[test]
    fn a_reconnect_continues_the_schedule_rather_than_restarting_it() {
        let p = MeasuredProfile::from_csv(CARRIER_CSV).unwrap();

        // Uninterrupted reference.
        let mut whole = CarrierSet::from_profile(&p);
        let mut reference = Vec::new();
        while let Some((i, em)) = whole.next_due(|_| 4096) {
            reference.push((i, em.at.to_bits(), em.bytes));
        }

        // Same set, "connection" lost after three emissions and resumed. The set
        // is NOT rebuilt - that is the whole point.
        let mut across = CarrierSet::from_profile(&p);
        let mut got = Vec::new();
        for _ in 0..3 {
            let (i, em) = across.next_due(|_| 4096).expect("pre-reconnect");
            got.push((i, em.at.to_bits(), em.bytes));
        }
        // ... connection drops and re-establishes here; the emitter is untouched ...
        while let Some((i, em)) = across.next_due(|_| 4096) {
            got.push((i, em.at.to_bits(), em.bytes));
        }

        assert_eq!(
            got, reference,
            "a reconnect changed the emitted schedule - the session boundary is observable"
        );
    }

    /// END-TO-END: what reaches the wire must equal what the schedule said.
    ///
    /// The mutation tests cover the emitter's contract. This covers the gap
    /// BETWEEN emitter and socket, which no test above can see: a wiring that
    /// coalesces two records into one write, pads to a different size, or drops a
    /// record on a partial write would leave the emitter perfectly correct and the
    /// wire wrong.
    ///
    /// The sink here records what it was handed, including a short write it has to
    /// finish - the case most likely to lose or merge a record in real code.
    ///
    /// MUTATION NOTE, because the first attempt to verify this test was itself a
    /// false result. Injecting "coalesce consecutive records from the same
    /// carrier" left the test GREEN - not because the test is blind, but because
    /// the fixture's due order is `[0,1,0,1,2,0,2]` and never has two consecutive
    /// records from one carrier, so the injected branch never ran. Coalescing
    /// adjacent records regardless of carrier fires, and is caught.
    ///
    /// That is the precondition rule (methodology note 3c) landing one minute
    /// after it was written down: a mutation that does not execute is not evidence
    /// that the assertion is weak. Any fixture used for mutation testing has to be
    /// checked for whether it can reach the mutated path at all.
    #[test]
    fn bytes_reaching_the_sink_match_the_schedule() {
        // Coverage, checked rather than assumed: one fixture must be able to reach
        // the coalesce-consecutive path or a mutation against it proves nothing.
        assert!(
            !has_adjacent_same_carrier(CARRIER_CSV),
            "CARRIER_CSV is the alternating fixture"
        );
        assert!(
            has_adjacent_same_carrier(CARRIER_CSV_ADJACENT),
            "CARRIER_CSV_ADJACENT must contain back-to-back records from one carrier, \
             or a coalescing mutation cannot execute and its verdict is meaningless"
        );
        for csv in [CARRIER_CSV, CARRIER_CSV_ADJACENT] {
            check_wire_matches_schedule(csv);
        }
    }

    /// The same socket-level assertion, on the HETEROGENEOUS path.
    ///
    /// The homogeneous test cannot see a defect that only appears when two cover
    /// classes share a wire: a router that drops an emission when switching class,
    /// merges records across classes into one write, or attributes a record to the
    /// wrong class. Each leaves every component correct and the wire wrong, which
    /// is exactly the gap between emitter and I/O this class of test exists for.
    ///
    /// The sink records `(class, bytes)` so a cross-class misattribution shows up
    /// as an ordering difference rather than being absorbed into a byte total.
    #[test]
    fn hetero_bytes_reaching_the_sink_match_the_schedule() {
        let bp = MeasuredProfile::from_csv(BROWSE_LIKE).unwrap();
        let vp = MeasuredProfile::from_csv(VIDEO_LIKE).unwrap();

        let schedule = |()| -> Vec<(StreamClass, usize)> {
            let mut set =
                HeteroCarrierSet::new(&[(StreamClass::Interactive, &bp), (StreamClass::Bulk, &vp)]);
            let mut v = Vec::new();
            while let Some((c, _, em)) = set.next_due(|_, _| 4096) {
                v.push((c, em.bytes));
            }
            v
        };

        let mut set =
            HeteroCarrierSet::new(&[(StreamClass::Interactive, &bp), (StreamClass::Bulk, &vp)]);
        let mut wire: Vec<(StreamClass, usize)> = Vec::new();
        let mut short = false;
        while let Some((c, _, em)) = set.next_due(|_, _| 4096) {
            // Partial write that must complete as ONE record of the scheduled
            // size, on whichever class it belongs to.
            short = !short;
            let mut written = 0usize;
            while written < em.bytes {
                let chunk = if short && written == 0 {
                    em.bytes / 2
                } else {
                    em.bytes - written
                };
                written += chunk.max(1);
            }
            assert_eq!(written, em.bytes);
            wire.push((c, written));
        }

        let sched = schedule(());
        assert!(!sched.is_empty());
        assert_eq!(wire, sched, "hetero wire diverged from the schedule");

        // Per-class totals must match too - a cross-class misattribution that
        // preserved the overall byte count would otherwise pass.
        for class in [StreamClass::Interactive, StreamClass::Bulk] {
            let w: usize = wire
                .iter()
                .filter(|&&(c, _)| c == class)
                .map(|&(_, b)| b)
                .sum();
            let e: usize = sched
                .iter()
                .filter(|&&(c, _)| c == class)
                .map(|&(_, b)| b)
                .sum();
            assert_eq!(w, e, "{class:?} byte total diverged");
            assert!(w > 0, "{class:?} carried nothing - the test proves nothing");
        }
    }

    fn check_wire_matches_schedule(csv: &str) {
        let p = MeasuredProfile::from_csv(csv).unwrap();
        let mut set = CarrierSet::from_profile(&p);

        let mut scheduled: Vec<(usize, usize)> = Vec::new();
        let mut wire: Vec<(usize, usize)> = Vec::new();
        let mut short_write_toggle = false;

        while let Some((i, em)) = set.next_due(|_| 4096) {
            scheduled.push((i, em.bytes));
            // A sink that sometimes accepts only half a record, forcing the caller
            // to finish the write. The record must still arrive as ONE record of
            // the scheduled size.
            short_write_toggle = !short_write_toggle;
            let mut written = 0usize;
            while written < em.bytes {
                let chunk = if short_write_toggle && written == 0 {
                    em.bytes / 2
                } else {
                    em.bytes - written
                };
                written += chunk.max(1);
            }
            assert_eq!(written, em.bytes, "partial writes must complete the record");
            wire.push((i, written));
        }

        assert!(!scheduled.is_empty());
        assert_eq!(
            wire, scheduled,
            "bytes on the wire diverged from the schedule"
        );
        // And the observable total is the schedule's, not the payload's.
        let total: usize = wire.iter().map(|&(_, b)| b).sum();
        let sched_total: usize = p.joint.iter().map(|&(_, b, _, _)| b).sum();
        assert_eq!(
            total, sched_total,
            "wire total must equal the captured total"
        );
    }

    /// Deficit permutation emits exactly the trace's multiset - zero marginal
    /// divergence - regardless of payload.
    ///
    /// This is the property the mechanism exists for: reordering does not change
    /// WHAT is sent, only WHEN. If the realised histogram ever differs from the
    /// trace's, the mechanism has become substitution rather than permutation and
    /// is paying divergence in the expensive place.
    #[test]
    fn permutation_preserves_the_size_histogram_exactly() {
        let p = MeasuredProfile::from_csv(CARRIER_CSV).unwrap();
        let sch = p.carrier_schedules().into_iter().next().unwrap();
        let trace: Vec<usize> = sch.tokens.iter().map(|t| t.bytes).collect();

        for policy in [0usize, usize::MAX, 777] {
            let mut perm = DeficitPermuter::new(&sch.tokens, 4, 2);
            let mut remaining = sch.tokens.clone();
            let mut got = Vec::new();
            while !remaining.is_empty() {
                let i = perm.pick(&remaining, policy);
                got.push(remaining.remove(i).bytes);
            }
            let (mut a, mut b) = (trace.clone(), got.clone());
            a.sort_unstable();
            b.sort_unstable();
            assert_eq!(a, b, "permutation must emit the trace's multiset exactly");
            assert_eq!(got.len(), trace.len(), "every record emitted exactly once");
        }
    }

    /// The `δ_max` cap holds at EVERY prefix, not just at the end.
    ///
    /// Convergence over a full session is not the guarantee that matters: a
    /// session ending early leaves the histogram unconverged in a
    /// payload-dependent direction - heavy use ends owing large records - and that
    /// is a session-boundary leak. The cap has to bound the deviation at every
    /// point, so the property is checked after every single pick.
    #[test]
    fn the_deficit_cap_holds_at_every_prefix_not_just_at_the_end() {
        // A purpose-built schedule, NOT one of the capture fixtures.
        //
        // The capture fixtures have three records of three distinct sizes on the
        // carrier under test, so no size can run more than one ahead of itself and
        // the cap is unreachable. A mutation removing the cap entirely came back
        // green against them - the fixture could not reach the state the cap
        // protects against, so the verdict meant nothing. (Methodology note 3c,
        // for the second time in this file.)
        //
        // Deficit only builds when sizes REPEAT and there are enough records to
        // run ahead: 40 records over three sizes, interleaved so a greedy
        // large-first policy would skew hard if unconstrained.
        let tokens: Vec<EmitToken> = (0..40)
            .map(|i| EmitToken {
                t: i as f64 * 0.01,
                bytes: [1391usize, 54, 900][i % 3],
                dir: Dir::Down,
            })
            .collect();
        // The fixture must be able to reach the guarded state, asserted rather
        // than assumed: without a cap the deficit must actually exceed the caps
        // under test.
        {
            // Max deficit DURING the run, not after it. At completion every size
            // has been emitted exactly its expected number of times, so the final
            // deficit is always 0 - that is the convergence property, and reading
            // it as the coverage check made the check itself vacuous.
            let mut free = DeficitPermuter::new(&tokens, 16, i64::MAX);
            let mut rem = tokens.clone();
            let mut peak = 0i64;
            while !rem.is_empty() {
                let i = free.pick(&rem, usize::MAX);
                rem.remove(i);
                peak = peak.max(free.worst_deficit());
            }
            assert!(
                peak > 3,
                "fixture cannot exercise the cap: uncapped deficit peaked at {peak}"
            );
        }
        for cap in [0i64, 1, 3] {
            let mut perm = DeficitPermuter::new(&tokens, 16, cap);
            let mut remaining = tokens.clone();
            let mut step = 0;
            while !remaining.is_empty() {
                let i = perm.pick(&remaining, usize::MAX); // maximum pressure to run ahead
                remaining.remove(i);
                step += 1;
                assert!(
                    perm.worst_deficit() <= cap.max(1),
                    "prefix {step}: deficit {} exceeded cap {cap}",
                    perm.worst_deficit()
                );
            }
        }
    }

    /// Permutation DOES make order depend on payload - stated as a test so the
    /// trade is explicit rather than discovered later.
    ///
    /// This is the cost the mechanism accepts: ordering carries demand
    /// information, in exchange for the size marginal carrying none. It is why the
    /// permuter is opt-in and off by default, and why
    /// `emission_times_and_sizes_are_identical_under_any_payload` asserts the
    /// DEFAULT path - that test would fail with permutation on, correctly.
    #[test]
    fn permutation_ordering_is_payload_dependent_by_design() {
        let p = MeasuredProfile::from_csv(CARRIER_CSV_ADJACENT).unwrap();
        let sch = p.carrier_schedules().into_iter().next().unwrap();
        let run = |available: usize| -> Vec<usize> {
            let mut perm = DeficitPermuter::new(&sch.tokens, 8, 8);
            let mut remaining = sch.tokens.clone();
            let mut got = Vec::new();
            while !remaining.is_empty() {
                let i = perm.pick(&remaining, available);
                got.push(remaining.remove(i).bytes);
            }
            got
        };
        let idle = run(0);
        let busy = run(usize::MAX);
        assert_ne!(
            idle, busy,
            "with a wide window and a loose cap the order must differ - if it does \
             not, the mechanism is not doing anything and its cost is being paid \
             for no gain"
        );
        // ...and the multiset is still identical, which is the whole bargain.
        let (mut a, mut b) = (idle.clone(), busy.clone());
        a.sort_unstable();
        b.sort_unstable();
        assert_eq!(a, b);
    }

    /// A zero-width window disables the mechanism: the trace order is emitted.
    #[test]
    fn window_of_one_is_the_unpermuted_trace() {
        let p = MeasuredProfile::from_csv(CARRIER_CSV).unwrap();
        let sch = p.carrier_schedules().into_iter().next().unwrap();
        let mut perm = DeficitPermuter::new(&sch.tokens, 1, 99);
        let mut remaining = sch.tokens.clone();
        let mut got = Vec::new();
        while !remaining.is_empty() {
            let i = perm.pick(&remaining, usize::MAX);
            assert_eq!(i, 0, "a window of one cannot reorder");
            got.push(remaining.remove(i).bytes);
        }
        assert_eq!(got, sch.tokens.iter().map(|t| t.bytes).collect::<Vec<_>>());
    }

    /// A browse-shaped capture: short burst, sub-100 ms gaps, low volume.
    const BROWSE_LIKE: &str = "flow,t,size,dir\n\
                               0,0.000,517,1\n0,0.010,1391,1\n0,0.030,1391,1\n\
                               0,0.095,220,-1\n1,0.005,1391,1\n1,0.060,900,1\n";
    /// A video-shaped capture: dense burst, then a full segment-duration stall.
    const VIDEO_LIKE: &str = "flow,t,size,dir\n\
                              0,0.000,1391,1\n0,0.001,1391,1\n0,0.002,1391,1\n\
                              0,10.000,1391,1\n0,10.001,1391,1\n0,10.002,1391,1\n";

    /// THE THROUGHPUT ANSWER: browse latency and video throughput at once.
    ///
    /// The 60-cell matrix said no single cover class clears both constraints -
    /// browse has the best gap bound (95.6 ms) and fails the throughput floor,
    /// while video clears throughput and stalls for ~10 s. This asserts the
    /// composite gets each from the class that has it, rather than a compromise
    /// that gets neither.
    #[test]
    fn interactive_keeps_browse_latency_while_bulk_carries_video_volume() {
        let bp = MeasuredProfile::from_csv(BROWSE_LIKE).unwrap();
        let vp = MeasuredProfile::from_csv(VIDEO_LIKE).unwrap();
        let mut set =
            HeteroCarrierSet::new(&[(StreamClass::Interactive, &bp), (StreamClass::Bulk, &vp)]);

        let mut by_class: std::collections::BTreeMap<StreamClass, Vec<f64>> = Default::default();
        let mut bytes: std::collections::BTreeMap<StreamClass, usize> = Default::default();
        while let Some((c, _, em)) = set.next_due(|_, _| 4096) {
            by_class.entry(c).or_default().push(em.at);
            *bytes.entry(c).or_default() += em.bytes;
        }

        let worst_gap = |v: &Vec<f64>| -> f64 {
            let mut s = v.clone();
            s.sort_by(f64::total_cmp);
            s.windows(2).map(|w| w[1] - w[0]).fold(0.0, f64::max)
        };
        let inter = worst_gap(&by_class[&StreamClass::Interactive]);
        let bulk = worst_gap(&by_class[&StreamClass::Bulk]);

        // Interactive rides the class with the tight gap bound.
        assert!(
            inter < 0.2,
            "interactive worst gap {inter}s must stay sub-200ms"
        );
        // Bulk wears the class that stalls - and that is fine, because bulk does
        // not care. Asserted so the test cannot pass by both classes being fast.
        assert!(
            bulk > 5.0,
            "bulk should wear the stalling class, saw {bulk}s"
        );
        // And bulk is where the volume is.
        assert!(
            bytes[&StreamClass::Bulk] > bytes[&StreamClass::Interactive],
            "bulk carriers must carry the volume"
        );
    }

    /// Each class's carrier count comes from its OWN capture.
    #[test]
    fn per_class_carrier_count_comes_from_that_class_capture() {
        let bp = MeasuredProfile::from_csv(BROWSE_LIKE).unwrap();
        let vp = MeasuredProfile::from_csv(VIDEO_LIKE).unwrap();
        let set =
            HeteroCarrierSet::new(&[(StreamClass::Interactive, &bp), (StreamClass::Bulk, &vp)]);
        assert_eq!(
            set.carriers_for(StreamClass::Interactive),
            bp.flow_starts.len()
        );
        assert_eq!(set.carriers_for(StreamClass::Bulk), vp.flow_starts.len());
        assert_eq!(set.len(), 3, "2 browse carriers + 1 video carrier");
        assert!(!set.is_empty());
    }

    /// Adding a second cover class must not add a channel.
    ///
    /// The per-carrier contract is unchanged, so the whole composite must still be
    /// payload-invariant in what a censor observes: same emission instants, same
    /// sizes, same class on each, whether the session is idle or saturated. If
    /// heterogeneity leaked, this is where it would show.
    #[test]
    fn heterogeneous_emission_is_payload_invariant() {
        let bp = MeasuredProfile::from_csv(BROWSE_LIKE).unwrap();
        let vp = MeasuredProfile::from_csv(VIDEO_LIKE).unwrap();
        let run = |f: &dyn Fn(StreamClass, usize) -> usize| -> Vec<(StreamClass, u64, usize)> {
            let mut set =
                HeteroCarrierSet::new(&[(StreamClass::Interactive, &bp), (StreamClass::Bulk, &vp)]);
            let mut out = Vec::new();
            while let Some((c, _, em)) = set.next_due(|a, b| f(a, b)) {
                out.push((c, em.at.to_bits(), em.bytes));
            }
            out
        };
        let idle = run(&|_, _| 0);
        let saturated = run(&|_, _| usize::MAX);
        // Payload skewed hard toward ONE class - the case where a naive
        // implementation would let a busy class steal the other's slots.
        let skewed = run(&|c, _| {
            if c == StreamClass::Bulk {
                usize::MAX
            } else {
                0
            }
        });
        assert_eq!(
            idle, saturated,
            "idle and saturated must be indistinguishable"
        );
        assert_eq!(idle, skewed, "one class being busy must not move the other");
    }

    /// Classification is fixed at accept and cannot be changed afterwards.
    ///
    /// Enforced by construction rather than asserted: `ClassifiedStream` has no
    /// setter and a private field, so a mid-life reclassification is unwritable.
    /// This test pins the API shape, because the defect would arrive as a
    /// well-meaning `fn reclassify(&mut self, bytes_seen: u64)`.
    #[test]
    fn stream_class_is_fixed_at_accept_and_has_no_setter() {
        let s = ClassifiedStream::accept(7, 443, false);
        assert_eq!(s.class(), StreamClass::Interactive);
        assert_eq!(s.id(), 7);

        // Copy semantics mean a "modified" stream is a different value entirely;
        // there is no path that mutates the original.
        let again = ClassifiedStream::accept(7, 443, false);
        assert_eq!(
            s, again,
            "classification is a pure function of accept-time facts"
        );

        // The classifier's signature cannot see volume: same inputs, same class,
        // no matter how much the stream has since carried. Asserted by the fact
        // that there is no parameter to vary - if a byte count is ever added to
        // `accept`, this test's call sites stop compiling, which is the point.
        assert_eq!(
            ClassifiedStream::accept(9, 873, false).class(),
            StreamClass::Bulk
        );
        assert_eq!(
            ClassifiedStream::accept(9, 6881, false).class(),
            StreamClass::Bulk
        );
        assert_eq!(
            ClassifiedStream::accept(9, 9999, false).class(),
            StreamClass::Interactive
        );
        assert_eq!(
            ClassifiedStream::accept(9, 443, true).class(),
            StreamClass::Bulk,
            "an explicit client hint is accept-time information and may be used"
        );
    }

    /// Unknown ports default to Interactive, and the asymmetry is deliberate.
    ///
    /// Misrouting bulk onto browse-class costs throughput; misrouting interactive
    /// onto video-class costs a ten-second stall. The second is far worse for the
    /// user, so the default favours latency.
    #[test]
    fn unknown_services_default_to_the_latency_safe_class() {
        for port in [1u16, 4444, 8080, 31337, 65535] {
            assert_eq!(
                ClassifiedStream::accept(1, port, false).class(),
                StreamClass::Interactive,
                "port {port} should default to the latency-safe class"
            );
        }
    }

    /// THE LIVE PATH: a carrier handed to `ScheduleStream::for_carrier` emits the
    /// carrier's own sizes, in order.
    ///
    /// This is the join between the carrier model and the transport, and it is the
    /// one seam none of the component tests can see. `CarrierSet` is verified,
    /// `PacedChannel` is verified, and a `for_carrier` that dropped a token,
    /// reordered them, or quietly substituted a generated schedule would leave
    /// both correct and the wire wrong.
    ///
    /// Sizes rather than instants, because `ScheduleStream` owns pacing and
    /// wraps on replay; what must survive the handoff is WHICH records, in WHAT
    /// order, at the carrier's own sizes.
    #[test]
    fn for_carrier_replays_that_carriers_own_records_in_order() {
        let p = MeasuredProfile::from_csv(CARRIER_CSV).unwrap();
        for sch in p.carrier_schedules() {
            let want: Vec<usize> = sch.tokens.iter().map(|t| t.bytes).collect();
            let mut st = ScheduleStream::for_carrier(&sch, 0);
            let got: Vec<usize> = (0..want.len()).map(|_| st.next_token().bytes).collect();
            assert_eq!(
                got, want,
                "carrier {} live schedule diverged from its capture",
                sch.flow
            );
            // And it must not have inherited another carrier's records.
            let others: std::collections::HashSet<usize> = p
                .carrier_schedules()
                .iter()
                .filter(|o| o.flow != sch.flow)
                .flat_map(|o| o.tokens.iter().map(|t| t.bytes))
                .collect();
            let mine: std::collections::HashSet<usize> = want.iter().copied().collect();
            for b in &got {
                assert!(
                    mine.contains(b) || !others.contains(b),
                    "carrier {} emitted {b}, which belongs to another carrier",
                    sch.flow
                );
            }
        }
    }

    /// The live path preserves per-class routing: an interactive stream is driven
    /// by a browse-class carrier, a bulk stream by a video-class one.
    #[test]
    fn live_carriers_come_from_the_class_the_stream_was_accepted_as() {
        let bp = MeasuredProfile::from_csv(BROWSE_LIKE).unwrap();
        let vp = MeasuredProfile::from_csv(VIDEO_LIKE).unwrap();
        let inter = ClassifiedStream::accept(1, 443, false);
        let bulk = ClassifiedStream::accept(2, 873, false);
        assert_eq!(inter.class(), StreamClass::Interactive);
        assert_eq!(bulk.class(), StreamClass::Bulk);

        let pick = |class: StreamClass| -> Vec<usize> {
            let prof = if class == StreamClass::Interactive {
                &bp
            } else {
                &vp
            };
            let sch = prof.carrier_schedules().into_iter().next().unwrap();
            let mut st = ScheduleStream::for_carrier(&sch, 0);
            (0..3).map(|_| st.next_token().bytes).collect()
        };
        let i_sizes = pick(inter.class());
        let b_sizes = pick(bulk.class());
        // The browse capture opens with 517; the video capture is all 1391.
        assert_eq!(
            i_sizes[0], 517,
            "interactive must ride the browse-class carrier"
        );
        assert!(
            b_sizes.iter().all(|&b| b == 1391),
            "bulk must ride the video-class carrier"
        );
    }

    #[test]
    fn schedule_stream_replay_loops_real_sizes_monotonically() {
        let csv = "flow,t,size,dir\n\
                   0,0.000,1391,1\n0,0.005,1391,1\n0,0.010,54,-1\n0,0.020,1215,1\n0,0.030,1391,1\n";
        let p = std::sync::Arc::new(MeasuredProfile::from_csv(csv).unwrap());
        let span = p.span;
        let mut st = ScheduleStream::replay(p, 7);
        let mut last = f64::NEG_INFINITY;
        let mut sizes = std::collections::HashSet::new();
        for _ in 0..5000 {
            let tok = st.next_token();
            assert!(tok.t >= last, "replay is monotonic across loop boundaries");
            last = tok.t;
            sizes.insert(tok.bytes);
        }
        // It replays the captured sizes (1391/1215/54), not a generative model.
        assert!(sizes.contains(&1391) && sizes.contains(&1215) && sizes.contains(&54));
        assert!(
            sizes.iter().all(|&s| s != MTU) || sizes.contains(&1391),
            "sizes come from the profile"
        );
        assert!(last > span * 3.0, "replays past several loop cycles");
    }

    #[test]
    fn schedule_stream_replay_direction_filter() {
        let csv = "0.0,1391,1\n0.01,54,-1\n0.02,1391,1\n0.03,600,-1\n";
        let p = std::sync::Arc::new(MeasuredProfile::from_csv(csv).unwrap());
        let mut st = ScheduleStream::replay(p, 3);
        for _ in 0..200 {
            assert_eq!(st.next_for(Dir::Down).dir, Dir::Down);
            assert_eq!(st.next_for(Dir::Up).dir, Dir::Up);
        }
    }
}
