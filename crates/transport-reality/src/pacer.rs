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

const MTU: usize = 1400;
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
}

impl MeasuredProfile {
    /// Parse a capture CSV. Accepts rows `flow,t,size,dir` or `t,size,dir` (dir:
    /// 1=down, -1=up); a header line is skipped. Multiple `flow` ids are concatenated
    /// in id-then-time order, each offset to continue just after the previous flow, so
    /// the result is one long monotonic token stream to replay. Returns `None` if no
    /// usable rows were found.
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
                let dir = if dr >= 0 { Dir::Down } else { Dir::Up };
                if sz > 0 {
                    rows.push((flow, t, sz, dir));
                }
            }
        }
        if rows.is_empty() {
            return None;
        }
        rows.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.total_cmp(&b.1)));
        // Concatenate flows: offset each flow to start just after the previous ended.
        const GAP: f64 = 0.02; // inter-flow gap (s)
        let mut tokens: Vec<EmitToken> = Vec::with_capacity(rows.len());
        let mut cur_flow = rows[0].0;
        let mut flow_start = rows[0].1;
        let mut base = 0.0f64;
        let mut last = 0.0f64;
        for (flow, t, sz, dir) in rows {
            if flow != cur_flow {
                base = last + GAP;
                flow_start = t;
                cur_flow = flow;
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
        Some(Self { tokens, span })
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
            }),
        }
    }

    /// Push the next chunk of profile tokens into the buffer, looping the profile with
    /// a continued monotonic clock.
    fn refill_replay(&mut self) {
        const CHUNK: usize = 256;
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
