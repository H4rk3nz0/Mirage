//! Reactive-censor adversary - is the adaptive router pinnable?
//!
//! Every other adversary in this crate models a **passive or active DPI
//! distinguisher** (does the wire betray Mirage?). This one models the
//! adversary the routing engine ([`mirage_transport::adaptive`]) actually
//! exists to beat: a **strategic, reactive censor** that watches which
//! transports the client relies on and blocks them - the game whose *only*
//! winning move for the defender is to stop being predictable.
//!
//! It is the empirical, CI-gateable proof of the routing engine's central
//! claim. "The routing resists an adaptive censor" is not an assertion here -
//! it is a number the test asserts, and a regression that made selection
//! collapse toward a fixed order (killing the entropy) would flip the verdict
//! to [`DetectionVerdict::Distinguished`] and fail the gate.
//!
//! # The game
//!
//! `k` transport arms. Each round: the policy picks an arm; a
//! [`ReactiveCensor`] that can block at most `capacity < k` arms at once
//! (blocking *all* of them is the total-collateral case no policy survives)
//! best-responds by blocking the arms selected most in a recent window; the arm
//! succeeds iff it is not currently blocked; the reward is fed back. We measure,
//! over the run:
//!
//! - **working rate** - fraction of rounds the picked arm was reachable;
//! - **selection entropy** - Shannon entropy of the realised selection
//!   histogram, normalised to `[0,1]` - the "routing entropy" as a number;
//!
//! and we run a **greedy** (always-pick-the-best, deterministic) policy through
//! the identical game as a control. A deterministic policy is pinned by the
//! reactive censor (its favourite is exactly what gets blocked); the adaptive
//! router keeps a working path. The verdict is `Defended` only if the router
//! clears the working-rate + entropy floors *and* strictly beats greedy.

use crate::{AdversaryResult, DetectionVerdict};
use mirage_transport::adaptive::{AdaptiveRouter, Posture};
use mirage_transport::success_rate::{NetworkFingerprint, SuccessRateMap};
use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// Real transport names (also gives each arm a realistic bearer class inside the
/// router). Up to 8 arms.
const ARMS: [&str; 8] = [
    "reality",
    "hysteria2",
    "ss2022",
    "meek",
    "doh",
    "websocket",
    "h3",
    "dnstt",
];

/// A censor that observes the client's realised selections and, each round,
/// blocks the `capacity` arms picked most within a recent window of size
/// `window`. It can never block more than `capacity` arms - modelling the fact
/// that blocking a whole class of real-internet traffic carries collateral cost
/// a censor cannot pay indefinitely.
pub struct ReactiveCensor {
    k: usize,
    capacity: usize,
    window: usize,
    recent: VecDeque<usize>,
    blocked: Vec<bool>,
}

impl ReactiveCensor {
    /// `k` arms, block at most `capacity`, best-respond over the last `window`
    /// selections.
    #[must_use]
    pub fn new(k: usize, capacity: usize, window: usize) -> Self {
        Self {
            k,
            capacity: capacity.min(k),
            window: window.max(1),
            recent: VecDeque::new(),
            blocked: vec![false; k],
        }
    }

    /// Is `arm` currently blocked?
    #[must_use]
    pub fn is_blocked(&self, arm: usize) -> bool {
        self.blocked.get(arm).copied().unwrap_or(false)
    }

    /// Record a client selection and recompute the block set (best-response).
    pub fn observe(&mut self, arm: usize) {
        self.recent.push_back(arm);
        while self.recent.len() > self.window {
            self.recent.pop_front();
        }
        // Count recent selections per arm and block the top-`capacity`.
        let mut counts = vec![0usize; self.k];
        for &a in &self.recent {
            if let Some(c) = counts.get_mut(a) {
                *c += 1;
            }
        }
        let mut order: Vec<usize> = (0..self.k).collect();
        order.sort_by(|&a, &b| counts[b].cmp(&counts[a]));
        self.blocked = vec![false; self.k];
        for &a in order.iter().take(self.capacity) {
            if counts[a] > 0 {
                self.blocked[a] = true;
            }
        }
    }
}

/// Resilience of a routing policy against the reactive censor.
#[derive(Debug, Clone, Copy)]
pub struct RoutingResilience {
    /// Fraction of rounds the adaptive router picked a reachable arm.
    pub working_rate: f64,
    /// Normalised Shannon entropy of the router's realised selections `[0,1]`.
    pub selection_entropy: f64,
    /// Working rate of the deterministic greedy control through the same game.
    pub greedy_working_rate: f64,
}

/// Normalised Shannon entropy of a selection histogram, in `[0,1]`.
fn normalized_entropy(counts: &[usize]) -> f64 {
    let total: usize = counts.iter().sum();
    let k = counts.len();
    if total == 0 || k <= 1 {
        return 0.0;
    }
    let mut h = 0.0;
    for &c in counts {
        if c > 0 {
            let p = c as f64 / total as f64;
            h -= p * p.ln();
        }
    }
    h / (k as f64).ln()
}

/// Run the REAL [`AdaptiveRouter`] against a reactive censor for `rounds`, and a
/// deterministic greedy control through the identical game.
#[must_use]
pub fn measure_routing_resilience(
    k: usize,
    rounds: usize,
    capacity: usize,
    seed: u64,
) -> RoutingResilience {
    let k = k.clamp(2, ARMS.len());
    let names = &ARMS[..k];
    let net = NetworkFingerprint::unknown();
    let history = SuccessRateMap::new();
    let posture = Posture::open();
    let base = Instant::now();

    // --- Adaptive router ---
    let mut router = AdaptiveRouter::new(seed);
    let mut censor = ReactiveCensor::new(k, capacity, k * 4);
    let mut counts = vec![0usize; k];
    let mut working = 0usize;
    for r in 0..rounds {
        // Advance the clock so the router's diversity window slides naturally.
        let now = base + Duration::from_millis(r as u64 * 100);
        let Some(sel) = router.select(&net, names, &history, &posture, now) else {
            continue;
        };
        let arm = names.iter().position(|&n| n == sel).unwrap_or(0);
        counts[arm] += 1;
        let blocked = censor.is_blocked(arm);
        if !blocked {
            working += 1;
        }
        router.record(&net, sel, if blocked { 0.0 } else { 1.0 });
        censor.observe(arm);
    }

    RoutingResilience {
        working_rate: working as f64 / rounds.max(1) as f64,
        selection_entropy: normalized_entropy(&counts),
        greedy_working_rate: greedy_working_rate(k, rounds, capacity),
    }
}

/// A deterministic greedy control: track a per-arm reward EMA, always pick the
/// argmax, and run it through the same reactive-censor game. A deterministic
/// favourite is exactly what the censor blocks, so it gets pinned.
fn greedy_working_rate(k: usize, rounds: usize, capacity: usize) -> f64 {
    let mut ema = vec![0.5f64; k];
    let mut censor = ReactiveCensor::new(k, capacity, k * 4);
    let mut working = 0usize;
    for _ in 0..rounds {
        // argmax (ties -> lowest index -> still deterministic).
        let arm = (0..k)
            .max_by(|&a, &b| ema[a].partial_cmp(&ema[b]).unwrap())
            .unwrap_or(0);
        let blocked = censor.is_blocked(arm);
        if !blocked {
            working += 1;
        }
        let reward = if blocked { 0.0 } else { 1.0 };
        ema[arm] = 0.7 * ema[arm] + 0.3 * reward;
        censor.observe(arm);
    }
    working as f64 / rounds.max(1) as f64
}

/// Verdict: is the router pinnable by a reactive censor with `capacity < k`?
///
/// `Defended` iff the router keeps a working path a majority of rounds, retains
/// real selection entropy, AND strictly beats the greedy control (proving the
/// entropy is *doing the work*). `Distinguished` if the censor pinned it - the
/// regression signal.
pub fn reactive_censor_distinguisher(
    k: usize,
    rounds: usize,
    capacity: usize,
    seed: u64,
) -> AdversaryResult {
    let m = measure_routing_resilience(k, rounds, capacity, seed);
    const WORKING_FLOOR: f64 = 0.5;
    const ENTROPY_FLOOR: f64 = 0.3;
    const BEAT_GREEDY_MARGIN: f64 = 0.15;

    if m.working_rate < WORKING_FLOOR {
        return Ok(DetectionVerdict::Distinguished(format!(
            "reactive censor pinned the router: working_rate={:.2} < {WORKING_FLOOR}",
            m.working_rate
        )));
    }
    if m.selection_entropy < ENTROPY_FLOOR {
        return Ok(DetectionVerdict::Distinguished(format!(
            "selection collapsed to a low-entropy (predictable) distribution: H={:.2} < {ENTROPY_FLOOR}",
            m.selection_entropy
        )));
    }
    if m.working_rate < m.greedy_working_rate + BEAT_GREEDY_MARGIN {
        return Ok(DetectionVerdict::Distinguished(format!(
            "adaptive routing did not beat the pinned greedy control: {:.2} vs {:.2}",
            m.working_rate, m.greedy_working_rate
        )));
    }
    Ok(DetectionVerdict::Defended)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn router_defends_against_a_capacity_limited_reactive_censor() {
        // The core CI-gate: a censor that can block 1 of 5 arms and best-responds
        // to the client's selections must NOT be able to pin the router. If this
        // ever flips to Distinguished, the routing engine has regressed toward a
        // predictable (censorable) policy.
        let v = reactive_censor_distinguisher(5, 3000, 1, 0xC0FFEE).unwrap();
        assert!(
            v.is_defended(),
            "routing must resist a reactive censor: {v:?}"
        );
    }

    #[test]
    fn router_holds_even_when_the_censor_blocks_two_of_five() {
        let v = reactive_censor_distinguisher(5, 3000, 2, 0x1234_5678).unwrap();
        assert!(
            v.is_defended(),
            "routing must resist a 2/5 reactive censor: {v:?}"
        );
    }

    #[test]
    fn adaptive_router_strictly_beats_the_pinned_greedy_control() {
        // Quantify the value: the entropy policy keeps a far better working rate
        // than the deterministic one the censor pins.
        let m = measure_routing_resilience(5, 3000, 1, 0xABCD);
        // A lagging reactive censor lets even a deterministic policy escape
        // *somewhat* by moving a step ahead, so the honest claim is decisive
        // DOMINANCE by the entropy policy, not that greedy is pinned to zero.
        assert!(
            m.working_rate > m.greedy_working_rate + 0.15,
            "adaptive must dominate greedy against a reactive censor: {:.2} vs {:.2}",
            m.working_rate,
            m.greedy_working_rate
        );
        assert!(
            m.working_rate > 0.6,
            "the router keeps a strong working path: {:.2}",
            m.working_rate
        );
    }

    #[test]
    fn selection_retains_entropy() {
        let m = measure_routing_resilience(5, 3000, 1, 0x55);
        assert!(
            m.selection_entropy > 0.4,
            "routing entropy must stay high: H={:.2}",
            m.selection_entropy
        );
    }

    #[test]
    fn entropy_metric_bounds() {
        assert_eq!(normalized_entropy(&[10, 0, 0, 0]), 0.0); // fully concentrated
        assert_eq!(normalized_entropy(&[]), 0.0);
        let uniform = normalized_entropy(&[5, 5, 5, 5]);
        assert!(
            (uniform - 1.0).abs() < 1e-9,
            "uniform => max entropy, got {uniform}"
        );
    }

    #[test]
    fn reactive_censor_blocks_the_most_used_arm() {
        let mut c = ReactiveCensor::new(4, 1, 8);
        for _ in 0..5 {
            c.observe(2); // hammer arm 2
        }
        assert!(c.is_blocked(2), "the most-selected arm must be blocked");
        assert!(!c.is_blocked(0), "an unused arm stays open");
    }
}
