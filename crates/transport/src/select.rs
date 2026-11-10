//! Adaptive transport selection - the decision layer over
//! [`crate::SuccessRateMap`].
//!
//! # The gap this closes
//!
//! Mirage ships ~10 carrier transports (Reality, Hysteria2, ss2022, WebSocket,
//! meek, `DoH`, VLESS, Shadowsocks, obfs-tcp, raw). The [`SuccessRateMap`]
//! records per-(network, transport) outcomes - but nothing turned those
//! observations into a *decision*: "given what I've learned on this network,
//! which transport do I try first, and in what order do I fall over?" Without
//! that, the client
//! picked one transport at config time and broke the moment a censor blocked
//! it. [`rank`] is that decision.
//!
//! # Policy
//!
//! Given the candidate transports and the success-rate map for the current
//! [`NetworkFingerprint`], [`rank`] orders candidates best-first by a score:
//!
//! 1. **Sticky winner** - a transport that succeeded within
//!    `recent_success_window` ranks at the top. The cheapest, least
//!    fingerprintable move is to reuse what just worked rather than re-fan-out.
//! 2. **Historically good** - higher empirical success rate ranks higher
//!    (a small prior keeps low-observation transports from dominating on noise).
//! 3. **Unexplored** - never-tried transports rank above known-poor ones so the
//!    client discovers a working path on a new network.
//! 4. **Known poor** - tried, low success rate, but not currently in backoff.
//! 5. **In backoff** - a transport that failed recently is deprioritized for an
//!    EXPONENTIALLY growing window (`backoff_base * 2^(consecutive_failures-1)`,
//!    capped at `backoff_max`). Within this band it's ordered by recovery
//!    likelihood (fewer consecutive failures first).
//!
//! **Never drop a candidate.** Even a transport blocked 100 times stays in the
//! returned order (last). Censorship is not assumed permanent - the client must
//! keep a path to re-probe, or a transient block becomes permanent self-harm.
//! Callers try the order front-to-back until a session handshake succeeds, then
//! [`SuccessRateMap::record`] the outcome so the next call adapts.

use crate::success_rate::{NetworkFingerprint, SuccessRateMap, SuccessStats};
use std::time::{Duration, Instant};

/// Tunables for [`rank`]. `Default` is sensible for a client probing a hostile
/// network; operators rarely need to touch it.
#[derive(Debug, Clone, Copy)]
pub struct SelectionPolicy {
    /// A success newer than this makes a transport "sticky" (ranked first).
    pub recent_success_window: Duration,
    /// First-failure backoff window. Doubles per consecutive failure.
    pub backoff_base: Duration,
    /// Upper bound on the backoff window - a persistently blocked transport is
    /// still re-probed at least this often.
    pub backoff_max: Duration,
    /// Laplace-style prior added to both successes and the denominator so a
    /// single lucky/unlucky observation doesn't swing the rate to 0 or 1.
    pub rate_prior: f64,
}

impl Default for SelectionPolicy {
    fn default() -> Self {
        Self {
            recent_success_window: Duration::from_secs(300),
            backoff_base: Duration::from_secs(15),
            backoff_max: Duration::from_secs(3600),
            rate_prior: 1.0,
        }
    }
}

/// Score bands (kept well separated so the band dominates the in-band value).
const BAND_STICKY: f64 = 100.0;
const BAND_HISTORICAL: f64 = 10.0;
const BAND_UNEXPLORED: f64 = 5.0;
const BAND_KNOWN_POOR: f64 = 1.0;
const BAND_BACKOFF: f64 = -100.0;

impl SelectionPolicy {
    /// Backoff window for a transport with `consecutive_failures` failures
    /// since its last success: `base * 2^(n-1)`, clamped to `backoff_max`.
    /// Zero failures -> zero (no backoff).
    pub fn backoff_window(&self, consecutive_failures: u32) -> Duration {
        if consecutive_failures == 0 {
            return Duration::ZERO;
        }
        // Cap the shift so 2^n can't overflow; backoff_max clamps anyway.
        let shift = (consecutive_failures - 1).min(20);
        let scaled = self.backoff_base.saturating_mul(1u32 << shift);
        scaled.min(self.backoff_max)
    }

    /// Laplace-smoothed empirical success rate.
    fn smoothed_rate(&self, stats: &SuccessStats) -> f64 {
        let s = f64::from(stats.successes);
        let f = f64::from(stats.failures);
        (s + self.rate_prior) / (s + f + 2.0 * self.rate_prior)
    }

    /// Pure scoring fn: higher is better. `since_success` / `since_failure`
    /// are the ages of the last success/failure (`None` if never). Taking
    /// ages as `Duration`s (rather than `Instant`s) keeps this unit-testable
    /// without clock games.
    pub fn score(
        &self,
        stats: &SuccessStats,
        since_success: Option<Duration>,
        since_failure: Option<Duration>,
    ) -> f64 {
        // In backoff? (failed recently, within the exponential window).
        if let Some(age) = since_failure {
            let window = self.backoff_window(stats.consecutive_failures);
            if age < window {
                // Lower (more negative) for more consecutive failures and a
                // fresher failure -> most-recovered candidates sort first.
                return BAND_BACKOFF
                    - f64::from(stats.consecutive_failures)
                    - (window - age).as_secs_f64() / 1_000_000.0;
            }
        }

        // Sticky: succeeded within the recent window.
        if let Some(age) = since_success {
            if age < self.recent_success_window {
                // Fresher success ranks higher within the sticky band.
                return BAND_STICKY + self.smoothed_rate(stats) - age.as_secs_f64() / 1_000_000.0;
            }
        }

        let observed = stats.successes + stats.failures;
        if observed == 0 {
            // Unexplored - try ahead of known-poor.
            return BAND_UNEXPLORED;
        }

        // Tried before. Good historical rate -> historical band; poor -> poor band.
        let rate = self.smoothed_rate(stats);
        if rate >= 0.5 {
            BAND_HISTORICAL + rate
        } else {
            BAND_KNOWN_POOR + rate
        }
    }
}

/// One ranked candidate plus its score (exposed for diagnostics / metrics).
#[derive(Debug, Clone, Copy)]
pub struct Ranked {
    /// Transport name.
    pub transport: &'static str,
    /// Score assigned by [`SelectionPolicy::score`] (higher = preferred).
    pub score: f64,
}

/// Rank `candidates` best-first for `network`, consulting `map`. The full set
/// is always returned (never dropped) so the caller can fall over through
/// every transport and still re-probe an apparently-blocked one as a last
/// resort. Ties preserve the caller's input order (its configured priority).
pub fn rank(
    map: &SuccessRateMap,
    network: &NetworkFingerprint,
    candidates: &[&'static str],
    policy: &SelectionPolicy,
    now: Instant,
) -> Vec<Ranked> {
    let mut scored: Vec<(usize, Ranked)> = candidates
        .iter()
        .enumerate()
        .map(|(idx, &t)| {
            let stats = map.lookup(network, t);
            let since_success = stats
                .last_success
                .map(|ls| now.saturating_duration_since(ls));
            let since_failure = stats
                .last_failure
                .map(|lf| now.saturating_duration_since(lf));
            (
                idx,
                Ranked {
                    transport: t,
                    score: policy.score(&stats, since_success, since_failure),
                },
            )
        })
        .collect();

    // Sort by score desc; stable on the original index for ties.
    scored.sort_by(|(ia, a), (ib, b)| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(ia.cmp(ib))
    });
    scored.into_iter().map(|(_, r)| r).collect()
}

/// Convenience: just the ranked transport names, best-first.
pub fn rank_names(
    map: &SuccessRateMap,
    network: &NetworkFingerprint,
    candidates: &[&'static str],
    policy: &SelectionPolicy,
    now: Instant,
) -> Vec<&'static str> {
    rank(map, network, candidates, policy, now)
        .into_iter()
        .map(|r| r.transport)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net() -> NetworkFingerprint {
        NetworkFingerprint::from_digest([7u8; 16])
    }

    const CANDS: &[&str] = &["reality", "hysteria2", "ss2022", "doh"];

    #[test]
    fn all_candidates_always_returned_in_order() {
        let map = SuccessRateMap::new();
        let order = rank_names(
            &map,
            &net(),
            CANDS,
            &SelectionPolicy::default(),
            Instant::now(),
        );
        assert_eq!(order.len(), CANDS.len(), "never drop a candidate");
        // All-unexplored -> ties -> input order preserved.
        assert_eq!(order, CANDS);
    }

    #[test]
    fn recent_success_is_sticky_first() {
        let map = SuccessRateMap::new();
        // hysteria2 just succeeded; it should rank first even though it's
        // listed second in the candidate priority.
        map.record(&net(), "hysteria2", true);
        let order = rank_names(
            &map,
            &net(),
            CANDS,
            &SelectionPolicy::default(),
            Instant::now(),
        );
        assert_eq!(order[0], "hysteria2");
    }

    #[test]
    fn just_failed_transport_is_deprioritized_below_unexplored() {
        let map = SuccessRateMap::new();
        // reality failed just now -> backoff band -> must sort behind the
        // still-unexplored hysteria2/ss2022/doh.
        map.record(&net(), "reality", false);
        let order = rank_names(
            &map,
            &net(),
            CANDS,
            &SelectionPolicy::default(),
            Instant::now(),
        );
        assert_eq!(
            *order.last().unwrap(),
            "reality",
            "freshly-failed sorts last"
        );
        assert!(order.contains(&"reality"), "but is never dropped");
    }

    #[test]
    fn backoff_window_grows_exponentially_and_caps() {
        let p = SelectionPolicy {
            backoff_base: Duration::from_secs(10),
            backoff_max: Duration::from_secs(100),
            ..SelectionPolicy::default()
        };
        assert_eq!(p.backoff_window(0), Duration::ZERO);
        assert_eq!(p.backoff_window(1), Duration::from_secs(10));
        assert_eq!(p.backoff_window(2), Duration::from_secs(20));
        assert_eq!(p.backoff_window(3), Duration::from_secs(40));
        assert_eq!(
            p.backoff_window(10),
            Duration::from_secs(100),
            "clamped to max"
        );
    }

    #[test]
    fn recovers_after_backoff_elapses() {
        // A transport with one recent failure scores in the backoff band
        // while within the window, but recovers to the unexplored/poor band
        // once the window elapses. Test the pure score fn with explicit ages.
        let p = SelectionPolicy::default();
        let stats = SuccessStats {
            successes: 0,
            failures: 1,
            last_success: None,
            last_failure: None, // unused - age passed explicitly
            consecutive_failures: 1,
        };
        let in_backoff = p.score(&stats, None, Some(Duration::from_secs(1)));
        let recovered = p.score(&stats, None, Some(Duration::from_secs(10_000)));
        assert!(
            in_backoff < BAND_BACKOFF + 1.0,
            "in-backoff is deeply negative"
        );
        assert!(recovered > 0.0, "recovered out of backoff band");
        assert!(recovered > in_backoff);
    }

    #[test]
    fn good_history_beats_poor_history() {
        let map = SuccessRateMap::new();
        for _ in 0..9 {
            map.record(&net(), "ss2022", true);
        }
        map.record(&net(), "ss2022", false); // 9/10
        for _ in 0..9 {
            map.record(&net(), "doh", false);
        }
        map.record(&net(), "doh", true); // 1/10
                                         // Both last touched ~now; ss2022's last op was a failure (record order),
                                         // so to isolate "historical rate" use the pure scorer with no recent
                                         // events.
        let p = SelectionPolicy::default();
        let good = p.score(&map.lookup(&net(), "ss2022"), None, None);
        let poor = p.score(&map.lookup(&net(), "doh"), None, None);
        assert!(good > poor, "9/10 should outrank 1/10 ({good} vs {poor})");
    }

    #[test]
    fn unexplored_beats_known_poor() {
        let p = SelectionPolicy::default();
        let unexplored = SuccessStats::default();
        let poor = SuccessStats {
            successes: 0,
            failures: 5,
            consecutive_failures: 0, // not in backoff (e.g. all old failures)
            ..SuccessStats::default()
        };
        let s_unexplored = p.score(&unexplored, None, None);
        let s_poor = p.score(&poor, None, None);
        assert!(
            s_unexplored > s_poor,
            "explore new before retrying known-bad"
        );
    }
}
