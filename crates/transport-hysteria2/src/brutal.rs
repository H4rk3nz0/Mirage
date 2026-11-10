//! Real BRUTAL congestion control for the Hysteria2 QUIC carrier (M3).
//!
//! Upstream Hysteria2's defining feature is a fixed-rate, loss-*immune* sender:
//! it paces at an operator-configured rate regardless of packet loss, so a
//! censor throttling the link by inducing loss cannot collapse throughput the
//! way it collapses a loss-responsive controller (BBR/CUBIC back off on loss).
//!
//! This implements that as an out-of-crate `quinn_proto::congestion::Controller`
//! (the trait + [`quinn_proto::RttEstimator`] are public in quinn-proto 0.11, so
//! it IS implementable outside quinn - the previous "private types" claim was
//! obsolete). The window is held at `rate * RTT` (a BDP sized for the target
//! rate) and, crucially, is NEVER reduced on a congestion event.
//!
//! # Trade-off (opt-in on purpose)
//!
//! Fixed-rate non-backoff pacing is itself a known Hysteria2 *behavioural* tell
//! (aggressive, non-responsive UDP), and it is antisocial on a shared/congested
//! path. Salamander obfuscation hides datagram CONTENT, not timing/volume, so
//! this does not hide the behaviour. BBR stays the default; operators opt in
//! only when a hostile link is actively throttling via induced loss.

use std::any::Any;
use std::sync::Arc;
use std::time::{Duration, Instant};

use quinn_proto::congestion::{Controller, ControllerFactory};
use quinn_proto::RttEstimator;

use crate::{compute_brutal_window, MIN_BRUTAL_WINDOW};

/// Assumed RTT before the first measurement (connection open).
const INITIAL_RTT: Duration = Duration::from_millis(100);

/// A fixed-rate, loss-immune BRUTAL congestion controller.
#[derive(Debug, Clone)]
pub struct Brutal {
    /// Target rate in BITS per second (matches `compute_brutal_window`, which
    /// divides by 8). `0` means "unlimited" and yields a very large window.
    rate_bps: u64,
    /// Current congestion window in bytes: `rate * RTT`, floored at
    /// [`MIN_BRUTAL_WINDOW`]. Recomputed from the latest RTT on each ack.
    window: u64,
}

impl Brutal {
    /// Construct with an assumed initial RTT until acks arrive.
    #[must_use]
    pub fn new(rate_bps: u64) -> Self {
        Self {
            rate_bps,
            window: compute_brutal_window(rate_bps, INITIAL_RTT),
        }
    }
}

impl Controller for Brutal {
    fn on_ack(
        &mut self,
        _now: Instant,
        _sent: Instant,
        _bytes: u64,
        _app_limited: bool,
        rtt: &RttEstimator,
    ) {
        // Track the window to rate * the current smallest observed RTT (the BDP
        // for the target rate). min() avoids inflating the window on transient
        // RTT spikes. This is the ONLY place the window moves - and it never
        // moves down in response to loss.
        self.window = compute_brutal_window(self.rate_bps, rtt.min());
    }

    fn on_congestion_event(
        &mut self,
        _now: Instant,
        _sent: Instant,
        _is_persistent_congestion: bool,
        _lost_bytes: u64,
    ) {
        // BRUTAL: deliberately do NOT reduce the window on loss/ECN. Holding the
        // rate through induced loss is the entire point of this controller.
    }

    fn on_mtu_update(&mut self, _new_mtu: u16) {
        // Window is rate-derived, not MTU-derived; nothing to adjust.
    }

    fn window(&self) -> u64 {
        self.window
    }

    // metrics(): the trait default reports `window()` as the congestion window,
    // which is exactly right for BRUTAL - no override needed.

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(self.clone())
    }

    fn initial_window(&self) -> u64 {
        self.window.max(MIN_BRUTAL_WINDOW)
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

/// [`ControllerFactory`] that builds [`Brutal`] controllers for quinn. Install
/// via `TransportConfig::congestion_controller_factory(Arc::new(BrutalConfig{..}))`.
#[derive(Debug, Clone, Copy)]
pub struct BrutalConfig {
    /// Target rate in BITS per second (see [`Brutal::rate_bps`]).
    pub rate_bps: u64,
}

impl ControllerFactory for BrutalConfig {
    fn build(self: Arc<Self>, _now: Instant, _current_mtu: u16) -> Box<dyn Controller> {
        Box::new(Brutal::new(self.rate_bps))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_tracks_rate_times_rtt() {
        // 80 Mbit/s * 100 ms / 8 = 1_000_000 bytes.
        let b = Brutal::new(80_000_000);
        assert_eq!(b.window(), 1_000_000);
    }

    #[test]
    fn window_floored_at_minimum() {
        // A tiny rate must not produce a sub-floor window (would stall QUIC).
        let b = Brutal::new(1);
        assert_eq!(b.window(), MIN_BRUTAL_WINDOW);
        assert_eq!(b.initial_window(), MIN_BRUTAL_WINDOW);
    }

    #[test]
    fn congestion_event_does_not_shrink_window() {
        let mut b = Brutal::new(80_000_000);
        let w = b.window();
        // A loss event MUST NOT reduce the window (the whole point of BRUTAL).
        b.on_congestion_event(Instant::now(), Instant::now(), true, 64_000);
        assert_eq!(b.window(), w, "BRUTAL must hold the window through loss");
    }

    #[test]
    fn zero_rate_is_effectively_unlimited() {
        // rate 0 => compute_brutal_window returns a very large window, not zero.
        let b = Brutal::new(0);
        assert!(b.window() > MIN_BRUTAL_WINDOW);
    }
}
