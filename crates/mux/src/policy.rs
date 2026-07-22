//! Mux connection policy.

use std::time::Duration;

/// Initial flow-control window per stream direction. Senders may
/// transmit up to this many bytes before the peer sends a
/// `WINDOW_UPDATE`. 64 KiB matches HTTP/2's default.
pub const DEFAULT_INITIAL_WINDOW: u32 = 65536;

/// Default cap on concurrent open streams per direction. A
/// well-behaved client opens 6-32 streams in normal browsing; the
/// 256 default leaves generous headroom while bounding the
/// per-connection state cost (each stream has a small ring buffer
/// + state machine).
pub const DEFAULT_MAX_CONCURRENT_STREAMS: u32 = 256;

/// Default per-stream idle timeout. A stream with no DATA flowing
/// in either direction for this duration is RESET to free the
/// state.
pub const DEFAULT_STREAM_IDLE_TIMEOUT: Duration = Duration::from_secs(120);

/// Default cap on the per-connection outbound frame queue. The
/// state machine queues frames into a `VecDeque` for the async
/// driver to drain; without a cap, a peer that sends many
/// `Begin`s while the driver stalls (or a local app that calls
/// `send_data` far faster than the wire can flush) would let the
/// queue grow unboundedly. 1024 frames at 4 KiB body cap is
/// ~4 MiB worst case - enough headroom for normal bursts, small
/// enough to enforce backpressure long before the process OOMs.
pub const DEFAULT_MAX_PENDING_OUTBOUND: usize = 1024;

/// Configurable per-mux-connection policy. Apply via
/// [`crate::stream::StreamId::new`] consumers and the connection
/// driver (v0.2 will host the driver).
#[derive(Debug, Clone)]
pub struct MuxPolicy {
    /// Initial flow-control credit per stream direction. Both
    /// directions of every newly opened stream start with this
    /// many bytes.
    pub initial_window: u32,
    /// Maximum concurrent open streams. Requests over the cap
    /// receive a `RESET` with error code `0x02` (resource-exhausted).
    pub max_concurrent_streams: u32,
    /// Per-stream idle timeout. Implementations track last-DATA
    /// time and reset on overrun.
    pub stream_idle_timeout: Duration,
    /// Max pending outbound frames before the state machine
    /// applies backpressure. See [`DEFAULT_MAX_PENDING_OUTBOUND`].
    pub max_pending_outbound: usize,
}

impl Default for MuxPolicy {
    fn default() -> Self {
        Self {
            initial_window: DEFAULT_INITIAL_WINDOW,
            max_concurrent_streams: DEFAULT_MAX_CONCURRENT_STREAMS,
            stream_idle_timeout: DEFAULT_STREAM_IDLE_TIMEOUT,
            max_pending_outbound: DEFAULT_MAX_PENDING_OUTBOUND,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_documented_constants() {
        let p = MuxPolicy::default();
        assert_eq!(p.initial_window, 65536);
        assert_eq!(p.max_concurrent_streams, 256);
        assert_eq!(p.stream_idle_timeout, Duration::from_secs(120));
    }
}
