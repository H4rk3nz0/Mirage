//! Mux connection policy.

use std::time::Duration;

/// Initial flow-control window per stream direction. Senders may
/// transmit up to this many bytes before the peer sends a
/// `WINDOW_UPDATE`. 64 KiB matches HTTP/2's default.
pub const DEFAULT_INITIAL_WINDOW: u32 = 65536;

/// Default cap on concurrent open streams per connection.
pub const DEFAULT_MAX_CONCURRENT_STREAMS: u32 = 256;

/// Reserved per-stream idle timeout. The connection driver does not currently
/// enforce this value.
pub const DEFAULT_STREAM_IDLE_TIMEOUT: Duration = Duration::from_secs(120);

/// Default cap on the per-connection outbound frame queue. The
/// state machine queues frames into a `VecDeque` for the async
/// driver to drain; without a cap, a peer that sends many
/// `Begin`s while the driver stalls (or a local app that calls
/// `send_data` far faster than the wire can flush) would let the
/// queue grow unboundedly. 1024 frames at the 16 KiB frame cap is
/// ~16 MiB per connection at worst; pooled connections multiply that
/// bound. The cap enforces backpressure before the queue grows further.
pub const DEFAULT_MAX_PENDING_OUTBOUND: usize = 1024;

/// Bytes of credit per stream per deficit-round-robin round. A full 16 KiB
/// frame needs four rounds; a small frame can pass in the first.
pub const DEFAULT_DRR_QUANTUM_BYTES: usize = 4096;

/// Configurable per-mux-connection policy.
#[derive(Debug, Clone)]
pub struct MuxPolicy {
    /// Initial flow-control credit per stream direction. Both
    /// directions of every newly opened stream start with this
    /// many bytes.
    pub initial_window: u32,
    /// Maximum concurrent open streams. Requests over the cap
    /// receive a `RESET` with error code `0x02` (resource-exhausted).
    pub max_concurrent_streams: u32,
    /// Reserved; the current connection driver does not enforce idle timeouts.
    pub stream_idle_timeout: Duration,
    /// Max pending outbound frames before the state machine
    /// applies backpressure. See [`DEFAULT_MAX_PENDING_OUTBOUND`].
    pub max_pending_outbound: usize,
    /// Per-round byte credit for deficit round-robin across streams when the
    /// outbound queue is drained. See [`DEFAULT_DRR_QUANTUM_BYTES`]. Set to 0 to
    /// restore strict FIFO (bulk transfers then starve interactive streams).
    pub drr_quantum_bytes: usize,
}

impl Default for MuxPolicy {
    fn default() -> Self {
        Self {
            initial_window: DEFAULT_INITIAL_WINDOW,
            max_concurrent_streams: DEFAULT_MAX_CONCURRENT_STREAMS,
            stream_idle_timeout: DEFAULT_STREAM_IDLE_TIMEOUT,
            max_pending_outbound: DEFAULT_MAX_PENDING_OUTBOUND,
            drr_quantum_bytes: DEFAULT_DRR_QUANTUM_BYTES,
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
        assert_eq!(p.drr_quantum_bytes, 4096);
    }
}
