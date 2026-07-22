//! **Attack**: tarpit-timing oracle on obfs-tcp.
//!
//! A censor probes N suspected obfs-tcp endpoints with garbage
//! (random 64 bytes that won't pass the BLAKE3 auth tag check).
//! Real TCP services close on garbage within milliseconds. The
//! older Mirage tarpit held the socket open for 500-3500 ms on
//! auth fail - itself a Mirage signature, since no real service
//! does that.
//!
//! **Defense being tested**: fast-close jitter window
//! `[0, OBFS_AUTH_FAIL_JITTER_MAX = 50ms]` matching real-server
//! behavior on garbage (RT-CN-3 closure).
//!
//! **Distinguisher we look for**: the auth-fail close time
//! distribution overlaps the real-server distribution (close in
//! milliseconds).

use crate::{AdversaryError, AdversaryResult, DetectionVerdict};
use mirage_transport_obfs::{obfs_server_authenticate, OBFS_AUTH_FAIL_JITTER_MAX};
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;

/// Run the tarpit-timing oracle attack. Submits N rounds of
/// garbage to a simulated obfs server and measures the close
/// time. Returns `Defended` if the 99th-percentile close time is
/// under `OBFS_AUTH_FAIL_JITTER_MAX + slack`; `Distinguished` if
/// the distribution looks like a tarpit (consistent hold times
/// > 100ms).
pub async fn tarpit_timing_oracle(n_probes: usize) -> AdversaryResult {
    if n_probes < 10 {
        return Ok(DetectionVerdict::Inconclusive(format!(
            "need >= 10 probes for timing statistics, got {n_probes}"
        )));
    }

    let pk = [0xAAu8; 32]; // dummy bridge static pk - auth always fails
    let mut elapsed_ms = Vec::with_capacity(n_probes);

    for _ in 0..n_probes {
        let (mut a, mut b) = tokio::io::duplex(1024);
        let garbage = [0u8; 64];
        a.write_all(&garbage).await?;
        a.flush().await?;
        let start = Instant::now();
        let _ = obfs_server_authenticate(&mut b, &pk, None, Duration::from_secs(10)).await;
        let elapsed = start.elapsed();
        elapsed_ms.push(elapsed.as_millis() as u64);
    }

    elapsed_ms.sort_unstable();
    let p99 = elapsed_ms[(n_probes * 99) / 100];
    let median = elapsed_ms[n_probes / 2];

    // Defense holds if p99 close time is within the jitter
    // window + a small slack for scheduler overhead (50ms).
    let ceiling = OBFS_AUTH_FAIL_JITTER_MAX.as_millis() as u64 + 50;
    if p99 > ceiling {
        return Ok(DetectionVerdict::Distinguished(format!(
            "p99 close time {p99}ms exceeds ceiling {ceiling}ms - \
             tarpit detected. Check OBFS_AUTH_FAIL_JITTER_MAX and \
             obfs_server_authenticate's jitter path."
        )));
    }
    // Sanity: median should be in the same range as p99 - a
    // bimodal distribution (some fast, some slow) is also a
    // distinguisher.
    if median.saturating_mul(10) < p99 {
        return Ok(DetectionVerdict::Distinguished(format!(
            "bimodal close-time distribution (median {median}ms, \
             p99 {p99}ms) - censor can bucket by mode."
        )));
    }
    Ok(DetectionVerdict::Defended)
}

/// Boxed [`Adversary`] wrapper.
pub struct TarpitTimingOracle {
    /// Number of garbage probes to send.
    pub n_probes: usize,
}

#[async_trait::async_trait]
impl crate::Adversary for TarpitTimingOracle {
    async fn run(&self) -> Result<DetectionVerdict, AdversaryError> {
        tarpit_timing_oracle(self.n_probes).await
    }
    fn name(&self) -> &'static str {
        "tarpit_timing_oracle"
    }
    fn defense(&self) -> &'static str {
        "RT-CN-3: fast-close jitter window in obfs_server_authenticate"
    }
}
