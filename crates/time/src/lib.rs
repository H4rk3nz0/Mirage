//! Hardened time source for Mirage clients.
//!
//! # Status: WIRED (live)
//!
//! The client runs a one-shot clock-skew pin at startup (`client::main::
//! pin_clock_offset`, before any epoch-derived discovery): it gathers
//! HTTPS-`Date` readings via [`fetch_https_date`] from the hosts it is ALREADY
//! configured to contact (its nostr relays, the DoH/meek CDN fronts), computes a
//! [`consensus`], routes the OS clock through [`check_local_time`], and applies
//! the correction to every `epoch_for_time` call. Because the probes reuse hosts
//! the client already talks to (an ordinary `GET /`), they add no new
//! hardcoded-host signature. Fail-open on availability (no reachable source ->
//! OS clock, with a warning); fail-closed on a gross skew that only < 3 sources
//! could confirm (refuse, rather than trust a possibly-poisoned single source).
//!
//! # Why
//!
//! Mirage discovery info-hashes are derived from `floor(t / 3600)`
//! (epoch). A user on a hostile network whose NTP source is poisoned
//! by 2+ hours lands on the wrong epoch and sees no announcements -
//! "all channels failed" is indistinguishable from "operator gone
//! offline." This is a silent denial-of-service against discovery.
//!
//! The defense is multi-source time consensus: the client compares
//! the OS system time against a list of pinned external sources
//! (HTTPS Date headers from major sites, Tor consensus time,
//! optionally a DoH-over-CDN time query). If the OS clock deviates
//! from the consensus by more than [`SKEW_WARN_THRESHOLD_SECS`]
//! (5 minutes), the client warns and SHOULD use the consensus for
//! epoch derivation. If the deviation exceeds
//! [`SKEW_REFUSE_THRESHOLD_SECS`] (24 h), the client refuses to
//! enter a discovery loop - the user gets a loud failure rather
//! than a silent NTP-attack victim.
//!
//! # Architecture
//!
//! The consensus/threshold logic ([`consensus`], [`check_local_time`],
//! [`SourceReading`], [`TimeSource`]) is **pure and dependency-free** - the
//! default build has no I/O. The reference HTTPS-`Date` source
//! ([`fetch_https_date`]) is behind the optional **`net`** feature (pulls the
//! workspace `tokio-rustls` stack); the client enables it and points it at hosts
//! it already contacts. v0.2 can add Tor-consensus / signed-NTP sources the same
//! way (implement [`TimeSource`] or return a [`SourceReading`]).

#![forbid(unsafe_code)]

use std::time::Duration;
use thiserror::Error;

/// Local-clock vs. consensus deviation that triggers a warning to
/// the user. 5 minutes is generous for normal NTP drift but tight
/// enough to surface a deliberate skew attack quickly.
pub const SKEW_WARN_THRESHOLD_SECS: u64 = 300;

/// Local-clock vs. consensus deviation that causes the client to
/// REFUSE to enter a discovery loop. 24 h is well past any
/// plausible accidental drift and well under most epoch-rotation
/// windows; landing here is a loud signal of attack or
/// misconfiguration.
pub const SKEW_REFUSE_THRESHOLD_SECS: u64 = 24 * 3600;

/// Recommended minimum number of independent time sources for a
/// production deployment. Two sources only catches gross outliers;
/// three is the smallest set that supports majority-consensus.
pub const MIN_RECOMMENDED_SOURCES: usize = 3;

/// Hard cap on the freshness of a single source's reading before the
/// consensus algorithm refuses to use it. A reading older than this
/// is treated as missing.
pub const SOURCE_FRESHNESS_CEILING: Duration = Duration::from_secs(15 * 60);

/// Errors produced by [`TimePin`].
#[derive(Debug, Error)]
pub enum TimePinError {
    /// Local clock is more than [`SKEW_REFUSE_THRESHOLD_SECS`]
    /// off the consensus. The client SHOULD refuse to continue.
    #[error("clock skew {0}s exceeds refuse threshold {SKEW_REFUSE_THRESHOLD_SECS}s")]
    SkewExceeded(u64),

    /// Fewer than 1 fresh source returned a reading; consensus is
    /// not computable. Distinct from [`Self::SkewExceeded`] so
    /// callers can distinguish "all sources offline" (transient,
    /// retry) from "clock is wrong" (loud failure).
    #[error("no fresh time sources available")]
    NoFreshSources,
}

/// One observation from a pinned time source.
#[derive(Debug, Clone, Copy)]
pub struct SourceReading {
    /// The source's reported Unix time in seconds.
    pub unix_secs: u64,
    /// Local monotonic-since-epoch when the reading was taken.
    /// Used to age the reading; a reading older than
    /// [`SOURCE_FRESHNESS_CEILING`] is treated as missing.
    pub observed_at_unix: u64,
}

impl SourceReading {
    /// True iff this reading is fresh relative to `now_unix`.
    pub fn is_fresh(&self, now_unix: u64) -> bool {
        let age = now_unix.saturating_sub(self.observed_at_unix);
        age <= SOURCE_FRESHNESS_CEILING.as_secs()
    }
}

/// Pluggable time source.
///
/// Implementations are responsible for fetching a Unix timestamp
/// from somewhere - an HTTPS Date header, Tor consensus, a
/// pinned-DoH time query, etc. The Mirage client wires up a small
/// set per deployment.
///
/// The trait is intentionally synchronous: callers fetch all
/// sources in parallel via `tokio::join!` or similar at the call
/// site; the consensus algorithm itself is pure.
pub trait TimeSource: Send + Sync {
    /// Stable name for diagnostics ("https-date:cloudflare.com",
    /// "tor-consensus", etc.).
    fn name(&self) -> &str;

    /// Most recent reading from this source, or `None` if the
    /// source has never reported or its last reading is stale.
    fn last_reading(&self) -> Option<SourceReading>;
}

/// Pin source readings into a consensus.
///
/// Algorithm:
/// 1. Drop any reading older than [`SOURCE_FRESHNESS_CEILING`].
/// 2. Sort the remaining readings by Unix time.
/// 3. Median is the consensus (robust to single-source attacks
///    when >= 3 sources are available).
/// 4. With 1 or 2 fresh sources, return the youngest (newest) -
///    a single attacker can shift this, so callers SHOULD ensure
///    at least 3 sources in production.
///
/// The function is pure; pass `now_unix` from `SystemTime::now()`
/// or any other clock at the call site.
pub fn consensus<R: AsRef<[SourceReading]>>(readings: R, now_unix: u64) -> Option<u64> {
    let mut fresh: Vec<u64> = readings
        .as_ref()
        .iter()
        .filter(|r| r.is_fresh(now_unix))
        .map(|r| r.unix_secs)
        .collect();
    if fresh.is_empty() {
        return None;
    }
    fresh.sort_unstable();
    Some(fresh[fresh.len() / 2])
}

/// Compare local time against the consensus.
///
/// Returns:
/// - `Ok(local_unix)` if deviation is within
///   [`SKEW_WARN_THRESHOLD_SECS`].
/// - `Ok(consensus_unix)` if deviation is between WARN and REFUSE,
///   with a `tracing::warn!` emitted (caller's logger picks it up).
/// - `Err(TimePinError::SkewExceeded)` if deviation exceeds
///   [`SKEW_REFUSE_THRESHOLD_SECS`]. Caller MUST refuse the
///   discovery loop.
/// - `Err(TimePinError::NoFreshSources)` if `consensus` returned
///   `None`.
pub fn check_local_time(local_unix: u64, consensus_unix: Option<u64>) -> Result<u64, TimePinError> {
    let Some(c) = consensus_unix else {
        return Err(TimePinError::NoFreshSources);
    };
    let dev = local_unix.abs_diff(c);
    if dev > SKEW_REFUSE_THRESHOLD_SECS {
        return Err(TimePinError::SkewExceeded(dev));
    }
    if dev > SKEW_WARN_THRESHOLD_SECS {
        tracing::warn!(
            local_unix,
            consensus_unix = c,
            deviation_secs = dev,
            "local clock deviates from pinned consensus; using consensus for epoch derivation"
        );
        return Ok(c);
    }
    Ok(local_unix)
}

/// Parse an HTTP `Date` header value (RFC 7231 IMF-fixdate, e.g.
/// `Sun, 06 Nov 1994 08:49:37 GMT`) into Unix seconds. Returns `None` on any
/// malformed field. Pure - no allocation of a date library, no `chrono`.
pub fn parse_http_date(value: &str) -> Option<u64> {
    // "<day-name>, DD Mon YYYY HH:MM:SS GMT"
    let after_comma = value.trim().split_once(", ")?.1;
    let mut fields = after_comma.split_whitespace();
    let day: i64 = fields.next()?.parse().ok()?;
    let month: i64 = match fields.next()? {
        "Jan" => 1,
        "Feb" => 2,
        "Mar" => 3,
        "Apr" => 4,
        "May" => 5,
        "Jun" => 6,
        "Jul" => 7,
        "Aug" => 8,
        "Sep" => 9,
        "Oct" => 10,
        "Nov" => 11,
        "Dec" => 12,
        _ => return None,
    };
    let year: i64 = fields.next()?.parse().ok()?;
    let mut hms = fields.next()?.split(':');
    let hour: i64 = hms.next()?.parse().ok()?;
    let min: i64 = hms.next()?.parse().ok()?;
    let sec: i64 = hms.next()?.parse().ok()?;
    if !(1..=31).contains(&day)
        || !(0..24).contains(&hour)
        || !(0..60).contains(&min)
        || !(0..=60).contains(&sec)
    {
        return None;
    }
    // days_from_civil (Howard Hinnant's algorithm) -> days since 1970-01-01.
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400; // [0, 399]
    let mp = if month > 2 { month - 3 } else { month + 9 }; // Mar=0..Feb=11
    let doy = (153 * mp + 2) / 5 + day - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    let days = era * 146_097 + doe - 719_468;
    let secs = days * 86400 + hour * 3600 + min * 60 + sec;
    u64::try_from(secs).ok()
}

/// Fetch a [`SourceReading`] from a host's HTTPS `Date` response header.
///
/// Speaks a minimal, browser-shaped `GET /` over the workspace `tokio-rustls`
/// stack and reads only the response headers. Intended to be pointed at hosts
/// the client ALREADY contacts (its configured discovery relays / `DoH` front /
/// Reality cover) so it introduces no new hardcoded-host signature; the request
/// itself is an ordinary `GET /` a browser would make to that host.
///
/// Returns `None` on any connect/TLS/parse failure or timeout - the caller
/// treats a missing reading as "source offline", never as a clock error.
pub async fn fetch_https_date(
    host: &str,
    port: u16,
    timeout: std::time::Duration,
    now_unix: u64,
) -> Option<SourceReading> {
    use std::sync::Arc;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_rustls::rustls::pki_types::ServerName;
    use tokio_rustls::rustls::{ClientConfig, RootCertStore};
    use tokio_rustls::TlsConnector;

    let attempt = async {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        // rustls is pinned to the ring provider workspace-wide.
        let provider = Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
        let cfg = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .ok()?
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(cfg));
        let server_name = ServerName::try_from(host.to_string()).ok()?;
        let tcp = tokio::net::TcpStream::connect((host, port)).await.ok()?;
        let mut tls = connector.connect(server_name, tcp).await.ok()?;

        let req = format!(
            "GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\n\
             Accept: */*\r\nConnection: close\r\n\r\n"
        );
        tls.write_all(req.as_bytes()).await.ok()?;
        tls.flush().await.ok()?;

        // Read only the response headers (bounded - we never touch the body).
        let mut buf: Vec<u8> = Vec::with_capacity(2048);
        let mut tmp = [0u8; 1024];
        loop {
            let n = tls.read(&mut tmp).await.ok()?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&tmp[..n]);
            if buf.windows(4).any(|w| w == b"\r\n\r\n") || buf.len() > 8192 {
                break;
            }
        }
        let text = String::from_utf8_lossy(&buf);
        for line in text.lines() {
            if line.len() >= 5 && line[..5].eq_ignore_ascii_case("date:") {
                if let Some(unix_secs) = parse_http_date(line[5..].trim()) {
                    return Some(SourceReading {
                        unix_secs,
                        observed_at_unix: now_unix,
                    });
                }
            }
        }
        None
    };

    tokio::time::timeout(timeout, attempt).await.ok().flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_http_date_rfc7231_examples() {
        // RFC 7231 §7.1.1.1 canonical example -> known Unix time.
        assert_eq!(
            parse_http_date("Sun, 06 Nov 1994 08:49:37 GMT"),
            Some(784111777)
        );
        // Unix epoch.
        assert_eq!(parse_http_date("Thu, 01 Jan 1970 00:00:00 GMT"), Some(0));
        // A recent date.
        assert_eq!(
            parse_http_date("Wed, 21 Oct 2015 07:28:00 GMT"),
            Some(1445412480)
        );
        // Malformed / partial inputs return None (never a bogus time).
        assert_eq!(parse_http_date("not a date"), None);
        assert_eq!(parse_http_date("Sun, 06 Zzz 1994 08:49:37 GMT"), None);
        assert_eq!(parse_http_date("Sun, 32 Nov 1994 08:49:37 GMT"), None);
        assert_eq!(parse_http_date(""), None);
    }

    fn r(unix_secs: u64, observed_at_unix: u64) -> SourceReading {
        SourceReading {
            unix_secs,
            observed_at_unix,
        }
    }

    #[test]
    fn consensus_uses_median_with_three_sources() {
        let readings = [r(1000, 100), r(2000, 100), r(1500, 100)];
        let now = 100;
        // Median of [1000, 1500, 2000] is 1500.
        assert_eq!(consensus(readings, now), Some(1500));
    }

    #[test]
    fn consensus_drops_stale_readings() {
        // First reading is older than the freshness ceiling and
        // MUST be excluded; median of remaining {2000, 3000} is 3000.
        let now = SOURCE_FRESHNESS_CEILING.as_secs() + 10;
        let readings = [
            r(1000, 0),   // stale
            r(2000, now), // fresh
            r(3000, now), // fresh
        ];
        // Median of [2000, 3000] (even count, picks index = len/2 = 1) = 3000.
        assert_eq!(consensus(readings, now), Some(3000));
    }

    #[test]
    fn consensus_returns_none_if_all_stale() {
        let now = SOURCE_FRESHNESS_CEILING.as_secs() + 10;
        let readings = [r(1000, 0), r(2000, 0)];
        assert_eq!(consensus(readings, now), None);
    }

    #[test]
    fn check_local_time_within_warn() {
        // 60s deviation: within warn threshold; returns local.
        let r = check_local_time(1_000_000, Some(999_940)).unwrap();
        assert_eq!(r, 1_000_000);
    }

    #[test]
    fn check_local_time_warn_zone_uses_consensus() {
        // 6 minutes deviation: above warn (5 min) but below refuse (24 h).
        // SHOULD return consensus, not local.
        let local = 1_000_000u64;
        let consensus = local + 6 * 60;
        let r = check_local_time(local, Some(consensus)).unwrap();
        assert_eq!(
            r, consensus,
            "warn-zone uses consensus for epoch derivation"
        );
    }

    #[test]
    fn check_local_time_refuse_zone_errors() {
        // 25 h deviation: above refuse threshold; MUST error.
        let local = 1_000_000u64;
        let consensus = local + 25 * 3600;
        let err = check_local_time(local, Some(consensus)).unwrap_err();
        assert!(matches!(err, TimePinError::SkewExceeded(_)));
    }

    #[test]
    fn check_local_time_no_consensus_errors() {
        let err = check_local_time(1_000_000, None).unwrap_err();
        assert!(matches!(err, TimePinError::NoFreshSources));
    }

    #[test]
    fn check_local_time_bidirectional_deviation() {
        // Test both forward and backward skew.
        let local = 1_000_000u64;
        // local AHEAD of consensus by 25 h: refuse.
        assert!(matches!(
            check_local_time(local, Some(local - 25 * 3600)).unwrap_err(),
            TimePinError::SkewExceeded(_)
        ));
        // local BEHIND consensus by 25 h: refuse.
        assert!(matches!(
            check_local_time(local, Some(local + 25 * 3600)).unwrap_err(),
            TimePinError::SkewExceeded(_)
        ));
    }
}
