//! Per-source-IP rate limit + concurrent-connection cap.
//!
//! Purpose: prevent a single client IP from
//!
//! - overwhelming the bridge's handshake path by opening connections
//!   faster than legitimate use (`rate_limit_per_ip_per_minute`), or
//! - tying up bridge-side resources by holding many concurrent
//!   half-open or idle sessions (`max_concurrent_per_ip`).
//!
//! A rejected connection is dropped at the TCP-accept boundary,
//! BEFORE any Reality probe or Mirage handshake work runs. This is
//! the cheapest defense - the bridge burns only a TCP socket's worth
//! of kernel state plus the HashMap lookup, not a ClientHello parse
//! and a probe MAC verify.
//!
//! Algorithm: token-bucket per IP with lazy refill.
//!
//! - Each `IpAddr` has a `Bucket { tokens: f64, last_refill: Instant,
//!   concurrent: usize }`.
//! - On `try_acquire(ip)`: refill tokens proportional to elapsed time
//!   (clamped to `capacity`), then check `concurrent < max_concurrent`
//!   AND `tokens >= 1.0`. If OK: decrement tokens, increment
//!   concurrent, return a `Guard` that decrements concurrent on drop.
//! - When the map exceeds `max_entries`, evict the oldest-seen entry
//!   (simple scan; acceptable at realistic map sizes).
//!
//! Thread-safety: wrapped in `std::sync::Mutex` - critical section is
//! a hashmap lookup + numeric update (sub-microsecond), so the
//! sync mutex beats `tokio::sync::Mutex`'s allocation overhead.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// A decrement-on-drop handle held for the lifetime of a session.
/// Dropping it releases the concurrent-session slot for the peer.
pub struct PeerGuard {
    limiter: Arc<PerPeerLimiter>,
    ip: IpAddr,
}

impl Drop for PeerGuard {
    fn drop(&mut self) {
        // Recover from a poisoned mutex here too: if Drop fails to
        // decrement because of a prior panic, the concurrent slot
        // would leak and legitimate sessions would get cap-rejected
        // until restart. `into_inner()` accepts possibly-stale
        // state but keeps the counter honest.
        let mut map = match self.limiter.buckets.lock() {
            Ok(m) => m,
            Err(p) => p.into_inner(),
        };
        if let Some(b) = map.get_mut(&self.ip) {
            b.concurrent = b.concurrent.saturating_sub(1);
        }
    }
}

/// Per-source-IP limiter.
pub struct PerPeerLimiter {
    buckets: Mutex<HashMap<IpAddr, Bucket>>,
    /// Max tokens held per IP (burst size).
    capacity: f64,
    /// Tokens added per second (steady-state rate).
    refill_per_sec: f64,
    /// Max concurrent open sessions per IP.
    max_concurrent: usize,
    /// Soft cap on the total number of IPs we track. When exceeded,
    /// we evict the oldest-seen entry on insert.
    max_entries: usize,
}

struct Bucket {
    tokens: f64,
    last_refill: Instant,
    last_seen: Instant,
    concurrent: usize,
}

impl PerPeerLimiter {
    /// Construct a limiter. `per_minute = 0` disables rate-limiting
    /// (always accepts new connections); `max_concurrent = 0`
    /// disables the concurrent-session cap.
    pub fn new(per_minute: u32, max_concurrent: usize, max_entries: usize) -> Self {
        let refill_per_sec = per_minute as f64 / 60.0;
        // Burst capacity matches the per-minute budget: a client can
        // reconnect up to `per_minute` times in a burst, then must
        // refill. This is a reasonable default.
        let capacity = (per_minute as f64).max(1.0);
        Self {
            buckets: Mutex::new(HashMap::new()),
            capacity,
            refill_per_sec,
            max_concurrent,
            max_entries,
        }
    }

    /// Attempt to acquire a slot for `ip`. Returns `Some(guard)` on
    /// success - the caller holds the guard for the session's
    /// lifetime; its `Drop` releases the concurrent slot. Returns
    /// `None` on rate-limit or concurrency-cap rejection.
    pub fn try_acquire(self: &Arc<Self>, ip: IpAddr) -> Option<PeerGuard> {
        // Lock, recovering from panic poisoning. The internal state
        // is just numeric counters and timestamps - a panic cannot
        // have left them in a semantically invalid shape, only in a
        // possibly-stale one (e.g., a concurrent counter that is
        // one too low because Drop didn't run). Recovering via
        // `into_inner()` is safer than either fail-closed (reject
        // all traffic after one panic) or fail-open (disable rate
        // limiting bridge-wide after one panic - what the earlier
        // version did, caught in RT-rl-1).
        let mut map = match self.buckets.lock() {
            Ok(m) => m,
            Err(poisoned) => poisoned.into_inner(),
        };

        let now = Instant::now();

        // GC: if map is over cap, evict the oldest IDLE entry. The
        // earlier "find absolute-oldest, evict only if idle" was
        // exploitable: an attacker holding ANY session open made the
        // oldest-seen entry permanently live, so the eviction was
        // skipped on every acquire and the map grew unbounded. Now:
        // skip live entries while searching, fail-closed if no idle
        // slot exists.
        if map.len() >= self.max_entries && !map.contains_key(&ip) {
            // RT #18: bound the eviction scan. A full `min_by_key` over the
            // whole map ran on EVERY new-IP accept once full - i.e. O(n) per
            // connection under a distinct-IP flood, the exact scenario that
            // fills the map, amplifying lock-hold time on the hot accept path.
            // Approximate-LRU instead: examine only the first EVICT_SAMPLE
            // entries and evict the oldest IDLE among them (O(SAMPLE)). Only
            // if the sample contains NO idle entry do we fall back to the full
            // scan, preserving the exact fail-closed-when-every-entry-is-live
            // guarantee (no premature rejection while an idle slot exists).
            const EVICT_SAMPLE: usize = 32;
            let sampled = map
                .iter()
                .take(EVICT_SAMPLE)
                .filter(|(_, b)| b.concurrent == 0)
                .min_by_key(|(_, b)| b.last_seen)
                .map(|(k, _)| *k);
            let victim = sampled.or_else(|| {
                map.iter()
                    .filter(|(_, b)| b.concurrent == 0)
                    .min_by_key(|(_, b)| b.last_seen)
                    .map(|(k, _)| *k)
            });
            match victim {
                Some(k) => {
                    map.remove(&k);
                }
                None => {
                    // Map is full and every entry is live. Fail-closed:
                    // refuse the new IP. This surfaces as a connection
                    // rejection at the bridge, not a memory blowup.
                    return None;
                }
            }
        }

        let b = map.entry(ip).or_insert_with(|| Bucket {
            tokens: self.capacity,
            last_refill: now,
            last_seen: now,
            concurrent: 0,
        });

        // Refill tokens proportional to elapsed time.
        let elapsed = now.duration_since(b.last_refill).as_secs_f64();
        b.tokens = (b.tokens + elapsed * self.refill_per_sec).min(self.capacity);
        b.last_refill = now;
        b.last_seen = now;

        // Concurrent-session cap (0 = disabled).
        if self.max_concurrent > 0 && b.concurrent >= self.max_concurrent {
            return None;
        }

        // Token-bucket check. refill_per_sec == 0 disables rate-limit.
        if self.refill_per_sec > 0.0 {
            if b.tokens < 1.0 {
                return None;
            }
            b.tokens -= 1.0;
        }

        b.concurrent += 1;

        Some(PeerGuard {
            limiter: Arc::clone(self),
            ip,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::thread;
    use std::time::Duration;

    fn ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
    }

    #[test]
    fn disabled_limiter_always_accepts() {
        let l = Arc::new(PerPeerLimiter::new(0, 0, 1024));
        for _ in 0..1000 {
            assert!(l.try_acquire(ip()).is_some());
        }
    }

    #[test]
    fn rate_limit_rejects_over_burst() {
        // 5 per minute; once 5 are consumed, next fails until refill.
        let l = Arc::new(PerPeerLimiter::new(5, 0, 1024));
        let guards: Vec<_> = (0..5).map(|_| l.try_acquire(ip())).collect();
        for g in &guards {
            assert!(g.is_some(), "first 5 must succeed");
        }
        // 6th within the same instant: bucket empty -> reject.
        assert!(l.try_acquire(ip()).is_none(), "6th must be rate-limited");
    }

    #[test]
    fn concurrent_cap_enforced() {
        let l = Arc::new(PerPeerLimiter::new(1000, 2, 1024));
        let g1 = l.try_acquire(ip()).expect("first");
        let g2 = l.try_acquire(ip()).expect("second");
        // Third concurrent: cap = 2 -> reject.
        assert!(l.try_acquire(ip()).is_none());
        // Release one -> slot opens.
        drop(g1);
        assert!(l.try_acquire(ip()).is_some());
        drop(g2);
    }

    #[test]
    fn guard_drop_releases_slot() {
        let l = Arc::new(PerPeerLimiter::new(1000, 1, 1024));
        let g = l.try_acquire(ip()).unwrap();
        assert!(l.try_acquire(ip()).is_none(), "cap of 1");
        drop(g);
        assert!(l.try_acquire(ip()).is_some(), "slot released");
    }

    #[test]
    fn different_ips_are_isolated() {
        let l = Arc::new(PerPeerLimiter::new(1, 0, 1024));
        let ip_a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let ip_b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        assert!(l.try_acquire(ip_a).is_some());
        assert!(l.try_acquire(ip_a).is_none(), "A is empty");
        // B has its own bucket, full.
        assert!(l.try_acquire(ip_b).is_some());
    }

    #[test]
    fn tokens_refill_with_time() {
        // 60 per minute = 1 per second. Burst 60, consume 60, wait
        // 200 ms -> at least 1 refilled.
        let l = Arc::new(PerPeerLimiter::new(60, 0, 1024));
        for _ in 0..60 {
            assert!(l.try_acquire(ip()).is_some());
        }
        assert!(l.try_acquire(ip()).is_none(), "burst exhausted");
        thread::sleep(Duration::from_millis(1100));
        assert!(l.try_acquire(ip()).is_some(), "refilled after 1s");
    }

    #[test]
    fn recovers_from_poisoned_mutex() {
        // Regression for RT-rl-1: the earlier implementation
        // returned an unconditional `Some(guard)` on a poisoned
        // mutex, effectively disabling rate-limiting bridge-wide
        // after one panic. The fixed implementation recovers via
        // `PoisonError::into_inner()` and continues enforcing the
        // cap.
        use std::panic;

        let l = Arc::new(PerPeerLimiter::new(2, 0, 1024));
        // Consume the burst so the next call MUST reject if the
        // limiter is actually running.
        assert!(l.try_acquire(ip()).is_some());
        assert!(l.try_acquire(ip()).is_some());

        // Poison the mutex by panicking while holding it.
        let l_for_poison = Arc::clone(&l);
        let _ = panic::catch_unwind(panic::AssertUnwindSafe(move || {
            let _guard = l_for_poison.buckets.lock().unwrap();
            panic!("poison");
        }));
        assert!(l.buckets.is_poisoned(), "mutex was not poisoned");

        // Recovery path: state is preserved, bucket is empty, so
        // the next acquire must still reject (fail-closed), not
        // silently bypass.
        assert!(
            l.try_acquire(ip()).is_none(),
            "post-poison acquire must still enforce the cap"
        );
    }

    #[test]
    fn evicts_oldest_idle_entry_at_cap() {
        // Cap of 2 entries. Fill with two idle IPs, then a third
        // request should cause eviction of the oldest (no concurrent
        // guards held).
        let l = Arc::new(PerPeerLimiter::new(1000, 0, 2));
        let ip_a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let ip_b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let ip_c = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
        drop(l.try_acquire(ip_a).unwrap()); // idle now
        thread::sleep(Duration::from_millis(5));
        drop(l.try_acquire(ip_b).unwrap()); // idle now
        thread::sleep(Duration::from_millis(5));
        drop(l.try_acquire(ip_c).unwrap()); // should evict ip_a
        let map = l.buckets.lock().unwrap();
        assert!(map.len() <= 2, "cap honored");
        assert!(!map.contains_key(&ip_a) || map.contains_key(&ip_b));
    }

    #[test]
    fn live_oldest_does_not_block_eviction_of_idle() {
        // Regression for the audit finding "PerPeerLimiter map grows
        // past max_entries when oldest entry is live". Earlier code
        // looked only at the absolute-oldest entry; if that one was
        // live, eviction was skipped and the map grew unbounded under
        // a slow attacker holding any session open.
        // Now: the search filters out live entries.
        let l = Arc::new(PerPeerLimiter::new(1000, 4, 2));
        let ip_a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let ip_b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let ip_c = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
        // ip_a is the oldest AND held live for the duration.
        let _hold = l.try_acquire(ip_a).expect("acquire ip_a");
        thread::sleep(Duration::from_millis(5));
        drop(l.try_acquire(ip_b).expect("acquire ip_b")); // idle now
        thread::sleep(Duration::from_millis(5));
        // Acquire ip_c: cap=2 reached, ip_a is live, ip_b is idle.
        // Must evict ip_b (oldest idle), not block.
        assert!(l.try_acquire(ip_c).is_some());
        let map = l.buckets.lock().unwrap();
        assert!(map.len() <= 2, "cap honored when oldest is live");
        assert!(map.contains_key(&ip_a), "live ip_a retained");
        assert!(map.contains_key(&ip_c), "new ip_c admitted");
    }

    #[test]
    fn rejects_when_all_entries_live_at_cap() {
        // If every slot is occupied by a live session, fail-closed
        // rather than silently grow the map.
        let l = Arc::new(PerPeerLimiter::new(1000, 4, 2));
        let ip_a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let ip_b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let ip_c = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
        let _ga = l.try_acquire(ip_a).unwrap();
        let _gb = l.try_acquire(ip_b).unwrap();
        // Both slots live, cap reached.
        assert!(
            l.try_acquire(ip_c).is_none(),
            "must fail-closed when all slots live"
        );
        let map = l.buckets.lock().unwrap();
        assert!(map.len() <= 2, "no unbounded growth");
    }
}
