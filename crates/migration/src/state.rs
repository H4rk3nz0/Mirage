//! Migration state machine.
//!
//! ```text
//!   Active(addrA) --packet from addrB--> ChallengingNew(addrB)
//!         |                                       |
//!         |                                       | valid response
//!         |                                       v
//!         |                                 Active(addrB), addrA -> Retired
//!         |
//!         +-migration-rate exceeded--> Closed
//! ```
//!
//! State per connection is `(active_path, challenging_paths)`.
//! When a packet arrives on a non-active path, we issue a
//! `PathChallenge` and store it in `challenging`. When the matching
//! `PathResponse` arrives within the timeout, we promote the path.

use crate::challenge::PathChallenge;
use crate::policy::MigrationPolicy;
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::time::Instant;
use thiserror::Error;

/// Per-path validation state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathState {
    /// Path is the live one; data flows here.
    Active,
    /// `PathChallenge` issued; awaiting `PathResponse`.
    Challenging,
    /// Was active; replaced by a newer path. Held briefly so
    /// in-flight packets on the old path don't drop on the floor.
    Retiring,
}

/// Errors produced by the state machine.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum MigrationError {
    /// Migration-rate cap exceeded. Caller MUST tear down the
    /// connection.
    #[error("migration rate exceeded ({0}/min)")]
    RateLimit(u32),
    /// Caller fed a `PathResponse` that doesn't match any
    /// outstanding challenge.
    #[error("no outstanding challenge matches the response")]
    UnmatchedResponse,
    /// CSPRNG failed when generating a challenge.
    #[error("CSPRNG failure")]
    Csprng,
}

/// Decision the state machine emits per inbound observation.
///
/// `PartialEq`/`Eq` are intentionally NOT derived because the
/// `NewChallenge` variant carries a [`PathChallenge`] whose bytes
/// must only be compared in constant time. Tests and callers use
/// `matches!(...)` to discriminate variants.
#[derive(Debug, Clone)]
pub enum MigrationDecision {
    /// Packet was on the active path; just process it.
    Active,
    /// Packet arrived on a new path; the state machine emitted a
    /// `PathChallenge` (caller MUST send it on the new path) and
    /// is now awaiting a `PathResponse`.
    NewChallenge {
        /// New path address.
        path: SocketAddr,
        /// Challenge bytes the caller sends.
        challenge: PathChallenge,
    },
    /// `PathResponse` validated a challenging path; that path is
    /// now active; the prior active path is retiring.
    Migrated {
        /// New active path.
        new_active: SocketAddr,
        /// Old path being retired.
        retiring: SocketAddr,
    },
    /// Packet was on a still-challenging path; caller waits.
    StillChallenging,
}

/// Migration state for one connection.
#[derive(Debug)]
pub struct MigrationState {
    policy: MigrationPolicy,
    /// Active path; data flows here.
    active: SocketAddr,
    /// Outstanding challenges, with timestamp. Bounded; we cap at
    /// 4 simultaneous challenges (more than that is suspicious).
    challenging: Vec<(SocketAddr, PathChallenge, Instant)>,
    /// Recently-completed migration timestamps for rate limiting.
    recent_migrations: VecDeque<Instant>,
    /// Path being retired plus the instant retirement began. The
    /// path stays in the "drain in-flight" state for
    /// `policy.retirement_grace`, then is forgotten. Without this
    /// auto-expiry, a single migration would pin one slot until
    /// the caller manually invoked `finalize_retirement` - easy
    /// to forget, and stale state piles up under churn.
    retiring: Option<(SocketAddr, Instant)>,
}

const MAX_SIMULTANEOUS_CHALLENGES: usize = 4;

impl MigrationState {
    /// Construct. `initial_path` is the path the connection was
    /// established on.
    pub fn new(policy: MigrationPolicy, initial_path: SocketAddr) -> Self {
        Self {
            policy,
            active: initial_path,
            challenging: Vec::with_capacity(MAX_SIMULTANEOUS_CHALLENGES),
            recent_migrations: VecDeque::new(),
            retiring: None,
        }
    }

    /// Active path. Caller sends outgoing packets to this address.
    pub fn active_path(&self) -> SocketAddr {
        self.active
    }

    /// State for a given path. Returns `None` if the path is
    /// unknown OR the retirement grace has elapsed (after which a
    /// previously retiring path is fully forgotten).
    pub fn path_state(&self, addr: &SocketAddr) -> Option<PathState> {
        if *addr == self.active {
            return Some(PathState::Active);
        }
        if self.challenging.iter().any(|(a, _, _)| a == addr) {
            return Some(PathState::Challenging);
        }
        if let Some((retiring_addr, _)) = self.retiring {
            if retiring_addr == *addr {
                return Some(PathState::Retiring);
            }
        }
        None
    }

    /// Process an inbound packet from `from_addr`. The state
    /// machine decides whether it's on the active path, a new
    /// path that needs challenging, or a still-challenging path.
    pub fn observe_inbound(
        &mut self,
        from_addr: SocketAddr,
        now: Instant,
    ) -> Result<MigrationDecision, MigrationError> {
        // Garbage-collect retired paths whose grace has elapsed.
        // Done up-front so subsequent comparisons treat the slot
        // as empty.
        self.expire_retiring(now);
        // Active path: just data.
        if from_addr == self.active {
            return Ok(MigrationDecision::Active);
        }
        // Still-challenging path: ignore, caller waits.
        if self.challenging.iter().any(|(a, _, _)| *a == from_addr) {
            return Ok(MigrationDecision::StillChallenging);
        }
        // Retiring path: in-flight packets are still authenticated
        // by the session-frame AEAD; we drain them as `Active` so
        // they aren't lost. After `policy.retirement_grace` the
        // slot is cleared and the next packet from the same address
        // falls through to the new-path challenge logic.
        if let Some((addr, _)) = self.retiring {
            if addr == from_addr {
                return Ok(MigrationDecision::Active);
            }
        }
        // New path. Rate-limit.
        self.expire_old_migrations(now);
        if self.recent_migrations.len() >= self.policy.max_migrations_per_min as usize {
            return Err(MigrationError::RateLimit(
                self.policy.max_migrations_per_min,
            ));
        }
        // Cap simultaneous challenges.
        if self.challenging.len() >= MAX_SIMULTANEOUS_CHALLENGES {
            // Drop the oldest challenge.
            self.challenging.remove(0);
        }
        let challenge = PathChallenge::random().ok_or(MigrationError::Csprng)?;
        self.challenging.push((from_addr, challenge, now));
        Ok(MigrationDecision::NewChallenge {
            path: from_addr,
            challenge,
        })
    }

    /// Process a `PathResponse` arriving on `from_addr`. If it
    /// matches an outstanding challenge for that address, the
    /// path is promoted. Caller MUST then route subsequent
    /// outbound traffic on the new path.
    pub fn observe_response(
        &mut self,
        from_addr: SocketAddr,
        response: crate::challenge::PathResponse,
        now: Instant,
    ) -> Result<MigrationDecision, MigrationError> {
        // Expire stale rate-limit entries BEFORE we push a new one.
        // Without this, `recent_migrations.len()` retained entries
        // older than the 60 s window forever - making the rate
        // limit grow tighter and tighter as the connection aged.
        self.expire_old_migrations(now);
        // Drop stale challenges past the validation timeout.
        let cutoff = now
            .checked_sub(self.policy.validation_timeout)
            .unwrap_or(now);
        self.challenging.retain(|(_, _, t)| *t >= cutoff);
        // Find a matching challenge for from_addr.
        let idx = self
            .challenging
            .iter()
            .position(|(a, c, _)| *a == from_addr && response.matches(c))
            .ok_or(MigrationError::UnmatchedResponse)?;
        let (new_active, _, _) = self.challenging.remove(idx);
        let retiring = std::mem::replace(&mut self.active, new_active);
        self.retiring = Some((retiring, now));
        self.recent_migrations.push_back(now);
        Ok(MigrationDecision::Migrated {
            new_active,
            retiring,
        })
    }

    /// Drop the retiring path (after enough time has passed for
    /// in-flight packets to drain). Idempotent.
    pub fn finalize_retirement(&mut self) {
        self.retiring = None;
    }

    fn expire_retiring(&mut self, now: Instant) {
        if let Some((_, started)) = self.retiring {
            if now.saturating_duration_since(started) >= self.policy.retirement_grace {
                self.retiring = None;
            }
        }
    }

    fn expire_old_migrations(&mut self, now: Instant) {
        let cutoff = now
            .checked_sub(std::time::Duration::from_secs(60))
            .unwrap_or(now);
        while let Some(t) = self.recent_migrations.front() {
            if *t < cutoff {
                self.recent_migrations.pop_front();
            } else {
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn addr(d: u8, p: u16) -> SocketAddr {
        SocketAddr::from((Ipv4Addr::new(10, 0, 0, d), p))
    }

    #[test]
    fn packet_on_active_path_is_active_decision() {
        let mut s = MigrationState::new(MigrationPolicy::default(), addr(1, 1000));
        let d = s.observe_inbound(addr(1, 1000), Instant::now()).unwrap();
        assert!(matches!(d, MigrationDecision::Active));
    }

    #[test]
    fn packet_on_new_path_emits_challenge() {
        let mut s = MigrationState::new(MigrationPolicy::default(), addr(1, 1000));
        match s.observe_inbound(addr(2, 2000), Instant::now()).unwrap() {
            MigrationDecision::NewChallenge { path, challenge: _ } => {
                assert_eq!(path, addr(2, 2000));
            }
            other => panic!("expected NewChallenge, got {other:?}"),
        }
        assert_eq!(s.path_state(&addr(2, 2000)), Some(PathState::Challenging));
    }

    #[test]
    fn valid_response_promotes_path_and_retires_old() {
        let now = Instant::now();
        let mut s = MigrationState::new(MigrationPolicy::default(), addr(1, 1000));
        let d = s.observe_inbound(addr(2, 2000), now).unwrap();
        let challenge = match d {
            MigrationDecision::NewChallenge { challenge, .. } => challenge,
            _ => unreachable!(),
        };
        let resp = challenge.to_response();
        let migrated = s.observe_response(addr(2, 2000), resp, now).unwrap();
        match migrated {
            MigrationDecision::Migrated {
                new_active,
                retiring,
            } => {
                assert_eq!(new_active, addr(2, 2000));
                assert_eq!(retiring, addr(1, 1000));
            }
            _ => panic!("expected Migrated"),
        }
        assert_eq!(s.active_path(), addr(2, 2000));
        assert_eq!(s.path_state(&addr(1, 1000)), Some(PathState::Retiring));
    }

    #[test]
    fn wrong_response_rejected() {
        let now = Instant::now();
        let mut s = MigrationState::new(MigrationPolicy::default(), addr(1, 1000));
        let _ = s.observe_inbound(addr(2, 2000), now).unwrap();
        // Forge a response with random bytes.
        let bogus = crate::challenge::PathResponse::from_bytes([0u8; 8]);
        let err = s.observe_response(addr(2, 2000), bogus, now).unwrap_err();
        assert_eq!(err, MigrationError::UnmatchedResponse);
        // Active path unchanged.
        assert_eq!(s.active_path(), addr(1, 1000));
    }

    #[test]
    fn migration_rate_limit_enforced() {
        let policy = MigrationPolicy {
            max_migrations_per_min: 2,
            ..MigrationPolicy::default()
        };
        let mut s = MigrationState::new(policy, addr(1, 1000));
        let mut now = Instant::now();
        // Two successful migrations.
        for tag in 2..=3u8 {
            let dec = s.observe_inbound(addr(tag, 1000), now).unwrap();
            let challenge = match dec {
                MigrationDecision::NewChallenge { challenge, .. } => challenge,
                _ => unreachable!(),
            };
            s.observe_response(addr(tag, 1000), challenge.to_response(), now)
                .unwrap();
            now += std::time::Duration::from_millis(10);
        }
        // Third migration attempt is rate-limited.
        let err = s.observe_inbound(addr(4, 1000), now).unwrap_err();
        assert!(matches!(err, MigrationError::RateLimit(2)));
    }

    #[test]
    fn challenging_path_redundant_packet_yields_still_challenging() {
        let mut s = MigrationState::new(MigrationPolicy::default(), addr(1, 1000));
        let now = Instant::now();
        s.observe_inbound(addr(2, 2000), now).unwrap();
        // Second packet on same not-yet-validated path.
        let d = s.observe_inbound(addr(2, 2000), now).unwrap();
        assert!(matches!(d, MigrationDecision::StillChallenging));
    }

    #[test]
    fn stale_response_rejected_as_unmatched() {
        let policy = MigrationPolicy {
            validation_timeout: std::time::Duration::from_millis(50),
            ..MigrationPolicy::default()
        };
        let mut s = MigrationState::new(policy, addr(1, 1000));
        let t0 = Instant::now();
        let dec = s.observe_inbound(addr(2, 2000), t0).unwrap();
        let challenge = match dec {
            MigrationDecision::NewChallenge { challenge, .. } => challenge,
            _ => unreachable!(),
        };
        // Response arrives well after the timeout.
        let t1 = t0 + std::time::Duration::from_millis(200);
        let err = s
            .observe_response(addr(2, 2000), challenge.to_response(), t1)
            .unwrap_err();
        assert_eq!(err, MigrationError::UnmatchedResponse);
    }

    #[test]
    fn finalize_retirement_clears_state() {
        let now = Instant::now();
        let mut s = MigrationState::new(MigrationPolicy::default(), addr(1, 1000));
        let dec = s.observe_inbound(addr(2, 2000), now).unwrap();
        let c = match dec {
            MigrationDecision::NewChallenge { challenge, .. } => challenge,
            _ => unreachable!(),
        };
        s.observe_response(addr(2, 2000), c.to_response(), now)
            .unwrap();
        assert_eq!(s.path_state(&addr(1, 1000)), Some(PathState::Retiring));
        s.finalize_retirement();
        assert_eq!(s.path_state(&addr(1, 1000)), None);
    }

    #[test]
    fn retiring_path_auto_clears_after_grace() {
        let policy = MigrationPolicy {
            retirement_grace: std::time::Duration::from_millis(100),
            ..MigrationPolicy::default()
        };
        let t0 = Instant::now();
        let mut s = MigrationState::new(policy, addr(1, 1000));
        // Migrate so addr(1) is retiring.
        let dec = s.observe_inbound(addr(2, 2000), t0).unwrap();
        let c = match dec {
            MigrationDecision::NewChallenge { challenge, .. } => challenge,
            _ => unreachable!(),
        };
        s.observe_response(addr(2, 2000), c.to_response(), t0)
            .unwrap();
        assert_eq!(s.path_state(&addr(1, 1000)), Some(PathState::Retiring));
        // After grace expires, the path is forgotten without a
        // manual finalize_retirement() call.
        let t1 = t0 + std::time::Duration::from_millis(200);
        let _ = s.observe_inbound(addr(3, 3000), t1).unwrap();
        assert_eq!(s.path_state(&addr(1, 1000)), None);
    }

    #[test]
    fn rate_limit_window_slides_in_observe_response() {
        // Pre-fix, observe_response pushed without expiring stale
        // entries. After the fix, migrations from > 60 s ago drop
        // out of the rolling window so a long-lived connection
        // doesn't get stuck.
        let policy = MigrationPolicy {
            max_migrations_per_min: 2,
            ..MigrationPolicy::default()
        };
        let t0 = Instant::now();
        let mut s = MigrationState::new(policy, addr(1, 1000));
        // Two migrations at t0 fill the budget.
        for tag in 2..=3u8 {
            let dec = s.observe_inbound(addr(tag, 1000), t0).unwrap();
            let c = match dec {
                MigrationDecision::NewChallenge { challenge, .. } => challenge,
                _ => unreachable!(),
            };
            s.observe_response(addr(tag, 1000), c.to_response(), t0)
                .unwrap();
        }
        // 90 s later, the window has rolled forward - migrations
        // from t0 should expire and not block a new one.
        let t1 = t0 + std::time::Duration::from_secs(90);
        // Initiate a fresh migration. observe_inbound expires old
        // migrations on the new-path branch.
        let dec = s.observe_inbound(addr(4, 1000), t1).unwrap();
        let c = match dec {
            MigrationDecision::NewChallenge { challenge, .. } => challenge,
            _ => panic!("expected NewChallenge after window slide, got {dec:?}"),
        };
        // observe_response should accept the migration; the budget
        // is back to 1/2 after expiry, then 2/2 after this push.
        s.observe_response(addr(4, 1000), c.to_response(), t1)
            .unwrap();
    }

    #[test]
    fn max_simultaneous_challenges_bounded() {
        let mut s = MigrationState::new(MigrationPolicy::default(), addr(1, 1000));
        let now = Instant::now();
        // Open 5 challenges; cap is 4 - oldest gets dropped.
        for tag in 2..=6u8 {
            s.observe_inbound(addr(tag, 1000), now).unwrap();
        }
        let active_challenges = (2..=6u8)
            .filter(|tag| s.path_state(&addr(*tag, 1000)) == Some(PathState::Challenging))
            .count();
        assert_eq!(active_challenges, MAX_SIMULTANEOUS_CHALLENGES);
    }
}
