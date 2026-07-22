//! Adaptive cover-class selection for Proteus.
//!
//! Per network, an EXP3 bandit picks which cover class (video / browse / ...) the
//! Reality pacer wears, rewarded by REAL session outcomes (connect success + latency;
//! a class the network throttles or RSTs scores low).
//!
//! Scope, stated honestly: this does NOT improve the flow's size-shape - replay is
//! already at the learned-distinguisher floor (measured 0.51 vs the source trace). It
//! reacts to how a given network *treats* a class: video streaming is throttled or
//! rate-limited on many networks, ordinary web browsing is not. When the reward signal
//! is flat (no network reacts differently), the bandit just explores harmlessly around
//! its prior. The win shows up only where the network discriminates by class.

use std::collections::HashMap;
use std::time::Duration;

use crate::adaptive::{outcome_reward, Exp3, SplitMix64};
use crate::success_rate::NetworkFingerprint;

/// A selectable cover class: a name plus the (mode, profile) the Reality pacer applies
/// via `set_pace_override`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoverClass {
    /// Human label, also the bandit arm name.
    pub name: String,
    /// Pace mode: `"replay"`, or a generative class (`"video"`/`"browse"`/`"dash"`).
    pub mode: String,
    /// Replay library path for `mode == "replay"`; `None` for generative classes.
    pub profile: Option<String>,
}

impl CoverClass {
    /// A replay class backed by a recorded library subdir (e.g. `library/video`).
    #[must_use]
    pub fn replay(name: impl Into<String>, profile: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            mode: "replay".into(),
            profile: Some(profile.into()),
        }
    }

    /// A generative class needing no library (the honest fallback; higher-entropy).
    #[must_use]
    pub fn generative(class: impl Into<String>) -> Self {
        let c = class.into();
        Self {
            name: c.clone(),
            mode: c,
            profile: None,
        }
    }
}

/// EXP3 exploration rate. Modest: cover class rarely needs to churn.
const GAMMA: f64 = 0.10;
/// Recovery floor. Higher than the transport router's: a class throttled today is
/// often fine tomorrow and switching is cheap, so no arm should decay away.
const RECOVERY: f64 = 0.10;

/// Per-network EXP3 bandit over cover classes.
pub struct CoverClassBandit {
    classes: Vec<CoverClass>,
    per_net: HashMap<[u8; 16], Exp3>,
    /// Last (arm, realised play-probability) selected per network, so `record` rewards
    /// the arm actually played with the correct importance weight.
    last: HashMap<[u8; 16], (usize, f64)>,
    rng: SplitMix64,
}

impl CoverClassBandit {
    /// Build over `classes` (seed from the OS CSPRNG).
    #[must_use]
    pub fn new(classes: Vec<CoverClass>, seed: u64) -> Self {
        Self {
            classes,
            per_net: HashMap::new(),
            last: HashMap::new(),
            rng: SplitMix64::new(seed),
        }
    }

    /// Adaptation is only worthwhile with >= 2 classes; below that the caller should
    /// use the static config unchanged.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.classes.len() >= 2
    }

    /// The classes this bandit chooses among.
    #[must_use]
    pub fn classes(&self) -> &[CoverClass] {
        &self.classes
    }

    /// Select a cover class for `net` (stochastic EXP3 draw). The realised selection
    /// probability is stashed for the matching [`Self::record`].
    pub fn select(&mut self, net: &NetworkFingerprint) -> &CoverClass {
        let k = self.classes.len().max(1);
        let r = self.rng.next_f64();
        let e = self
            .per_net
            .entry(net.digest)
            .or_insert_with(|| Exp3::new(k, GAMMA, RECOVERY));
        let arm = e.select(r);
        let p = e.prob(arm);
        self.last.insert(net.digest, (arm, p));
        &self.classes[arm.min(k - 1)]
    }

    /// Reward the class last selected for `net` from a session outcome.
    pub fn record(&mut self, net: &NetworkFingerprint, success: bool, latency: Option<Duration>) {
        let Some(&(arm, p)) = self.last.get(&net.digest) else {
            return;
        };
        let k = self.classes.len().max(1);
        let reward = outcome_reward(success, latency);
        self.per_net
            .entry(net.digest)
            .or_insert_with(|| Exp3::new(k, GAMMA, RECOVERY))
            .update(arm, reward, p);
    }

    /// Current per-class play distribution for `net` (diagnostics / logging).
    #[must_use]
    pub fn distribution(&self, net: &NetworkFingerprint) -> Vec<(String, f64)> {
        let k = self.classes.len().max(1);
        match self.per_net.get(&net.digest) {
            Some(e) => (0..self.classes.len())
                .map(|i| (self.classes[i].name.clone(), e.prob(i)))
                .collect(),
            None => self
                .classes
                .iter()
                .map(|c| (c.name.clone(), 1.0 / k as f64))
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn classes() -> Vec<CoverClass> {
        vec![
            CoverClass::replay("video", "/lib/video"),
            CoverClass::replay("browse", "/lib/browse"),
        ]
    }

    #[test]
    fn inactive_below_two_classes() {
        assert!(!CoverClassBandit::new(vec![CoverClass::generative("video")], 1).is_active());
        assert!(CoverClassBandit::new(classes(), 1).is_active());
    }

    #[test]
    fn learns_the_class_the_network_tolerates() {
        // Simulate a network that throttles "video" (failure) but tolerates "browse"
        // (fast success). The bandit should shift play mass toward "browse".
        let net = NetworkFingerprint::from_digest([9u8; 16]);
        let mut b = CoverClassBandit::new(classes(), 0xC0FFEE);
        for _ in 0..400 {
            let picked = b.select(&net).name.clone();
            let (success, lat) = if picked == "browse" {
                (true, Some(Duration::from_millis(80)))
            } else {
                (false, None) // video throttled -> RST/timeout
            };
            b.record(&net, success, lat);
        }
        let dist = b.distribution(&net);
        let p = |name: &str| {
            dist.iter()
                .find(|(n, _)| n == name)
                .map(|(_, p)| *p)
                .unwrap()
        };
        assert!(
            p("browse") > p("video"),
            "bandit should favour the tolerated class: {dist:?}"
        );
        assert!(p("browse") > 0.6, "and favour it decisively: {dist:?}");
    }

    #[test]
    fn record_without_select_is_a_noop() {
        // No prior select for this network -> record has no arm to reward, must not panic.
        let mut b = CoverClassBandit::new(classes(), 1);
        b.record(&NetworkFingerprint::from_digest([1u8; 16]), true, None);
    }
}
