//! The `proteus` config value: a switch that also accepts a mode.
//!
//! Proteus is meant to be turned on, not configured. The overwhelmingly common
//! config is `proteus = true`, so that has to be spelled the obvious way and has
//! to be sufficient on its own. An operator who has read the docs and wants a
//! specific cover class writes `proteus = "browse"` in the same field rather than
//! learning a second one.

use serde::{Deserialize, Serialize};

/// Name of the cover class recorded to supply the UPSTREAM direction.
///
/// Lives here because two crates that do not depend on each other both have to
/// agree on it: `mirage-cover` writes the directory, and
/// `mirage-transport-reality` must EXCLUDE it when pooling a library root for
/// DOWNSTREAM cover. That exclusion matters - the class is recorded dense and
/// gap-free on purpose (a tunnel's flow control rides upstream), so a 2-3 s
/// page-load burst is exactly the wrong shape to wear as downstream browsing,
/// and pooling it alongside the browse class made a session's cover rate a
/// lottery between the two. Measured: the same library produced 88.7 KiB/s of
/// idle cover in one session and 125.3 KiB/s in another, which inflates the
/// separability floor for every measurement taken over it.
pub const UPSTREAM_COVER_CLASS: &str = "upstream";

/// `proteus = true` | `proteus = "replay"` | `proteus = "browse"` | `proteus = false`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ProteusSwitch {
    /// `true` / `false`. `true` means the recommended mode with cover sourced
    /// automatically; `false` is the same as leaving the field out.
    On(bool),
    /// An explicit mode: `replay` (what `true` resolves to), or the weaker
    /// generative classes `video` / `browse`.
    Mode(String),
}

impl ProteusSwitch {
    /// The mode string to hand the pacer, or `None` when Proteus is off.
    ///
    /// `true` resolves to `replay` rather than to a class, because replay is the
    /// only mode that reaches the indistinguishability floor - the generative
    /// classes inject entropy no real flow has. Someone who writes `proteus =
    /// true` is asking for the good one.
    #[must_use]
    pub fn mode(&self) -> Option<&str> {
        match self {
            Self::On(true) => Some("replay"),
            Self::On(false) => None,
            Self::Mode(m) => {
                let m = m.trim();
                // Accept the words people actually write in a config file, so a
                // YAML `proteus: on` (which parses as the string "on", not a
                // bool) does not silently mean "off".
                match m.to_ascii_lowercase().as_str() {
                    "" | "off" | "false" | "no" | "none" | "0" => None,
                    // The cost tiers are all replay - they change WHICH real
                    // flow gets worn, not how it is worn. See [`Self::tier`].
                    "on" | "true" | "yes" | "1" | "auto" | "proteus" | "lean" | "cheap"
                    | "metered" | "balanced" | "aggressive" | "max" => Some("replay"),
                    _ => Some(m),
                }
            }
        }
    }

    /// Whether this value turns Proteus on at all.
    #[must_use]
    pub fn is_on(&self) -> bool {
        self.mode().is_some()
    }

    /// The legacy cost-tier name in this value, lowercased, or `None` when it
    /// names none (in which case the caller's default budget applies).
    ///
    /// Tiers are gone as a concept - what they set was a bandwidth ceiling, not
    /// a concealment level - but a config written against them has to keep
    /// working. `mirage-common` sits below `mirage-cover`, so the name is passed
    /// up as a string and resolved to a GB/day ceiling there via
    /// `mirage_cover::legacy_tier_budget`.
    #[must_use]
    pub fn tier_name(&self) -> Option<String> {
        match self {
            Self::On(_) => None,
            Self::Mode(m) => {
                let m = m.trim().to_ascii_lowercase();
                matches!(
                    m.as_str(),
                    "lean" | "cheap" | "metered" | "balanced" | "aggressive" | "max"
                )
                .then_some(m)
            }
        }
    }
}

impl From<bool> for ProteusSwitch {
    fn from(b: bool) -> Self {
        Self::On(b)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bool_and_string_forms_agree() {
        assert_eq!(ProteusSwitch::On(true).mode(), Some("replay"));
        assert_eq!(ProteusSwitch::On(false).mode(), None);
        for on in ["on", "ON", "true", "yes", "1", "auto", " proteus "] {
            assert_eq!(
                ProteusSwitch::Mode(on.into()).mode(),
                Some("replay"),
                "{on} should turn Proteus on"
            );
        }
        for off in ["off", "FALSE", "no", "none", "0", ""] {
            assert_eq!(
                ProteusSwitch::Mode(off.into()).mode(),
                None,
                "{off} should turn Proteus off"
            );
        }
    }

    #[test]
    fn cost_tiers_are_all_replay_and_name_themselves() {
        // A tier changes WHICH real flow is worn, never whether it is real, so
        // every tier must still resolve to the replay pacing mode.
        for (spelling, tier) in [
            ("lean", "lean"),
            ("Balanced", "balanced"),
            ("AGGRESSIVE", "aggressive"),
            ("metered", "metered"),
        ] {
            let s = ProteusSwitch::Mode(spelling.into());
            assert_eq!(s.mode(), Some("replay"), "{spelling} must still be replay");
            assert_eq!(s.tier_name().as_deref(), Some(tier));
        }
        // Plain on/off name no tier, so the caller's default applies.
        assert_eq!(ProteusSwitch::On(true).tier_name(), None);
        assert_eq!(ProteusSwitch::Mode("replay".into()).tier_name(), None);
    }

    #[test]
    fn an_explicit_class_survives_untouched() {
        assert_eq!(ProteusSwitch::Mode("browse".into()).mode(), Some("browse"));
        assert_eq!(ProteusSwitch::Mode("replay".into()).mode(), Some("replay"));
        // A typo stays a typo rather than being silently coerced to a default -
        // the pacer's own dispatch will decline it and say so.
        assert_eq!(ProteusSwitch::Mode("vidoe".into()).mode(), Some("vidoe"));
    }

    #[test]
    fn deserializes_from_either_json_shape() {
        let t: ProteusSwitch = serde_json::from_str("true").expect("bool form");
        assert!(t.is_on());
        let s: ProteusSwitch = serde_json::from_str("\"browse\"").expect("string form");
        assert_eq!(s.mode(), Some("browse"));
        let f: ProteusSwitch = serde_json::from_str("false").expect("bool form");
        assert!(!f.is_on());
    }
}
