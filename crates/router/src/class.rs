//! Traffic class taxonomy + application-hint API.

/// Stream traffic class. Drives circuit profile selection.
///
/// See [`crate::profile::CircuitProfile`] for what each class
/// resolves to in terms of hop count, transport bias, padding, and
/// cover-traffic budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Class {
    /// Tiny + frequent + leaky-if-observed traffic: DNS lookups,
    /// captcha solves, identity-provider hops, `.well-known`
    /// fetches. Same anonymity floor as Interactive but typically
    /// hot-pooled aggressively because the request volume is high.
    Metadata,
    /// Default for unclassified TCP streams. Web browsing, SSH,
    /// REST APIs, mail. Latency matters; throughput is moderate.
    /// Standard 3-hop full-padding profile.
    Interactive,
    /// Sustained high-throughput transfers. Software updates,
    /// rsync / SFTP, `BitTorrent`, large response bodies, HTTP-based
    /// video on demand. Same hop count as Interactive, but the
    /// circuit is built with parallelism enabled so the bulk
    /// stream can be split across multiple circuits transparently.
    Bulk,
    /// Real-time bidirectional UDP. Voice calls (SIP/RTP),
    /// WebRTC video, online games. **2-hop by default** - the
    /// anonymity downgrade is explicit, opt-in, and policy-
    /// controlled. Compensated by stronger cover-traffic at the
    /// circuit endpoints.
    Realtime,
    /// Mirage hidden-service streams (`.mirage` destinations).
    /// Always 6-hop (3 client side + 3 service side) - the
    /// destination is in-protocol, so anonymity is maximal.
    OnionService,
    /// Delay-tolerant background work: software-update fetches,
    /// sync, federated mailbox polling, cover-traffic carriers
    /// for other users. Generous on hops + padding + cover.
    Background,
}

impl Class {
    /// Stable diagnostic name. Used in metrics labels and tracing
    /// spans; does NOT change between releases.
    pub fn name(self) -> &'static str {
        match self {
            Class::Metadata => "metadata",
            Class::Interactive => "interactive",
            Class::Bulk => "bulk",
            Class::Realtime => "realtime",
            Class::OnionService => "onion-service",
            Class::Background => "background",
        }
    }

    /// All classes in stable iteration order.
    ///
    /// **Order is part of the public API** (closes [RT-L1]).
    /// Operator dashboards, metrics labels, and per-class tables
    /// MAY rely on this exact order persisting across releases:
    ///
    /// 1. [`Class::Metadata`]
    /// 2. [`Class::Interactive`]
    /// 3. [`Class::Bulk`]
    /// 4. [`Class::Realtime`]
    /// 5. [`Class::OnionService`]
    /// 6. [`Class::Background`]
    ///
    /// New classes (if added in a future release) MUST be appended
    /// to this list, not inserted, to preserve indices in
    /// downstream consumers.
    pub fn all() -> &'static [Class] {
        &[
            Class::Metadata,
            Class::Interactive,
            Class::Bulk,
            Class::Realtime,
            Class::OnionService,
            Class::Background,
        ]
    }

    /// True iff this class permits a hop count below the
    /// 3-hop Mirage baseline. Used by callers that want to
    /// explicitly refuse anonymity downgrades.
    ///
    /// Today only [`Class::Realtime`] returns `true` (it's the
    /// only profile with a 2-hop default). Adding a new
    /// downgrade-permissive class requires explicit review.
    pub fn permits_hop_downgrade(self) -> bool {
        matches!(self, Class::Realtime)
    }
}

/// Application-supplied class hint. Set via
/// [`crate::classifier::Classifier::classify_with_hint`] or the
/// per-stream submit API at the SOCKS5 frontend.
///
/// A Mirage-aware client (browser extension, mobile SDK, library
/// API) SHOULD attach a hint when it knows the stream's purpose.
/// Hints override the port-based heuristic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClassHint {
    /// "Treat this as interactive web." -> [`Class::Interactive`].
    Web,
    /// "Treat this as bulk transfer." -> [`Class::Bulk`]. Use for
    /// downloads, large `<video>`/`<audio>` element fetches.
    Bulk,
    /// "Treat this as real-time." -> [`Class::Realtime`]. **Opts in
    /// to the 2-hop anonymity downgrade.** Browsers SHOULD use
    /// this for WebRTC `PeerConnection` streams; voice/video apps
    /// SHOULD use it for media flows.
    Realtime,
    /// "Treat this as background work." -> [`Class::Background`].
    Background,
    /// "Treat this as a hidden-service stream." ->
    /// [`Class::OnionService`]. Set automatically when the
    /// destination resolves as a `.mirage` address; rarely used
    /// directly by clients.
    OnionService,
    /// "Treat this as metadata." -> [`Class::Metadata`]. Use for
    /// DNS-over-HTTPS, captcha, `IdP` fetches.
    Metadata,
}

impl ClassHint {
    /// Resolve the hint to a class.
    pub fn class(self) -> Class {
        match self {
            ClassHint::Web => Class::Interactive,
            ClassHint::Bulk => Class::Bulk,
            ClassHint::Realtime => Class::Realtime,
            ClassHint::Background => Class::Background,
            ClassHint::OnionService => Class::OnionService,
            ClassHint::Metadata => Class::Metadata,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn class_names_are_stable() {
        // These strings ship in metrics labels; renaming breaks
        // operator dashboards. Pin them.
        assert_eq!(Class::Metadata.name(), "metadata");
        assert_eq!(Class::Interactive.name(), "interactive");
        assert_eq!(Class::Bulk.name(), "bulk");
        assert_eq!(Class::Realtime.name(), "realtime");
        assert_eq!(Class::OnionService.name(), "onion-service");
        assert_eq!(Class::Background.name(), "background");
    }

    #[test]
    fn only_realtime_permits_hop_downgrade() {
        for &c in Class::all() {
            let permits = c.permits_hop_downgrade();
            assert_eq!(
                permits,
                c == Class::Realtime,
                "{} should{} permit hop downgrade",
                c.name(),
                if c == Class::Realtime { "" } else { " not" }
            );
        }
    }

    #[test]
    fn hints_resolve_to_correct_class() {
        assert_eq!(ClassHint::Web.class(), Class::Interactive);
        assert_eq!(ClassHint::Bulk.class(), Class::Bulk);
        assert_eq!(ClassHint::Realtime.class(), Class::Realtime);
        assert_eq!(ClassHint::Background.class(), Class::Background);
        assert_eq!(ClassHint::OnionService.class(), Class::OnionService);
        assert_eq!(ClassHint::Metadata.class(), Class::Metadata);
    }

    #[test]
    fn class_all_lists_every_variant_exactly_once() {
        let all = Class::all();
        assert_eq!(all.len(), 6);
        let names: Vec<&'static str> = all.iter().map(|c| c.name()).collect();
        let mut sorted = names.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), names.len(), "Class::all has duplicates");
    }
}
