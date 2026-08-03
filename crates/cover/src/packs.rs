//! Where cover traffic is recorded FROM, and why that has to be configurable.
//!
//! # The problem with one global default
//!
//! Recording cover means making real requests to real sites. The original
//! defaults were Wikipedia and a set of PeerTube instances - excellent choices
//! for an uncensored host, and close to the worst possible ones for the people
//! Mirage exists to serve. Wikipedia has been blocked in China since 2019 and
//! periodically in Turkey, Pakistan and Venezuela; the PeerTube instances are
//! obscure enough to be unreachable or conspicuous almost anywhere.
//!
//! On a censored network that produces two failures at once:
//!
//! - **It does not work.** The fetches fail, the library never fills, and
//!   Proteus runs unpaced. The daemon says so now, but saying so is not the same
//!   as working.
//! - **It is a signal.** Repeatedly reaching for a site the local censor blocks
//!   is noteworthy traffic in its own right, on exactly the network where being
//!   unremarkable is the entire objective.
//!
//! # What a pack is for
//!
//! A pack names sites that are **reachable and unremarkable in one region**.
//! Cover has to be both: an unreachable source records nothing, and a reachable
//! but exotic one records traffic no local user generates.
//!
//! These lists are a **starting point, not an endorsement or a guarantee**.
//! Reachability changes without notice and varies by ISP within one country.
//! An operator or user who knows their own network should override with an
//! explicit list; that is why [`SourcePack::Custom`] exists and why it is not
//! second-class.
//!
//! # Video is deliberately thin outside `global`
//!
//! Video capture drives an HLS master playlist through the PeerTube API, and
//! domestic video platforms do not expose that API. So regional packs supply
//! BROWSE sources, and video falls back to the global set or to an explicit
//! `--hls` URL the operator provides. Browse is the more important of the two
//! anyway: it is the class that carries a tunnel's upstream, and the one the
//! lean tier uses exclusively.

/// Cover sources for one region.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourcePack {
    /// Wikipedia + PeerTube. The right default for an uncensored host - which a
    /// bridge usually is, and a client usually is not.
    Global,
    /// Mainland China.
    Cn,
    /// Iran.
    Ir,
    /// Russia.
    Ru,
    /// Turkey.
    Tr,
    /// An explicit list of start URLs, which always wins over any preset.
    Custom(Vec<String>),
}

/// Default browse sources: random real pages, ubiquitous and high-collateral to
/// block. `Special:Random` 302-redirects to a random article and the recorder
/// follows it.
const GLOBAL_BROWSE: &[&str] = &[
    "https://en.wikipedia.org/wiki/Special:Random",
    "https://de.wikipedia.org/wiki/Special:Random",
    "https://fr.wikipedia.org/wiki/Special:Random",
    "https://es.wikipedia.org/wiki/Special:Random",
    "https://ja.wikipedia.org/wiki/Special:Random",
    "https://ru.wikipedia.org/wiki/Special:Random",
];

// The regional lists below are the dominant domestic platforms in each market -
// search, video, commerce, news, forums - chosen so that a recording session
// looks like ordinary local browsing. The recorder starts at these pages and
// follows real links out of them, so a homepage is enough; no per-site
// random-article path is needed.

const CN_BROWSE: &[&str] = &[
    "https://www.baidu.com/",
    "https://www.bilibili.com/",
    "https://www.zhihu.com/",
    "https://www.douban.com/",
    "https://www.jd.com/",
    "https://www.qq.com/",
];

const IR_BROWSE: &[&str] = &[
    "https://www.aparat.com/",
    "https://www.digikala.com/",
    "https://www.varzesh3.com/",
    "https://www.telewebion.com/",
];

const RU_BROWSE: &[&str] = &[
    "https://ya.ru/",
    "https://vk.com/",
    "https://ok.ru/",
    "https://rutube.ru/",
    "https://lenta.ru/",
];

const TR_BROWSE: &[&str] = &[
    "https://www.trendyol.com/",
    "https://www.hurriyet.com.tr/",
    "https://eksisozluk.com/",
    "https://www.milliyet.com.tr/",
];

/// Default video sources: PeerTube instances, which expose the playlist API the
/// video recorder drives.
const GLOBAL_PEERTUBE: &[&str] = &[
    "video.blender.org",
    "framatube.org",
    "tilvids.com",
    "makertube.net",
    "peertube.tv",
    "diode.zone",
    "spectra.video",
    "video.hardlimit.com",
    "tube.tchncs.de",
    "peertube.stream",
];

impl Default for SourcePack {
    fn default() -> Self {
        Self::Global
    }
}

impl SourcePack {
    /// Parse a config or CLI spelling. Anything containing `/` or `.` that is
    /// not a known pack name is treated as a comma-separated URL list, so
    /// `proteus_sources = "https://example.org/"` does the obvious thing.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        let t = s.trim();
        match t.to_ascii_lowercase().as_str() {
            "" => None,
            "global" | "default" | "intl" => Some(Self::Global),
            "cn" | "china" => Some(Self::Cn),
            "ir" | "iran" => Some(Self::Ir),
            "ru" | "russia" => Some(Self::Ru),
            "tr" | "turkey" | "turkiye" => Some(Self::Tr),
            _ => {
                let urls: Vec<String> = t
                    .split(',')
                    .map(str::trim)
                    .filter(|u| !u.is_empty())
                    .map(|u| {
                        // Accept a bare host as well as a full URL; an operator
                        // writing "example.org" means https://example.org/.
                        if u.contains("://") {
                            u.to_string()
                        } else {
                            format!("https://{u}/")
                        }
                    })
                    .collect();
                (!urls.is_empty()).then_some(Self::Custom(urls))
            }
        }
    }

    /// The short name, for logs and diagnostics.
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Self::Global => "global",
            Self::Cn => "cn",
            Self::Ir => "ir",
            Self::Ru => "ru",
            Self::Tr => "tr",
            Self::Custom(_) => "custom",
        }
    }

    /// Start URLs for a browsing capture.
    #[must_use]
    pub fn browse_urls(&self) -> Vec<String> {
        match self {
            Self::Global => GLOBAL_BROWSE.iter().map(|s| (*s).to_string()).collect(),
            Self::Cn => CN_BROWSE.iter().map(|s| (*s).to_string()).collect(),
            Self::Ir => IR_BROWSE.iter().map(|s| (*s).to_string()).collect(),
            Self::Ru => RU_BROWSE.iter().map(|s| (*s).to_string()).collect(),
            Self::Tr => TR_BROWSE.iter().map(|s| (*s).to_string()).collect(),
            Self::Custom(v) => v.clone(),
        }
    }

    /// Hosts to try for a video capture.
    ///
    /// Regional packs return the global PeerTube set: domestic video platforms
    /// do not expose the playlist API the video recorder drives, so pretending
    /// otherwise would just produce a class that never records. An operator who
    /// wants regional video supplies an explicit HLS URL.
    /// (A custom pack names browse pages, and there is no way to tell whether
    /// any of them speaks the PeerTube API, so it keeps the set that does.)
    #[must_use]
    pub fn peertube_hosts(&self) -> Vec<String> {
        GLOBAL_PEERTUBE.iter().map(|s| (*s).to_string()).collect()
    }

    /// Hostnames this pack draws browse cover from.
    #[must_use]
    pub fn hosts(&self) -> Vec<String> {
        self.browse_urls()
            .iter()
            .filter_map(|u| {
                u.split("://")
                    .nth(1)?
                    .split('/')
                    .next()
                    .map(|h| h.trim_start_matches("www.").to_ascii_lowercase())
            })
            .collect()
    }

    /// Whether `sni` is a plausible thing to claim to be, on this pack's network.
    ///
    /// A Reality session announces its cover host in the clear, in the TLS SNI.
    /// Shaping the flow perfectly does nothing about that: a client on a Chinese
    /// network opening a TLS connection whose SNI says `www.wikipedia.org` has
    /// already said the interesting part before a single record is paced,
    /// because that domain is blocked there and nobody local connects to it.
    ///
    /// The test is deliberately coarse - a suffix match against the pack's own
    /// hosts, which are by construction reachable and ordinary in-region. It
    /// exists to catch the obvious mismatch (a foreign SNI on a regional pack),
    /// not to certify any particular choice. `Global` and `Custom` return true
    /// for everything: neither carries a claim about what a censor blocks.
    #[must_use]
    pub fn sni_is_plausible(&self, sni: &str) -> bool {
        if matches!(self, Self::Global | Self::Custom(_)) {
            return true;
        }
        let s = sni.trim().trim_start_matches("www.").to_ascii_lowercase();
        if s.is_empty() {
            return true;
        }
        self.hosts()
            .iter()
            .any(|h| s == *h || s.ends_with(&format!(".{h}")))
    }

    /// Whether this pack's video sources are known-reachable in its region.
    ///
    /// False for every regional pack, because video falls back to the global
    /// PeerTube set. Callers use this to warn rather than to silently record a
    /// class that will not fill.
    #[must_use]
    pub fn video_is_regional(&self) -> bool {
        matches!(self, Self::Global)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pack_names_parse_including_aliases() {
        for (s, want) in [
            ("global", SourcePack::Global),
            ("CN", SourcePack::Cn),
            ("china", SourcePack::Cn),
            ("Iran", SourcePack::Ir),
            ("ru", SourcePack::Ru),
            ("turkiye", SourcePack::Tr),
        ] {
            assert_eq!(SourcePack::parse(s), Some(want), "{s}");
        }
        assert_eq!(SourcePack::parse(""), None);
    }

    #[test]
    fn an_explicit_list_beats_any_preset() {
        // The presets are a starting point; someone who knows their own network
        // must be able to override them, and a bare host must work because that
        // is what people type.
        let p = SourcePack::parse("example.org, https://other.example/news").expect("parse");
        assert_eq!(
            p.browse_urls(),
            vec![
                "https://example.org/".to_string(),
                "https://other.example/news".to_string()
            ]
        );
        assert_eq!(p.name(), "custom");
    }

    #[test]
    fn every_pack_offers_browse_and_video_sources() {
        // A pack that returned nothing would record nothing, and the daemon
        // would report an empty library with no indication why.
        for p in [
            SourcePack::Global,
            SourcePack::Cn,
            SourcePack::Ir,
            SourcePack::Ru,
            SourcePack::Tr,
        ] {
            assert!(!p.browse_urls().is_empty(), "{} browse", p.name());
            assert!(!p.peertube_hosts().is_empty(), "{} video", p.name());
            assert!(
                p.browse_urls().iter().all(|u| u.starts_with("https://")),
                "{} must use https - a cleartext fetch would expose which cover \
                 site was chosen",
                p.name()
            );
        }
    }

    #[test]
    fn a_regional_pack_flags_a_foreign_sni() {
        // Shaping the flow does nothing about the cover host announced in the
        // clear in the TLS SNI. Claiming to be a site the local censor blocks
        // gives the game away before a single record is paced.
        let cn = SourcePack::Cn;
        assert!(cn.sni_is_plausible("www.baidu.com"));
        assert!(cn.sni_is_plausible("baidu.com"));
        assert!(cn.sni_is_plausible("images.baidu.com"), "subdomains count");
        assert!(!cn.sni_is_plausible("www.wikipedia.org"));

        // A near-miss must not pass: `notbaidu.com` merely ends with the same
        // letters, and a plain substring test would wave it through.
        assert!(!cn.sni_is_plausible("notbaidu.com"));

        // Global and custom packs make no claim about what is blocked where, so
        // they must not emit warnings they cannot justify.
        assert!(SourcePack::Global.sni_is_plausible("www.wikipedia.org"));
        assert!(SourcePack::parse("example.org")
            .expect("parse")
            .sni_is_plausible("anything.test"));
        // An unset SNI is not a mismatch.
        assert!(cn.sni_is_plausible(""));
    }

    #[test]
    fn only_the_global_pack_claims_regional_video() {
        // Regional video falls back to the global PeerTube set, so callers must
        // be able to warn instead of quietly recording a class that will not
        // fill on a censored network.
        assert!(SourcePack::Global.video_is_regional());
        for p in [
            SourcePack::Cn,
            SourcePack::Ir,
            SourcePack::Ru,
            SourcePack::Tr,
        ] {
            assert!(!p.video_is_regional(), "{}", p.name());
        }
    }
}
