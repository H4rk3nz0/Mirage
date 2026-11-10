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
//! # Video sources are per-platform, because discovery is
//!
//! Video capture needs a playable stream, and there is no universal way to get
//! from a video page to one. PeerTube publishes an HLS master in a video-detail
//! object; Rutube's page is a JS app that inlines nothing but whose play-options
//! API is public; OK.ru inlines the manifest URL in the page itself; Bilibili
//! serves no HLS at all, only byte-ranged DASH. So [`VideoSource`] names the
//! DISCOVERY METHOD alongside the host, and a pack lists the sources that are
//! both reachable and ordinary in its region.
//!
//! Note what that means: the barrier to covering a region was never that these
//! platforms are hard to extract from - Bilibili's API is public and takes no
//! credentials. It was that the recorder understood one container format.
//!
//! # A regional pack must not reach for global video
//!
//! Falling back to the global PeerTube set on a censored network is the exact
//! failure this module exists to prevent: the fetch fails, the video class never
//! fills, and repeatedly reaching for a blocked host is itself the signal. So
//! every regional pack lists ONLY domestic video, and if those fail it records no
//! video rather than reaching abroad. Browse still records, and browse is the more
//! important class anyway - it carries the tunnel's upstream, and it is all a
//! small budget uses.
//!
//! Only [`SourcePack::Custom`] keeps the global set, as a last group, because a
//! list of browse pages carries no claim that a manifest is findable on any of
//! them. [`SourcePack::video_is_regional`] is exactly "has no fallback group".
//!
//! # These lists will rot
//!
//! A site changes its player, an API starts demanding credentials, a CDN adds a
//! header check. Each presents at runtime as a video class that quietly never
//! fills. `mirage-cover-record --sources <pack> --check-sources` resolves every
//! source without recording, so the question can be asked from the network in
//! question before a user discovers the answer.

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

// `telewebion.com` was here and is gone: public DNS answers NXDOMAIN for it, so
// it resolved nowhere and the recorder simply lost a source every time it drew
// that entry. Found by `--check-sources`, which is why that flag exists.
const IR_BROWSE: &[&str] = &[
    "https://www.aparat.com/",
    "https://www.digikala.com/",
    "https://www.varzesh3.com/",
    "https://www.divar.ir/",
    "https://www.zoomit.ir/",
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

/// How the recorder finds a playable HLS master playlist on one platform.
///
/// Each variant is a discovery METHOD, not just an address. Adding a platform
/// means adding the handful of requests that platform needs - there is no
/// generic path from "a video site" to "a manifest", and pretending otherwise
/// produces a class that never records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VideoSource {
    /// A PeerTube instance, by hostname. `/api/v1/videos` lists recent videos
    /// and the video-detail object carries the HLS master URL outright.
    PeerTube(String),
    /// Rutube, Russia's dominant domestic video platform.
    ///
    /// Its video page is a JS app that inlines no manifest, and its video-list
    /// API needs credentials - but the per-video play-options endpoint is public
    /// and returns a master playlist. So discovery reads IDs off the homepage and
    /// asks that endpoint, which is one more hop than PeerTube and no less real.
    Rutube,
    /// Aparat, Iran's dominant domestic video platform.
    ///
    /// Its player is a JS app like Rutube's, but its public API returns both an
    /// HLS link and a set of per-profile progressive files, so discovery is two
    /// API calls with a progressive fallback if the HLS link is refused.
    Aparat,
    /// Bilibili, China's dominant domestic video platform.
    ///
    /// Serves no HLS at all: its public `playurl` endpoint returns DASH
    /// representations that are byte ranges into ONE file. That is why the
    /// recorder has a ranged mode - see [`crate::Stream::Ranged`] - rather than
    /// why Bilibili is unusable.
    Bilibili,
    /// A site that inlines its manifest URL in the page's own HTML or embedded
    /// JSON, found by scanning for it.
    ///
    /// `video_path` is a substring identifying links to video pages on `start`
    /// (`"/video/"` on OK.ru). `None` scans `start` itself, which is what an
    /// operator's explicit URL means: record from THIS page.
    Embedded {
        /// Page to start from.
        start: String,
        /// Substring marking a link to a video page, or `None` to scan `start`.
        video_path: Option<String>,
    },
}

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

/// The global PeerTube set as video sources.
fn global_peertube() -> impl Iterator<Item = VideoSource> {
    GLOBAL_PEERTUBE
        .iter()
        .map(|s| VideoSource::PeerTube((*s).to_string()))
}

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

    /// Video sources to try, as GROUPS in preference order.
    ///
    /// Sources within a group are equally preferred and the caller picks among
    /// them at random, so a whole population does not hammer one host and a
    /// single dead source is never permanently first. Groups themselves are
    /// ordered and must be tried in order: shuffling across a group boundary
    /// would let a last-resort global source beat the operator's own list, which
    /// is exactly what "an explicit list always wins over any preset" forbids.
    ///
    /// A pack with verified domestic video has ONE group containing only that:
    /// see the module note on why a regional pack must not fall back abroad.
    #[must_use]
    pub fn video_sources(&self) -> Vec<Vec<VideoSource>> {
        match self {
            // Russia blocks or throttles essentially every global video
            // platform, PeerTube instances included, so reaching for one is both
            // useless and conspicuous. One group, no fallback: if both domestic
            // sources fail, no video is recorded - which is the right answer.
            Self::Ru => vec![vec![
                VideoSource::Rutube,
                VideoSource::Embedded {
                    start: "https://ok.ru/video".to_string(),
                    video_path: Some("/video/".to_string()),
                },
            ]],
            // Iran: Aparat is the dominant domestic platform and its public API
            // hands back a CDN playlist directly.
            Self::Ir => vec![vec![VideoSource::Aparat]],
            // Turkey: puhutv inlines the live HLS endpoints of the Dogus
            // broadcast channels (NTV, Kral Pop), which is about as ordinary as
            // Turkish video traffic gets. YouTube is reachable in Turkey and
            // would also be defensible, but it needs an extractor that fights
            // back; a domestic live stream needs one page fetch.
            Self::Tr => vec![vec![VideoSource::Embedded {
                start: "https://puhutv.com/".to_string(),
                video_path: None,
            }]],
            // China: Bilibili's playurl API is public and its DASH
            // representations are byte-ranged, which the recorder drives with
            // `Mode::Video`'s ranged path rather than an HLS playlist.
            Self::Cn => vec![vec![VideoSource::Bilibili]],
            // An operator naming their own sources is naming sites they know are
            // ordinary locally, so their pages are group one and are tried to
            // exhaustion first. The global set stays as a LAST group because a
            // custom list is usually browse pages and dropping to no video at all
            // would be a surprise; a regional pack is how to say "never reach
            // abroad".
            Self::Custom(v) => vec![
                v.iter()
                    .map(|u| VideoSource::Embedded {
                        start: u.clone(),
                        video_path: None,
                    })
                    .collect(),
                global_peertube().collect(),
            ],
            Self::Global => vec![global_peertube().collect()],
        }
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
    /// True where [`Self::video_sources`] is domestic (or, for `global`, where
    /// "the region" is the uncensored internet). False means video falls back to
    /// the global PeerTube set, which on a censored network records nothing and
    /// is conspicuous while failing - so callers warn rather than silently
    /// filling a class that will not fill.
    ///
    /// `custom` is false because a list of browse pages carries no claim that a
    /// manifest can be found on any of them; it keeps the global set as a last
    /// group precisely because it cannot make that claim.
    ///
    /// Equivalently: true exactly when there is no global fallback group to fall
    /// into, which is the property the warning is really about.
    #[must_use]
    pub fn video_is_regional(&self) -> bool {
        self.video_sources().len() == 1
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
            assert!(!p.video_sources().is_empty(), "{} video", p.name());
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
    fn a_pack_without_domestic_video_says_so() {
        // Where video falls back to the global PeerTube set, callers must be able
        // to warn instead of quietly recording a class that will not fill on a
        // censored network. Every regional pack now has a domestic source, so
        // the only thing that still falls back is a custom list.
        for p in [
            SourcePack::Global,
            SourcePack::Ru,
            SourcePack::Ir,
            SourcePack::Tr,
            SourcePack::Cn,
        ] {
            assert!(p.video_is_regional(), "{}", p.name());
        }
        // A custom list is browse pages; nothing promises a manifest is findable
        // on them, so it must not claim regional video.
        assert!(!SourcePack::parse("example.org")
            .expect("parse")
            .video_is_regional());
    }

    #[test]
    fn a_regional_pack_never_reaches_for_global_video() {
        // The whole point of a regional pack. These regions block the global
        // platforms, so a fallback would record nothing AND be conspicuous while
        // failing - recording no video is the better outcome. One group means
        // there is nothing to fall back INTO.
        for (p, domestic) in [
            (SourcePack::Ru, "ok.ru"),
            (SourcePack::Tr, "puhutv.com"),
            (SourcePack::Ir, ""),
            (SourcePack::Cn, ""),
        ] {
            let groups = p.video_sources();
            assert_eq!(groups.len(), 1, "{} must have no fallback group", p.name());
            for s in &groups[0] {
                assert!(
                    !matches!(s, VideoSource::PeerTube(_)),
                    "{} must not fall back to PeerTube: {s:?}",
                    p.name()
                );
                if let VideoSource::Embedded { start, .. } = s {
                    assert!(
                        start.contains(domestic),
                        "{} sources must be domestic: {start}",
                        p.name()
                    );
                }
            }
        }
        assert!(SourcePack::Ru.video_sources()[0].contains(&VideoSource::Rutube));
        assert_eq!(SourcePack::Ir.video_sources()[0], vec![VideoSource::Aparat]);
        assert_eq!(
            SourcePack::Cn.video_sources()[0],
            vec![VideoSource::Bilibili]
        );
    }

    #[test]
    fn a_custom_pack_exhausts_its_own_pages_before_the_global_set() {
        // An operator naming sources is naming sites they know are ordinary
        // locally. The global set must be a LATER GROUP, not a peer shuffled in
        // among them - otherwise a random draw can put PeerTube first and the
        // explicit list loses to the preset it is supposed to beat.
        let p = SourcePack::parse("video.example.org,other.example").expect("parse");
        let groups = p.video_sources();
        assert_eq!(groups.len(), 2, "own sources, then the fallback");
        assert_eq!(
            groups[0],
            vec![
                VideoSource::Embedded {
                    start: "https://video.example.org/".to_string(),
                    video_path: None,
                },
                VideoSource::Embedded {
                    start: "https://other.example/".to_string(),
                    video_path: None,
                }
            ]
        );
        assert!(groups[1]
            .iter()
            .all(|s| matches!(s, VideoSource::PeerTube(_))));
    }
}
