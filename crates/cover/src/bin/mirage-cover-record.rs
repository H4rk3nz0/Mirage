//! `mirage-cover-record` - the CLI over [`mirage_cover`].
//!
//! Recording cover is normally NOT something an operator does: turning Proteus on
//! makes the daemon source and refresh its own library in-process (see
//! [`mirage_cover::keep_fresh`]). This binary is for the operator who has read the
//! docs and wants a specific envelope - their own site, a particular video, an
//! upload endpoint they control - rather than the automatic one.

use std::path::PathBuf;
use std::time::Duration;

use mirage_common::process_hardening::harden_process;
use mirage_cover::packs::SourcePack;
use mirage_cover::{
    legacy_tier_budget, prune, record_one, Args, Mode, RealTime, UPLOAD_BODY_BYTES, UPLOAD_CHUNKS,
};

fn usage() -> ! {
    eprintln!(
        "usage: mirage-cover-record <lib-dir> [options]\n\
         \n\
         Records real traffic's wire envelope into <lib-dir>/<name>/<i>.csv, the replay\n\
         library Proteus wears. Self-contained (no external tools).\n\
         \n\
         You usually do not need this: `proteus = true` makes the daemon record and\n\
         refresh its own library. Use this when you want a SPECIFIC envelope.\n\
         \n\
         options:\n\
           --mode video|browse|upload\n\
                                cover class (default video). upload records the\n\
                                UPSTREAM envelope of a file POST - the only class\n\
                                with records big enough to pad a full-size QUIC\n\
                                datagram into (browse/video upstream is a few\n\
                                hundred bytes of HTTP request). Use it as\n\
                                proteus_profile_up to size-shape QUIC egress.\n\
           --count N            record N traces (default 1)\n\
           --hls URL            video: record a specific HLS master playlist\n\
           --peertube HOST      video: use a specific PeerTube instance\n\
           --hls-cmd CMD        video: run CMD and record the HLS URL it prints.\n\
                                The escape hatch for platforms that fight\n\
                                extraction - e.g. --hls-cmd 'yt-dlp -g <url>'.\n\
                                Mirage does NOT depend on yt-dlp: nothing is run\n\
                                unless you set this. The extractor's own requests\n\
                                are not part of the capture, but they do go out\n\
                                un-tunnelled like every other discovery fetch.\n\
           --url URL            browse: record a specific page + its subresources\n\
                                upload: REQUIRED - the endpoint to POST to. This\n\
                                mode sends real bytes, so it will not pick a\n\
                                stranger's server for you.\n\
           --name NAME          library subdir name (default: the mode)\n\
           --realtime           video: wait the TRUE segment duration (a player's\n\
                                idle gaps), so the trace's average rate is the\n\
                                stream's real bitrate. Required if the envelope\n\
                                will be replayed as CONTINUOUS cover.\n\
           --low-bitrate        video: take the LOWEST HLS variant, not the\n\
                                highest. Pair with --realtime for always-on cover.\n\
           --upload-bytes N     upload: bytes per POST (default 262144)\n\
           --upload-count N     upload: how many POSTs (default 24)\n\
           --tier NAME          DEPRECATED, kept so old configs keep working.\n\
                                lean|metered = 2.5 GB/day, balanced = 6 GB/day,\n\
                                aggressive|max = 6 GB/day (it used to be uncapped).\n\
                                Tiers were never a concealment choice - every one\n\
                                measured equally undetectable - so say the number\n\
                                you mean with --max-gb-day instead.\n\
           --max-gb-day N       the ceiling directly, in GB/day. Default for this\n\
                                CLI is none: you asked for a specific envelope.\n\
           --sources PACK       where to record cover FROM: global|cn|ir|ru|tr, or a\n\
                                comma-separated list of your own URLs/hosts. The\n\
                                default (global) is Wikipedia + PeerTube, which is\n\
                                right for an uncensored host and BLOCKED in several\n\
                                of the places this tool is for. Presets are a\n\
                                starting point - verify reachability on your own\n\
                                network and override with a list if in doubt.\n\
                                VIDEO sources are per-pack and DOMESTIC-ONLY for\n\
                                every region: ru = Rutube + OK.ru, ir = Aparat,\n\
                                cn = Bilibili, tr = puhutv. None of them falls back\n\
                                to a global platform, because reaching for a blocked\n\
                                host both fails and is conspicuous - if the domestic\n\
                                sources fail, no video is recorded. A custom list is\n\
                                scanned for an embedded manifest first, then the\n\
                                global PeerTube set.\n\
           --check-sources      probe every BROWSE and VIDEO source --sources\n\
                                names and report which work from THIS network,\n\
                                without recording. Regional lists are reachability\n\
                                claims that rot; run this to find out before a user\n\
                                does. Exits non-zero only if a whole class has\n\
                                nothing left. Needs no <lib-dir>.\n\
           --loop MINUTES       self-driving: record, wait, repeat forever\n\
           --max K              in --loop, keep only the K newest traces\n\
         \n\
         Point the tunnel at a class dir:\n\
           proteus = \"replay\", proteus_profile = \"<lib-dir>/video\"\n\
         Leaving proteus_profile unset is the supported path: the daemon records\n\
         its own."
    );
    std::process::exit(2);
}

/// Next arg value or usage-exit (option requires an argument).
fn val<I: Iterator<Item = String>>(a: &mut I) -> String {
    a.next().unwrap_or_else(|| usage())
}

fn parse_args() -> (Args, bool) {
    let mut a = std::env::args().skip(1);
    let mut lib: Option<PathBuf> = None;
    let mut name: Option<String> = None;
    let mut mode = None;
    let mut count = 1usize;
    let mut hls = None;
    let mut url = None;
    let mut real_time = false;
    let mut low_bitrate = false;
    let mut instance = None;
    let mut hls_cmd = None;
    let mut loop_mins = None;
    let mut max = None;
    let mut up_bytes = UPLOAD_BODY_BYTES;
    let mut up_chunks = UPLOAD_CHUNKS;
    // The CLI defaults to NO ceiling: an operator asking for a specific envelope
    // wants that envelope, not a cheaper substitute.
    let mut max_gb_day: Option<f64> = None;
    let mut pack = SourcePack::default();
    let mut check_sources = false;
    while let Some(arg) = a.next() {
        match arg.as_str() {
            "-h" | "--help" => usage(),
            "--mode" => {
                mode = Some(match val(&mut a).as_str() {
                    "video" => Mode::Video,
                    "browse" => Mode::Browse,
                    "upload" => Mode::Upload,
                    _ => usage(),
                })
            }
            "--count" => count = val(&mut a).parse().unwrap_or_else(|_| usage()),
            "--hls" => hls = Some(val(&mut a)),
            "--url" => url = Some(val(&mut a)),
            "--peertube" => instance = Some(val(&mut a)),
            "--hls-cmd" => hls_cmd = Some(val(&mut a)),
            "--name" => name = Some(val(&mut a)),
            "--realtime" => real_time = true,
            "--low-bitrate" => low_bitrate = true,
            "--loop" => loop_mins = Some(val(&mut a).parse().unwrap_or_else(|_| usage())),
            "--max" => max = Some(val(&mut a).parse().unwrap_or_else(|_| usage())),
            "--upload-bytes" => up_bytes = val(&mut a).parse().unwrap_or_else(|_| usage()),
            "--upload-count" => up_chunks = val(&mut a).parse().unwrap_or_else(|_| usage()),
            "--max-gb-day" => max_gb_day = Some(val(&mut a).parse().unwrap_or_else(|_| usage())),
            "--sources" => pack = SourcePack::parse(&val(&mut a)).unwrap_or_else(|| usage()),
            "--check-sources" => check_sources = true,
            "--tier" => {
                max_gb_day = Some(legacy_tier_budget(&val(&mut a)).unwrap_or_else(|| usage()));
            }
            s if s.starts_with('-') => usage(),
            s => lib = Some(PathBuf::from(s)),
        }
    }
    // `--check-sources` resolves and writes nothing, so demanding an output
    // directory for it would be a paper requirement that only trips people up.
    let lib = match lib {
        Some(l) => l,
        None if check_sources => PathBuf::from("."),
        None => usage(),
    };
    // --url implies browse, --hls implies video; else default video.
    let mode = mode.unwrap_or(if url.is_some() {
        Mode::Browse
    } else {
        Mode::Video
    });
    let name = name.unwrap_or_else(|| match mode {
        Mode::Video => "video".into(),
        Mode::Browse => "browse".into(),
        Mode::Upload => "upload".into(),
    });
    (
        Args {
            max_gap_secs: mirage_cover::DEFAULT_MAX_GAP_SECS,
            lib,
            name,
            mode,
            count,
            hls,
            url,
            instance,
            hls_cmd,
            loop_mins,
            max,
            rt: RealTime {
                real_time,
                low_bitrate,
                max_gap: std::time::Duration::from_secs_f64(mirage_cover::DEFAULT_MAX_GAP_SECS),
            },
            up_bytes,
            up_chunks,
            // The CLI's output IS its console narration.
            verbose: true,
            pack,
            max_gb_day,
        },
        check_sources,
    )
}

#[tokio::main]
async fn main() {
    if let Err(e) = harden_process() {
        eprintln!("fatal: harden_process: {e}");
        std::process::exit(2);
    }
    let _ = rustls::crypto::ring::default_provider().install_default();

    let (args, check_sources) = parse_args();

    // A reachability probe, not a recording. The regional source lists are
    // claims about what works from a given network, and they rot silently -
    // this is how to ask before a user discovers the answer.
    if check_sources {
        let report = |kind: &str, checks: &[mirage_cover::SourceCheck]| -> usize {
            let mut worked = 0usize;
            for c in checks {
                match &c.outcome {
                    Ok(detail) => {
                        worked += 1;
                        println!("  ok    [{kind}] {:<44} -> {detail}", c.source);
                    }
                    Err(e) => println!("  FAIL  [{kind}] {:<44} -> {e}", c.source),
                }
            }
            worked
        };

        // Browse first, because it is the class that matters most: it carries
        // the tunnel's upstream and is recorded at every budget, while video
        // only appears above 6 GB/day. A pack whose video resolves and whose
        // browse does not is a pack that cannot carry a tunnel.
        let browse = mirage_cover::check_browse_sources(&args.pack).await;
        let browse_ok = report("browse", &browse);
        let video = mirage_cover::check_video_sources(&args.pack, args.rt.low_bitrate).await;
        let video_ok = report("video ", &video);

        println!(
            "{}: {browse_ok}/{} browse, {video_ok}/{} video sources resolved",
            args.pack.name(),
            browse.len(),
            video.len()
        );
        // Exit non-zero when a class has NOTHING left, so a scheduled check
        // fails loudly. One dead source among several is not an outage: the
        // recorder tries the next, which is the whole reason a pack lists more
        // than one.
        let dead = (browse_ok == 0 && !browse.is_empty()) || (video_ok == 0 && !video.is_empty());
        std::process::exit(i32::from(dead));
    }

    let dir = args.lib.join(&args.name);

    loop {
        for _ in 0..args.count {
            if let Err(e) = record_one(&args, &dir).await {
                eprintln!("trace skipped: {e}");
            }
        }
        if let Some(k) = args.max {
            prune(&dir, k);
        }
        match args.loop_mins {
            Some(m) => {
                eprintln!("sleeping {m} min before next batch...");
                tokio::time::sleep(Duration::from_secs(m as u64 * 60)).await;
            }
            None => break,
        }
    }
}
