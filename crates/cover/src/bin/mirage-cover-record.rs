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
    prune, record_one, Args, Mode, RealTime, Tier, UPLOAD_BODY_BYTES, UPLOAD_CHUNKS,
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
           --tier NAME          lean (default, 2.5 GB/day) or balanced (6 GB/day) -\n\
                                a ceiling on what the envelope costs to replay\n\
                                24/7. Both wear REAL captured traffic; they differ\n\
                                only in which real flow, never in whether it is\n\
                                real. A tier is a THROUGHPUT choice, not a\n\
                                concealment one: both measured equally\n\
                                undetectable. The old aggressive tier is gone\n\
                                and now maps to balanced.\n\
           --max-gb-day N       the ceiling directly, in GB/day. Default for this\n\
                                CLI is none: you asked for a specific envelope.\n\
           --sources PACK       where to record cover FROM: global|cn|ir|ru|tr, or a\n\
                                comma-separated list of your own URLs/hosts. The\n\
                                default (global) is Wikipedia + PeerTube, which is\n\
                                right for an uncensored host and BLOCKED in several\n\
                                of the places this tool is for. Presets are a\n\
                                starting point - verify reachability on your own\n\
                                network and override with a list if in doubt.\n\
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

fn parse_args() -> Args {
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
    let mut loop_mins = None;
    let mut max = None;
    let mut up_bytes = UPLOAD_BODY_BYTES;
    let mut up_chunks = UPLOAD_CHUNKS;
    // The CLI defaults to NO ceiling: an operator asking for a specific envelope
    // wants that envelope, not a cheaper substitute.
    let mut max_gb_day: Option<f64> = None;
    let mut pack = SourcePack::default();
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
            "--name" => name = Some(val(&mut a)),
            "--realtime" => real_time = true,
            "--low-bitrate" => low_bitrate = true,
            "--loop" => loop_mins = Some(val(&mut a).parse().unwrap_or_else(|_| usage())),
            "--max" => max = Some(val(&mut a).parse().unwrap_or_else(|_| usage())),
            "--upload-bytes" => up_bytes = val(&mut a).parse().unwrap_or_else(|_| usage()),
            "--upload-count" => up_chunks = val(&mut a).parse().unwrap_or_else(|_| usage()),
            "--max-gb-day" => max_gb_day = Some(val(&mut a).parse().unwrap_or_else(|_| usage())),
            "--sources" => pack = SourcePack::parse(&val(&mut a)).unwrap_or_else(|| usage()),
            "--tier" => {
                max_gb_day = Tier::parse(&val(&mut a))
                    .unwrap_or_else(|| usage())
                    .max_gb_day();
            }
            s if s.starts_with('-') => usage(),
            s => lib = Some(PathBuf::from(s)),
        }
    }
    let lib = lib.unwrap_or_else(|| usage());
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
    Args {
        max_gap_secs: mirage_cover::DEFAULT_MAX_GAP_SECS,
        lib,
        name,
        mode,
        count,
        hls,
        url,
        instance,
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
    }
}

#[tokio::main]
async fn main() {
    if let Err(e) = harden_process() {
        eprintln!("fatal: harden_process: {e}");
        std::process::exit(2);
    }
    let _ = rustls::crypto::ring::default_provider().install_default();

    let args = parse_args();
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
