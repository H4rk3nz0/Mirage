//! Self-contained cover-traffic recorder: the source of the replay library
//! **Proteus** wears.
//!
//! Fetches real traffic over rustls and writes its TLS-record envelope
//! `(t, size, dir)` to a trace library. No external tools - no yt-dlp, ffmpeg,
//! tcpdump, or python. Record sizes are read straight off the wire by parsing the
//! cleartext 5-byte TLS record headers of the connection this process drives: the
//! same signal a DPI sees, and exactly what Proteus replays.
//!
//! Two ways in, and the first is the one that matters:
//!
//! - [`keep_fresh`] - what a daemon runs when Proteus is switched on. It sources
//!   and refreshes its own library in-process, so turning Proteus on is the whole
//!   procedure. No timer unit, no recorder invocation, no CSVs to ship.
//! - [`record_one`] with an [`Args`] built from flags - the `mirage-cover-record`
//!   CLI, for an operator who wants a specific envelope instead of the automatic
//!   one.
//!
//! Random content is deliberate: a fixed set of clips would be a signature in
//! itself, so each run pulls different real traffic and a session chains a random
//! shuffle of several traces.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

pub mod packs;

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use serde_json::Value;
use tokio::io::{
    AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, ReadBuf,
};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;
use url::Url;

/// Traces below this are looped by the pacer (a periodicity fingerprint); reject them.
const MIN_TRACE_BYTES: usize = 64 * 1024;
/// Per-trace fetch budget: stop after any of these.
const MAX_SEGS: usize = 16;
const MAX_BYTES: usize = 6 * 1024 * 1024;
const MAX_TIME: Duration = Duration::from_secs(30);
/// Cap a single body read (a progressive media URL can be huge).
const BODY_CAP: usize = 6 * 1024 * 1024;
/// Inter-segment pace cap - mimic a player's buffer wait without stalling recording.
const SEG_GAP_MAX: Duration = Duration::from_millis(1200);
/// Budget for a real-time recording: long enough to span many player buffer
/// cycles, so the trace's average rate is the stream's true bitrate rather than
/// one burst. Bytes stay bounded because a low-bitrate rendition is small.
const RT_MAX_SEGS: usize = 120;
const RT_MAX_BYTES: usize = 24 * 1024 * 1024;
const RT_MAX_TIME: Duration = Duration::from_secs(360);

/// How faithfully to reproduce a player's timing while recording video.
///
/// This is the difference between a trace that SAMPLES a video stream's record
/// shape and one that can be replayed as CONTINUOUS cover. With `real_time` off
/// the recorder rushes: it waits at most [`SEG_GAP_MAX`] between segments, so a
/// 6 s segment's worth of media is fetched in 1.2 s and the trace's replay rate
/// is several times the real stream's. With it on, the recorder waits the true
/// segment duration, so the trace carries the player's genuine idle gaps and its
/// average rate is the stream's own bitrate - the number that becomes a
/// 24/7 bandwidth bill if the envelope is replayed continuously.
#[derive(Clone, Copy)]
pub struct RealTime {
    /// Wait the true segment duration instead of capping at [`SEG_GAP_MAX`].
    pub real_time: bool,
    /// Take the LOWEST-bandwidth HLS variant rather than the highest.
    pub low_bitrate: bool,
    /// Worst-case gap the tunnel can afford, in seconds - the same ceiling
    /// [`Args::max_gap_secs`] applies when accepting a finished capture.
    ///
    /// Carried into the RECORDER so a browse session never manufactures a gap
    /// it is going to be rejected for. Without this the two halves disagree:
    /// the recorder dwells 4-14 s, the acceptance check rejects anything over
    /// 2 s, and the retry loop produces the same violation three times before
    /// giving up and keeping it anyway.
    pub max_gap: Duration,
}

impl RealTime {
    /// Segment/byte/time budget for this recording style.
    fn budget(self) -> (usize, usize, Duration) {
        if self.real_time {
            (RT_MAX_SEGS, RT_MAX_BYTES, RT_MAX_TIME)
        } else {
            (MAX_SEGS, MAX_BYTES, MAX_TIME)
        }
    }
}
/// Gap between successive upload chunks, so an upload trace has real structure
/// rather than one continuous blast.
const UPLOAD_GAP: Duration = Duration::from_millis(400);
/// Bytes per upload chunk. Large enough that the TLS records it produces reach
/// full size (a QUIC datagram runs to the path MTU, and padding cannot shrink
/// one), small enough to stay a courteous request against the operator's own
/// endpoint.
pub const UPLOAD_BODY_BYTES: usize = 256 * 1024;
/// How many chunks one upload trace records.
pub const UPLOAD_CHUNKS: usize = 24;
/// Browse: subresource fetch caps + inter-asset gap (a page loads assets in a burst).
const MAX_ASSETS: usize = 48;
const BROWSE_GAP: Duration = Duration::from_millis(60);

/// Wall-clock a realtime browse session aims to cover, and the page cap that
/// stops it running away on a site that loads fast.
///
/// A capture's SPAN sets the replay loop's period, and a short period is a
/// fingerprint in its own right (a 40 s seed-invariant loop was a real defect
/// here once). So span is the thing to hold fixed. What fills it is the choice:
/// artificial waiting, or more real pages. See [`DWELL_MIN`] for why it is now
/// the latter.
const SESSION_TARGET_SPAN: Duration = Duration::from_secs(30);
const SESSION_MAX_PAGES: usize = 24;

/// Dwell floor between pages in a realtime browse session.
///
/// A page load is a ~2-4 s burst; a person then reads. Capturing only the burst
/// and replaying it continuously means "load pages back to back forever", which
/// is a shape no browser produces, so some inter-page gap belongs in the trace.
/// Holding the connection open through it records whatever the site sends in
/// that window (keepalives, beacons, analytics pings) or genuine silence. Both
/// are real; the one SYNTHESISED parameter is how long to wait, drawn per-gap
/// rather than fixed, because a constant period would itself be a fingerprint.
///
/// # Why the ceiling is the tunnel's latency budget, not a reading time
///
/// The cover envelope is simultaneously the disguise AND the tunnel's capacity:
/// bytes leave only on a schedule token, so a gap in the capture is a stall for
/// the user. A 4-14 s dwell was measured on this repo's own captures at a 6.9x
/// burstiness and a 14.3 s worst-case gap, which makes a 120 KB fetch take
/// 10.6 s at p90 against a 2.9 s ideal - **45% of the budget paid for and
/// undeliverable**. The same pages recorded dense measured 1.7x and 2.5 s.
///
/// That gap is not a tuning accident, it is forced: `min(capacity, demand)` is
/// concave in capacity, so by Jensen the smoothest cover achieving a given mean
/// rate delivers strictly the most, at every budget. Burstiness is never a
/// trade against detectability - it is pure loss.
///
/// So the ceiling is [`Args::max_gap_secs`], the operator's own worst-case
/// latency, and the span the dwell used to buy is bought with real pages
/// instead. That also removes the last reason the dwell existed: it was sized
/// to cut bandwidth roughly 4x, and per-session bandwidth is now an explicit
/// operator setting rather than something the recorder economises on silently.
const DWELL_MIN: Duration = Duration::from_millis(500);

/// Share of the latency ceiling the dwell may spend, leaving the rest for the
/// next page's time to first byte. See [`dwell_ms`] for the measurement that
/// fixed it here: dwelling to the full ceiling overshot it every time.
const DWELL_CEILING_FRACTION: f64 = 0.6;

/// Upstream tokens per second a capture must sustain to be usable as cover.
///
/// Mirrors `mirage_transport_reality`'s own starvation threshold. Checked HERE,
/// at record time, so a trace that cannot carry a tunnel never enters the
/// library: the alternative is discovering it at handshake time, where it looks
/// like an unreachable bridge rather than a cover-selection mistake. The margin
/// over 1.0 is deliberate - a trace that only just clears the threshold has no
/// room for a slow network on top.
const MIN_UPSTREAM_TOKENS: f64 = 2.0;

/// Upstream PAYLOAD bytes per second a capture must sustain to carry a tunnel.
///
/// The token-rate floor above is necessary but not sufficient, and the
/// difference is not academic. A tunnel's downstream is gated by its own flow
/// control, which travels UPSTREAM - so upstream payload capacity, not
/// downstream, sets how fast a download actually goes.
///
/// Measured, on the same browse pages recorded two ways:
///
/// | capture | down payload | up payload | 120 KB download |
/// |---|---|---|---|
/// | page load only | 117 KiB/s | 3.93 KiB/s | 2 s |
/// | with reading dwell | 44.7 KiB/s | 0.91 KiB/s | 18 s ... 389 s |
///
/// Downstream was never the constraint; 120 KB needs under 3 s of it either way.
/// Spreading the same handful of upstream request bytes over four times the wall
/// clock is what made the tunnel unusable, and it passed the token-rate floor
/// because the tokens were still there - they were just tiny. A token at or
/// below `RECORD_OVERHEAD + FRAME_HEADER` carries no payload at all.
const MIN_UPSTREAM_PAYLOAD_BPS: f64 = 2048.0;

/// Bytes of framing every token spends before any payload rides. Mirrors the
/// pacer's `RECORD_OVERHEAD + FRAME_HEADER`; a token this size or smaller is
/// pure cover and moves nothing.
const TOKEN_FRAMING_OVERHEAD: u32 = 21 + 4;
/// Realistic browser UA so CDNs / PeerTube serve normally.
const UA: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 \
                  (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36";

/// One recorded record: (relative time s, wire size bytes, dir: 1=down, -1=up).
type Event = (f64, u32, i8);

/// Largest token the pacer replays as a single TLS record (rustls caps plaintext at
/// 2^14). A CDN's max-size record (up to ~16406 wire) is clamped here so replay never
/// splits one recorded record into two.
const MAX_RECORD: u32 = 16384;

// --- TLS-record tap ---------------------------------------------------------

/// Walks the cleartext TLS record framing (`type[1] version[2] length[2]`) of a
/// byte stream, emitting one `(t, 5+length, dir)` per record as its header lands.
#[derive(Default)]
struct RecordParser {
    hdr: [u8; 5],
    hlen: usize,
    need: usize,
}

impl RecordParser {
    fn feed(&mut self, mut buf: &[u8], t: f64, dir: i8, out: &Mutex<Vec<Event>>) {
        while !buf.is_empty() {
            if self.need > 0 {
                let take = self.need.min(buf.len());
                self.need -= take;
                buf = &buf[take..];
                continue;
            }
            let take = (5 - self.hlen).min(buf.len());
            self.hdr[self.hlen..self.hlen + take].copy_from_slice(&buf[..take]);
            self.hlen += take;
            buf = &buf[take..];
            if self.hlen == 5 {
                let len = u16::from_be_bytes([self.hdr[3], self.hdr[4]]) as usize;
                out.lock()
                    .unwrap()
                    .push((t, ((len + 5) as u32).min(MAX_RECORD), dir));
                self.need = len;
                self.hlen = 0;
            }
        }
    }
}

/// Wraps the raw TCP stream under rustls so both directions' encrypted records are
/// seen on the wire and their sizes/timings logged into a shared event vector.
struct RecordTap<S> {
    inner: S,
    start: Instant,
    out: Arc<Mutex<Vec<Event>>>,
    down: RecordParser,
    up: RecordParser,
}

impl<S> RecordTap<S> {
    fn new(inner: S, start: Instant, out: Arc<Mutex<Vec<Event>>>) -> Self {
        Self {
            inner,
            start,
            out,
            down: RecordParser::default(),
            up: RecordParser::default(),
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for RecordTap<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let t = this.start.elapsed().as_secs_f64();
        let r = Pin::new(&mut this.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &r {
            let filled = buf.filled();
            if filled.len() > before {
                this.down.feed(&filled[before..], t, 1, &this.out);
            }
        }
        r
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for RecordTap<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let t = this.start.elapsed().as_secs_f64();
        let r = Pin::new(&mut this.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &r {
            if *n > 0 {
                this.up.feed(&buf[..*n], t, -1, &this.out);
            }
        }
        r
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

// --- HTTP/1.1 over the tapped TLS stream ------------------------------------

type Conn = BufReader<TlsStream<RecordTap<TcpStream>>>;

/// A connection pool of one: reuses the current TLS connection while the next URL
/// is the same host (a real player keeps the connection), reconnecting otherwise.
struct Fetcher {
    start: Instant,
    out: Arc<Mutex<Vec<Event>>>,
    connector: TlsConnector,
    cur: Option<(String, Conn)>,
    /// Sent as `Referer` on every request when set.
    ///
    /// Some CDNs hotlink-protect their media and answer 403 without it -
    /// measured on Bilibili, where the same byte range is 403 bare and 206 with
    /// `https://www.bilibili.com/`. It is also what a real player sends, so
    /// setting it makes the capture MORE like the traffic being imitated, not
    /// less.
    referer: Option<String>,
}

impl Fetcher {
    fn new(start: Instant, out: Arc<Mutex<Vec<Event>>>) -> io::Result<Self> {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        Ok(Self {
            start,
            out,
            connector: TlsConnector::from(Arc::new(config)),
            cur: None,
            referer: None,
        })
    }

    async fn connect(&self, host: &str, port: u16) -> io::Result<Conn> {
        let tcp = tokio::time::timeout(Duration::from_secs(10), TcpStream::connect((host, port)))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "connect timeout"))??;
        tcp.set_nodelay(true).ok();
        let tap = RecordTap::new(tcp, self.start, self.out.clone());
        let sni = ServerName::try_from(host.to_string())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "bad SNI"))?;
        let tls = tokio::time::timeout(Duration::from_secs(15), self.connector.connect(sni, tap))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "handshake timeout"))??;
        Ok(BufReader::new(tls))
    }

    /// GET a URL, following up to 4 redirects, returning `(status, body)`. The tap logs
    /// record sizes as a side effect.
    async fn get(&mut self, url: &Url) -> io::Result<(u16, Vec<u8>)> {
        self.get_ranged(url, None).await
    }

    /// POST `body` to `url`, recording the UPSTREAM envelope it produces.
    async fn post(&mut self, url: &Url, body: &[u8]) -> io::Result<(u16, Vec<u8>)> {
        // No redirect following: a redirected POST would replay the body, which
        // doubles the upload and distorts the very envelope being measured.
        let (status, _location, resp) = self.get_once_with(url, None, Some(body)).await?;
        Ok((status, resp))
    }

    /// GET `url`, optionally only the `(offset, len)` byte range.
    async fn get_ranged(
        &mut self,
        url: &Url,
        range: Option<(u64, u64)>,
    ) -> io::Result<(u16, Vec<u8>)> {
        let mut cur = url.clone();
        for _ in 0..5 {
            let (status, location, body) = self.get_once(&cur, range).await?;
            if (301..=308).contains(&status) && status != 304 && status != 305 && status != 306 {
                if let Some(loc) = location.as_deref().and_then(|l| cur.join(l).ok()) {
                    cur = loc;
                    continue;
                }
            }
            return Ok((status, body));
        }
        Err(io::Error::new(io::ErrorKind::Other, "too many redirects"))
    }

    /// One request/response (no redirect handling), reusing the per-host connection.
    async fn get_once(
        &mut self,
        url: &Url,
        range: Option<(u64, u64)>,
    ) -> io::Result<(u16, Option<String>, Vec<u8>)> {
        self.get_once_with(url, range, None).await
    }

    /// [`Self::get_once`] with an optional request body (making it a POST).
    async fn get_once_with(
        &mut self,
        url: &Url,
        range: Option<(u64, u64)>,
        body: Option<&[u8]>,
    ) -> io::Result<(u16, Option<String>, Vec<u8>)> {
        let host = url
            .host_str()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no host"))?
            .to_string();
        let port = url.port_or_known_default().unwrap_or(443);
        let key = format!("{host}:{port}");
        if self.cur.as_ref().map(|(k, _)| *k != key).unwrap_or(true) {
            let c = self.connect(&host, port).await?;
            self.cur = Some((key, c));
        }
        let conn = &mut self.cur.as_mut().unwrap().1;
        let path = match url.query() {
            Some(q) => format!("{}?{}", url.path(), q),
            None => url.path().to_string(),
        };
        let referer = self.referer.clone();
        match request(conn, &host, &path, range, body, referer.as_deref()).await {
            Ok((status, location, body, keep)) => {
                if !keep {
                    self.cur = None;
                }
                Ok((status, location, body))
            }
            Err(e) => {
                self.cur = None;
                Err(e)
            }
        }
    }
}

/// Send one request and read the full response. Returns `(status, location, body, reusable)`.
async fn request(
    conn: &mut Conn,
    host: &str,
    path: &str,
    range: Option<(u64, u64)>,
    body: Option<&[u8]>,
    referer: Option<&str>,
) -> io::Result<(u16, Option<String>, Vec<u8>, bool)> {
    // HLS byte-range segments (`#EXT-X-BYTERANGE`) address slices of ONE media
    // file. Without the Range header every "segment" fetch pulls the whole file,
    // so the recording is a few huge bursts instead of a stream.
    let range_hdr = match range {
        Some((off, len)) => format!("Range: bytes={}-{}\r\n", off, off + len - 1),
        None => String::new(),
    };
    let referer_hdr = match referer {
        Some(r) => format!("Referer: {r}\r\n"),
        None => String::new(),
    };
    let req = match body {
        // POST: the only way to record an UPSTREAM envelope. A browse or video
        // capture is a client that barely speaks - measured upstream records max
        // around 600 bytes - so it cannot size-shape a QUIC carrier's upstream,
        // whose datagrams reach the path MTU. Uploading produces the large
        // client-to-server records that direction actually needs.
        Some(b) => format!(
            "POST {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {UA}\r\n\
             Accept: */*\r\nAccept-Encoding: identity\r\n{referer_hdr}\
             Content-Type: application/octet-stream\r\n\
             Content-Length: {}\r\nConnection: keep-alive\r\n\r\n",
            b.len()
        ),
        None => format!(
            "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {UA}\r\n\
             Accept: */*\r\nAccept-Encoding: identity\r\n{range_hdr}{referer_hdr}\
             Connection: keep-alive\r\n\r\n"
        ),
    };
    conn.get_mut().write_all(req.as_bytes()).await?;
    if let Some(b) = body {
        conn.get_mut().write_all(b).await?;
    }
    conn.get_mut().flush().await?;

    let mut line = String::new();
    if conn.read_line(&mut line).await? == 0 {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "no status"));
    }
    let status: u16 = line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad status line"))?;

    let mut content_len: Option<usize> = None;
    let mut chunked = false;
    let mut keep = true;
    let mut location: Option<String> = None;
    loop {
        let mut h = String::new();
        if conn.read_line(&mut h).await? == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "headers cut"));
        }
        let h = h.trim_end();
        if h.is_empty() {
            break;
        }
        let lower = h.to_ascii_lowercase();
        if let Some(v) = lower.strip_prefix("content-length:") {
            content_len = v.trim().parse().ok();
        } else if lower.starts_with("transfer-encoding:") && lower.contains("chunked") {
            chunked = true;
        } else if lower.starts_with("connection:") && lower.contains("close") {
            keep = false;
        } else if lower.starts_with("location:") {
            // preserve original case of the value (URLs are case-sensitive)
            location = h.split_once(':').map(|(_, v)| v.trim().to_string());
        }
    }

    let body = if chunked {
        read_chunked(conn).await?
    } else if let Some(n) = content_len {
        let take = n.min(BODY_CAP);
        if take < n {
            keep = false; // body not drained; can't reuse
        }
        let mut b = vec![0u8; take];
        conn.read_exact(&mut b).await?;
        b
    } else {
        keep = false;
        let mut b = Vec::new();
        conn.take(BODY_CAP as u64).read_to_end(&mut b).await?;
        b
    };
    Ok((status, location, body, keep))
}

async fn read_chunked(conn: &mut Conn) -> io::Result<Vec<u8>> {
    let mut body = Vec::new();
    loop {
        let mut size_line = String::new();
        if conn.read_line(&mut size_line).await? == 0 {
            break;
        }
        let sz = usize::from_str_radix(size_line.trim().split(';').next().unwrap_or("").trim(), 16)
            .unwrap_or(0);
        if sz == 0 {
            let mut trailer = String::new();
            while conn.read_line(&mut trailer).await? != 0 && !trailer.trim().is_empty() {
                trailer.clear();
            }
            break;
        }
        let mut chunk = vec![0u8; sz];
        conn.read_exact(&mut chunk).await?;
        body.extend_from_slice(&chunk);
        let mut crlf = [0u8; 2];
        conn.read_exact(&mut crlf).await?;
        if body.len() > BODY_CAP {
            break;
        }
    }
    Ok(body)
}

// --- HLS parsing ------------------------------------------------------------

/// Value of a `KEY="v"` or `KEY=v` attribute in an HLS tag line.
fn attr(s: &str, key: &str) -> Option<String> {
    let pat = format!("{key}=");
    let rest = &s[s.find(&pat)? + pat.len()..];
    Some(match rest.strip_prefix('"') {
        Some(q) => q.split('"').next().unwrap_or("").to_string(),
        None => rest.split(',').next().unwrap_or("").trim().to_string(),
    })
}

/// Repair a playlist URI whose query is preceded by a stray `&`.
///
/// Measured on the Dogus CDN that carries Turkey's broadcast channels: the
/// master lists `ntv_360p.m3u8&?sid=...`, which resolves to a PATH ending in `&`
/// and a query of `sid=...`. The server answers **200 with an empty body**, so
/// the failure presents as "no segments" rather than as an error, and the whole
/// source looks broken. Dropping the `&` that immediately precedes the first `?`
/// yields the URI the CDN actually serves.
///
/// Narrow by construction: only a `&` directly before the FIRST `?` is removed,
/// so a legitimate `&?` inside a query value is untouched.
fn normalise_uri(uri: &str) -> std::borrow::Cow<'_, str> {
    match uri.find('?') {
        Some(q) if q > 0 && uri.as_bytes()[q - 1] == b'&' => {
            std::borrow::Cow::Owned(format!("{}{}", &uri[..q - 1], &uri[q..]))
        }
        _ => std::borrow::Cow::Borrowed(uri),
    }
}

/// Master playlist -> `(bandwidth, variant url)` list.
fn parse_master(text: &str, base: &Url) -> Vec<(u64, Url)> {
    let lines: Vec<&str> = text.lines().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let l = lines[i].trim();
        if l.starts_with("#EXT-X-STREAM-INF") {
            let bw = attr(l, "BANDWIDTH")
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
            if let Some(uri) = lines.get(i + 1).map(|s| s.trim()) {
                if !uri.is_empty() && !uri.starts_with('#') {
                    if let Ok(u) = base.join(&normalise_uri(uri)) {
                        out.push((bw, u));
                    }
                }
            }
            i += 2;
            continue;
        }
        i += 1;
    }
    out
}

/// Media playlist -> `(segment duration s, segment url, byte range)` list
/// (including any init map).
///
/// `#EXT-X-BYTERANGE:<len>[@<off>]` addresses a slice of the URL that follows.
/// A missing `@off` means "immediately after the previous range of the same
/// resource", which is how PeerTube writes its playlists. Ignoring this makes
/// every segment fetch pull the entire media file, so a recording becomes a few
/// multi-megabyte bursts rather than a stream.
type Seg = (f64, Url, Option<(u64, u64)>);

fn parse_media(text: &str, base: &Url) -> Vec<Seg> {
    let mut out: Vec<Seg> = Vec::new();
    let mut dur = 0.0f64;
    let mut pending: Option<(u64, Option<u64>)> = None;
    let mut next_off: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
    for l in text.lines() {
        let l = l.trim();
        if let Some(rest) = l.strip_prefix("#EXTINF:") {
            dur = rest
                .split(',')
                .next()
                .and_then(|x| x.trim().parse().ok())
                .unwrap_or(0.0);
        } else if let Some(rest) = l.strip_prefix("#EXT-X-BYTERANGE:") {
            let mut it = rest.trim().splitn(2, '@');
            let len = it.next().and_then(|x| x.trim().parse::<u64>().ok());
            let off = it.next().and_then(|x| x.trim().parse::<u64>().ok());
            pending = len.map(|l| (l, off));
        } else if let Some(rest) = l.strip_prefix("#EXT-X-MAP:") {
            if let Some(uri) = attr(rest, "URI") {
                if let Ok(u) = base.join(&uri) {
                    // An init map may itself carry a BYTERANGE attribute.
                    let r = attr(rest, "BYTERANGE").and_then(|b| {
                        let mut it = b.trim().splitn(2, '@');
                        let len = it.next().and_then(|x| x.trim().parse::<u64>().ok())?;
                        let off = it.next().and_then(|x| x.trim().parse::<u64>().ok())?;
                        Some((off, len))
                    });
                    if let Some((off, len)) = r {
                        next_off.insert(u.to_string(), off + len);
                    }
                    out.push((0.0, u, r));
                }
            }
        } else if l.starts_with('#') || l.is_empty() {
            continue;
        } else if let Ok(u) = base.join(&normalise_uri(l)) {
            let range = pending.take().map(|(len, off)| {
                let key = u.to_string();
                let off = off.unwrap_or_else(|| next_off.get(&key).copied().unwrap_or(0));
                next_off.insert(key, off + len);
                (off, len)
            });
            out.push((dur, u, range));
            dur = 0.0;
        }
    }
    out
}

// --- HTML subresource parsing (browse class) --------------------------------

/// Page subresource URLs: quoted `src="..."` (images/scripts/media, incl. `data-src`)
/// and `href="....css"` (stylesheets), resolved absolute and deduped. Not navigation
/// links - we replay a page LOAD, not a crawl.
fn parse_subresources(html: &str, base: &Url) -> Vec<Url> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for attr in ["src=\"", "href=\""] {
        let is_href = attr.starts_with("href");
        let mut rest = html;
        while let Some(i) = rest.find(attr) {
            rest = &rest[i + attr.len()..];
            let Some(end) = rest.find('"') else { break };
            let val = &rest[..end];
            rest = &rest[end + 1..];
            if val.is_empty() || val.starts_with("data:") || val.starts_with('#') {
                continue;
            }
            if is_href && !(val.contains(".css") || val.contains("load.php")) {
                continue; // href: stylesheets/asset bundles only, not page links
            }
            if let Ok(u) = base.join(val) {
                if matches!(u.scheme(), "https" | "http") && seen.insert(u.as_str().to_string()) {
                    out.push(u);
                }
            }
        }
    }
    out
}

// --- discovery --------------------------------------------------------------

fn rand_u64() -> u64 {
    let mut b = [0u8; 8];
    getrandom::fill(&mut b).expect("getrandom");
    u64::from_le_bytes(b)
}

/// A random permutation of `0..n`.
fn shuffled(n: usize) -> Vec<usize> {
    let mut v: Vec<usize> = (0..n).collect();
    for i in (1..n).rev() {
        let j = (rand_u64() % (i as u64 + 1)) as usize;
        v.swap(i, j);
    }
    v
}

/// First HLS master-playlist URL in a PeerTube video-detail object.
fn hls_from_detail(d: &Value) -> Option<Url> {
    for sp in d.get("streamingPlaylists")?.as_array()? {
        if let Some(u) = sp.get("playlistUrl").and_then(Value::as_str) {
            if let Ok(url) = Url::parse(u) {
                return Some(url);
            }
        }
    }
    None
}

/// Query a PeerTube instance for a random recent video with an HLS playlist.
async fn peertube_hls(f: &mut Fetcher, instance: &str) -> io::Result<Url> {
    let list = Url::parse(&format!(
        "https://{instance}/api/v1/videos?count=25&sort=-trending&isLive=false&nsfw=false"
    ))
    .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "bad instance"))?;
    let (st, body) = f.get(&list).await?;
    if st != 200 {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("list HTTP {st}"),
        ));
    }
    let v: Value =
        serde_json::from_slice(&body).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let arr = v
        .get("data")
        .and_then(Value::as_array)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no data[]"))?;
    for i in shuffled(arr.len()) {
        let Some(id) = arr[i]
            .get("uuid")
            .or_else(|| arr[i].get("shortUUID"))
            .and_then(Value::as_str)
        else {
            continue;
        };
        let Ok(detail) = Url::parse(&format!("https://{instance}/api/v1/videos/{id}")) else {
            continue;
        };
        if let Ok((200, dbody)) = f.get(&detail).await {
            if let Ok(d) = serde_json::from_slice::<Value>(&dbody) {
                if let Some(pl) = hls_from_detail(&d) {
                    return Ok(pl);
                }
            }
        }
    }
    Err(io::Error::new(io::ErrorKind::Other, "no HLS video found"))
}

/// Undo the escaping a manifest URL picks up on its way into a page.
///
/// A site that inlines its manifest almost never does so as plain text: it is a
/// string inside JSON, inside an HTML attribute, sometimes escaped twice over.
/// Measured on OK.ru the literal bytes are
/// `hlsManifestUrl\&quot;:\&quot;https://...m3u8?cmd=x\\u0026expires=...`, so a
/// scanner that does not unescape first finds a URL truncated at the first `&`
/// and fetches a 400. Order matters: the doubled form has to go before the
/// single one, or it leaves a stray backslash mid-URL.
fn unescape_embedded(s: &str) -> String {
    let mut out = s.to_string();
    for (from, to) in [
        (r"\\u0026", "&"),
        ("\\u0026", "&"),
        (r"\\/", "/"),
        ("\\/", "/"),
        ("&amp;", "&"),
        ("&quot;", "\""),
        (r#"\""#, "\""),
    ] {
        if out.contains(from) {
            out = out.replace(from, to);
        }
    }
    out
}

/// Characters that cannot appear in a URL as it is written inside a page, and so
/// bound one when scanning. `,` is deliberately absent going FORWARD: real query
/// strings contain it (Rutube lists variant GUIDs comma-separated).
const URL_STOP_BEFORE: &[char] = &['"', '\'', '<', '>', '\\', '(', ')', ',', '=', ' ', '\t'];
const URL_STOP_AFTER: &[char] = &['"', '\'', '<', '>', '\\', ' ', '\t'];

/// Every HLS manifest URL that appears in `text`, resolved against `base`.
///
/// Deliberately a substring scan rather than an HTML parse: the URL is as likely
/// to be in a JSON blob inside a `<script>` as in an attribute, and a parser that
/// only understood one of those would miss the common case.
fn scan_manifests(text: &str, base: &Url) -> Vec<Url> {
    let text = unescape_embedded(text);
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    let mut from = 0usize;
    while let Some(i) = text[from..].find(".m3u8") {
        let hit = from + i;
        from = hit + ".m3u8".len();
        let start = text[..hit].rfind(URL_STOP_BEFORE).map_or(0, |p| {
            p + text[p..].chars().next().map_or(1, char::len_utf8)
        });
        let end = text[from..]
            .find(URL_STOP_AFTER)
            .map_or(text.len(), |p| from + p);
        let tok = text[start..end].trim();
        if tok.is_empty() {
            continue;
        }
        if let Ok(u) = base.join(tok) {
            if matches!(u.scheme(), "https" | "http") && seen.insert(u.as_str().to_string()) {
                out.push(u);
            }
        }
    }
    out
}

/// Links on `text` whose URL contains `needle`, resolved absolute and deduped.
fn links_containing(text: &str, base: &Url, needle: &str) -> Vec<Url> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(i) = rest.find("href=\"") {
        rest = &rest[i + 6..];
        let Some(end) = rest.find('"') else { break };
        let val = &rest[..end];
        rest = &rest[end + 1..];
        if !val.contains(needle) {
            continue;
        }
        if let Ok(u) = base.join(val) {
            if matches!(u.scheme(), "https" | "http") && seen.insert(u.as_str().to_string()) {
                out.push(u);
            }
        }
    }
    out
}

/// How many candidate video pages to open before giving up on one `Embedded`
/// source. Each is a real page load; a source that has not yielded a manifest in
/// three is not going to, and the next source is a better use of the time.
const EMBEDDED_PAGE_TRIES: usize = 3;

/// Confirm a candidate URL really is an HLS playlist before handing it on.
///
/// A scan finds strings that LOOK like manifests - a thumbnail sprite named
/// `.m3u8.jpg`, a dead CDN path, a URL whose signature has expired. Handing one
/// of those to the recorder costs a full retry cycle; one HEAD-shaped GET here
/// costs nothing, because discovery runs on a throwaway event log that is never
/// written to the library.
async fn is_playlist(f: &mut Fetcher, u: &Url) -> bool {
    matches!(f.get(u).await, Ok((200, b)) if b.starts_with(b"#EXTM3U"))
}

/// Find an HLS master playlist inlined in a site's own pages.
///
/// `video_path` marks links to video pages; `None` means scan `start` itself,
/// which is what an operator's explicit URL means.
async fn embedded_hls(f: &mut Fetcher, start: &Url, video_path: Option<&str>) -> io::Result<Url> {
    let (st, body) = f.get(start).await?;
    if st != 200 {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("start page HTTP {st}"),
        ));
    }
    let text = String::from_utf8_lossy(&body).into_owned();

    // The start page occasionally carries a manifest itself (an autoplaying
    // hero video), so it is always worth scanning before hopping.
    for cand in scan_manifests(&text, start) {
        if is_playlist(f, &cand).await {
            return Ok(cand);
        }
    }
    let Some(needle) = video_path else {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "no HLS manifest on page",
        ));
    };

    let pages = links_containing(&unescape_embedded(&text), start, needle);
    if pages.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("no links matching {needle}"),
        ));
    }
    for i in shuffled(pages.len()).into_iter().take(EMBEDDED_PAGE_TRIES) {
        let page = &pages[i];
        let Ok((200, pbody)) = f.get(page).await else {
            continue;
        };
        for cand in scan_manifests(&String::from_utf8_lossy(&pbody), page) {
            if is_playlist(f, &cand).await {
                return Ok(cand);
            }
        }
    }
    Err(io::Error::new(
        io::ErrorKind::Other,
        "no HLS manifest on any video page",
    ))
}

/// Rutube video IDs are 32 lowercase hex characters under `/video/`.
fn rutube_ids(text: &str) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(i) = rest.find("/video/") {
        rest = &rest[i + "/video/".len()..];
        let id: String = rest
            .chars()
            .take_while(char::is_ascii_hexdigit)
            .take(32)
            .collect();
        if id.len() == 32 && seen.insert(id.clone()) {
            out.push(id);
        }
    }
    out
}

/// Query Rutube for a random recent video with an HLS playlist.
///
/// Two hops rather than PeerTube's one, because Rutube's video-LIST API requires
/// credentials (it answers 401 to an anonymous request) while its per-video
/// play-options endpoint is public. So the IDs come off the homepage, which is a
/// page a Russian user loads anyway.
async fn rutube_hls(f: &mut Fetcher) -> io::Result<Url> {
    let home = Url::parse("https://rutube.ru/")
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
    let (st, body) = f.get(&home).await?;
    if st != 200 {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("rutube home HTTP {st}"),
        ));
    }
    let ids = rutube_ids(&String::from_utf8_lossy(&body));
    if ids.is_empty() {
        return Err(io::Error::new(io::ErrorKind::Other, "no video ids on page"));
    }
    for i in shuffled(ids.len()).into_iter().take(EMBEDDED_PAGE_TRIES) {
        let Ok(opts) = Url::parse(&format!(
            "https://rutube.ru/api/play/options/{}/?no_404=true&referer=https%3A%2F%2Frutube.ru",
            ids[i]
        )) else {
            continue;
        };
        let Ok((200, b)) = f.get(&opts).await else {
            continue;
        };
        let Ok(v) = serde_json::from_slice::<Value>(&b) else {
            continue;
        };
        if let Some(u) = rutube_m3u8(&v) {
            return Ok(u);
        }
    }
    Err(io::Error::new(io::ErrorKind::Other, "no HLS video found"))
}

/// The master-playlist URL in a Rutube play-options object.
fn rutube_m3u8(v: &Value) -> Option<Url> {
    let m = v.get("video_balancer")?.get("m3u8")?.as_str()?;
    Url::parse(m).ok()
}

/// Run an operator's extractor command and take the last URL it prints.
///
/// Deliberately dumb: it runs what it is given through a shell and reads stdout.
/// The command is operator configuration, exactly like `--url` or `--hls`, and
/// carries the same trust - anyone who can set it can already run commands.
/// `yt-dlp -g` prints the video URL and then the audio URL, so the LAST line is
/// taken; a single-URL extractor is unaffected.
fn hls_from_command(cmd: &str) -> io::Result<Url> {
    let out = std::process::Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .output()
        .map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("--hls-cmd could not run (is the extractor installed?): {e}"),
            )
        })?;
    if !out.status.success() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!(
                "--hls-cmd exited {}: {}",
                out.status,
                String::from_utf8_lossy(&out.stderr).trim()
            ),
        ));
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    let last = stdout
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with("http://") || l.starts_with("https://"))
        .next_back()
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "--hls-cmd printed no http(s) URL",
            )
        })?;
    Url::parse(last).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
}

/// A resolved video source: what to drive, and how.
///
/// Not every platform serves HLS. Bilibili - the only video source that is
/// reachable AND ordinary on a Chinese network - serves DASH representations
/// that are byte ranges into ONE file, and plenty of smaller sites just serve a
/// progressive MP4. Both are driven the same way: sequential `Range` requests
/// paced at the stream's bitrate, which is what a player's buffer does and is
/// already how the recorder handles PeerTube's `#EXT-X-BYTERANGE` playlists.
///
/// So the gap that kept whole regions out was never extraction difficulty; it
/// was that the recorder only spoke one container format.
#[derive(Debug, Clone)]
pub enum Stream {
    /// An HLS master or media playlist.
    Hls(Url),
    /// One media file, driven by byte ranges at `bitrate_bps`.
    Ranged {
        /// The media file.
        url: Url,
        /// Declared bitrate, which sets the pacing and the cover's cost.
        bitrate_bps: u64,
        /// `Referer` the CDN requires, if any. See [`Fetcher::referer`].
        referer: Option<String>,
    },
}

impl Stream {
    /// The underlying URL, whatever the container.
    #[must_use]
    pub fn as_url(&self) -> &Url {
        match self {
            Self::Hls(u) | Self::Ranged { url: u, .. } => u,
        }
    }

    /// The host serving it, for the recorded-trace line.
    #[must_use]
    pub fn host(&self) -> &str {
        self.as_url().host_str().unwrap_or("?")
    }
}

/// Bounds on a ranged request, so a pathological bitrate cannot produce a chunk
/// that is either a single packet or a multi-megabyte burst.
const RANGE_CHUNK_MIN: u64 = 16 * 1024;
const RANGE_CHUNK_MAX: u64 = 4 * 1024 * 1024;

/// Bytes to request so that one chunk is `gap` seconds of media at `bitrate_bps`.
///
/// Sized in TIME, not bytes, and this is the whole point. A DASH player asks for
/// roughly a segment at a time and then idles for about that segment's duration,
/// so the request size follows from the cadence you want - not the other way
/// round. A fixed byte count inverts that and breaks on low-bitrate streams: 512
/// KiB of Bilibili's 158 kbit/s rendition is **26.5 seconds** of media, so a
/// realtime capture would idle 26.5 s between requests against a 2 s latency
/// ceiling, and every such capture would be rejected or kept with a warning.
/// Deriving the chunk from the ceiling makes the recorder aim at the same number
/// the acceptance check enforces, which is the same one-source-of-truth rule
/// `record_one` already applies to `rt.max_gap`.
fn range_chunk_bytes(bitrate_bps: u64, gap: Duration) -> u64 {
    let secs = (gap.as_secs_f64() * RANGE_GAP_HEADROOM).max(0.25);
    (((bitrate_bps as f64) / 8.0 * secs) as u64).clamp(RANGE_CHUNK_MIN, RANGE_CHUNK_MAX)
}

/// Fraction of the latency ceiling one chunk of media is allowed to be.
///
/// Aiming at the whole ceiling leaves no room for the request itself. The stall
/// a capture is judged on is the sleep PLUS the time to first byte of the next
/// response, so a chunk sized at 100% of the budget measures just OVER it and
/// the capture is rejected - observed at 2.5 s against a 2.0 s ceiling. 0.6 of
/// the default budget is 1.2 s, which is also exactly [`SEG_GAP_MAX`], the cap
/// the HLS path uses for the same reason.
const RANGE_GAP_HEADROOM: f64 = 0.6;

/// Drive one byte-ranged media file and return its wire record envelope.
///
/// The DASH/progressive counterpart to [`record_stream`]. Pacing is the whole
/// point: a chunk represents a known number of seconds of media, and waiting
/// that long between requests is what makes the trace a STREAM whose average
/// rate is the stream's real bitrate, rather than a bulk download that would be
/// unaffordable as continuous cover.
async fn record_ranged(
    url: &Url,
    bitrate_bps: u64,
    referer: Option<&str>,
    rt: RealTime,
) -> io::Result<Vec<Event>> {
    let start = Instant::now();
    let out = Arc::new(Mutex::new(Vec::new()));
    let mut f = Fetcher::new(start, out.clone())?;
    f.referer = referer.map(str::to_string);

    // A zero or absurd bitrate would make the gap either zero (a bulk download)
    // or unbounded. Clamp to something a real rendition could plausibly be.
    let bitrate = bitrate_bps.clamp(50_000, 50_000_000);
    // Aim each request at one latency budget's worth of media, so the gaps this
    // produces are gaps the acceptance check will accept.
    let chunk = range_chunk_bytes(bitrate, rt.max_gap);
    let secs_per_chunk = chunk as f64 * 8.0 / bitrate as f64;
    eprintln!(
        "  ranged stream: {:.0} kbit/s, {} KiB per request, {:.1}s of media each \
         ({:.2} GB/day if replayed continuously)",
        bitrate as f64 / 1000.0,
        chunk / 1024,
        secs_per_chunk,
        bitrate as f64 / 8.0 * 86400.0 / 1e9
    );

    let (max_segs, max_bytes, max_time) = rt.budget();
    let mut got = 0usize;
    let mut bytes = 0usize;
    let mut off = 0u64;
    while got < max_segs && bytes < max_bytes && start.elapsed() < max_time {
        match f.get_ranged(url, Some((off, chunk))).await {
            // 206 is the success status for a ranged request; a 200 means the
            // server ignored Range and sent the whole file, which is not a
            // stream and must not be paced as though it were.
            Ok((206, b)) => {
                if b.is_empty() {
                    break;
                }
                bytes += b.len();
                got += 1;
                off += b.len() as u64;
                // Short read means end of file: stop rather than spin on ranges
                // past the end, which answer 416 forever.
                if (b.len() as u64) < chunk {
                    break;
                }
            }
            // The server ignored Range and sent the whole file. The tap has
            // already logged those records, so the capture is whatever that one
            // burst was; there is nothing to pace and no point asking again.
            Ok((200, _)) => break,
            _ => break,
        }
        let want = Duration::from_secs_f64(secs_per_chunk);
        tokio::time::sleep(if rt.real_time {
            want
        } else {
            want.min(SEG_GAP_MAX)
        })
        .await;
    }
    drop(f);
    let events = out.lock().unwrap().clone();
    Ok(events)
}

/// A random recent Aparat video hash.
///
/// The tag listing is the API behind the homepage's own rails, so this is a
/// request the site makes for every visitor rather than a scraper-shaped one.
async fn aparat_hash(f: &mut Fetcher) -> io::Result<String> {
    let list = Url::parse("https://www.aparat.com/api/fa/v1/video/video/list/tagid/1")
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
    let (st, body) = f.get(&list).await?;
    if st != 200 {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("aparat list HTTP {st}"),
        ));
    }
    let text = String::from_utf8_lossy(&body);
    let mut hashes = aparat_hashes(&text);
    if hashes.is_empty() {
        return Err(io::Error::new(io::ErrorKind::Other, "no video hashes"));
    }
    let i = (rand_u64() as usize) % hashes.len();
    Ok(hashes.swap_remove(i))
}

/// Video hashes in an Aparat listing response: the `uid` fields.
fn aparat_hashes(text: &str) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(i) = rest.find("\"uid\"") {
        rest = &rest[i + 5..];
        let Some(q) = rest.find('"') else { break };
        let after = &rest[q + 1..];
        let Some(end) = after.find('"') else { break };
        let id = &after[..end];
        rest = &after[end + 1..];
        if !id.is_empty()
            && id.len() <= 24
            && id.chars().all(|c| c.is_ascii_alphanumeric())
            && seen.insert(id.to_string())
        {
            out.push(id.to_string());
        }
    }
    out
}

/// Playable streams in an Aparat video-detail object, best first.
///
/// The HLS link comes first, but it is only a CANDIDATE: that endpoint is a
/// signed redirector which sometimes answers 400 (measured), while the
/// per-profile CDN files are handed out plainly and a progressive file is a
/// perfectly good ranged stream. Returning both and letting the caller VALIDATE
/// is the point - preferring the HLS link unconditionally made the progressive
/// path unreachable in exactly the case it exists for, because the recorder's
/// retry loop re-resolves and picks the same broken link every time.
///
/// Profiles are ordered smallest-first by the API, which is the order a
/// low-bitrate capture wants.
fn aparat_candidates(d: &Value, low_bitrate: bool) -> Vec<Stream> {
    let Some(attrs) = d.get("data").and_then(|x| x.get("attributes")) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if let Some(u) = attrs
        .get("hls")
        .and_then(|h| h.get("link"))
        .and_then(Value::as_str)
        .and_then(|l| Url::parse(l).ok())
    {
        out.push(Stream::Hls(u));
    }
    if let Some(all) = attrs.get("file_link_all").and_then(Value::as_array) {
        let pick = if low_bitrate { all.first() } else { all.last() };
        if let Some(s) = pick.and_then(|p| {
            Some(Stream::Ranged {
                url: p
                    .get("urls")?
                    .as_array()?
                    .first()?
                    .as_str()
                    .and_then(|u| Url::parse(u).ok())?,
                referer: None,
                // The API reports a size and a profile, not a bitrate. Rather
                // than invent one, take the profile height as a coarse proxy -
                // the pacing only has to be the right order of magnitude for the
                // trace to read as a stream rather than a download.
                bitrate_bps: aparat_profile_bps(p.get("profile").and_then(Value::as_str)),
            })
        }) {
            out.push(s);
        }
    }
    out
}

/// A plausible bitrate for an Aparat profile label like `360p`.
fn aparat_profile_bps(profile: Option<&str>) -> u64 {
    match profile
        .map(|p| p.trim_end_matches('p'))
        .and_then(|p| p.parse::<u64>().ok())
    {
        Some(h) if h <= 144 => 150_000,
        Some(h) if h <= 240 => 300_000,
        Some(h) if h <= 360 => 600_000,
        Some(h) if h <= 480 => 1_000_000,
        Some(h) if h <= 720 => 2_000_000,
        Some(_) => 4_000_000,
        None => 600_000,
    }
}

/// Query Aparat for a random recent video's stream.
async fn aparat_stream_for(f: &mut Fetcher, low_bitrate: bool) -> io::Result<Stream> {
    for _ in 0..EMBEDDED_PAGE_TRIES {
        let hash = aparat_hash(f).await?;
        let Ok(detail) = Url::parse(&format!(
            "https://www.aparat.com/api/fa/v1/video/video/show/videohash/{hash}?pr=1&mf=1"
        )) else {
            continue;
        };
        let Ok((200, b)) = f.get(&detail).await else {
            continue;
        };
        let Ok(v) = serde_json::from_slice::<Value>(&b) else {
            continue;
        };
        for cand in aparat_candidates(&v, low_bitrate) {
            match &cand {
                // Validate the playlist here so a refused redirector falls
                // through to the progressive file NOW, rather than failing at
                // record time and being re-picked on every retry.
                Stream::Hls(u) if !is_playlist(f, u).await => continue,
                // A ranged candidate is not probed: the first `Range` request is
                // the recording, so a probe would cost a real fetch to learn
                // what the capture is about to learn anyway.
                _ => return Ok(cand),
            }
        }
    }
    Err(io::Error::new(io::ErrorKind::Other, "no playable video"))
}

/// Bilibili's CDN requires this on media requests, and its API on `playurl`.
const BILIBILI_REFERER: &str = "https://www.bilibili.com/";

/// The DASH representation to wear from a Bilibili play-options object.
///
/// Bilibili serves no HLS: `dash.video[]` lists representations that are byte
/// ranges into one file, each with a real `bandwidth`. Picking by bandwidth is
/// picking the cover's 24/7 cost, so it follows the budget exactly as the HLS
/// variant choice does.
fn bilibili_stream(d: &Value, low_bitrate: bool) -> Option<Stream> {
    let mut reps: Vec<(u64, &str)> = d
        .get("data")?
        .get("dash")?
        .get("video")?
        .as_array()?
        .iter()
        .filter_map(|r| {
            Some((
                r.get("bandwidth").and_then(Value::as_u64)?,
                r.get("baseUrl")
                    .or_else(|| r.get("base_url"))
                    .and_then(Value::as_str)?,
            ))
        })
        .collect();
    reps.sort_by_key(|(bw, _)| *bw);
    let (bw, url) = if low_bitrate {
        reps.first()
    } else {
        reps.last()
    }?;
    Some(Stream::Ranged {
        url: Url::parse(url).ok()?,
        bitrate_bps: *bw,
        // Bilibili hotlink-protects its CDN: the same range is 403 bare and 206
        // with this, which is also exactly what its web player sends.
        referer: Some(BILIBILI_REFERER.to_string()),
    })
}

/// Query Bilibili for a random popular video's DASH stream.
///
/// Both endpoints are public and unauthenticated: `popular` is the site's own
/// trending rail, and `playurl` is what the web player calls.
async fn bilibili_stream_for(f: &mut Fetcher, low_bitrate: bool) -> io::Result<Stream> {
    let list = Url::parse("https://api.bilibili.com/x/web-interface/popular")
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
    let (st, body) = f.get(&list).await?;
    if st != 200 {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("bilibili popular HTTP {st}"),
        ));
    }
    let v: Value =
        serde_json::from_slice(&body).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let arr = v
        .get("data")
        .and_then(|d| d.get("list"))
        .and_then(Value::as_array)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no data.list[]"))?;
    for i in shuffled(arr.len()).into_iter().take(EMBEDDED_PAGE_TRIES) {
        let (Some(bvid), Some(cid)) = (
            arr[i].get("bvid").and_then(Value::as_str),
            arr[i].get("cid").and_then(Value::as_u64),
        ) else {
            continue;
        };
        // fnval=16 asks for DASH. Without it the API answers with a progressive
        // MP4 and no bandwidth figure, which would leave the pacing guessing.
        let Ok(play) = Url::parse(&format!(
            "https://api.bilibili.com/x/player/playurl?bvid={bvid}&cid={cid}&fnval=16&fourk=1"
        )) else {
            continue;
        };
        let Ok((200, b)) = f.get(&play).await else {
            continue;
        };
        let Ok(d) = serde_json::from_slice::<Value>(&b) else {
            continue;
        };
        if let Some(s) = bilibili_stream(&d, low_bitrate) {
            return Ok(s);
        }
    }
    Err(io::Error::new(io::ErrorKind::Other, "no DASH video found"))
}

/// The result of probing one video source.
#[derive(Debug, Clone)]
pub struct SourceCheck {
    /// Which source was probed, as it appears in diagnostics.
    pub source: String,
    /// Preference group it belongs to; group 0 is tried first.
    pub group: usize,
    /// The host it resolved to, or why it failed.
    pub outcome: Result<String, String>,
}

/// Probe every video source a pack lists, without recording anything.
///
/// The regional source lists are **reachability claims that will rot**: a site
/// changes its player, an API starts demanding credentials, a CDN adds a header
/// check. Each of those presents at runtime as a video class that quietly never
/// fills, which is the failure mode this whole module is written to avoid - so
/// there has to be a way to ask the question directly, from a machine on the
/// network in question, before a user discovers it.
///
/// Resolution only: it stops at the manifest and never drives a stream, so the
/// check is cheap enough to run on a schedule.
pub async fn check_video_sources(pack: &packs::SourcePack, low_bitrate: bool) -> Vec<SourceCheck> {
    let out = Arc::new(Mutex::new(Vec::new()));
    let Ok(mut f) = Fetcher::new(Instant::now(), out) else {
        return Vec::new();
    };
    let mut results = Vec::new();
    for (group, sources) in pack.video_sources().iter().enumerate() {
        for src in sources {
            let outcome = match video_source_stream(&mut f, src, low_bitrate).await {
                Ok(s) => Ok(s.host().to_string()),
                Err(e) => Err(e.to_string()),
            };
            results.push(SourceCheck {
                source: video_source_label(src),
                group,
                outcome,
            });
        }
    }
    results
}

/// Probe every BROWSE source a pack lists, without recording anything.
///
/// Browse is checked as well as video because browse is the class that matters
/// most: it carries the tunnel's upstream and is recorded at every budget, while
/// video only appears above 6 GB/day. A checker that only looked at video would
/// report a healthy pack whose actually-load-bearing sources were all blocked.
///
/// A page is "reachable" here if it answers 200 and returns a body worth
/// recording. The floor is deliberately low - this is a reachability probe, not
/// an acceptance check, and `record_one` already rejects a capture that turns
/// out too thin.
pub async fn check_browse_sources(pack: &packs::SourcePack) -> Vec<SourceCheck> {
    let out = Arc::new(Mutex::new(Vec::new()));
    let Ok(mut f) = Fetcher::new(Instant::now(), out) else {
        return Vec::new();
    };
    let mut results = Vec::new();
    for url in pack.browse_urls() {
        let outcome = match Url::parse(&url) {
            Err(e) => Err(e.to_string()),
            Ok(u) => match f.get(&u).await {
                Ok((200, body)) if body.len() >= MIN_BROWSE_PROBE_BYTES => {
                    Ok(format!("{} bytes", body.len()))
                }
                Ok((200, body)) => Err(format!("200 but only {} bytes", body.len())),
                Ok((st, _)) => Err(format!("HTTP {st}")),
                Err(e) => Err(e.to_string()),
            },
        };
        results.push(SourceCheck {
            source: url,
            group: 0,
            outcome,
        });
    }
    results
}

/// Smallest body a browse probe treats as a real page.
///
/// Block pages and captive-portal interstitials are small; a real article is
/// not. This only has to tell "the site answered" from "something answered for
/// it".
const MIN_BROWSE_PROBE_BYTES: usize = 2048;

/// What to print when a source fails, so the operator can tell WHICH one did.
fn video_source_label(src: &packs::VideoSource) -> String {
    match src {
        packs::VideoSource::PeerTube(h) => h.clone(),
        packs::VideoSource::Rutube => "rutube.ru".to_string(),
        packs::VideoSource::Aparat => "aparat.com".to_string(),
        packs::VideoSource::Bilibili => "bilibili.com".to_string(),
        packs::VideoSource::Embedded { start, .. } => start.clone(),
    }
}

/// Resolve one video source to a drivable stream.
async fn video_source_stream(
    f: &mut Fetcher,
    src: &packs::VideoSource,
    low_bitrate: bool,
) -> io::Result<Stream> {
    // Set per source and always cleared, because one fetcher walks the whole
    // list: a referer left set from a previous source would be sent to the next
    // one, which is both wrong and conspicuous.
    f.referer = match src {
        packs::VideoSource::Bilibili => Some(BILIBILI_REFERER.to_string()),
        _ => None,
    };
    let resolved = video_source_stream_inner(f, src, low_bitrate).await;
    f.referer = None;
    resolved
}

async fn video_source_stream_inner(
    f: &mut Fetcher,
    src: &packs::VideoSource,
    low_bitrate: bool,
) -> io::Result<Stream> {
    match src {
        packs::VideoSource::PeerTube(host) => peertube_hls(f, host).await.map(Stream::Hls),
        packs::VideoSource::Rutube => rutube_hls(f).await.map(Stream::Hls),
        packs::VideoSource::Aparat => aparat_stream_for(f, low_bitrate).await,
        packs::VideoSource::Bilibili => bilibili_stream_for(f, low_bitrate).await,
        packs::VideoSource::Embedded { start, video_path } => {
            let u = Url::parse(start)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
            embedded_hls(f, &u, video_path.as_deref())
                .await
                .map(Stream::Hls)
        }
    }
}

// --- record one stream ------------------------------------------------------

/// Drive one HLS stream and return its wire record envelope.
async fn record_stream(master: &Url, rt: RealTime) -> io::Result<Vec<Event>> {
    let start = Instant::now();
    let out = Arc::new(Mutex::new(Vec::new()));
    let mut f = Fetcher::new(start, out.clone())?;

    let (st, body) = f.get(master).await?;
    if st != 200 {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("master HTTP {st}"),
        ));
    }
    let text = String::from_utf8_lossy(&body);
    let segs = if text.contains("#EXT-X-STREAM-INF") {
        // Variant choice sets the cover's BITRATE, which for an always-on posture
        // is a bandwidth bill paid 24/7. `high` yields more MTU-sized records per
        // second; `low` yields a genuinely low-bitrate rendition (the one to
        // replay continuously - see `RealTime`).
        let mut variants = parse_master(&text, master);
        variants.sort_by_key(|(bw, _)| *bw);
        // Report what the source actually offers. For an always-on posture the
        // chosen variant's bitrate IS the 24/7 bandwidth bill, so it must be
        // visible at record time rather than discovered from the phone bill.
        let offered: Vec<String> = variants
            .iter()
            .map(|(bw, _)| format!("{:.0}k", *bw as f64 / 1000.0))
            .collect();
        let chosen = if rt.low_bitrate {
            variants.first()
        } else {
            variants.last()
        }
        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "no variants"))?;
        eprintln!(
            "  variants offered: [{}] -> picked {:.0} kbit/s ({:.2} GB/day if replayed continuously)",
            offered.join(", "),
            chosen.0 as f64 / 1000.0,
            chosen.0 as f64 / 8.0 * 86400.0 / 1e9
        );
        let pick = chosen.1.clone();
        let (st2, mbody) = f.get(&pick).await?;
        if st2 != 200 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("media HTTP {st2}"),
            ));
        }
        parse_media(&String::from_utf8_lossy(&mbody), &pick)
    } else {
        parse_media(&text, master)
    };
    if segs.is_empty() {
        return Err(io::Error::new(io::ErrorKind::Other, "no segments"));
    }

    let (max_segs, max_bytes, max_time) = rt.budget();
    eprintln!(
        "  media playlist: {} segments, {:.0}s of media, byte-ranged={}",
        segs.len(),
        segs.iter().map(|(d, _, _)| *d).sum::<f64>(),
        segs.iter().any(|(_, _, r)| r.is_some())
    );
    let mut got = 0usize;
    let mut bytes = 0usize;
    for (dur, seg, range) in &segs {
        if got >= max_segs || bytes >= max_bytes || start.elapsed() >= max_time {
            break;
        }
        // 206 Partial Content is the success status for a ranged segment.
        if let Ok((200 | 206, b)) = f.get_ranged(seg, *range).await {
            bytes += b.len();
            got += 1;
        }
        // Wait like a player draining its buffer. The gap is what makes the trace
        // a STREAM rather than a bulk download: a real player fetches a segment
        // and then idles for roughly its media duration, so the trace's average
        // rate equals the stream's bitrate. Capping the gap (the default, which
        // keeps recording quick) compresses several seconds of media into one,
        // producing a trace whose replay rate is many times the real stream's -
        // fine as a shape sample, unaffordable as continuous cover.
        let want = Duration::from_secs_f64(dur.max(0.0));
        let gap = if rt.real_time {
            want
        } else {
            want.min(SEG_GAP_MAX)
        };
        tokio::time::sleep(gap).await;
    }
    drop(f);
    let events = out.lock().unwrap().clone();
    Ok(events)
}

/// Drive one page load (HTML + its subresources) and return its wire envelope - a
/// web-browsing shape (bursty small/medium objects), distinct from streaming video.
/// Drive a real HTTPS upload and return its wire envelope.
///
/// This exists because no download-shaped capture can size-shape a QUIC carrier's
/// UPSTREAM. Measured on real browse and video captures, upstream records top out
/// around 600 bytes - a client fetching things barely speaks - while a QUIC
/// datagram runs to the path MTU. Padding cannot shrink a datagram, so those
/// records are unusable in that direction and the upstream simply goes unshaped.
/// An upload produces the large client-to-server records the direction needs.
///
/// The target is always operator-supplied: this posts real bytes to a real
/// server, so it points at infrastructure the operator controls rather than
/// quietly loading a stranger's endpoint. `chunks` uploads are sent on one
/// connection with a player-like gap between them, so the trace has genuine
/// structure rather than one flat blast.
async fn record_upload(target: &Url, body_bytes: usize, chunks: usize) -> io::Result<Vec<Event>> {
    let start = Instant::now();
    let out = Arc::new(Mutex::new(Vec::new()));
    let mut f = Fetcher::new(start, out.clone())?;

    // Open with a real page load against the same host. Uploads do not happen in
    // a vacuum - a user lands on the page, then submits - and the page load is
    // where the SMALL upstream records come from. Without it the capture is
    // nothing but 16 KiB TLS records, and a cover whose upstream is uniformly
    // maximal pads every datagram to the MTU, which is a fingerprint of its own.
    // Best-effort: some upload endpoints are bare API paths with no page to load,
    // and that is not a reason to lose the upload envelope.
    if let Err(e) = browse_into(&mut f, target, false).await {
        eprintln!("  upload: page load skipped ({e}); recording the POST envelope only");
    }

    // Incompressible payload: a compressing endpoint would otherwise shrink the
    // very records being measured.
    let mut body = vec![0u8; body_bytes.clamp(1024, 8 * 1024 * 1024)];
    getrandom::fill(&mut body).map_err(|e| io::Error::other(e.to_string()))?;

    let mut ok = 0usize;
    for i in 0..chunks.max(1) {
        match f.post(target, &body).await {
            Ok((200..=299, _)) => ok += 1,
            Ok((st, _)) => {
                if i == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        format!("upload HTTP {st} (does the target accept POST?)"),
                    ));
                }
                break;
            }
            Err(e) => {
                if i == 0 {
                    return Err(e);
                }
                break;
            }
        }
        tokio::time::sleep(UPLOAD_GAP).await;
    }
    if ok == 0 {
        return Err(io::Error::new(io::ErrorKind::Other, "no upload succeeded"));
    }
    drop(f);
    let events = out.lock().unwrap().clone();
    Ok(events)
}

async fn record_browse(page: &Url, rt: RealTime) -> io::Result<Vec<Event>> {
    let start = Instant::now();
    let out = Arc::new(Mutex::new(Vec::new()));
    let mut f = Fetcher::new(start, out.clone())?;
    let first_html = browse_into(&mut f, page, true).await?;

    // A session, not a page load. Without this the trace ends when the burst
    // ends, and replaying it as continuous cover means loading pages forever -
    // a shape no browser produces. Follow real links from the page we already
    // fetched, so the follow-ups are a real navigation path rather than a
    // synthesised one.
    //
    // Length is governed by SPAN, not page count: the span sets the replay
    // loop's period, and holding it fixed is what stops a short loop becoming a
    // fingerprint. Whether that span is filled with waiting or with pages is
    // then free to choose, and pages win - see DWELL_MIN's header for the
    // measurement and the Jensen argument behind it.
    if rt.real_time {
        let mut here = page.clone();
        let mut html = first_html;
        for i in 1..SESSION_MAX_PAGES {
            if start.elapsed() >= SESSION_TARGET_SPAN {
                break;
            }
            // Choose where to go BEFORE dwelling, from the HTML already in hand.
            // Re-fetching the current page to read its links would put two
            // identical loads back to back in the trace - which no browser does,
            // and which doubles the capture's cost for nothing.
            //
            // When a page offers no usable same-origin link, revisit the start
            // page rather than ending the session. A link-sparse site would
            // otherwise collapse the capture back to a single page load, well
            // under the span target, and it does so silently. Measured: a
            // kernel.org capture ended at 1.2 s. Wikipedia hides this because it
            // is link-dense; a custom or regional pack will not. Revisiting is
            // also a real thing people do.
            let next = pick_next_page(&here, &html).unwrap_or_else(|| page.clone());
            // Hold the connection open through the dwell and record whatever the
            // site sends in that window; if it sends nothing, the silence is real
            // too. Then navigate.
            dwell(i as u64, start, rt.max_gap).await;
            match browse_into(&mut f, &next, false).await {
                Ok(body) => {
                    here = next;
                    html = body;
                }
                Err(_) => break,
            }
        }
    }
    drop(f);
    let events = out.lock().unwrap().clone();
    Ok(events)
}

/// Sleep a per-gap-varied inter-page dwell, bounded by the tunnel's own
/// worst-case latency. Varied, not fixed: a constant period between bursts
/// would be a periodicity fingerprint of its own.
async fn dwell(seq: u64, start: Instant, max_gap: Duration) {
    // Cheap jitter from a source that is already varying, so the recorder needs
    // no RNG plumbing and two concurrent recordings do not sit in lockstep.
    let mix = start.elapsed().as_nanos() as u64 ^ (seq.wrapping_mul(0x9E37_79B9_7F4A_7C15));
    tokio::time::sleep(Duration::from_millis(dwell_ms(mix, max_gap))).await;
}

/// The dwell length for one gap, split out so the CEILING is testable without
/// sleeping. The invariant that matters is `<= max_gap`: a capture that breaks
/// it is one the acceptance check will reject, so the recorder must not be
/// able to produce it.
fn dwell_ms(mix: u64, max_gap: Duration) -> u64 {
    // The ceiling applies to the gap the CHECKER observes, and that gap is the
    // dwell PLUS the next page's time to first byte (DNS, TLS resumption, the
    // request itself). Dwelling right up to the ceiling therefore overshoots it
    // by the fetch latency: measured at 2.31-2.32 s against a 2.0 s ceiling,
    // which sent every capture through the full retry loop before being kept
    // anyway. Reserve headroom instead.
    let hi = max_gap
        .mul_f64(DWELL_CEILING_FRACTION)
        .max(Duration::from_millis(50));
    let lo = DWELL_MIN.min(hi);
    let span = hi.as_millis() as u64 - lo.as_millis() as u64;
    lo.as_millis() as u64 + (mix % span.max(1))
}

/// Choose the next page of a browsing session: a real link out of `html`,
/// or `None` when the page offers no usable same-origin link.
///
/// Pure: it reads the HTML the caller already downloaded rather than fetching
/// the page again.
fn pick_next_page(current: &Url, body: &[u8]) -> Option<Url> {
    let html = String::from_utf8_lossy(body);
    let mut candidates: Vec<Url> = Vec::new();
    for cap in html.split("href=\"").skip(1) {
        let Some(raw) = cap.split('"').next() else {
            continue;
        };
        // Same-origin document links only: an off-site jump usually means a new
        // TLS connection, and the tap follows one connection at a time.
        if raw.starts_with('#') || raw.contains("://") {
            continue;
        }
        if let Ok(u) = current.join(raw) {
            if u.host_str() == current.host_str() && u != *current {
                candidates.push(u);
            }
        }
        if candidates.len() >= 32 {
            break;
        }
    }
    if candidates.is_empty() {
        return None;
    }
    let idx = (Instant::now().elapsed().as_nanos() as usize).wrapping_add(candidates.len());
    Some(candidates[idx % candidates.len()].clone())
}

/// Fetch `page` and its subresources through `f`, logging into `f`'s tap.
///
/// Split out of `record_browse` so an upload capture can open with a real page
/// load. That matters: a bare POST run yields nothing but 16 KiB TLS records,
/// and a cover whose upstream is uniformly maximal shapes every datagram to the
/// MTU - itself a fingerprint. A browse-then-upload session is one real thing a
/// user does, and it carries BOTH bands: hundreds of small request records and a
/// run of big ones.
///
/// `require_subs` is false for the upload path, where the POST supplies the
/// bytes and a thin page is not a reason to throw the capture away.
async fn browse_into(f: &mut Fetcher, page: &Url, require_subs: bool) -> io::Result<Vec<u8>> {
    // Budget from THIS page's start, not the session's. A multi-page session
    // spends most of its wall clock in reading dwell, so a session-relative
    // budget would starve every page after the first of its subresources and
    // leave a trace whose later bursts are a single request each.
    let start = Instant::now();
    let (st, body) = f.get(page).await?;
    if st != 200 {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("page HTTP {st}"),
        ));
    }
    let subs = parse_subresources(&String::from_utf8_lossy(&body), page);
    if subs.is_empty() && require_subs {
        // Name the page. Someone debugging their own `--sources` list needs to
        // know WHICH source was unsuitable; a bare "no subresources" repeated
        // three times reads as a bug in the recorder rather than a bad pick.
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!(
                "{page} has no subresources, so it cannot produce a browse envelope - \
                 pick a page that loads assets"
            ),
        ));
    }

    let mut bytes = 0usize;
    for (n, u) in subs.iter().enumerate() {
        if n >= MAX_ASSETS || bytes >= MAX_BYTES || start.elapsed() >= MAX_TIME {
            break;
        }
        if let Ok((200, b)) = f.get(u).await {
            bytes += b.len();
        }
        tokio::time::sleep(BROWSE_GAP).await;
    }
    Ok(body)
}

// --- library output ---------------------------------------------------------

fn next_index(dir: &Path) -> usize {
    let mut max = None;
    if let Ok(rd) = fs::read_dir(dir) {
        for e in rd.flatten() {
            if let Some(stem) = e.path().file_stem().and_then(|s| s.to_str()) {
                if let Ok(n) = stem.parse::<usize>() {
                    max = Some(max.map_or(n, |m: usize| m.max(n)));
                }
            }
        }
    }
    max.map_or(0, |m| m + 1)
}

/// Keep only the `keep` newest `<n>.csv` files (by index).
pub fn prune(dir: &Path, keep: usize) {
    let mut idx: Vec<usize> = fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| e.path().file_stem()?.to_str()?.parse().ok())
        .collect();
    if idx.len() <= keep {
        return;
    }
    idx.sort_unstable();
    for n in &idx[..idx.len() - keep] {
        let _ = fs::remove_file(dir.join(format!("{n}.csv")));
    }
}

fn write_csv(dir: &Path, events: &[Event]) -> io::Result<PathBuf> {
    fs::create_dir_all(dir)?;
    let path = dir.join(format!("{}.csv", next_index(dir)));
    let mut s = String::from("t,size,dir\n");
    for (t, sz, dr) in events {
        s.push_str(&format!("{t:.6},{sz},{dr}\n"));
    }
    fs::write(&path, s)?;
    Ok(path)
}

fn down_bytes(events: &[Event]) -> usize {
    events
        .iter()
        .filter(|(_, _, d)| *d > 0)
        .map(|(_, s, _)| *s as usize)
        .sum()
}

/// What a recorded envelope costs if replayed around the clock.
///
/// A cover envelope replayed continuously IS the bandwidth bill, in both
/// directions, forever. Whoever adopts a profile should see this number before
/// the invoice does - so the CLI prints it and the auto-sourcer logs it.
#[derive(Debug, Clone, Copy, Default)]
pub struct Cost {
    /// Wall-clock span of the capture, in seconds.
    pub span_secs: f64,
    /// Downstream rate, kbit/s.
    pub down_kbps: f64,
    /// Upstream rate, kbit/s.
    pub up_kbps: f64,
    /// Downstream volume if replayed for a day, GB.
    pub down_gb_day: f64,
    /// Upstream volume if replayed for a day, GB.
    pub up_gb_day: f64,
    /// Longest downstream gap, in seconds - the tunnel's WORST-CASE LATENCY.
    ///
    /// A record only leaves on a schedule token, so a capture's silent stretches
    /// become stalls of exactly that length for whoever is using the tunnel. A
    /// dwelled browse capture is roughly 90% silent with multi-second reading
    /// pauses, which measured as 66 SECONDS of latency on a live cluster. No
    /// amount of bandwidth makes that usable, and alignment cannot help: it
    /// moves sizes between slots and never moves a slot's time.
    pub max_gap_secs: f64,
    /// Longest UPSTREAM gap, in seconds.
    ///
    /// Kept separate because the two directions fail differently and only one of
    /// them was ever being checked. `max_gap_secs` is the data plane's latency,
    /// which is a downstream property. The HANDSHAKE is multi-round-trip, so a
    /// quiet upstream stalls it exactly as hard as a quiet downstream -
    /// `mirage_transport_reality::paced_handshake_budget` takes the worst over
    /// BOTH directions for precisely that reason, while acceptance here looked
    /// only downstream and would pass a capture with a minute-long upstream
    /// silence.
    pub up_gap_secs: f64,
    /// Seconds from the capture's start to its first DOWNSTREAM record.
    ///
    /// The tunnel cannot send until a token arrives, so this is dead air at
    /// connect time with no error anywhere - the session simply does not
    /// progress. It is the measured reason video cover "would not come up at
    /// all": a video flow opens with a manifest fetch and then a quiet stretch
    /// before the first segment, and a faithfully replayed handshake crawls past
    /// its deadline inside it. Nothing else in `Cost` sees this, because a
    /// capture can have a short worst-gap and still open slowly.
    pub open_down_secs: f64,
    /// Seconds from the capture's start to its first UPSTREAM record.
    pub open_up_secs: f64,
}

impl Cost {
    fn of(events: &[Event]) -> Self {
        let span = match (events.first(), events.last()) {
            (Some((a, _, _)), Some((b, _, _))) if b > a => b - a,
            _ => return Self::default(),
        };
        let rate = |bytes: usize| (bytes as f64 * 8.0) / span / 1000.0;
        let day = |bytes: usize| (bytes as f64) * (86_400.0 / span) / 1e9;
        let (d, u) = (down_bytes(events), up_bytes(events));
        // The worst DOWNSTREAM gap, which is the tunnel's worst-case latency: a
        // record only leaves on a schedule token, so a capture with a 45-second
        // reading pause stalls the tunnel for 45 seconds no matter how much
        // bandwidth the envelope has. Measured on a live cluster at 66 SECONDS,
        // which no amount of throughput makes usable.
        // Both directions, because they gate different things: downstream is the
        // data plane's latency, upstream gates the other half of every handshake
        // round trip. Measuring only downstream (which this did) accepts a
        // capture whose upstream is silent for a minute.
        let t0 = events.first().map_or(0.0, |&(t, _, _)| t);
        let leg = |want_down: bool| {
            let mut worst = 0.0f64;
            let mut first: Option<f64> = None;
            let mut prev: Option<f64> = None;
            for &(t, _, _) in events
                .iter()
                .filter(|&&(_, _, d)| if want_down { d > 0 } else { d < 0 })
            {
                first.get_or_insert(t);
                if let Some(p) = prev {
                    worst = worst.max(t - p);
                }
                prev = Some(t);
            }
            // A direction with NO records at all opens "at" the capture's end:
            // it never produces a token, which is the worst case, not the best.
            (worst, first.map_or(span, |f| f - t0))
        };
        let (worst_down, open_down) = leg(true);
        let (worst_up, open_up) = leg(false);
        Self {
            span_secs: span,
            down_kbps: rate(d),
            up_kbps: rate(u),
            down_gb_day: day(d),
            up_gb_day: day(u),
            max_gap_secs: worst_down,
            up_gap_secs: worst_up,
            open_down_secs: open_down,
            open_up_secs: open_up,
        }
    }
}

impl std::fmt::Display for Cost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            // Both directions and the opening, because those are the three ways
            // a capture can be affordable and still unusable, and an operator
            // reading a log should be able to tell WHICH one bit.
            "{:.1}s, down {:.0} kbit/s ({:.2} GB/day), up {:.0} kbit/s ({:.2} GB/day) \
             if replayed continuously, worst stall {:.1}s down / {:.1}s up, \
             opens after {:.1}s down / {:.1}s up",
            self.span_secs,
            self.down_kbps,
            self.down_gb_day,
            self.up_kbps,
            self.up_gb_day,
            self.max_gap_secs,
            self.up_gap_secs,
            self.open_down_secs,
            self.open_up_secs
        )
    }
}

/// Wall-clock span of a capture, in seconds. Zero for a capture too short or
/// malformed to have one.
#[must_use]
pub fn span_secs(events: &[Event]) -> f64 {
    match (events.first(), events.last()) {
        (Some((a, _, _)), Some((b, _, _))) if b > a => b - a,
        _ => 0.0,
    }
}

/// Upstream PAYLOAD bytes per second: what a tunnel can actually push upstream
/// through this envelope, after every token pays its framing.
///
/// This is the number that decides download speed, because the tunnel's flow
/// control travels upstream. Counting raw record bytes instead would flatter a
/// capture made of tokens too small to carry anything.
#[must_use]
pub fn upstream_payload_bps(events: &[Event]) -> f64 {
    let span = span_secs(events);
    if span <= 0.0 {
        return 0.0;
    }
    let bytes: u64 = events
        .iter()
        .filter(|(_, _, d)| *d < 0)
        .map(|(_, s, _)| u64::from(s.saturating_sub(TOKEN_FRAMING_OVERHEAD)))
        .sum();
    bytes as f64 / span
}

/// Upstream records per second across the capture's span.
///
/// The quantity that decides whether a tunnel's own handshake can complete
/// inside this envelope: handshake bytes leave only on an upstream token, so a
/// capture below roughly one token per second cannot finish one at all.
#[must_use]
pub fn upstream_tokens_per_sec(events: &[Event]) -> f64 {
    let span = match (events.first(), events.last()) {
        (Some((a, _, _)), Some((b, _, _))) if b > a => b - a,
        _ => return 0.0,
    };
    let up = events.iter().filter(|(_, _, d)| *d < 0).count();
    up as f64 / span
}

/// Total upstream bytes. The figure of merit for an upload capture, whose whole
/// purpose is the direction a download-shaped trace cannot supply.
fn up_bytes(events: &[Event]) -> usize {
    events
        .iter()
        .filter(|(_, _, d)| *d < 0)
        .map(|(_, s, _)| *s as usize)
        .sum()
}

// --- recording job ----------------------------------------------------------

/// Cover class: a streaming-video envelope or a web-browsing envelope.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mode {
    /// Streaming video: steady large TLS records, from a segmented HLS stream.
    Video,
    /// Web browsing: bursty, varied object sizes - a page and its subresources.
    Browse,
    /// Record an UPSTREAM envelope by uploading to an operator-supplied endpoint.
    /// The only mode that produces records large enough to size-shape a QUIC
    /// carrier's upstream; see [`record_upload`].
    Upload,
}

/// One recording job. Built by the CLI from flags, or by a daemon's auto-sourcer
/// from defaults - the recorder itself does not care which.
pub struct Args {
    /// Longest downstream silence to accept, in seconds - a LATENCY ceiling.
    ///
    /// Separate from [`Self::max_gb_day`] because the two failures are
    /// different: an over-budget capture costs money, a stalling one costs
    /// usability, and a capture can easily be cheap AND unusable. A dwelled
    /// browse trace is ~90% silent, and those silences become the tunnel's
    /// stalls verbatim - measured at 66 seconds on a live cluster.
    ///
    /// Default [`DEFAULT_MAX_GAP_SECS`].
    pub max_gap_secs: f64,
    /// Library root; traces land in `<lib>/<name>/<i>.csv`.
    pub lib: PathBuf,
    /// Library subdirectory, conventionally the class name.
    pub name: String,
    /// Which envelope to record.
    pub mode: Mode,
    /// How many traces to record per batch.
    pub count: usize,
    /// Video: a specific HLS master playlist instead of a random one.
    pub hls: Option<String>,
    /// Browse: a specific page. Upload: the endpoint to POST to (required).
    pub url: Option<String>,
    /// Video: a specific PeerTube instance instead of a random one.
    pub instance: Option<String>,
    /// Video: run this command and record whatever HLS URL it prints.
    ///
    /// The supported way to use an external extractor without Mirage depending
    /// on one. `yt-dlp -g <url>` covers the platforms that actively fight
    /// extraction - YouTube above all - which no in-tree adapter can keep up
    /// with, and it stays entirely the operator's choice: nothing is installed,
    /// invoked or required unless this is set, so the shipped binary remains
    /// self-contained.
    ///
    /// The command's traffic is NOT part of the capture. Discovery runs before
    /// recording starts and on a separate event log, so an extractor's own
    /// scraper-shaped requests never enter the library - though they do go out
    /// on the wire, un-tunnelled, like every other discovery fetch.
    pub hls_cmd: Option<String>,
    /// Self-driving: minutes to wait between batches, or `None` to record once.
    pub loop_mins: Option<usize>,
    /// Keep only the K newest traces after each batch.
    pub max: Option<usize>,
    /// Whether to record at true playback rate, and at which quality.
    pub rt: RealTime,
    /// Upload: bytes per POST.
    pub up_bytes: usize,
    /// Upload: how many POSTs.
    pub up_chunks: usize,
    /// Narrate progress on stdout/stderr. True for the CLI, where that IS the
    /// output; false inside a daemon, where console prints bypass the log system
    /// and land wherever stdout happens to go.
    pub verbose: bool,
    /// Where to record cover FROM. Defaults to the global pack, which is right
    /// for an uncensored host and wrong for a censored one - see
    /// [`packs::SourcePack`].
    pub pack: packs::SourcePack,
    /// Reject captures costing more than this many GB/day to replay
    /// continuously. `None` accepts whatever the network hands back.
    ///
    /// This is how Proteus's cost tiers work, and it is worth being precise
    /// about why it does not weaken the disguise: every trace in the library is
    /// still a REAL capture of REAL traffic, replayed verbatim. A ceiling only
    /// decides WHICH real flow gets worn - it never synthesises a cheaper one,
    /// which is the thing that would put a fingerprint on the wire. Page weight
    /// varies enormously (measured 1.87 to 8.21 GB/day across three consecutive
    /// Wikipedia sessions), so choosing among them is most of the available
    /// saving.
    ///
    /// The honest caveat: a censor who knew you only ever wear sub-2 GB/day
    /// flows learns something from that. It is weak - plenty of real users are
    /// on metered links and never stream - and it buys a tunnel that people on
    /// expensive data can actually afford to leave on.
    pub max_gb_day: Option<f64>,
}

/// The default cover ceiling, in GB/day of continuous replay.
///
/// The cheapest cover that still carries a tunnel, and the right choice on a
/// metered or mobile link - which is most of the people this exists for. An
/// operator who wants more says so as a NUMBER; see [`Args::max_gb_day`].
pub const DEFAULT_MAX_GB_DAY: f64 = 2.5;

/// The ceiling a legacy `lean`/`balanced` config name asked for, in GB/day.
///
/// Tiers are gone as a concept. They were never a concealment choice - a 15-cell
/// censor-vantage matrix measured lean, balanced and the former `aggressive`
/// tier ALL at the harness's noise floor, with the mean if anything drifting the
/// wrong way as cover was added (lean 0.546, balanced 0.553). What a tier
/// actually set was a bandwidth ceiling, and a name that reads as "more
/// protection" while meaning "more spending" is the kind of thing an operator
/// picks for the wrong reason. So the quantity is named directly and this
/// function exists only so an existing config keeps working.
///
/// `None` for anything unrecognised, which callers resolve to the default rather
/// than silently uncapping.
#[must_use]
pub fn legacy_tier_budget(name: &str) -> Option<f64> {
    match name.trim().to_ascii_lowercase().as_str() {
        "lean" | "cheap" | "metered" => Some(DEFAULT_MAX_GB_DAY),
        // `aggressive` was an UNCAPPED tier that preferred video cover. It is
        // gone: it measured no less detectable than lean, and it was the only
        // tier to produce a tunnel that would not come up at all (a video
        // capture opens with a quiet stretch a handshake cannot crawl past).
        // Mapped to the strongest ceiling that remains rather than honoured.
        "balanced" | "aggressive" | "max" => Some(6.0),
        _ => None,
    }
}

/// A daily cover budget: a number of GB/day, or explicitly unlimited.
///
/// Unlimited is a legitimate choice and is spelled as a WORD rather than hidden
/// behind a tier name. The removed `aggressive` tier was uncapped, and the
/// problem with it was never that uncapped is wrong - it was that the name
/// promised concealment it did not deliver, so an operator picked it for the
/// wrong reason. Naming the quantity makes the trade explicit: more budget is
/// more throughput and more bandwidth, and measurably not more hiding.
///
/// In JSON this is either a number or the string "unlimited":
///
/// ```json
/// { "proteus_max_gb_day": 5.0 }
/// { "proteus_max_gb_day": "unlimited" }
/// ```
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
#[serde(untagged)]
pub enum CoverBudget {
    /// A ceiling in GB/day of continuous replay.
    GbPerDay(f64),
    /// The word "unlimited" (anything else fails to resolve and falls back to
    /// the tier default, rather than silently uncapping).
    Named(String),
}

/// GB/day of continuous replay for a sustained rate in Mbit/s.
///
/// The natural unit for an operator is "how fast is each session", and the
/// natural unit for a cover BILL is GB/day. They are the same quantity because
/// cover runs around the clock: the envelope's rate IS the session's throughput
/// ceiling, 1:1, so a limit set in Mbit/s is exactly a bill in GB/day.
///
/// 1 Mbit/s is 10.8 GB/day. 10 Mbit/s is 108.
#[must_use]
pub fn gb_day_from_mbit(mbit: f64) -> f64 {
    mbit * 1_000_000.0 / 8.0 * 86_400.0 / 1e9
}

/// The inverse of [`gb_day_from_mbit`].
#[must_use]
pub fn mbit_from_gb_day(gb: f64) -> f64 {
    gb * 1e9 * 8.0 / 86_400.0 / 1_000_000.0
}

impl CoverBudget {
    /// The ceiling in GB/day, or `None` for no ceiling.
    ///
    /// Returns `None` ONLY for an explicit "unlimited"; an unrecognised string
    /// resolves to `fallback` so a typo cannot silently remove the cap.
    #[must_use]
    pub fn gb_per_day(&self, fallback: Option<f64>) -> Option<f64> {
        match self {
            Self::GbPerDay(v) if *v > 0.0 => Some(*v),
            // A zero or negative ceiling would record nothing at all; treat it
            // as the operator meaning "no limit" rather than "no cover".
            Self::GbPerDay(_) => None,
            Self::Named(s) => {
                let s = s.trim().to_ascii_lowercase();
                if matches!(s.as_str(), "unlimited" | "none" | "off" | "uncapped") {
                    None
                } else {
                    fallback
                }
            }
        }
    }

    /// What this costs sustained, for showing an operator the real trade.
    #[must_use]
    pub fn describe(&self, fallback: Option<f64>) -> String {
        match self.gb_per_day(fallback) {
            None => "unlimited (throughput bounded only by the captures)".to_string(),
            Some(gb) => format!(
                "{gb} GB/day, about {:.2} Mbit/s sustained",
                mbit_from_gb_day(gb)
            ),
        }
    }
}

impl Args {
    /// A job with everything defaulted but the library root and the class. What
    /// the auto-sourcer uses: Proteus is a switch, so the code behind the switch
    /// must be able to ask for cover without filling in a form.
    #[must_use]
    pub fn auto(lib: PathBuf, mode: Mode) -> Self {
        Self {
            max_gap_secs: DEFAULT_MAX_GAP_SECS,
            lib,
            name: match mode {
                Mode::Video => "video".into(),
                Mode::Browse => "browse".into(),
                Mode::Upload => "upload".into(),
            },
            mode,
            count: 1,
            hls: None,
            url: None,
            instance: None,
            // Unattended sourcing never shells out. An extractor is an explicit
            // operator choice, and the daemon must not acquire one by default.
            hls_cmd: None,
            loop_mins: None,
            max: None,
            // Always-on cover is a 24/7 bandwidth bill, so the unattended path
            // takes the low-bitrate rendition at its true playback rate. An
            // operator who wants a fatter envelope can say so; nobody should
            // discover a 40 GB/day default on an invoice.
            rt: RealTime {
                real_time: true,
                low_bitrate: true,
                max_gap: Duration::from_secs_f64(DEFAULT_MAX_GAP_SECS),
            },
            up_bytes: UPLOAD_BODY_BYTES,
            up_chunks: UPLOAD_CHUNKS,
            verbose: false,
            pack: packs::SourcePack::default(),
            max_gb_day: Some(DEFAULT_MAX_GB_DAY),
        }
    }

    /// [`Args::auto`] driven by the resolved BUDGET and cover-source pack.
    ///
    /// The budget decides the video bitrate, because the two are the same
    /// question. Taking the lowest HLS variant caps the envelope at a few
    /// hundred kbit/s, which caps the tunnel at a few hundred kbit/s - so an
    /// operator who asked for a large budget, or for none at all, and then got
    /// the cheapest possible stream would have paid for headroom the recorder
    /// refused to record.
    #[must_use]
    pub fn auto_budget(
        lib: PathBuf,
        mode: Mode,
        max_gb_day: Option<f64>,
        pack: packs::SourcePack,
    ) -> Self {
        Self {
            pack,
            max_gb_day,
            rt: RealTime {
                real_time: true,
                // Cheapest stream only when the budget is genuinely tight. No
                // ceiling means take the best available: that is what "I do not
                // care about bandwidth" has to buy, or the setting is cosmetic.
                low_bitrate: wants_low_bitrate(max_gb_day),
                max_gap: Duration::from_secs_f64(DEFAULT_MAX_GAP_SECS),
            },
            ..Self::auto(lib, mode)
        }
    }
}

/// Longest downstream silence a cover trace may contain, in seconds.
///
/// A schedule token is the only thing that puts bytes on the wire, so a capture's
/// quiet stretches are the tunnel's stalls, one for one. Two seconds is already
/// poor for interactive use and is set here as the outer bound of tolerable
/// rather than as a target; the reading pauses in an unfiltered browse capture
/// run to tens of seconds.
pub const DEFAULT_MAX_GAP_SECS: f64 = 2.0;

/// Above this, a budget is generous enough that video is worth recording.
///
/// Video is where the throughput is - a page load is a few hundred KB over a few
/// seconds however hard you try, so a browse-only library caps the tunnel around
/// 1 Mbit/s no matter what the ceiling says. Below this a video capture would
/// blow the budget on its own and get rejected repeatedly, which is worse than
/// not attempting it.
const VIDEO_WORTH_IT_GB_DAY: f64 = 6.0;

/// Above this, take the BEST video variant rather than the cheapest.
const HIGH_BITRATE_GB_DAY: f64 = 20.0;

/// Should the recorder ask for the lowest-bitrate stream?
#[must_use]
pub fn wants_low_bitrate(max_gb_day: Option<f64>) -> bool {
    max_gb_day.is_some_and(|gb| gb < HIGH_BITRATE_GB_DAY)
}

/// Which classes to record for a resolved budget.
///
/// The budget, not any tier name, is what decides whether a fat downstream
/// capture is affordable - so it is the only input.
#[must_use]
pub fn classes_for_budget(max_gb_day: Option<f64>) -> &'static [(Mode, &'static str)] {
    // Every budget records an `upstream` class: reading gaps destroy upstream
    // capacity and a tunnel's flow control rides upstream, so without it every
    // download throttles regardless of how fat the downstream is.
    if max_gb_day.is_none_or(|gb| gb >= VIDEO_WORTH_IT_GB_DAY) {
        &[
            (Mode::Browse, "browse"),
            (Mode::Browse, UPSTREAM_CLASS),
            (Mode::Video, "video"),
        ]
    } else {
        &[(Mode::Browse, "browse"), (Mode::Browse, UPSTREAM_CLASS)]
    }
}

// --- auto-sourcing ----------------------------------------------------------

/// How many traces the auto-sourcer keeps per class. A session chains a random
/// shuffle of several, so one trace would make every session identical and a
/// hundred would spend a day recording before the first one is usable.
pub const AUTO_LIBRARY_TARGET: usize = 12;

/// How long between unattended refreshes once the library is full. Cover that
/// never changes becomes a signature of its own; cover re-recorded every few
/// minutes is a bandwidth cost with no benefit.
pub const AUTO_REFRESH: Duration = Duration::from_secs(45 * 60);

/// Where a daemon keeps its self-recorded cover when the operator has not chosen
/// a location.
///
/// `$MIRAGE_STATE_DIR/cover`, else `$XDG_STATE_HOME/mirage/cover`, else
/// `$HOME/.local/state/mirage/cover`, else a temp dir. Never fails: Proteus not
/// starting is a worse outcome than cover living somewhere unglamorous.
#[must_use]
pub fn default_library_dir() -> PathBuf {
    if let Some(d) = std::env::var_os("MIRAGE_STATE_DIR") {
        return PathBuf::from(d).join("cover");
    }
    if let Some(d) = std::env::var_os("XDG_STATE_HOME") {
        return PathBuf::from(d).join("mirage/cover");
    }
    if let Some(h) = std::env::var_os("HOME") {
        return PathBuf::from(h).join(".local/state/mirage/cover");
    }
    std::env::temp_dir().join("mirage-cover")
}

/// Class directory holding captures recorded for the UPSTREAM direction.
///
/// A separate class because the two directions want opposite things and cannot
/// both be served by one capture. Downstream wants the realistic, mostly-idle
/// browsing envelope - that is what a censor sees most of, and its reading gaps
/// are what make it look like a person. Upstream has to carry the tunnel's flow
/// control, and those same gaps throttle it: measured, adding realistic dwell
/// cut upstream payload from 3.93 to 0.91 KiB/s and turned a 2-second download
/// into one that took up to 389 seconds.
///
/// So this class is recorded WITHOUT dwell - a real page load's upstream burst,
/// which is still a real capture, just of the active part of a session rather
/// than the whole of one. `merge_directional` pairs it with the dwelled
/// downstream.
pub const UPSTREAM_CLASS: &str = "upstream";

/// The class directory whose UPSTREAM a tunnel should wear.
///
/// A video capture is the better downstream disguise, but it is a client that
/// barely speaks - measured at 0.26 upstream tokens/s against a browse
/// capture's ~14 - and a multi-round-trip handshake simply cannot complete over
/// it. Pointing the upstream at the browse class keeps the video downstream
/// while borrowing upload capacity from a capture that has some, which is what
/// `proteus_profile_up` exists for. Self-sourcing gets that pairing by default
/// rather than leaving it as a knob nobody finds.
#[must_use]
pub fn upstream_class_dir(lib: &Path) -> String {
    lib.join(UPSTREAM_CLASS).to_string_lossy().into_owned()
}

/// Count traces under a library path, recursing one level.
///
/// Reporting helper: a daemon's `--check-config` needs a real number whether the
/// operator pointed at a class dir (`<lib>/browse`) or at a library root holding
/// class dirs, and answering "0" for the root would read as "Proteus has nothing
/// to wear" when it has plenty.
#[must_use]
pub fn count_traces(dir: &Path) -> usize {
    let Ok(rd) = fs::read_dir(dir) else {
        return 0;
    };
    let mut n = 0;
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            n += library_size(&p);
        } else if p.extension().is_some_and(|x| x == "csv") {
            n += 1;
        }
    }
    n
}

/// How many usable traces `<lib>/<class>` already holds.
fn library_size(dir: &Path) -> usize {
    fs::read_dir(dir)
        .map(|rd| {
            rd.flatten()
                .filter(|e| {
                    e.path().extension().is_some_and(|x| x == "csv")
                        && e.metadata().map(|m| m.len() > 64).unwrap_or(false)
                })
                .count()
        })
        .unwrap_or(0)
}

/// Keep `<lib>/video` and `<lib>/browse` stocked with real traces, forever.
///
/// This is what makes Proteus a switch rather than a project. Turning it on with
/// no profile configured starts this task; it records until each class has
/// [`AUTO_LIBRARY_TARGET`] traces, then tops them up every [`AUTO_REFRESH`],
/// pruning the oldest so the library neither goes stale nor grows without bound.
/// The operator installs no timer, runs no recorder and ships no CSVs.
///
/// Both classes are recorded because they are not interchangeable: a video
/// capture is the better downstream disguise but its upstream is far too sparse
/// to carry a tunnel's own handshake, so the pacer pairs a video downstream with
/// a browse upstream. Sourcing only one would leave that pairing impossible.
///
/// Failures are logged and retried at the next tick rather than propagated:
/// a recording run needs the network, and the network is exactly what is
/// unreliable for the people this is for. A tunnel with stale cover still works;
/// a tunnel that refused to start because a video host was down does not. But
/// silence is not acceptable either - if the library never fills, Proteus is off
/// and the operator has to be told, because "it looked like it was on" is the
/// failure this whole design exists to prevent.
pub async fn keep_fresh(lib: PathBuf) {
    keep_fresh_sourcing(lib, packs::SourcePack::default(), Some(DEFAULT_MAX_GB_DAY)).await;
}

/// [`keep_fresh`] with an explicit source pack and daily ceiling.
///
/// `max_gb_day` of `None` means UNLIMITED: the recorder keeps whatever it
/// captures, however heavy. The budget is the only knob, because the budget is
/// the only thing that was ever being chosen - it decides both what a capture
/// costs to replay and, through [`classes_for_budget`], whether a fat video
/// capture is affordable at all.
pub async fn keep_fresh_sourcing(lib: PathBuf, pack: packs::SourcePack, max_gb_day: Option<f64>) {
    keep_fresh_inner(lib, pack, max_gb_day, None).await;
}

/// [`keep_fresh_sourcing`] that stops when `stop` is set.
///
/// A client stops recording once it has pulled the bridge's library: continuing
/// would keep making un-tunnelled requests it no longer needs, to sites that may
/// be blocked where it is running. Checked BETWEEN captures rather than by
/// aborting the task, so a trace is never left half-written on disk for the
/// pacer to pick up.
pub async fn keep_fresh_budget(
    lib: PathBuf,
    pack: packs::SourcePack,
    max_gb_day: Option<f64>,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
) {
    keep_fresh_inner(lib, pack, max_gb_day, Some(stop)).await;
}

async fn keep_fresh_inner(
    lib: PathBuf,
    pack: packs::SourcePack,
    max_gb_day: Option<f64>,
    stop: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
) {
    // Browse first, deliberately. A realtime video capture takes minutes by
    // construction (it waits the stream's true segment gaps), while a browse
    // capture is seconds - so recording browse first means Proteus has something
    // to wear almost immediately instead of pacing nothing for the first six
    // minutes of every cold start.
    // Classes follow the BUDGET, not the tier name: video is where the
    // throughput is, and whether it is affordable is a budget question.
    let classes = classes_for_budget(max_gb_day);
    // Say up front when the chosen pack cannot supply one of the classes this
    // budget wants. A pack with no verified domestic video falls back to the
    // global PeerTube set, which on a censored network is very likely
    // unreachable. Without this the operator sees a video class that simply
    // never fills and has no way to know the reason is structural rather than
    // transient.
    if !pack.video_is_regional() && classes.iter().any(|(m, _)| *m == Mode::Video) {
        tracing::warn!(
            pack = pack.name(),
            "proteus: this pack has no verified domestic VIDEO sources, so video capture falls \
             back to the global PeerTube set - which may be unreachable from here. Browse cover \
             is unaffected. Supply an --hls URL for a stream you know is reachable, name your \
             own sources with --sources, or stay under the video budget threshold, which is \
             browse-only."
        );
    }
    let mut was_usable = false;
    let mut barren_rounds = 0usize;
    loop {
        // Checked here, between captures, so a stop can never leave a trace
        // half-written for the pacer to read.
        if stop
            .as_ref()
            .is_some_and(|s| s.load(std::sync::atomic::Ordering::Relaxed))
        {
            tracing::info!("proteus: cover sourcing stopped (library now comes from the bridge)");
            return;
        }
        let mut recorded = 0usize;
        for &(mode, class) in classes {
            let mut args = Args::auto_budget(lib.clone(), mode, max_gb_day, pack.clone());
            args.name = class.to_string();
            // The upstream class is a browse capture recorded WITHOUT dwell, into
            // its own directory. Realistic reading gaps are right for the
            // downstream disguise and ruinous for upstream capacity, and one
            // capture cannot be both.
            if mode == Mode::Browse && args.name == UPSTREAM_CLASS {
                args.rt.real_time = false;
            }
            let dir = lib.join(&args.name);
            if fs::create_dir_all(&dir).is_err() {
                tracing::warn!(dir = %dir.display(), "proteus: cannot create cover library dir");
                continue;
            }
            // Record at most a few per tick. Recording is real traffic to a real
            // host; doing twelve back to back on startup is both slow and a burst
            // that looks nothing like the steady trickle it is meant to model.
            let have = library_size(&dir);
            let want = AUTO_LIBRARY_TARGET.saturating_sub(have).min(2);
            for _ in 0..want {
                match record_one(&args, &dir).await {
                    Ok(cost) => {
                        recorded += 1;
                        // The bill, in the log, where a daemon operator will
                        // actually see it. Continuous cover costs what the cover
                        // costs, and finding that out from a bandwidth graph is
                        // too late.
                        tracing::info!(
                            class = ?mode,
                            envelope = %cost,
                            "proteus: recorded cover"
                        );
                        // Announce usability HERE, not at the end of the round: a
                        // round also records video, which by design takes minutes,
                        // so an end-of-round announcement would claim Proteus was
                        // inactive for six minutes after it had started working.
                        if !was_usable {
                            was_usable = true;
                            tracing::info!(
                                "proteus: cover library is now usable - sessions will wear \
                                 a recorded envelope"
                            );
                        }
                    }
                    Err(e) => {
                        // Info, not debug: a daemon at the default log level must
                        // be able to see WHY its cover library is not filling.
                        tracing::info!(class = ?mode, error = %e, "proteus: cover recording failed");
                        break;
                    }
                }
            }
            prune(&dir, AUTO_LIBRARY_TARGET);
        }
        let (video, browse) = (
            library_size(&lib.join("video")),
            library_size(&lib.join("browse")),
        );
        if recorded > 0 {
            tracing::info!(
                lib = %lib.display(),
                recorded,
                video,
                browse,
                "proteus: cover library updated"
            );
        }

        // A library that already had traces when we started (a restart) is usable
        // without us having recorded anything this round.
        let usable = video + browse > 0;
        was_usable |= usable;

        // Say plainly when it never gets there. Logging failures at debug
        // meant a daemon at the default level showed nothing at all: Proteus
        // silently inactive, which is exactly the outcome the switch exists to
        // rule out. Warn once the failures have persisted long enough to be a
        // real problem rather than one flaky fetch.
        if usable {
            barren_rounds = 0;
        } else {
            barren_rounds += 1;
            if barren_rounds % 10 == 0 {
                tracing::warn!(
                    lib = %lib.display(),
                    rounds = barren_rounds,
                    "proteus: enabled but no cover recorded yet, so sessions are running \
                     UNPACED. The recorder needs outbound HTTPS to reach public video and \
                     wiki hosts; if this host cannot make those requests, record a library \
                     elsewhere and set proteus_profile."
                );
            }
        }

        // Fill fast while the library is thin, then settle into the slow refresh.
        let thin = video < AUTO_LIBRARY_TARGET || browse < AUTO_LIBRARY_TARGET;
        tokio::time::sleep(if thin {
            Duration::from_secs(20)
        } else {
            AUTO_REFRESH
        })
        .await;
    }
}

/// Resolve a source: the pack's video sources for video, `--url`/random page for browse.
async fn resolve_source(args: &Args, start: Instant) -> io::Result<Stream> {
    let parse = |u: &str| {
        Url::parse(u)
            .map(Stream::Hls)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))
    };
    match args.mode {
        // Upload posts real bytes to a real server, so there is deliberately no
        // default target: the operator names infrastructure they control.
        Mode::Upload => match &args.url {
            Some(u) => parse(u),
            None => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "--mode upload requires --url <endpoint that accepts POST>; it uploads real \
                 bytes, so it will not pick a stranger's server for you",
            )),
        },
        Mode::Browse => {
            if let Some(u) = &args.url {
                return parse(u);
            }
            let urls = args.pack.browse_urls();
            if urls.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "cover source pack has no browse sources",
                ));
            }
            parse(&urls[(rand_u64() as usize) % urls.len()])
        }
        Mode::Video => {
            if let Some(u) = &args.hls {
                return parse(u);
            }
            // An operator-supplied command is the escape hatch for platforms
            // that fight extraction: `--hls-cmd 'yt-dlp -g <url>'` gets yt-dlp's
            // whole catalogue without Mirage depending on yt-dlp. Nothing is
            // installed or required by default, and the shipped binary stays
            // self-contained.
            if let Some(cmd) = &args.hls_cmd {
                return hls_from_command(cmd).map(Stream::Hls);
            }
            let out = Arc::new(Mutex::new(Vec::new()));
            let mut f = Fetcher::new(start, out)?;
            // `--peertube HOST` pins one instance and skips the pack entirely;
            // it is how an operator names a source they have verified.
            let groups: Vec<Vec<packs::VideoSource>> = match &args.instance {
                Some(i) => vec![vec![packs::VideoSource::PeerTube(i.clone())]],
                None => args.pack.video_sources(),
            };
            // Groups in order, shuffled WITHIN each group. Shuffling across a
            // group boundary would let the global fallback beat the operator's
            // own list on a coin flip - which is the bug this ordering exists to
            // prevent, not a detail.
            for group in &groups {
                for i in shuffled(group.len()) {
                    let src = &group[i];
                    match video_source_stream(&mut f, src, args.rt.low_bitrate).await {
                        Ok(s) => return Ok(s),
                        Err(e) => eprintln!("  {}: {e}", video_source_label(src)),
                    }
                }
            }
            Err(io::Error::new(io::ErrorKind::Other, "no source resolved"))
        }
    }
}

/// Record one trace (with a few attempts to clear the volume floor).
///
/// # Errors
/// Returns the last failure if every attempt failed, or a usage error (which is
/// not retried) when the job itself is malformed.
pub async fn record_one(args: &Args, dir: &Path) -> io::Result<Cost> {
    for attempt in 1..=3 {
        let src = match resolve_source(args, Instant::now()).await {
            Ok(u) => u,
            Err(e) if e.kind() == io::ErrorKind::InvalidInput => {
                // A missing or malformed argument will not fix itself on attempt
                // two. Say it once and stop, rather than repeating a usage error
                // three times as though the network were flaky.
                return Err(e);
            }
            Err(e) => {
                eprintln!("  resolve failed: {e}");
                continue;
            }
        };
        // One source of truth for the latency ceiling. `Args::max_gap_secs` is
        // what the acceptance check below enforces, so it is also what the
        // recorder must aim at; letting `rt.max_gap` carry a stale default
        // would reinstate exactly the recorder/checker disagreement this
        // ceiling exists to remove.
        let mut rt = args.rt;
        rt.max_gap = Duration::from_secs_f64(args.max_gap_secs);
        // Video dispatches on the CONTAINER the source turned out to serve, not
        // on the mode: a DASH or progressive source is still a video capture and
        // still lands in the video class, it is just driven by byte ranges
        // instead of a segment playlist.
        let recorded = match (args.mode, &src) {
            (Mode::Video, Stream::Hls(u)) => record_stream(u, rt).await,
            (
                Mode::Video,
                Stream::Ranged {
                    url,
                    bitrate_bps,
                    referer,
                },
            ) => record_ranged(url, *bitrate_bps, referer.as_deref(), rt).await,
            (Mode::Browse, s) => record_browse(s.as_url(), rt).await,
            (Mode::Upload, s) => record_upload(s.as_url(), args.up_bytes, args.up_chunks).await,
        };
        match recorded {
            Ok(events) => {
                // Judge a trace by the direction it exists to supply. An upload
                // capture is upstream-heavy by construction, so a downstream-byte
                // minimum would reject exactly the traces that are working.
                let (measured, label) = match args.mode {
                    Mode::Upload => (up_bytes(&events), "up"),
                    _ => (down_bytes(&events), "down"),
                };
                if measured < MIN_TRACE_BYTES {
                    eprintln!(
                        "  attempt {attempt}: only {measured} {label} bytes \
                         (< {MIN_TRACE_BYTES}); retrying"
                    );
                    continue;
                }
                // A cover envelope is not just a shape, it is a BUDGET, and the
                // tunnel has to fit inside it in both directions. A capture whose
                // upstream is too sparse cannot carry a multi-round-trip
                // handshake at all - the carrier comes up, the handshake starves,
                // and the failure presents as an unreachable bridge rather than as
                // a cover-selection mistake. Catch that HERE, where it is one
                // rejected trace, instead of at handshake time on a user's
                // machine.
                //
                // The check applies to the class that SUPPLIES upstream, which is
                // browse. Video and upload are exempt for opposite reasons: an
                // upload capture is upstream-heavy by construction, and a video
                // capture is a client that barely speaks - measured at 0.26
                // upstream tokens/s - which is exactly why it is paired with a
                // browse upstream via `proteus_profile_up` rather than used for
                // both directions. Applying the floor to video rejected every
                // video capture there is, silently collapsing the balanced and
                // aggressive tiers into browse-only.
                // A realtime browse capture is supposed to be a SESSION spanning
                // roughly SESSION_TARGET_SPAN. If it came back at a fraction of
                // that, the source ran out of links and it is really one page
                // load - which shortens the replay loop's period, and a short
                // loop is a fingerprint. Reject rather than let the library
                // refill with it. Measured: a link-sparse source produced a
                // 1.2 s capture that passed every other check.
                //
                // The floor is a fraction of the SPAN TARGET, not a dwell
                // length: dwell is now bounded by the tunnel's latency budget
                // and is far shorter than any session, so keying off it would
                // wave the 1.2 s case straight through.
                if matches!(args.mode, Mode::Browse)
                    && args.rt.real_time
                    && span_secs(&events) < SESSION_TARGET_SPAN.as_secs_f64() / 2.0
                {
                    eprintln!(
                        "  attempt {attempt}: browse session collapsed to {:.1}s (a single page \
                         load, not a session); retrying",
                        span_secs(&events)
                    );
                    continue;
                }
                // Every acceptance check below reads from this, so compute it
                // once and up front. It is a pure function of the events and
                // costs nothing; leaving it below the upstream floors only meant
                // those floors could not see the gap and opening figures.
                let cost = Cost::of(&events);
                // FAIL-OPEN GUARD. `Cost::of` returns all zeros when a capture
                // has no usable span (empty, single-record, or non-monotonic
                // times), and every ceiling below is an upper bound - so a
                // degenerate capture passes the cost check, the latency check
                // and both opening checks vacuously, then gets written to the
                // library as valid cover. Reject it explicitly rather than let
                // zero read as "costs nothing, stalls never".
                if cost.span_secs <= 0.0 {
                    if args.verbose {
                        eprintln!(
                            "  attempt {attempt}: capture has no usable span ({} records); \
                             every ceiling would pass it vacuously, retrying",
                            events.len()
                        );
                    }
                    continue;
                }
                let up_rate = upstream_tokens_per_sec(&events);
                let up_bps = upstream_payload_bps(&events);
                // Only the capture that will SUPPLY upstream has to clear the
                // upstream floors, and that is the dense one. A dwelled browse
                // capture is a downstream artifact by construction - its reading
                // gaps are the whole point and they put its upstream payload at
                // 0.91 KiB/s, well under the floor. Checking it here rejected
                // every dwelled capture and left the library with an upstream
                // class and no downstream one, which is the same mistake as
                // applying the floor to video: judging a class by a direction it
                // was never meant to serve.
                let supplies_upstream = args.name == UPSTREAM_CLASS
                    || (matches!(args.mode, Mode::Browse) && !args.rt.real_time);
                // OPENING silence, checked separately from the worst gap because
                // a capture can have a fine worst-gap and still open slowly, and
                // the opening is what decides whether the tunnel comes up AT ALL.
                // This is the measured reason video cover was unusable: a video
                // flow fetches its manifest and then goes quiet before the first
                // segment, so a faithfully replayed handshake crawls past its
                // deadline with no error anywhere. The cost tier got the blame
                // ("aggressive was the only tier that produced a tunnel which
                // would not come up") when the real fault was cover SELECTION -
                // which is fixable, and worth fixing, because video is the only
                // cover class fast enough to carry a tunnel at real line speed.
                //
                // Judged against the same latency budget as any other stall: the
                // first byte is just the first thing the user waits for.
                let open = if supplies_upstream {
                    cost.open_up_secs
                } else {
                    cost.open_down_secs
                };
                if open > args.max_gap_secs {
                    if attempt < 3 {
                        if args.verbose {
                            eprintln!(
                                "  attempt {attempt}: capture opens with {open:.1}s of silence \
                                 (> {:.1}s); a handshake would stall inside it, retrying",
                                args.max_gap_secs
                            );
                        }
                        continue;
                    }
                    tracing::warn!(
                        open_secs = open,
                        ceiling_secs = args.max_gap_secs,
                        "proteus: kept a capture that opens slowly; the tunnel may be slow to \
                         come up on this profile"
                    );
                }
                // A quiet UPSTREAM stalls the handshake as hard as a quiet
                // downstream, and only the downstream was ever checked. Judge it
                // on the class that actually supplies upstream: a browse
                // downstream capture is meant to be paired with a dense upstream
                // one, so failing it for its own sparse request traffic would
                // reject every downstream capture there is - the same mistake as
                // applying the upstream payload floor to video.
                if supplies_upstream && cost.up_gap_secs > args.max_gap_secs && attempt < 3 {
                    if args.verbose {
                        eprintln!(
                            "  attempt {attempt}: worst UPSTREAM stall {:.1}s exceeds the \
                             {:.1}s ceiling; a handshake round trip would sit in it, retrying",
                            cost.up_gap_secs, args.max_gap_secs
                        );
                    }
                    continue;
                }
                if supplies_upstream && up_bps < MIN_UPSTREAM_PAYLOAD_BPS {
                    eprintln!(
                        "  attempt {attempt}: upstream payload only {:.0} B/s \
                         (< {MIN_UPSTREAM_PAYLOAD_BPS:.0}); a tunnel's flow control rides \
                         upstream, so this would throttle every download, retrying",
                        up_bps
                    );
                    continue;
                }
                if supplies_upstream && up_rate < MIN_UPSTREAM_TOKENS {
                    eprintln!(
                        "  attempt {attempt}: upstream only {up_rate:.2} tokens/s \
                         (< {MIN_UPSTREAM_TOKENS:.1}); too sparse to carry a tunnel, retrying"
                    );
                    continue;
                }
                if matches!(args.mode, Mode::Upload) {
                    // The point of this mode is records big enough to pad a QUIC
                    // datagram into. Say whether the capture actually delivered
                    // them, rather than leaving it to be discovered later as an
                    // upstream that silently will not shape.
                    let big = events
                        .iter()
                        .filter(|&&(_, sz, dir)| dir < 0 && sz >= 1211)
                        .count();
                    eprintln!(
                        "  upstream records >=1211 B (QUIC-shapeable): {big} of {}",
                        events.iter().filter(|&&(_, _, dir)| dir < 0).count()
                    );
                }
                // LATENCY ceiling, checked before the bandwidth one because a
                // capture can be perfectly affordable and still unusable. The
                // tunnel stalls for exactly as long as the cover is silent, so a
                // trace with a 45-second reading pause hands the user a 45-second
                // freeze. Reject and record another REAL flow - selection among
                // real captures, never synthesis of a busier-looking fake.
                if cost.max_gap_secs > args.max_gap_secs {
                    // Retrying only helps when the stall was ACCIDENTAL - a
                    // page that happened to be quiet, so another draw may be
                    // busier. A realtime video capture's gaps are not accidental:
                    // they ARE the source's segment durations, waited faithfully
                    // because that is what makes the trace replayable as
                    // continuous cover. Measured, Aparat and Turkey's NTV both
                    // publish 10 s segments and OK.ru around 6 s, so every draw
                    // from those sources stalls the same way and the retry is
                    // provably futile - it just spends two more full recording
                    // budgets (2 x 360 s) arriving at the same trace.
                    //
                    // The ranged path does NOT land here, because there the
                    // recorder chooses the request size and sizes it to this very
                    // ceiling. That is a real advantage of DASH/progressive
                    // sources for latency, not an accident.
                    let structural = matches!(args.mode, Mode::Video) && args.rt.real_time;
                    if attempt < 3 && !structural {
                        if args.verbose {
                            eprintln!(
                                "  attempt {attempt}: worst stall {:.1}s exceeds the {:.1}s \
                                 latency ceiling; looking for a busier page",
                                cost.max_gap_secs, args.max_gap_secs
                            );
                        }
                        continue;
                    }
                    // Out of attempts. Keep it - unpaced is worse than laggy -
                    // but SAY so, the way the cost path does. Silence here is
                    // the worse failure: the operator sees a laggy tunnel and
                    // has no way to learn that cover selection gave up, or that
                    // the fix is a budget rather than a shaping knob.
                    //
                    // The two ceilings genuinely conflict at a low budget: a
                    // page load is either fast (costly) or waiting (a gap), so
                    // cheap cover cannot also be smooth. Name that, because it
                    // is the actionable part.
                    if structural {
                        // Raising the budget does NOT fix this one: a bigger
                        // budget buys a fatter variant of the same stream, and
                        // the segment durations - which are what the stalls are -
                        // do not change. Saying "raise the budget" here would
                        // send an operator to spend money on nothing.
                        tracing::warn!(
                            stall_secs = cost.max_gap_secs,
                            ceiling_secs = args.max_gap_secs,
                            "proteus: this video source publishes segments longer than the \
                             latency ceiling, so its cover carries stalls that long. A real \
                             player is genuinely silent between segments, so the capture is \
                             faithful - the tunnel simply inherits the silence. Raising the \
                             bandwidth budget will NOT shorten it. Use browse cover for \
                             latency-sensitive traffic, a source with shorter segments, or a \
                             DASH/progressive source, where the recorder sizes its own requests"
                        );
                        if args.verbose {
                            eprintln!(
                                "  WARNING: kept a {:.1}s worst stall, over the {:.1}s ceiling. \
                                 This source's SEGMENTS are that long, so every capture from it \
                                 stalls the same way and a bigger budget will not help.",
                                cost.max_gap_secs, args.max_gap_secs
                            );
                        }
                    } else {
                        tracing::warn!(
                            stall_secs = cost.max_gap_secs,
                            ceiling_secs = args.max_gap_secs,
                            budget_gb_day = ?args.max_gb_day,
                            "proteus: could not find cover under the latency ceiling; keeping \
                             this capture anyway. A low bandwidth budget forces bursty cover - \
                             raising it is what lowers worst-case latency"
                        );
                        if args.verbose {
                            eprintln!(
                                "  WARNING: kept a {:.1}s worst stall, over the {:.1}s latency \
                                 ceiling (no smoother page found in 3 tries). Cheap cover cannot \
                                 also be smooth; raise the bandwidth budget to lower this.",
                                cost.max_gap_secs, args.max_gap_secs
                            );
                        }
                    }
                }
                // No ceiling means take whatever was recorded, however heavy.
                // Say so, because otherwise an operator who chose "unlimited"
                // cannot tell from the log whether it took - the only visible
                // difference is the ABSENCE of rejection messages, and absence
                // is not evidence.
                if args.max_gb_day.is_none() && args.verbose {
                    eprintln!(
                        "  no ceiling (unlimited): keeping this {:.2} GB/day capture",
                        cost.down_gb_day
                    );
                }
                if let Some(cap) = args.max_gb_day {
                    if cost.down_gb_day > cap {
                        if attempt < 3 {
                            eprintln!(
                                "  attempt {attempt}: {:.2} GB/day exceeds the {cap:.1} GB/day \
                                 ceiling; looking for a lighter page",
                                cost.down_gb_day
                            );
                            continue;
                        }
                        // Out of attempts. Keep it rather than leave Proteus with
                        // nothing to wear - unpaced is a worse outcome than
                        // over-budget - but say so, because an operator who set a
                        // ceiling and silently got 60% more would find out from
                        // their bill. Real page weight varies more than any
                        // ceiling can promise.
                        tracing::warn!(
                            over_budget_gb_day = cost.down_gb_day,
                            ceiling_gb_day = cap,
                            "proteus: could not find cover under the cost ceiling; keeping this \
                             capture anyway, since unpaced is worse than over-budget"
                        );
                        if args.verbose {
                            eprintln!(
                                "  WARNING: kept {:.2} GB/day, over the {cap:.1} GB/day ceiling \
                                 (no lighter page found in 3 tries)",
                                cost.down_gb_day
                            );
                        }
                    }
                }
                let path = write_csv(dir, &events)?;
                if args.verbose {
                    println!(
                        "recorded {} ({} records, {} KiB {}) from {}",
                        path.display(),
                        events.len(),
                        measured / 1024,
                        label,
                        src.host()
                    );
                    println!("  envelope: {cost}");
                }
                return Ok(cost);
            }
            Err(e) => eprintln!("  attempt {attempt}: record failed: {e}"),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::Other,
        "gave up after 3 attempts",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_recorder_only_rejects_when_a_ceiling_actually_reached_it() {
        // The bug this pins: a caller resolved "unlimited" to None, LOGGED it,
        // and then handed the recorder the tier's default anyway - so the
        // operator saw ceiling=None in the log while captures were still being
        // rejected at 2.5 GB/day. Computed-but-not-applied is the exact shape of
        // defect this crate keeps producing, so the ceiling that reaches `Args`
        // is asserted directly.
        let lib = std::env::temp_dir().join("mirage-cover-ceiling-test");

        // Unlimited: nothing to compare against, so nothing can be rejected.
        let mut a = Args::auto_budget(
            lib.clone(),
            Mode::Browse,
            Some(DEFAULT_MAX_GB_DAY),
            packs::SourcePack::Global,
        );
        a.max_gb_day = CoverBudget::Named("unlimited".into()).gb_per_day(Some(DEFAULT_MAX_GB_DAY));
        assert_eq!(
            a.max_gb_day, None,
            "unlimited must leave the recorder with no ceiling to enforce"
        );

        // A number is carried through verbatim, not rounded to a tier.
        let mut b = Args::auto_budget(
            lib,
            Mode::Browse,
            Some(DEFAULT_MAX_GB_DAY),
            packs::SourcePack::Global,
        );
        b.max_gb_day = CoverBudget::GbPerDay(9.0).gb_per_day(Some(DEFAULT_MAX_GB_DAY));
        assert_eq!(
            b.max_gb_day,
            Some(9.0),
            "an explicit budget must override the default, not be replaced by it"
        );
        assert_ne!(
            b.max_gb_day,
            Some(DEFAULT_MAX_GB_DAY),
            "9 GB/day must not silently become the 2.5 default"
        );
    }

    #[test]
    fn bandwidth_and_bill_are_the_same_quantity() {
        // The envelope's rate IS the session's throughput ceiling, because cover
        // runs around the clock - so a per-session bandwidth limit and a daily
        // cover bill are one number in two units. If this ever drifts, an
        // operator sets a limit in Mbit/s and gets billed for something else.
        assert!((gb_day_from_mbit(1.0) - 10.8).abs() < 1e-9);
        assert!((gb_day_from_mbit(10.0) - 108.0).abs() < 1e-6);
        // Round trip, over the range an operator would plausibly pick.
        for mbit in [0.25_f64, 1.0, 5.0, 25.0, 100.0] {
            let back = mbit_from_gb_day(gb_day_from_mbit(mbit));
            assert!(
                (back - mbit).abs() < 1e-9,
                "{mbit} Mbit/s round-tripped to {back}"
            );
        }
        // And the tier defaults still describe themselves correctly.
        assert!((mbit_from_gb_day(2.5) - 0.2315).abs() < 1e-3);
    }

    #[test]
    fn the_recorder_cannot_manufacture_a_gap_the_checker_will_reject() {
        // The recorder and the acceptance check used to disagree: browse dwelled
        // 4-14 s while `max_gap_secs` rejected anything past 2 s, so every retry
        // reproduced the same violation and the third was kept anyway. The dwell
        // is now drawn under the ceiling by construction.
        for ceiling in [0.05_f64, 0.5, 2.0, DEFAULT_MAX_GAP_SECS, 30.0] {
            let max_gap = Duration::from_secs_f64(ceiling);
            for mix in [0_u64, 1, 7, 12345, u64::MAX, 0x9E37_79B9_7F4A_7C15] {
                let ms = dwell_ms(mix, max_gap);
                assert!(
                    ms <= max_gap.as_millis().max(50) as u64,
                    "dwell {ms}ms exceeds the {ceiling}s ceiling it must respect"
                );
                // And it leaves room for the next page's time to first byte,
                // because the ceiling applies to dwell + TTFB, not to the dwell
                // alone. Without this the recorder overshoots by the fetch
                // latency - measured at 2.31s against a 2.0s ceiling.
                if ceiling >= 1.0 {
                    let headroom = max_gap.as_millis() as u64 - ms;
                    assert!(
                        headroom >= 300,
                        "dwell {ms}ms leaves only {headroom}ms of the {ceiling}s \
                         ceiling for the next page's first byte"
                    );
                }
            }
        }
        // And it still VARIES - a constant inter-burst period is its own
        // fingerprint, which is the reason the dwell is drawn at all.
        let wide = Duration::from_secs(2);
        let drawn: std::collections::HashSet<u64> =
            (0..64).map(|i| dwell_ms(i * 7919, wide)).collect();
        assert!(drawn.len() > 1, "dwell collapsed to a constant period");
    }

    #[test]
    fn the_upstream_class_name_is_shared_not_duplicated() {
        // `mirage-transport-reality` excludes this directory when pooling a
        // library root for DOWNSTREAM cover, and it cannot depend on this crate
        // to learn the name. If the two ever drift, the exclusion silently stops
        // matching and upstream captures start being worn as downstream cover
        // again - with no error anywhere, just a slower and more variable tunnel.
        assert_eq!(
            UPSTREAM_CLASS,
            mirage_common::proteus_switch::UPSTREAM_COVER_CLASS
        );
    }

    #[test]
    fn cost_measures_both_directions_and_the_opening() {
        // A capture whose DOWNSTREAM is dense and whose UPSTREAM is silent for
        // most of a minute. Acceptance used to look only downstream, so this
        // passed - and then stalled the handshake, which needs an upstream token
        // for the other half of every round trip.
        let mut ev: Vec<Event> = Vec::new();
        for i in 0..200 {
            ev.push((f64::from(i) * 0.05, 1400, 1)); // downstream every 50 ms
        }
        ev.push((0.10, 200, -1)); // one upstream record early
        ev.push((9.90, 200, -1)); // then nothing for 9.8 s
        ev.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap());
        let c = Cost::of(&ev);
        assert!(c.max_gap_secs < 0.1, "downstream is dense: {c:?}");
        assert!(
            c.up_gap_secs > 9.0,
            "the upstream silence must be visible, not averaged away: {c:?}"
        );

        // And the OPENING is its own quantity: a capture can have a fine worst
        // gap and still open slowly, which is the video-cover failure.
        let slow_open: Vec<Event> = std::iter::once((0.0, 300, -1))
            .chain((0..100).map(|i| (12.0 + f64::from(i) * 0.05, 1400, 1)))
            .collect();
        let c2 = Cost::of(&slow_open);
        assert!(
            c2.max_gap_secs < 0.1,
            "worst gap alone says this capture is fine: {c2:?}"
        );
        assert!(
            c2.open_down_secs > 11.0,
            "but it opens 12s late, which is what stalls the handshake: {c2:?}"
        );

        // A direction with no records at all is the worst case, not the best -
        // it never yields a token, so it must not read as "opens instantly".
        let no_up: Vec<Event> = (0..50).map(|i| (f64::from(i) * 0.1, 1400, 1)).collect();
        let c3 = Cost::of(&no_up);
        assert!(
            c3.open_up_secs >= c3.span_secs,
            "a silent direction must not look like a fast one: {c3:?}"
        );
    }

    #[test]
    fn a_browse_session_is_measured_by_span_not_page_count() {
        // Span sets the replay loop's period, so it is the quantity the session
        // targets and the quantity the collapse check polices. Keying the check
        // off a dwell length (as it once did) would wave through the measured
        // 1.2 s single-page-load case now that dwell is sub-second.
        let floor = SESSION_TARGET_SPAN.as_secs_f64() / 2.0;
        assert!(
            floor > 1.2,
            "a 1.2s collapsed capture must not clear the session floor"
        );
        assert!(
            floor > DWELL_MIN.as_secs_f64() * 2.0,
            "the floor must be a session length, not a dwell length"
        );
    }

    #[test]
    fn unlimited_really_means_no_ceiling() {
        // "unlimited" is an I-DO-NOT-CARE button and has to behave like one: no
        // ceiling reaches the recorder, so no capture is ever rejected for being
        // heavy. The recorder skips its whole cost check on `None`, so the only
        // thing that can break this is the config value failing to resolve to
        // `None` - which is exactly what this pins.
        let fallback = Some(2.5);
        for spelling in [
            "unlimited",
            "UNLIMITED",
            " Unlimited ",
            "none",
            "off",
            "uncapped",
        ] {
            assert_eq!(
                CoverBudget::Named(spelling.to_string()).gb_per_day(fallback),
                None,
                "{spelling} must resolve to no ceiling"
            );
        }
        // A number is that number.
        assert_eq!(CoverBudget::GbPerDay(7.5).gb_per_day(fallback), Some(7.5));
        // A typo must NOT silently uncap - it falls back to the tier ceiling,
        // because quietly removing someone's bandwidth limit is the one failure
        // that costs real money.
        assert_eq!(
            CoverBudget::Named("unlimted".to_string()).gb_per_day(fallback),
            fallback,
            "an unrecognised spelling must not remove the cap"
        );
        // And the description an operator reads has to match what happens.
        assert!(CoverBudget::Named("unlimited".into())
            .describe(fallback)
            .starts_with("unlimited"));
        assert!(CoverBudget::GbPerDay(2.5)
            .describe(fallback)
            .contains("0.23 Mbit/s"));
    }

    #[test]
    fn legacy_tier_names_still_resolve_to_a_budget() {
        // Tiers are gone from the API, but a config written against them must
        // keep working rather than failing to parse on upgrade.
        assert_eq!(legacy_tier_budget("lean"), Some(DEFAULT_MAX_GB_DAY));
        assert_eq!(legacy_tier_budget("metered"), Some(DEFAULT_MAX_GB_DAY));
        assert_eq!(legacy_tier_budget("balanced"), Some(6.0));
        assert_eq!(legacy_tier_budget(" BALANCED "), Some(6.0));

        // `aggressive` was the UNCAPPED tier. It resolves to a ceiling, never to
        // `None`: it measured no less detectable than lean and was the only
        // setting that produced a tunnel which would not come up, so honouring
        // "no limit" would restore a footgun the measurements already closed.
        assert_eq!(legacy_tier_budget("aggressive"), Some(6.0));
        assert_eq!(legacy_tier_budget("max"), Some(6.0));

        // An unrecognised spelling must not silently uncap; callers fall back to
        // the default ceiling.
        assert_eq!(legacy_tier_budget("nonsense"), None);
    }

    #[test]
    fn record_parser_splits_records() {
        // Two TLS records: header len 3 then len 2, back to back, fed in odd chunks.
        let mut p = RecordParser::default();
        let out = Mutex::new(Vec::new());
        let rec1 = [0x17u8, 0x03, 0x03, 0x00, 0x03, 1, 2, 3];
        let rec2 = [0x17u8, 0x03, 0x03, 0x00, 0x02, 9, 9];
        let mut all = Vec::new();
        all.extend_from_slice(&rec1);
        all.extend_from_slice(&rec2);
        // feed in 3-byte chunks to exercise header/body straddling
        for c in all.chunks(3) {
            p.feed(c, 0.0, 1, &out);
        }
        let got = out.lock().unwrap().clone();
        assert_eq!(got, vec![(0.0, 8, 1), (0.0, 7, 1)]); // 5+3, 5+2
    }

    #[test]
    fn parse_master_picks_bandwidth_and_resolves() {
        let base = Url::parse("https://cdn.example/v/master.m3u8").unwrap();
        let m = "#EXTM3U\n#EXT-X-STREAM-INF:BANDWIDTH=800000,RESOLUTION=640x360\n360.m3u8\n\
                 #EXT-X-STREAM-INF:BANDWIDTH=2400000\nhttps://cdn2.example/720.m3u8\n";
        let v = parse_master(m, &base);
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].0, 800_000);
        assert_eq!(v[0].1.as_str(), "https://cdn.example/v/360.m3u8");
        assert_eq!(v[1].1.as_str(), "https://cdn2.example/720.m3u8");
    }

    #[test]
    fn a_stray_ampersand_before_the_query_is_repaired() {
        // Measured on the Dogus CDN carrying Turkey's broadcast channels. The
        // unrepaired form resolves to a path ending in `&` and answers 200 with
        // an EMPTY body, so the failure looks like "no segments" and the whole
        // source reads as broken rather than as one malformed URI.
        let base = Url::parse("https://dogus.daioncdn.net/ntv/ntv.m3u8").unwrap();
        let m = "#EXTM3U\n#EXT-X-STREAM-INF:BANDWIDTH=550000\nntv_360p.m3u8&?sid=abc&ce=2\n";
        let v = parse_master(m, &base);
        assert_eq!(
            v[0].1.as_str(),
            "https://dogus.daioncdn.net/ntv/ntv_360p.m3u8?sid=abc&ce=2"
        );
        // Only a `&` directly before the FIRST `?` is stripped; one inside a
        // query value is a legitimate character and must survive.
        assert_eq!(normalise_uri("a.m3u8?x=1&?y=2"), "a.m3u8?x=1&?y=2");
        assert_eq!(normalise_uri("plain.m3u8"), "plain.m3u8");
    }

    #[test]
    fn a_ranged_chunk_is_one_latency_budget_of_media() {
        // The regression this pins: a FIXED 512 KiB chunk is 26.5 seconds of
        // Bilibili's 158 kbit/s rendition, so a realtime capture idled 26.5 s
        // between requests against a 2 s ceiling - every such capture rejected,
        // or kept with a warning as cover that stalls the tunnel for 26 s. The
        // chunk has to follow the cadence, not the other way round.
        let gap = Duration::from_secs_f64(DEFAULT_MAX_GAP_SECS);
        for bitrate in [158_000u64, 252_244, 654_777, 2_166_129] {
            let chunk = range_chunk_bytes(bitrate, gap);
            let secs = chunk as f64 * 8.0 / bitrate as f64;
            assert!(
                secs <= DEFAULT_MAX_GAP_SECS * RANGE_GAP_HEADROOM + 0.01,
                "{bitrate} bit/s -> {chunk} B is {secs:.1}s of media; the ceiling is \
                 {DEFAULT_MAX_GAP_SECS}s and the request itself needs headroom inside it"
            );
        }

        // The old constant, stated as the failure it was.
        let old = 512.0 * 1024.0 * 8.0 / 158_000.0;
        assert!(old > 25.0, "sanity: the fixed chunk really was {old:.1}s");

        // Clamps keep a pathological bitrate from producing a single-packet
        // request or a multi-megabyte burst, neither of which a player makes.
        assert_eq!(range_chunk_bytes(1, gap), RANGE_CHUNK_MIN);
        assert_eq!(range_chunk_bytes(u64::MAX / 16, gap), RANGE_CHUNK_MAX);
        // A zero gap must not ask for a zero-length range.
        assert!(range_chunk_bytes(500_000, Duration::ZERO) >= RANGE_CHUNK_MIN);
    }

    #[test]
    fn bilibili_dash_picks_by_bandwidth_in_both_directions() {
        // Bilibili serves no HLS at all, so this is the only path to Chinese
        // domestic video. Bandwidth choice IS the 24/7 cover bill, exactly as
        // the HLS variant choice is.
        let d: Value = serde_json::from_str(
            r#"{"data":{"dash":{"video":[
                 {"bandwidth":654777,"baseUrl":"https://cdn.test/hi.m4s"},
                 {"bandwidth":252244,"baseUrl":"https://cdn.test/lo.m4s"}]}}}"#,
        )
        .unwrap();
        let Some(Stream::Ranged {
            url,
            bitrate_bps,
            referer,
        }) = bilibili_stream(&d, true)
        else {
            panic!("expected a ranged stream");
        };
        assert_eq!(url.as_str(), "https://cdn.test/lo.m4s");
        assert_eq!(bitrate_bps, 252_244);
        // Without this the CDN answers 403 to every range.
        assert_eq!(referer.as_deref(), Some("https://www.bilibili.com/"));

        let Some(Stream::Ranged { url, .. }) = bilibili_stream(&d, false) else {
            panic!("expected a ranged stream");
        };
        assert_eq!(url.as_str(), "https://cdn.test/hi.m4s");
        assert!(bilibili_stream(&serde_json::json!({"code": -404}), true).is_none());
    }

    #[test]
    fn aparat_offers_hls_and_a_progressive_fallback_together() {
        // Both must be OFFERED, in that order. Returning only the HLS link made
        // the fallback unreachable in exactly the case it exists for: that
        // endpoint is a signed redirector that answers 400 in the wild, and the
        // recorder's retry loop re-resolves and picks the same broken link every
        // time. The caller validates the playlist and moves to the progressive
        // file when it does not answer.
        let both: Value = serde_json::from_str(
            r#"{"data":{"attributes":{"hls":{"link":"https://aparat.test/m.m3u8"},
                 "file_link_all":[
                   {"profile":"144p","urls":["https://cdn.test/144.apt"]},
                   {"profile":"720p","urls":["https://cdn.test/720.apt"]}]}}}"#,
        )
        .unwrap();
        let c = aparat_candidates(&both, true);
        assert_eq!(c.len(), 2, "HLS plus a progressive fallback: {c:?}");
        assert!(matches!(&c[0], Stream::Hls(u) if u.as_str() == "https://aparat.test/m.m3u8"));
        let Stream::Ranged {
            url, bitrate_bps, ..
        } = &c[1]
        else {
            panic!("second candidate must be ranged");
        };
        assert_eq!(url.as_str(), "https://cdn.test/144.apt");
        assert_eq!(*bitrate_bps, aparat_profile_bps(Some("144p")));

        // The budget picks the profile, exactly as it picks an HLS variant.
        let Stream::Ranged { url, .. } = &aparat_candidates(&both, false)[1] else {
            panic!("expected a ranged candidate");
        };
        assert_eq!(url.as_str(), "https://cdn.test/720.apt");

        // No HLS field at all: the progressive file is the only candidate.
        let prog: Value = serde_json::from_str(
            r#"{"data":{"attributes":{"file_link_all":[
                 {"profile":"360p","urls":["https://cdn.test/360.apt"]}]}}}"#,
        )
        .unwrap();
        let c = aparat_candidates(&prog, true);
        assert_eq!(c.len(), 1);
        assert!(
            matches!(&c[0], Stream::Ranged { url, .. } if url.as_str() == "https://cdn.test/360.apt")
        );

        // A response carrying neither must yield nothing rather than panic.
        assert!(aparat_candidates(&serde_json::json!({ "data": {} }), true).is_empty());
    }

    #[test]
    fn aparat_hashes_are_alphanumeric_uids() {
        let body = r#"{"data":[{"attributes":{"uid":"civlzbq"}},{"attributes":{"uid":"civlzbq"}},
                      {"attributes":{"uid":"x5bnk56"}},{"attributes":{"uid":"not a hash!"}}]}"#;
        assert_eq!(aparat_hashes(body), vec!["civlzbq", "x5bnk56"]);
    }

    #[test]
    fn an_extractor_command_yields_its_last_url() {
        // `yt-dlp -g` prints the video URL then the audio URL, so the last line
        // is the one to take. Non-URL chatter must not be mistaken for output.
        let u = hls_from_command(
            "echo picking best format; echo https://a.test/v.m3u8; echo https://a.test/audio.m3u8",
        )
        .expect("command");
        assert_eq!(u.as_str(), "https://a.test/audio.m3u8");
        // A command that prints nothing usable must fail loudly rather than
        // silently recording from somewhere else.
        assert!(hls_from_command("echo no url here").is_err());
        assert!(hls_from_command("exit 3").is_err());
    }

    #[test]
    fn scan_finds_a_manifest_through_double_escaping() {
        // The literal bytes OK.ru serves: a JSON string inside an HTML attribute,
        // escaped twice. A scanner that skips the unescape finds a URL truncated
        // at the first `&` and fetches a 400, so this is the case that matters.
        let base = Url::parse("https://ok.ru/video/14941296593488").unwrap();
        let page = r#"<div data-options="{\&quot;hlsManifestUrl\&quot;:\&quot;https://ok6-31.vkuser.net/video.m3u8?cmd=videoPlayerCdn\\u0026expires=1785967790424\\u0026mid=14941296593488\&quot;}"></div>"#;
        let found = scan_manifests(page, &base);
        assert_eq!(found.len(), 1, "{found:?}");
        let u = found[0].as_str();
        assert!(u.starts_with("https://ok6-31.vkuser.net/video.m3u8?cmd=videoPlayerCdn"));
        assert!(u.contains("&expires=1785967790424"), "query survived: {u}");
        assert!(u.ends_with("&mid=14941296593488"), "not truncated: {u}");
        assert!(!u.contains('\\'), "no stray backslash: {u}");
    }

    #[test]
    fn scan_resolves_relative_manifests_and_keeps_commas() {
        let base = Url::parse("https://v.example/watch/1").unwrap();
        // A comma is legal in a query string - Rutube lists variant GUIDs that
        // way - so it must not terminate the URL going forward.
        let page = "var src = \"/hls/master.m3u8?guids=a_1080,b_720\";";
        let found = scan_manifests(page, &base);
        assert_eq!(
            found.iter().map(Url::as_str).collect::<Vec<_>>(),
            vec!["https://v.example/hls/master.m3u8?guids=a_1080,b_720"]
        );
    }

    #[test]
    fn scan_ignores_a_page_with_no_manifest() {
        let base = Url::parse("https://v.example/").unwrap();
        assert!(scan_manifests("<html><body>no video here</body></html>", &base).is_empty());
    }

    #[test]
    fn rutube_ids_are_32_hex_under_video() {
        // Only the fixed-width hex form is a video id; `/video/browse` and short
        // hex fragments are navigation, and asking the play-options API about
        // them wastes a round trip per candidate.
        let html = "<a href=\"/video/0159941b24c63763c4a9aed839fad682/\">x</a>\
                    <a href=\"/video/browse/\">nav</a>\
                    <a href=\"/video/abc123/\">short</a>\
                    <a href=\"/video/0159941b24c63763c4a9aed839fad682/\">dup</a>";
        assert_eq!(
            rutube_ids(html),
            vec!["0159941b24c63763c4a9aed839fad682".to_string()]
        );
    }

    #[test]
    fn rutube_play_options_yields_the_master_playlist() {
        let v: Value = serde_json::from_str(
            r#"{"video_balancer":{"m3u8":"https://bl.rutube.ru/route/abc.m3u8?sign=x&expire=1"}}"#,
        )
        .unwrap();
        assert_eq!(
            rutube_m3u8(&v).map(|u| u.as_str().to_string()),
            Some("https://bl.rutube.ru/route/abc.m3u8?sign=x&expire=1".to_string())
        );
        // A response without a balancer must not panic or invent a URL.
        assert!(rutube_m3u8(&serde_json::json!({"detail": "not found"})).is_none());
    }

    #[test]
    fn links_containing_selects_only_video_pages() {
        let base = Url::parse("https://ok.ru/video").unwrap();
        let html = "<a href=\"/video/14941296593488\">a</a>\
                    <a href=\"/profile/123\">b</a>\
                    <a href=\"/video/14941296593488\">dup</a>";
        let v = links_containing(html, &base, "/video/");
        assert_eq!(
            v.iter().map(Url::as_str).collect::<Vec<_>>(),
            vec!["https://ok.ru/video/14941296593488"]
        );
    }

    #[test]
    fn parse_subresources_collects_assets_not_nav() {
        let base = Url::parse("https://en.wikipedia.org/wiki/Cat").unwrap();
        let html = "<link rel=stylesheet href=\"/w/load.php?modules=x\">\
                    <a href=\"/wiki/Dog\">Dog</a>\
                    <img src=\"//upload.wikimedia.org/a/cat.jpg\">\
                    <script src=\"/w/index.js\"></script>\
                    <img data-src=\"data:image/gif;base64,zzz\">";
        let urls: Vec<String> = parse_subresources(html, &base)
            .iter()
            .map(|u| u.as_str().to_string())
            .collect();
        assert!(urls.contains(&"https://upload.wikimedia.org/a/cat.jpg".to_string()));
        assert!(urls.contains(&"https://en.wikipedia.org/w/index.js".to_string()));
        assert!(urls.iter().any(|u| u.contains("load.php")));
        // navigation link and data: URI are not fetched
        assert!(!urls.iter().any(|u| u.ends_with("/wiki/Dog")));
        assert!(!urls.iter().any(|u| u.starts_with("data:")));
    }

    #[test]
    fn parse_media_reads_map_and_durations() {
        let base = Url::parse("https://cdn.example/v/360.m3u8").unwrap();
        let m = "#EXTM3U\n#EXT-X-MAP:URI=\"init.mp4\"\n#EXTINF:4.0,\nseg0.m4s\n#EXTINF:3.5,\nseg1.m4s\n";
        let segs = parse_media(m, &base);
        assert_eq!(segs.len(), 3);
        assert_eq!(segs[0].1.as_str(), "https://cdn.example/v/init.mp4");
        assert_eq!(segs[1].0, 4.0);
        assert_eq!(segs[1].1.as_str(), "https://cdn.example/v/seg0.m4s");
        assert_eq!(segs[1].2, None, "no BYTERANGE means a whole-resource fetch");
        assert_eq!(segs[2].0, 3.5);
    }

    /// Byte-range playlists (what PeerTube actually serves) address slices of ONE
    /// media file. Before this was parsed, every segment fetch pulled the entire
    /// file up to the body cap, so a "video" recording was a handful of
    /// multi-megabyte bursts rather than a stream - the trace's replay rate came
    /// out 1-2 orders of magnitude above the real stream's bitrate.
    #[test]
    fn parse_media_reads_byteranges_including_implicit_offsets() {
        let base = Url::parse("https://cdn.example/v/360.m3u8").unwrap();
        let m = "#EXTM3U\n\
                 #EXT-X-MAP:URI=\"media.mp4\",BYTERANGE=\"720@0\"\n\
                 #EXTINF:4.0,\n#EXT-X-BYTERANGE:1000@720\nmedia.mp4\n\
                 #EXTINF:4.0,\n#EXT-X-BYTERANGE:2000\nmedia.mp4\n\
                 #EXTINF:4.0,\n#EXT-X-BYTERANGE:1500\nmedia.mp4\n";
        let segs = parse_media(m, &base);
        assert_eq!(segs.len(), 4);
        // Init map carries its own explicit range.
        assert_eq!(segs[0].2, Some((0, 720)));
        // Explicit `len@off`.
        assert_eq!(segs[1].2, Some((720, 1000)));
        // Implicit offsets continue from the previous range of the SAME resource.
        assert_eq!(segs[2].2, Some((1720, 2000)));
        assert_eq!(segs[3].2, Some((3720, 1500)));
        // All four address the same file - which is exactly why the range matters.
        assert!(segs
            .iter()
            .all(|(_, u, _)| u.as_str().ends_with("media.mp4")));
    }

    #[test]
    fn attr_handles_quoted_and_bare() {
        assert_eq!(attr("URI=\"a.mp4\",X=1", "URI").as_deref(), Some("a.mp4"));
        assert_eq!(
            attr("BANDWIDTH=1234,CODECS=x", "BANDWIDTH").as_deref(),
            Some("1234")
        );
    }
}
