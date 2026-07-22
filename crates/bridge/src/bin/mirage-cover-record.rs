//! `mirage-cover-record` - self-contained cover-traffic recorder. Fetches a real
//! video stream (HLS) over rustls and writes its TLS-record envelope `(t,size,dir)`
//! to the replay library the Reality pacer wears. No external tools: no yt-dlp,
//! ffmpeg, tcpdump, or python.
//!
//! Record sizes are read straight off the wire by parsing the cleartext 5-byte TLS
//! record headers of the connection this process drives - the same signal a DPI
//! sees, and exactly what the pacer replays.
//!
//! ```sh
//! mirage-cover-record ./library                 # random real PeerTube video
//! mirage-cover-record ./library --count 20      # 20 random traces
//! mirage-cover-record ./library --hls <url>     # a specific HLS master playlist
//! mirage-cover-record ./library --loop 30 --max 40   # self-driving: refresh forever
//! ```

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use mirage_common::process_hardening::harden_process;
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
/// Browse: subresource fetch caps + inter-asset gap (a page loads assets in a burst).
const MAX_ASSETS: usize = 48;
const BROWSE_GAP: Duration = Duration::from_millis(60);
/// Realistic browser UA so CDNs / PeerTube serve normally.
const UA: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 \
                  (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36";
/// Default open video sources (real HD content, HLS, no walled-garden extractor).
const PEERTUBE: &[&str] = &[
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
/// Default browse sources: random real pages, ubiquitous + high-collateral to block.
/// Special:Random 302-redirects to a random article (we follow it).
const BROWSE_SITES: &[&str] = &[
    "en.wikipedia.org",
    "de.wikipedia.org",
    "fr.wikipedia.org",
    "es.wikipedia.org",
    "ja.wikipedia.org",
    "ru.wikipedia.org",
];

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
        let mut cur = url.clone();
        for _ in 0..5 {
            let (status, location, body) = self.get_once(&cur).await?;
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
    async fn get_once(&mut self, url: &Url) -> io::Result<(u16, Option<String>, Vec<u8>)> {
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
        match request(conn, &host, &path).await {
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
) -> io::Result<(u16, Option<String>, Vec<u8>, bool)> {
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {UA}\r\n\
         Accept: */*\r\nAccept-Encoding: identity\r\nConnection: keep-alive\r\n\r\n"
    );
    conn.get_mut().write_all(req.as_bytes()).await?;
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
                    if let Ok(u) = base.join(uri) {
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

/// Media playlist -> `(segment duration s, segment url)` list (incl. any init map).
fn parse_media(text: &str, base: &Url) -> Vec<(f64, Url)> {
    let mut out = Vec::new();
    let mut dur = 0.0f64;
    for l in text.lines() {
        let l = l.trim();
        if let Some(rest) = l.strip_prefix("#EXTINF:") {
            dur = rest
                .split(',')
                .next()
                .and_then(|x| x.trim().parse().ok())
                .unwrap_or(0.0);
        } else if let Some(rest) = l.strip_prefix("#EXT-X-MAP:") {
            if let Some(uri) = attr(rest, "URI") {
                if let Ok(u) = base.join(&uri) {
                    out.push((0.0, u));
                }
            }
        } else if l.starts_with('#') || l.is_empty() {
            continue;
        } else if let Ok(u) = base.join(l) {
            out.push((dur, u));
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

// --- record one stream ------------------------------------------------------

/// Drive one HLS stream and return its wire record envelope.
async fn record_stream(master: &Url) -> io::Result<Vec<Event>> {
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
        // Master: pick a high-bitrate variant (more MTU-sized records = better cover).
        let mut variants = parse_master(&text, master);
        variants.sort_by_key(|(bw, _)| *bw);
        let pick = variants
            .last()
            .map(|(_, u)| u.clone())
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "no variants"))?;
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

    let mut got = 0usize;
    let mut bytes = 0usize;
    for (dur, seg) in &segs {
        if got >= MAX_SEGS || bytes >= MAX_BYTES || start.elapsed() >= MAX_TIME {
            break;
        }
        if let Ok((200, b)) = f.get(seg).await {
            bytes += b.len();
            got += 1;
        }
        // Pace like a player buffering: wait ~segment duration, capped.
        let gap = Duration::from_secs_f64(dur.max(0.0)).min(SEG_GAP_MAX);
        tokio::time::sleep(gap).await;
    }
    drop(f);
    let events = out.lock().unwrap().clone();
    Ok(events)
}

/// Drive one page load (HTML + its subresources) and return its wire envelope - a
/// web-browsing shape (bursty small/medium objects), distinct from streaming video.
async fn record_browse(page: &Url) -> io::Result<Vec<Event>> {
    let start = Instant::now();
    let out = Arc::new(Mutex::new(Vec::new()));
    let mut f = Fetcher::new(start, out.clone())?;

    let (st, body) = f.get(page).await?;
    if st != 200 {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("page HTTP {st}"),
        ));
    }
    let subs = parse_subresources(&String::from_utf8_lossy(&body), page);
    if subs.is_empty() {
        return Err(io::Error::new(io::ErrorKind::Other, "no subresources"));
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
    drop(f);
    let events = out.lock().unwrap().clone();
    Ok(events)
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
fn prune(dir: &Path, keep: usize) {
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

// --- CLI --------------------------------------------------------------------

/// Cover class: a streaming-video envelope or a web-browsing envelope.
#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Video,
    Browse,
}

struct Args {
    lib: PathBuf,
    name: String,
    mode: Mode,
    count: usize,
    hls: Option<String>,
    url: Option<String>,
    instance: Option<String>,
    loop_mins: Option<u64>,
    max: Option<usize>,
}

fn usage() -> ! {
    eprintln!(
        "usage: mirage-cover-record <lib-dir> [options]\n\
         \n\
         Records real traffic's wire envelope into <lib-dir>/<name>/<i>.csv, the replay\n\
         library the Reality pacer wears. Self-contained (no external tools).\n\
         \n\
         options:\n\
           --mode video|browse  cover class (default video)\n\
           --count N            record N traces (default 1)\n\
           --hls URL            video: record a specific HLS master playlist\n\
           --peertube HOST      video: use a specific PeerTube instance\n\
           --url URL            browse: record a specific page + its subresources\n\
           --name NAME          library subdir name (default: the mode)\n\
           --loop MINUTES       self-driving: record, wait, repeat forever\n\
           --max K              in --loop, keep only the K newest traces\n\
         \n\
         Point the tunnel at a class dir:\n\
           reality_pace: \"replay\", reality_pace_profile: \"<lib-dir>/video\"\n\
         (paranoid mode sets this for you)."
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
    let mut instance = None;
    let mut loop_mins = None;
    let mut max = None;
    while let Some(arg) = a.next() {
        match arg.as_str() {
            "-h" | "--help" => usage(),
            "--mode" => {
                mode = Some(match val(&mut a).as_str() {
                    "video" => Mode::Video,
                    "browse" => Mode::Browse,
                    _ => usage(),
                })
            }
            "--count" => count = val(&mut a).parse().unwrap_or_else(|_| usage()),
            "--hls" => hls = Some(val(&mut a)),
            "--url" => url = Some(val(&mut a)),
            "--peertube" => instance = Some(val(&mut a)),
            "--name" => name = Some(val(&mut a)),
            "--loop" => loop_mins = Some(val(&mut a).parse().unwrap_or_else(|_| usage())),
            "--max" => max = Some(val(&mut a).parse().unwrap_or_else(|_| usage())),
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
    });
    Args {
        lib,
        name,
        mode,
        count,
        hls,
        url,
        instance,
        loop_mins,
        max,
    }
}

/// Resolve a source URL: `--hls`/random PeerTube for video, `--url`/random page for browse.
async fn resolve_source(args: &Args, start: Instant) -> io::Result<Url> {
    let parse = |u: &str| {
        Url::parse(u).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))
    };
    match args.mode {
        Mode::Browse => {
            if let Some(u) = &args.url {
                return parse(u);
            }
            let site = BROWSE_SITES[(rand_u64() as usize) % BROWSE_SITES.len()];
            parse(&format!("https://{site}/wiki/Special:Random"))
        }
        Mode::Video => {
            if let Some(u) = &args.hls {
                return parse(u);
            }
            let out = Arc::new(Mutex::new(Vec::new()));
            let mut f = Fetcher::new(start, out)?;
            let instances: Vec<String> = match &args.instance {
                Some(i) => vec![i.clone()],
                None => shuffled(PEERTUBE.len())
                    .into_iter()
                    .map(|i| PEERTUBE[i].to_string())
                    .collect(),
            };
            for inst in &instances {
                match peertube_hls(&mut f, inst).await {
                    Ok(u) => return Ok(u),
                    Err(e) => eprintln!("  {inst}: {e}"),
                }
            }
            Err(io::Error::new(io::ErrorKind::Other, "no source resolved"))
        }
    }
}

/// Record one trace (with a few attempts to clear the volume floor).
async fn record_one(args: &Args, dir: &Path) -> io::Result<()> {
    for attempt in 1..=3 {
        let src = match resolve_source(args, Instant::now()).await {
            Ok(u) => u,
            Err(e) => {
                eprintln!("  resolve failed: {e}");
                continue;
            }
        };
        let recorded = match args.mode {
            Mode::Video => record_stream(&src).await,
            Mode::Browse => record_browse(&src).await,
        };
        match recorded {
            Ok(events) => {
                let db = down_bytes(&events);
                if db < MIN_TRACE_BYTES {
                    eprintln!(
                        "  attempt {attempt}: only {db} down bytes (< {MIN_TRACE_BYTES}); retrying"
                    );
                    continue;
                }
                let path = write_csv(dir, &events)?;
                println!(
                    "recorded {} ({} records, {} KiB down) from {}",
                    path.display(),
                    events.len(),
                    db / 1024,
                    src.host_str().unwrap_or("?")
                );
                return Ok(());
            }
            Err(e) => eprintln!("  attempt {attempt}: record failed: {e}"),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::Other,
        "gave up after 3 attempts",
    ))
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
                tokio::time::sleep(Duration::from_secs(m * 60)).await;
            }
            None => break,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(
            segs[1],
            (4.0, Url::parse("https://cdn.example/v/seg0.m4s").unwrap())
        );
        assert_eq!(segs[2].0, 3.5);
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
