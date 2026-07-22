//! WebSocket-based `DiscoveryChannel` implementation for real Nostr relays.
//!
//! Gated behind the `relay` feature. The protocol layer in the sibling
//! modules (`event`, `signing`, `wrap`) is I/O-free; this module adds
//! the async WebSocket client that talks to a relay on the other end.
//!
//! Wire protocol (NIP-01 client-to-relay messages we emit / consume):
//!
//! ```text
//! client -> relay:  ["EVENT", <event>]
//! client -> relay:  ["REQ", "<subid>", <filter>, ...]
//! client -> relay:  ["CLOSE", "<subid>"]
//! relay  -> client: ["EVENT", "<subid>", <event>]
//! relay  -> client: ["OK", "<event_id>", <bool>, "<reason>"]
//! relay  -> client: ["EOSE", "<subid>"]
//! relay  -> client: ["NOTICE", "<message>"]
//! ```
//!
//! # Concurrency model
//!
//! Each call to [`NostrRelayChannel::publish`] / [`NostrRelayChannel::fetch`]
//! opens a **fresh** WebSocket connection, completes the operation, and
//! tears it down. This trades per-call latency (~1 extra round-trip for
//! the handshake) for a dramatically simpler error model - no shared
//! connection state to manage, no read/write task coordination, no
//! reconnection state machine. A persistent-connection variant
//! (`NostrRelayClient::connected`) can be a v0.2 optimization if profiling
//! shows latency cost is material.
//!
//! # Trust boundary
//!
//! The relay is **untrusted for content** but **metadata-trusted for
//! reachability**. Every blob returned by `fetch` rides the same end-to-end
//! verification pipeline as any other channel (`seal::open` + operator
//! signature), so a relay cannot forge Mirage announcements. It CAN, however,
//! observe *who fetches what*: `fetch` opens a fresh WSS directly from the
//! client's real IP (discovery runs before any tunnel exists), so a
//! censor-run or subpoenaed relay records `(client_IP -> subscription)`. A
//! censor holding any invite for operator O can derive O's per-epoch
//! rendezvous, so a subscription keyed on the exact rendezvous would confirm
//! "this IP is a Mirage user of O this epoch" (finding #17).
//!
//! Two mitigations:
//!
//! - **Coarse fetch (implemented).** `fetch` filters only on the per-epoch
//!   `kinds` bucket and matches the exact `info_hash` locally, so the relay
//!   never learns WHICH rendezvous the client wanted - only that it pulled a
//!   1-in-10000 bucket shared by many unrelated NIP-33 apps.
//! - **Route discovery through a circumvention transport / Tor (recommended,
//!   stronger).** The coarse fetch hides the exact rendezvous but not the
//!   client IP or the fact of a Mirage-shaped subscription. A directly
//!   reachable relay remains a metadata-trusted party; the robust fix is to
//!   route the discovery fetch itself over a circumvention transport (or Tor)
//!   so the relay never sees the real client IP. That is a larger change than
//!   this module makes today and is documented here as the recommended
//!   deployment posture.
//!
//! # Security notes
//!
//! - We build sealed payloads into NIP-01 events using
//!   [`crate::wrap::build_announcement_event`], which binds the
//!   published ciphertext into the event ID via SHA-256. A relay cannot
//!   rewrite `content` without invalidating the signature.
//! - On `fetch`, we enforce the [`DiscoveryChannel::publish`] 4 KiB cap
//!   AND the [`crate::wrap::MAX_CONTENT_LEN`] 2 KiB cap on returned
//!   events, so a relay that streams gigabytes of junk cannot OOM us.
//! - The WebSocket client is built with rustls + webpki-roots. Operators
//!   publishing from a hostile network should combine this with DoT/DoH
//!   or a circumvention transport for the name lookup itself.

use std::time::Duration;

use async_trait::async_trait;
use futures::{SinkExt, StreamExt};
use mirage_discovery::{
    channel::{ChannelError, DiscoveryChannel, MAX_PUBLISH_BYTES},
    derive::INFO_HASH_LEN,
};
use serde_json::{json, Value};
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::{self, protocol::WebSocketConfig, Message};
use tracing::{debug, trace, warn};

use crate::{
    event::NostrEvent,
    signing::NostrSigningKey,
    wrap::{build_announcement_event, unpack_announcement_event, MAX_CONTENT_LEN, TAG_D},
};

/// Default per-operation deadline. Relays are geographically diverse;
/// 10 seconds is generous without being a `DoS` window.
pub const DEFAULT_IO_TIMEOUT_MS: u64 = 10_000;

/// Bound on the number of events we'll accept in a single `fetch`. A
/// compliant relay returns tens at most; this cap stops an adversarial
/// relay from streaming indefinitely.
pub const DEFAULT_FETCH_EVENT_CAP: usize = 64;

/// Bound on the total WebSocket frame bytes we'll read per fetch.
/// ~256 KiB is generous for `DEFAULT_FETCH_EVENT_CAP` * 2 KiB content
/// + JSON overhead, while still closing fast on runaway relays.
pub const DEFAULT_FETCH_BYTE_CAP: usize = 256 * 1024;

/// Configuration for a [`NostrRelayChannel`].
#[derive(Debug, Clone)]
pub struct NostrRelayConfig {
    /// `wss://...` (production) or `ws://...` (test/localhost). URL is
    /// validated at channel construction via the `url` crate.
    pub url: String,
    /// Static name used for diagnostics and router metrics. Typically
    /// the hostname of the relay.
    pub name: &'static str,
    /// Per-operation deadline. Applied around the whole publish/fetch
    /// cycle, including the WebSocket handshake.
    pub io_timeout: Duration,
    /// Maximum events per fetch. An adversarial relay that tries to
    /// stream more is cut off and its results truncated.
    pub fetch_event_cap: usize,
    /// Maximum total WebSocket frame bytes per fetch. Second line of
    /// defense against a relay flooding us.
    pub fetch_byte_cap: usize,
    /// Optional: include this `created_at` lower bound in the filter
    /// (`since` in NIP-01). Useful to avoid pulling historical events
    /// a client no longer cares about.
    pub created_at_since: Option<u64>,
    /// Optional explicit `expires_at` to set on published events. If
    /// `None`, publisher uses `created_at + 3600` (one epoch).
    pub default_event_ttl_secs: Option<u64>,
}

impl NostrRelayConfig {
    /// Construct a config with sensible defaults for a given URL and name.
    pub fn new(url: impl Into<String>, name: &'static str) -> Self {
        Self {
            url: url.into(),
            name,
            io_timeout: Duration::from_millis(DEFAULT_IO_TIMEOUT_MS),
            fetch_event_cap: DEFAULT_FETCH_EVENT_CAP,
            fetch_byte_cap: DEFAULT_FETCH_BYTE_CAP,
            created_at_since: None,
            default_event_ttl_secs: None,
        }
    }
}

/// `DiscoveryChannel` implementation backed by a Nostr WebSocket relay.
///
/// Holds the relay configuration and a Schnorr signing key. Each
/// published event is signed with this key; the key is a disposable
/// operator Nostr identity -
/// compromise only costs attribution of publishes, not transport or
/// session security.
pub struct NostrRelayChannel {
    config: NostrRelayConfig,
    signing_key: NostrSigningKey,
    parsed_url: url::Url,
    /// When `Some`, each publish is signed by a Schnorr key derived
    /// per-rendezvous from `(epoch_secret, info_hash)` instead of the fixed
    /// `signing_key`. This closes red-team HIGH #8: a static author pubkey lets
    /// one Nostr `authors` filter enumerate an operator's entire rendezvous
    /// history. The client fetch path filters only on `kinds`+`#d` (never
    /// `authors`), so per-epoch rotation is fully transparent.
    ///
    /// The base is an **operator-held secret**, NOT the invite's `shared_salt`
    /// (audit CRIT #17/#18, applied consistently with the DHT channel's blinded
    /// keys in `mirage_discovery_dht::blinded`): were it the invite salt, every
    /// cohort member could derive this signing key and forge / pollute the
    /// operator's Nostr rendezvous. Deriving from an operator secret keeps
    /// write authority with the operator while leaving read (which needs no
    /// author key) fully open to invite-holders.
    epoch_secret: Option<[u8; 32]>,
    /// When `Some`, the cohort `shared_salt` used to mask the NIP-44 frame's
    /// length prefix (red-team). Both publisher and invite-holding fetcher hold
    /// `shared_salt`, so both derive the same mask; a relay scraper without the
    /// invite cannot, so it cannot run the length-consistency test that would
    /// otherwise enumerate Mirage announcements. `None` = legacy (cleartext
    /// length; back-compat with pre-fix events).
    frame_key: Option<[u8; 32]>,
}

impl NostrRelayChannel {
    /// Construct a channel. Validates the URL and that its scheme is
    /// `ws` or `wss`; rejects anything else.
    pub fn new(
        config: NostrRelayConfig,
        signing_key: NostrSigningKey,
    ) -> Result<Self, ChannelError> {
        let parsed = url::Url::parse(&config.url)
            .map_err(|_| ChannelError::Invalid("unparseable relay URL"))?;
        match parsed.scheme() {
            "ws" | "wss" => {}
            _ => return Err(ChannelError::Invalid("relay URL scheme must be ws or wss")),
        }
        Ok(Self {
            config,
            signing_key,
            parsed_url: parsed,
            epoch_secret: None,
            frame_key: None,
        })
    }

    /// Sign each publish with a per-rendezvous key derived from an
    /// **operator-held secret** and the publish's `info_hash`, so the author
    /// pubkey rotates every epoch and is unlinkable across epochs to anyone
    /// without the secret. Operators SHOULD use this on the publish path
    /// (red-team HIGH #8). The base MUST be operator-secret, not the invite
    /// `shared_salt`, so invite-holders cannot derive it and forge publishes
    /// (audit CRIT #17/#18).
    #[must_use]
    pub fn with_epoch_secret(mut self, operator_secret: [u8; 32]) -> Self {
        self.epoch_secret = Some(operator_secret);
        self
    }

    /// Set the cohort `shared_salt` used to mask the NIP-44 frame length so a
    /// relay scraper cannot enumerate Mirage announcements (red-team). Both the
    /// publisher and invite-holding fetchers hold `shared_salt`, so both mask and
    /// unmask identically.
    #[must_use]
    pub fn with_frame_salt(mut self, shared_salt: [u8; 32]) -> Self {
        self.frame_key = Some(shared_salt);
        self
    }

    /// The signing key for one publish: a per-epoch key derived from
    /// `(epoch_secret, info_hash)` when a secret is configured, else the fixed
    /// key.
    fn key_for(&self, info_hash: &[u8; INFO_HASH_LEN]) -> NostrSigningKey {
        if let Some(secret) = self.epoch_secret {
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            // v2: base is an operator secret (was the invite salt in v1, which
            // let any cohort member forge author keys - audit CRIT #17/#18).
            h.update(b"mirage nostr per-epoch key v2\0");
            h.update(secret);
            h.update(info_hash);
            let seed: [u8; 32] = h.finalize().into();
            // A near-impossible invalid secp256k1 scalar falls back to the fixed
            // key rather than failing the publish.
            if let Ok(k) = NostrSigningKey::from_seed(&seed) {
                return k;
            }
        }
        self.signing_key.clone()
    }

    async fn connect(
        &self,
    ) -> Result<
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
        ChannelError,
    > {
        let cfg = WebSocketConfig::default()
            // 1 MiB per-message cap. Our largest expected message is
            // ~1 KiB announcement + JSON framing; 1 MiB leaves generous
            // headroom while preventing a relay from shoving a huge
            // frame into our buffer.
            .max_message_size(Some(1 << 20))
            .max_frame_size(Some(1 << 20));
        // `disable_nagle = true`: we send small WebSocket frames (~1 KiB
        // each) in a one-shot publish/fetch pattern. Nagle's algorithm
        // adds up to ~40ms buffering waiting for more data that never
        // comes. Disable it so each frame ships immediately.
        let (ws, _resp) =
            tokio_tungstenite::connect_async_with_config(self.parsed_url.as_str(), Some(cfg), true)
                .await
                .map_err(|e| ChannelError::Transport(format!("ws connect: {e}")))?;
        Ok(ws)
    }

    fn build_event(
        &self,
        info_hash: &[u8; INFO_HASH_LEN],
        ciphertext: &[u8],
    ) -> Result<NostrEvent, ChannelError> {
        let created_at = now_unix_secs();
        // Jitter the NIP-40 expiration by up to +30 min so a relay scraper can't
        // key on a fixed created_at+TTL offset (an "hourly cadence" tell -
        // red-team #15). Real clients set varied NIP-40 expirations.
        let jitter = {
            let mut b = [0u8; 2];
            match getrandom::fill(&mut b) {
                Ok(()) => u64::from(u16::from_le_bytes(b)) % 1801, // 0..=1800s
                Err(_) => 0,
            }
        };
        let expires_at = created_at
            .saturating_add(self.config.default_event_ttl_secs.unwrap_or(3_600))
            .saturating_add(jitter);
        build_announcement_event(
            info_hash,
            ciphertext,
            created_at,
            expires_at,
            &self.key_for(info_hash),
            self.frame_key.as_ref(),
        )
        .map_err(|e| ChannelError::Transport(format!("event build: {e}")))
    }
}

fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn gen_sub_id() -> String {
    // 16 random hex chars - plenty unique across the lifetime of a
    // single WebSocket call, and short enough to keep frame sizes low.
    let mut raw = [0u8; 8];
    // `getrandom::fill` is infallible on supported platforms per the
    // crate's docs; on failure we fall back to a zeroed subid, which
    // still works because each connection is fresh.
    let _ = getrandom::fill(&mut raw);
    hex::encode(raw)
}

#[async_trait]
impl DiscoveryChannel for NostrRelayChannel {
    async fn publish(
        &self,
        info_hash: &[u8; INFO_HASH_LEN],
        ciphertext: &[u8],
    ) -> Result<(), ChannelError> {
        if ciphertext.len() > MAX_PUBLISH_BYTES {
            return Err(ChannelError::Invalid("ciphertext exceeds publish cap"));
        }
        let event = self.build_event(info_hash, ciphertext)?;
        let event_id = event.id.clone();

        let wire = json!(["EVENT", event]);
        let frame = Message::Text(wire.to_string().into());

        let io = async {
            let mut ws = self.connect().await?;
            ws.send(frame)
                .await
                .map_err(|e| ChannelError::Transport(format!("ws send: {e}")))?;

            // Wait for OK ack. Many relays send immediately; some don't
            // ack for replaceable events. We bound the wait and treat
            // a close-without-OK as success (message reached the relay).
            while let Some(msg) = ws.next().await {
                let msg = match msg {
                    Ok(m) => m,
                    Err(e) => {
                        return Err(ChannelError::Transport(format!("ws recv: {e}")));
                    }
                };
                match msg {
                    Message::Text(t) => {
                        if let Some(outcome) = parse_ok_frame(&t, &event_id) {
                            return outcome;
                        }
                        // Ignore NOTICE and other frames; keep listening
                        // briefly for the OK.
                        trace!(target: "mirage_discovery_nostr", text = %t, "relay non-OK frame");
                    }
                    Message::Close(_) => {
                        break;
                    }
                    Message::Ping(p) => {
                        let _ = ws.send(Message::Pong(p)).await;
                    }
                    // NIP-01 is text; ignore Binary and any other frames.
                    _ => {}
                }
            }
            // No definitive OK before the socket closed. Many relays
            // behave this way on parametric-replaceable events. We
            // treat it as success; the client will notice via fetch
            // if the event actually didn't land. This path masks
            // black-hole / censor relays - the router's fan-out to
            // multiple channels is the mitigation.
            warn!(
                target: "mirage_discovery_nostr",
                relay = self.config.name,
                "publish: relay closed without OK ack; treating as success (possible black-hole)"
            );
            Ok(())
        };

        timeout(self.config.io_timeout, io)
            .await
            .map_err(|_| ChannelError::Timeout(self.config.io_timeout.as_millis() as u64))?
    }

    async fn fetch(&self, info_hash: &[u8; INFO_HASH_LEN]) -> Result<Vec<Vec<u8>>, ChannelError> {
        let sub_id = gen_sub_id();

        let epoch_kind = crate::event::mirage_event_kind(info_hash);
        // Finding #17: fetch a COARSE superset. Filter ONLY on the per-epoch
        // `kinds` bucket - NOT on the exact `#d` rendezvous - and match the
        // info_hash LOCALLY after download (the `unpacked.info_hash == info_hash`
        // check below). A hostile / subpoenaed relay then learns only that this
        // IP subscribed to a 1-in-10000 kind bucket (shared by many unrelated
        // NIP-33 apps), not the exact rendezvous the client wanted - so it cannot
        // confirm "this IP is a Mirage user of operator O this epoch". The
        // `kinds` filter is retained to bound download volume.
        let mut filter = json!({
            "kinds": [epoch_kind],
            "limit": self.config.fetch_event_cap,
        });
        if let Some(since) = self.config.created_at_since {
            filter
                .as_object_mut()
                .expect("filter is object")
                .insert("since".into(), json!(since));
        }
        let req = Message::Text(json!(["REQ", &sub_id, filter]).to_string().into());
        let close = Message::Text(json!(["CLOSE", &sub_id]).to_string().into());

        let cap_events = self.config.fetch_event_cap;
        let cap_bytes = self.config.fetch_byte_cap;

        let io = async move {
            let mut ws = self.connect().await?;
            ws.send(req)
                .await
                .map_err(|e| ChannelError::Transport(format!("ws send REQ: {e}")))?;

            let mut blobs: Vec<Vec<u8>> = Vec::new();
            let mut byte_budget = cap_bytes;
            while let Some(msg) = ws.next().await {
                let msg = msg.map_err(|e| ChannelError::Transport(format!("ws recv: {e}")))?;
                match msg {
                    Message::Text(t) => {
                        if t.len() > byte_budget {
                            warn!(
                                target: "mirage_discovery_nostr",
                                bytes = t.len(),
                                remaining = byte_budget,
                                "fetch byte cap exhausted; truncating"
                            );
                            break;
                        }
                        byte_budget -= t.len();
                        match classify_frame(&t, &sub_id, epoch_kind) {
                            RelayFrame::Event(event) => {
                                if blobs.len() >= cap_events {
                                    break;
                                }
                                match unpack_announcement_event(&event, self.frame_key.as_ref()) {
                                    Ok(unpacked) => {
                                        // Defense in depth: make sure the
                                        // relay isn't returning events for
                                        // a different info_hash than we asked.
                                        if &unpacked.info_hash == info_hash {
                                            blobs.push(unpacked.ciphertext);
                                        } else {
                                            warn!(
                                                target: "mirage_discovery_nostr",
                                                "relay returned event with wrong d-tag; dropping"
                                            );
                                        }
                                    }
                                    Err(e) => {
                                        trace!(
                                            target: "mirage_discovery_nostr",
                                            error = %e,
                                            "event failed unpack; dropping"
                                        );
                                    }
                                }
                            }
                            RelayFrame::EndOfStoredEvents => break,
                            // Not our subscription, a NOTICE, or unparseable: ignore.
                            RelayFrame::OtherSub
                            | RelayFrame::Notice
                            | RelayFrame::Unrecognized => {}
                        }
                    }
                    Message::Close(_) => break,
                    Message::Ping(p) => {
                        let _ = ws.send(Message::Pong(p)).await;
                    }
                    _ => {}
                }
            }
            let _ = ws.send(close).await;
            Ok(blobs)
        };

        timeout(self.config.io_timeout, io)
            .await
            .map_err(|_| ChannelError::Timeout(self.config.io_timeout.as_millis() as u64))?
    }

    fn name(&self) -> &'static str {
        self.config.name
    }
}

/// Result of parsing an `OK` frame addressed to our event.
///
/// Returns `None` if the frame is not `OK` for `event_id`; the caller
/// keeps listening.
fn parse_ok_frame(text: &str, event_id: &str) -> Option<Result<(), ChannelError>> {
    let v: Value = serde_json::from_str(text).ok()?;
    let arr = v.as_array()?;
    if arr.first()?.as_str()? != "OK" {
        return None;
    }
    if arr.get(1)?.as_str()? != event_id {
        return None;
    }
    let accepted = arr.get(2).and_then(Value::as_bool).unwrap_or(false);
    let reason = arr.get(3).and_then(Value::as_str).unwrap_or("");
    if accepted {
        Some(Ok(()))
    } else {
        Some(Err(ChannelError::Refused(format!("relay: {reason}"))))
    }
}

/// Kinds of frames we get back on a subscription.
enum RelayFrame {
    Event(NostrEvent),
    EndOfStoredEvents,
    OtherSub,
    /// Relay sent a NOTICE. Traced at debug for operator visibility but
    /// we don't act on the message body.
    Notice,
    Unrecognized,
}

fn classify_frame(text: &str, our_sub_id: &str, expected_kind: u64) -> RelayFrame {
    let v: Value = match serde_json::from_str(text) {
        Ok(v) => v,
        Err(_) => return RelayFrame::Unrecognized,
    };
    let Some(arr) = v.as_array() else {
        return RelayFrame::Unrecognized;
    };
    let Some(tag) = arr.first().and_then(Value::as_str) else {
        return RelayFrame::Unrecognized;
    };
    match tag {
        "EVENT" => {
            let Some(sub_id) = arr.get(1).and_then(Value::as_str) else {
                return RelayFrame::Unrecognized;
            };
            if sub_id != our_sub_id {
                return RelayFrame::OtherSub;
            }
            let Some(event_value) = arr.get(2) else {
                return RelayFrame::Unrecognized;
            };
            match serde_json::from_value::<NostrEvent>(event_value.clone()) {
                Ok(e) => {
                    // Sanity: drop events from the wrong (per-epoch derived)
                    // kind before we even hand them to the slower unpacker.
                    if e.kind != expected_kind {
                        return RelayFrame::Unrecognized;
                    }
                    // Sanity: must have a `d` tag. (unpack re-verifies.)
                    if !e
                        .tags
                        .iter()
                        .any(|t| t.first().map(String::as_str) == Some(TAG_D))
                    {
                        return RelayFrame::Unrecognized;
                    }
                    RelayFrame::Event(e)
                }
                Err(_) => RelayFrame::Unrecognized,
            }
        }
        "EOSE" => {
            if arr.get(1).and_then(Value::as_str) == Some(our_sub_id) {
                RelayFrame::EndOfStoredEvents
            } else {
                RelayFrame::OtherSub
            }
        }
        "NOTICE" => {
            if let Some(msg) = arr.get(1).and_then(Value::as_str) {
                debug!(target: "mirage_discovery_nostr", message = %msg, "relay NOTICE");
            }
            RelayFrame::Notice
        }
        _ => RelayFrame::Unrecognized,
    }
}

/// Silence unused-import warnings when feature is built headlessly.
#[allow(dead_code)]
fn _ensure_used() {
    let _ = MAX_CONTENT_LEN;
    let _: tungstenite::Error;
}

// Tests: in-process mock relay

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tokio::net::TcpListener;

    /// In-process NIP-01 relay. Holds events keyed by the `d` tag,
    /// responds to REQ with matching events followed by EOSE, accepts
    /// EVENT with an OK ack. Compliant with the minimal subset of
    /// NIP-01 we exercise; not production-ready.
    struct MockRelay {
        addr: String,
        store: Arc<Mutex<std::collections::HashMap<String, Vec<NostrEvent>>>>,
    }

    impl MockRelay {
        async fn spawn() -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = format!("ws://{}", listener.local_addr().unwrap());
            let store: Arc<Mutex<std::collections::HashMap<String, Vec<NostrEvent>>>> =
                Arc::new(Mutex::new(std::collections::HashMap::new()));
            let store_c = Arc::clone(&store);
            tokio::spawn(async move {
                loop {
                    let (sock, _) = match listener.accept().await {
                        Ok(v) => v,
                        Err(_) => break,
                    };
                    let store = Arc::clone(&store_c);
                    tokio::spawn(async move {
                        let ws = match tokio_tungstenite::accept_async(sock).await {
                            Ok(w) => w,
                            Err(_) => return,
                        };
                        handle_connection(ws, store).await;
                    });
                }
            });
            Self { addr, store }
        }

        fn stored_events_for(&self, d_tag: &str) -> usize {
            self.store
                .lock()
                .ok()
                .and_then(|g| g.get(d_tag).map(Vec::len))
                .unwrap_or(0)
        }
    }

    async fn handle_connection(
        mut ws: tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>,
        store: Arc<Mutex<std::collections::HashMap<String, Vec<NostrEvent>>>>,
    ) {
        while let Some(msg) = ws.next().await {
            let msg = match msg {
                Ok(m) => m,
                Err(_) => break,
            };
            let text = match msg {
                Message::Text(t) => t,
                Message::Close(_) => break,
                Message::Ping(p) => {
                    let _ = ws.send(Message::Pong(p)).await;
                    continue;
                }
                _ => continue,
            };
            let v: Value = match serde_json::from_str(&text) {
                Ok(v) => v,
                Err(_) => continue,
            };
            let arr = match v.as_array() {
                Some(a) => a,
                None => continue,
            };
            let tag = arr.first().and_then(Value::as_str).unwrap_or_default();
            match tag {
                "EVENT" => {
                    let event_val = match arr.get(1) {
                        Some(v) => v,
                        None => continue,
                    };
                    let event: NostrEvent = match serde_json::from_value(event_val.clone()) {
                        Ok(e) => e,
                        Err(_) => continue,
                    };
                    let d = event
                        .tags
                        .iter()
                        .find(|t| t.first().map(String::as_str) == Some(TAG_D))
                        .and_then(|t| t.get(1))
                        .cloned()
                        .unwrap_or_default();
                    {
                        let mut guard = store.lock().unwrap();
                        guard.entry(d).or_default().push(event.clone());
                    }
                    let ok = json!(["OK", event.id, true, ""]);
                    let _ = ws.send(Message::Text(ok.to_string().into())).await;
                }
                "REQ" => {
                    let sub_id = arr.get(1).and_then(Value::as_str).unwrap_or_default();
                    let filter = match arr.get(2) {
                        Some(v) => v,
                        None => continue,
                    };
                    // Support both the coarse `kinds`-only fetch the Mirage
                    // client now sends (finding #17) and an optional `#d`
                    // filter: return every stored event matching whichever
                    // filters are present, so the client can select the
                    // rendezvous locally.
                    let kinds: Option<Vec<u64>> = filter
                        .get("kinds")
                        .and_then(Value::as_array)
                        .map(|a| a.iter().filter_map(Value::as_u64).collect());
                    let d_filter: Option<String> = filter
                        .get("#d")
                        .and_then(Value::as_array)
                        .and_then(|a| a.first())
                        .and_then(Value::as_str)
                        .map(str::to_string);
                    let all: Vec<NostrEvent> = store
                        .lock()
                        .ok()
                        .map(|g| g.values().flatten().cloned().collect())
                        .unwrap_or_default();
                    for ev in all {
                        if let Some(ks) = &kinds {
                            if !ks.contains(&ev.kind) {
                                continue;
                            }
                        }
                        if let Some(d) = &d_filter {
                            let evd = ev
                                .tags
                                .iter()
                                .find(|t| t.first().map(String::as_str) == Some(TAG_D))
                                .and_then(|t| t.get(1))
                                .cloned()
                                .unwrap_or_default();
                            if &evd != d {
                                continue;
                            }
                        }
                        let frame = json!(["EVENT", sub_id, ev]);
                        if ws
                            .send(Message::Text(frame.to_string().into()))
                            .await
                            .is_err()
                        {
                            return;
                        }
                    }
                    let eose = json!(["EOSE", sub_id]);
                    let _ = ws.send(Message::Text(eose.to_string().into())).await;
                }
                "CLOSE" => { /* nothing to clean up */ }
                _ => {}
            }
        }
    }

    fn ih(n: u8) -> [u8; INFO_HASH_LEN] {
        [n; INFO_HASH_LEN]
    }

    fn sk() -> NostrSigningKey {
        NostrSigningKey::from_seed(&[0x42u8; 32]).unwrap()
    }

    #[test]
    fn epoch_secret_rotates_author_pubkey_per_info_hash() {
        // red-team HIGH #8: with an operator secret, the signing key (hence
        // author pubkey) is derived per info_hash, so it rotates every epoch and
        // is deterministic for a given (secret, info_hash).
        let base = NostrRelayChannel::new(NostrRelayConfig::new("wss://r", "n"), sk()).unwrap();
        let salted = NostrRelayChannel::new(NostrRelayConfig::new("wss://r", "n"), sk())
            .unwrap()
            .with_epoch_secret([0x7u8; 32]);

        // No secret => fixed key regardless of info_hash.
        assert_eq!(
            base.key_for(&ih(1)).verifying_key_bytes(),
            base.key_for(&ih(2)).verifying_key_bytes()
        );
        // Secret => distinct pubkey per epoch/info_hash...
        let a = salted.key_for(&ih(1)).verifying_key_bytes();
        let b = salted.key_for(&ih(2)).verifying_key_bytes();
        assert_ne!(a, b, "author pubkey must rotate across epochs");
        // ...deterministic for the same (secret, info_hash) so a re-publish keeps
        // the same author within an epoch (fetch never filters on author anyway).
        assert_eq!(a, salted.key_for(&ih(1)).verifying_key_bytes());
        // ...and unrelated to the fixed fallback key.
        assert_ne!(a, base.key_for(&ih(1)).verifying_key_bytes());
    }

    #[tokio::test]
    async fn publish_and_fetch_roundtrip_through_mock_relay() {
        let relay = MockRelay::spawn().await;
        let cfg = NostrRelayConfig {
            io_timeout: Duration::from_secs(3),
            ..NostrRelayConfig::new(&relay.addr, "mock")
        };
        let ch = NostrRelayChannel::new(cfg, sk()).unwrap();

        ch.publish(&ih(1), b"hello").await.unwrap();
        // Give the mock relay a beat to store.
        assert_eq!(relay.stored_events_for(&hex::encode(ih(1))), 1);

        let blobs = ch.fetch(&ih(1)).await.unwrap();
        assert_eq!(blobs, vec![b"hello".to_vec()]);
    }

    #[tokio::test]
    async fn fetch_for_unknown_info_hash_returns_empty() {
        let relay = MockRelay::spawn().await;
        let ch = NostrRelayChannel::new(
            NostrRelayConfig {
                io_timeout: Duration::from_secs(3),
                ..NostrRelayConfig::new(&relay.addr, "mock")
            },
            sk(),
        )
        .unwrap();
        let blobs = ch.fetch(&ih(99)).await.unwrap();
        assert!(blobs.is_empty());
    }

    /// Two distinct `info_hashes` that map to the SAME per-epoch `kinds` bucket,
    /// so a coarse `kinds`-only fetch (finding #17) returns BOTH as one bucket
    /// and the client must select the right rendezvous locally.
    fn colliding_kind_pair() -> ([u8; INFO_HASH_LEN], [u8; INFO_HASH_LEN]) {
        let base = ih(1);
        let k0 = crate::event::mirage_event_kind(&base);
        for n in 2u32..=u32::MAX {
            let mut cand = [0u8; INFO_HASH_LEN];
            cand[..4].copy_from_slice(&n.to_le_bytes());
            if cand != base && crate::event::mirage_event_kind(&cand) == k0 {
                return (base, cand);
            }
        }
        unreachable!("a kind collision must exist within 2^32 candidates over 10000 buckets");
    }

    #[tokio::test]
    async fn coarse_fetch_matches_rendezvous_locally_in_shared_bucket() {
        // Finding #17: the relay returns the whole per-epoch kind BUCKET (no `#d`
        // filter). When two rendezvous share a bucket, the client must still
        // return only the exact rendezvous it asked for, matched locally.
        let (a, b) = colliding_kind_pair();
        assert_eq!(
            crate::event::mirage_event_kind(&a),
            crate::event::mirage_event_kind(&b),
            "test setup: the pair must share a kind bucket"
        );

        let relay = MockRelay::spawn().await;
        let ch = NostrRelayChannel::new(
            NostrRelayConfig {
                io_timeout: Duration::from_secs(3),
                ..NostrRelayConfig::new(&relay.addr, "mock")
            },
            sk(),
        )
        .unwrap();

        ch.publish(&a, b"alpha").await.unwrap();
        ch.publish(&b, b"beta").await.unwrap();

        // Both events live in the same kind bucket, so the coarse fetch pulls
        // both, but the local info_hash match yields only the requested one.
        assert_eq!(ch.fetch(&a).await.unwrap(), vec![b"alpha".to_vec()]);
        assert_eq!(ch.fetch(&b).await.unwrap(), vec![b"beta".to_vec()]);
    }

    #[tokio::test]
    async fn multiple_publishes_different_info_hashes_are_independent() {
        let relay = MockRelay::spawn().await;
        let ch = NostrRelayChannel::new(
            NostrRelayConfig {
                io_timeout: Duration::from_secs(3),
                ..NostrRelayConfig::new(&relay.addr, "mock")
            },
            sk(),
        )
        .unwrap();
        ch.publish(&ih(1), b"a").await.unwrap();
        ch.publish(&ih(2), b"b").await.unwrap();
        assert_eq!(ch.fetch(&ih(1)).await.unwrap(), vec![b"a".to_vec()]);
        assert_eq!(ch.fetch(&ih(2)).await.unwrap(), vec![b"b".to_vec()]);
    }

    #[tokio::test]
    async fn publish_rejects_oversized_ciphertext_locally() {
        let relay = MockRelay::spawn().await;
        let ch = NostrRelayChannel::new(NostrRelayConfig::new(&relay.addr, "mock"), sk()).unwrap();
        let huge = vec![0u8; MAX_PUBLISH_BYTES + 1];
        match ch.publish(&ih(1), &huge).await {
            Err(ChannelError::Invalid(_)) => {}
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn invalid_relay_url_is_rejected_at_construction() {
        let err = NostrRelayChannel::new(NostrRelayConfig::new("http://example.com", "mock"), sk())
            .map(|_| ())
            .expect_err("expected Err");
        assert!(matches!(err, ChannelError::Invalid(_)));
    }

    #[tokio::test]
    async fn unparseable_url_is_rejected_at_construction() {
        let err = NostrRelayChannel::new(NostrRelayConfig::new("not a url at all", "mock"), sk())
            .map(|_| ())
            .expect_err("expected Err");
        assert!(matches!(err, ChannelError::Invalid(_)));
    }

    #[tokio::test]
    async fn connect_timeout_on_unreachable_host() {
        // RFC 5737 TEST-NET-1 addresses must not be routable.
        let cfg = NostrRelayConfig {
            io_timeout: Duration::from_millis(150),
            ..NostrRelayConfig::new("ws://192.0.2.1:9/", "unreachable")
        };
        let ch = NostrRelayChannel::new(cfg, sk()).unwrap();
        // Either we hit ConnRefused immediately (Transport) or the
        // 150ms deadline hits first (Timeout). Both are acceptable.
        let err = ch.fetch(&ih(1)).await.unwrap_err();
        assert!(matches!(
            err,
            ChannelError::Timeout(_) | ChannelError::Transport(_)
        ));
    }
}
