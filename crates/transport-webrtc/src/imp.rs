//! Real WebRTC data-channel implementation (feature `webrtc`).
//!
//! Turns a `webrtc-rs` reliable/ordered data channel into a plain
//! `AsyncRead + AsyncWrite` byte pipe ([`WebRtcStream`]) and provides the two
//! ends of the connection - [`webrtc_dial`] (offerer / client) and
//! [`webrtc_answer`] (answerer / bridge) - plus a [`Signaling`] seam for the
//! SDP offer/answer exchange.
//!
//! The channel is message-oriented under the hood; [`WebRtcStream`] concatenates
//! inbound messages into a byte stream and chops outbound writes to the SCTP
//! message ceiling, so the Mirage session layer above just sees a socket. The
//! plumbing (mpsc + a send driver + `on_message` push) mirrors the meek carrier's
//! stream driver.

use std::collections::VecDeque;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, Notify};

use webrtc::api::interceptor_registry::register_default_interceptors;
use webrtc::api::media_engine::MediaEngine;
use webrtc::api::setting_engine::SettingEngine;
use webrtc::api::{APIBuilder, API};
use webrtc::data_channel::data_channel_message::DataChannelMessage;
use webrtc::data_channel::RTCDataChannel;
use webrtc::dtls::extension::extension_use_srtp::SrtpProtectionProfile;
use webrtc::dtls_transport::dtls_role::DTLSRole;
use webrtc::ice_transport::ice_server::RTCIceServer;
use webrtc::interceptor::registry::Registry;
use webrtc::peer_connection::configuration::RTCConfiguration;
use webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;
use webrtc::peer_connection::RTCPeerConnection;

/// Default STUN server used when no ICE servers are configured. A bridge with a
/// public IP can often connect on host candidates alone and drop even this.
pub const DEFAULT_STUN_SERVER: &str = "stun:stun.l.google.com:19302";

/// Largest chunk written to the data channel in one SCTP message. Well under the
/// negotiated max-message-size ceiling; larger session writes are split.
const MAX_MESSAGE: usize = 16 * 1024;

/// Errors from the WebRTC transport.
#[derive(Debug, thiserror::Error)]
pub enum WebRtcError {
    /// Underlying `webrtc-rs` error.
    #[error("webrtc: {0}")]
    Rtc(#[from] webrtc::Error),
    /// Signaling exchange failed (broker unreachable, rejected, malformed).
    #[error("signaling: {0}")]
    Signaling(String),
    /// The peer connection produced no local description.
    #[error("no local description")]
    NoLocalDescription,
    /// The connection failed or closed before the data channel opened.
    #[error("connection failed before data channel opened")]
    ConnectionFailed,
    /// The data channel did not open within the deadline.
    #[error("timed out waiting for data channel")]
    Timeout,
}

/// SDP offer/answer rendezvous. The client hands its offer to `exchange` and
/// gets the bridge's answer back; the implementation owns the transport (a
/// CDN-fronted HTTPS broker, a Mirage discovery channel, anything).
#[async_trait]
pub trait Signaling: Send + Sync {
    /// Send `offer_sdp`, return the peer's answer SDP.
    async fn exchange(&self, offer_sdp: String) -> Result<String, WebRtcError>;
}

/// Open/failed gate shared between the connection callbacks and the waiters.
#[derive(Default)]
struct Gate {
    opened: AtomicBool,
    failed: AtomicBool,
    notify: Notify,
}

impl Gate {
    fn mark_open(&self) {
        self.opened.store(true, Ordering::SeqCst);
        self.notify.notify_waiters();
    }
    fn mark_failed(&self) {
        self.failed.store(true, Ordering::SeqCst);
        self.notify.notify_waiters();
    }
    /// Wait until the channel opens (Ok) or the connection fails (Err),
    /// bounded by `deadline`.
    async fn wait_open(&self, deadline: Duration) -> Result<(), WebRtcError> {
        let wait = async {
            loop {
                // Register interest BEFORE checking, so a mark_* between the
                // check and the await is never lost.
                let notified = self.notify.notified();
                if self.opened.load(Ordering::SeqCst) {
                    return Ok(());
                }
                if self.failed.load(Ordering::SeqCst) {
                    return Err(WebRtcError::ConnectionFailed);
                }
                notified.await;
            }
        };
        tokio::time::timeout(deadline, wait)
            .await
            .map_err(|_| WebRtcError::Timeout)?
    }
}

/// A Mirage session byte-pipe over a WebRTC data channel.
///
/// `AsyncRead + AsyncWrite`. Holds the peer connection alive for the stream's
/// lifetime (dropping it tears the connection down).
pub struct WebRtcStream {
    inbound_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    inbound_buf: VecDeque<u8>,
    outbound_tx: mpsc::UnboundedSender<Vec<u8>>,
    gate: Arc<Gate>,
    _pc: Arc<RTCPeerConnection>,
}

impl WebRtcStream {
    /// Wait for the data channel to finish opening (ICE + DTLS + SCTP up).
    pub async fn wait_open(&self, deadline: Duration) -> Result<(), WebRtcError> {
        self.gate.wait_open(deadline).await
    }
}

/// Wire a freshly-created data channel to a [`WebRtcStream`]: push inbound
/// messages to a channel, spawn a driver that sends outbound writes once the
/// channel opens, and track open/close state on the shared gate.
fn attach_data_channel(pc: Arc<RTCPeerConnection>, dc: &Arc<RTCDataChannel>) -> WebRtcStream {
    let (in_tx, in_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let gate = Arc::new(Gate::default());

    {
        let gate = gate.clone();
        dc.on_open(Box::new(move || {
            let gate = gate.clone();
            Box::pin(async move {
                gate.mark_open();
            })
        }));
    }
    {
        let in_tx = in_tx.clone();
        dc.on_message(Box::new(move |msg: DataChannelMessage| {
            let in_tx = in_tx.clone();
            Box::pin(async move {
                let _ = in_tx.send(msg.data.to_vec());
            })
        }));
    }
    {
        let gate = gate.clone();
        dc.on_close(Box::new(move || {
            let gate = gate.clone();
            Box::pin(async move {
                gate.mark_failed();
            })
        }));
    }
    {
        // A failed/closed/disconnected peer connection must wake any waiter so
        // dial/accept don't hang until the deadline.
        let gate = gate.clone();
        pc.on_peer_connection_state_change(Box::new(move |s: RTCPeerConnectionState| {
            let gate = gate.clone();
            Box::pin(async move {
                if matches!(
                    s,
                    RTCPeerConnectionState::Failed
                        | RTCPeerConnectionState::Closed
                        | RTCPeerConnectionState::Disconnected
                ) {
                    gate.mark_failed();
                }
            })
        }));
    }

    // Send driver: wait for open, then forward outbound writes as SCTP messages.
    {
        let dc = dc.clone();
        let gate = gate.clone();
        tokio::spawn(async move {
            if gate.wait_open(Duration::from_secs(60)).await.is_err() {
                return;
            }
            while let Some(bytes) = out_rx.recv().await {
                for chunk in bytes.chunks(MAX_MESSAGE) {
                    if dc.send(&Bytes::copy_from_slice(chunk)).await.is_err() {
                        gate.mark_failed();
                        return;
                    }
                }
            }
        });
    }

    WebRtcStream {
        inbound_rx: in_rx,
        inbound_buf: VecDeque::new(),
        outbound_tx: out_tx,
        gate,
        _pc: pc,
    }
}

fn rtc_config(ice_servers: &[String]) -> RTCConfiguration {
    // Leak-fix: NO STUN by default. The old default phoned stun.l.google.com,
    // which (a) marks the flow as WebRTC setup to any on-path observer and (b)
    // hands a fixed third party a timestamped record of the client. A bridge
    // with a public IP works on host candidates alone; operators who genuinely
    // need STUN/TURN (NAT-bound bridge) set ice_servers explicitly.
    // Empty ice_servers => host candidates only (no STUN/TURN phone-home).
    let servers = if ice_servers.is_empty() {
        Vec::new()
    } else {
        vec![RTCIceServer {
            urls: ice_servers.to_vec(),
            ..Default::default()
        }]
    };
    RTCConfiguration {
        ice_servers: servers,
        ..Default::default()
    }
}

fn build_api(with_media: bool, dtls_client: bool) -> Result<API, WebRtcError> {
    let mut media = MediaEngine::default();
    if with_media {
        // Register the standard codecs (incl. Opus) so we can negotiate an
        // audio m-line - the connection then profiles as a real call.
        media.register_default_codecs()?;
    }
    let registry = register_default_interceptors(Registry::new(), &mut media)?;

    // Chrome-shaped ICE credentials. webrtc-rs defaults to a 16-char ufrag and
    // 32-char pwd from an alpha-only charset; browsers use a 4-char ufrag and a
    // 24-char pwd from the base64 ICE charset (RFC 5245 `ice-char`). Set fresh
    // per-connection credentials of the browser shape (a fresh API is built per
    // peer connection, so these never repeat across sessions).
    let mut settings = SettingEngine::default();
    settings.set_ice_credentials(gen_ice_string(4), gen_ice_string(24));

    // DTLS-SRTP `use_srtp` profiles: set explicitly (not webrtc-rs's default) so
    // Mirage owns this fingerprint field. Chrome/libwebrtc offers THREE profiles,
    // led by AEAD_AES_256_GCM: `0x0008, 0x0007, 0x0001` (see webrtc-dtls
    // This one list feeds the DTLS `use_srtp` extension in two
    // roles:
    //   * on the DTLS CLIENT it is the ClientHello's *advertised* offer - a wire
    //     fingerprint a censor enumerates (count + order);
    //   * on the DTLS SERVER it is the set the server *selects* from: the first
    //     client-offered profile also present here (dtls::find_matching_srtp).
    //
    // webrtc-srtp 0.13 cannot KEY AES_256_GCM, and webrtc's DtlsTransport::start
    // fails the whole connection (ErrNoSRTPProtectionProfile) if 0x0008 is the
    // *negotiated* profile - even for a bare data channel. So 0x0008 is safe to
    // ADVERTISE but must never be SELECTED. We split this by role (#19):
    //   * the DTLS client advertises all three, byte-matching Chrome's ClientHello;
    //   * the DTLS server offers only the two keyable profiles, so it can only
    //     ever select 0x0007 - 0x0008 is offered-only, never keyed.
    settings.set_srtp_protection_profiles(use_srtp_profiles(dtls_client));

    // Pin the DTLS role so the split above holds deterministically: the answerer
    // (bridge) is the DTLS client - it emits the fingerprinted ClientHello, so it
    // advertises the full 3-profile list; the offerer (dialer) is then the DTLS
    // server and selects a keyable profile. `DTLSRole::Client` matches webrtc-rs's
    // default answer role (setup:active), so this alters no SDP byte in the common
    // case - it just makes the client/server split explicit rather than relying on
    // the implied ICE-role default (#19).
    if dtls_client {
        settings.set_answering_dtls_role(DTLSRole::Client)?;
    }

    Ok(APIBuilder::new()
        .with_media_engine(media)
        .with_interceptor_registry(registry)
        .with_setting_engine(settings)
        .build())
}

/// The DTLS-SRTP `use_srtp` protection profiles this endpoint presents, in the
/// exact order they appear on the wire. The DTLS client and server present
/// different lists on purpose - see [`build_api`]: only the client's list is a
/// `ClientHello` fingerprint, and only the server's list can be *selected* from,
/// so the client advertises Chrome's full three (incl. the unkeyable 0x0008)
/// while the server restricts to the two keyable profiles.
fn use_srtp_profiles(dtls_client: bool) -> Vec<SrtpProtectionProfile> {
    if dtls_client {
        // Chrome/libwebrtc ClientHello order. 0x0008 is advertised only.
        vec![
            SrtpProtectionProfile::Srtp_Aead_Aes_256_Gcm,
            SrtpProtectionProfile::Srtp_Aead_Aes_128_Gcm,
            SrtpProtectionProfile::Srtp_Aes128_Cm_Hmac_Sha1_80,
        ]
    } else {
        // DTLS server: only the KEYABLE profiles, so 0x0008 is never selected.
        vec![
            SrtpProtectionProfile::Srtp_Aead_Aes_128_Gcm,
            SrtpProtectionProfile::Srtp_Aes128_Cm_Hmac_Sha1_80,
        ]
    }
}

/// Generate an `n`-char string over the ICE credential charset (RFC 5245
/// `ice-char = ALPHA / DIGIT / "+" / "/"`) - the base64 alphabet browsers use.
fn gen_ice_string(n: usize) -> String {
    // Exactly 64 chars, so `byte & 0x3F` is an unbiased index (base64 alphabet).
    const ICE_CHARS: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(n);
    let mut buf = vec![0u8; n];
    rand::RngCore::fill_bytes(&mut rand::rng(), &mut buf);
    for b in buf {
        if let Some(&c) = ICE_CHARS.get((b & 0x3F) as usize) {
            out.push(c as char);
        }
    }
    out
}

/// Negotiate an Opus audio track on `pc` and start a paced RTP emitter, so the
/// connection carries real SRTP media alongside the data channel and profiles
/// like a WebRTC voice/video call rather than a lone data channel.
///
/// The samples are comfort-noise-shaped (not real speech) - this closes the
/// *structural* "no media" tell (SDP audio m-line + Opus-paced SRTP at 20 ms);
/// defeating deep audio content analysis is a higher bar we don't claim.
async fn spawn_cover_audio(pc: &Arc<RTCPeerConnection>) -> Result<(), WebRtcError> {
    use webrtc::api::media_engine::MIME_TYPE_OPUS;
    use webrtc::media::Sample;
    use webrtc::rtp_transceiver::rtp_codec::RTCRtpCodecCapability;
    use webrtc::track::track_local::track_local_static_sample::TrackLocalStaticSample;
    use webrtc::track::track_local::TrackLocal;

    let track = Arc::new(TrackLocalStaticSample::new(
        RTCRtpCodecCapability {
            mime_type: MIME_TYPE_OPUS.to_owned(),
            clock_rate: 48_000,
            channels: 2,
            ..Default::default()
        },
        "audio".to_owned(),
        "mirage-webrtc".to_owned(),
    ));

    let rtp_sender = pc
        .add_track(Arc::clone(&track) as Arc<dyn TrackLocal + Send + Sync>)
        .await?;

    // Drain RTCP so the sender keeps flowing; ends when the sender closes.
    tokio::spawn(async move {
        let mut buf = vec![0u8; 1500];
        while rtp_sender.read(&mut buf).await.is_ok() {}
    });

    // Emit ~20 ms Opus frames until the track errors (connection gone). A fixed
    // 40-byte frame on a jitter-free 20 ms clock is a constant-bitrate signature
    // that real Opus never produces: a VBR encoder varies frame size with the
    // signal, DTX emits tiny comfort-noise frames during silence, and real send
    // pacing carries a few ms of jitter. Model all three so the SRTP flow's
    // size/timing distribution profiles like a genuine call rather than a beacon.
    tokio::spawn(async move {
        loop {
            // Draw this frame's size/content/pacing in a scope that ends BEFORE
            // any await - ThreadRng is !Send and must not be held across the
            // await points of this spawned (Send) task.
            let (data, next_ms) = {
                use rand::{Rng, RngCore};
                let mut rng = rand::rng();
                // ~6% DTX/comfort-noise (tiny) frames, else a VBR voice frame
                // whose size spans the range a typical 24-64 kbps Opus encoder
                // produces for a 20 ms frame.
                let size: usize = if rng.random_bool(0.06) {
                    rng.random_range(3..=10)
                } else {
                    rng.random_range(40..=120)
                };
                let mut d = vec![0u8; size];
                // Content is SRTP-encrypted on the wire; randomizing it just
                // avoids a constant plaintext. Size + timing are what a censor sees.
                rng.fill_bytes(&mut d);
                // Pace near 20 ms with small jitter so the cadence has no stable
                // fundamental frequency.
                let n: u64 = rng.random_range(17..=23);
                (d, n)
            };
            let sample = Sample {
                data: Bytes::from(data),
                duration: Duration::from_millis(20),
                ..Default::default()
            };
            if track.write_sample(&sample).await.is_err() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(next_ms)).await;
        }
    });
    Ok(())
}

/// Client side: create the offer, exchange it through `signaling` for the
/// bridge's answer, and return the byte-pipe once the data channel is open.
pub async fn webrtc_dial<S: Signaling + ?Sized>(
    signaling: &S,
    ice_servers: &[String],
    label: &str,
    cover_media: bool,
    deadline: Duration,
) -> Result<WebRtcStream, WebRtcError> {
    // The dialer is the SDP offerer, hence the DTLS server (the answerer takes
    // setup:active / DTLS client). As DTLS server it SELECTS the SRTP profile, so
    // it must offer only keyable profiles - `dtls_client = false` (#19).
    let api = build_api(cover_media, false)?;
    let pc = Arc::new(api.new_peer_connection(rtc_config(ice_servers)).await?);
    let dc = pc.create_data_channel(label, None).await?;
    let stream = attach_data_channel(pc.clone(), &dc);
    if cover_media {
        spawn_cover_audio(&pc).await?;
    }

    let offer = pc.create_offer(None).await?;
    let mut gather = pc.gathering_complete_promise().await;
    pc.set_local_description(offer).await?;
    // Non-trickle: wait for ICE gathering so the offer carries all candidates.
    let _ = tokio::time::timeout(deadline, gather.recv()).await;
    let local = pc
        .local_description()
        .await
        .ok_or(WebRtcError::NoLocalDescription)?;

    let answer_sdp = signaling.exchange(local.sdp).await?;
    let answer = RTCSessionDescription::answer(answer_sdp)?;
    pc.set_remote_description(answer).await?;

    stream.wait_open(deadline).await?;
    Ok(stream)
}

/// Bridge side: consume the client's `offer_sdp`, produce the answer SDP to send
/// back **immediately**, and a [`WebRtcAccept`] to await the data channel (which
/// only opens after the client has the answer and ICE completes).
pub async fn webrtc_answer(
    offer_sdp: String,
    ice_servers: &[String],
    cover_media: bool,
    deadline: Duration,
) -> Result<(String, WebRtcAccept), WebRtcError> {
    // Register codecs whenever cover media may be in play so an audio m-line in
    // the offer is answered properly (not rejected with port 0, which is a tell).
    // The answerer is the DTLS client (setup:active) and emits the fingerprinted
    // ClientHello, so it advertises Chrome's full 3-profile use_srtp list -
    // `dtls_client = true` (#19).
    let api = build_api(cover_media, true)?;
    let pc = Arc::new(api.new_peer_connection(rtc_config(ice_servers)).await?);

    let (dc_tx, dc_rx) = mpsc::channel::<Arc<RTCDataChannel>>(1);
    pc.on_data_channel(Box::new(move |dc: Arc<RTCDataChannel>| {
        let dc_tx = dc_tx.clone();
        Box::pin(async move {
            let _ = dc_tx.send(dc).await;
        })
    }));

    pc.set_remote_description(RTCSessionDescription::offer(offer_sdp)?)
        .await?;
    if cover_media {
        // Reciprocate audio so the call looks bidirectional.
        spawn_cover_audio(&pc).await?;
    }
    let answer = pc.create_answer(None).await?;
    let mut gather = pc.gathering_complete_promise().await;
    pc.set_local_description(answer).await?;
    let _ = tokio::time::timeout(deadline, gather.recv()).await;
    let local = pc
        .local_description()
        .await
        .ok_or(WebRtcError::NoLocalDescription)?;

    Ok((local.sdp, WebRtcAccept { pc, dc_rx }))
}

/// Handle the bridge awaits after returning its answer: it resolves to the
/// [`WebRtcStream`] once the client-initiated data channel opens.
pub struct WebRtcAccept {
    pc: Arc<RTCPeerConnection>,
    dc_rx: mpsc::Receiver<Arc<RTCDataChannel>>,
}

impl WebRtcAccept {
    /// Await the incoming data channel and its open, bounded by `deadline`.
    pub async fn established(mut self, deadline: Duration) -> Result<WebRtcStream, WebRtcError> {
        let dc = tokio::time::timeout(deadline, self.dc_rx.recv())
            .await
            .map_err(|_| WebRtcError::Timeout)?
            .ok_or(WebRtcError::ConnectionFailed)?;
        let stream = attach_data_channel(self.pc.clone(), &dc);
        stream.wait_open(deadline).await?;
        Ok(stream)
    }
}

/// Kept for API symmetry / re-export: a `WebRtcStream` *is* the established
/// session, so this is a transparent alias callers can name.
pub type WebRtcSession = WebRtcStream;

// AsyncRead + AsyncWrite

impl AsyncRead for WebRtcStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if !this.inbound_buf.is_empty() {
            let n = buf.remaining().min(this.inbound_buf.len());
            let bytes: Vec<u8> = this.inbound_buf.drain(..n).collect();
            buf.put_slice(&bytes);
            return Poll::Ready(Ok(()));
        }
        match this.inbound_rx.poll_recv(cx) {
            Poll::Ready(Some(msg)) => {
                this.inbound_buf.extend(msg);
                let n = buf.remaining().min(this.inbound_buf.len());
                let bytes: Vec<u8> = this.inbound_buf.drain(..n).collect();
                buf.put_slice(&bytes);
                Poll::Ready(Ok(()))
            }
            // Sender dropped -> peer closed -> clean EOF.
            Poll::Ready(None) => Poll::Ready(Ok(())),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for WebRtcStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        // Non-blocking: hand the bytes to the send driver. If it's gone the
        // channel is dead.
        if self.outbound_tx.send(buf.to_vec()).is_err() {
            return Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()));
        }
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.gate.mark_failed();
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// In-process signaling: `exchange` runs the answerer inline, stashes the
    /// bridge-side stream for the test to pick up, and returns the answer. This
    /// drives two *real* peer connections that connect over loopback host ICE
    /// candidates - no external STUN/network needed.
    struct LoopbackSignaling {
        server_stream: Arc<Mutex<Option<WebRtcStream>>>,
        cover_media: bool,
        saw_audio_offer: Arc<AtomicBool>,
    }

    #[async_trait]
    impl Signaling for LoopbackSignaling {
        async fn exchange(&self, offer_sdp: String) -> Result<String, WebRtcError> {
            if offer_sdp.contains("m=audio") {
                self.saw_audio_offer.store(true, Ordering::SeqCst);
            }
            let (answer, accept) =
                webrtc_answer(offer_sdp, &[], self.cover_media, Duration::from_secs(20)).await?;
            let slot = self.server_stream.clone();
            tokio::spawn(async move {
                if let Ok(s) = accept.established(Duration::from_secs(20)).await {
                    *slot.lock().expect("poisoned") = Some(s);
                }
            });
            Ok(answer)
        }
    }

    #[test]
    fn ice_credentials_are_browser_shaped() {
        // Browsers: 4-char ufrag, 24-char pwd, base64 ICE charset.
        let ufrag = gen_ice_string(4);
        let pwd = gen_ice_string(24);
        assert_eq!(ufrag.len(), 4);
        assert_eq!(pwd.len(), 24);
        let ok = |c: char| c.is_ascii_alphanumeric() || c == '+' || c == '/';
        assert!(ufrag.chars().all(ok) && pwd.chars().all(ok));
    }

    #[test]
    fn dtls_client_use_srtp_matches_chrome_three_profile_order() {
        // The DTLS client (Mirage's answerer) emits the ClientHello, so its
        // use_srtp must be Chrome/libwebrtc's exact 3-profile list in order:
        // AEAD_AES_256_GCM (0x0008), AEAD_AES_128_GCM (0x0007),
        // AES128_CM_HMAC_SHA1_80 (0x0001) - fixing the "2-profiles-starting-0x0007"
        // tell that no current Chrome emits (#19).
        let client: Vec<u16> = use_srtp_profiles(true).iter().map(|p| *p as u16).collect();
        assert_eq!(client, vec![0x0008, 0x0007, 0x0001]);

        // The DTLS server (Mirage's dialer) SELECTS a profile from its own list,
        // so it must exclude the unkeyable 0x0008 - otherwise webrtc's
        // DtlsTransport::start would fail the connection. It thus always selects
        // 0x0007 from the client's offer.
        let server: Vec<u16> = use_srtp_profiles(false).iter().map(|p| *p as u16).collect();
        assert_eq!(server, vec![0x0007, 0x0001]);
        assert!(
            !server.contains(&0x0008),
            "server must never be able to select 0x0008"
        );
    }

    #[tokio::test]
    async fn loopback_data_channel_tunnels_bytes_both_ways() {
        let slot = Arc::new(Mutex::new(None));
        let signaling = LoopbackSignaling {
            server_stream: slot.clone(),
            cover_media: false,
            saw_audio_offer: Arc::new(AtomicBool::new(false)),
        };

        let mut client = webrtc_dial(&signaling, &[], "data", false, Duration::from_secs(20))
            .await
            .expect("dial establishes a data channel over loopback");

        // Pick up the bridge-side stream the answerer stashed.
        let mut server = {
            let mut s = None;
            for _ in 0..200 {
                if let Some(v) = slot.lock().expect("poisoned").take() {
                    s = Some(v);
                    break;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            s.expect("bridge-side stream established")
        };

        // client -> server
        let msg1 = b"hello over webrtc";
        client.write_all(msg1).await.unwrap();
        client.flush().await.unwrap();
        let mut buf1 = vec![0u8; msg1.len()];
        server.read_exact(&mut buf1).await.unwrap();
        assert_eq!(buf1, msg1);

        // server -> client
        let msg2 = b"ack from bridge";
        server.write_all(msg2).await.unwrap();
        server.flush().await.unwrap();
        let mut buf2 = vec![0u8; msg2.len()];
        client.read_exact(&mut buf2).await.unwrap();
        assert_eq!(buf2, msg2);
    }

    #[tokio::test]
    async fn cover_media_negotiates_audio_and_still_tunnels() {
        // With cover media on, the offer carries an audio m-line (so the flow
        // profiles as a call), and the data channel still tunnels bytes.
        let slot = Arc::new(Mutex::new(None));
        let saw_audio = Arc::new(AtomicBool::new(false));
        let signaling = LoopbackSignaling {
            server_stream: slot.clone(),
            cover_media: true,
            saw_audio_offer: saw_audio.clone(),
        };

        let mut client = webrtc_dial(&signaling, &[], "data", true, Duration::from_secs(20))
            .await
            .expect("cover-media dial establishes over loopback");

        assert!(
            saw_audio.load(Ordering::SeqCst),
            "offer must carry an audio m-line when cover media is on"
        );

        let mut server = {
            let mut s = None;
            for _ in 0..200 {
                if let Some(v) = slot.lock().expect("poisoned").take() {
                    s = Some(v);
                    break;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            s.expect("bridge-side stream established")
        };

        let msg = b"tunneled alongside cover audio";
        client.write_all(msg).await.unwrap();
        client.flush().await.unwrap();
        let mut got = vec![0u8; msg.len()];
        server.read_exact(&mut got).await.unwrap();
        assert_eq!(got, msg);
    }
}
