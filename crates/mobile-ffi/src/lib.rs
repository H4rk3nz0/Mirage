//! Mobile FFI for Mirage.
//!
//! Embeds the [`mirage_client`] core so a phone app can run the Mirage VPN by
//! handing Mirage the OS-provided TUN device and a config, and starting/stopping
//! it. Two surfaces sit on top of one shared core ([`MirageVpn`]):
//!
//! - **Android** - JNI entry points in [`android`], called from a Kotlin
//!   `VpnService`. The app `establish()`es the tunnel, passes the raw fd down,
//!   and Mirage runs the netstack on it. The app also provides a
//!   `VpnService.protect(fd)` upcall so carrier sockets bypass the tunnel.
//! - **iOS** - a C ABI (`mirage_vpn_*`, below) linked into an XCFramework and
//!   called from a Swift `NEPacketTunnelProvider`. iOS delivers packets by
//!   callback rather than a fd (see the packet-flow entry points), so it drives
//!   a [`mirage_tun::ChannelTun`]. The Swift bridge is fleshed out in Phase E.
//!
//! # Safety
//! This crate crosses an unavoidable `unsafe` FFI boundary (JNI, raw C
//! pointers). It therefore does NOT inherit the workspace `forbid(unsafe_code)`;
//! it `deny`s unsafe and scopes every block. All *protocol* logic lives in the
//! safe upstream crates - this is a thin, audited shim.

#![deny(unsafe_code)]
#![warn(missing_docs)]

use tokio_util::sync::CancellationToken;

#[cfg(unix)]
pub mod android;

#[cfg(unix)]
mod cabi;

/// A running Mirage VPN instance. Opaque to the host: created by a `start_*`
/// entry point, torn down by [`MirageVpn::stop`]. Holds the Tokio runtime that
/// drives the tunnel and a [`CancellationToken`] that stops it.
pub struct MirageVpn {
    runtime: tokio::runtime::Runtime,
    shutdown: CancellationToken,
    /// Present only in packet-flow (iOS) mode: the sink app-outbound packets are
    /// pushed into via [`MirageVpn::push_inbound`].
    inbound: Option<mirage_tun::ChannelTunSink>,
}

impl MirageVpn {
    /// Start the VPN on an OS-provided TUN **file descriptor** (the Android
    /// `VpnService` model).
    ///
    /// - `config_json` is the same JSON schema a desktop `mirage-client` reads.
    /// - `tun_fd` is the fd from `VpnService.establish()` (already configured
    ///   with address/MTU/routes by the app). Mirage does NOT close it or touch
    ///   routing - the app owns both.
    /// - `protector` is called with each carrier socket's fd before it connects,
    ///   so the host can `VpnService.protect()` it (returns `true` on success).
    ///   Passing `None` on Android will loop traffic back into the tunnel - it
    ///   is only correct to omit on a host that does no VPN-side routing.
    ///
    /// # Errors
    /// Returns a human-readable message if the config is invalid, the pool
    /// cannot be built, the fd cannot be adopted, or the runtime cannot start.
    #[cfg(unix)]
    pub fn start_fd<P>(
        config_json: &str,
        tun_fd: std::os::unix::io::RawFd,
        protector: Option<P>,
    ) -> Result<Self, String>
    where
        P: Fn(i32) -> bool + Send + Sync + 'static,
    {
        let cfg = mirage_client::Config::from_json(config_json)?;
        let mtu = cfg.tun_mtu();
        if let Some(p) = protector {
            mirage_client::set_socket_protector(p);
        }
        // The app keeps ownership of the ParcelFileDescriptor, so do not close
        // the fd on drop here.
        let dev = mirage_tun::OsTun::from_fd(tun_fd, mtu, false).map_err(|e| e.to_string())?;
        Self::spawn(cfg, dev, mtu, None)
    }

    /// Start the VPN in **packet-flow** mode (the iOS `NEPacketTunnelProvider`
    /// model): the host delivers app packets by pushing them via
    /// [`MirageVpn::push_inbound`], and each packet the tunnel produces for
    /// delivery to apps is handed to `on_outbound`.
    ///
    /// - `config_json` - the desktop client's JSON schema.
    /// - `mtu_hint` - the tunnel MTU; `0` uses the config's `tun_mtu`.
    /// - `on_outbound` - invoked with each outbound IP packet (write it via
    ///   `packetFlow.writePackets`). Called from a Tokio worker thread.
    ///
    /// # Errors
    /// As [`MirageVpn::start_fd`].
    pub fn start_packet_flow<W>(
        config_json: &str,
        mtu_hint: usize,
        on_outbound: W,
    ) -> Result<Self, String>
    where
        W: Fn(&[u8]) + Send + 'static,
    {
        let cfg = mirage_client::Config::from_json(config_json)?;
        let mtu = if mtu_hint > 0 {
            mtu_hint
        } else {
            cfg.tun_mtu()
        };
        let (device, mut handle) = mirage_tun::ChannelTun::new(mtu, 512);
        let sink = handle.inbound_sink();
        let vpn = Self::spawn(cfg, device, mtu, Some(sink))?;
        // Drain outbound packets on the same runtime and hand each to the host.
        let sd = vpn.shutdown.clone();
        vpn.runtime.spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    () = sd.cancelled() => break,
                    pkt = handle.next_outbound() => match pkt {
                        Some(p) => on_outbound(&p),
                        None => break,
                    },
                }
            }
        });
        Ok(vpn)
    }

    /// Push an app-outbound IP packet into the tunnel (packet-flow mode only).
    /// Returns `false` if the queue is full (dropped) or not in packet-flow mode.
    #[must_use]
    pub fn push_inbound(&self, pkt: Vec<u8>) -> bool {
        self.inbound.as_ref().is_some_and(|s| s.try_push(pkt))
    }

    /// Start the VPN driving a caller-provided [`mirage_tun::TunDevice`]. The
    /// fd and packet-flow entry points both funnel through here.
    fn spawn<D>(
        cfg: mirage_client::Config,
        device: D,
        mtu: usize,
        inbound: Option<mirage_tun::ChannelTunSink>,
    ) -> Result<Self, String>
    where
        D: mirage_tun::TunDevice + Send + 'static,
    {
        let client = mirage_client::Client::new(cfg)?;
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .map_err(|e| format!("tokio runtime: {e}"))?;
        let shutdown = CancellationToken::new();
        let sd = shutdown.clone();
        runtime.spawn(async move {
            match client.run_tun(device, mtu, sd).await {
                Ok(()) => tracing::info!("mirage vpn: tunnel stopped"),
                Err(e) => tracing::error!(error = %e, "mirage vpn: tunnel ended with error"),
            }
        });
        Ok(Self {
            runtime,
            shutdown,
            inbound,
        })
    }

    /// Signal shutdown and tear the tunnel down, giving in-flight tasks a brief
    /// grace period before the runtime is dropped.
    pub fn stop(self) {
        self.shutdown.cancel();
        self.runtime
            .shutdown_timeout(std::time::Duration::from_secs(2));
    }
}

/// FFI ABI/library version, exposed so a host can sanity-check the linked core.
#[must_use]
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(test)]
mod tests {
    #[test]
    fn version_is_nonempty() {
        assert!(!super::version().is_empty());
    }

    // The C ABI version string must be NUL-terminated and match the crate.
    #[test]
    fn cabi_version_matches() {
        let ptr = super::cabi::mirage_vpn_version();
        // SAFETY (test-only): the pointer is a 'static NUL-terminated string.
        #[allow(unsafe_code)]
        let s = unsafe { std::ffi::CStr::from_ptr(ptr) }.to_str().unwrap();
        assert_eq!(s, super::version());
    }

    #[test]
    fn packet_flow_rejects_bad_config() {
        assert!(super::MirageVpn::start_packet_flow("not json", 1400, |_| {}).is_err());
    }

    // End-to-end (no networking): a packet-flow VPN starts, accepts a pushed
    // packet into the inbound queue, and stops cleanly - exercising the runtime,
    // ChannelTun, outbound-drain task, and shutdown path.
    #[test]
    fn packet_flow_start_push_stop() {
        let json = format!(
            r#"{{"local_bind":"127.0.0.1:1080",
                 "bridge_addr":"192.0.2.10:443",
                 "bridge_x25519_pk_hex":"{pk}",
                 "bridge_ed25519_pk_hex":"{pk}"}}"#,
            pk = "11".repeat(32)
        );
        if let Ok(vpn) = super::MirageVpn::start_packet_flow(&json, 1400, |_pkt| {}) {
            // A minimal IPv4 header. The netstack may drop it (no live flow), but
            // push_inbound must accept it into the queue.
            let pkt = vec![
                0x45, 0, 0, 20, 0, 0, 0, 0, 64, 6, 0, 0, 10, 111, 0, 2, 93, 184, 216, 34,
            ];
            assert!(vpn.push_inbound(pkt), "packet-flow handle accepts pushes");
            vpn.stop();
        }
    }
}
