//! Production OS TUN device (Linux / macOS / Windows), behind the `device`
//! feature.
//!
//! - **Linux/macOS**: opens `/dev/net/tun` (needs `CAP_NET_ADMIN`/root).
//! - **Windows**: creates a [Wintun](https://www.wintun.net/) adapter (needs
//!   Administrator, and `wintun.dll` present - see [`OsTun::create`]).
//!
//! This is feature-gated and never exercised by the default build or unit tests
//! (which drive the netstack through [`crate::MemoryTun`]). All `unsafe` - the
//! `TUNSETIFF` ioctl on Unix, the `LoadLibrary`/wintun FFI on Windows - lives
//! inside the `tun` dependency, preserving Mirage's crate-level
//! `#![forbid(unsafe_code)]`.

use std::net::Ipv4Addr;

use async_trait::async_trait;

use crate::device::{TunDevice, TunError};

/// Configuration for a production TUN interface.
#[derive(Debug, Clone)]
pub struct OsTunConfig {
    /// Interface name (e.g. `mirage0`). `None` lets the OS pick.
    pub name: Option<String>,
    /// Address assigned to the interface (the gateway address apps route to).
    pub address: Ipv4Addr,
    /// Netmask for the interface subnet.
    pub netmask: Ipv4Addr,
    /// Interface MTU.
    pub mtu: usize,
}

impl Default for OsTunConfig {
    fn default() -> Self {
        Self {
            name: Some("mirage0".to_string()),
            address: Ipv4Addr::new(10, 200, 0, 1),
            netmask: Ipv4Addr::new(255, 255, 255, 0),
            mtu: crate::device::DEFAULT_TUN_MTU,
        }
    }
}

fn io_err(e: impl std::fmt::Display) -> TunError {
    TunError::Io(std::io::Error::other(e.to_string()))
}

/// A live OS TUN device implementing [`TunDevice`].
pub struct OsTun {
    dev: tun::AsyncDevice,
    mtu: usize,
}

impl OsTun {
    /// Create + bring up the TUN interface.
    ///
    /// - **Unix**: requires `CAP_NET_ADMIN`/root.
    /// - **Windows**: requires **Administrator** and `wintun.dll`. To avoid a
    ///   working-directory dependency, the DLL is loaded from **next to the
    ///   running executable** (the release archive ships it there); if that path
    ///   does not exist the `tun` crate falls back to the OS DLL search path.
    ///
    /// The caller is responsible for OS-level routing (adding routes that send
    /// the traffic to be protected into this interface) - this only opens the
    /// device and assigns its address/MTU.
    pub fn create(cfg: &OsTunConfig) -> Result<Self, TunError> {
        let mut c = tun::Configuration::default();
        c.address(cfg.address)
            .netmask(cfg.netmask)
            .mtu(cfg.mtu as u16)
            .up();
        if let Some(name) = &cfg.name {
            c.tun_name(name);
        }
        // On Windows, pin wintun.dll to the executable's directory so the
        // adapter opens regardless of the current working directory (the tun
        // crate otherwise looks only in the CWD). A missing file here just
        // leaves the crate's default search behaviour in place.
        #[cfg(windows)]
        if let Some(dll) = std::env::current_exe()
            .ok()
            .and_then(|exe| exe.parent().map(|dir| dir.join("wintun.dll")))
            .filter(|p| p.exists())
        {
            c.platform_config(|p| {
                p.wintun_file(dll);
            });
        }
        let dev = tun::create_as_async(&c).map_err(create_err)?;
        Ok(Self { dev, mtu: cfg.mtu })
    }

    /// Adopt an **already-open** TUN file descriptor instead of creating a new
    /// interface. This is the **Android** integration point: the app stands up a
    /// `VpnService`, calls `establish()` to get a `ParcelFileDescriptor`, and
    /// hands the raw fd down to native code. The OS already owns the interface's
    /// address, MTU, and routing (configured via `VpnService.Builder`), so this
    /// only wires the fd into the async read/write path - it installs nothing.
    ///
    /// `close_on_drop` controls fd ownership: pass `true` when the app
    /// `detachFd()`'d and handed ownership to native (native must close it),
    /// `false` when the app keeps the `ParcelFileDescriptor` and closes it
    /// itself. Mismatching this leaks the fd or closes it twice.
    ///
    /// No `unsafe` here: the `tun` crate adopts the fd internally, so this crate
    /// stays `#![forbid(unsafe_code)]`.
    ///
    /// # Errors
    /// Returns [`TunError::Io`] if the fd cannot be wrapped as an async device.
    #[cfg(unix)]
    pub fn from_fd(
        fd: std::os::unix::io::RawFd,
        mtu: usize,
        close_on_drop: bool,
    ) -> Result<Self, TunError> {
        let mut c = tun::Configuration::default();
        c.raw_fd(fd).close_fd_on_drop(close_on_drop).mtu(mtu as u16);
        let dev = tun::create_as_async(&c).map_err(create_err)?;
        Ok(Self { dev, mtu })
    }

    /// The **actual** kernel-assigned interface name. On Linux/Windows this is
    /// the requested name (`mirage0`); on macOS the kernel forces a `utunN`
    /// name regardless of what was requested, so route installation MUST use
    /// this value, not the configured one. Returns `None` if the platform
    /// cannot report it (routing then falls back to the configured name).
    pub fn if_name(&self) -> Option<String> {
        use tun::AbstractDevice as _;
        self.dev.tun_name().ok()
    }
}

/// Wrap a device-open failure, appending the platform-specific prerequisite
/// most likely to be the cause so the operator gets an actionable message.
fn create_err(e: impl std::fmt::Display) -> TunError {
    #[cfg(windows)]
    let hint = " (Windows TUN needs Administrator privileges and wintun.dll \
                 next to the executable - download it from https://www.wintun.net/)";
    #[cfg(not(windows))]
    let hint = " (needs CAP_NET_ADMIN or root)";
    TunError::Io(std::io::Error::other(format!("{e}{hint}")))
}

#[async_trait]
impl TunDevice for OsTun {
    async fn recv(&mut self, buf: &mut [u8]) -> Result<usize, TunError> {
        self.dev.recv(buf).await.map_err(io_err)
    }

    async fn send(&mut self, pkt: &[u8]) -> Result<(), TunError> {
        if pkt.len() > self.mtu {
            return Err(TunError::TooLarge {
                len: pkt.len(),
                mtu: self.mtu,
            });
        }
        self.dev.send(pkt).await.map(|_| ()).map_err(io_err)
    }

    fn mtu(&self) -> usize {
        self.mtu
    }
}
