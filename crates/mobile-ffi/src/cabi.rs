//! C ABI for iOS and other C hosts.
//!
//! The Swift `NEPacketTunnelProvider` (see `bindings/ios/`) links the staticlib
//! and calls these. Two ways to start:
//! - [`mirage_vpn_start_packet_flow`] + [`mirage_vpn_push_packet`] - the iOS
//!   packet-flow model (callbacks), driving a [`mirage_tun::ChannelTun`].
//! - [`mirage_vpn_start_fd`] - for any C host that already has a TUN fd.
//!
//! Plus [`mirage_vpn_stop`] / [`mirage_vpn_version`].
//!
//! Note: unlike Android, an iOS `NEPacketTunnelProvider`'s own sockets are
//! already outside the tunnel, so no `protect()` upcall is installed here.

use std::ffi::{c_char, c_int, c_void, CStr};

use crate::MirageVpn;

/// C callback invoked with each IP packet the tunnel produces for delivery to
/// apps. The Swift bridge writes it via `packetFlow.writePackets`. `packet` is
/// valid only for the duration of the call.
pub type WritePacketCallback = extern "C" fn(ctx: *mut c_void, packet: *const u8, len: usize);

/// Wrapper making the opaque Swift context pointer `Send` so it can be captured
/// by the outbound-drain task.
struct SendCtx(*mut c_void);
// SAFETY: the host (Swift) owns `ctx`, guarantees it outlives the tunnel, and
// guarantees `write_cb(ctx, ...)` is safe to call from a background thread. Rust
// only stores the pointer and hands it back to the host's own callback.
#[allow(unsafe_code)]
unsafe impl Send for SendCtx {}

impl SendCtx {
    /// Deliver one outbound packet to the host callback. Taking `&self` forces
    /// the capturing closure to hold the whole (Send) wrapper rather than the
    /// bare `*mut c_void` field (edition-2021 disjoint capture).
    fn deliver(&self, cb: WritePacketCallback, pkt: &[u8]) {
        cb(self.0, pkt.as_ptr(), pkt.len());
    }
}

/// `mirage_vpn_start_packet_flow(config_json, mtu, write_cb, write_ctx)`.
///
/// The iOS `NEPacketTunnelProvider` model: the tunnel calls `write_cb` for each
/// outbound packet, and the host feeds app packets in via
/// [`mirage_vpn_push_packet`]. `mtu` of 0 uses the config default. Returns an
/// opaque handle, or NULL on failure. Free with [`mirage_vpn_stop`].
///
/// # Safety
/// `config_json` must be a valid NUL-terminated UTF-8 C string for the call.
/// `write_ctx` must satisfy the [`SendCtx`] contract.
#[no_mangle]
#[allow(unsafe_code)]
pub extern "C" fn mirage_vpn_start_packet_flow(
    config_json: *const c_char,
    mtu: usize,
    write_cb: WritePacketCallback,
    write_ctx: *mut c_void,
) -> *mut MirageVpn {
    if config_json.is_null() {
        return std::ptr::null_mut();
    }
    // SAFETY: caller contract - valid NUL-terminated string for the duration.
    let cfg = match unsafe { CStr::from_ptr(config_json) }.to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };
    let ctx = SendCtx(write_ctx);
    // Calling an `extern "C"` fn pointer is safe; only `ctx` needed the wrapper.
    let on_outbound = move |pkt: &[u8]| {
        ctx.deliver(write_cb, pkt);
    };
    match MirageVpn::start_packet_flow(cfg, mtu, on_outbound) {
        Ok(vpn) => Box::into_raw(Box::new(vpn)),
        Err(e) => {
            tracing::error!("mirage_vpn_start_packet_flow: {e}");
            std::ptr::null_mut()
        }
    }
}

/// `mirage_vpn_push_packet(handle, packet, len) -> bool`. Push an app-outbound
/// IP packet (from `packetFlow.readPackets`) into the tunnel. The bytes are
/// copied; the caller keeps ownership. Returns `true` if accepted.
///
/// # Safety
/// `handle` must be a live handle from [`mirage_vpn_start_packet_flow`], and
/// `packet` must point to `len` readable bytes for the duration of the call.
#[no_mangle]
#[allow(unsafe_code)]
pub extern "C" fn mirage_vpn_push_packet(
    handle: *const MirageVpn,
    packet: *const u8,
    len: usize,
) -> bool {
    if handle.is_null() || packet.is_null() || len == 0 {
        return false;
    }
    // SAFETY: per the documented contract, `handle` is live and `packet`/`len`
    // is a readable buffer for the call.
    let (vpn, bytes) = unsafe { (&*handle, std::slice::from_raw_parts(packet, len).to_vec()) };
    vpn.push_inbound(bytes)
}

/// `mirage_vpn_start_fd(config_json, tun_fd) -> *mut MirageVpn`.
///
/// `config_json` is a NUL-terminated UTF-8 string (the desktop client's JSON
/// schema). Returns an opaque handle, or NULL on failure. Free with
/// [`mirage_vpn_stop`].
///
/// # Safety
/// `config_json` must be a valid, NUL-terminated, UTF-8 C string that stays
/// valid for the duration of the call.
#[no_mangle]
#[allow(unsafe_code)]
pub extern "C" fn mirage_vpn_start_fd(config_json: *const c_char, tun_fd: c_int) -> *mut MirageVpn {
    if config_json.is_null() {
        return std::ptr::null_mut();
    }
    // SAFETY: caller contract (documented above) guarantees a valid
    // NUL-terminated string for the duration of this call.
    let cfg = match unsafe { CStr::from_ptr(config_json) }.to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };
    // No socket protector on the C path (see module note).
    match MirageVpn::start_fd::<fn(i32) -> bool>(cfg, tun_fd, None) {
        Ok(vpn) => Box::into_raw(Box::new(vpn)),
        Err(e) => {
            tracing::error!("mirage_vpn_start_fd: {e}");
            std::ptr::null_mut()
        }
    }
}

/// `mirage_vpn_stop(handle)`. Stops the tunnel and frees the handle. NULL is a
/// no-op.
///
/// # Safety
/// `handle` MUST be a pointer returned by [`mirage_vpn_start_fd`], passed here
/// at most once.
#[no_mangle]
#[allow(unsafe_code)]
pub extern "C" fn mirage_vpn_stop(handle: *mut MirageVpn) {
    if handle.is_null() {
        return;
    }
    // SAFETY: `handle` came from `mirage_vpn_start_fd`'s `Box::into_raw` and is
    // reconstructed exactly once here.
    let vpn = unsafe { Box::from_raw(handle) };
    vpn.stop();
}

/// `mirage_vpn_version() -> *const c_char`. A static NUL-terminated version
/// string; the caller must NOT free it.
#[no_mangle]
#[allow(unsafe_code)] // `#[no_mangle]` is an unsafe attribute; body is safe.
pub extern "C" fn mirage_vpn_version() -> *const c_char {
    concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr().cast()
}
