package dev.mirage.vpn

import android.net.VpnService

/**
 * JNI bridge to the Mirage mobile FFI (`libmirage_mobile_ffi.so`, built from
 * `crates/mobile-ffi`).
 *
 * The native layer runs the whole Mirage client — carriers, discovery, session
 * crypto, onion routing — on the OS TUN file descriptor the app provides. This
 * object is just the thin JNI seam; see [MirageVpnService] for how it is driven.
 */
object MirageVpn {
    init {
        // Matches the cdylib name in crates/mobile-ffi/Cargo.toml
        // (libmirage_mobile_ffi.so → "mirage_mobile_ffi").
        System.loadLibrary("mirage_mobile_ffi")
    }

    /**
     * Start the tunnel.
     *
     * @param configJson the client config (same JSON schema the desktop
     *   `mirage-client` reads — invite/bridge, carriers, onion, cover, etc.).
     * @param tunFd the raw fd from `VpnService.establish()`. The app retains
     *   ownership of the [android.os.ParcelFileDescriptor] and must close it
     *   after [nativeStop]; native does NOT close it.
     * @param vpnService the running service, so native can call
     *   `VpnService.protect(fd)` on each carrier socket (excluding the encrypted
     *   carrier from the tunnel — without this the tunnel loops).
     * @return an opaque handle, or 0 on failure (see logcat tag "mirage").
     */
    external fun nativeStart(configJson: String, tunFd: Int, vpnService: VpnService): Long

    /** Stop the tunnel and free the handle returned by [nativeStart]. */
    external fun nativeStop(handle: Long)
}
