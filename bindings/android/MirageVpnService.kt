package dev.mirage.vpn

import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log

/**
 * Reference Android [VpnService] that runs a Mirage tunnel.
 *
 * This is a **skeleton** to build a real app on top of, not a finished app. It
 * shows the full lifecycle: stand up the TUN interface, hand its fd to the Rust
 * core, and tear it down. The app owns everything above this — UI, config
 * source, the foreground-service notification, and the always-on/kill-switch
 * toggles. Search for `TODO(app)` for the integration points.
 *
 * Manifest requirements:
 * ```xml
 * <uses-permission android:name="android.permission.FOREGROUND_SERVICE"/>
 * <uses-permission android:name="android.permission.FOREGROUND_SERVICE_SPECIAL_USE"/>
 * <service android:name="dev.mirage.vpn.MirageVpnService"
 *          android:permission="android.permission.BIND_VPN_SERVICE"
 *          android:foregroundServiceType="specialUse"
 *          android:exported="false">
 *     <intent-filter><action android:name="android.net.VpnService"/></intent-filter>
 * </service>
 * ```
 * Before starting, the app must call `VpnService.prepare(context)` and handle the
 * consent Activity result.
 */
class MirageVpnService : VpnService() {

    private var tunInterface: ParcelFileDescriptor? = null
    private var handle: Long = 0L

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // TODO(app): load the real client config (from your settings / an
        // imported invite). This must be the same JSON the desktop client uses.
        val configJson = intent?.getStringExtra(EXTRA_CONFIG_JSON)
            ?: run {
                Log.e(TAG, "no config provided; stopping")
                stopSelf()
                return START_NOT_STICKY
            }

        // TODO(app): promote to a foreground service with a notification here,
        // or Android will kill the VPN shortly after backgrounding.

        try {
            startTunnel(configJson)
        } catch (e: Exception) {
            Log.e(TAG, "failed to start Mirage tunnel", e)
            stopSelf()
            return START_NOT_STICKY
        }
        return START_STICKY
    }

    private fun startTunnel(configJson: String) {
        // Build the OS TUN interface. Mirage does the actual tunneling; here we
        // only configure how the OS routes packets INTO the tunnel. A default
        // route captures everything; exclude/allow specific apps as needed.
        val builder = Builder()
            .setSession("Mirage")
            .setMtu(MTU)
            .addAddress("10.111.0.2", 32)          // TUN-local address (any private /32)
            .addRoute("0.0.0.0", 0)                // capture all IPv4
            .addRoute("::", 0)                     // capture all IPv6
            .addDnsServer("1.1.1.1")               // TODO(app): a DNS you trust
        // TODO(app): builder.addDisallowedApplication(packageName)  // don't tunnel ourselves

        val pfd = builder.establish()
            ?: throw IllegalStateException("VpnService.establish() returned null (permission not granted?)")
        tunInterface = pfd

        // Hand the fd to Rust. close_on_drop is false on the native side, so we
        // keep ownership of `pfd` and close it in stopTunnel().
        handle = MirageVpn.nativeStart(configJson, pfd.fd, this)
        if (handle == 0L) {
            throw IllegalStateException("native start failed (see logcat tag \"mirage\")")
        }
        Log.i(TAG, "Mirage tunnel up")
    }

    private fun stopTunnel() {
        if (handle != 0L) {
            MirageVpn.nativeStop(handle)
            handle = 0L
        }
        tunInterface?.close()
        tunInterface = null
        Log.i(TAG, "Mirage tunnel down")
    }

    override fun onDestroy() {
        stopTunnel()
        super.onDestroy()
    }

    companion object {
        private const val TAG = "mirage"
        private const val MTU = 1400
        /** Intent extra carrying the client config JSON. */
        const val EXTRA_CONFIG_JSON = "dev.mirage.vpn.CONFIG_JSON"
    }
}
