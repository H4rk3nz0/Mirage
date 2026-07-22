//! Android JNI entry points, called from the Kotlin `VpnService` (see
//! `bindings/android/MirageVpnService.kt`).
//!
//! Symbol names encode the Kotlin class `dev.mirage.vpn.MirageVpn`. The whole
//! module compiles on the host too (the `jni` crate is portable), so CI type-
//! checks it without an emulator; the symbols are only *loaded* on-device.
#![allow(non_snake_case)]

use jni::objects::{JClass, JObject, JString, JValue};
use jni::sys::{jint, jlong};
use jni::JNIEnv;

use crate::MirageVpn;

/// `MirageVpn.nativeStart(configJson, tunFd, vpnService) -> Long`.
///
/// Builds the client from `configJson`, adopts the `tunFd` from
/// `VpnService.establish()`, installs a `VpnService.protect()` upcall for
/// carrier sockets, and starts the tunnel. Returns an opaque handle, or `0` on
/// failure (check logcat).
#[no_mangle]
#[allow(unsafe_code)] // `#[no_mangle]` is an unsafe attribute; body is safe.
pub extern "system" fn Java_dev_mirage_vpn_MirageVpn_nativeStart<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    config: JString<'local>,
    tun_fd: jint,
    vpn_service: JObject<'local>,
) -> jlong {
    init_logging();

    let config_json: String = match env.get_string(&config) {
        Ok(s) => s.into(),
        Err(e) => {
            tracing::error!("nativeStart: invalid config string: {e}");
            return 0;
        }
    };

    let protector = match make_protector(&mut env, &vpn_service) {
        Ok(p) => p,
        Err(e) => {
            tracing::error!("nativeStart: could not build protect() upcall: {e}");
            return 0;
        }
    };

    match MirageVpn::start_fd(&config_json, tun_fd, Some(protector)) {
        Ok(vpn) => Box::into_raw(Box::new(vpn)) as jlong,
        Err(e) => {
            tracing::error!("nativeStart: {e}");
            0
        }
    }
}

/// `MirageVpn.nativeStop(handle)`. Stops the tunnel and frees the handle.
///
/// # Safety
/// `handle` MUST be a value returned by [`Java_dev_mirage_vpn_MirageVpn_nativeStart`]
/// and passed here at most once (the Kotlin layer guarantees one stop per start).
#[no_mangle]
#[allow(unsafe_code)]
pub extern "system" fn Java_dev_mirage_vpn_MirageVpn_nativeStop<'local>(
    _env: JNIEnv<'local>,
    _class: JClass<'local>,
    handle: jlong,
) {
    if handle == 0 {
        return;
    }
    // SAFETY: `handle` is a pointer produced by `Box::into_raw` in nativeStart,
    // reconstructed exactly once here (single stop per start, enforced Kotlin-
    // side). Dropping the box runs `MirageVpn::stop` via the `.stop()` call.
    let vpn = unsafe { Box::from_raw(handle as *mut MirageVpn) };
    vpn.stop();
}

/// Build the `Fn(fd) -> bool` protector as an upcall to
/// `VpnService.protect(int): boolean`. The closure captures the JVM + a global
/// ref to the service, so it is `Send + Sync + 'static` and can be called from
/// any carrier-dial task.
fn make_protector(
    env: &mut JNIEnv,
    vpn_service: &JObject,
) -> Result<impl Fn(i32) -> bool + Send + Sync + 'static, String> {
    let vm = env.get_java_vm().map_err(|e| e.to_string())?;
    let service = env.new_global_ref(vpn_service).map_err(|e| e.to_string())?;
    Ok(move |fd: i32| -> bool {
        // Attach this Tokio worker thread to the JVM for the upcall.
        let Ok(mut guard) = vm.attach_current_thread() else {
            return false;
        };
        match guard.call_method(&service, "protect", "(I)Z", &[JValue::Int(fd)]) {
            Ok(v) => v.z().unwrap_or(false),
            Err(_) => false,
        }
    })
}

/// Install a default tracing subscriber once, so the core's logs are captured.
///
/// A cross-platform `fmt` subscriber (verified on the host and identical on
/// device). Routing to Android logcat is left to the host app - it can install
/// its own `tracing`/`log` subscriber (e.g. `android_logger` + `tracing-log`)
/// BEFORE calling `nativeStart`, in which case this `try_init` is a no-op and the
/// app's subscriber wins. Keeping logcat integration app-side avoids pinning a
/// stale bridge crate into the FFI.
fn init_logging() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = tracing_subscriber::fmt().try_init();
    });
}
