# Mirage mobile bindings

Reference glue for embedding the Mirage client on mobile. The Rust core lives in
[`crates/mobile-ffi`](../crates/mobile-ffi); these are the thin platform layers a
host app copies in and builds on.

| Dir | Platform | Contents |
|---|---|---|
| [`android/`](android) | Android | `MirageVpn.kt` (JNI declarations) + `MirageVpnService.kt` (reference `VpnService`) |
| `ios/` | iOS | Swift `PacketTunnelProvider` bridge + XCFramework packaging (Phase E) |

These are **skeletons**, not finished apps: they show the full tunnel lifecycle
and the exact integration points (`TODO(app)` markers), and the app team builds
the UI, config storage, and store packaging on top.

- **Android build & integration:** [docs/building-android.md](../docs/building-android.md)
- **iOS build & integration:** [docs/building-ios.md](../docs/building-ios.md)

The FFI surface is stable and small: start the tunnel on an OS-provided TUN
device + a config, stop it. Everything else - carriers, discovery, onion
routing, cover traffic - is selected at runtime by the same JSON config the
desktop client uses.
