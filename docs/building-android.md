# Building Mirage for Android

Mirage runs on Android as a native library (`libmirage_mobile_ffi.so`) that a
Kotlin `VpnService` drives. The whole client - carriers, discovery, session
crypto, onion routing - runs in Rust on the TUN file descriptor the app hands
down. This page builds the `.so` and wires it into an app.

The pieces:

| Piece | Where |
|---|---|
| FFI core (`cdylib`) | [`crates/mobile-ffi`](../crates/mobile-ffi) - JNI entry points + shared core |
| fd adoption | `mirage_tun::OsTun::from_fd` (no OS routing - the app owns it) |
| socket protection | `mirage_client::set_socket_protector` -> `VpnService.protect()` upcall |
| Kotlin bridge | [`bindings/android/`](../bindings/android) - `MirageVpn.kt`, `MirageVpnService.kt` |

## Supported ABIs

| ABI | Rust target | Notes |
|---|---|---|
| `arm64-v8a` | `aarch64-linux-android` | ~all modern phones; ship this first |
| `armeabi-v7a` | `armv7-linux-androideabi` | legacy 32-bit ARM |
| `x86_64` | `x86_64-linux-android` | emulator / some Chromebooks |
| `x86` | `i686-linux-android` | 32-bit emulator (usually skippable) |

`ring` (Mirage's crypto backend) supports all four, so every transport compiles
- unlike the MIPS router case (see [building.md](building.md)).

## Prerequisites

- The pinned Rust 1.86 toolchain with the Android targets:
  ```sh
  rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
  ```
- The **Android NDK** (r26+), and [`cargo-ndk`](https://github.com/bbqsrc/cargo-ndk):
  ```sh
  cargo install cargo-ndk
  # point cargo-ndk at your NDK
  export ANDROID_NDK_HOME=$HOME/Android/Sdk/ndk/<version>
  ```
  The NDK provides the per-ABI clang that `ring`'s C build needs.

## Build the `.so`s

From the repo root, build all ABIs straight into an Android `jniLibs` tree:

```sh
cargo ndk \
  -t arm64-v8a -t armeabi-v7a -t x86_64 \
  -o app/src/main/jniLibs \
  build --release -p mirage-mobile-ffi
```

This produces `app/src/main/jniLibs/<abi>/libmirage_mobile_ffi.so`. Gradle packs
whatever is under `jniLibs/` into the APK/AAB automatically.

CI builds the same artifacts on every tag - see
[`.github/workflows/mobile.yml`](../.github/workflows/mobile.yml).

## Wire it into the app

1. Copy [`bindings/android/MirageVpn.kt`](../bindings/android/MirageVpn.kt) and
   [`MirageVpnService.kt`](../bindings/android/MirageVpnService.kt) into your app
   (package `dev.mirage.vpn`, or rename - but then rename the `Java_...` symbols in
   `crates/mobile-ffi/src/android.rs` to match).
2. Declare the service + permissions in the manifest (the header of
   `MirageVpnService.kt` has the exact XML).
3. Call `VpnService.prepare(context)` for user consent, then start the service
   with the client config JSON in `EXTRA_CONFIG_JSON`.

### The `protect()` requirement (important)

Every socket Mirage opens to reach a bridge must be excluded from the VPN via
`VpnService.protect(fd)`, or the encrypted carrier packets get routed back into
the tunnel - an infinite loop that breaks connectivity. The native layer calls
back into your `VpnService` to do this automatically; you just pass `this` to
`nativeStart` (the skeleton already does).

**Carrier caveat:** the automatic `protect()` upcall currently covers the
**TCP** carriers (Reality, WebSocket, meek, DoH, Shadowsocks-2022, obfs). The
QUIC carriers (**Hysteria2, MASQUE**) open their UDP socket inside `quinn`, which
isn't yet routed through the hook - prefer a TCP carrier for the first Android
release, or wire the QUIC socket protection before enabling them. This is
tracked as the remaining Android integration item.

## Config source

`nativeStart` takes the **same JSON** a desktop client uses. Generate one with
`mirage-keygen --write-client-config`, or import a `mirage://` invite and build
the config in-app. Keep secrets in Android's `EncryptedSharedPreferences` /
Keystore, never in plaintext.
