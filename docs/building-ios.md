# Building Mirage for iOS

iOS support is **design + skeleton** at this stage (Android is the priority
platform - see [building-android.md](building-android.md)). Everything below up
to and including the XCFramework is a repo artifact you can build today; the last
mile - installing on a device and shipping - needs a **paid Apple Developer
account** and is marked as such.

Mirage runs on iOS as a `staticlib` linked into a **Network Extension** (a
`NEPacketTunnelProvider`). Unlike Android's file-descriptor model, iOS hands the
extension a **packet-flow** object (`readPackets`/`writePackets`), so Mirage
drives a callback-based `mirage_tun::ChannelTun` rather than a TUN fd.

The pieces:

| Piece | Where |
|---|---|
| FFI core (`staticlib`) | [`crates/mobile-ffi`](../crates/mobile-ffi) - the `mirage_vpn_*` C ABI |
| C header | [`bindings/ios/mirage.h`](../bindings/ios/mirage.h) |
| Swift bridge | [`bindings/ios/PacketTunnelProvider.swift`](../bindings/ios/PacketTunnelProvider.swift) |

`ring` supports arm64/x86-64 Apple, so there is **no crypto blocker** - the whole
transport set compiles. The only hard requirement is a **macOS runner with
Xcode** (the iOS SDK's `xcrun` is needed to compile `ring`'s asm and blake3's
NEON intrinsics); nothing iOS builds on Linux.

## Targets

| Rust target | Use |
|---|---|
| `aarch64-apple-ios` | physical devices (arm64) |
| `aarch64-apple-ios-sim` | Apple-silicon simulator |
| `x86_64-apple-ios` | Intel-Mac simulator (optional) |

```sh
rustup target add aarch64-apple-ios aarch64-apple-ios-sim
```

## Build the XCFramework (macOS, no account needed)

```sh
# 1. Build the staticlib for device + simulator.
cargo build --release -p mirage-mobile-ffi --target aarch64-apple-ios
cargo build --release -p mirage-mobile-ffi --target aarch64-apple-ios-sim

# 2. Assemble an XCFramework (add a lipo'd x86_64 sim slice too if you need it).
xcodebuild -create-xcframework \
  -library target/aarch64-apple-ios/release/libmirage_mobile_ffi.a \
      -headers bindings/ios \
  -library target/aarch64-apple-ios-sim/release/libmirage_mobile_ffi.a \
      -headers bindings/ios \
  -output Mirage.xcframework
```

CI builds this on a macOS runner - see the `ios` job in
[`.github/workflows/mobile.yml`](../.github/workflows/mobile.yml).

## Wire it into the extension

1. Add a **Packet Tunnel Provider** app-extension target to your Xcode project.
2. Drag in `Mirage.xcframework`; set a **bridging header** that `#import "mirage.h"`.
3. Use [`PacketTunnelProvider.swift`](../bindings/ios/PacketTunnelProvider.swift)
   as the provider (fill in `loadConfigJson()` and the network settings). It
   already bridges `packetFlow` <-> the `mirage_vpn_*` packet-flow C ABI.
4. Configure the tunnel from the containing app with `NETunnelProviderManager`.

## Account-gated steps (need a paid Apple Developer account)

These cannot be done from the repo or on a free account:

- The **`com.apple.developer.networking.networkextension`** entitlement with the
  `packet-tunnel-provider` value, on both the app and the extension.
- A **provisioning profile** that includes that entitlement, and code signing.
- Device install, **TestFlight**, and App Store submission (Network Extensions
  get extra review scrutiny).

## Footprint caveat (verify on device)

A Network Extension has a tight memory budget (~50 MB on modern iOS, less on
older). The full menu - `quinn` (QUIC/Hysteria2/MASQUE) + WebRTC + smoltcp +
tokio in one address space - may approach it. If you hit the limit, trim the
active carriers **at runtime in the config** (Mirage has no compile-time feature
flags): a TLS-family carrier set (Reality/WebSocket/meek/DoH) is much lighter
than pulling in QUIC and WebRTC. Measure with Instruments before shipping.
