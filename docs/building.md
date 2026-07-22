# Building Mirage & supported platforms

Mirage builds from one workspace with **no feature flags** (see the [docs index](README.md)).
This page is the reference for **which platforms are supported, how the release pipeline builds
each, and how to cross-compile yourself** - including the awkward targets (old routers, MIPS,
and mobile).

The toolchain is pinned to **Rust 1.86 (stable)** in `rust-toolchain.toml`. Everything below
holds to that pin unless a section explicitly says otherwise.

```sh
cargo build --release --workspace     # the whole thing, host target
```

---

## Supported target matrix

The [release workflow](../.github/workflows/release.yml) builds and publishes these on every
`v*` tag:

| Target triple | Class | Notes |
|---|---|---|
| `x86_64-unknown-linux-musl` | Desktop / server | Fully static, runs anywhere |
| `aarch64-unknown-linux-musl` | Server / SBC | 64-bit ARM (RPi 3+, most cloud ARM) |
| `armv7-unknown-linux-musleabihf` | Router / SBC | 32-bit ARM v7 hard-float (RPi 2+, many routers) |
| `arm-unknown-linux-musleabihf` | Router / SBC | ARM v6 hard-float (RPi 1 / Zero, ARM11 routers) |
| `arm-unknown-linux-musleabi` | Router | ARM v6 **soft-float** (low-end OpenWrt without VFP) |
| `x86_64-apple-darwin` | Desktop | Intel macOS |
| `aarch64-apple-darwin` | Desktop | Apple-silicon macOS |
| `x86_64-pc-windows-msvc` | Desktop | Windows |

The CLI set (`mirage-client`, `mirage-bridge`, `mirage-keygen`, `mirage-publish`, `mirage-setup`)
is built **static against musl** on Linux, so there are no glibc-version surprises on old router
firmware.

The desktop GUI (`mirage-client-gui`) ships in separate `...-gui` archives. It uses Slint's software
renderer, so it needs **no GTK and no system build libraries** - plain `cargo build` works - but it
**cannot** be static-musl: its windowing backend (winit) dlopens the desktop's X11/Wayland libraries
at run time, which a fully-static binary has no loader for. So the Linux GUI is a **glibc** build
that runs on any desktop session; macOS/Windows GUI builds are native. The GUI archive bundles a
matching `mirage-client` (the daemon it supervises).

### How the router/ARM cross-builds work

The musl-ARM legs do **not** use `cross`. `ring` (Mirage's only C dependency, pulled in through
QUIC and cert generation) ships C + perl-asm and needs a real musl C cross-compiler. The release
job installs one per triple with
[`taiki-e/setup-cross-toolchain-action`](https://github.com/taiki-e/setup-cross-toolchain-action),
which exports `CC_<triple>` / `AR_<triple>` / `CARGO_TARGET_<TRIPLE>_LINKER` so a plain
`cargo build --target <triple>` just works. It only runs `rustup target add` on the pinned 1.86
toolchain - never a newer rustc - so the MSRV pin holds.

To reproduce an ARM router build locally you need the matching musl cross toolchain (e.g. from
[musl.cc](https://musl.cc) or your distro), then:

```sh
export CC_arm_unknown_linux_musleabihf=arm-linux-musleabihf-gcc
export CARGO_TARGET_ARM_UNKNOWN_LINUX_MUSLEABIHF_LINKER=arm-linux-musleabihf-gcc
rustup target add arm-unknown-linux-musleabihf
cargo build --release --target arm-unknown-linux-musleabihf \
    -p mirage-client -p mirage-bridge
```

`ring` accepts every ARM/musl target here - the only thing CI adds over a bare checkout is the
cross `gcc`.

---

## RISC-V (buildable, not yet a release leg)

`riscv64gc-unknown-linux-gnu` is Rust **tier 2 with prebuilt std** and `ring` builds for it (via
its portable, no-asm fallback - slower but correct), so the **full** transport set compiles with
no changes. It isn't in the release matrix yet only because there's no demand signal; add it the
same way as an ARM leg (it needs a `riscv64-linux-gnu-gcc` cross toolchain) if you target RISC-V
routers/SBCs.

---

## MIPS routers (advanced / deferred)

**Short version: MIPS is not a supported release target, on purpose.** OpenWrt's classic MIPS
devices (ath79, ramips, ...) hit *two* independent blockers:

1. **No standard library on the stable pin.** Every MIPS triple
   (`mips-unknown-linux-musl`, `mipsel-unknown-linux-musl`, `mips64...-muslabi64`) was demoted to
   Rust **tier 3**. `rustup target add mipsel-unknown-linux-musl` on the 1.86 toolchain returns
   `rust-std ... unavailable for download`. Building therefore requires **nightly `-Z build-std`**,
   which breaks the MSRV-1.86-stable pin the whole project holds.
2. **`ring` has no MIPS backend.** `ring` reaches the client through QUIC (`quinn-proto` ->
   Hysteria2 + MASQUE), cert generation (`rcgen`), WebRTC (`webrtc` + the vendored
   `webrtc-dtls`), **and** the workspace's pinned `rustls`/`tokio-rustls` `ring` provider (used
   for ordinary HTTPS). Its build fails hunting for `mipsel-linux-musl-gcc` because there is no
   MIPS assembly to compile.

A MIPS build is only possible as a **reduced "lite" client**, and even that needs nightly. If you
must have one, the documented recipe is:

1. Use a **nightly** toolchain with `rust-src`, and `cargo build -Z build-std=std,panic_abort`.
2. Provide a musl-MIPS C toolchain (OpenWrt SDK, or musl.cc) and export the usual
   `CC_/AR_/CARGO_TARGET_*_LINKER` env for the triple.
3. **Drop the ring-only transports** - Hysteria2, MASQUE, and WebRTC (all QUIC/DTLS) - and swap
   the rustls provider to the pure-Rust [`rustls-rustcrypto`](https://github.com/rustls/rustls-rustcrypto)
   so the TLS-family carriers (Reality, WebSocket, meek, DoH, dnstt, Shadowsocks-2022, obfs) still
   work. This means reintroducing a build-time transport-selection feature *for that leg only* -
   the one place Mirage's "no feature flags" rule is relaxed, because the alternative is no MIPS
   build at all.

This is deliberately left as an operator recipe, not a CI leg: it is nightly, unaudited on
big-endian codecs, and ships a strictly smaller carrier menu. Prefer an **ARM** router where you
can - almost every router sold in the last decade has an ARM option, and those get the full,
audited build above.

---

## Mobile (iOS / Android)

Mobile is delivered as an **embeddable core library + FFI bindings**, not as CLI binaries - a
phone app links the Rust core and drives it. See:

- **[Android build guide](building-android.md)** - per-ABI `.so`, UniFFI Kotlin bindings, and a
  reference `VpnService`.
- **[iOS build guide](building-ios.md)** - `staticlib` -> XCFramework, a Swift
  `NEPacketTunnelProvider` bridge, and the Apple Developer account gates.

Both are unblocked at the CPU level (`ring` supports arm64/x86-64 Android and iOS); the work is
the FFI surface and each OS's VPN integration, not cross-compilation.

---

## Reproducible builds (Nix)

```sh
nix build .#mirage-bridge     # or .#mirage-client, etc.
```

The flake pins the same 1.86 toolchain and produces bit-reproducible artifacts.
