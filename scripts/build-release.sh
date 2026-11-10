#!/usr/bin/env bash
# Build Mirage release archives into ./dist/.
#
#   Linux (server + client) and Windows (client) are cross-compiled with
#   `cross` (Docker/Podman).  Install it once:   cargo install cross
#   macOS (client, Intel + Apple Silicon) builds natively - run this on a Mac.
#
# Client binaries include the TUN VPN feature (runtime-opt-in via `tun_enabled`);
# set CLIENT_FEATURES="" for a proxy-only client.  Targets that fail are skipped,
# so this builds everything the current host *can* build.
set -uo pipefail
cd "$(dirname "$0")/.."                                   # repo root

VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)"
DIST="dist"; mkdir -p "$DIST"
CLIENT_FEATURES="${CLIENT_FEATURES-tun}"
# `cross` prefers Docker; fall back to Podman when that's all we have.
command -v docker >/dev/null 2>&1 || export CROSS_CONTAINER_ENGINE="${CROSS_CONTAINER_ENGINE:-podman}"

SERVER_BINS=(--bin mirage-bridge --bin mirage-keygen --bin mirage-publish)

#   target                          role    builder
TARGETS=(
  "x86_64-unknown-linux-musl        both    cross"       # Linux x86-64
  "aarch64-unknown-linux-musl       both    cross"       # Linux ARM64
  "armv7-unknown-linux-musleabihf   both    cross"       # Linux ARMv7 (Pi 2+, routers)
  "x86_64-pc-windows-gnu            client  cross"       # Windows x86-64
  "x86_64-apple-darwin              client  cargo"       # macOS Intel        (Mac only)
  "aarch64-apple-darwin             client  cargo"       # macOS Apple Silicon (Mac only)
)
# Extra ARM variant - uncomment if you need older soft-float ARM:
#   "arm-unknown-linux-musleabi     both    cross"
# MIPS is intentionally omitted: mips*-unknown-linux-* are Rust tier 3 (no
# rustup std; nightly + -Zbuild-std only) and `ring` has no MIPS asm.

for row in "${TARGETS[@]}"; do
  read -r target role builder _ <<<"$row"
  [[ "$target" == *apple-darwin* && "$(uname -s)" != Darwin ]] && { echo "SKIP $target - Apple targets build only on macOS"; continue; }
  command -v "$builder" >/dev/null 2>&1 || { echo "SKIP $target - '$builder' not found (run: cargo install cross)"; continue; }
  [[ "$builder" == cargo ]] && rustup target add "$target" >/dev/null 2>&1

  echo "==> building $target ($role)"
  ok=1
  [[ "$role" == both ]] && { "$builder" build --release --locked --target "$target" "${SERVER_BINS[@]}" || ok=0; }
  feats=(); [[ -n "$CLIENT_FEATURES" ]] && feats=(--features "$CLIENT_FEATURES")
  "$builder" build --release --locked --target "$target" -p mirage-client "${feats[@]}" || ok=0
  [[ "$ok" == 1 ]] || echo "!! $target had build failures - packaging whatever produced"

  # Collect + archive.
  ext=""; [[ "$target" == *windows* ]] && ext=".exe"
  out="$DIST/mirage-$VERSION-$target"; rm -rf "$out"; mkdir -p "$out"
  for b in mirage-client mirage-bridge mirage-keygen mirage-publish; do
    cp -f "target/$target/release/$b$ext" "$out/" 2>/dev/null || true
  done
  # Windows: bundle the WireGuard Wintun driver the TUN client loads (pinned + verified).
  if [[ "$target" == *windows* && -n "$CLIENT_FEATURES" ]]; then
    wt=0.14.1; sha=07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51
    if curl -fsSL "https://git.zx2c4.com/wintun/builds/wintun-$wt.zip" -o "$DIST/wintun.zip" \
       && echo "$sha  $DIST/wintun.zip" | sha256sum -c - >/dev/null 2>&1 \
       && unzip -qo "$DIST/wintun.zip" -d "$DIST/wt"; then
      cp "$DIST/wt/wintun/bin/amd64/wintun.dll" "$out/"
    else
      echo "   (wintun.dll not bundled - fetch it from https://www.wintun.net/ next to the .exe)"
    fi
    rm -rf "$DIST/wt" "$DIST/wintun.zip"
  fi
  base="mirage-$VERSION-$target"
  ( cd "$DIST" && if [[ "$target" == *windows* ]]; then zip -qr "$base.zip" "$base"; else tar czf "$base.tar.gz" "$base"; fi )
  echo "   -> $DIST/$base.$([[ "$target" == *windows* ]] && echo zip || echo tar.gz)"
done

# ---- Desktop GUI (mirage-client-gui) ----
# Built for the HOST's native desktop target only. The Slint GUI cannot be
# musl-static (its winit backend dlopens X11/Wayland at run time), so it is a
# glibc/macOS/Windows dynamic build, packaged with a matching mirage-client (the
# GUI supervises it). No system build libraries are needed.
HOST_TARGET="$(rustc -vV | sed -n 's/^host: //p')"
echo "==> building desktop GUI for host $HOST_TARGET"
if rustup target add "$HOST_TARGET" >/dev/null 2>&1; cargo build --release --locked --target "$HOST_TARGET" -p mirage-client-gui -p mirage-client; then
  ext=""; [[ "$HOST_TARGET" == *windows* ]] && ext=".exe"
  gout="$DIST/mirage-$VERSION-$HOST_TARGET-gui"; rm -rf "$gout"; mkdir -p "$gout"
  for b in mirage-client-gui mirage-client; do
    cp -f "target/$HOST_TARGET/release/$b$ext" "$gout/" 2>/dev/null || true
  done
  gbase="mirage-$VERSION-$HOST_TARGET-gui"
  ( cd "$DIST" && if [[ "$HOST_TARGET" == *windows* ]]; then zip -qr "$gbase.zip" "$gbase"; else tar czf "$gbase.tar.gz" "$gbase"; fi )
  echo "   -> $DIST/$gbase.$([[ "$HOST_TARGET" == *windows* ]] && echo zip || echo tar.gz)"
else
  echo "!! GUI build failed for $HOST_TARGET - skipped"
fi

echo; echo "Archives in ./$DIST/  (macOS targets build only on a Mac; the GUI builds for the host desktop only; MIPS is not supported on the stable toolchain.)"
