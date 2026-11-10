# Installing the Mirage desktop app

The desktop app (`mirage-client-gui`) ships as a native installer for each
platform, bundling the GUI and its `mirage-client` daemon. Download the file for
your OS from the [latest release](../../releases).

> **The installers are unsigned during the alpha.** They work, but macOS and
> Windows will show a one-time warning because the app isn't signed with a paid
> developer certificate. The steps below clear it. (Code signing will come once
> the project has certificates.)

## Linux

Two options:

- **AppImage** - `mirage-<version>-x86_64.AppImage`. No install; just make it
  executable and run:
  ```sh
  chmod +x mirage-*-x86_64.AppImage
  ./mirage-*-x86_64.AppImage
  ```
  Needs a normal desktop session (X11 or Wayland), which any Linux desktop has.

- **Debian/Ubuntu package** - `mirage-<version>-amd64.deb`:
  ```sh
  sudo apt install ./mirage-*-amd64.deb
  ```
  Installs `mirage-client-gui` and `mirage-client` to `/usr/bin` and adds a
  "Mirage" entry to your applications menu.

## macOS

Open `mirage-<version>-<arch>.dmg` and drag **Mirage** to Applications.

The first launch is blocked because the app is unsigned - clear it once:

- **Right-click** (or Control-click) the app -> **Open** -> **Open** in the dialog.

  or from a terminal:
  ```sh
  xattr -dr com.apple.quarantine /Applications/Mirage.app
  ```

After that it opens normally. Use the **Apple Silicon** (`aarch64`) build on M1/M2/M3
Macs and the **x86_64** build on Intel Macs.

## Windows

Run `mirage-<version>-x86_64.msi`.

SmartScreen may show **"Windows protected your PC"** because the installer is
unsigned - click **More info -> Run anyway**. The installer places Mirage under
`Program Files\Mirage` with a Start-menu shortcut, and includes the Wintun driver
the VPN mode uses.

## Verify your download (recommended)

A censor's easiest attack is a trojaned build. Each release ships `SHA256SUMS.txt`
and keyless build-provenance:

```sh
sha256sum -c SHA256SUMS.txt                 # against the file you downloaded
gh attestation verify <file> --owner OWNER  # proves it was built by the release workflow
```

## Build it yourself

No system libraries are required (Slint software renderer):

```sh
cargo build --release -p mirage-client-gui
```
