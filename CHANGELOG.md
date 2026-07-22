# Changelog

All notable changes to Mirage are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and Mirage aims to
follow [Semantic Versioning](https://semver.org/) once it reaches 1.0. Until
then, pre-releases may make breaking changes between versions.

## [0.1.3-alpha.1] - 2026-07-21

### Added
- **Desktop GUI rewritten on Slint, and now shipped in the releases.** The
  graphical client (`mirage-client-gui`) moved off egui/GTK to Slint's software
  renderer: it builds with plain `cargo build` (no GTK or system libraries) and
  links only the standard C runtime. It is now packaged in per-OS `...-gui`
  archives (Linux glibc, macOS, Windows) alongside a matching `mirage-client`,
  instead of being source-only.
  - A built-in file browser for picking a `client.json` (no dependency on a
    system file-dialog tool like zenity/kdialog).
  - The log panel is selectable and copyable; each bridge shows a stable colour
    swatch so you can tell them apart at a glance.
- **Bridge operator admin web UI** (`mirage-bridge --admin-ui`, default
  `127.0.0.1:3825`). A local, token-gated, loopback-only web app to view live
  counters, edit the bridge config (secrets masked, written atomically `0600`),
  and restart the service. See `docs/operators.md` §8.
- **Hysteria2 hardening knobs** - UDP **port-hopping** (`derived_port_*`),
  loss-immune **BRUTAL** congestion control (`hysteria2_brutal`), and serving a
  **real leaf cert** (`hysteria2_cert_der_path` / `hysteria2_key_der_path`)
  instead of a self-signed one.
- **Reality `borrow` TLS mode** (`reality_tls_mode = "borrow"`) - the bridge
  auto-fetches the cover site's real leaf certificate at startup for passive
  cert-comparison parity.

### Changed
- **Reality server flight now mirrors the cover's record framing.** The bridge
  measures the real cover's TLS record sizes and splits its own handshake flight
  to match them (falling back to a single padded record when they don't fit),
  so the encrypted flight matches the cover in record boundaries, not just total
  size.
- Client and operator docs updated for all of the above
  (`configuration.md`, `operators.md`, `getting-started.md`, `building.md`,
  `features.md`, `QUICKSTART.md`).

## [0.1.1-alpha.2] - 2026-07-20

### Added
- **Mobile and router platform support.** New release targets plus an embeddable
  core so the same client runs on a phone:
  - Router/embedded ARM added to the release matrix - `arm-unknown-linux-musleabihf`
    (ARMv6 hard-float: RPi 1/Zero, ARM11 routers) and `arm-unknown-linux-musleabi`
    (soft-float: low-end OpenWrt) - alongside the existing aarch64/armv7 musl legs.
  - The client is now an embeddable **library**: `mirage-client` exposes a
    `Config`/`Client` API and a cancellable `run_tun`, so the code that runs the
    desktop CLI also runs inside a mobile app. The desktop binary is byte-identical.
  - **Android** - a JNI FFI (`crates/mobile-ffi`, cdylib) that drives the tunnel
    off a `VpnService` file descriptor, with a `VpnService.protect()` upcall so
    carrier sockets bypass the tunnel; a reference `VpnService` and a cargo-ndk
    build. (`OsTun::from_fd` adopts the OS fd; no OS-route installation on mobile.)
  - **iOS** - a C ABI plus an `NEPacketTunnelProvider` packet-flow bridge
    (callback-driven `ChannelTun`), packaged as an XCFramework; a reference Swift
    provider. Design + skeleton: building the XCFramework needs only a macOS runner,
    but device install/TestFlight needs an Apple Developer account.
  - **MIPS routers** are documented as deferred - no `rust-std` on the pinned
    stable toolchain and `ring` has no MIPS backend - with a recipe for a future
    nightly "lite" build. See `docs/building.md`, `docs/building-android.md`,
    `docs/building-ios.md`.
- **Multi-hop onion telescoping - live, up to 3 hops, both directions.** A client
  now builds a real onion circuit through an entry bridge plus one or two further
  hops (`select_circuit_extra_hops`), telescoping with `CMD_EXTEND`; each extended
  hop authenticates the client with its OWN capability token (token-bearing Noise
  msg-3 in `CMD_EXTEND_FINISH`, verified against the shared replay set) before it
  serves - so one bridge's token does not unlock the relay fleet. The bridge side
  detects an inbound relay leg by matching the peer's authenticated static key
  against a `relay_peers` allowlist and flips that session into relay mode; the
  entry dials the next hop through a `SessionNextHopDialer` (SSRF-guarded). A deep
  hop returns its `CMD_EXTENDED` reverse-wrapped through the onion so intermediate
  hops can forward it. Proven end-to-end by 2-bridge (9000 B) and 3-bridge (7000 B)
  DATA round-trip tests and a 5-attacker adversarial pass (nonce-reuse, token-gate,
  blind-forward, fragmentation-overflow, seq-accounting) that returned zero
  findings. With hops run by DIFFERENT operators, no single bridge sees both who
  you are and where you're going.
- **Idle-period cover traffic (cover-fetch driver).** Opt-in via `cover_destinations`:
  during idle periods the client connects to its own SOCKS listener as a local
  client (byte-identical to a browser), CONNECTs a decoy host through the tunnel,
  and performs a REAL end-to-end HTTPS fetch (browser webpki roots), discarding the
  response. Because it rides real bytes it can never emit a wrong synthetic byte
  distribution - unlike naive record-size shaping, which the flow classifier
  measured can backfire. Bounded by a configurable cover-share cap.
- **Hidden-service descriptor sealing** (`crates/onion/src/seal.rs`). Closes the
  publication-plane fingerprint: an encoded onion descriptor began with the
  cleartext `"MI"` magic + fixed layout, a passive-scraper tell. Descriptors are
  now ChaCha20-Poly1305-sealed under a key derived from `BLAKE3(service_pk, epoch)`
  before they touch any channel (`publish_descriptor` seals, `resolve_descriptor`
  unseals), so a scraper holding only the info-hash sees random bytes while a
  client with the `.mirage` address re-derives the key. (The interactive
  rendezvous plane - intro/rendezvous bridge roles, service daemon, client
  resolver - remains future work; this is the descriptor plane only.)
- **Predictive entropy-DPI steering (a self-adversary prior on transport
  selection).** *Honest framing:* this is a static per-transport prior, not the
  live "grades its own egress" closed loop an earlier draft implied - the client
  runs the classifier on a representative wire-character per transport, not on
  tapped wire bytes (a live per-flow tap is the follow-up that would make it
  adaptive). The adaptive router learned
  only from dial *outcomes*: a transport that connects scored well, one that got
  blocked scored badly - reactive, so by the time the block arrives the client has
  already been fingerprinted. Now the client runs a censor's **own**
  fully-encrypted-traffic classifier (Wu et al., USENIX Security 2023 - the GFW's
  entropy-DPI heuristic) against each transport's first-packet egress character
  and folds a **predictive** negative reward into the per-network EXP3 selector, so
  a carrier that frames Noise/obfs directly on TCP (a uniformly-random first packet
  entropy-DPI blocks on sight) is dispreferred in favour of TLS/HTTP-wrapped
  carriers - *before* it is blocked. No upstream circumvention tool grades its own
  egress this way. Three dampers keep the feedback loop from oscillating (the risk
  a naive coupling would hit): an EWMA over samples, a min-sample hysteresis gate,
  and a bounded penalty that floors the reward multiplier so a flagged transport
  stays explorable rather than being abandoned (a censor's entropy rule can lift).
  Keyed per network, matching the router's per-network state. The current wiring
  feeds the classifier a representative first-packet *character* per transport (a
  predictive prior, correct for every transport today); a live per-flow tap that
  makes it fully adaptive is a follow-up - the dampers are in place for it.
- **Length-*sequence* measurement for the flow-shape distinguisher, plus an
  opt-in conditional record-length process.** The `mirage-adversary` flow
  classifier gained **sequential** features (lag-1 autocorrelation, mean run
  length, size-repeat fraction) - it previously scored only the marginal size
  histogram, so it could not see the length-*sequence* structure TLS-in-TLS
  detectors (Xue et al., USENIX '22/'24) key on. With them it now measures that a
  record shaper drawing sizes i.i.d. reproduces the marginal but leaves ~zero
  autocorrelation. A first-order Markov record-length process
  (`SplitSource::Markov`) that correlates consecutive sizes into runs is available
  as an **opt-in** for a deployment that has calibrated a profile to a capture of
  its cover. It is **not the default**, and this is a corrected claim: measurement
  shows a first-order single-stickiness chain only helps against a cover whose
  run-length law it matches - against a *bimodal* cover (short interactive bursts
  + long bulk runs, which is what real TLS is) it is *worse* than the i.i.d. draw,
  because its uniform geometric autocorrelation is itself a signature real traffic
  lacks. The i.i.d. CDF remains the shaper default; genuinely closing the sequence
  gap for real traffic needs a capture-calibrated phase-state model, tracked as a
  residual. (The marginal-preservation property `(1-a)*π + a*I => π` and the
  distinguisher's new features are both genuinely useful and retained.)
- **Epoch-ratcheted Reality anti-probe (closes pubkey-only bridge enumeration
  for invite-reached bridges; opt-in, and not yet possible for cohort bridges).**
  The Reality carrier's auth probe MAC keyed off the bridge's X25519 static key,
  whose *public* half is published in the signed announcement broadcast on public
  discovery channels (Nostr/DNS-TXT/CT). A censor who scraped one announcement
  could forge a valid probe and permanently confirm the IP is a Mirage bridge -
  with no invite or token (the same structural weakness as REALITY short-IDs). The
  probe MAC now additionally binds a **per-epoch secret** derived from a per-bridge
  root delivered only in the authenticated **invite**
  (`INVITE_EXT_REALITY_PROBE_ROOT`, mirroring the existing QUIC-obfs-secret
  extension) and re-derived by the bridge from its static secret - so scraping an
  announcement no longer confirms a bridge. The epoch index is read from the
  probe's own timestamp on both sides, so this adds **zero wire bytes** and needs
  no negotiation. **The guided single-bridge deploy closes the hole automatically:**
  `mirage-setup` writes `reality_probe_accept_legacy: false` into the new bridge
  config - its bridge is reached only via the invite it mints (which carries the
  root), so no legacy-probe clients can exist. **Everything else stays seamless:**
  the daemon default is the permissive `true` (so clients holding pre-extension
  invites, and clients reaching a bridge via the cohort service - who hold no
  per-bridge invite for it - keep working), and the bridge logs a startup warning
  that the hole is open until the operator flips the flag. Set it `false` only for
  a bridge whose clients are **all** invite-reached; a cohort-reached bridge must
  keep `true` until per-bridge roots can propagate confidentially through the
  cohort service (a follow-up). An all-zero root is byte-identical to the legacy
  probe. Operators provision nothing new: the root derives from the bridge key the
  mint already holds.
- **Transparent system-wide VPN (TUN mode).** A new `mirage-tun` crate adds a
  userspace IP stack (built on `smoltcp`) that terminates **every** TCP and UDP
  flow off an OS TUN device and tunnels it through Mirage - so all traffic
  (including DNS and QUIC/HTTP-3) is protected with **no per-app proxy config**,
  not just SOCKS5-aware apps. Build the client with `--features tun`, set
  `"tun_enabled": true`, and run with `CAP_NET_ADMIN`. The SOCKS5 listener still
  runs alongside. TCP flows ride the carrier pool; UDP flows reuse the existing
  UDP-over-Mirage relay. The netstack is bounded against memory-DoS (per-flow
  write caps, socket timeouts, SYN-flood flow caps) and keeps the
  `#![forbid(unsafe_code)]` guarantee (the only `unsafe`, the TUN `ioctl`, lives
  in the `tun` dependency behind the feature).
- **Per-hop capability-token verification for multi-hop circuits.** Extended
  (relay) hops now verify the client holds a valid capability token for *that*
  hop - via a token-bearing Noise message-3 delivered in `CMD_EXTEND_FINISH` and
  checked with `read_message_3` + the shared replay set - before the hop will
  exit-dispatch or extend further. This closes an authorization gap where a token
  for the entry bridge could have been leveraged to use any bridge as a relay. A
  production bridge-to-bridge dialer (`SessionNextHopDialer`) establishes the
  authenticated relay leg and refuses private/loopback/reserved next-hop
  addresses (SSRF guard). The relay engine remains disabled unless explicitly
  configured.
- **Gecko/Salamander QUIC obfuscation is now on by default.** The hysteria2 and
  h3 carriers previously shipped a raw `quinn`/`rustls` QUIC handshake unless the
  operator set a `quic_obfs_password` - a parseable, non-browser QUIC fingerprint
  on the wire (a captured session showed the ClientHello, transport parameters,
  and cover SNI in the clear). When no password is configured, client and bridge
  now derive the same per-bridge obfs key from the bridge's X25519 static pubkey
  (the same public material both already hold, exactly like the per-bridge cover
  SNI), so the QUIC header + ClientHello are XOR-scrambled and handshake packets
  fragmented by default. A `quic_obfs_password` still upgrades this to a
  secrecy-grade shared key. **Wire-compatibility note:** a new client and an old
  bridge (or vice versa) no longer interoperate on the QUIC carriers - rebuild
  both ends.
- **DHT announcement publishing.** `mirage-publish` gained `--dht` (and
  `--dht-bootstrap host:port`) to announce on the BitTorrent mainline DHT
  (BEP-44) alongside or instead of Nostr relays. Unlike a relay list, the DHT has
  no fixed server to enumerate and block; clients already fetched from it, and
  `mirage-setup` now enables it by default. At least one channel (`--dht` and/or
  `--relay`) is required.
- **`mirage-setup` prompts for every transport and discovery method.** Added
  prompts for the meek (CDN-fronted) and WebRTC carriers and for mainline-DHT
  discovery/announcement, in both the new-deployment and client-from-invite
  flows. The generated invite now advertises the hysteria2, meek, and WebRTC
  capability bits (hysteria2 was previously missing from the cap set).
- **Stream multiplexing - the browser now actually works.** Previously every
  local connection opened its own bridge session: a full Noise+ML-KEM handshake,
  a single-use capability token, and a bridge per-IP concurrency slot *per
  connection*. A browser opens 100-300 parallel connections to load one page, so
  it exhausted the ~8-token bootstrap pool, blew through the bridge's per-IP
  concurrency cap (32) and rate limit (60/min), and most connections failed -
  while a single `curl` sailed through. Mirage now multiplexes many streams over
  a small pool of long-lived carriers (`mirage-mux`'s new async driver wraps the
  authenticated session; one carrier serves up to 200 streams), so one user
  costs **O(1)** handshakes / tokens / per-IP slots instead of O(connections).
  Per-stream flow control (64 KiB windows), TCP half-close propagation
  (`EndLocal`), and reset-on-drop are all handled by the driver. On by default
  (`stream_mux_enabled`, both ends must match - like padding); a client tags a
  mux carrier with a `0x00` session byte, and the legacy single-request SOCKS
  path (`0x05`) is byte-for-byte unchanged, so it is fully backward compatible.
- **Connection observability.** The management API (`/api/status`,
  `/api/bridges`), `mirage-client status`, and the GUI now surface live mux
  carrier + stream counts (aggregate and per-bridge) alongside the existing
  per-transport learned success/failure - so an operator can see the healthy
  "few carriers x many streams" state and which transport is winning on this
  network at a glance.
- **`mirage-bridge --doctor`** - an operator preflight: everything
  `--check-config` reports, plus **active** self-tests that the bridge can reach
  the internet (else it can't proxy) and that each configured Reality cover host
  is real and reachable (a fake/unreachable cover is both a fingerprint and
  breaks the auth-probe fallback).
- **TCP keepalive on long-lived carriers.** Now that one mux carrier is held
  open across many streams, an idle carrier could be silently dropped by an
  on-path NAT / stateful firewall; keepalive keeps that middlebox state alive
  and turns a dead bridge into a prompt error (carrier pruned) instead of the
  next connection paying a full timeout.
- **`mirage-client doctor <config | mirage://invite>`** - a connectivity
  preflight for end users. It validates the config/invite, checks the local
  SOCKS port is free, and **live-tests whether each bridge is actually
  reachable**, with plain-language hints - separating "bad config" from "config
  is fine but the bridge/network is unreachable," the two failure modes that
  used to look identical. Output is log-free (tracing now initializes only on
  the daemon path, so `status`/`doctor`/`--check-config` stay clean).
- **`mirage-bridge --check-config`** now reports the `padding` and `stream mux`
  toggles (which must match the client's settings) and whether the bind port is
  actually available (distinguishing "in use" from "needs privileges"), so a
  mismatched or unbindable operator setup is obvious before launch.
- **WebRTC transport is now a real, browser-faithful carrier.** Mirage vendors a
  patched `webrtc-dtls` fork (`third_party/webrtc-dtls`) so the DTLS 1.2
  ClientHello is byte-indistinguishable from Chrome/libwebrtc: the exact 11-suite
  cipher list, `ChaCha20-Poly1305` (RFC 7905) implemented and negotiable, the
  9-entry `signature_algorithms` as raw `SignatureScheme` codes (incl. RSA-PSS),
  X25519-first groups, the 6 real extensions permuted per-connection, a fully
  random 32-byte ClientHello Random (no `gmt_unix_time` leak), record-layer
  version `0xfeff`, and Chrome-shaped ICE credentials + optional cover audio.
  Validated against `openssl s_server` (ChaCha20 + AES-128-GCM interop) and a
  full SOCKS-over-WebRTC Podman e2e that asserts the on-wire ClientHello.

### Changed
- **Every transport is compiled into the standard build - no more `--features`
  flags.** The WebRTC carrier (previously behind `--features webrtc`) and the
  real mainline DHT backend (previously behind the `mainline` feature) are now
  always compiled; which transports and discovery channels are active is chosen
  in config, prompted by `mirage-setup`. This pulls the webrtc-rs stack (~50
  crates) into the default build - a deliberate trade of build size for
  "everything is promptable, nothing is hidden behind a build flag."
- **`mirage-setup` no longer pins a Reality CertVerify key in the invite.** The
  bridge it generates runs ephemeral Reality, so a pinned key was orphaned and
  every handshake failed `CertVerify signature invalid`; setup now matches
  `mirage-keygen` and leaves it unpinned. It also rejects a wildcard (`0.0.0.0` /
  `::`) public address, which is a bind-only placeholder no client can dial.
- **Reality identity migrated to ECDSA P-256.** The ephemeral cert and TLS 1.3
  `CertificateVerify` now use `ecdsa_secp256r1_sha256` (0x0403) - the scheme
  every desktop browser signs with - instead of Ed25519 (0x0807, a JA4 tell no
  browser produces). `signature_algorithms` in all three fingerprint templates
  now byte-match the mimicked browser. The invite's `tls_cert_verify_pk` grew to
  a 33-byte compressed-SEC1 point (wire-format change).
- Discovery rendezvous names/tags are now key-derived, not fixed strings: the
  DNS-TXT `_mirage.` label and `mchunk/` record tag are gone (the epoch label is
  already un-enumerable), and the Nostr event `kind` is derived per-epoch across
  the `30000-39999` parametric-replaceable window instead of the constant
  `30303` - so no single relay filter enumerates all Mirage announcements.
- meek/DoH now rotate a full, internally-consistent browser persona per
  connection (complete `sec-ch-ua`/`Accept-*`/`sec-fetch-*` header set, not a
  frozen `Chrome/126` UA) and jitter the idle poll cadence with exponential
  backoff instead of a metronomic 200 ms. The MASQUE benign-probe `404` and the
  `transport-pad` chaff cadence were likewise de-signatured. The default meek
  path is now `/` (never the project-identifying `/mirage`).

### Fixed
- **Reverse bulk data over a circuit was silently dropped.** The exit dispatcher
  reads up to 4 KiB per upstream read, but the reverse path wrapped each read into
  a single onion sub-cell - any response chunk larger than the cell payload cap
  blew `Cell::new` and was discarded, so a multi-hop circuit could complete its
  handshake yet fail to deliver a real web page. Reverse DATA is now chunked to
  `MAX_REVERSE_RELAY_DATA_BYTES` (a size that survives re-wrapping at every hop up
  to `MAX_CIRCUIT_HOPS`); the 2-hop e2e now round-trips 9000 bytes both ways.
- **Onion `Circuit` used a single sequence counter for all hops**, which desynced
  a telescoped exit's AEAD nonce (each bridge hop counts only the cells it sees,
  and the exit never sees the deep-EXTEND construction cells). Now per-hop
  counters, sealed/opened layer-by-layer. Wire-identical for 2-hop; required for 3.
- **Connection-resiliency hardening** (surfaced while diagnosing the browser
  failure above): the bridge's SOCKS/mux upstream `connect` now bounds DNS
  resolution with a timeout (a slow resolver could hang a connect indefinitely);
  the client's local SOCKS negotiation is time-bounded so a half-open app socket
  can't park a task/fd forever; `pick_entry` falls back to the least-recently-
  failed bridge instead of returning "no healthy bridge" (a single bad round no
  longer blacks out every connection for the full 30 s backoff); and the client
  reaps idle mux carriers down to one warm spare so a browsing session doesn't
  hold several bridge sessions open. The padding layer (`PaddedStream`) now
  surfaces a `BrokenPipe` when its carrier is dead (it used to report phantom
  write success forever) and flushes a real FIN on close so TCP half-close
  reaches the peer.
- **Client GUI usability:** the invite field is now a width-bounded single-line
  box (a long `mirage://` invite scrolls horizontally instead of wrapping and
  filling the whole window), with a one-click clear button; the Start/Stop Proxy
  control is pinned to an always-visible bottom bar and the main body scrolls, so
  the action button can no longer be pushed off-screen and out of reach.
- **Reality advertised AES-128-GCM but encrypted with ChaCha20-Poly1305** - a
  self-inconsistent handshake that a real TLS 1.3 client fails to decrypt (both a
  correctness bug and a distinguisher). The ServerHello now advertises the
  ChaCha20 suite the record layer actually uses.
- **DoS bounds:** dnstt now caps + idle-evicts its pre-auth session table and
  spawned tasks and bounds the reliable-stream reorder buffer; the MASQUE h3
  client no longer leaks a `quinn::Endpoint` (UDP socket + driver task) per dial;
  `SeenNonceSet` eviction is amortized O(1) instead of an O(n) scan on every
  insert; the AES-CBC DTLS record decrypt validates length before slicing.
- **Auth hardening:** the mux obfs-tcp knock now has the same replay gate as its
  SS-2022 sibling (a captured knock no longer confirms the bridge to an active
  prober); VLESS UUIDs are compared in constant time; the dnstt DNS transaction
  ID is drawn from the CSPRNG instead of a `1,2,3,...` counter.

### Removed
- **The `anon-creds` crate is deleted.** It was a 213-line scaffold whose every
  operation returned `NotImplemented`, with zero dependents - a dead stub that
  implied a shipped feature. The genuinely-novel receipt-free-vouching crypto it
  gestured at lives, built and tested, in `crates/crypto/src/dvs.rs`.
- **The CT-log (crt.sh) rendezvous discovery channel is deleted.** The
  `discovery-ct` crate and the `ct_rendezvous` codec were an unwired dead end
  (no client, publisher, or bridge ever used them) and depended on crt.sh, which
  is flaky and unreliable. Discovery is Nostr + DNS-TXT + mainline DHT.
- The orphaned `transport-hls` crate (dropped from the build in a prior release
  but left on disk) is deleted, along with all now-dead Ed25519 Reality-cert code.
- **The `SPEC/` folder and the `mirage-conformance` crate are gone.** The spec
  had drifted ~30% from the source tree (an orphaned obfs4 transport doc; no spec
  for the shipped dnstt / DoH / stream-mux / padding pieces; a stale `v0.2`
  roadmap; a failing hand-maintained `v0.1w` golden vector) and its conformance
  gate mostly caught its own drift. The source tree is now the single source of
  truth. `mirage-spec` is kept (it's the protocol-constants crate) but no longer
  BLAKE3-hashes a spec directory at build time.

### Security
- **Traffic-analysis / active-probing hardening (validated red-team of the
  circumvention surface).** Nine findings across timing, probing, packet
  structure, and flow correlation were adversarially validated; the confirmed,
  worthwhile ones fixed:
  - **Behavioural-fingerprint decorrelation.** The client's periodic bridge
    re-probe was a fixed 60 s, single-burst fan-out (a metronome no app emits);
    it is now a jittered 45-90 s period with per-bridge staggered probes, and the
    carrier TCP keepalive is jittered per-connection instead of a constant 25/15 s.
  - **Reality record-size distribution re-calibrated to a REAL capture.** The
    `browser_https` profile was hand-guessed and materially wrong (28 % of records
    at 1024 B vs 2 % measured; 10 % full-size vs 26 % measured). Re-derived from a
    tcpdump/tshark capture of real CDN HTTPS (`tls.record.length`), and guarded by
    a test asserting the shipped CDF stays within TVD 0.03 of the measurement.
  - **Hysteria2 plain-QUIC probe response.** A wrong-knock probe to a plain-QUIC
    Hysteria2 bridge (ALPN `h3`) now receives a plausible nginx `404` (the same
    defense the MASQUE carrier has) instead of a silent drop that a scanner could
    distinguish from a real HTTP/3 origin.
  - Corrected an over-claim in the padding docs ("defeats ML flow fingerprinting")
    to an honest, scoped statement, and added a marginal-preserving phase-state
    record shaper as an opt-in (i.i.d. remains the default; a sequence model is
    not shipped as default without a capture-calibrated certification).
- **Multi-round adversarial re-audit of the whole codebase.** Further
  hypercritical passes fixed, each with a regression test: a **pre-auth remote
  DoS** in the vendored DTLS stack (unbounded handshake-fragment recursion ->
  stack overflow, now iterative + count-bounded) and an out-of-bounds
  ClientHello/ServerHello extension parse (remote panic); a **stale-index race**
  in the multi-entry bridge pool (a reaped entry could mis-attribute a failure -
  now a stable handle); an **unbounded split-exit stream map** (Open-and-never-
  closed streams could exhaust memory - now capped); a **DoH request that carried
  a session cookie** no real stateless resolver sends (removed; the bridge now
  correlates DoH sessions without it); a **missed wakeup** in the circuit pool's
  backpressure wait; and an O(n) eviction scan in the probe detector (now a
  bounded approximate-LRU). Earlier rounds hardened the DPI/state-adversary
  surface across every transport (see the DPI items above).
- **Pre-deployment adversarial vet** (5 threat-model dimensions: connectivity,
  passive distinguishers, DoS, crypto/auth, deanonymization) - 12 confirmed
  findings, fixed in place:
  - *Deanonymization:* the UDP-relay path no longer logs the client's
    destination (it ignored `anonymize_target_logs`); the circuit-relay client
    no longer logs the browsing destination; and a VLESS UUID over a **Raw**
    (unencrypted) carrier - a static cleartext cross-session tracking handle - is
    now refused at config load (VLESS must ride an encrypted carrier).
  - *Fingerprint:* padding is gated OFF on the Reality path (its TLS
    `RecordShaper` is the sole size/timing owner; stacking `PaddedStream` emitted
    a power-of-two record comb + chaff beacon *inside* the TLS flow); the
    WebSocket `Upgrade` now carries a full rotating browser header persona
    (User-Agent / Origin / Accept-\* / client-hints / permessage-deflate) instead
    of being a UA-less anomaly.
  - *Connectivity / DoS:* an oversized UDP datagram is now dropped, not used to
    tear down (and no longer truncated) an entire relay direction; the legacy
    (non-mux) SOCKS/HTTP-CONNECT byte pumps use the idle-aware copy so a dead
    tunnel can't pin a concurrency slot forever; the dnstt DNS-name decompressor
    is bounded to `MAX_NAME` output (was an unauthenticated decompression bomb).
  - *Crypto:* cohort-gossip signatures now verify with `verify_strict`
    (canonical, non-malleable), matching the rest of the codebase.
  - **Known follow-up (flagged, not a ship-blocker):** the Reality *server*
    negotiates plain X25519 + ChaCha20 while the client ClientHello byte-mimics
    modern Chrome (X25519MLKEM768 first + AES-128-GCM offered) - a cleartext PQ/
    cipher downgrade tell. The correct fix is to implement the X25519MLKEM768 key
    schedule + an AES-128-GCM record path on the bridge; a fingerprint-degrading
    interim was declined.
- 40-finding adversarial audit swept every transport + the discovery, session,
  and daemon crates for hardcoded signatures and fragile code; the confirmed
  findings are fixed above. Honesty corrections where a full fix is deferred:
  the hysteria2/ws/obfs "knock" tokens are documented as cheap public-key-gated
  filters (the real auth is the inner Noise handshake), hysteria2 congestion
  control is documented as stock BBR (not loss-immune BRUTAL), and the
  pre-integration crates (`migration`, and the `onion` rendezvous plane)
  are clearly marked not-on-a-live-path so they cannot be mistaken for shipped
  controls.
- keygen-generated Reality configs now carry a `REPLACE-WITH-REAL-CDN-HOST.invalid`
  cover-host sentinel and the bridge **fails closed** on a placeholder/reserved
  cover host, so an operator cannot accidentally front an obviously-fake site.
- **Clock-skew / NTP-poisoning defense is now wired.** The client runs a
  one-shot startup clock pin (`mirage-time`): it gathers HTTPS-`Date` readings
  from the hosts it already contacts (its nostr relays / DoH / meek fronts - an
  ordinary `GET /`, so no new hardcoded-host signature), takes a median
  consensus, and corrects (or, on a gross skew only < 3 sources could confirm,
  refuses) the discovery-epoch clock - so a poisoned OS clock can no longer
  silently land the client on the wrong, empty epoch.

## [0.1.0-alpha.2]

### Added
- **Adversarial routing-entropy engine** (`mirage-transport::adaptive`) - the
  client selects transports with an EXP3 adversarial bandit rather than a
  deterministic order, so the choice is a high-entropy distribution a reactive
  censor cannot pre-empt. Warm-started from the success-rate history, with an
  EXP3.S recovery floor and a diversity guard that caps any one transport's
  selection share (anti-enumeration). Wired into the client's dial loop.
- **Collaborative censorship-posture** (`mirage-transport::posture_net`) - a
  poisoning-robust, Sybil-resistant estimate of what the local network is doing
  to each transport bearer class, aggregating first-hand and (trusted) peer
  observations via a weighted median. Includes a gossip wire codec
  (`PostureReport`). Feeds the routing engine's bearer-class gate.
- **Per-network fingerprinting** (`mirage-transport::netfp`) - routing and
  posture state is now scoped to the network the client is actually on (stable
  across DHCP, flips when the user changes networks).
- **Reactive-censor adversary** (`mirage-adversary::adaptive_routing`) - a new
  adversary class that models a strategic censor and makes "routing resists an
  adaptive censor" a measured, CI-gated property.
- Sigstore build-provenance attestation on release artifacts.

### Changed
- Reality ClientHello now emits the full modern-Chrome extension set (session
  ticket, status_request, SCT, compress_certificate, ALPS), GREASE in the first
  and last extension slots, and a per-connection shuffled extension order.
- Session handshake messages are now length-prefixed and randomly padded, so the
  fixed 1221/1189/203-byte triplet no longer forms a constant size signature.
- ss2022 and VLESS handshakes are 0-RTT (no standalone server-response round
  trip); ss2022 reads its deferred server response on the first stream read.
- meek/DoH requests/responses carry a browser `User-Agent`/`Accept` and a
  `Date`/`Server` persona; the HTTP/3 carrier answers a benign probe with a
  plausible `404` instead of hanging.
- WebSocket auth is carried as an ordinary `subprotocol, bearer-token` offer;
  hysteria2/h3 default cover SNIs are derived per-bridge instead of a reserved
  `cdn.example.com`.

### Removed
- The **obfs4** carrier was removed; its niche is covered more soundly by
  Shadowsocks-2022. Capability bit 6 is reserved and never reused.

### Security
- Broad DPI/state-adversary remediation across all transports; `#[must_use]` on authentication/replay predicates so a dropped
  result can never silently accept an unauthenticated peer.
- **Client-IP log anonymization** (`anonymize_client_logs`, default on): the
  bridge no longer writes raw client IPs to logs - a per-run-salted, irreversible
  `client-xxxxxxxx` label is logged instead, so a seized bridge log cannot reveal
  which clients connected.
- The client no longer logs the user's destination at INFO in the circuit-relay
  path (a seized client device must not be a record of where the user went), and
  warns loudly if its local SOCKS proxy is bound to a non-loopback (open-proxy)
  address.
- Bridge/client config structs no longer derive `Debug`, so a stray
  `debug!(?config)` can never dump the master secret keys / PSK / token; the
  SS-2022 PSK derivation buffer is now zeroized.
- Release artifacts carry a keyless Sigstore build-provenance attestation, and
  the release workflow refuses to publish while any "fill before publishing"
  placeholder (security contact, verification owner) remains.

## [0.1.0-alpha.1]

Initial public pre-release: the client, bridge, keygen, and publisher binaries;
the Reality / Hysteria2 / HTTP-3 / Shadowsocks-2022 / WebSocket / VLESS / meek /
DoH / dnstt transports; the post-quantum Noise session layer; DHT / Nostr /
DNS-TXT discovery with cohort, refresh, and claim tokens; and the multi-hop
relay engine. See the per-crate module docs for the design.

<!-- Maintainers: add version-compare links here once the forge/repo URL is
     fixed, e.g. [0.1.1-alpha.2]: https://<forge>/<org>/mirage/releases/tag/... -->

