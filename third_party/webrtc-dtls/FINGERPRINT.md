# webrtc-dtls fingerprint patch (Mirage vendored fork)

This is a vendored copy of `webrtc-dtls 0.10.0`, patched so the DTLS 1.2
ClientHello Mirage's WebRTC transport emits is byte-indistinguishable from a
stock **Chrome / libwebrtc (BoringSSL)** WebRTC DTLS ClientHello. It is pulled in
via `[patch.crates-io]` in the workspace root `Cargo.toml`.

## Why this has to be a fork

The DTLS ClientHello is the WebRTC analogue of a TLS JA3/JA4 fingerprint: a
censor can passively classify "this is the Rust webrtc stack, not a browser" from
the cipher-suite list, the supported-groups order, the signature-algorithms list,
the extension set/order, and even the record-layer version — then block it with
zero collateral. Those fields are **hardcoded in `flight1.rs` / `flight3.rs` and
are not reachable from the `webrtc-rs` `SettingEngine` API**, so aligning them
requires patching the crate directly. (`SettingEngine` *does* expose SRTP profiles
and ICE ufrag/pwd — those Mirage sets from its own code, no fork needed.)

## Ground truth

Every claim below is anchored to **real Chrome WebRTC DTLS captures** (the Tor
anti-censorship team's `covert-dtls` corpus + the FOCI 2025 paper "Fingerprint-
resistant DTLS for usage in Snowflake", Midtlien & Palma) cross-checked against
BoringSSL (`ssl/extensions.cc`) and libwebrtc (`rtc_base/openssl_stream_adapter.cc`)
source. Where source-level reasoning and captures disagreed, **the captures win**
(see the GREASE reversal below).

## What is patched (done)

The Chrome fingerprint is emitted only when `HandshakeConfig.offer_chrome_fingerprint`
is set, which `conn::DTLSConn::new` turns on automatically for the default ECDHE
case (`config.cipher_suites` empty **and** no PSK) — exactly how the high-level
`webrtc` crate configures DTLS. Callers that pin suites or use PSK keep upstream
behavior, so the crate's own negotiation/PSK semantics and tests are unchanged.

The shared builder is `flight1::client_hello_body()` (used by both flight1 =
initial and flight3 = HelloVerifyRequest cookie retransmit, so the two ClientHellos
are byte-identical bar the cookie).

1. **Cipher-suite list — exact Chrome 11-suite order, NO GREASE**
   (`cipher_suite::chrome_dtls_cipher_suites`):
   `c02b c02f cca9 cca8 c009 c013 c00a c014 009c 002f 0035` (22 bytes).
   Derived from libwebrtc's `SSL_CTX_set_cipher_list("DEFAULT:!NULL:!aNULL:
   !SHA256:!SHA384:!aECDH:!AESGCM+AES256:!aPSK:!3DES")`. **AES-256-GCM is
   deliberately absent** (`!AESGCM+AES256`). ChaCha20-Poly1305 (`cca9`/`cca8`) is
   fully implemented (RFC 7905, `crypto/crypto_chacha20_poly1305.rs`) and
   negotiable; AES-128-CBC and the static-RSA suites are **offer-only** (marshaled
   for parity, never selected — no `cipher_suite_for_id` arm). The *negotiable*
   set (`default_cipher_suites`) is decoupled from this *offered* list.
2. **signature_algorithms — raw 9-entry list with RSA-PSS + SHA-1 tail**
   (`signature_hash_algorithm::chrome_dtls_signature_schemes`):
   `0403 0804 0401 0503 0805 0501 0806 0601 0201`. The extension
   (`extension_supported_signature_algorithms.rs`) was reworked to carry raw u16
   `SignatureScheme` code points instead of the legacy `{HashAlgorithm(1),
   SignatureAlgorithm(1)}` pairs, which cannot express RSA-PSS (0x08 is not a
   valid HashAlgorithm). Note this is the raw BoringSSL `kVerifySignatureAlgorithms`
   default — it INCLUDES the trailing `rsa_pkcs1_sha1` (0x0201) that the Chrome
   *HTTPS* stack strips but the WebRTC path does not, and EXCLUDES ed25519. These
   are advertised for wire parity only; actual signing uses ECDSA-P256.
3. **Supported groups lead with X25519, NO GREASE group**: `[X25519, P256, P384]`
   = `001d 0017 0018`.
4. **Exactly 6 extensions, NO GREASE, NO SNI**
   (`flight1::chrome_client_hello_extensions`): extended_master_secret,
   renegotiation_info, supported_groups, ec_point_formats, signature_algorithms,
   use_srtp. A P2P DTLS ClientHello never carries `server_name`.
5. **Per-connection extension permutation** (Chrome M120+ Fisher–Yates)
   (`flight1::permute_extensions`): seeded from an INDEPENDENT CSPRNG value
   (`State.ch_ext_perm_seed`, generated once in flight1 and reused by flight3) —
   NOT from the client_random. Seeding from client_random would make
   `order = f(client_random)` for a public `f`, letting a censor recompute the
   order from the wire-visible random and detect us; real Chrome permutes with an
   RNG independent of its random. The cached seed keeps flight1==flight3 without
   the correlation. Our answerer (`flight0`) parses extensions by type,
   order-independently.
6. **Fully-random 32-byte Random** (`handshake_random::populate`): the entire
   ClientHello Random is CSPRNG output with NO embedded `gmt_unix_time`. Upstream
   webrtc-rs stamped `SystemTime::now()` into the first 4 bytes — both a
   fingerprint (differs from every browser) and a clock leak. BoringSSL
   (`ssl_fill_hello_random`) fills all 32 bytes randomly; we now match.
7. **ClientHello record-layer version = DTLS 1.0 (0xfeff)**: the pre-negotiation
   ClientHello record carries 0xfeff (RFC 6347 §4.2.1), while the ClientHello
   *body* `client_version` stays DTLS 1.2 (0xfefd). Upstream webrtc-rs stamped
   0xfefd on every record — a distinguisher on the very first datagram. Both
   flight1 and flight3 use 0xfeff; later flights use 0xfefd normally.

Validated by: `flight1::fingerprint_test` (byte-level ClientHello assertions +
permutation stability), `crypto_chacha20_poly1305::test` (RFC 7905 framing vs an
independent sealing), the ChaCha20 full-handshake case in
`test_cipher_suite_configuration`, and the full 64-test loopback suite.

## The GREASE reversal (read this before re-adding GREASE)

An earlier revision of this fork **injected RFC 8701 GREASE** (a GREASE cipher
0x0a0a, group 0x1a1a, and extension 0x2a2a), reasoning from browser-TLS behavior
and BoringSSL's `grease_enabled` code path. **That was wrong and has been removed.**
Real Chrome WebRTC DTLS captures show **NO GREASE anywhere** — libwebrtc creates
its own DTLS `SSL_CTX` and does not enable BoringSSL GREASE, and Chrome's TCP-TLS
GREASE does not carry over. Emitting GREASE that a real Chrome WebRTC peer never
emits is *itself* a distinguisher. Do not re-add it. (The GREASE *parse* path —
`ExtensionValue::Grease`, `NamedCurve::Grease`, the flight0 skip-filter — is kept
purely defensively, to tolerate a peer that sends GREASE; we never emit it.)

## Residual gaps (NOT yet closed — the honest list)

1. **Record-layer framing for larger/later flights.** `conn/mod.rs` sizes
   handshake fragments off the message body ignoring header/AEAD overhead
   (`split_bytes(&content, mtu)`), and `compact_raw_packets` is a naive `>= mtu`
   datagram flush — both diverge from BoringSSL's overhead-aware, datagram-budget
   packing (and BoringSSL coalesces multiple messages per encrypted record). This
   is **dormant for the ClientHello and the vanilla ECDSA handshake** (every
   message is < 1200 B, so no fragmentation triggers), so it does not affect the
   ClientHello fingerprint — but a full-flight framing histogram would differ.
   Fix when that is in the threat model.
2. **session_ticket (0x0023).** Chrome M124 emits an empty one (→ 7 extensions);
   M133 omits it (→ 6). We emit 6 (M133-like), correct for a no-resumption stack.
   To target an M124-era fingerprint, add an empty `0x0023` into the *permuted*
   set.
3. **use_srtp profile list is 2 of Chrome's 3.** Mirage now explicitly sets the
   DTLS-SRTP profiles (`transport-webrtc::build_api`) to `[AEAD_AES_128_GCM
   (0x0007), AES128_CM_HMAC_SHA1_80 (0x0001)]`. Chrome offers three, led by
   `AEAD_AES_256_GCM (0x0008)`. We cannot add 0x0008: `webrtc-srtp 0.13` cannot
   key AES-256-GCM, and since the answerer selects the first mutually-offered
   profile, offering 0x0008 would get it selected and abort the handshake.
   Closing this needs AES-256-GCM keying support in webrtc-srtp (upstream patch).
4. **Server-side CertificateRequest sig_algs.** The bridge's CertificateRequest
   (`flight4`) still advertises `cfg.local_signature_schemes` as legacy `{hash,sig}`
   pairs (no PSS). It is server→client and far less fingerprinted than the
   ClientHello, but a thorough censor could key on it; rework the CertReq message
   struct to raw u16 for full server-side parity.
5. **Validation is against captures + spec, not a live browser in-sandbox.** The
   byte-level tests here assert against the documented Chrome bytes. To finalize,
   capture Mirage's ClientHello on the wire (`tcpdump`/tshark on a podman run) and
   diff against a real Chrome WebRTC DTLS ClientHello; also interop-test the new
   ChaCha20 AEAD against `openssl s_server -dtls1_2 -cipher
   ECDHE-ECDSA-CHACHA20-POLY1305` (a loopback handshake alone can hide a
   symmetric nonce bug — the reference-vector test mitigates but interop is the
   gold standard).

## Updating the vendored version

If `webrtc`/`webrtc-dtls` is bumped, re-vendor the new `webrtc-dtls` here and
re-apply the patches (search `MIRAGE FINGERPRINT PATCH`). The `[workspace]` marker
at the top of `Cargo.toml` lets this fork be built/tested standalone
(`cargo test` inside `third_party/webrtc-dtls`) without being adopted by the
parent Mirage workspace.
