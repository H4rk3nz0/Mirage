//! HTTP/3 transport carrier for Mirage.
//!
//! # Status: LIVE HTTP/3 carrier (the [`h3`] module)
//!
//! This crate ships a WORKING `quinn`-based HTTP/3 carrier ([`h3`],
//! [`h3::h3_client_connect`]), wired into the client as `TransportMode::H3`: it
//! opens a real QUIC + HTTP/3 connection to the bridge, presents a byte-
//! identical nginx-style cover, and can XOR-obfuscate datagrams (Salamander).
//! Also shipped: the `QUIC_MASQUE` capability bit and the
//! [`build_connect_udp_path`] path builder + host validation.
//!
//! # NOT built (deliberately): full RFC-9298 MASQUE
//!
//! A true MASQUE CONNECT-UDP transport - proxied through a third-party CDN that
//! forwards UDP datagrams to the bridge - is NOT implemented, and a dead stub
//! that used to sit here was removed. Rationale: it adds only marginal cover
//! over the shipped h3 / hysteria2 / webrtc menu while introducing a worse trust
//! model (an external proxy that sees datagram boundaries) and an external CDN
//! dependency. The wire-format notes below describe RFC 9298 for reference only;
//! the live carrier speaks HTTP/3 to the bridge directly, not through a proxy.
//!
//! # Why MASQUE in Mirage
//!
//! MASQUE rides "HTTP/3 to a CDN tenant" - the canonical
//! T2-collateral-cost asymmetry. A nation-state that blocks
//! HTTP/3-to-Cloudflare breaks every modern web property; the
//! cost-of-blocking is high enough that even motivated censors
//! defer.
//!
//! # Wire format
//!
//! The Mirage session layer rides
//! inside a CONNECT-UDP capsule per RFC 9298. From a wire-shape
//! perspective the connection looks like:
//!
//! 1. Client opens a QUIC connection to the MASQUE proxy
//!    (operator-deployed CDN-fronted endpoint).
//! 2. Client issues `:method = CONNECT`, `:protocol =
//!    connect-udp`, `:scheme = https`, `:path =
//!    /.well-known/masque/udp/<bridge-host>/<bridge-port>/`.
//!    The bridge-host is the **Mirage bridge** the proxy will
//!    forward UDP datagrams to (announcement endpoint).
//! 3. Proxy responds `:status = 2xx`; from then on, HTTP/3
//!    DATAGRAMs / capsules carry UDP payloads to the bridge.
//! 4. The Mirage session layer treats the capsule stream as a
//!    duplex byte stream (concat-and-frame at the [`UdpFramer`]
//!    layer for length-prefixing).
//!
//! [`UdpFramer`]: mirage_session::udp_frame::UdpFramer
//!
//! # Why `connect-udp` (and not `connect`/`connect-ip`)
//!
//! - `CONNECT` (RFC 7231): TCP-to-host proxying. Wire-shape is a
//!   regular HTTP/2/3 request, but the entire Mirage flow is
//!   visible to the proxy operator at the byte level - no
//!   defense in depth beyond TLS.
//! - `connect-udp` (RFC 9298): UDP-via-HTTP/3-DATAGRAM. The proxy
//!   only sees datagram boundaries; the inner session is opaque
//!   AEAD'd Mirage frames. **This is what we use.**
//! - `connect-ip` (RFC 9484): full L3 IP tunneling. Heavier; gives
//!   no benefit over `connect-udp` for our session-over-UDP
//!   pattern.
//!
//! # Operator deployment story
//!
//! An operator running a Mirage bridge with MASQUE support deploys:
//! 1. The bridge daemon listening on a UDP port (Mirage frames over
//!    UDP via [`UdpFramer`]).
//! 2. A MASQUE proxy (e.g., open-source `masque-h3` or a Cloudflare
//!    Worker) on a CDN-fronted endpoint, configured to forward
//!    UDP traffic for a specific path/authority to the bridge's
//!    UDP port.
//! 3. An announcement with `transport_caps |= QUIC_MASQUE`,
//!    `endpoint = Domain { domain: "<masque-proxy-host>", port: 443 }`.
//!
//! Clients that speak `QUIC_MASQUE` see the announcement, dial the
//! MASQUE endpoint over QUIC + HTTP/3, request CONNECT-UDP to the
//! bridge, and the rest is the standard Mirage session protocol.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

/// HTTP/3 (QUIC) carrier: the real transport core (quinn + HTTP/3 framing).
pub mod h3;

/// Capability bit for MASQUE (bit 1).
/// Re-exported from `mirage_discovery` here for callers that only
/// pull in the transport crate.
pub const QUIC_MASQUE_CAPABILITY_BIT: u32 = 1 << 1;

/// Default ALPN value the QUIC layer negotiates.
/// RFC 9114 §3.1 says `h3` for HTTP/3.
pub const QUIC_ALPN_H3: &[u8] = b"h3";

/// Default `:protocol` value for the extended-CONNECT request that
/// upgrades to UDP-over-HTTP/3 datagrams (RFC 9298 §3).
pub const MASQUE_PROTOCOL_CONNECT_UDP: &str = "connect-udp";

/// Errors produced by MASQUE-side helpers.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MasqueError {
    /// `bridge_host` failed validation. RFC 9298 §3 path-templates
    /// embed the host as a literal segment, so anything that isn't
    /// a hostname-or-IP-literal would let the caller smuggle path
    /// components, query strings, or `..` traversal into the URL -
    /// a DNS-rebinding / path-injection vector. Rejected at build
    /// time so a hostile announcement can't redirect the proxy.
    #[error("invalid bridge_host: {reason}")]
    InvalidBridgeHost {
        /// Human-readable reason (no host content embedded).
        reason: &'static str,
    },
}

/// Construct the canonical `:path` template for the CONNECT-UDP
/// request that targets `(bridge_host, bridge_port)`. Mirrors
/// RFC 9298 §3 path-template form.
///
/// Returns `/.well-known/masque/udp/<bridge_host>/<bridge_port>/`
/// (the trailing slash is required by §3 path-template syntax).
///
/// `bridge_host` MUST be either:
/// - an LDH hostname (`a-z`, `A-Z`, `0-9`, `-`, `.`) of length 1..=253
///   with no leading/trailing dot and no `..` sequences, OR
/// - an IPv4 dotted-quad, OR
/// - an IPv6 literal in `[...]` form (RFC 3986 §3.2.2).
///
/// Rejected: `/`, `?`, `#`, `%`, whitespace, control characters,
/// empty string. Without this validation, a hostile `bridge_host`
/// like `evil.com/?x=` would let a tampered announcement smuggle
/// arbitrary `:path` content past the proxy ACL.
pub fn build_connect_udp_path(bridge_host: &str, bridge_port: u16) -> Result<String, MasqueError> {
    validate_bridge_host(bridge_host)?;
    Ok(format!(
        "/.well-known/masque/udp/{bridge_host}/{bridge_port}/"
    ))
}

fn validate_bridge_host(host: &str) -> Result<(), MasqueError> {
    if host.is_empty() {
        return Err(MasqueError::InvalidBridgeHost { reason: "empty" });
    }
    if host.len() > 253 {
        return Err(MasqueError::InvalidBridgeHost {
            reason: "longer than 253 bytes",
        });
    }
    // IPv6 literal form.
    if let Some(stripped) = host.strip_prefix('[') {
        let inner = stripped
            .strip_suffix(']')
            .ok_or(MasqueError::InvalidBridgeHost {
                reason: "IPv6 literal missing closing ']'",
            })?;
        if !inner
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f' | b'A'..=b'F' | b':' | b'.'))
        {
            return Err(MasqueError::InvalidBridgeHost {
                reason: "IPv6 literal contains non-hex/colon characters",
            });
        }
        return Ok(());
    }
    // LDH hostname or dotted-quad IPv4.
    if host.starts_with('.') || host.ends_with('.') {
        return Err(MasqueError::InvalidBridgeHost {
            reason: "leading or trailing dot",
        });
    }
    if host.contains("..") {
        return Err(MasqueError::InvalidBridgeHost {
            reason: "consecutive dots",
        });
    }
    for label in host.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(MasqueError::InvalidBridgeHost {
                reason: "label empty or longer than 63 bytes",
            });
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(MasqueError::InvalidBridgeHost {
                reason: "label has leading or trailing hyphen",
            });
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err(MasqueError::InvalidBridgeHost {
                reason: "label contains non-LDH bytes",
            });
        }
    }
    Ok(())
}

// NOTE (#cut): a dead `MasqueClientTransport` (a `ClientTransport` stub that
// returned "not implemented") and an unused `MasqueOperatorConfig` used to live
// here. They were REMOVED - the live HTTP/3 carrier is the [`h3`] module, wired
// into the client as `TransportMode::H3` via [`h3::h3_client_connect`]. A full
// RFC-9298 MASQUE-CONNECT-UDP-through-a-proxy transport (a third party seeing
// datagram boundaries + an external CDN dependency) is deliberately NOT built:
// it adds marginal cover over the shipped h3/hysteria2/webrtc menu at a worse
// trust cost. This crate's shipped surface is the h3 carrier plus the
// `build_connect_udp_path` path builder + validation.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_bit_matches_registry() {
        assert_eq!(
            QUIC_MASQUE_CAPABILITY_BIT,
            mirage_discovery::wire::transport_caps::QUIC_MASQUE
        );
    }

    #[test]
    fn connect_udp_path_format() {
        assert_eq!(
            build_connect_udp_path("bridge.example.com", 4433).unwrap(),
            "/.well-known/masque/udp/bridge.example.com/4433/"
        );
    }

    #[test]
    fn connect_udp_path_accepts_ipv4_literal() {
        assert_eq!(
            build_connect_udp_path("203.0.113.5", 443).unwrap(),
            "/.well-known/masque/udp/203.0.113.5/443/"
        );
    }

    #[test]
    fn connect_udp_path_accepts_ipv6_literal() {
        assert_eq!(
            build_connect_udp_path("[2001:db8::1]", 443).unwrap(),
            "/.well-known/masque/udp/[2001:db8::1]/443/"
        );
    }

    #[test]
    fn connect_udp_path_rejects_slash_in_host() {
        // Pre-fix this would have silently produced
        // "/.well-known/masque/udp/evil.com/?x=/443/" - the proxy
        // would route to evil.com and the bridge target ends up in
        // the query string. Now it errors.
        let err = build_connect_udp_path("evil.com/?x=", 443).unwrap_err();
        assert!(matches!(err, MasqueError::InvalidBridgeHost { .. }));
    }

    #[test]
    fn connect_udp_path_rejects_traversal() {
        let err = build_connect_udp_path("..", 443).unwrap_err();
        assert!(matches!(err, MasqueError::InvalidBridgeHost { .. }));
        let err = build_connect_udp_path("a..b", 443).unwrap_err();
        assert!(matches!(err, MasqueError::InvalidBridgeHost { .. }));
    }

    #[test]
    fn connect_udp_path_rejects_control_and_percent() {
        for bad in ["host\n", "host ", "host%41", "host?q", "host#f", ""] {
            let err = build_connect_udp_path(bad, 443).unwrap_err();
            assert!(
                matches!(err, MasqueError::InvalidBridgeHost { .. }),
                "expected reject for {bad:?}"
            );
        }
    }
}
