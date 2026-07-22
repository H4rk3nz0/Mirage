//! Target address carried in a `BEGIN` mux frame's body.
//!
//! The mux layer is destination-agnostic - `BEGIN` just says "open
//! a stream." But the receiving end needs to know the destination,
//! so we encode a SOCKS5-style target inside the BEGIN body. This
//! keeps the wire format compact AND lets the mux layer compose
//! cleanly with the existing SOCKS5 path inside the bridge.
//!
//! Wire format (matches RFC 1928 §4 ATYP field, with one tweak):
//!
//! ```text
//!  Offset  Size   Field
//!  ------  ----   -----
//!  0       1      atyp (0x01 = IPv4, 0x03 = domain, 0x04 = IPv6)
//!  1       var    addr  (IPv4: 4 B; domain: u8 len + bytes; IPv6: 16 B)
//!  ...     2      port  (u16 BE)
//! ```

use thiserror::Error;

/// Errors produced by [`MuxTarget`] encode/decode.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum TargetError {
    /// Wire format violation (truncated, bad atyp, etc.).
    #[error("wire: {0}")]
    Wire(&'static str),
    /// Domain-name length is 0 or > 253.
    #[error("domain length {0} out of range")]
    DomainLength(usize),
    /// Domain bytes are not valid UTF-8.
    #[error("domain not UTF-8")]
    DomainEncoding,
    /// Domain failed LDH validation (not letters/digits/hyphens
    /// arranged into legal hostname labels). Without this, a
    /// caller could smuggle `/`, NUL, or control characters into
    /// the destination address - relays would faithfully forward
    /// to a target string a normal resolver couldn't even attempt.
    #[error("domain not LDH-conformant")]
    DomainNotLdh,
    /// Port `0` reserved.
    #[error("port 0 reserved")]
    ZeroPort,
    /// IPv6 address is the v4-mapped form `::ffff:0:0/96`. RFC 4291
    /// §2.5.5.2 says these MUST be represented as IPv4 (atyp 0x01)
    /// to keep encoding canonical - mux equality comparisons,
    /// dedup, and ACL checks all assume one address <-> one wire form.
    #[error("IPv4-mapped IPv6 must be encoded as IPv4")]
    Ipv4MappedIpv6,
}

/// SOCKS5-style target.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum MuxTarget {
    /// IPv4 + port.
    Ipv4 { addr: [u8; 4], port: u16 },
    /// IPv6 + port.
    Ipv6 { addr: [u8; 16], port: u16 },
    /// Domain + port (e.g., `example.com:443`).
    Domain { domain: String, port: u16 },
}

impl MuxTarget {
    /// Wire-format byte length (atyp + body + port).
    pub fn wire_len(&self) -> usize {
        1 + match self {
            MuxTarget::Ipv4 { .. } => 4 + 2,
            MuxTarget::Ipv6 { .. } => 16 + 2,
            MuxTarget::Domain { domain, .. } => 1 + domain.len() + 2,
        }
    }

    /// Encode to a fresh Vec. Returns `Err` if the value is not
    /// representable on the wire (e.g., domain too long for the
    /// 1-byte length prefix, IPv4-mapped IPv6 supplied as `Ipv6`,
    /// reserved port 0). Encode-side validation matches decode-side
    /// - we never serialize bytes the decoder would refuse.
    pub fn encode(&self) -> Result<Vec<u8>, TargetError> {
        match self {
            MuxTarget::Ipv4 { port, .. }
            | MuxTarget::Ipv6 { port, .. }
            | MuxTarget::Domain { port, .. }
                if *port == 0 =>
            {
                return Err(TargetError::ZeroPort);
            }
            _ => {}
        }
        let mut out = Vec::with_capacity(self.wire_len());
        match self {
            MuxTarget::Ipv4 { addr, port } => {
                out.push(0x01);
                out.extend_from_slice(addr);
                out.extend_from_slice(&port.to_be_bytes());
            }
            MuxTarget::Domain { domain, port } => {
                let bytes = domain.as_bytes();
                if bytes.is_empty() || bytes.len() > 253 {
                    return Err(TargetError::DomainLength(bytes.len()));
                }
                if !is_ldh_hostname(domain) {
                    return Err(TargetError::DomainNotLdh);
                }
                out.push(0x03);
                // Length is bounded above by the 253 check; cast is
                // exact, not truncating.
                out.push(bytes.len() as u8);
                out.extend_from_slice(bytes);
                out.extend_from_slice(&port.to_be_bytes());
            }
            MuxTarget::Ipv6 { addr, port } => {
                if is_ipv4_mapped(addr) {
                    return Err(TargetError::Ipv4MappedIpv6);
                }
                out.push(0x04);
                out.extend_from_slice(addr);
                out.extend_from_slice(&port.to_be_bytes());
            }
        }
        Ok(out)
    }

    /// Parse from wire bytes. Strict (no trailing bytes accepted).
    pub fn decode(buf: &[u8]) -> Result<Self, TargetError> {
        if buf.is_empty() {
            return Err(TargetError::Wire("empty"));
        }
        let port_at = |port_off: usize| -> Result<u16, TargetError> {
            if buf.len() < port_off + 2 {
                return Err(TargetError::Wire("truncated at port"));
            }
            let port = u16::from_be_bytes([buf[port_off], buf[port_off + 1]]);
            if port == 0 {
                return Err(TargetError::ZeroPort);
            }
            if buf.len() != port_off + 2 {
                return Err(TargetError::Wire("trailing bytes after port"));
            }
            Ok(port)
        };
        match buf[0] {
            0x01 => {
                // IPv4
                if buf.len() < 1 + 4 + 2 {
                    return Err(TargetError::Wire("ipv4 truncated"));
                }
                let mut addr = [0u8; 4];
                addr.copy_from_slice(&buf[1..5]);
                let port = port_at(5)?;
                Ok(MuxTarget::Ipv4 { addr, port })
            }
            0x03 => {
                // Domain
                if buf.len() < 2 {
                    return Err(TargetError::Wire("domain truncated at len"));
                }
                let dlen = buf[1] as usize;
                if dlen == 0 || dlen > 253 {
                    return Err(TargetError::DomainLength(dlen));
                }
                if buf.len() < 2 + dlen + 2 {
                    return Err(TargetError::Wire("domain truncated"));
                }
                let domain = std::str::from_utf8(&buf[2..2 + dlen])
                    .map_err(|_| TargetError::DomainEncoding)?
                    .to_string();
                if !is_ldh_hostname(&domain) {
                    return Err(TargetError::DomainNotLdh);
                }
                let port = port_at(2 + dlen)?;
                Ok(MuxTarget::Domain { domain, port })
            }
            0x04 => {
                // IPv6
                if buf.len() < 1 + 16 + 2 {
                    return Err(TargetError::Wire("ipv6 truncated"));
                }
                let mut addr = [0u8; 16];
                addr.copy_from_slice(&buf[1..17]);
                if is_ipv4_mapped(&addr) {
                    return Err(TargetError::Ipv4MappedIpv6);
                }
                let port = port_at(17)?;
                Ok(MuxTarget::Ipv6 { addr, port })
            }
            other => Err(TargetError::Wire(if other == 0x02 {
                "atyp 0x02 reserved (legacy)"
            } else {
                "unknown atyp"
            })),
        }
    }
}

/// True iff `addr` falls in the IPv4-mapped IPv6 prefix
/// `::ffff:0:0/96` (RFC 4291 §2.5.5.2). Such addresses MUST be
/// represented as IPv4 (atyp 0x01) so the wire encoding is canonical.
fn is_ipv4_mapped(addr: &[u8; 16]) -> bool {
    addr[..10] == [0u8; 10] && addr[10] == 0xff && addr[11] == 0xff
}

/// Strict LDH hostname validator. Accepts dotted-quad IPv4 too
/// (the digits + dots are LDH-conformant). Rejects empty labels,
/// labels > 63 bytes, leading/trailing hyphens, and non-LDH bytes.
fn is_ldh_hostname(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 {
        return false;
    }
    if host.starts_with('.') || host.ends_with('.') {
        return false;
    }
    for label in host.split('.') {
        if label.is_empty() || label.len() > 63 {
            return false;
        }
        if label.starts_with('-') || label.ends_with('-') {
            return false;
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_ipv4_roundtrip() {
        let t = MuxTarget::Ipv4 {
            addr: [203, 0, 113, 5],
            port: 443,
        };
        let buf = t.encode().unwrap();
        assert_eq!(MuxTarget::decode(&buf).unwrap(), t);
    }

    #[test]
    fn target_ipv6_roundtrip() {
        let t = MuxTarget::Ipv6 {
            addr: [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            port: 443,
        };
        let buf = t.encode().unwrap();
        assert_eq!(MuxTarget::decode(&buf).unwrap(), t);
    }

    #[test]
    fn target_domain_roundtrip() {
        let t = MuxTarget::Domain {
            domain: "example.com".to_string(),
            port: 443,
        };
        let buf = t.encode().unwrap();
        assert_eq!(MuxTarget::decode(&buf).unwrap(), t);
    }

    #[test]
    fn rejects_zero_port() {
        // Encoder rejects port 0 up front (defense in depth - even
        // if a buggy caller bypassed encoder and crafted bytes by
        // hand, the decoder also rejects).
        let t = MuxTarget::Ipv4 {
            addr: [127, 0, 0, 1],
            port: 0,
        };
        assert_eq!(t.encode().unwrap_err(), TargetError::ZeroPort);
        let mut buf = vec![0x01u8, 127, 0, 0, 1];
        buf.extend_from_slice(&0u16.to_be_bytes());
        assert_eq!(MuxTarget::decode(&buf).unwrap_err(), TargetError::ZeroPort);
    }

    #[test]
    fn encode_rejects_oversized_domain() {
        // Pre-fix this silently truncated `domain.len() as u8`,
        // wrapping a 256-byte domain to a 0-length wire field.
        let t = MuxTarget::Domain {
            domain: "a".repeat(254),
            port: 443,
        };
        assert!(matches!(
            t.encode().unwrap_err(),
            TargetError::DomainLength(254)
        ));
    }

    #[test]
    fn encode_rejects_non_ldh_domain() {
        let t = MuxTarget::Domain {
            domain: "evil.com/?a=b".to_string(),
            port: 443,
        };
        assert_eq!(t.encode().unwrap_err(), TargetError::DomainNotLdh);
    }

    #[test]
    fn decode_rejects_non_ldh_domain() {
        // Manually craft a wire frame with a domain containing `/`.
        let mut buf = vec![0x03u8, 13];
        buf.extend_from_slice(b"evil.com/?a=b");
        buf.extend_from_slice(&443u16.to_be_bytes());
        assert_eq!(
            MuxTarget::decode(&buf).unwrap_err(),
            TargetError::DomainNotLdh
        );
    }

    #[test]
    fn encode_rejects_ipv4_mapped_ipv6() {
        // ::ffff:203.0.113.5 - should be encoded as IPv4 to keep
        // the wire form canonical.
        let t = MuxTarget::Ipv6 {
            addr: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 203, 0, 113, 5],
            port: 443,
        };
        assert_eq!(t.encode().unwrap_err(), TargetError::Ipv4MappedIpv6);
    }

    #[test]
    fn decode_rejects_ipv4_mapped_ipv6() {
        let mut buf = vec![0x04u8];
        buf.extend_from_slice(&[0u8; 10]);
        buf.extend_from_slice(&[0xff, 0xff]);
        buf.extend_from_slice(&[203, 0, 113, 5]);
        buf.extend_from_slice(&443u16.to_be_bytes());
        assert_eq!(
            MuxTarget::decode(&buf).unwrap_err(),
            TargetError::Ipv4MappedIpv6
        );
    }

    #[test]
    fn rejects_zero_length_domain() {
        let mut buf = vec![0x03u8, 0]; // atyp=3, dlen=0
        buf.extend_from_slice(&443u16.to_be_bytes());
        let err = MuxTarget::decode(&buf).unwrap_err();
        assert!(matches!(err, TargetError::DomainLength(0)));
    }

    #[test]
    fn rejects_oversized_domain_length_field() {
        // atyp=3, dlen=254 - exceeds 253 cap.
        let mut buf = vec![0x03u8, 254];
        buf.extend(vec![b'a'; 254]);
        buf.extend_from_slice(&443u16.to_be_bytes());
        let err = MuxTarget::decode(&buf).unwrap_err();
        assert!(matches!(err, TargetError::DomainLength(254)));
    }

    #[test]
    fn rejects_unknown_atyp() {
        let buf = [0x99u8, 0, 0, 0, 0, 0, 0];
        assert!(matches!(
            MuxTarget::decode(&buf),
            Err(TargetError::Wire("unknown atyp"))
        ));
    }

    #[test]
    fn rejects_legacy_atyp_2() {
        let buf = [0x02u8, 0, 0, 0, 0, 0, 0];
        let err = MuxTarget::decode(&buf).unwrap_err();
        assert!(matches!(err, TargetError::Wire(s) if s.contains("0x02")));
    }

    #[test]
    fn rejects_trailing_bytes() {
        let t = MuxTarget::Ipv4 {
            addr: [127, 0, 0, 1],
            port: 80,
        };
        let mut buf = t.encode().unwrap();
        buf.push(0x99); // junk
        assert!(matches!(MuxTarget::decode(&buf), Err(TargetError::Wire(_))));
    }

    #[test]
    fn rejects_invalid_utf8_domain() {
        // atyp=3, dlen=4, body = invalid UTF-8 (lone 0xFF), port=80.
        let mut buf = vec![0x03u8, 4, 0xFF, 0xFF, 0xFF, 0xFF];
        buf.extend_from_slice(&80u16.to_be_bytes());
        assert_eq!(
            MuxTarget::decode(&buf).unwrap_err(),
            TargetError::DomainEncoding
        );
    }
}
