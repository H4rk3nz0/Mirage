//! SOCKS5 UDP datagram header codec (RFC 1928 §7).
//!
//! # What
//!
//! When a SOCKS5 client uses UDP ASSOCIATE, every UDP datagram
//! sent through the proxy is wrapped in a small header that names
//! the **destination** address + port. The wire format:
//!
//! ```text
//!   +----+------+------+----------+----------+----------+
//!   |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
//!   +----+------+------+----------+----------+----------+
//!   | 2  |  1   |  1   | Variable |    2     | Variable |
//!   +----+------+------+----------+----------+----------+
//! ```
//!
//! - `RSV`: reserved, MUST be `0x0000`.
//! - `FRAG`: fragmentation byte. `0x00` = unfragmented (the only
//!   form Mirage supports). Non-zero is rejected - fragmentation
//!   is rare in practice and complicates reassembly.
//! - `ATYP`: address-type byte (same encoding as TCP CONNECT).
//! - `DST.ADDR`: 4 bytes (IPv4), 16 bytes (IPv6), or `len + name`
//!   (domain).
//! - `DST.PORT`: 2 bytes BE.
//! - `DATA`: opaque UDP payload.
//!
//! # Why ship this in `mirage-socks5`?
//!
//! The same codec is used by:
//! - Mirage client's SOCKS5 UDP ASSOCIATE responder (parses
//!   datagrams arriving from the local app, forwards over Mirage).
//! - Mirage bridge's UDP-relay handler (parses datagrams arriving
//!   over Mirage, sends to the named upstream).
//!
//! Centralising the codec means both sides are bug-for-bug
//! identical. Lives next to the SOCKS5 TCP code so a reader
//! finding the protocol surface in one place finds the rest.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::{ATYP_DOMAIN, ATYP_IPV4, ATYP_IPV6};

/// Hard cap on the destination domain string. Same as the TCP
/// CONNECT path uses; bounds the encode/decode allocations.
pub const MAX_UDP_DOMAIN_BYTES: usize = 255;

/// A parsed SOCKS5 UDP datagram header + body.
#[derive(Debug, Clone)]
pub struct Socks5UdpDgram {
    /// Destination host. Either a resolved IP socket address or a
    /// `(domain, port)` pair the relay must DNS-resolve.
    pub dst: Socks5UdpDest,
    /// Opaque UDP payload.
    pub data: Vec<u8>,
}

/// Destination of a SOCKS5 UDP datagram. Mirrors the address-type
/// distinction in the TCP path.
#[derive(Debug, Clone)]
pub enum Socks5UdpDest {
    /// IPv4 / IPv6 socket address. Resolved before relay sees it.
    Ip(SocketAddr),
    /// Domain + port. Relay performs DNS lookup at egress.
    Domain {
        /// Hostname; validated as RFC 1123 LDH at decode time.
        name: String,
        /// Destination port.
        port: u16,
    },
}

impl Socks5UdpDest {
    /// Helper: get the port regardless of variant.
    pub fn port(&self) -> u16 {
        match self {
            Socks5UdpDest::Ip(a) => a.port(),
            Socks5UdpDest::Domain { port, .. } => *port,
        }
    }
}

/// Errors from parsing a SOCKS5 UDP datagram header.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Socks5UdpDgramError {
    /// Datagram too short for a complete header.
    #[error("truncated: {0}")]
    Truncated(&'static str),
    /// `RSV` field non-zero - RFC 1928 says MUST be 0.
    #[error("RSV not zero")]
    BadRsv,
    /// `FRAG` non-zero - Mirage does not support fragmentation.
    #[error("FRAG non-zero (fragmentation unsupported)")]
    Fragmented,
    /// `ATYP` byte was not 0x01 / 0x03 / 0x04.
    #[error("unknown ATYP {0:#04x}")]
    UnknownAtyp(u8),
    /// Domain name field exceeded [`MAX_UDP_DOMAIN_BYTES`] OR
    /// failed UTF-8 / RFC 1123 LDH validation.
    #[error("invalid domain")]
    InvalidDomain,
}

/// Encode a SOCKS5 UDP datagram (header + payload) to wire bytes.
///
/// Rejects domain destinations whose name is empty, exceeds
/// [`MAX_UDP_DOMAIN_BYTES`], or contains a character outside the
/// RFC 1123 LDH set. The decoder applies the same checks; both
/// MUST be consistent or wire bytes a caller produced won't
/// roundtrip - a silent corruption channel we explicitly close
/// (RT-udp-1 + RT-udp-2).
pub fn encode(dst: &Socks5UdpDest, data: &[u8]) -> Result<Vec<u8>, Socks5UdpDgramError> {
    let mut out = Vec::with_capacity(10 + data.len());
    out.extend_from_slice(&[0x00, 0x00]); // RSV
    out.push(0x00); // FRAG
    match dst {
        Socks5UdpDest::Ip(SocketAddr::V4(a)) => {
            out.push(ATYP_IPV4);
            out.extend_from_slice(&a.ip().octets());
            out.extend_from_slice(&a.port().to_be_bytes());
        }
        Socks5UdpDest::Ip(SocketAddr::V6(a)) => {
            out.push(ATYP_IPV6);
            out.extend_from_slice(&a.ip().octets());
            out.extend_from_slice(&a.port().to_be_bytes());
        }
        Socks5UdpDest::Domain { name, port } => {
            let bytes = name.as_bytes();
            if bytes.is_empty() || bytes.len() > MAX_UDP_DOMAIN_BYTES {
                return Err(Socks5UdpDgramError::InvalidDomain);
            }
            for &b in bytes {
                if !(b.is_ascii_alphanumeric() || b == b'.' || b == b'-') {
                    return Err(Socks5UdpDgramError::InvalidDomain);
                }
            }
            out.push(ATYP_DOMAIN);
            out.push(bytes.len() as u8);
            out.extend_from_slice(bytes);
            out.extend_from_slice(&port.to_be_bytes());
        }
    }
    out.extend_from_slice(data);
    Ok(out)
}

/// Parse a SOCKS5 UDP datagram from wire bytes. The slice MUST
/// contain exactly one datagram (header + body). Returns the
/// parsed header + a borrowed view of the data; callers that
/// need owned data can use [`decode_owned`].
pub fn decode(buf: &[u8]) -> Result<(Socks5UdpDest, &[u8]), Socks5UdpDgramError> {
    if buf.len() < 4 {
        return Err(Socks5UdpDgramError::Truncated("header < 4 bytes"));
    }
    if buf[0] != 0x00 || buf[1] != 0x00 {
        return Err(Socks5UdpDgramError::BadRsv);
    }
    if buf[2] != 0x00 {
        return Err(Socks5UdpDgramError::Fragmented);
    }
    let atyp = buf[3];
    let (dst, body_off) = match atyp {
        ATYP_IPV4 => {
            if buf.len() < 4 + 4 + 2 {
                return Err(Socks5UdpDgramError::Truncated("ipv4"));
            }
            let ip = Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]);
            let port = u16::from_be_bytes([buf[8], buf[9]]);
            (Socks5UdpDest::Ip(SocketAddr::from((ip, port))), 10)
        }
        ATYP_IPV6 => {
            if buf.len() < 4 + 16 + 2 {
                return Err(Socks5UdpDgramError::Truncated("ipv6"));
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&buf[4..20]);
            let ip = Ipv6Addr::from(octets);
            let port = u16::from_be_bytes([buf[20], buf[21]]);
            (Socks5UdpDest::Ip(SocketAddr::from((ip, port))), 22)
        }
        ATYP_DOMAIN => {
            if buf.len() < 5 {
                return Err(Socks5UdpDgramError::Truncated("domain length byte"));
            }
            let n = buf[4] as usize;
            if n == 0 || n > MAX_UDP_DOMAIN_BYTES {
                return Err(Socks5UdpDgramError::InvalidDomain);
            }
            if buf.len() < 5 + n + 2 {
                return Err(Socks5UdpDgramError::Truncated("domain bytes"));
            }
            let name_bytes = &buf[5..5 + n];
            // RFC 1123 LDH: ASCII letters, digits, hyphens, dots.
            // Same shape the TCP CONNECT validator enforces.
            for &b in name_bytes {
                if !(b.is_ascii_alphanumeric() || b == b'.' || b == b'-') {
                    return Err(Socks5UdpDgramError::InvalidDomain);
                }
            }
            let name =
                std::str::from_utf8(name_bytes).map_err(|_| Socks5UdpDgramError::InvalidDomain)?;
            let port = u16::from_be_bytes([buf[5 + n], buf[5 + n + 1]]);
            (
                Socks5UdpDest::Domain {
                    name: name.to_string(),
                    port,
                },
                5 + n + 2,
            )
        }
        other => return Err(Socks5UdpDgramError::UnknownAtyp(other)),
    };
    Ok((dst, &buf[body_off..]))
}

/// Like [`decode`] but returns owned `data`. Convenience for the
/// bridge-side relay which needs to send the datagram on a UDP
/// socket without holding the parser's borrow.
pub fn decode_owned(buf: &[u8]) -> Result<Socks5UdpDgram, Socks5UdpDgramError> {
    let (dst, data) = decode(buf)?;
    Ok(Socks5UdpDgram {
        dst,
        data: data.to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_roundtrip() {
        let dst = Socks5UdpDest::Ip(SocketAddr::from(([192, 0, 2, 1], 1234)));
        let body = b"hello";
        let bytes = encode(&dst, body).unwrap();
        let (got_dst, got_body) = decode(&bytes).unwrap();
        match got_dst {
            Socks5UdpDest::Ip(a) => {
                assert_eq!(a.to_string(), "192.0.2.1:1234");
            }
            _ => panic!("expected IPv4"),
        }
        assert_eq!(got_body, body);
    }

    #[test]
    fn ipv6_roundtrip() {
        let dst = Socks5UdpDest::Ip(SocketAddr::from((
            "2001:db8::1".parse::<Ipv6Addr>().unwrap(),
            443,
        )));
        let body = b"";
        let bytes = encode(&dst, body).unwrap();
        let (got_dst, got_body) = decode(&bytes).unwrap();
        match got_dst {
            Socks5UdpDest::Ip(a) => assert_eq!(a.port(), 443),
            _ => panic!("expected IPv6"),
        }
        assert!(got_body.is_empty());
    }

    #[test]
    fn domain_roundtrip() {
        let dst = Socks5UdpDest::Domain {
            name: "bridge.example.com".to_string(),
            port: 443,
        };
        let body = b"\x01\x02\x03";
        let bytes = encode(&dst, body).unwrap();
        let (got, gb) = decode(&bytes).unwrap();
        match got {
            Socks5UdpDest::Domain { name, port } => {
                assert_eq!(name, "bridge.example.com");
                assert_eq!(port, 443);
            }
            _ => panic!("expected domain"),
        }
        assert_eq!(gb, body);
    }

    #[test]
    fn rejects_nonzero_rsv() {
        let mut dgram = encode(&Socks5UdpDest::Ip(SocketAddr::from(([0; 4], 0))), b"x").unwrap();
        dgram[1] = 0x01;
        assert_eq!(decode(&dgram).unwrap_err(), Socks5UdpDgramError::BadRsv);
    }

    #[test]
    fn rejects_fragmentation() {
        let mut dgram = encode(&Socks5UdpDest::Ip(SocketAddr::from(([0; 4], 0))), b"x").unwrap();
        dgram[2] = 0x01;
        assert_eq!(decode(&dgram).unwrap_err(), Socks5UdpDgramError::Fragmented);
    }

    #[test]
    fn encode_rejects_oversize_domain() {
        // RT-udp-1: previous version silently truncated to 255
        // bytes; the resulting name decoded to a different host
        // -> silent rerouting. Now: explicit error.
        let too_long = "a".repeat(MAX_UDP_DOMAIN_BYTES + 1);
        let dst = Socks5UdpDest::Domain {
            name: too_long,
            port: 80,
        };
        assert_eq!(
            encode(&dst, b"data").unwrap_err(),
            Socks5UdpDgramError::InvalidDomain
        );
    }

    #[test]
    fn encode_rejects_empty_domain() {
        let dst = Socks5UdpDest::Domain {
            name: String::new(),
            port: 80,
        };
        assert_eq!(
            encode(&dst, b"data").unwrap_err(),
            Socks5UdpDgramError::InvalidDomain
        );
    }

    #[test]
    fn encode_rejects_invalid_domain_chars() {
        // RT-udp-2: encoder + decoder MUST agree on what's a
        // valid name. Spaces, slashes, etc. fail decode ->
        // failing encode produces a loud error rather than wire
        // bytes that won't roundtrip.
        for bad in [
            "has space.com",
            "slash/.com",
            "underscore_.com",
            "non-ascii-é.com",
        ] {
            let dst = Socks5UdpDest::Domain {
                name: bad.to_string(),
                port: 80,
            };
            assert_eq!(
                encode(&dst, b"data").unwrap_err(),
                Socks5UdpDgramError::InvalidDomain,
                "must reject {bad:?}"
            );
        }
    }

    #[test]
    fn encode_max_size_domain_works() {
        // 255-byte name (no dots, all alphanumeric) is OK.
        let max = "a".repeat(MAX_UDP_DOMAIN_BYTES);
        let dst = Socks5UdpDest::Domain {
            name: max.clone(),
            port: 443,
        };
        let bytes = encode(&dst, b"").unwrap();
        let (got, _) = decode(&bytes).unwrap();
        match got {
            Socks5UdpDest::Domain { name, .. } => assert_eq!(name, max),
            _ => panic!("expected domain"),
        }
    }

    #[test]
    fn rejects_unknown_atyp() {
        let bytes = [0x00, 0x00, 0x00, 0x99, 0x00];
        assert_eq!(
            decode(&bytes).unwrap_err(),
            Socks5UdpDgramError::UnknownAtyp(0x99)
        );
    }

    #[test]
    fn rejects_truncated_header() {
        assert!(matches!(
            decode(&[0x00, 0x00]).unwrap_err(),
            Socks5UdpDgramError::Truncated(_)
        ));
        // ipv4 needs 10 bytes total (0x00 00 00 01 + 4 + 2)
        assert!(matches!(
            decode(&[0x00, 0x00, 0x00, 0x01, 0xC0]).unwrap_err(),
            Socks5UdpDgramError::Truncated(_)
        ));
        // domain header missing length byte
        assert!(matches!(
            decode(&[0x00, 0x00, 0x00, 0x03]).unwrap_err(),
            Socks5UdpDgramError::Truncated(_)
        ));
    }

    #[test]
    fn rejects_invalid_domain_chars() {
        // domain length 5, characters include space (invalid LDH)
        let bytes = [
            0x00, 0x00, 0x00, 0x03, 0x05, b'a', b' ', b'b', b'.', b'c', 0x00, 0x50,
        ];
        assert_eq!(
            decode(&bytes).unwrap_err(),
            Socks5UdpDgramError::InvalidDomain
        );
    }

    #[test]
    fn rejects_zero_length_domain() {
        let bytes = [0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x50];
        assert_eq!(
            decode(&bytes).unwrap_err(),
            Socks5UdpDgramError::InvalidDomain
        );
    }

    #[test]
    fn fuzz_decode_never_panics() {
        use proptest::prelude::*;
        proptest!(ProptestConfig::with_cases(256), |(b in prop::collection::vec(any::<u8>(), 0..512))| {
            let _ = decode(&b);
            let _ = decode_owned(&b);
        });
    }
}
