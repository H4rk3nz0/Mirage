//! Parse the flow 5-tuple + TCP control flags out of a raw IP packet.
//!
//! Uses `smoltcp`'s safe wire parsers (bounds-checked `*_checked` constructors),
//! so a malformed or truncated packet yields `None` rather than a panic - the
//! netstack simply drops it.

use std::net::{IpAddr, SocketAddr};

use smoltcp::wire::{IpProtocol, Ipv4Packet, Ipv6Packet, TcpPacket, UdpPacket};

/// Transport protocol of a captured flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    /// TCP.
    Tcp,
    /// UDP.
    Udp,
}

/// The 4-tuple + protocol identifying one transport flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    /// Source endpoint (the app's local ip:port).
    pub src: SocketAddr,
    /// Destination endpoint (where the app wants to reach - the Mirage target).
    pub dst: SocketAddr,
    /// Transport protocol.
    pub protocol: Protocol,
}

/// A parsed packet's flow identity + the TCP control flags relevant to
/// connection lifecycle (SYN opens a flow, RST/FIN tear one down).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParsedPacket {
    /// The flow this packet belongs to.
    pub key: FlowKey,
    /// TCP SYN set AND ACK clear - a fresh connection initiation.
    pub tcp_syn: bool,
    /// TCP RST set.
    pub tcp_rst: bool,
    /// TCP FIN set.
    pub tcp_fin: bool,
}

/// Parse a raw IP packet (v4 or v6) into its flow identity + TCP flags.
/// Returns `None` for non-IP, non-TCP/UDP, or malformed input.
#[must_use]
pub fn parse_packet(ip: &[u8]) -> Option<ParsedPacket> {
    let version = ip.first()? >> 4;
    match version {
        4 => {
            let pkt = Ipv4Packet::new_checked(ip).ok()?;
            // A non-first fragment (frag_offset > 0) carries raw segment data, not
            // an L4 header, yet keeps next_header=Tcp/Udp - parsing its payload as
            // a TCP header yields garbage ports/flags that can look like a SYN and
            // open a dead listener. Only the reassembled datagram (which smoltcp
            // handles) carries a real header, so skip fragments for flow detection.
            if pkt.frag_offset() != 0 {
                return None;
            }
            let src_ip = IpAddr::V4(pkt.src_addr());
            let dst_ip = IpAddr::V4(pkt.dst_addr());
            parse_l4(pkt.next_header(), pkt.payload(), src_ip, dst_ip)
        }
        6 => {
            let pkt = Ipv6Packet::new_checked(ip).ok()?;
            let src_ip = IpAddr::V6(pkt.src_addr());
            let dst_ip = IpAddr::V6(pkt.dst_addr());
            parse_l4(pkt.next_header(), pkt.payload(), src_ip, dst_ip)
        }
        _ => None,
    }
}

fn parse_l4(proto: IpProtocol, l4: &[u8], src_ip: IpAddr, dst_ip: IpAddr) -> Option<ParsedPacket> {
    match proto {
        IpProtocol::Tcp => {
            let seg = TcpPacket::new_checked(l4).ok()?;
            Some(ParsedPacket {
                key: FlowKey {
                    src: SocketAddr::new(src_ip, seg.src_port()),
                    dst: SocketAddr::new(dst_ip, seg.dst_port()),
                    protocol: Protocol::Tcp,
                },
                tcp_syn: seg.syn() && !seg.ack(),
                tcp_rst: seg.rst(),
                tcp_fin: seg.fin(),
            })
        }
        IpProtocol::Udp => {
            let dg = UdpPacket::new_checked(l4).ok()?;
            Some(ParsedPacket {
                key: FlowKey {
                    src: SocketAddr::new(src_ip, dg.src_port()),
                    dst: SocketAddr::new(dst_ip, dg.dst_port()),
                    protocol: Protocol::Udp,
                },
                tcp_syn: false,
                tcp_rst: false,
                tcp_fin: false,
            })
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use smoltcp::wire::{
        IpAddress, Ipv4Address, Ipv4Repr, TcpControl, TcpRepr, TcpSeqNumber, UdpRepr,
    };

    /// Build a real IPv4+TCP packet via smoltcp's emitters so the parser is
    /// tested against wire-correct bytes, not hand-rolled ones.
    fn ipv4_tcp(src: (Ipv4Address, u16), dst: (Ipv4Address, u16), control: TcpControl) -> Vec<u8> {
        let tcp = TcpRepr {
            src_port: src.1,
            dst_port: dst.1,
            control,
            seq_number: TcpSeqNumber(0),
            ack_number: None,
            window_len: 64240,
            window_scale: None,
            max_seg_size: None,
            sack_permitted: false,
            sack_ranges: [None, None, None],
            timestamp: None,
            payload: &[],
        };
        let ip = Ipv4Repr {
            src_addr: src.0,
            dst_addr: dst.0,
            next_header: IpProtocol::Tcp,
            payload_len: tcp.buffer_len(),
            hop_limit: 64,
        };
        let mut buf = vec![0u8; ip.buffer_len() + tcp.buffer_len()];
        let mut v4 = Ipv4Packet::new_unchecked(&mut buf);
        ip.emit(&mut v4, &smoltcp::phy::ChecksumCapabilities::default());
        let src_ipa = IpAddress::Ipv4(src.0);
        let dst_ipa = IpAddress::Ipv4(dst.0);
        let mut seg = TcpPacket::new_unchecked(v4.payload_mut());
        tcp.emit(
            &mut seg,
            &src_ipa,
            &dst_ipa,
            &smoltcp::phy::ChecksumCapabilities::default(),
        );
        buf
    }

    #[test]
    fn parses_tcp_syn_as_new_flow() {
        let pkt = ipv4_tcp(
            (Ipv4Address::new(10, 0, 0, 2), 51000),
            (Ipv4Address::new(93, 184, 216, 34), 443),
            TcpControl::Syn,
        );
        let p = parse_packet(&pkt).expect("parse");
        assert_eq!(p.key.protocol, Protocol::Tcp);
        assert_eq!(p.key.dst, "93.184.216.34:443".parse().unwrap());
        assert_eq!(p.key.src, "10.0.0.2:51000".parse().unwrap());
        assert!(p.tcp_syn, "SYN (no ACK) is a new flow");
    }

    #[test]
    fn syn_ack_is_not_a_new_flow() {
        let pkt = ipv4_tcp(
            (Ipv4Address::new(10, 0, 0, 2), 51000),
            (Ipv4Address::new(1, 1, 1, 1), 80),
            TcpControl::None, // plain ACK-ish (no SYN)
        );
        let p = parse_packet(&pkt).unwrap();
        assert!(!p.tcp_syn);
    }

    #[test]
    fn parses_udp_flow() {
        let udp = UdpRepr {
            src_port: 40000,
            dst_port: 53,
        };
        let src = Ipv4Address::new(10, 0, 0, 2);
        let dst = Ipv4Address::new(8, 8, 8, 8);
        let payload = [0u8; 4];
        let ip = Ipv4Repr {
            src_addr: src,
            dst_addr: dst,
            next_header: IpProtocol::Udp,
            payload_len: udp.header_len() + payload.len(),
            hop_limit: 64,
        };
        let mut buf = vec![0u8; ip.buffer_len() + udp.header_len() + payload.len()];
        let mut v4 = Ipv4Packet::new_unchecked(&mut buf);
        ip.emit(&mut v4, &smoltcp::phy::ChecksumCapabilities::default());
        let mut dg = UdpPacket::new_unchecked(v4.payload_mut());
        udp.emit(
            &mut dg,
            &IpAddress::Ipv4(src),
            &IpAddress::Ipv4(dst),
            payload.len(),
            |b| b.copy_from_slice(&payload),
            &smoltcp::phy::ChecksumCapabilities::default(),
        );
        let p = parse_packet(&buf).expect("parse udp");
        assert_eq!(p.key.protocol, Protocol::Udp);
        assert_eq!(p.key.dst, "8.8.8.8:53".parse().unwrap());
    }

    #[test]
    fn malformed_packet_is_none() {
        assert!(parse_packet(&[0x45, 0x00, 0x00]).is_none()); // truncated v4
        assert!(parse_packet(&[]).is_none());
        assert!(parse_packet(&[0x00]).is_none()); // bad version
    }
}
