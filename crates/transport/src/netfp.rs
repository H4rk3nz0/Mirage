//! Network fingerprinting - deriving a stable [`NetworkFingerprint`] from the
//! signals that identify "the network the client is currently on."
//!
//! # Why
//!
//! The adaptive router ([`crate::adaptive`]) and the collaborative posture
//! estimator ([`crate::posture_net`]) both key their learned state on a
//! [`NetworkFingerprint`]. Until that key is REAL, they run in one global
//! bucket - a mobile client that hops from a censored cellular network to an
//! open café Wi-Fi would carry the cellular block-map onto the café, mis-routing
//! for no reason. A per-network key keeps each network's censorship experience
//! separate, and is the scope a swarm gossip report is tagged with (a "UDP is
//! blocked here" claim is only meaningful for the network it was measured on).
//!
//! # Design
//!
//! The fingerprint must be **stable across short-term IP churn** (a DHCP renew
//! on the same LAN keeps you on the same network) but **flip when you actually
//! move** (a different subnet / a different resolver = a different network,
//! plausibly a different censor). So we hash *coarsened* signals:
//!
//! - the local outbound IP **masked to its subnet** (`/24` for IPv4, `/48` for
//!   IPv6) - same LAN => same masked prefix across DHCP; different network =>
//!   different prefix;
//! - the configured DNS resolvers (sorted, deduped) - a strong network
//!   discriminator, and censorship-relevant (the resolver is often *the*
//!   poisoning point).
//!
//! With **no** signals (a platform where gathering fails) it returns
//! [`NetworkFingerprint::unknown`] - identical to today's behaviour, so this is
//! a strict, safe upgrade.
//!
//! # Purity
//!
//! This module is pure + dependency-free: it turns already-gathered signals into
//! a fingerprint using a dependency-free 128-bit hash (a network *identifier*,
//! not a security primitive - a collision merely merges two networks' learned
//! state, never a safety issue). The platform I/O that *gathers* the signals
//! lives at the client edge.

use crate::success_rate::NetworkFingerprint;
use std::net::IpAddr;

/// The coarse signals that identify the current network.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetworkSignals {
    /// The local IP the OS would use to reach the internet (identifies the
    /// subnet). `None` if it could not be determined.
    pub local_ip: Option<IpAddr>,
    /// The configured DNS resolver IPs.
    pub resolvers: Vec<IpAddr>,
}

impl NetworkSignals {
    /// Derive the [`NetworkFingerprint`]. Returns [`NetworkFingerprint::unknown`]
    /// when there are no usable signals at all.
    #[must_use]
    pub fn fingerprint(&self) -> NetworkFingerprint {
        let mut bytes: Vec<u8> = Vec::with_capacity(48);

        if let Some(ip) = self.local_ip {
            bytes.push(0xC0); // "subnet" domain tag
            append_subnet(&mut bytes, ip);
        }

        // Sort + dedup resolvers so ordering / duplicates don't change the key.
        let mut res: Vec<IpAddr> = self.resolvers.clone();
        res.sort();
        res.dedup();
        for ip in res {
            bytes.push(0xD5); // "resolver" domain tag
            append_ip(&mut bytes, ip);
        }

        if bytes.is_empty() {
            return NetworkFingerprint::unknown();
        }
        NetworkFingerprint::from_digest(hash128(&bytes))
    }
}

/// Append `ip` coarsened to its subnet: IPv4 `/24` (first 3 octets), IPv6 `/48`
/// (first 6 bytes). Stable across DHCP within a network; flips between networks.
fn append_subnet(out: &mut Vec<u8>, ip: IpAddr) {
    match ip {
        IpAddr::V4(v4) => {
            out.push(4);
            out.extend_from_slice(&v4.octets()[..3]);
        }
        IpAddr::V6(v6) => {
            out.push(6);
            out.extend_from_slice(&v6.octets()[..6]);
        }
    }
}

/// Append a full IP (used for resolvers, where the exact address is the signal).
fn append_ip(out: &mut Vec<u8>, ip: IpAddr) {
    match ip {
        IpAddr::V4(v4) => {
            out.push(4);
            out.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            out.push(6);
            out.extend_from_slice(&v6.octets());
        }
    }
}

/// Dependency-free 128-bit hash: two FNV-1a-64 passes with distinct seeds.
/// Sufficient for a network identifier (not a security primitive).
fn hash128(data: &[u8]) -> [u8; 16] {
    let a = fnv1a64(data, 0xcbf2_9ce4_8422_2325);
    let b = fnv1a64(data, 0x8422_2325_cbf2_9ce4);
    let mut out = [0u8; 16];
    out[..8].copy_from_slice(&a.to_le_bytes());
    out[8..].copy_from_slice(&b.to_le_bytes());
    out
}

fn fnv1a64(data: &[u8], seed: u64) -> u64 {
    let mut h = seed;
    for &byte in data {
        h ^= u64::from(byte);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn sig(ip: &str, res: &[&str]) -> NetworkSignals {
        NetworkSignals {
            local_ip: Some(ip.parse().unwrap()),
            resolvers: res.iter().map(|r| r.parse().unwrap()).collect(),
        }
    }

    #[test]
    fn stable_across_dhcp_within_a_subnet() {
        // Same /24 + same resolver, different host octet (DHCP renew) -> same fp.
        let a = sig("192.168.1.50", &["192.168.1.1"]).fingerprint();
        let b = sig("192.168.1.207", &["192.168.1.1"]).fingerprint();
        assert_eq!(
            a, b,
            "DHCP renew within the subnet must keep the fingerprint"
        );
    }

    #[test]
    fn flips_across_networks() {
        let home = sig("192.168.1.50", &["192.168.1.1"]).fingerprint();
        let cafe = sig("10.0.5.9", &["10.0.5.1"]).fingerprint();
        let cell = sig("100.72.3.4", &["8.8.8.8"]).fingerprint();
        assert_ne!(home, cafe);
        assert_ne!(home, cell);
        assert_ne!(cafe, cell);
    }

    #[test]
    fn resolver_change_flips_even_on_same_subnet() {
        // Same subnet but the network hands out a different (e.g. poisoning)
        // resolver -> a different network posture, so a different fingerprint.
        let a = sig("192.168.1.50", &["192.168.1.1"]).fingerprint();
        let b = sig("192.168.1.50", &["192.168.1.254"]).fingerprint();
        assert_ne!(a, b);
    }

    #[test]
    fn resolver_order_and_dupes_do_not_matter() {
        let a = sig("192.168.1.50", &["1.1.1.1", "8.8.8.8"]).fingerprint();
        let b = sig("192.168.1.50", &["8.8.8.8", "1.1.1.1", "8.8.8.8"]).fingerprint();
        assert_eq!(a, b);
    }

    #[test]
    fn no_signals_is_unknown() {
        assert_eq!(
            NetworkSignals::default().fingerprint(),
            NetworkFingerprint::unknown()
        );
    }

    #[test]
    fn deterministic() {
        let s = sig("192.168.1.50", &["192.168.1.1"]);
        assert_eq!(s.fingerprint(), s.fingerprint());
    }

    #[test]
    fn ipv6_subnet_masking() {
        // Same /48, different lower bits -> same fingerprint.
        let a = NetworkSignals {
            local_ip: Some(IpAddr::V6(
                "2001:db8:abcd:1111::1".parse::<Ipv6Addr>().unwrap(),
            )),
            resolvers: vec![],
        }
        .fingerprint();
        let b = NetworkSignals {
            local_ip: Some(IpAddr::V6(
                "2001:db8:abcd:2222::99".parse::<Ipv6Addr>().unwrap(),
            )),
            resolvers: vec![],
        }
        .fingerprint();
        assert_eq!(a, b, "same /48 must match");
        let c = NetworkSignals {
            local_ip: Some(IpAddr::V6(
                "2001:db8:ffff:1111::1".parse::<Ipv6Addr>().unwrap(),
            )),
            resolvers: vec![],
        }
        .fingerprint();
        assert_ne!(a, c, "different /48 must differ");
    }

    #[test]
    fn ipv4_and_ipv6_do_not_collide_trivially() {
        let v4 = NetworkSignals {
            local_ip: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            resolvers: vec![],
        }
        .fingerprint();
        let v6 = NetworkSignals {
            local_ip: Some(IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().unwrap())),
            resolvers: vec![],
        }
        .fingerprint();
        assert_ne!(v4, v6);
    }
}
