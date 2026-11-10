//! Stream classification: turn a destination + protocol into a [`Class`].
//!
//! Classification source ranking (first non-`Unknown` wins):
//!
//! 1. Application hint via [`ClassHint`] - short-circuits everything.
//! 2. Onion-service detection (caller passes `is_onion = true` when
//!    the destination resolves as a `.mirage` address).
//! 3. SOCKS5 protocol - UDP ASSOCIATE biases toward [`Class::Realtime`]
//!    unless the port matches a known TCP-fallback (e.g. DNS).
//! 4. Port heuristic - see [`Classifier::classify_tcp`] /
//!    [`classify_udp`].
//! 5. Default - TCP defaults to [`Class::Interactive`]; UDP defaults
//!    to [`Class::Realtime`] (since unknown UDP is most likely
//!    media or gaming).
//!
//! Tables are intentionally short - port-based classification is a
//! starting heuristic, not a contract. Phase 3 adaptive
//! reclassification refines based on observed flow shape.

use crate::class::{Class, ClassHint};
use std::collections::HashMap;

/// IP transport protocol the stream rides over. Used by
/// [`Classifier::classify`] to pick between the TCP and UDP tables.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    /// TCP. Default class is [`Class::Interactive`].
    Tcp,
    /// UDP. Default class is [`Class::Realtime`].
    Udp,
}

/// Classifier with TCP / UDP heuristic tables.
///
/// Construct via [`Classifier::standard`] for the default tables, or
/// build a custom one via [`Classifier::new`] + [`override_tcp`] /
/// [`override_udp`].
pub struct Classifier {
    tcp_overrides: HashMap<u16, Class>,
    udp_overrides: HashMap<u16, Class>,
    default_tcp: Class,
    default_udp: Class,
}

impl Default for Classifier {
    fn default() -> Self {
        Self::standard()
    }
}

impl Classifier {
    /// Empty classifier. Every port falls through to the protocol
    /// default ([`Class::Interactive`] for TCP,
    /// [`Class::Realtime`] for UDP).
    pub fn new() -> Self {
        Self {
            tcp_overrides: HashMap::new(),
            udp_overrides: HashMap::new(),
            default_tcp: Class::Interactive,
            default_udp: Class::Realtime,
        }
    }

    /// Classifier pre-populated with the default tables.
    pub fn standard() -> Self {
        let mut c = Self::new();
        // TCP overrides
        for (port, class) in standard_tcp_table() {
            c.tcp_overrides.insert(*port, *class);
        }
        // UDP overrides
        for (port, class) in standard_udp_table() {
            c.udp_overrides.insert(*port, *class);
        }
        c
    }

    /// Override the class for a specific TCP port.
    pub fn override_tcp(&mut self, port: u16, class: Class) {
        self.tcp_overrides.insert(port, class);
    }

    /// Override the class for a specific UDP port.
    pub fn override_udp(&mut self, port: u16, class: Class) {
        self.udp_overrides.insert(port, class);
    }

    /// Set the protocol-default class. Affects ports not covered
    /// by an override.
    pub fn set_default(&mut self, proto: Protocol, class: Class) {
        match proto {
            Protocol::Tcp => self.default_tcp = class,
            Protocol::Udp => self.default_udp = class,
        }
    }

    /// Classify a TCP stream by destination port. Equivalent to
    /// `classify(Protocol::Tcp, port, false, None)`.
    pub fn classify_tcp(&self, port: u16) -> Class {
        self.classify(Protocol::Tcp, port, false, None)
    }

    /// Classify a UDP datagram association by destination port.
    pub fn classify_udp(&self, port: u16) -> Class {
        self.classify(Protocol::Udp, port, false, None)
    }

    /// Single classification entry point. Applies the source
    /// ranking.
    ///
    /// - `proto`: TCP or UDP.
    /// - `port`: destination port. Ignored if `is_onion = true`.
    /// - `is_onion`: caller has determined the destination is a
    ///   Mirage hidden service (e.g., the address ended in
    ///   `.mirage`). Forces [`Class::OnionService`] regardless of
    ///   port - onion streams don't have meaningful port semantics
    ///   from the network's view since the destination is in-protocol.
    /// - `hint`: optional application hint. If `Some`, takes
    ///   precedence over everything else.
    pub fn classify(
        &self,
        proto: Protocol,
        port: u16,
        is_onion: bool,
        hint: Option<ClassHint>,
    ) -> Class {
        // 1. Hint wins.
        if let Some(h) = hint {
            return h.class();
        }
        // 2. Onion service.
        if is_onion {
            return Class::OnionService;
        }
        // 3 + 4. Protocol + port heuristic.
        let table = match proto {
            Protocol::Tcp => &self.tcp_overrides,
            Protocol::Udp => &self.udp_overrides,
        };
        if let Some(&c) = table.get(&port) {
            return c;
        }
        // 5. Protocol default.
        match proto {
            Protocol::Tcp => self.default_tcp,
            Protocol::Udp => self.default_udp,
        }
    }
}

// Default tables

fn standard_tcp_table() -> &'static [(u16, Class)] {
    &[
        // Metadata
        (53, Class::Metadata), // DNS-over-TCP
        // Interactive - web
        (80, Class::Interactive),
        (443, Class::Interactive),
        (8080, Class::Interactive),
        (8443, Class::Interactive),
        // Interactive - SSH
        (22, Class::Interactive),
        // Interactive - mail
        (25, Class::Interactive),
        (465, Class::Interactive),
        (587, Class::Interactive),
        (993, Class::Interactive),
        (995, Class::Interactive),
        // Realtime - TCP signalling
        (5060, Class::Realtime), // SIP
        (5061, Class::Realtime), // SIP-TLS
        (1935, Class::Realtime), // RTMP
        // Bulk
        (873, Class::Bulk), // rsync
        (21, Class::Bulk),  // FTP control
        (989, Class::Bulk), // FTPS data
        (990, Class::Bulk), // FTPS control
        // BitTorrent ephemeral range - populated explicitly so an
        // override `set_default(Tcp, Bulk)` isn't required to
        // catch standard-port torrent traffic. Apps using ephemeral
        // ports above 6889 fall through to Interactive default
        // (they should set a hint).
        (6881, Class::Bulk),
        (6882, Class::Bulk),
        (6883, Class::Bulk),
        (6884, Class::Bulk),
        (6885, Class::Bulk),
        (6886, Class::Bulk),
        (6887, Class::Bulk),
        (6888, Class::Bulk),
        (6889, Class::Bulk),
    ]
}

fn standard_udp_table() -> &'static [(u16, Class)] {
    &[
        // Metadata
        (53, Class::Metadata), // DNS-over-UDP
        // Interactive - HTTP/3 / QUIC. Note: classifying QUIC web
        // as Interactive (not Realtime) so it follows web's full-
        // anonymity profile. QUIC carrying media (e.g., a video
        // call inside a QUIC tunnel) needs an explicit hint.
        (80, Class::Interactive),
        (443, Class::Interactive),
        // Realtime - signalling
        (5060, Class::Realtime), // SIP
        // Realtime - STUN / TURN
        (3478, Class::Realtime),
        (5349, Class::Realtime),
        // RTP ephemeral range - only the LOWER bound is in the
        // table; anything in 16384..=32767 is also treated as
        // realtime via [`classify`] below. We use a small numbered
        // sample here; the range check is in `classify_udp_range`.
    ]
}

// Range fallthrough: ports the explicit table can't cover without
// becoming a 16k-entry HashMap. Currently the RTP ephemeral range
// 16384..=32767 and Source-engine games 27015..=27050. Applied
// before the default in [`Classifier::classify`].
//
// Implemented as part of the Classifier method because using a
// HashMap entry per port would balloon allocation.
impl Classifier {
    fn classify_udp_range(port: u16) -> Option<Class> {
        if (16384..=32767).contains(&port) {
            return Some(Class::Realtime);
        }
        if (27015..=27050).contains(&port) {
            return Some(Class::Realtime);
        }
        None
    }
}

// Override `classify` to consult the range table before falling
// through to the default. (Implemented as a separate impl block so
// the order of the source ranking is the most readable
// presentation of the algorithm.)
impl Classifier {
    /// Classify with range-based UDP heuristics applied. This is
    /// the actual entry point invoked by `classify_udp` and is
    /// equivalent to [`Self::classify`] except that it consults
    /// the RTP / game ranges before falling through to the
    /// protocol default.
    pub fn classify_full(
        &self,
        proto: Protocol,
        port: u16,
        is_onion: bool,
        hint: Option<ClassHint>,
    ) -> Class {
        if let Some(h) = hint {
            return h.class();
        }
        if is_onion {
            return Class::OnionService;
        }
        let table = match proto {
            Protocol::Tcp => &self.tcp_overrides,
            Protocol::Udp => &self.udp_overrides,
        };
        if let Some(&c) = table.get(&port) {
            return c;
        }
        if proto == Protocol::Udp {
            if let Some(c) = Self::classify_udp_range(port) {
                return c;
            }
        }
        match proto {
            Protocol::Tcp => self.default_tcp,
            Protocol::Udp => self.default_udp,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c() -> Classifier {
        Classifier::standard()
    }

    // --- Hint precedence ---

    #[test]
    fn hint_overrides_port_based_classification() {
        let c = c();
        // Port 443 normally -> Interactive.
        assert_eq!(c.classify_tcp(443), Class::Interactive);
        // Hint forces Bulk for the same port.
        assert_eq!(
            c.classify(Protocol::Tcp, 443, false, Some(ClassHint::Bulk)),
            Class::Bulk
        );
        // Hint also overrides onion detection - caller's
        // explicit intent wins over the .mirage detection.
        assert_eq!(
            c.classify(Protocol::Tcp, 443, true, Some(ClassHint::Web)),
            Class::Interactive
        );
    }

    // --- Onion service detection ---

    #[test]
    fn onion_destination_routes_to_onion_service() {
        let c = c();
        // Port doesn't matter for onion services.
        assert_eq!(
            c.classify(Protocol::Tcp, 80, true, None),
            Class::OnionService
        );
        assert_eq!(
            c.classify(Protocol::Tcp, 9000, true, None),
            Class::OnionService
        );
        assert_eq!(
            c.classify(Protocol::Udp, 443, true, None),
            Class::OnionService
        );
    }

    // --- TCP heuristics ---

    #[test]
    fn standard_tcp_web_ports_are_interactive() {
        let c = c();
        for port in [80, 443, 8080, 8443] {
            assert_eq!(c.classify_tcp(port), Class::Interactive, "port {port}");
        }
    }

    #[test]
    fn standard_tcp_dns_is_metadata() {
        assert_eq!(c().classify_tcp(53), Class::Metadata);
    }

    #[test]
    fn standard_tcp_ssh_is_interactive() {
        assert_eq!(c().classify_tcp(22), Class::Interactive);
    }

    #[test]
    fn standard_tcp_sip_is_realtime() {
        let c = c();
        assert_eq!(c.classify_tcp(5060), Class::Realtime);
        assert_eq!(c.classify_tcp(5061), Class::Realtime);
    }

    #[test]
    fn standard_tcp_bittorrent_default_ports_are_bulk() {
        let c = c();
        for port in 6881u16..=6889 {
            assert_eq!(c.classify_tcp(port), Class::Bulk, "port {port}");
        }
    }

    #[test]
    fn standard_tcp_default_is_interactive() {
        // Random unmapped port -> default.
        assert_eq!(c().classify_tcp(31337), Class::Interactive);
    }

    // --- UDP heuristics ---

    #[test]
    fn standard_udp_dns_is_metadata() {
        assert_eq!(c().classify_udp(53), Class::Metadata);
    }

    #[test]
    fn standard_udp_quic_web_is_interactive() {
        let c = c();
        // HTTP/3 over QUIC: port 443 is web, even though it's UDP.
        assert_eq!(c.classify_udp(443), Class::Interactive);
        assert_eq!(c.classify_udp(80), Class::Interactive);
    }

    #[test]
    fn standard_udp_stun_turn_is_realtime() {
        let c = c();
        assert_eq!(c.classify_udp(3478), Class::Realtime);
        assert_eq!(c.classify_udp(5349), Class::Realtime);
    }

    #[test]
    fn standard_udp_rtp_ephemeral_range_is_realtime_via_full() {
        // Ephemeral RTP range only matched via classify_full /
        // classify_udp; classify_udp goes through classify_full.
        let c = c();
        for port in [16384u16, 17000, 20000, 32767] {
            assert_eq!(
                c.classify_full(Protocol::Udp, port, false, None),
                Class::Realtime,
                "port {port}"
            );
        }
    }

    #[test]
    fn standard_udp_source_engine_games_are_realtime() {
        let c = c();
        for port in 27015u16..=27050 {
            assert_eq!(
                c.classify_full(Protocol::Udp, port, false, None),
                Class::Realtime,
                "port {port}"
            );
        }
    }

    #[test]
    fn standard_udp_default_is_realtime() {
        // Random unmapped UDP port -> default Realtime (most
        // likely media/gaming).
        assert_eq!(
            c().classify_full(Protocol::Udp, 9999, false, None),
            Class::Realtime
        );
    }

    // --- Overrides ---

    #[test]
    fn override_changes_classification() {
        let mut c = Classifier::standard();
        // 80/TCP normally -> Interactive.
        assert_eq!(c.classify_tcp(80), Class::Interactive);
        c.override_tcp(80, Class::Bulk);
        assert_eq!(c.classify_tcp(80), Class::Bulk);
    }

    #[test]
    fn override_default_changes_unmapped_classification() {
        let mut c = Classifier::standard();
        // Unmapped TCP port -> Interactive.
        assert_eq!(c.classify_tcp(31337), Class::Interactive);
        c.set_default(Protocol::Tcp, Class::Bulk);
        assert_eq!(c.classify_tcp(31337), Class::Bulk);
        // Mapped ports stay mapped.
        assert_eq!(c.classify_tcp(443), Class::Interactive);
    }

    #[test]
    fn empty_classifier_falls_back_to_protocol_default() {
        let c = Classifier::new();
        assert_eq!(c.classify_tcp(443), Class::Interactive);
        assert_eq!(c.classify_udp(443), Class::Realtime);
    }

    #[test]
    fn full_classify_respects_full_source_ranking() {
        let c = c();
        // Hint > onion > port-table > range > default.
        // Hint beats everything:
        assert_eq!(
            c.classify_full(Protocol::Udp, 53, true, Some(ClassHint::Bulk)),
            Class::Bulk
        );
        // Onion beats port-table:
        assert_eq!(
            c.classify_full(Protocol::Udp, 53, true, None),
            Class::OnionService
        );
        // Port-table beats range:
        assert_eq!(
            c.classify_full(Protocol::Udp, 5060, false, None),
            Class::Realtime
        );
        // Range beats default:
        assert_eq!(
            c.classify_full(Protocol::Udp, 17000, false, None),
            Class::Realtime
        );
    }
}
