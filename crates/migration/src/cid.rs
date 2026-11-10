//! Connection ID (CID).
//!
//! 16 bytes drawn from CSPRNG. The CID is the per-direction match
//! key the receiver uses to dispatch incoming packets to the
//! correct connection state.
//!
//! Both peers issue their own CIDs: the **destination CID** in an
//! outgoing packet is the value the PEER picked (so it can route);
//! the **source CID** is the value the local side picked (so the
//! peer can route the reply). [`CidPair`] holds both.

use mirage_crypto::subtle::ConstantTimeEq;

/// Connection-ID byte length. 16 bytes = ~128 bits of randomness;
/// matches QUIC's recommended CID length.
pub const CID_LEN: usize = 16;

/// A connection identifier.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Cid(pub [u8; CID_LEN]);

impl Cid {
    /// Construct from raw bytes.
    pub fn from_bytes(bytes: [u8; CID_LEN]) -> Self {
        Self(bytes)
    }

    /// Generate a fresh CID from the OS CSPRNG. On RNG failure
    /// (vanishingly rare; misconfigured container) returns
    /// `None`. Caller MUST decide between fail-closed (refuse
    /// connection) and retry.
    pub fn random() -> Option<Self> {
        let mut bytes = [0u8; CID_LEN];
        getrandom::fill(&mut bytes).ok()?;
        Some(Self(bytes))
    }

    /// Raw byte slice.
    pub fn as_bytes(&self) -> &[u8; CID_LEN] {
        &self.0
    }

    /// Constant-time equality.
    pub fn ct_eq(&self, other: &Cid) -> bool {
        self.0.ct_eq(&other.0).unwrap_u8() == 1
    }

    /// Hex representation. Diagnostics only; do NOT use for
    /// equality (use [`Self::ct_eq`]).
    pub fn to_hex(&self) -> String {
        use std::fmt::Write as _;
        let mut s = String::with_capacity(CID_LEN * 2);
        for b in &self.0 {
            // Writing to a String is infallible.
            let _ = write!(s, "{b:02x}");
        }
        s
    }
}

impl std::fmt::Debug for Cid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Cid({})", self.to_hex())
    }
}

impl std::fmt::Display for Cid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// Both peers' CIDs for a connection direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CidPair {
    /// CID the LOCAL side uses to identify its own state. The
    /// peer puts this in `dest_cid` field of outgoing packets.
    pub local: Cid,
    /// CID the PEER uses. The local side puts this in `dest_cid`
    /// when sending to the peer.
    pub remote: Cid,
}

impl CidPair {
    /// Generate both CIDs from CSPRNG.
    pub fn random() -> Option<Self> {
        Some(Self {
            local: Cid::random()?,
            remote: Cid::random()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cid_random_is_distinct() {
        let a = Cid::random().expect("rng");
        let b = Cid::random().expect("rng");
        assert!(!a.ct_eq(&b), "two random CIDs collided (rng broken)");
    }

    #[test]
    fn cid_constant_time_eq() {
        let a = Cid::from_bytes([0xAAu8; CID_LEN]);
        let b = Cid::from_bytes([0xAAu8; CID_LEN]);
        let c = Cid::from_bytes([0xBBu8; CID_LEN]);
        assert!(a.ct_eq(&b));
        assert!(!a.ct_eq(&c));
    }

    #[test]
    fn cid_pair_random_yields_distinct() {
        let p = CidPair::random().expect("rng");
        assert!(!p.local.ct_eq(&p.remote));
    }

    #[test]
    fn cid_to_hex_roundtrip() {
        let a = Cid::from_bytes([0x01u8; CID_LEN]);
        assert_eq!(a.to_hex(), "01010101010101010101010101010101");
        assert_eq!(format!("{a}"), "01010101010101010101010101010101");
    }

    #[test]
    fn cid_debug_doesnt_panic() {
        let a = Cid::random().expect("rng");
        let _ = format!("{a:?}");
    }
}
