//! Rolling info-hash and per-epoch key derivation.
//!
//! All outputs are deterministic functions of `(shared_salt, namespace, epoch)`.
//! Different namespaces yield independent derivation trees even with the same
//! salt, so client<->bridge and bridge<->bridge discovery cannot cross-contaminate.

use mirage_crypto::blake3;
use mirage_crypto::zeroize::Zeroizing;

/// Default epoch length (1 hour). Mirrors [`mirage_spec::DISCOVERY_EPOCH_SECONDS`].
pub const DISCOVERY_EPOCH_SECONDS: u64 = mirage_spec::DISCOVERY_EPOCH_SECONDS;

/// Namespace bytes for client->bridge discovery (spec §4.1).
pub const NAMESPACE_CLIENT_TO_BRIDGE: &[u8] = b"mirage-namespace-c2b-v1";

/// Namespace bytes for bridge->bridge discovery (spec §4.1). v0.2+.
pub const NAMESPACE_BRIDGE_TO_BRIDGE: &[u8] = b"mirage-namespace-b2b-v1";

/// Info-hash length (20 bytes, BitTorrent-DHT compatible).
pub const INFO_HASH_LEN: usize = 20;
/// ChaCha20-Poly1305 key length.
pub const CIPHER_KEY_LEN: usize = 32;
/// ChaCha20-Poly1305 nonce length.
pub const CIPHER_NONCE_LEN: usize = 12;

/// Convert a Unix time (seconds) to an epoch number under the default period.
pub fn epoch_for_time(unix_secs: u64) -> u64 {
    unix_secs / DISCOVERY_EPOCH_SECONDS
}

/// Minimum allowed `port_base` for [`derive_port`]. Privileged ports
/// (< 1024) require root to bind on POSIX; the derivation refuses
/// to land there even if an operator misconfigures.
pub const DERIVED_PORT_MIN: u16 = 1024;

/// Per-epoch port-derivation primitive (A35).
///
/// Both bridge and client compute this locally from material they
/// already have:
/// - `shared_salt` from the invite (operator-published).
/// - `namespace` for the discovery direction.
/// - `epoch` from the current Unix time.
/// - `port_base` + `port_range` from the deployment config.
///
/// The derived port is **not secret** - anyone holding the invite
/// computes it. The defense is fingerprint rotation (a censor must
/// block the entire `port_base..port_base+port_range` to deny
/// service, vs. a single static port).
///
/// # Inspiration
///
/// The kadnap malware family used a similar primitive on the
/// BitTorrent DHT: it walked info-hash bytes to derive its C2 port.
/// Mirroring the technique for a defensive use case (censorship
/// resistance) - same property of "port follows rendezvous, rotates
/// per-epoch, no explicit byte on wire" - yields a passive-DPI
/// fingerprint-rotation defense.
///
/// # Algorithm
///
/// `port_base + (BLAKE3-keyed(salt, "mirage-port-v1" || namespace ||
/// epoch_be) [0..2] as u16 BE) % port_range`
///
/// Returns `port_base` if `port_range == 0` (degenerate config; the
/// caller is responsible for validating `port_range > 0`, but the
/// helper is still well-defined). Refuses to return a value below
/// [`DERIVED_PORT_MIN`].
///
/// # Errors
///
/// Returns `None` if `port_base < DERIVED_PORT_MIN`, if `port_base
/// + port_range as u32 > 65536`, or if `port_range == 0`. Callers
/// in the bridge daemon and client treat `None` as a config error.
pub fn derive_port(
    shared_salt: &[u8; 32],
    namespace: &[u8],
    epoch: u64,
    port_base: u16,
    port_range: u16,
) -> Option<u16> {
    if port_base < DERIVED_PORT_MIN {
        return None;
    }
    if port_range == 0 {
        return None;
    }
    if (port_base as u32) + (port_range as u32) > 65536 {
        return None;
    }
    let mut h = blake3::Hasher::new_keyed(shared_salt);
    h.update(b"mirage-port-v1");
    h.update(namespace);
    h.update(&epoch.to_be_bytes());
    let bytes = *h.finalize().as_bytes();
    let pick = u16::from_be_bytes([bytes[0], bytes[1]]);
    Some(port_base + (pick % port_range))
}

/// Rolling pseudo-random key (32 B) for a given `(shared_salt, namespace, epoch)`.
///
/// This is the intermediate secret from which `info_hash`, `cipher_key`, and
/// `cipher_nonce` are derived. Callers do not typically use it directly;
/// prefer [`info_hash`], [`cipher_key`], [`cipher_nonce`], or the combined
/// [`rolling_outputs`].
fn rolling_prk(shared_salt: &[u8; 32], namespace: &[u8], epoch: u64) -> [u8; 32] {
    let mut h = blake3::Hasher::new_keyed(shared_salt);
    h.update(b"mirage-rolling-v1");
    h.update(namespace);
    h.update(&epoch.to_be_bytes());
    *h.finalize().as_bytes()
}

/// Derive the info-hash for an epoch.
///
/// `info_hash` itself is public (appears on the wire). The intermediate
/// `prk` is per-epoch secret material and is zeroized on scope exit.
pub fn info_hash(shared_salt: &[u8; 32], namespace: &[u8], epoch: u64) -> [u8; INFO_HASH_LEN] {
    let prk = Zeroizing::new(rolling_prk(shared_salt, namespace, epoch));
    let mut h = blake3::Hasher::new_keyed(&prk);
    h.update(b"mirage-info-hash-v1");
    let full = h.finalize();
    let mut out = [0u8; INFO_HASH_LEN];
    out.copy_from_slice(&full.as_bytes()[..INFO_HASH_LEN]);
    out
}

/// Derive the ChaCha20-Poly1305 cipher key for an epoch.
///
/// Returns the key by value. Callers are expected to wrap in `Zeroizing`
/// for the same reasons this function's internal `prk` is wrapped.
pub fn cipher_key(shared_salt: &[u8; 32], namespace: &[u8], epoch: u64) -> [u8; CIPHER_KEY_LEN] {
    let prk = Zeroizing::new(rolling_prk(shared_salt, namespace, epoch));
    let mut h = blake3::Hasher::new_keyed(&prk);
    h.update(b"mirage-cipher-key-v1");
    *h.finalize().as_bytes()
}

/// Derive the ChaCha20-Poly1305 nonce for an epoch.
pub fn cipher_nonce(
    shared_salt: &[u8; 32],
    namespace: &[u8],
    epoch: u64,
) -> [u8; CIPHER_NONCE_LEN] {
    let prk = Zeroizing::new(rolling_prk(shared_salt, namespace, epoch));
    let mut h = blake3::Hasher::new_keyed(&prk);
    h.update(b"mirage-cipher-nonce-v1");
    let full = h.finalize();
    let mut out = [0u8; CIPHER_NONCE_LEN];
    out.copy_from_slice(&full.as_bytes()[..CIPHER_NONCE_LEN]);
    out
}

/// Derive all three outputs at once. Preferred over separate calls to avoid
/// recomputing `rolling_prk`.
pub fn rolling_outputs(
    shared_salt: &[u8; 32],
    namespace: &[u8],
    epoch: u64,
) -> (
    [u8; INFO_HASH_LEN],
    [u8; CIPHER_KEY_LEN],
    [u8; CIPHER_NONCE_LEN],
) {
    let prk = Zeroizing::new(rolling_prk(shared_salt, namespace, epoch));
    let ih = {
        let mut h = blake3::Hasher::new_keyed(&prk);
        h.update(b"mirage-info-hash-v1");
        let full = h.finalize();
        let mut out = [0u8; INFO_HASH_LEN];
        out.copy_from_slice(&full.as_bytes()[..INFO_HASH_LEN]);
        out
    };
    let ck = {
        let mut h = blake3::Hasher::new_keyed(&prk);
        h.update(b"mirage-cipher-key-v1");
        *h.finalize().as_bytes()
    };
    let cn = {
        let mut h = blake3::Hasher::new_keyed(&prk);
        h.update(b"mirage-cipher-nonce-v1");
        let full = h.finalize();
        let mut out = [0u8; CIPHER_NONCE_LEN];
        out.copy_from_slice(&full.as_bytes()[..CIPHER_NONCE_LEN]);
        out
    };
    (ih, ck, cn)
}

/// Rotation-announcement info-hash (§9.2). Same across all epochs for a given
/// salt - clients poll this at a low rate.
pub fn rotation_info_hash(shared_salt: &[u8; 32]) -> [u8; INFO_HASH_LEN] {
    let mut h = blake3::Hasher::new_keyed(shared_salt);
    h.update(b"mirage-rotation-v1");
    let full = h.finalize();
    let mut out = [0u8; INFO_HASH_LEN];
    out.copy_from_slice(&full.as_bytes()[..INFO_HASH_LEN]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn salt() -> [u8; 32] {
        *b"0123456789abcdef0123456789abcdef"
    }

    #[test]
    fn deterministic_for_same_inputs() {
        let s = salt();
        let a = info_hash(&s, NAMESPACE_CLIENT_TO_BRIDGE, 42);
        let b = info_hash(&s, NAMESPACE_CLIENT_TO_BRIDGE, 42);
        assert_eq!(a, b);
    }

    #[test]
    fn different_epoch_yields_different_hash() {
        let s = salt();
        let a = info_hash(&s, NAMESPACE_CLIENT_TO_BRIDGE, 42);
        let b = info_hash(&s, NAMESPACE_CLIENT_TO_BRIDGE, 43);
        assert_ne!(a, b, "consecutive epochs MUST yield different info-hashes");
    }

    #[test]
    fn different_namespace_yields_different_hash() {
        let s = salt();
        let a = info_hash(&s, NAMESPACE_CLIENT_TO_BRIDGE, 42);
        let b = info_hash(&s, NAMESPACE_BRIDGE_TO_BRIDGE, 42);
        assert_ne!(a, b, "namespaces MUST be cryptographically independent");
    }

    #[test]
    fn different_salt_yields_different_hash() {
        let mut s1 = salt();
        let mut s2 = salt();
        s2[0] ^= 0x01;
        let a = info_hash(&s1, NAMESPACE_CLIENT_TO_BRIDGE, 42);
        let b = info_hash(&s2, NAMESPACE_CLIENT_TO_BRIDGE, 42);
        assert_ne!(a, b);
        // Silence unused-mut warning and assert distinct salts.
        s1[0] ^= 0x00;
        assert_ne!(s1, s2);
    }

    #[test]
    fn cipher_key_and_nonce_are_distinct() {
        // Even derived from the same PRK, cipher_key and cipher_nonce use
        // different labels and so MUST produce different bytes.
        let s = salt();
        let ck = cipher_key(&s, NAMESPACE_CLIENT_TO_BRIDGE, 100);
        let cn = cipher_nonce(&s, NAMESPACE_CLIENT_TO_BRIDGE, 100);
        // First 12 bytes of key should not coincide with the full nonce (would
        // indicate label mixing bug).
        assert_ne!(&ck[..12], &cn[..]);
    }

    #[test]
    fn rolling_outputs_matches_individual_calls() {
        let s = salt();
        let (ih1, ck1, cn1) = rolling_outputs(&s, NAMESPACE_CLIENT_TO_BRIDGE, 7);
        let ih2 = info_hash(&s, NAMESPACE_CLIENT_TO_BRIDGE, 7);
        let ck2 = cipher_key(&s, NAMESPACE_CLIENT_TO_BRIDGE, 7);
        let cn2 = cipher_nonce(&s, NAMESPACE_CLIENT_TO_BRIDGE, 7);
        assert_eq!(ih1, ih2);
        assert_eq!(ck1, ck2);
        assert_eq!(cn1, cn2);
    }

    #[test]
    fn derive_port_is_deterministic() {
        let s = salt();
        let p1 = derive_port(&s, NAMESPACE_CLIENT_TO_BRIDGE, 1000, 8000, 1000).unwrap();
        let p2 = derive_port(&s, NAMESPACE_CLIENT_TO_BRIDGE, 1000, 8000, 1000).unwrap();
        assert_eq!(p1, p2);
    }

    #[test]
    fn derive_port_in_range() {
        let s = salt();
        for epoch in 0..200 {
            let p = derive_port(&s, NAMESPACE_CLIENT_TO_BRIDGE, epoch, 8000, 1000).unwrap();
            assert!(
                (8000..9000).contains(&p),
                "port {p} out of [8000, 9000) at epoch {epoch}"
            );
        }
    }

    #[test]
    fn derive_port_rotates_per_epoch() {
        // Sample across 1024 epochs; expect the derived port to take
        // many distinct values (at least 200 of the 1000-wide range).
        // A constant function would yield only 1 distinct value.
        use std::collections::HashSet;
        let s = salt();
        let seen: HashSet<u16> = (0..1024)
            .map(|e| derive_port(&s, NAMESPACE_CLIENT_TO_BRIDGE, e, 8000, 1000).unwrap())
            .collect();
        assert!(
            seen.len() > 200,
            "derived port lacks rotation entropy: only {} distinct values across 1024 epochs",
            seen.len()
        );
    }

    #[test]
    fn derive_port_separates_namespaces() {
        let s = salt();
        // Same epoch, different namespaces -> different derived ports
        // (at least most of the time).
        let mut diff = 0;
        for e in 0..256u64 {
            let p1 = derive_port(&s, NAMESPACE_CLIENT_TO_BRIDGE, e, 8000, 1000).unwrap();
            let p2 = derive_port(&s, NAMESPACE_BRIDGE_TO_BRIDGE, e, 8000, 1000).unwrap();
            if p1 != p2 {
                diff += 1;
            }
        }
        assert!(
            diff > 230,
            "namespaces don't separate: {diff} / 256 epochs differ"
        );
    }

    #[test]
    fn derive_port_separates_salts() {
        let s1 = salt();
        let mut s2 = salt();
        s2[0] ^= 1;
        let mut diff = 0;
        for e in 0..256u64 {
            let p1 = derive_port(&s1, NAMESPACE_CLIENT_TO_BRIDGE, e, 8000, 1000).unwrap();
            let p2 = derive_port(&s2, NAMESPACE_CLIENT_TO_BRIDGE, e, 8000, 1000).unwrap();
            if p1 != p2 {
                diff += 1;
            }
        }
        assert!(
            diff > 230,
            "salt change doesn't separate: {diff} / 256 epochs differ"
        );
    }

    #[test]
    fn derive_port_rejects_privileged_base() {
        let s = salt();
        assert_eq!(
            derive_port(&s, NAMESPACE_CLIENT_TO_BRIDGE, 0, 80, 100),
            None
        );
        assert_eq!(
            derive_port(&s, NAMESPACE_CLIENT_TO_BRIDGE, 0, 1023, 100),
            None
        );
        // 1024 is the floor - accepted.
        assert!(derive_port(&s, NAMESPACE_CLIENT_TO_BRIDGE, 0, 1024, 100).is_some());
    }

    #[test]
    fn derive_port_rejects_zero_range() {
        let s = salt();
        assert_eq!(
            derive_port(&s, NAMESPACE_CLIENT_TO_BRIDGE, 0, 8000, 0),
            None
        );
    }

    #[test]
    fn derive_port_rejects_overflow() {
        let s = salt();
        // base + range > 65536: the derived port could exceed u16
        // bounds. Refuse rather than wrap.
        assert_eq!(
            derive_port(&s, NAMESPACE_CLIENT_TO_BRIDGE, 0, 60000, 6000),
            None
        );
        // Exactly 65536: still rejected (port 65536 is invalid).
        assert_eq!(
            derive_port(&s, NAMESPACE_CLIENT_TO_BRIDGE, 0, 65535, 2),
            None
        );
        // Tight fit: base=65535, range=1 -> can only return 65535.
        assert_eq!(
            derive_port(&s, NAMESPACE_CLIENT_TO_BRIDGE, 0, 65535, 1).unwrap(),
            65535
        );
    }

    #[test]
    fn epoch_for_time_floors() {
        assert_eq!(epoch_for_time(0), 0);
        assert_eq!(epoch_for_time(DISCOVERY_EPOCH_SECONDS - 1), 0);
        assert_eq!(epoch_for_time(DISCOVERY_EPOCH_SECONDS), 1);
        assert_eq!(epoch_for_time(DISCOVERY_EPOCH_SECONDS * 42 + 5), 42);
    }

    #[test]
    fn rotation_info_hash_is_epoch_independent() {
        let s = salt();
        let a = rotation_info_hash(&s);
        let b = rotation_info_hash(&s);
        assert_eq!(a, b);
        // And different from any epoch-based info-hash.
        let c = info_hash(&s, NAMESPACE_CLIENT_TO_BRIDGE, 0);
        assert_ne!(a, c);
    }
}
