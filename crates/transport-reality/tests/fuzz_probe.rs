//! Property-based fuzz tests for the REALITY-v2 auth-probe layer.
//!
//! The probe verifier is the FIRST code path that touches bytes from a
//! scanning adversary. It must:
//!
//! 1. Never panic on any input (bytes, keys, timestamps).
//! 2. Always fail cleanly for adversarial input - and the failure MUST
//!    map to a single cover-service behavior regardless of which check
//!    rejected.
//! 3. Never allocate unboundedly.

use mirage_crypto::x25519_dalek::{PublicKey, StaticSecret};
use mirage_transport_reality::probe::{
    build_probe, verify_probe, BridgeProbeInputs, ClientProbeInputs, NONCE_LEN,
    PROBE_ROOT_DISABLED, SESSION_ID_LEN,
};
use mirage_transport_reality::ReplayProbeSet;
use proptest::prelude::*;

fn rand_seed() -> [u8; 32] {
    let mut s = [0u8; 32];
    getrandom::fill(&mut s).unwrap();
    s
}

fn fresh_bridge() -> (StaticSecret, [u8; 32]) {
    let sk = StaticSecret::from(rand_seed());
    let pk: [u8; 32] = PublicKey::from(&sk).to_bytes();
    (sk, pk)
}

fn fresh_eph() -> (StaticSecret, [u8; 32]) {
    let sk = StaticSecret::from(rand_seed());
    let pk: [u8; 32] = PublicKey::from(&sk).to_bytes();
    (sk, pk)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// Arbitrary 32-byte wire probes. verify_probe MUST return Err, never panic.
    #[test]
    fn verify_arbitrary_wire_never_panics(
        wire in prop::array::uniform32(any::<u8>()),
        client_eph_pk in prop::array::uniform32(any::<u8>()),
        ch_random in prop::array::uniform32(any::<u8>()),
        now in any::<u32>(),
    ) {
        let (bridge_sk, _) = fresh_bridge();
        let mut rs = ReplayProbeSet::new(64);
        let _ = verify_probe(&mut BridgeProbeInputs {
            bridge_static_sk: &bridge_sk,
            client_eph_pk: &client_eph_pk,
            ch_random: &ch_random,
            now_unix: now,
            wire_probe: wire,
            probe_root: &PROBE_ROOT_DISABLED,
            accept_legacy: true,
            replay_set: &mut rs,
        });
    }

    /// Arbitrary byte length for session_id - MUST reject cleanly and
    /// not panic even if the caller somehow supplies the wrong length.
    /// (The type system forbids this at the fn boundary, but the probe
    /// `Probe::decode` accepts arbitrary `&[u8]`.)
    #[test]
    fn probe_decode_arbitrary_never_panics(
        bytes in prop::collection::vec(any::<u8>(), 0..256),
    ) {
        let _ = mirage_transport_reality::probe::Probe::decode(&bytes);
    }

    /// Valid probes always verify; tampering ANY field causes rejection
    /// without panic.
    #[test]
    fn tamper_any_byte_rejects(
        tamper_offset in 0usize..SESSION_ID_LEN,
        tamper_mask in 1u8..=255,
    ) {
        let (bridge_sk, bridge_pk) = fresh_bridge();
        let (client_sk, client_pk) = fresh_eph();
        let ch_random = [0xAAu8; 32];
        let nonce: [u8; NONCE_LEN] = rand_seed()[..NONCE_LEN].try_into().unwrap();
        let now = 1_700_000_000u32;

        let probe = build_probe(&ClientProbeInputs {
            eph_sk: &client_sk,
            bridge_static_pk: &bridge_pk,
            ch_random: &ch_random,
            nonce,
            probe_root: &PROBE_ROOT_DISABLED,
            now_unix: now,
        })
        .unwrap();

        let mut wire = probe.encode();
        wire[tamper_offset] ^= tamper_mask;

        let mut rs = ReplayProbeSet::new(64);
        let res = verify_probe(&mut BridgeProbeInputs {
            bridge_static_sk: &bridge_sk,
            client_eph_pk: &client_pk,
            ch_random: &ch_random,
            now_unix: now,
            wire_probe: wire,
            probe_root: &PROBE_ROOT_DISABLED,
            accept_legacy: true,
            replay_set: &mut rs,
        });
        // Every tampered byte MUST cause verification to fail.
        prop_assert!(res.is_err());
    }

    /// For any ClientHello.random value, probe construction must succeed
    /// and verification must succeed round-trip. No `ch_random` is "bad."
    #[test]
    fn any_ch_random_roundtrips(
        ch_random in prop::array::uniform32(any::<u8>()),
    ) {
        let (bridge_sk, bridge_pk) = fresh_bridge();
        let (client_sk, client_pk) = fresh_eph();
        let nonce: [u8; NONCE_LEN] = rand_seed()[..NONCE_LEN].try_into().unwrap();
        let now = 1_700_000_000u32;
        let probe = build_probe(&ClientProbeInputs {
            eph_sk: &client_sk,
            bridge_static_pk: &bridge_pk,
            ch_random: &ch_random,
            nonce,
            probe_root: &PROBE_ROOT_DISABLED,
            now_unix: now,
        }).unwrap();
        let mut rs = ReplayProbeSet::new(64);
        verify_probe(&mut BridgeProbeInputs {
            bridge_static_sk: &bridge_sk,
            client_eph_pk: &client_pk,
            ch_random: &ch_random,
            now_unix: now,
            wire_probe: probe.encode(),
            probe_root: &PROBE_ROOT_DISABLED,
            accept_legacy: true,
            replay_set: &mut rs,
        }).expect("roundtrip");
    }

    /// At any point within the +/-60s window, verification succeeds.
    #[test]
    fn any_skew_within_window_verifies(
        skew_secs in -(TIMESTAMP_WINDOW as i64)..=(TIMESTAMP_WINDOW as i64),
    ) {
        let (bridge_sk, bridge_pk) = fresh_bridge();
        let (client_sk, client_pk) = fresh_eph();
        let ch_random = [0xAAu8; 32];
        let nonce: [u8; NONCE_LEN] = rand_seed()[..NONCE_LEN].try_into().unwrap();
        let client_time = 1_700_000_000u32;
        let probe = build_probe(&ClientProbeInputs {
            eph_sk: &client_sk,
            bridge_static_pk: &bridge_pk,
            ch_random: &ch_random,
            nonce,
            probe_root: &PROBE_ROOT_DISABLED,
            now_unix: client_time,
        }).unwrap();
        let bridge_time = (client_time as i64 + skew_secs) as u32;
        let mut rs = ReplayProbeSet::new(64);
        verify_probe(&mut BridgeProbeInputs {
            bridge_static_sk: &bridge_sk,
            client_eph_pk: &client_pk,
            ch_random: &ch_random,
            now_unix: bridge_time,
            wire_probe: probe.encode(),
            probe_root: &PROBE_ROOT_DISABLED,
            accept_legacy: true,
            replay_set: &mut rs,
        }).expect("skew within window must verify");
    }
}

const TIMESTAMP_WINDOW: u64 = mirage_transport_reality::probe::TIMESTAMP_WINDOW_SECONDS;

// Sanity smoke: many parallel probes with random nonces all verify and
// populate the replay set without collision.
#[test]
fn many_fresh_probes_fill_replay_set_without_false_reject() {
    let (bridge_sk, bridge_pk) = fresh_bridge();
    let ch_random = [0xCCu8; 32];
    let now = 1_700_000_000u32;
    let mut rs = ReplayProbeSet::new(1024);

    for i in 0..256u32 {
        let (client_sk, client_pk) = fresh_eph();
        let mut nonce = [0u8; NONCE_LEN];
        nonce[..4].copy_from_slice(&i.to_be_bytes());
        let probe = build_probe(&ClientProbeInputs {
            eph_sk: &client_sk,
            bridge_static_pk: &bridge_pk,
            ch_random: &ch_random,
            nonce,
            probe_root: &PROBE_ROOT_DISABLED,
            now_unix: now,
        })
        .unwrap();
        verify_probe(&mut BridgeProbeInputs {
            bridge_static_sk: &bridge_sk,
            client_eph_pk: &client_pk,
            ch_random: &ch_random,
            now_unix: now,
            wire_probe: probe.encode(),
            probe_root: &PROBE_ROOT_DISABLED,
            accept_legacy: true,
            replay_set: &mut rs,
        })
        .unwrap_or_else(|e| panic!("fresh probe #{} must verify: {:?}", i, e));
    }
    assert_eq!(rs.len(), 256);
}
