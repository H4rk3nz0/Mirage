//! **Attack**: active probe replay.
//!
//! The censor captures a legitimate Mirage client's `ClientHello`
//! (e.g., from a tap on a residential ISP) and replays it against
//! a suspected bridge. If the bridge accepts the replay, it's
//! confirmed as Mirage. If the bridge falls through to cover
//! identically to a probe with random bytes, it's indistinguishable.
//!
//! **Defense being tested**: replay-probe set in
//! `mirage_transport_reality::probe`; per-prober key in the
//! `ClientHello`'s `session_id` slot.
//!
//! **Distinguisher we look for**: a replayed `ClientHello`
//! produces a different bridge response than a fresh-random one.
//!
//! Phase 2K scope: this adversary tests the **replay-set
//! semantic** at the verifier level. End-to-end probing against
//! a live bridge needs an in-process bridge daemon - that's the
//! Phase 2L integration scope. For now, we build a genuinely
//! valid probe (correct X25519-derived tag + in-window
//! timestamp), confirm `verify_probe` accepts it once and
//! inserts it into the `ReplayProbeSet`, then confirm a
//! byte-identical replay is rejected exactly as a fresh garbage
//! probe is - both fall through to cover with no wire-visible
//! difference.

use crate::{AdversaryError, AdversaryResult, DetectionVerdict};
use mirage_crypto::x25519_dalek::{PublicKey, StaticSecret};
use mirage_transport_reality::error::RealityError;
use mirage_transport_reality::probe::{
    build_probe, verify_probe, BridgeProbeInputs, ClientProbeInputs, NONCE_LEN,
    PROBE_ROOT_DISABLED, SESSION_ID_LEN,
};
use mirage_transport_reality::replay::ReplayProbeSet;

/// Run the replay-attack check against the REAL Reality probe
/// verifier + replay set.
///
/// Unlike the earlier stub (which fed the verifier random bytes
/// that never survived the tag check, so the replay-set step was
/// never reached), this builds a **genuinely valid** probe with
/// [`build_probe`] - correct X25519-derived tag and a fresh,
/// in-window timestamp - so [`verify_probe`] runs all the way to
/// its final `check_and_insert` step.
///
/// It then drives three verifications against a shared
/// [`ReplayProbeSet`]:
///
/// 1. **Valid probe, first sight.** MUST verify `Ok` and insert
///    the `(nonce, timestamp)` pair into the replay set.
/// 2. **Byte-identical replay** of the captured `ClientHello`. MUST
///    be caught by the replay set as [`RealityError::Replay`].
/// 3. **Fresh, in-window garbage probe** (random tag). Rejected at
///    the auth stage.
///
/// The defense holds iff the replay is caught AND both the replay
/// and the fresh garbage map to the **same** wire-visible outcome
/// (cover-service fallback) - i.e. the censor gains no 1-bit oracle
/// that separates a replayed capture from random noise.
pub async fn active_probe_replay() -> AdversaryResult {
    // Real bridge static keypair + real client ephemeral. Deterministic
    // seeds keep the adversary reproducible; the crypto is genuine.
    let bridge_sk = StaticSecret::from([0xAA; 32]);
    let bridge_pk: [u8; 32] = PublicKey::from(&bridge_sk).to_bytes();
    let client_eph_sk = StaticSecret::from([0x11; 32]);
    let client_eph_pk: [u8; 32] = PublicKey::from(&client_eph_sk).to_bytes();
    let ch_random = [0xCCu8; 32];
    let nonce = [0x77u8; NONCE_LEN];
    let now = 1_700_000_000u32;

    // Build a probe exactly as a real Mirage client would, so it carries a
    // correct tag and reaches the replay-check step in `verify_probe`.
    let probe = build_probe(&ClientProbeInputs {
        eph_sk: &client_eph_sk,
        bridge_static_pk: &bridge_pk,
        ch_random: &ch_random,
        nonce,
        now_unix: now,
        probe_root: &PROBE_ROOT_DISABLED,
    })
    .map_err(|e| AdversaryError::Parse(format!("probe construction failed: {e}")))?;
    let wire_valid = probe.encode();

    // Fresh, in-window garbage probe: same timestamp so it clears the
    // freshness check and is rejected at the tag stage (like a real active
    // prober guessing bytes), never touching the replay set.
    let mut wire_garbage = [0xDDu8; SESSION_ID_LEN];
    wire_garbage[NONCE_LEN..NONCE_LEN + 4].copy_from_slice(&now.to_be_bytes());

    let mut replay_set = ReplayProbeSet::new(64);

    // 1. Valid probe, first sight -> Ok + inserts into the replay set.
    let r_first = verify_probe(&mut BridgeProbeInputs {
        bridge_static_sk: &bridge_sk,
        client_eph_pk: &client_eph_pk,
        ch_random: &ch_random,
        now_unix: now,
        wire_probe: wire_valid,
        probe_root: &PROBE_ROOT_DISABLED,
        accept_legacy: true,
        replay_set: &mut replay_set,
    });

    // 2. Byte-identical replay of the captured ClientHello -> Err(Replay).
    let r_replay = verify_probe(&mut BridgeProbeInputs {
        bridge_static_sk: &bridge_sk,
        client_eph_pk: &client_eph_pk,
        ch_random: &ch_random,
        now_unix: now,
        wire_probe: wire_valid,
        probe_root: &PROBE_ROOT_DISABLED,
        accept_legacy: true,
        replay_set: &mut replay_set,
    });

    // 3. Fresh in-window garbage -> rejected at the auth (tag) stage.
    let r_garbage = verify_probe(&mut BridgeProbeInputs {
        bridge_static_sk: &bridge_sk,
        client_eph_pk: &client_eph_pk,
        ch_random: &ch_random,
        now_unix: now,
        wire_probe: wire_garbage,
        probe_root: &PROBE_ROOT_DISABLED,
        accept_legacy: true,
        replay_set: &mut replay_set,
    });

    // The valid probe MUST be accepted on first sight; otherwise the replay
    // step was never driven and the whole check is vacuous - this was the
    // original F12 bug (the stub never reached `check_and_insert`).
    if let Err(e) = &r_first {
        return Ok(DetectionVerdict::Distinguished(format!(
            "valid first-seen probe REJECTED ({e:?}) - the replay-check step \
             was never reached, so the ReplayProbeSet defense is untested."
        )));
    }

    // The byte-identical replay MUST be caught specifically as Replay.
    if r_replay != Err(RealityError::Replay) {
        return Ok(DetectionVerdict::Distinguished(format!(
            "byte-identical replay yielded {r_replay:?}, expected Err(Replay) \
             - ReplayProbeSet did not catch the captured ClientHello."
        )));
    }

    // Wire-visible behavior: `Ok` => bridge accepts as Mirage; ANY `Err` =>
    // fall through to cover-service. The censor observes only THIS bit. A
    // replay and a fresh garbage probe MUST map to the same bit, else the
    // censor has a 1-bit oracle separating a replayed capture from random.
    let wire = |r: &Result<(), RealityError>| -> &'static str {
        if r.is_ok() {
            "accept-as-mirage"
        } else {
            "cover-fallback"
        }
    };
    let w_replay = wire(&r_replay);
    let w_garbage = wire(&r_garbage);
    if w_replay != w_garbage {
        return Ok(DetectionVerdict::Distinguished(format!(
            "replay maps to wire `{w_replay}` but first-seen garbage maps to \
             `{w_garbage}` - censor distinguishes a replayed capture from random."
        )));
    }

    Ok(DetectionVerdict::Defended)
}

/// Boxed [`Adversary`] wrapper.
pub struct ActiveProbeReplay;

#[async_trait::async_trait]
impl crate::Adversary for ActiveProbeReplay {
    async fn run(&self) -> Result<DetectionVerdict, AdversaryError> {
        active_probe_replay().await
    }
    fn name(&self) -> &'static str {
        "active_probe_replay"
    }
    fn defense(&self) -> &'static str {
        "Reality replay-probe set: valid probe accepted once; byte-identical \
         replay -> cover fallback, indistinguishable from fresh garbage"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn replay_maps_to_cover_with_no_oracle() {
        let verdict = active_probe_replay().await.expect("adversary ran");
        assert!(
            verdict.is_defended(),
            "replay oracle re-emerged: {verdict:?}"
        );
    }

    /// Directly assert the two load-bearing facts against the REAL
    /// defense: a valid probe verifies once (inserting into the replay
    /// set) and a byte-identical replay is caught as `Err(Replay)`. This
    /// genuinely drives `ReplayProbeSet::check_and_insert`.
    #[test]
    fn first_seen_ok_then_byte_identical_replay_is_replay() {
        let bridge_sk = StaticSecret::from([0x01; 32]);
        let bridge_pk: [u8; 32] = PublicKey::from(&bridge_sk).to_bytes();
        let client_sk = StaticSecret::from([0x02; 32]);
        let client_pk: [u8; 32] = PublicKey::from(&client_sk).to_bytes();
        let ch_random = [0x33u8; 32];
        let nonce = [0x44u8; NONCE_LEN];
        let now = 1_700_000_000u32;

        let probe = build_probe(&ClientProbeInputs {
            eph_sk: &client_sk,
            bridge_static_pk: &bridge_pk,
            ch_random: &ch_random,
            nonce,
            now_unix: now,
            probe_root: &PROBE_ROOT_DISABLED,
        })
        .expect("valid probe builds");
        let wire = probe.encode();
        let mut rs = ReplayProbeSet::new(64);

        let first = verify_probe(&mut BridgeProbeInputs {
            bridge_static_sk: &bridge_sk,
            client_eph_pk: &client_pk,
            ch_random: &ch_random,
            now_unix: now,
            wire_probe: wire,
            probe_root: &PROBE_ROOT_DISABLED,
            accept_legacy: true,
            replay_set: &mut rs,
        });
        assert!(
            first.is_ok(),
            "valid probe must verify first-seen: {first:?}"
        );
        assert_eq!(
            rs.len(),
            1,
            "first-seen probe must insert into the replay set"
        );

        let replay = verify_probe(&mut BridgeProbeInputs {
            bridge_static_sk: &bridge_sk,
            client_eph_pk: &client_pk,
            ch_random: &ch_random,
            now_unix: now,
            wire_probe: wire,
            probe_root: &PROBE_ROOT_DISABLED,
            accept_legacy: true,
            replay_set: &mut rs,
        });
        assert_eq!(
            replay,
            Err(RealityError::Replay),
            "byte-identical replay must be caught as Err(Replay)"
        );
    }
}
