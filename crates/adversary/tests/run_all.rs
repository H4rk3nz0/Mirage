//! Continuously verified defenses: every adversary in
//! `mirage-adversary` runs here as part of `cargo test`. A
//! regression in any defense surfaces as a test failure.

use mirage_adversary::*;

#[tokio::test]
async fn rt_cn_4_weighted_ja3_blends_with_population() {
    let verdict = ja3_signature_match(2000).await.expect("ja3 attack ran");
    assert!(verdict.is_defended(), "RT-CN-4 regression: {verdict:?}");
}

#[tokio::test]
async fn rt_cn_4_baseline_uniform_distinguishes_documented() {
    // Documents the (pre-RT-CN-4) failure mode: uniform rotation
    // yields Chrome share ~33% vs real-world ~75%. We assert
    // Distinguished here so a future "fix" that accidentally
    // makes pick_random_template weighted-too would notice.
    let verdict = ja3::ja3_uniform_population_skew(2000)
        .await
        .expect("baseline ran");
    assert!(
        verdict.is_distinguished(),
        "baseline must distinguish to document the contrast with RT-CN-4: {verdict:?}"
    );
}

#[tokio::test]
async fn rt_cn_3_tarpit_timing_collapses_to_fast_close() {
    let verdict = tarpit_timing_oracle(50).await.expect("tarpit attack ran");
    assert!(
        verdict.is_defended(),
        "RT-CN-3 regression: tarpit re-emerged. {verdict:?}"
    );
}

#[tokio::test]
async fn rt_cn_9_announcement_version_universal_v0_1t() {
    let verdict = announcement_version_tag_leak()
        .await
        .expect("version-leak attack ran");
    assert!(
        verdict.is_defended(),
        "RT-CN-9 regression: encoder leaked single-vs-multi version. {verdict:?}"
    );
}

#[tokio::test]
async fn rt_cn_11_token_batch_smeared_with_jitter() {
    let verdict = token_batch_correlator(100, 3600).await.expect("ok");
    assert!(
        verdict.is_defended(),
        "RT-CN-11 regression: token batch collapsed to one expiry. {verdict:?}"
    );
}

#[tokio::test]
async fn rt_cn_11_baseline_no_jitter_distinguishes_documented() {
    let verdict = token_batch::token_batch_no_jitter_baseline(100)
        .await
        .expect("ok");
    assert!(
        verdict.is_distinguished(),
        "baseline must distinguish for contrast with RT-CN-11: {verdict:?}"
    );
}

#[tokio::test]
async fn rt_cn_10_in_memory_baseline_fails_documented() {
    // Documents that the InMemoryRevealStore deliberately does
    // NOT close RT-CN-10. Operators in adversarial deployments
    // MUST use a persistent backing.
    let verdict = cohort_dos::cohort_restart_dos_in_memory_baseline()
        .await
        .expect("ok");
    assert!(
        verdict.is_distinguished(),
        "InMemoryRevealStore should be distinguishable by restart-DoS - \
         pinned so operators don't accidentally rely on it: {verdict:?}"
    );
}

#[tokio::test]
async fn rt_cn_10_file_backed_survives_restart() {
    // RT-CN-10 fully closed: the file-backed RevealStore
    // persists reveal records across restarts; the censor can't
    // re-exhaust the cohort cap by triggering bridge restarts.
    let verdict = cohort_dos::cohort_restart_dos_file_backed()
        .await
        .expect("ok");
    assert!(
        verdict.is_defended(),
        "RT-CN-10 regression: FileRevealStore didn't persist across simulated restart: {verdict:?}"
    );
}

#[tokio::test]
async fn frame_length_oracle_closed_by_fixed_cell_size() {
    let verdict = relay_payload_length_classifier().await.expect("ok");
    assert!(verdict.is_defended(), "Cell-length leak: {verdict:?}");
}

#[tokio::test]
async fn active_probe_replay_no_oracle() {
    let verdict = active_probe_replay().await.expect("ok");
    assert!(
        verdict.is_defended(),
        "Replay oracle in probe verifier: {verdict:?}"
    );
}
