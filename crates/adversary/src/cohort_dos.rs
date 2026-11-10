//! **Attack**: cohort-reveal-cap restart `DoS`.
//!
//! A censor running a bridge in the cohort requests
//! `DEFAULT_PER_TOKEN_REVEAL_CAP` announcements, hits the cap,
//! triggers a bridge restart (or simulates one by re-instantiating
//! the in-memory state), then requests up to the cap again. With
//! in-memory-only reveal counters, the censor can re-exhaust the
//! cap on every restart and walk the entire cohort.
//!
//! **Defense being tested**: persistent [`RevealStore`] backing
//! (RT-CN-10 closure).
//!
//! **Distinguisher we look for**: a freshly-instantiated store
//! "forgets" prior reveals.

use crate::{AdversaryError, AdversaryResult, DetectionVerdict};
use mirage_discovery::cohort::{InMemoryRevealStore, RevealStore};

/// Run the restart-DoS attack against a [`RevealStore`] factory.
///
/// `factory` is called twice: once before the simulated restart
/// (to record reveals) and once after (to query). A persistent
/// store returns the same state both times. An in-memory store
/// "forgets" - that's the distinguisher.
///
/// The function takes an `async` factory so persistent
/// implementations can perform their on-disk init.
pub async fn cohort_restart_dos<F, Fut, S>(factory: F) -> AdversaryResult
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = S>,
    S: RevealStore,
{
    let token = [0xCCu8; 32];
    let bridges_round1 = [[0x01u8; 32], [0x02u8; 32], [0x03u8; 32]];
    let bridges_round2 = [[0x04u8; 32], [0x05u8; 32]];

    // Round 1: record reveals.
    let store_round1 = factory().await;
    store_round1.record_reveals(&token, &bridges_round1).await;
    let r1_count = store_round1.reveal_count(&token).await;
    assert_eq!(r1_count, 3, "round 1 record didn't persist within session");
    drop(store_round1);

    // Round 2: simulated restart. Re-instantiate the store via
    // the SAME factory. Persistent backings reload from disk;
    // in-memory backings start empty.
    let store_round2 = factory().await;
    let r2_count = store_round2.reveal_count(&token).await;
    if r2_count == 0 {
        return Ok(DetectionVerdict::Distinguished(format!(
            "store forgot {} reveals across restart - censor can \
             re-exhaust the cap via a restart loop. Use a \
             persistent RevealStore (file / SQLite / etc.).",
            bridges_round1.len()
        )));
    }
    if r2_count < bridges_round1.len() as u8 {
        return Ok(DetectionVerdict::Distinguished(format!(
            "store recovered {r2_count} of {} reveals across restart - \
             partial persistence is dangerous (under-counts allow \
             extra reveals).",
            bridges_round1.len()
        )));
    }
    // Sanity: persistent store should also accept new reveals.
    store_round2.record_reveals(&token, &bridges_round2).await;
    let r2_final = store_round2.reveal_count(&token).await;
    if r2_final != (bridges_round1.len() + bridges_round2.len()) as u8 {
        return Ok(DetectionVerdict::Distinguished(format!(
            "expected final count {}, got {r2_final}",
            bridges_round1.len() + bridges_round2.len()
        )));
    }

    Ok(DetectionVerdict::Defended)
}

/// Documented baseline: [`InMemoryRevealStore`] DOES NOT close
/// RT-CN-10. Returns `Distinguished` deliberately.
pub async fn cohort_restart_dos_in_memory_baseline() -> AdversaryResult {
    cohort_restart_dos(|| async { InMemoryRevealStore::new() }).await
}

/// Run the attack against [`mirage_discovery::FileRevealStore`].
/// This is the persistent-backing path; the file-backed store
/// MUST survive the simulated restart and return `Defended`.
/// Closes [RT-CN-10] for real.
pub async fn cohort_restart_dos_file_backed() -> AdversaryResult {
    // Unique temp path per run.
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let path = std::env::temp_dir().join(format!("mirage-adversary-{nanos}.mrrs"));
    let path_for_factory = path.clone();
    let verdict = cohort_restart_dos(move || {
        let p = path_for_factory.clone();
        async move { mirage_discovery::FileRevealStore::open(&p, false).expect("open file store") }
    })
    .await;
    let _ = std::fs::remove_file(&path);
    verdict
}

/// Boxed [`crate::Adversary`] wrapper for the file-backed path
/// (the closure-form of RT-CN-10).
pub struct CohortRestartDosFileBacked;

#[async_trait::async_trait]
impl crate::Adversary for CohortRestartDosFileBacked {
    async fn run(&self) -> Result<DetectionVerdict, AdversaryError> {
        cohort_restart_dos_file_backed().await
    }
    fn name(&self) -> &'static str {
        "cohort_restart_dos_file_backed"
    }
    fn defense(&self) -> &'static str {
        "RT-CN-10: persistent FileRevealStore (mirage_discovery::FileRevealStore)"
    }
}

/// Boxed [`Adversary`] wrapper.
pub struct CohortRestartDosBaseline;

#[async_trait::async_trait]
impl crate::Adversary for CohortRestartDosBaseline {
    async fn run(&self) -> Result<DetectionVerdict, AdversaryError> {
        cohort_restart_dos_in_memory_baseline().await
    }
    fn name(&self) -> &'static str {
        "cohort_restart_dos_in_memory_baseline"
    }
    fn defense(&self) -> &'static str {
        "RT-CN-10: persistent RevealStore - in-memory deliberately fails this test"
    }
}
