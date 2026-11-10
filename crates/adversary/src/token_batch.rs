//! **Attack**: token-batch expiry correlator.
//!
//! An operator mints N capability tokens at time T. If all tokens
//! share the same `expires_at`, a censor who later obtains a
//! leaked subset of those tokens can correlate the cluster's
//! shared expiry timestamp back to the mint moment (revealing
//! operator rotation cadence + likely activity patterns).
//!
//! **Defense being tested**: per-token expiry jitter via
//! `sign_token_jittered` (RT-CN-11 closure).
//!
//! **Distinguisher we look for**: the variance of `expires_at`
//! across the batch is below a meaningful threshold.

use crate::{AdversaryError, AdversaryResult, DetectionVerdict};
use mirage_crypto::ed25519_dalek::SigningKey;
use mirage_discovery::token::sign_token_jittered;
use std::collections::HashSet;

fn rand_seed() -> [u8; 32] {
    let mut s = [0u8; 32];
    getrandom::fill(&mut s).expect("CSPRNG");
    s
}

/// Run the batch-correlator attack. Mints `batch_size` tokens
/// with `jitter_seconds` and checks the variance.
///
/// Returns `Defended` if the batch produces at least
/// `batch_size / 2` distinct expiries. Returns `Distinguished` if
/// all tokens share one expiry (clear sign that jitter was 0 or
/// disabled). Returns `Inconclusive` for small batches.
pub async fn token_batch_correlator(batch_size: usize, jitter_seconds: u64) -> AdversaryResult {
    if batch_size < 50 {
        return Ok(DetectionVerdict::Inconclusive(format!(
            "need >= 50 tokens to claim a distribution, got {batch_size}"
        )));
    }
    if jitter_seconds < 60 {
        // Below 1-minute jitter, the variance is below clock-skew
        // noise - caller likely meant something else.
        return Ok(DetectionVerdict::Inconclusive(format!(
            "jitter {jitter_seconds}s is below 1 minute - the test \
             needs a meaningful window"
        )));
    }
    let op = SigningKey::from_bytes(&rand_seed());
    let nominal = 1_700_000_000u64;
    let mut expiries: HashSet<u64> = HashSet::new();
    for i in 0..batch_size {
        let mut tid = [0u8; 32];
        tid[..8].copy_from_slice(&(i as u64).to_be_bytes());
        let tok = sign_token_jittered(tid, [0x88u8; 32], nominal, jitter_seconds, &op);
        expiries.insert(tok.expires_at);
    }
    if expiries.len() < batch_size / 2 {
        return Ok(DetectionVerdict::Distinguished(format!(
            "{} unique expiries across {} tokens - variance too low. \
             Check `sign_token_jittered` and ensure callers pass a \
             non-zero jitter_seconds.",
            expiries.len(),
            batch_size
        )));
    }
    Ok(DetectionVerdict::Defended)
}

/// Same attack but using the **non-jittered** `sign_token` -
/// documents the historical (pre-RT-CN-11) leak as a contrast.
/// Always returns `Distinguished`.
pub async fn token_batch_no_jitter_baseline(batch_size: usize) -> AdversaryResult {
    use mirage_discovery::token::sign_token;
    let op = SigningKey::from_bytes(&rand_seed());
    let nominal = 1_700_000_000u64;
    let mut expiries: HashSet<u64> = HashSet::new();
    for i in 0..batch_size {
        let mut tid = [0u8; 32];
        tid[..8].copy_from_slice(&(i as u64).to_be_bytes());
        let tok = sign_token(tid, [0x88u8; 32], nominal, &op);
        expiries.insert(tok.expires_at);
    }
    // sign_token is deterministic - all tokens share the
    // supplied expires_at. This IS the distinguisher RT-CN-11
    // addresses.
    if expiries.len() == 1 {
        return Ok(DetectionVerdict::Distinguished(format!(
            "baseline `sign_token` yields 1 shared expiry across {batch_size} \
             tokens. Use `sign_token_jittered` to smear the batch."
        )));
    }
    Ok(DetectionVerdict::Defended)
}

/// Boxed [`Adversary`] wrapper for the jittered-path test.
pub struct TokenBatchCorrelator {
    /// Number of tokens to mint.
    pub batch_size: usize,
    /// Per-token jitter window in seconds.
    pub jitter_seconds: u64,
}

#[async_trait::async_trait]
impl crate::Adversary for TokenBatchCorrelator {
    async fn run(&self) -> Result<DetectionVerdict, AdversaryError> {
        token_batch_correlator(self.batch_size, self.jitter_seconds).await
    }
    fn name(&self) -> &'static str {
        "token_batch_correlator"
    }
    fn defense(&self) -> &'static str {
        "RT-CN-11: sign_token_jittered per-token expiry smearing"
    }
}
