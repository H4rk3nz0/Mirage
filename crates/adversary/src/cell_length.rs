//! **Attack**: cell-length classifier.
//!
//! Mirage circuit cells are fixed 1024-byte frames. A passive
//! observer who can see frame boundaries (e.g., from packet
//! captures of an unencrypted bridge-to-bridge link, or from a
//! compromised CDN that sees underlying TCP segment sizes) can
//! classify traffic by frame-size distribution.
//!
//! **Defense being tested**: cells are always 1024 B (no leakage
//! of payload length via frame size). Verified by encoding cells
//! with payloads spanning the full `0..MAX_CELL_PAYLOAD` range and
//! confirming the on-wire byte count is invariant.
//!
//! **Distinguisher we look for**: any cell encode produces a
//! non-1024-byte output for a valid input.

use crate::{AdversaryError, AdversaryResult, DetectionVerdict};
use mirage_circuit::{Cell, CIRCUIT_CELL_LEN, CMD_DATA, MAX_CELL_PAYLOAD};

/// Encode cells with payloads of 0, 1, 50, `MAX_CELL_PAYLOAD/2`,
/// `MAX_CELL_PAYLOAD` bytes. Every encoded cell MUST be exactly
/// `CIRCUIT_CELL_LEN` bytes.
pub async fn relay_payload_length_classifier() -> AdversaryResult {
    let probe_payload_sizes = [0, 1, 50, MAX_CELL_PAYLOAD / 2, MAX_CELL_PAYLOAD];
    for &n in &probe_payload_sizes {
        let body = vec![0xABu8; n];
        let cell = Cell::new(1, CMD_DATA, body)
            .map_err(|e| AdversaryError::Parse(format!("Cell::new({n} B): {e}")))?;
        let encoded = cell
            .encode()
            .map_err(|e| AdversaryError::Parse(format!("Cell::encode({n} B): {e}")))?;
        if encoded.len() != CIRCUIT_CELL_LEN {
            return Ok(DetectionVerdict::Distinguished(format!(
                "cell with {n}-byte body encodes to {} bytes on wire \
                 (expected {CIRCUIT_CELL_LEN}). Frame-size oracle present.",
                encoded.len()
            )));
        }
    }
    Ok(DetectionVerdict::Defended)
}

/// Boxed [`Adversary`] wrapper.
pub struct RelayPayloadLengthClassifier;

#[async_trait::async_trait]
impl crate::Adversary for RelayPayloadLengthClassifier {
    async fn run(&self) -> Result<DetectionVerdict, AdversaryError> {
        relay_payload_length_classifier().await
    }
    fn name(&self) -> &'static str {
        "relay_payload_length_classifier"
    }
    fn defense(&self) -> &'static str {
        "Fixed 1024 B cell size in mirage_circuit::Cell::encode"
    }
}
