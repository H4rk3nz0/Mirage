//! Emit each built-in fingerprint template's JA3 string.
//!
//! Used by the CI drift-check workflow
//! ([`.github/workflows/fingerprint-drift.yml`](../../../.github/workflows/fingerprint-drift.yml))
//! to compare Mirage's pinned JA3 strings against an operator-
//! curated fixture.
//!
//! Output: one line per template, `<name>\t<ja3_string>`.

use mirage_transport_reality::tls_fingerprint::{
    ja3_string, CHROME_DESKTOP, FIREFOX_DESKTOP, SAFARI_DESKTOP,
};

fn main() {
    for t in [&CHROME_DESKTOP, &FIREFOX_DESKTOP, &SAFARI_DESKTOP] {
        println!("{}\t{}", t.name, ja3_string(t));
    }
}
