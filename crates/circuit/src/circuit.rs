//! Client-side `Circuit` state.
//!
//! A `Circuit` holds the per-hop key material the client uses to
//! seal RELAY cells outbound (with N onion layers in OUTERMOST-first
//! order - `layers[0]` is the first hop's key) and peel them inbound.
//! The circuit grows incrementally via [`Circuit::extend`] as each
//! hop's CREATED/EXTENDED handshake completes.
//!
//! # Sequence counters
//!
//! Per-direction `seq` counters increment per cell. The forward
//! direction (client -> exit) uses `c2h_seq`; reverse uses `h2c_seq`.
//! The seq is part of the AEAD nonce + AAD so cell uniqueness is
//! enforced.
//!
//! # State machine
//!
//! ```text
//!  Empty
//!    +- extend(hop_keys[0])
//!  Extended[1]
//!    +- extend(hop_keys[1])
//!  Extended[2]
//!    +- extend(hop_keys[2])
//!  Extended[3]                   <- can now send RELAY cells through
//!    +- destroy()
//!  Destroyed
//! ```

use crate::keys::HopKeys;
use crate::onion::{onion_open, onion_seal, OnionError, OnionLayer};
use thiserror::Error;

/// Circuit-level direction byte. Matches the onion-AEAD direction
/// constants used in `onion::onion_seal` / `onion::onion_open`.
pub const DIR_CLIENT_TO_HOP: u8 = 0;
/// See [`DIR_CLIENT_TO_HOP`].
pub const DIR_HOP_TO_CLIENT: u8 = 1;

/// Maximum hops a Mirage circuit may have.
///
/// # STATUS (#1): multi-hop is NOT wired in production - single-hop only
///
/// The multi-hop onion machinery in this crate (per-hop tokens, N-layer
/// peeling, next-hop dialing) is COMPLETE and tested but is NOT wired into any
/// shipped binary. The production bridge builds an exit-only executor and never
/// enters relay mode; the client's `run_circuit_relay` sends one `CMD_CREATE`,
/// seals a single onion layer, and never emits `CMD_EXTEND`. So when
/// circuit-relay is enabled today, the entry bridge IS the exit: it sees the
/// client's transport source IP AND decrypts the destination - a single
/// compromised bridge deanonymizes the user. The hop model documented below is
/// the DESIGN, not what runs. Until the relay path is wired end-to-end
/// (client sends `EXTEND`/`EXTEND_FINISH`; the bridge classifies bridge-to-
/// bridge links and pairs `with_relay_mode` + `with_token_verification`, which
/// `SessionTask::run` now enforces together - see #5), circuit-relay MUST NOT
/// be presented to users as anonymity-providing. Treat it as a single-hop
/// access path only.
///
/// **Capped at 3 by design.** Mirage's anonymity strategy is
/// "multi-entry cooperative routing" - the user runs MULTIPLE
/// circuits concurrently through DIFFERENT entry bridges, not
/// a single long chain through one entry. The "single-IP-at-a-
/// time" weakness of Tor's guard model is addressed by
/// horizontal diversity across entries, not by stacking more
/// hops on one chain.
///
/// Hop accounting:
/// - **Hop 1 = entry**: client-facing bridge. Sees client IP +
///   per-circuit forward-direction onion layer.
/// - **Hop 2 = relay**: middle bridge. Sees neither client IP
///   nor destination - pure onion forwarder.
/// - **Hop 3 = exit**: destination-facing bridge. Sees
///   destination + per-circuit reverse-direction onion layer.
///
/// 1-hop is permitted for non-anonymity uses (`Realtime` /
/// access-only profiles); 2-hop is permitted but discouraged
/// (anonymity downgrade); 3-hop is the recommended default.
///
/// Anything beyond 3 hops adds latency without adding anonymity -
/// the relevant security parameter is the count of concurrent
/// entries (cohort-coverage), not the depth of one chain.
pub const MIN_CIRCUIT_HOPS: usize = 1;
/// See [`MIN_CIRCUIT_HOPS`].
pub const MAX_CIRCUIT_HOPS: usize = 3;

/// Maximum application-payload bytes an exit/deep hop may place in ONE reverse
/// `CMD_RELAY` DATA sub-cell so the cell still fits [`crate::MAX_CELL_PAYLOAD`]
/// after every upstream hop re-wraps it with its own reverse onion layer.
///
/// A reverse cell gains one [`crate::onion::onion_seal`] layer (+16 B Poly1305
/// tag) at the emitting hop and one more at each intermediate hop on the way to
/// the client - up to [`MAX_CIRCUIT_HOPS`] layers total. Subtracting that worst
/// case plus the `RelaySubCell` header (3 B) and the `DataBody` `stream_id`
/// prefix (2 B) from the cell payload cap yields the safe per-cell chunk. The
/// emitting bridge does NOT know the true circuit depth, so it MUST assume the
/// maximum. Mirrors the client's forward `max_data_bytes` bound.
pub const MAX_REVERSE_RELAY_DATA_BYTES: usize =
    crate::cell::MAX_CELL_PAYLOAD - (MAX_CIRCUIT_HOPS * 16) - 3 - 2;

/// Errors produced by circuit operations.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CircuitError {
    /// `extend` was called on a circuit that is already at
    /// [`MAX_CIRCUIT_HOPS`].
    #[error("circuit already at max hops ({MAX_CIRCUIT_HOPS})")]
    TooManyHops,
    /// `relay_seal` / `relay_open` was called on an empty circuit.
    #[error("circuit has no hops")]
    NoHops,
    /// `relay_seal` / `relay_open` was called on a destroyed circuit.
    #[error("circuit is destroyed")]
    Destroyed,
    /// Onion-AEAD failure (auth fail or empty layers).
    #[error("onion: {0}")]
    Onion(#[from] OnionError),
    /// Sequence-counter overflow (theoretical; happens after 2^64
    /// cells in one direction). The caller MUST destroy the circuit.
    #[error("sequence counter exhausted")]
    SeqExhausted,
}

/// Client-side circuit state.
///
/// The circuit owns a Vec of [`OnionLayer`] pairs (one per hop).
/// Sealing an outbound RELAY cell wraps the payload with all
/// forward layers. Peeling an inbound RELAY cell unwraps with all
/// reverse layers.
#[derive(Debug, Clone)]
pub struct Circuit {
    /// Per-hop forward layers, in OUTERMOST-first order: hop 0
    /// (first hop) is `forward[0]`, the exit is `forward[N-1]`.
    forward: Vec<OnionLayer>,
    /// Per-hop reverse layers, same ordering.
    reverse: Vec<OnionLayer>,
    /// PER-HOP forward (client->hop) sequence counters, indexed like `forward`.
    /// A hop's counter is the AEAD nonce seq for ITS layer and MUST mirror that
    /// bridge hop's own `forward_seq`, which counts only the cells that hop
    /// actually peels. A single shared counter is WRONG for telescoping: during
    /// a deep EXTEND the client sends RELAY cells that the not-yet-added exit
    /// never sees, so the exit's counter would lag a global one. A new hop's
    /// counter starts at 0 (`extend`), and every present hop's counter advances
    /// once per sealed cell (all current hops peel each RELAY cell).
    c2h_seq: Vec<u64>,
    /// PER-HOP reverse (hop->client) sequence counters, indexed like `reverse`.
    /// Mirrors each bridge hop's `reverse_seq`. See [`Self::c2h_seq`].
    h2c_seq: Vec<u64>,
    /// Epoch counter; the client MAY rotate the epoch on a long-
    /// lived circuit to refresh AEAD nonces. v0.1u uses a constant
    /// epoch=0; v0.2 wires this to the session-frame ratchet.
    epoch: u32,
    /// True iff the circuit has been destroyed; once set, no more
    /// cells may be sealed/peeled.
    destroyed: bool,
}

impl Circuit {
    /// Construct an empty circuit. Hops are added via [`Circuit::extend`].
    pub fn new() -> Self {
        Self {
            forward: Vec::new(),
            reverse: Vec::new(),
            c2h_seq: Vec::new(),
            h2c_seq: Vec::new(),
            epoch: 0,
            destroyed: false,
        }
    }

    /// Add a hop's key material to the circuit. Hops MUST be added
    /// in extension order (hop 0 first, hop 1 next, etc.).
    pub fn extend(&mut self, hop_keys: HopKeys) -> Result<(), CircuitError> {
        if self.destroyed {
            return Err(CircuitError::Destroyed);
        }
        if self.forward.len() >= MAX_CIRCUIT_HOPS {
            return Err(CircuitError::TooManyHops);
        }
        self.forward.push(hop_keys.forward);
        self.reverse.push(hop_keys.reverse);
        // Fresh hop: its per-hop nonce counters start at 0, independent of the
        // already-advanced counters of the hops in front of it.
        self.c2h_seq.push(0);
        self.h2c_seq.push(0);
        Ok(())
    }

    /// Number of hops in the circuit.
    pub fn hop_count(&self) -> usize {
        self.forward.len()
    }

    /// True iff the circuit can carry RELAY traffic (>= 1 hop and
    /// not destroyed).
    pub fn is_ready(&self) -> bool {
        !self.destroyed && !self.forward.is_empty()
    }

    /// True iff the circuit has been destroyed.
    pub fn is_destroyed(&self) -> bool {
        self.destroyed
    }

    /// Mark the circuit destroyed. Subsequent seal/open attempts
    /// return [`CircuitError::Destroyed`].
    pub fn destroy(&mut self) {
        self.destroyed = true;
    }

    /// Seal a relay cell payload for transmission to the exit hop.
    /// Wraps with all forward layers (OUTERMOST-first onion). The
    /// outbound `seq` increments after a successful seal so the
    /// next cell uses a fresh nonce.
    pub fn relay_seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, CircuitError> {
        if self.destroyed {
            return Err(CircuitError::Destroyed);
        }
        if self.forward.is_empty() {
            return Err(CircuitError::NoHops);
        }
        // Wrap INNERMOST-first (exit layer first, entry layer last), each layer
        // with ITS hop's own nonce seq so a telescoped exit - whose counter
        // trails the front hops' - still matches the bridge's per-hop peel.
        let mut payload = plaintext.to_vec();
        for i in (0..self.forward.len()).rev() {
            payload = onion_seal(
                std::slice::from_ref(&self.forward[i]),
                &payload,
                DIR_CLIENT_TO_HOP,
                self.epoch,
                self.c2h_seq[i],
            )?;
        }
        // Every present hop peels this cell, so advance them all.
        for s in &mut self.c2h_seq {
            *s = s.checked_add(1).ok_or(CircuitError::SeqExhausted)?;
        }
        Ok(payload)
    }

    /// Build an onion-sealed circuit-padding cover payload (H4).
    ///
    /// The inner sub-cell is `CMD_PADDING` with an empty body, sealed for the
    /// full forward path so it is dropped at the exit hop - every hop peels it,
    /// adding timing/volume cover on every leg without touching real traffic
    /// (flow-correlation resistance for the multi-hop path). The returned bytes
    /// go into a `Cell::new(circ_id, CMD_RELAY, _)`; the constant 1024-byte cell
    /// size makes the cover cell indistinguishable on the wire from a data cell.
    /// Advances the per-hop send counters exactly like a real relay cell, so
    /// interleaving padding with data keeps both peers' nonce sequences aligned.
    pub fn build_padding_payload(&mut self) -> Result<Vec<u8>, CircuitError> {
        let sub = crate::extend::RelaySubCell {
            command: crate::cell::CMD_PADDING,
            body: Vec::new(),
        }
        .encode()
        .expect("empty-body padding sub-cell always encodes");
        self.relay_seal(&sub)
    }

    /// Peel an incoming relay cell received from hop 0 (the first
    /// hop). Unwraps all reverse layers. The inbound `seq`
    /// increments after a successful peel.
    pub fn relay_open(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, CircuitError> {
        if self.destroyed {
            return Err(CircuitError::Destroyed);
        }
        if self.reverse.is_empty() {
            return Err(CircuitError::NoHops);
        }
        // Peel OUTER-first (entry layer first, exit layer last), each with ITS
        // hop's own nonce seq - the mirror of `relay_seal` and of each bridge
        // hop's independent `reverse_seq` re-wrap.
        let mut payload = ciphertext.to_vec();
        for i in 0..self.reverse.len() {
            payload = onion_open(
                std::slice::from_ref(&self.reverse[i]),
                &payload,
                DIR_HOP_TO_CLIENT,
                self.epoch,
                self.h2c_seq[i],
            )?;
        }
        for s in &mut self.h2c_seq {
            *s = s.checked_add(1).ok_or(CircuitError::SeqExhausted)?;
        }
        Ok(payload)
    }

    /// Snapshot representative per-direction sequence counters (the highest
    /// across hops). Diagnostics only; not used by the wire protocol. With
    /// per-hop counters the front hop (entry) advances on every cell, so its
    /// value is the total cell count in that direction.
    pub fn sequence_state(&self) -> (u64, u64) {
        (
            self.c2h_seq.iter().copied().max().unwrap_or(0),
            self.h2c_seq.iter().copied().max().unwrap_or(0),
        )
    }
}

impl Default for Circuit {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::derive_hop_keys;

    fn make_hop(tag: u8) -> HopKeys {
        let i2r = [tag; 32];
        let r2i = [tag.wrapping_add(0x10); 32];
        derive_hop_keys(&i2r, &r2i)
    }

    /// Mirror the client-side circuit: the "hops" each have their
    /// own copy of the same per-hop keys. We model peeling
    /// hop-by-hop here for tests.
    fn server_view(client: &Circuit, idx: usize) -> Vec<OnionLayer> {
        vec![client.forward[idx].clone()]
    }

    #[test]
    fn one_hop_seal_open_roundtrip() {
        let mut c = Circuit::new();
        c.extend(make_hop(1)).unwrap();
        let pt = b"single hop".to_vec();
        let ct = c.relay_seal(&pt).unwrap();
        // The hop peels its own layer.
        let hop_view = server_view(&c, 0);
        let unwrapped = crate::onion::onion_open(&hop_view, &ct, DIR_CLIENT_TO_HOP, 0, 0).unwrap();
        assert_eq!(unwrapped, pt);
    }

    #[test]
    fn build_padding_payload_seals_a_cmd_padding_subcell() {
        // H4: the client's padding cover cell must peel to a CMD_PADDING
        // sub-cell with an empty body - exactly what the bridge drop path keys
        // on. (The bridge-side drop is proven in bridge_circuit's tests.)
        let mut c = Circuit::new();
        c.extend(make_hop(1)).unwrap();
        let wire = c.build_padding_payload().unwrap();
        let hop_view = server_view(&c, 0);
        let peeled = crate::onion::onion_open(&hop_view, &wire, DIR_CLIENT_TO_HOP, 0, 0).unwrap();
        let sub = crate::extend::RelaySubCell::decode(&peeled).unwrap();
        assert_eq!(sub.command, crate::cell::CMD_PADDING);
        assert!(sub.body.is_empty(), "padding carries no application data");
    }

    #[test]
    fn three_hop_telescope_roundtrip() {
        // Build a 3-hop circuit and exercise the full wrap/peel
        // pipeline.
        let mut c = Circuit::new();
        c.extend(make_hop(1)).unwrap();
        c.extend(make_hop(2)).unwrap();
        c.extend(make_hop(3)).unwrap();
        assert_eq!(c.hop_count(), 3);
        assert!(c.is_ready());

        let pt = b"three-hop application data".to_vec();
        let mut wire = c.relay_seal(&pt).unwrap();
        // Walk through the hops one at a time.
        for i in 0..3 {
            let hop_view = server_view(&c, i);
            wire = crate::onion::onion_open(&hop_view, &wire, DIR_CLIENT_TO_HOP, 0, 0).unwrap();
        }
        assert_eq!(wire, pt);
    }

    #[test]
    fn reverse_path_three_hop() {
        // Reverse direction: exit (hop 2) wraps once with its key,
        // hop 1 wraps with its key, hop 0 wraps with its key.
        // Client peels all three at once.
        let mut c = Circuit::new();
        c.extend(make_hop(1)).unwrap();
        c.extend(make_hop(2)).unwrap();
        c.extend(make_hop(3)).unwrap();

        let pt = b"exit-to-client data".to_vec();
        // Step 1: exit hop seals with its reverse key.
        let mut wire =
            crate::onion::onion_seal(&[c.reverse[2].clone()], &pt, DIR_HOP_TO_CLIENT, 0, 0)
                .unwrap();
        // Step 2: hop 1 wraps.
        wire = crate::onion::onion_seal(&[c.reverse[1].clone()], &wire, DIR_HOP_TO_CLIENT, 0, 0)
            .unwrap();
        // Step 3: hop 0 wraps.
        wire = crate::onion::onion_seal(&[c.reverse[0].clone()], &wire, DIR_HOP_TO_CLIENT, 0, 0)
            .unwrap();
        // Step 4: client peels all three.
        let back = c.relay_open(&wire).unwrap();
        assert_eq!(back, pt);
    }

    #[test]
    fn extend_past_cap_rejected() {
        let mut c = Circuit::new();
        for tag in 1..=MAX_CIRCUIT_HOPS as u8 {
            c.extend(make_hop(tag)).unwrap();
        }
        let err = c.extend(make_hop(0xFE)).unwrap_err();
        assert_eq!(err, CircuitError::TooManyHops);
    }

    #[test]
    fn empty_circuit_seal_rejected() {
        let mut c = Circuit::new();
        assert_eq!(c.relay_seal(b"x").unwrap_err(), CircuitError::NoHops);
        assert_eq!(c.relay_open(b"x").unwrap_err(), CircuitError::NoHops);
    }

    #[test]
    fn destroyed_circuit_rejects_ops() {
        let mut c = Circuit::new();
        c.extend(make_hop(1)).unwrap();
        c.destroy();
        assert!(c.is_destroyed());
        assert_eq!(c.relay_seal(b"x").unwrap_err(), CircuitError::Destroyed);
        assert_eq!(c.relay_open(b"x").unwrap_err(), CircuitError::Destroyed);
        assert_eq!(c.extend(make_hop(2)).unwrap_err(), CircuitError::Destroyed);
    }

    #[test]
    fn sequence_increments_with_each_seal() {
        let mut c = Circuit::new();
        c.extend(make_hop(1)).unwrap();
        let (s0, _) = c.sequence_state();
        assert_eq!(s0, 0);
        let _ = c.relay_seal(b"a").unwrap();
        let _ = c.relay_seal(b"b").unwrap();
        let (s1, _) = c.sequence_state();
        assert_eq!(s1, 2);
    }

    #[test]
    fn out_of_order_decrypt_fails() {
        // If client seals with seq=0,1,2 but tries to peel in the
        // order 2,1,0, the AEAD MUST fail because the nonce won't
        // match.
        let mut c = Circuit::new();
        c.extend(make_hop(1)).unwrap();
        let ct0 = c.relay_seal(b"first").unwrap();
        let ct1 = c.relay_seal(b"second").unwrap();
        // Try to peel ct1 first (server expects seq=0).
        let hop_view = server_view(&c, 0);
        // Server's expected next seq = 0; opening ct1 (which was
        // sealed with seq=1) MUST fail.
        let err = crate::onion::onion_open(&hop_view, &ct1, DIR_CLIENT_TO_HOP, 0, 0);
        assert!(err.is_err());
        // Opening ct0 with seq=0 succeeds.
        let pt = crate::onion::onion_open(&hop_view, &ct0, DIR_CLIENT_TO_HOP, 0, 0).unwrap();
        assert_eq!(pt, b"first");
    }
}
