//! Multi-hop telescoping circuits with hybrid PQ at every hop.
//!
//! # Why
//!
//! Tor's circuit model gives anonymity by separating the network
//! adversary observing flow A from the network adversary observing
//! flow B: each hop knows only its predecessor and successor. Mirage's
//! v0.1 single-hop session protocol does not. v0.1u plus this crate
//! delivers Mirage's L5 invariant - multi-hop circuits - with two
//! refinements over Tor:
//!
//! 1. **Hybrid PQ at every hop.** Each circuit-extend step runs
//!    Mirage's Noise-XX + ML-KEM-768 hybrid handshake. A future
//!    quantum adversary who breaks classical DH at one hop still
//!    can't decrypt because of ML-KEM; an adversary who breaks
//!    ML-KEM still can't because of Noise-XX. Tor's circuits use
//!    classical DH only.
//! 2. **Transport-diversity per hop.** A circuit can run hop A
//!    over Reality-v2, hop B over obfs-tcp, hop C over MASQUE.
//!    The transport choice is per-hop, not per-circuit. A censor
//!    blocking one transport at one hop's network position cannot
//!    block the whole circuit.
//!
//! # Telescoping
//!
//! Client builds circuits incrementally, one hop at a time:
//!
//! ```text
//!  Client                    Hop 1                   Hop 2              Hop 3
//!  ------                    -----                   -----              -----
//!  CREATE   -------------->  (run Mirage handshake)
//!           <--------------  CREATED
//!
//!  EXTEND(Hop2-pk)--------->
//!                            CREATE ------------>   (run handshake)
//!                                                <-------  CREATED
//!           <--------------  EXTENDED
//!
//!  EXTEND(Hop3-pk)--------->
//!                            relay ------------->
//!                                                  CREATE ------> (handshake)
//!                                                            <-------  CREATED
//!                                                  <----  EXTENDED
//!                            <---------------  relay
//!           <--------------  EXTENDED
//!
//!  RELAY(BEGIN, target.example:80) onion-encrypted 3 layers, peeled hop-by-hop
//! ```
//!
//! At every hop's CREATE/CREATED step, the client establishes a
//! separate Mirage session with that hop. The client therefore holds
//! N session states for an N-hop circuit. Onion encryption layers
//! the per-hop AEAD over the data flow.
//!
//! # Cell format
//!
//! Circuit cells are 1024 bytes fixed. They ride inside the per-hop
//! Mirage session-frame layer (which provides the AEAD); cells are
//! the multiplexing primitive within a session.
//!
//! ```text
//! +------+------+---------+-----------+
//! | cir  | cmd  | pad_len | payload   |
//! | u32  | u8   | u16 BE  |  variable  |
//! | 4 B  | 1 B  | 2 B     | 1024-7=1017|
//! +------+------+---------+-----------+
//! ```
//!
//! - `circ_id` (u32 BE): the circuit this cell belongs to. Per-hop
//!   independent (Hop 1 sees `circ_id_A`; Hop 2 sees `circ_id_B`;
//!   Hop 1 maintains a translation table). Zero is reserved.
//! - `command` (u8): one of [`CMD_*`].
//! - `pad_len` (u16 BE): bytes of trailing padding inside `payload`
//!   that decoders MUST discard. Lets short payloads ride a 1024-B
//!   cell without leaking length.
//! - `payload` (1017 B): command-specific. Trailing `pad_len` bytes
//!   are random padding.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod bridge_circuit;
pub mod builder;
pub mod cell;
pub mod circuit;
pub mod extend;
pub mod keys;
pub mod onion;
pub mod split_exit;
/// Wire codec for relay sub-cell stream bodies (BEGIN / DATA / END).
pub mod stream;

pub use bridge_circuit::{
    deterministic_out_circ_id_picker, sequential_out_circ_id_picker, BridgeAction,
    BridgeCircuitError, BridgeCircuitState, BridgePolicy, CircuitEntryState,
};
pub use builder::{BuildStep, BuilderError, CircuitBuilder, HopSpec};
pub use cell::MAX_CELL_PAYLOAD;
pub use cell::{Cell, CellError, CIRCUIT_CELL_LEN, CMD_BEGIN, CMD_CREATE, CMD_CREATED};
pub use cell::{
    CMD_CREATED_CONT, CMD_CREATE_CONT, CMD_EXTENDED_CONT, CMD_EXTEND_CONT, CMD_EXTEND_FINISH,
    CMD_HANDOFF, CMD_HANDOFF_RESULT, CMD_RESOLVE,
};
pub use cell::{CMD_DATA, CMD_DESTROY, CMD_END, CMD_EXTEND, CMD_EXTENDED, CMD_PADDING, CMD_RELAY};
pub use circuit::{
    Circuit, CircuitError, MAX_CIRCUIT_HOPS, MAX_REVERSE_RELAY_DATA_BYTES, MIN_CIRCUIT_HOPS,
};
pub use extend::{
    ExtendBody, ExtendError, ExtendFinishBody, ExtendHeader, ExtendedBody, HandshakeBody,
    HopEndpoint, RelaySubCell, MAX_HANDSHAKE_BODY_LEN, MAX_HS_MSG1_LEN, MAX_HS_MSG2_LEN,
    RELAY_SUBCELL_HEADER_LEN, RELAY_SUBCELL_MAX_BODY,
};
pub use keys::{
    derive_hop_keys, derive_hop_keys_from_handshake, HopKeys, SESSION_DIRECTION_LABEL_I2R,
    SESSION_DIRECTION_LABEL_R2I,
};
pub use onion::{onion_open, onion_seal, OnionError, OnionLayer};
pub use split_exit::{
    ForwarderPolicy, ForwarderState, ForwarderStreamState, HandoffBody, HandoffResultBody,
    HandoffStatus, ResolveBody, ResolveTarget, ResolverDecision, ResolverPolicy, ResolverState,
    ResolverStreamState, SplitExitError,
};
pub use stream::{BeginBody, DataBody, EndBody, StreamBodyError, StreamId};
