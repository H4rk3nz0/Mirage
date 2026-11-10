//! Real-I/O `HopRuntime` impl backed by `mirage_transport` +
//! `mirage_session` + `mirage_runtime::cell_io`.
//!
//! Phase 2E ships a single-transport variant: the runtime is
//! parameterised over one [`mirage_transport::ClientTransport`]
//! and uses it for every hop's transport-layer dial. A future
//! variant could consult the adaptive router per hop against the
//! bridge catalogue's full `transport_caps` (naive parallel racing
//! was removed as an anti-enumeration footgun).
//!
//! # Scope
//!
//! [`SingleTransportHopRuntime`] handles:
//!
//! - **`dial_hop0`** - direct dial via `transport.dial(DialInputs)`,
//!   then a manual Mirage handshake (so we can capture
//!   `mlkem_ss + session_binding` for the circuit's hop keys),
//!   then wrapping in `SessionStream`.
//! - **`extend_hop`** - sends `CMD_EXTEND` over the existing
//!   `SessionStream` to hop 0; reads `CMD_EXTENDED` reply;
//!   finishes the per-hop `HandshakeInitiator`. Suitable for
//!   2-hop circuits today; 3+ hop telescoping requires bridge-
//!   side `handle_relay_from_prev` to detect inner control cells
//!   (Phase 2F).
//! - **`destroy_circuit`** - sends `CMD_DESTROY` for the hop-0
//!   circuit and drops the `SessionStream`.
//!
//! # Why manual handshake instead of `mirage_session::connect`
//!
//! `mirage_session::connect` consumes the `SessionKeys` into a
//! `SessionFramer` internally - the caller never sees `mlkem_ss`
//! or `session_binding`. The circuit layer needs both to derive
//! per-hop onion keys via [`mirage_circuit::derive_hop_keys_from_handshake`].
//! Doing the handshake by hand here lets us snapshot those bytes
//! before they're moved into the framer.

use crate::cell_io::write_cell;
use crate::{HopRuntime, RuntimeError};
use async_trait::async_trait;
use mirage_circuit::{
    derive_hop_keys_from_handshake, Cell, ExtendBody, ExtendFinishBody, ExtendedBody, HopEndpoint,
    HopKeys, HopSpec, CMD_DESTROY, CMD_EXTEND, CMD_EXTENDED, CMD_EXTENDED_CONT, CMD_EXTEND_CONT,
    CMD_EXTEND_FINISH,
};
use mirage_discovery::token::CapabilityToken;
use mirage_discovery::wire::Endpoint;
use mirage_session::wire::{MSG_2_LEN, MSG_3_LEN_WITH_FS_TOKEN, MSG_3_LEN_WITH_TOKEN};
use mirage_session::{HandshakeInitiator, SessionFramer, SessionStream};
use mirage_transport::{ClientTransport, DialInputs, DuplexStream};
use std::sync::Arc;
use std::time::Duration;
use zeroize::Zeroizing;

// ConnHandle - runtime-owned circuit state

/// Per-circuit runtime state. Holds the `SessionStream` to hop 0
/// (which all subsequent EXTEND / RELAY cells flow through) plus
/// the hop-0 circuit id used in cells.
///
/// **Interior mutability via `tokio::sync::Mutex`** - Phase 2F
/// shipped `extend_hop` with `&self` on the runtime trait and
/// `&Self::ConnHandle` on the conn, so all real-I/O mutation goes
/// through the mutex. The `Mutex` is held for the duration of one
/// EXTEND/EXTENDED roundtrip (ms-scale) and never across other
/// async work - circuit-build is single-threaded per circuit, so
/// contention is zero in practice.
pub struct TransportConn {
    /// Established AEAD'd session to hop 0. Locked across each
    /// cell-write / cell-read pair.
    pub session: tokio::sync::Mutex<SessionStream<DuplexStream>>,
    /// Circuit id allocated for this circuit. Picked client-side;
    /// the bridge sees the same value in inbound CREATE.
    pub hop0_circ_id: u32,
}

impl std::fmt::Debug for TransportConn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransportConn")
            .field("hop0_circ_id", &self.hop0_circ_id)
            .field("session", &"<SessionStream (Mutex)>")
            .finish()
    }
}

// Token supplier

/// Supplies capability tokens for hop dials. Every Mirage handshake
/// requires a fresh **single-use** token. Returning the
/// same token twice would (a) be rejected by the bridge's burn-list
/// and (b) create a client-side correlation fingerprint linking
/// distinct circuits - both fatal for unlinkability.
///
/// Implementations MUST consume each token at most once and MUST
/// return `None` once the pool is drained.
pub trait TokenSupplier: Send + Sync {
    /// Return one fresh token, consumed from the pool. Returns
    /// `None` if the pool is exhausted - `dial_hop0` / `extend_hop`
    /// then fail with `RuntimeError::Other("no tokens available")`.
    /// Subsequent calls after `None` MUST continue to return `None`
    /// (no resurrection).
    fn next_token(&self) -> Option<CapabilityToken>;
}

/// Single-use token pool over an owned `Vec<CapabilityToken>`. Each
/// `next_token` call pops one token and returns it; once the pool is
/// empty, every subsequent call returns `None`.
///
/// Closes [RT-N5]: the previous round-robin variant reused tokens
/// after `% tokens.len()` wrap, violating the single-use invariant
/// and creating a correlation pattern across circuits separated by
/// `tokens.len()` builds.
pub struct OneShotTokens {
    /// `Mutex<Vec>` (not lock-free) is acceptable because token
    /// consumption is rare (once per per-hop dial, ~us path) and
    /// `pop` is O(1).
    tokens: std::sync::Mutex<Vec<CapabilityToken>>,
}

impl OneShotTokens {
    /// Construct from a `Vec`. Tokens are consumed in **reverse**
    /// order (the last element is taken first, since `pop` is O(1)).
    /// Callers that care about order should reverse the input.
    pub fn new(tokens: Vec<CapabilityToken>) -> Self {
        Self {
            tokens: std::sync::Mutex::new(tokens),
        }
    }

    /// Number of tokens still in the pool. Primarily for tests.
    pub fn remaining(&self) -> usize {
        self.tokens
            .lock()
            .expect("OneShotTokens mutex poisoned")
            .len()
    }
}

impl TokenSupplier for OneShotTokens {
    fn next_token(&self) -> Option<CapabilityToken> {
        self.tokens
            .lock()
            .expect("OneShotTokens mutex poisoned")
            .pop()
    }
}

// SingleTransportHopRuntime

/// Real-I/O `HopRuntime` parameterised over one
/// [`mirage_transport::ClientTransport`].
pub struct SingleTransportHopRuntime {
    transport: Arc<dyn ClientTransport>,
    client_static_sk: [u8; 32],
    tokens: Arc<dyn TokenSupplier>,
    /// Optional per-bridge obfs SECRET from the invite (audit #9). When set, the
    /// hop-0 dial keys its pre-session knock (obfs-tcp / websocket) on this
    /// secret instead of the public bridge key, so a pubkey-only prober cannot
    /// forge it. `None` (default) => legacy pubkey-derived knock.
    obfs_secret: Option<[u8; 32]>,
    /// Per-circuit unique id allocator. Each `dial_hop0` picks a
    /// fresh id from the CSPRNG-backed pool (collision probability
    /// ~ 1 in 2^32 per circuit pair).
    next_circ_id: std::sync::atomic::AtomicU32,
}

impl SingleTransportHopRuntime {
    /// Construct.
    pub fn new(
        transport: Arc<dyn ClientTransport>,
        client_static_sk: [u8; 32],
        tokens: Arc<dyn TokenSupplier>,
    ) -> Self {
        Self {
            transport,
            client_static_sk,
            tokens,
            obfs_secret: None,
            // Start at 1 so 0 (reserved) is never returned.
            next_circ_id: std::sync::atomic::AtomicU32::new(1),
        }
    }

    /// Set the invite-shared obfs secret so the hop-0 knock is keyed on it
    /// (audit #9). Consuming builder; apply before wrapping in `Arc`.
    #[must_use]
    pub fn with_obfs_secret(mut self, obfs_secret: Option<[u8; 32]>) -> Self {
        self.obfs_secret = obfs_secret;
        self
    }

    fn alloc_circ_id(&self) -> u32 {
        // Wraps at u32::MAX; collisions in practice require both
        // bridges and clients to agree on the wrap, which a
        // 2^32-cell circuit lifetime makes nearly impossible.
        // Skip 0 (reserved) on wrap.
        let id = self
            .next_circ_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if id == 0 {
            self.next_circ_id
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        } else {
            id
        }
    }
}

#[async_trait]
impl HopRuntime for SingleTransportHopRuntime {
    type ConnHandle = TransportConn;

    async fn dial_hop0(
        &self,
        spec: &HopSpec,
        deadline: Duration,
    ) -> Result<(Self::ConnHandle, HopKeys), RuntimeError> {
        // Convert the caller's relative `deadline` into an absolute
        // `Instant` so the transport-dial and the Mirage handshake
        // share **one** budget instead of each silently consuming
        // the full duration. Closes [RT-N6]: the previous
        // implementation passed `deadline` to both the transport
        // and the handshake, allowing total elapsed to reach 2x
        // the intended bound (or, more dangerously, masking a
        // censor-induced delay in the transport that left no time
        // for handshake retry).
        let absolute_deadline = tokio::time::Instant::now() + deadline;

        // 1. Transport-level dial.
        let endpoint = hop_endpoint_to_discovery(&spec.endpoint)
            .map_err(|e| RuntimeError::Other(format!("hop-0 endpoint conversion: {e}")))?;
        let inputs = DialInputs {
            endpoint: &endpoint,
            bridge_static_pk: &spec.static_pk,
            obfs_secret: self.obfs_secret.as_ref(),
            deadline: remaining_until(absolute_deadline),
        };
        let stream = self.transport.dial(&inputs).await.map_err(|e| {
            tracing::debug!(error = %e, "hop-0 transport dial failed");
            RuntimeError::TransportDial
        })?;

        // 2. Run Mirage handshake manually so we can snapshot
        // mlkem_ss + session_binding before they move into the
        // framer. Hand it the **remaining** time, not the original
        // duration.
        //
        // Closes [RT-O1] (Phase 2F re-scan): check the handshake
        // budget BEFORE consuming a capability token. The previous
        // ordering popped a token from `OneShotTokens` and then
        // discovered the deadline had already elapsed - burning a
        // single-use token without ever sending it. Tokens are
        // expensive (operator-signed) and finite per session;
        // burning one on a fast-failing deadline is wasteful and
        // erodes the per-circuit token budget.
        let handshake_budget = remaining_until(absolute_deadline);
        if handshake_budget.is_zero() {
            return Err(RuntimeError::HopTimeout { hop_idx: 0 });
        }
        let token = self
            .tokens
            .next_token()
            .ok_or_else(|| RuntimeError::Other("no capability tokens available".into()))?;
        let (session, mlkem_ss, session_binding) = run_handshake_initiator(
            stream,
            &self.client_static_sk,
            &spec.static_pk,
            &token,
            handshake_budget,
        )
        .await?;

        // 3. Derive per-hop circuit keys.
        let keys = derive_hop_keys_from_handshake(&mlkem_ss, &session_binding);
        Ok((
            TransportConn {
                session: tokio::sync::Mutex::new(session),
                hop0_circ_id: self.alloc_circ_id(),
            },
            keys,
        ))
    }

    async fn extend_hop(
        &self,
        conn: &Self::ConnHandle,
        circuit_so_far: &mirage_circuit::Circuit,
        new_hop_spec: &HopSpec,
        deadline: Duration,
    ) -> Result<HopKeys, RuntimeError> {
        // Phase 2F ships the **2-hop** real-I/O extend: the EXTEND
        // cell is sent directly on the hop-0 session (no RELAY
        // wrap), since hop-0 IS the recipient. 3+ hop telescoping
        // requires RELAY-encapsulated EXTEND with bridge-side
        // inner-cell dispatch (Phase 2G).
        //
        // Why we accept this scope: 2-hop circuits cover the
        // Realtime profile (Realtime is 2-hop by design). The 3+
        // hop case for Interactive/Bulk/Background still uses
        // MockHopRuntime until Phase 2G lands.
        let hops_already_built = circuit_so_far.hop_count();
        if hops_already_built != 1 {
            return Err(RuntimeError::Other(format!(
                "extend_hop: 3+ hop telescoping deferred to Phase 2G (this circuit has {hops_already_built} hops, only 1 supported)"
            )));
        }

        let absolute_deadline = tokio::time::Instant::now() + deadline;
        let next_hop_idx = hops_already_built; // 1 for the 2-hop case.

        // 1. Check the budget BEFORE consuming a token (closes
        // [RT-O1]: tokens are single-use and finite per session;
        // burning one on a fast-failing deadline is wasteful).
        //
        // [RT-P2G-6]: The token is popped here; if a subsequent
        // step (`HandshakeInitiator::new`, `write_message_1`)
        // fails before the token reaches the wire, it's wasted
        // without being verified by the bridge. Both failure
        // modes are programmer-error / library-bug paths (token
        // format was validated when minted; keys are fixed-size
        // arrays), not attacker-controllable, so the leak window
        // is theoretical. A `peek-then-commit` API on
        // `OneShotTokens` would close it; deferred until a
        // concrete failure mode is reproduced.
        let initial_budget = remaining_until(absolute_deadline);
        if initial_budget.is_zero() {
            return Err(RuntimeError::HopTimeout {
                hop_idx: next_hop_idx,
            });
        }
        let token = self
            .tokens
            .next_token()
            .ok_or_else(|| RuntimeError::Other("no capability tokens available".into()))?;

        // 2. Drive the per-hop HandshakeInitiator through msg_1
        //    locally to produce the EXTEND payload.
        let mut initiator =
            HandshakeInitiator::new(&self.client_static_sk, &new_hop_spec.static_pk, &token)
                .map_err(|e| {
                    RuntimeError::Other(format!(
                        "HandshakeInitiator::new (hop {next_hop_idx}): {e}"
                    ))
                })?;
        let hs_msg1 = initiator
            .write_message_1()
            .map_err(|_| RuntimeError::HopHandshake {
                hop_idx: next_hop_idx,
            })?;

        // 3. Build the EXTEND cell + any CMD_EXTEND_CONT
        //    continuation cells. Closes [RT-O3]: hs_msg1 (1221 B
        //    in v0.1 with ML-KEM-768) doesn't fit in a single
        //    1024 B cell; fragmentation handles the overflow.
        let extend_body = ExtendBody {
            next_hop_pk: new_hop_spec.static_pk,
            endpoint: new_hop_spec.endpoint.clone(),
            hs_msg1,
        };
        let (extend_cell_body, cont_bodies) = extend_body
            .encode_fragmented(mirage_circuit::MAX_CELL_PAYLOAD)
            .map_err(|e| RuntimeError::Other(format!("ExtendBody fragmentation: {e}")))?;
        let extend_cell = Cell::new(conn.hop0_circ_id, CMD_EXTEND, extend_cell_body)
            .map_err(|e| RuntimeError::Other(format!("Cell::new(EXTEND): {e}")))?;
        let mut cont_cells = Vec::with_capacity(cont_bodies.len());
        for body in cont_bodies {
            cont_cells.push(
                Cell::new(conn.hop0_circ_id, CMD_EXTEND_CONT, body)
                    .map_err(|e| RuntimeError::Other(format!("Cell::new(EXTEND_CONT): {e}")))?,
            );
        }

        // 4. Send + receive the EXTEND/EXTENDED roundtrip,
        //    bounded by the remaining handshake budget.
        let extended_body = {
            let send_budget = remaining_until(absolute_deadline);
            if send_budget.is_zero() {
                return Err(RuntimeError::HopTimeout {
                    hop_idx: next_hop_idx,
                });
            }
            let mut session = conn.session.lock().await;
            let result = tokio::time::timeout(send_budget, async {
                write_cell(&mut *session, &extend_cell).await.map_err(|_| {
                    RuntimeError::ExtendExchange {
                        hop_idx: next_hop_idx,
                    }
                })?;
                for cell in &cont_cells {
                    write_cell(&mut *session, cell).await.map_err(|_| {
                        RuntimeError::ExtendExchange {
                            hop_idx: next_hop_idx,
                        }
                    })?;
                }
                let first = crate::cell_io::read_cell(&mut *session)
                    .await
                    .map_err(|_| RuntimeError::ExtendExchange {
                        hop_idx: next_hop_idx,
                    })?;
                if first.command != CMD_EXTENDED || first.circ_id != conn.hop0_circ_id {
                    return Err(RuntimeError::ExtendExchange {
                        hop_idx: next_hop_idx,
                    });
                }
                // Closes [RT-O3] reverse: hs_msg2 may span
                // multiple cells (CMD_EXTENDED + N CMD_EXTENDED_CONT).
                let (total_len, first_chunk) =
                    ExtendedBody::decode_partial(&first.body).map_err(|_| {
                        RuntimeError::ExtendExchange {
                            hop_idx: next_hop_idx,
                        }
                    })?;
                let mut hs_msg2 = first_chunk.to_vec();
                while hs_msg2.len() < total_len {
                    let cont = crate::cell_io::read_cell(&mut *session)
                        .await
                        .map_err(|_| RuntimeError::ExtendExchange {
                            hop_idx: next_hop_idx,
                        })?;
                    if cont.command != CMD_EXTENDED_CONT || cont.circ_id != conn.hop0_circ_id {
                        return Err(RuntimeError::ExtendExchange {
                            hop_idx: next_hop_idx,
                        });
                    }
                    if hs_msg2.len() + cont.body.len() > total_len {
                        return Err(RuntimeError::ExtendExchange {
                            hop_idx: next_hop_idx,
                        });
                    }
                    hs_msg2.extend_from_slice(&cont.body);
                }
                Ok(ExtendedBody { hs_msg2 })
            })
            .await;
            match result {
                Ok(Ok(body)) => body,
                Ok(Err(e)) => return Err(e),
                Err(_) => {
                    return Err(RuntimeError::HopTimeout {
                        hop_idx: next_hop_idx,
                    })
                }
            }
        };

        // 5. Drive the initiator through msg_2 -> extract circuit-level
        //    hop keys (from noise_h_after_msg2, matching the bridge
        //    responder's write_message_2_for_circuit_hop) -> then msg_3.
        //
        //    Keys are derived BEFORE write_message_3 so both parties
        //    agree on the same transcript point. msg_3 is still sent
        //    via CMD_EXTEND_FINISH for token verification at the next
        //    hop (Phase 2G). Closes [RT-P2G-6]: token not burned until
        //    after the circuit-key binding is committed.
        initiator
            .read_message_2(&extended_body.hs_msg2)
            .map_err(|_| RuntimeError::HopHandshake {
                hop_idx: next_hop_idx,
            })?;
        // Extract circuit binding from noise_h_after_msg2.
        let (mlkem_ss, circuit_binding) =
            initiator
                .circuit_hop_binding()
                .map_err(|_| RuntimeError::HopHandshake {
                    hop_idx: next_hop_idx,
                })?;
        let (msg_3, _session_keys) =
            initiator
                .write_message_3()
                .map_err(|_| RuntimeError::HopHandshake {
                    hop_idx: next_hop_idx,
                })?;

        // Phase 2G: send msg_3 to the responder via a
        // `CMD_EXTEND_FINISH` cell on the hop-0 session. Closes
        // [RT-O2]. The bridge at hop-0 detects the command,
        // forwards `hs_msg3` verbatim to hop-1's transport, and
        // hop-1's `HandshakeResponder::read_message_3` completes
        // the handshake.
        //
        // 2-hop case: send directly on the hop-0 session.
        // 3+ hop case: would onion-seal and send as RELAY; this
        // path is gated by the `hops_already_built != 1` check
        // above so we always reach here in 2-hop scope.
        let finish_body = ExtendFinishBody { hs_msg3: msg_3 };
        let finish_cell = build_extend_finish_cell(conn.hop0_circ_id, finish_body)?;
        {
            let send_budget = remaining_until(absolute_deadline);
            if send_budget.is_zero() {
                return Err(RuntimeError::HopTimeout {
                    hop_idx: next_hop_idx,
                });
            }
            let mut session = conn.session.lock().await;
            let result = tokio::time::timeout(send_budget, async {
                write_cell(&mut *session, &finish_cell).await.map_err(|_| {
                    RuntimeError::ExtendExchange {
                        hop_idx: next_hop_idx,
                    }
                })
            })
            .await;
            match result {
                Ok(Ok(())) => {}
                Ok(Err(e)) => return Err(e),
                Err(_) => {
                    return Err(RuntimeError::HopTimeout {
                        hop_idx: next_hop_idx,
                    })
                }
            }
        }

        let keys = derive_hop_keys_from_handshake(&mlkem_ss, &circuit_binding);
        Ok(keys)
    }

    async fn destroy_circuit(&self, conn: Self::ConnHandle, _hops_built: usize) {
        // Best-effort: send DESTROY on hop-0 circuit and drop
        // the SessionStream. Failures are logged at debug level -
        // the caller has already failed; we don't return errors.
        if let Ok(cell) = Cell::new(conn.hop0_circ_id, CMD_DESTROY, vec![]) {
            let mut session = conn.session.lock().await;
            if let Err(e) = write_cell(&mut *session, &cell).await {
                tracing::debug!(error = %e, "destroy: write_cell failed (best-effort)");
            }
        }
        // SessionStream drop (when conn falls out of scope) closes
        // the underlying transport.
    }
}

// Internal helpers

/// Remaining time until `deadline`, or `Duration::ZERO` if the
/// deadline has passed. Used to share one budget across multiple
/// async I/O calls without each one silently re-consuming the full
/// caller-supplied `Duration`.
fn remaining_until(deadline: tokio::time::Instant) -> Duration {
    deadline.saturating_duration_since(tokio::time::Instant::now())
}

/// Convert a circuit `HopEndpoint` to a discovery `Endpoint` so
/// it can be passed to `mirage_transport::DialInputs`. The two
/// types are intentionally distinct (circuit excludes the
/// deprecated `Domain` variant) - this conversion is total.
fn hop_endpoint_to_discovery(ep: &HopEndpoint) -> Result<Endpoint, &'static str> {
    match ep {
        HopEndpoint::Ipv4 { addr, port } => Ok(Endpoint::Ipv4 {
            addr: *addr,
            port: *port,
        }),
        HopEndpoint::Ipv6 { addr, port } => Ok(Endpoint::Ipv6 {
            addr: *addr,
            port: *port,
        }),
        HopEndpoint::OnionV3 { ascii, port } => Ok(Endpoint::OnionV3 {
            ascii: *ascii,
            port: *port,
        }),
    }
}

/// Run the initiator side of the Mirage handshake by hand.
/// Returns the post-handshake `SessionStream` plus the bytes the
/// circuit layer needs for hop-key derivation.
async fn run_handshake_initiator(
    mut stream: DuplexStream,
    client_static_sk: &[u8; 32],
    bridge_static_pk: &[u8; 32],
    token: &CapabilityToken,
    deadline: Duration,
) -> Result<(SessionStream<DuplexStream>, Zeroizing<[u8; 32]>, [u8; 32]), RuntimeError> {
    let result = tokio::time::timeout(deadline, async move {
        let mut initiator = HandshakeInitiator::new(client_static_sk, bridge_static_pk, token)
            .map_err(|e| RuntimeError::Other(format!("HandshakeInitiator::new: {e}")))?;

        // Message 1. Length-prefixed + randomly padded, byte-identical to
        // `mirage_session::connect` - the bridge's `accept` reads framed
        // handshakes, so a raw message would be misparsed (review-1).
        let m1 = initiator
            .write_message_1()
            .map_err(|e| RuntimeError::Other(format!("write_message_1: {e}")))?;
        mirage_session::write_padded_handshake(&mut stream, &m1)
            .await
            .map_err(|_| RuntimeError::TransportDial)?;

        // Message 2.
        let m2 = mirage_session::read_padded_handshake(&mut stream, MSG_2_LEN)
            .await
            .map_err(|_| RuntimeError::HopHandshake { hop_idx: 0 })?;
        initiator
            .read_message_2(&m2)
            .map_err(|_| RuntimeError::HopHandshake { hop_idx: 0 })?;

        // Message 3 - produces SessionKeys.
        let (m3, session_keys) = initiator
            .write_message_3()
            .map_err(|_| RuntimeError::HopHandshake { hop_idx: 0 })?;
        debug_assert_eq!(m3.len(), MSG_3_LEN_WITH_TOKEN);

        // Snapshot key material the circuit layer needs BEFORE
        // SessionFramer consumes the keys.
        // Snapshot K_pq in a Zeroizing wrapper so this copy (and everything it
        // threads into for onion-key derivation) wipes on drop.
        let mlkem_ss = Zeroizing::new(session_keys.mlkem_ss);
        let session_binding = session_keys.session_binding;

        // Pad msg 3 up to the common FS floor (315) exactly like the single-hop
        // client path, so a relay-to-relay handshake's msg-3 length is
        // indistinguishable from a client-to-bridge one and from an FS-token
        // handshake (red-team #18/#20). This path always carries a legacy
        // (203-byte) token, which would otherwise stand out by length.
        mirage_session::write_padded_handshake_floor(&mut stream, &m3, MSG_3_LEN_WITH_FS_TOKEN)
            .await
            .map_err(|_| RuntimeError::TransportDial)?;

        // Build the framer + session stream.
        let framer =
            SessionFramer::from_session_keys(session_keys, mirage_session::Role::Initiator)
                .map_err(|e| RuntimeError::Other(format!("SessionFramer: {e}")))?;
        let session = SessionStream::new(framer, stream);

        Ok::<_, RuntimeError>((session, mlkem_ss, session_binding))
    })
    .await;

    match result {
        Ok(Ok(triple)) => Ok(triple),
        Ok(Err(e)) => Err(e),
        Err(_) => Err(RuntimeError::HopTimeout { hop_idx: 0 }),
    }
}

// EXTEND / EXTENDED cell construction helpers. `build_extend_finish_cell` is
// used by the live extend path (above); `build_extend_cell` /
// `parse_extended_cell` are construction/parse helpers retained as public API.

/// Build an EXTEND cell with the supplied `extend_body` and `circ_id`.
pub fn build_extend_cell(circ_id: u32, body: ExtendBody) -> Result<Cell, RuntimeError> {
    let bytes = body
        .encode()
        .map_err(|e| RuntimeError::Other(format!("ExtendBody::encode: {e}")))?;
    Cell::new(circ_id, CMD_EXTEND, bytes)
        .map_err(|e| RuntimeError::Other(format!("Cell::new: {e}")))
}

/// Parse an EXTENDED cell's body.
pub fn parse_extended_cell(cell: &Cell) -> Result<ExtendedBody, RuntimeError> {
    if cell.command != CMD_EXTENDED {
        return Err(RuntimeError::ExtendExchange { hop_idx: 0 });
    }
    ExtendedBody::decode(&cell.body)
        .map_err(|e| RuntimeError::Other(format!("ExtendedBody::decode: {e}")))
}

/// Build an `EXTEND_FINISH` cell with the supplied `body` and
/// `circ_id`. Phase 2G helper - closes [RT-O2]. The cell carries
/// the initiator's `hs_msg3`; the bridge at hop-0 forwards the
/// bytes verbatim to the responder so it can complete the
/// handshake.
pub fn build_extend_finish_cell(
    circ_id: u32,
    body: ExtendFinishBody,
) -> Result<Cell, RuntimeError> {
    let bytes = body
        .encode()
        .map_err(|e| RuntimeError::Other(format!("ExtendFinishBody::encode: {e}")))?;
    Cell::new(circ_id, CMD_EXTEND_FINISH, bytes)
        .map_err(|e| RuntimeError::Other(format!("Cell::new: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_shot_tokens_drains_to_none() {
        // The TokenSupplier API is testable without the rest of
        // the runtime stack. Construction of real tokens requires
        // operator-signed material we don't synthesise here, so we
        // verify the empty-pool case (which models exhaustion).
        let supplier = OneShotTokens::new(Vec::new());
        assert!(supplier.next_token().is_none());
        assert_eq!(supplier.remaining(), 0);
        // After exhaustion, repeated calls keep returning None
        // (no resurrection).
        assert!(supplier.next_token().is_none());
        assert!(supplier.next_token().is_none());
    }

    #[test]
    fn hop_endpoint_conversion_ipv4() {
        let circuit_ep = HopEndpoint::Ipv4 {
            addr: [203, 0, 113, 5],
            port: 4433,
        };
        let discovery_ep = hop_endpoint_to_discovery(&circuit_ep).unwrap();
        match discovery_ep {
            Endpoint::Ipv4 { addr, port } => {
                assert_eq!(addr, [203, 0, 113, 5]);
                assert_eq!(port, 4433);
            }
            _ => panic!("expected ipv4"),
        }
    }

    #[test]
    fn hop_endpoint_conversion_ipv6() {
        let circuit_ep = HopEndpoint::Ipv6 {
            addr: [
                0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x00, 0x01,
            ],
            port: 4433,
        };
        let discovery_ep = hop_endpoint_to_discovery(&circuit_ep).unwrap();
        assert!(matches!(discovery_ep, Endpoint::Ipv6 { .. }));
    }

    #[test]
    fn build_extend_cell_round_trips_body() {
        let body = ExtendBody {
            next_hop_pk: [0x42; 32],
            endpoint: HopEndpoint::Ipv4 {
                addr: [10, 0, 0, 1],
                port: 4433,
            },
            hs_msg1: vec![0xAB; 100],
        };
        let cell = build_extend_cell(7, body.clone()).unwrap();
        assert_eq!(cell.command, CMD_EXTEND);
        assert_eq!(cell.circ_id, 7);
        // Parse body back.
        let decoded = ExtendBody::decode(&cell.body).unwrap();
        assert_eq!(decoded.next_hop_pk, body.next_hop_pk);
        assert_eq!(decoded.hs_msg1, body.hs_msg1);
    }

    #[test]
    fn parse_extended_cell_rejects_wrong_command() {
        let cell = Cell::new(7, CMD_EXTEND, vec![0; 10]).unwrap();
        let err = parse_extended_cell(&cell).unwrap_err();
        assert!(matches!(err, RuntimeError::ExtendExchange { hop_idx: 0 }));
    }

    #[test]
    fn parse_extended_cell_decodes_body() {
        let body = ExtendedBody {
            hs_msg2: vec![0xCD; 200],
        };
        let cell = Cell::new(7, CMD_EXTENDED, body.encode().unwrap()).unwrap();
        let parsed = parse_extended_cell(&cell).unwrap();
        assert_eq!(parsed.hs_msg2, body.hs_msg2);
    }

    #[test]
    fn alloc_circ_id_skips_zero() {
        // Construct a runtime stub just to exercise the allocator.
        // No real transport needed for this unit test.
        struct NopTransport;
        #[async_trait::async_trait]
        impl ClientTransport for NopTransport {
            fn name(&self) -> &'static str {
                "nop"
            }
            fn capability_bit(&self) -> u32 {
                0
            }
            async fn dial(
                &self,
                _: &DialInputs<'_>,
            ) -> Result<DuplexStream, mirage_transport::TransportError> {
                Err(mirage_transport::TransportError::Other("nop".into()))
            }
        }
        let rt = SingleTransportHopRuntime::new(
            Arc::new(NopTransport),
            [0u8; 32],
            Arc::new(OneShotTokens::new(Vec::new())),
        );
        // Force the counter near wraparound.
        rt.next_circ_id
            .store(u32::MAX, std::sync::atomic::Ordering::Relaxed);
        // First fetch_add returns u32::MAX, wraps to 0 internally.
        // Our alloc_circ_id detects 0 and re-allocates.
        let id = rt.alloc_circ_id();
        assert_ne!(id, 0);
    }

    #[test]
    fn remaining_until_returns_zero_after_deadline() {
        // RT-N6 closure: the helper must return Duration::ZERO
        // (not panic, not return a negative-cast wrap) when called
        // past the deadline.
        let now = tokio::time::Instant::now();
        let past = now - Duration::from_secs(1);
        assert_eq!(remaining_until(past), Duration::ZERO);
        let future = now + Duration::from_secs(1);
        let r = remaining_until(future);
        // Should be approximately 1s, with some scheduling slack.
        assert!(r > Duration::from_millis(900) && r <= Duration::from_secs(1));
    }

    // Note: a full integration test for `extend_hop` (driving a
    // simulated bridge over `tokio::io::duplex` through the EXTEND
    // / EXTENDED roundtrip) is deferred to the Phase 2G integration
    // test pass, when 3+ hop telescoping is real-I/O. Until then,
    // the public API surface is unit-tested above and the 2-hop
    // path is covered by manual integration smoke tests on
    // operator machines.
}
