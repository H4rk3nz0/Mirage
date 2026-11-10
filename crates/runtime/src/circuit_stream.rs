//! A built circuit as an ordinary byte stream.
//!
//! # Why this exists
//!
//! Everything above a circuit wants a duplex: a Mirage session, a SOCKS relay, a
//! hidden service's local TCP target. A circuit is not one - it is a sequence of
//! onion-sealed `CMD_RELAY` cells with per-direction sequence counters that only
//! one owner may advance. So every consumer has hand-rolled the same loop, and
//! the one place that most needs it has not been written at all: a client and a
//! hidden service that have met at a rendezvous point still have no way to run a
//! session between them, which is why traffic crossing a joined pair is currently
//! readable by the bridge hosting the meeting.
//!
//! [`circuit_stream`] closes that. It takes a session carrying a built circuit
//! and returns a `DuplexStream`; the caller reads and writes bytes and never sees
//! a cell.
//!
//! # Why a task and a duplex rather than a poll state machine
//!
//! A hand-written `AsyncRead`/`AsyncWrite` over this would have to interleave
//! two directions, each mid-cell, each holding a borrow of the circuit for
//! sealing - a state machine with several partial-progress cases and no way to
//! test them individually. Handing the framing to one task that owns the circuit
//! outright makes the sequence counters trivially correct: only one place
//! advances them, in order. The pacer (`mirage_transport_reality::PacedChannel`)
//! made the same trade for the same reason.
//!
//! The cost is a copy through the duplex buffer, which is irrelevant next to the
//! AEAD work per cell.
//!
//! # What this does NOT do
//!
//! It carries bytes over a circuit that is ALREADY BUILT. It does not build one,
//! does not extend it, and does not decide how many hops it should have - all of
//! which are the caller's, because a circuit's hop count is an anonymity decision
//! and not a transport one. A hidden service reaching an introduction point over
//! a one-hop circuit has told that bridge its IP address, which is the single
//! property the service exists to protect.

use std::time::Duration;

use mirage_circuit::cell::Cell;
use mirage_circuit::circuit::Circuit;
use mirage_circuit::{
    stream::DataBody, RelaySubCell, CMD_DATA, CMD_END, CMD_RELAY, MAX_CELL_PAYLOAD,
    MAX_CIRCUIT_HOPS,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream};

use crate::cell_io::{read_cell, write_cell};

/// Bytes of application data per `CMD_DATA` cell.
///
/// Cell cap minus one AEAD tag PER HOP (each hop adds an onion layer), minus the
/// sub-cell header and the stream id. Sized against `MAX_CIRCUIT_HOPS` rather
/// than the circuit's actual depth so a forward cell is the same size whatever
/// the depth is - otherwise a relay could read its own hop index off the body
/// length.
pub const MAX_STREAM_DATA: usize =
    MAX_CELL_PAYLOAD.saturating_sub(MAX_CIRCUIT_HOPS * 16 + RELAY_HDR + STREAM_ID_LEN);
const RELAY_HDR: usize = 3;
const STREAM_ID_LEN: usize = 2;

/// Duplex buffer between the caller and the framing task.
const DUPLEX_BUF: usize = 64 * 1024;

/// Wrap a built circuit as a byte stream.
///
/// `session` must already carry the circuit identified by `circ_id`, and
/// `circuit` must hold its hop keys with both sequence counters where the
/// handshake left them. `stream_id` labels the single logical stream this
/// carries.
///
/// The returned duplex closes when the peer sends `CMD_END`, when the session
/// errors, or when the caller drops it.
pub fn circuit_stream<S>(session: S, circuit: Circuit, circ_id: u32, stream_id: u16) -> DuplexStream
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (caller, inner) = tokio::io::duplex(DUPLEX_BUF);
    tokio::spawn(pump(session, circuit, circ_id, stream_id, inner));
    caller
}

/// Own the circuit and shuttle bytes both ways until either side finishes.
async fn pump<S>(
    session: S,
    mut circuit: Circuit,
    circ_id: u32,
    stream_id: u16,
    inner: DuplexStream,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // Split both sides so the two directions can be selected on concurrently.
    // Without this the select arms would each need a mutable borrow of the same
    // stream and the loop would not compile - which is the first thing a
    // hand-rolled version gets wrong.
    let (mut net_r, mut net_w) = tokio::io::split(session);
    let (mut app_r, mut app_w) = tokio::io::split(inner);
    let mut buf = vec![0u8; MAX_STREAM_DATA];

    loop {
        tokio::select! {
            // Peer -> caller.
            cell = read_cell(&mut net_r) => {
                let Ok(cell) = cell else { break };
                if cell.circ_id != circ_id || cell.command != CMD_RELAY {
                    // Not ours. Dropping is right: a circuit carries exactly one
                    // stream here, and anything else on it is either another
                    // consumer's business or a peer doing something unexpected.
                    continue;
                }
                let Ok(plain) = circuit.relay_open(&cell.body) else { break };
                let Ok(sub) = RelaySubCell::decode(&plain) else { break };
                match sub.command {
                    CMD_DATA => {
                        let Ok(d) = DataBody::decode(&sub.body) else { break };
                        if app_w.write_all(&d.bytes).await.is_err() {
                            break;
                        }
                    }
                    CMD_END => break,
                    // Anything else on this circuit is not this stream's.
                    _ => {}
                }
            }
            // Caller -> peer.
            n = app_r.read(&mut buf) => {
                let Ok(n) = n else { break };
                if n == 0 {
                    // Caller finished writing: tell the peer rather than leaving
                    // it waiting on a stream that will never produce more.
                    let _ = send_end(&mut net_w, &mut circuit, circ_id, stream_id).await;
                    break;
                }
                let body = DataBody { stream_id, bytes: buf[..n].to_vec() }.encode();
                let Ok(payload) = (RelaySubCell { command: CMD_DATA, body }).encode() else {
                    break;
                };
                let Ok(sealed) = circuit.relay_seal(&payload) else { break };
                let Ok(cell) = Cell::new(circ_id, CMD_RELAY, sealed) else { break };
                if write_cell(&mut net_w, &cell).await.is_err() {
                    break;
                }
            }
        }
    }
    // Best-effort: the caller's half closes when this task drops its end, which
    // is what surfaces EOF to whoever is reading.
    let _ = app_w.shutdown().await;
}

/// Send `CMD_END` so the peer learns the stream is finished.
async fn send_end<W>(
    net_w: &mut W,
    circuit: &mut Circuit,
    circ_id: u32,
    stream_id: u16,
) -> Result<(), ()>
where
    W: AsyncWrite + Unpin,
{
    let body = mirage_circuit::stream::EndBody { stream_id }
        .encode()
        .to_vec();
    let payload = RelaySubCell {
        command: CMD_END,
        body,
    }
    .encode()
    .map_err(|_| ())?;
    let sealed = circuit.relay_seal(&payload).map_err(|_| ())?;
    let cell = Cell::new(circ_id, CMD_RELAY, sealed).map_err(|_| ())?;
    // Bounded: a peer that has stopped reading must not hold this task open.
    tokio::time::timeout(Duration::from_secs(5), write_cell(net_w, &cell))
        .await
        .map_err(|_| ())?
        .map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use mirage_circuit::circuit::{DIR_CLIENT_TO_HOP, DIR_HOP_TO_CLIENT};
    use mirage_circuit::{onion_open, onion_seal, HopKeys};

    /// One hop's keys, shared by both ends of a loopback test.
    fn hop() -> HopKeys {
        mirage_circuit::derive_hop_keys_from_handshake(&[7u8; 32], &[9u8; 32])
    }

    #[tokio::test]
    async fn carries_bytes_over_a_circuit_in_both_directions() {
        // The property the hidden-service end-to-end layer needs: bytes in one
        // side come out the other, with all the cell framing and onion sealing
        // handled underneath. Without this, a client and service that have met at
        // a rendezvous point have no way to run a session between them, which is
        // why traffic crossing a joined pair is currently readable by the bridge
        // hosting the meeting.
        let keys = hop();
        let circ_id = 42u32;
        let (net_a, net_b) = tokio::io::duplex(64 * 1024);

        // Our side: a circuit holding the forward/reverse keys.
        let mut circuit = mirage_circuit::circuit::Circuit::new();
        circuit.extend(keys.clone()).expect("one hop");
        let mut stream = circuit_stream(net_a, circuit, circ_id, 7);

        // The peer: opens forward cells, echoes the payload back reverse-sealed.
        let peer_keys = keys.clone();
        let peer = tokio::spawn(async move {
            let (mut r, mut w) = tokio::io::split(net_b);
            let mut fwd_seq = 0u64;
            let mut rev_seq = 0u64;
            loop {
                let Ok(cell) = crate::cell_io::read_cell(&mut r).await else {
                    return;
                };
                let Ok(plain) = onion_open(
                    &[peer_keys.forward.clone()],
                    &cell.body,
                    DIR_CLIENT_TO_HOP,
                    0,
                    fwd_seq,
                ) else {
                    return;
                };
                fwd_seq += 1;
                let Ok(sub) = RelaySubCell::decode(&plain) else {
                    return;
                };
                if sub.command != CMD_DATA {
                    // CMD_END or anything else: stop echoing.
                    return;
                }
                let d = DataBody::decode(&sub.body).expect("data body");
                // Echo the same bytes back, reverse-sealed.
                let body = DataBody {
                    stream_id: d.stream_id,
                    bytes: d.bytes,
                }
                .encode();
                let payload = RelaySubCell {
                    command: CMD_DATA,
                    body,
                }
                .encode()
                .expect("encode");
                let sealed = onion_seal(
                    &[peer_keys.reverse.clone()],
                    &payload,
                    DIR_HOP_TO_CLIENT,
                    0,
                    rev_seq,
                )
                .expect("seal");
                rev_seq += 1;
                let cell = Cell::new(circ_id, CMD_RELAY, sealed).expect("cell");
                if crate::cell_io::write_cell(&mut w, &cell).await.is_err() {
                    return;
                }
            }
        });

        let payload = b"hidden service end-to-end payload".to_vec();
        stream.write_all(&payload).await.expect("write");
        stream.flush().await.expect("flush");

        let mut got = vec![0u8; payload.len()];
        tokio::time::timeout(
            Duration::from_secs(5),
            tokio::io::AsyncReadExt::read_exact(&mut stream, &mut got),
        )
        .await
        .expect("timed out waiting for the echo")
        .expect("read");
        assert_eq!(got, payload, "bytes must survive the round trip intact");

        drop(stream);
        let _ = peer.await;
    }

    #[tokio::test]
    async fn a_payload_larger_than_one_cell_is_split_and_reassembled() {
        // A cell holds well under 1 KiB of application data, so anything real
        // spans several. If the split or the reassembly is wrong it shows up as
        // truncation or reordering, both of which this catches.
        // A cell holds well under 2 KiB of application data, so the payload
        // below genuinely spans several and the split/reassembly is exercised
        // rather than trivially satisfied by one cell.
        const _: () = assert!(MAX_STREAM_DATA > 0 && MAX_STREAM_DATA < 2000);
        let keys = hop();
        let circ_id = 9u32;
        let (net_a, net_b) = tokio::io::duplex(256 * 1024);
        let mut circuit = mirage_circuit::circuit::Circuit::new();
        circuit.extend(keys.clone()).expect("one hop");
        let mut stream = circuit_stream(net_a, circuit, circ_id, 3);

        let peer_keys = keys.clone();
        let peer = tokio::spawn(async move {
            let (mut r, mut w) = tokio::io::split(net_b);
            let (mut fwd, mut rev) = (0u64, 0u64);
            loop {
                let Ok(cell) = crate::cell_io::read_cell(&mut r).await else {
                    return;
                };
                let Ok(plain) = onion_open(
                    &[peer_keys.forward.clone()],
                    &cell.body,
                    DIR_CLIENT_TO_HOP,
                    0,
                    fwd,
                ) else {
                    return;
                };
                fwd += 1;
                let Ok(sub) = RelaySubCell::decode(&plain) else {
                    return;
                };
                if sub.command != CMD_DATA {
                    return;
                }
                let d = DataBody::decode(&sub.body).expect("data");
                let payload = RelaySubCell {
                    command: CMD_DATA,
                    body: DataBody {
                        stream_id: d.stream_id,
                        bytes: d.bytes,
                    }
                    .encode(),
                }
                .encode()
                .expect("encode");
                let sealed = onion_seal(
                    &[peer_keys.reverse.clone()],
                    &payload,
                    DIR_HOP_TO_CLIENT,
                    0,
                    rev,
                )
                .expect("seal");
                rev += 1;
                let cell = Cell::new(circ_id, CMD_RELAY, sealed).expect("cell");
                if crate::cell_io::write_cell(&mut w, &cell).await.is_err() {
                    return;
                }
            }
        });

        // Several cells' worth, with a recognisable pattern so a reordering or a
        // dropped chunk is visible rather than merely a length mismatch.
        let payload: Vec<u8> = (0..MAX_STREAM_DATA * 3 + 17)
            .map(|i| (i % 251) as u8)
            .collect();
        stream.write_all(&payload).await.expect("write");
        stream.flush().await.expect("flush");

        let mut got = vec![0u8; payload.len()];
        tokio::time::timeout(
            Duration::from_secs(10),
            tokio::io::AsyncReadExt::read_exact(&mut stream, &mut got),
        )
        .await
        .expect("timed out")
        .expect("read");
        assert_eq!(got, payload, "multi-cell payload must reassemble in order");

        drop(stream);
        let _ = peer.await;
    }
}
