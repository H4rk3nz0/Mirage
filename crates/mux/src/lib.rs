//! Stream multiplexing for Mirage sessions.
//!
//! # Why
//!
//! v0.1 Mirage opened one tunnel per SOCKS5 CONNECT. Every browser
//! tab -> fresh handshake; every parallel HTTP/2 connection ->
//! fresh handshake. That's expensive (~1 RTT + crypto cost) and
//! a flow-correlation signal (a flurry of fresh tunnels at once
//! is suspicious in itself).
//!
//! This crate carries N concurrent streams over ONE Mirage session.
//! Per-stream flow control prevents one slow consumer from blocking
//! the others. Stream IDs are randomly drawn so two simultaneous
//! BEGIN cells don't collide.
//!
//! # Wire format
//!
//! Inside the session-frame plaintext, mux frames are length-prefixed:
//!
//! ```text
//! +------------+------------+-----+----------------------------+
//! | frame_len  | stream_id  | cmd | body (frame_len - 7 bytes) |
//! |  u16 BE    |  u32 BE    | u8  |                             |
//! |  2 B       |  4 B       | 1 B |                             |
//! +------------+------------+-----+----------------------------+
//! ```
//!
//! - `frame_len`: total bytes including the 7-byte header. Bounded
//!   at [`MAX_MUX_FRAME_LEN`] (16384) to fit one Mirage session-frame
//!   plaintext.
//! - `stream_id`: u32 BE; each side allocates from a separate
//!   namespace (initiator: even IDs; responder: odd IDs) to avoid
//!   collisions on simultaneous BEGIN.
//! - `cmd`: one of [`MuxCmd::*`]. See §3.
//! - `body`: command-specific.
//!
//! # Commands
//!
//! - **`BEGIN`** - caller side opens a stream. Body = SOCKS5-style
//!   target address (kind byte + addr + port). The receiver
//!   responds with `BEGIN_OK` (data flows) or `RESET` (error).
//! - **`BEGIN_OK`** - responder accepted the stream.
//! - **`DATA`** - application payload bytes.
//! - **`WINDOW_UPDATE`** - credit delta (u32 BE), per-direction.
//! - **`END_LOCAL`** - sender informs peer it has no more bytes
//!   to send (half-close). Peer can still send to sender.
//! - **`RESET`** - abort with a 1-byte error code.
//!
//! # Flow control
//!
//! Each direction of each stream has a flow-control window. Initial
//! credit = [`DEFAULT_INITIAL_WINDOW`] = 65536 bytes. Senders track
//! local credit; receivers send `WINDOW_UPDATE` to top up.
//!
//! # Stream IDs
//!
//! Per RFC-style convention:
//! - Initiator-opened streams use **even** IDs (2, 4, 6, ...).
//! - Responder-opened streams use **odd** IDs (1, 3, 5, ...).
//! - ID `0` is reserved for the connection-level (e.g.,
//!   future-use connection-window-update).
//!
//! # Threat-model fit
//!
//! - **Active prober opens many fast streams**: bounded by the
//!   `max_concurrent_streams` policy ([`MuxPolicy`]).
//! - **Slow-loris on one stream**: per-stream idle timeout closes
//!   it without affecting siblings.
//! - **Per-stream metadata leak**: stream IDs are randomly drawn
//!   within their parity, so an observer of the session-frame
//!   plaintext cannot trivially correlate streams across sessions.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod conn;
pub mod frame;
pub mod policy;
pub mod state;
pub mod stream;
pub mod target;

pub use conn::{IncomingStream, MuxAcceptor, MuxConnError, MuxConnection, MuxStream};

/// One-byte session-type tag the client sends as the FIRST plaintext byte over
/// an authenticated Mirage session, telling the bridge how to interpret the
/// rest of the stream:
///
/// - `0x00` ([`MUX_SESSION_TAG`]) - a mux carrier; this crate's length-prefixed
///   frames follow, and many concurrent streams ride the one session.
/// - `0x05` - a legacy single SOCKS5 request (the value is the SOCKS version
///   byte, so the pre-mux wire is unchanged and needs no tag of its own).
/// - anything else - dispatched by the bridge as before (e.g. HTTP CONNECT,
///   whose methods begin with an ASCII letter).
///
/// `0x00` is safe as a discriminator: it is neither the SOCKS5 version nor a
/// valid leading byte of an HTTP request line.
pub const MUX_SESSION_TAG: u8 = 0x00;
pub use frame::{MuxCmd, MuxFrame, MuxFrameError, MAX_MUX_FRAME_LEN, MUX_HEADER_LEN};
pub use policy::{MuxPolicy, DEFAULT_INITIAL_WINDOW, DEFAULT_MAX_CONCURRENT_STREAMS};
pub use state::{MuxEvent, MuxState, MuxStateError, StreamState};
pub use stream::{StreamId, StreamRole};
pub use target::{MuxTarget, TargetError};
