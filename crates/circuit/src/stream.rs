//! Wire codec for relay sub-cell stream bodies (BEGIN / DATA / END).
//!
//! These types belong in `mirage_circuit` - both the bridge (exit hop) and
//! the client (initiator) encode/decode them. Placing them here avoids a
//! client-on-bridge or bridge-on-client dependency.

/// Stream identifier type (per-circuit, client-chosen, non-zero).
pub type StreamId = u16;

/// Error returned by stream body encode/decode.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StreamBodyError {
    /// Malformed body.
    #[error("stream body: {0}")]
    Body(&'static str),
}

/// Encoded `BEGIN` body: `[stream_id u16 BE, host_len u8, host, port u16 BE]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BeginBody {
    /// Client-chosen stream identifier.
    pub stream_id: StreamId,
    /// Destination host (DNS name or IP literal).
    pub host: String,
    /// Destination TCP port.
    pub port: u16,
}

impl BeginBody {
    /// Encode to wire bytes.
    pub fn encode(&self) -> Result<Vec<u8>, StreamBodyError> {
        if self.host.len() > u8::MAX as usize {
            return Err(StreamBodyError::Body("host too long"));
        }
        let mut out = Vec::with_capacity(2 + 1 + self.host.len() + 2);
        out.extend_from_slice(&self.stream_id.to_be_bytes());
        out.push(self.host.len() as u8);
        out.extend_from_slice(self.host.as_bytes());
        out.extend_from_slice(&self.port.to_be_bytes());
        Ok(out)
    }

    /// Decode from wire bytes.
    pub fn decode(buf: &[u8]) -> Result<Self, StreamBodyError> {
        if buf.len() < 3 {
            return Err(StreamBodyError::Body("BEGIN body too short"));
        }
        let stream_id = u16::from_be_bytes([buf[0], buf[1]]);
        let host_len = buf[2] as usize;
        if buf.len() < 3 + host_len + 2 {
            return Err(StreamBodyError::Body("BEGIN body truncated"));
        }
        let host = std::str::from_utf8(&buf[3..3 + host_len])
            .map_err(|_| StreamBodyError::Body("host not utf-8"))?
            .to_string();
        let port = u16::from_be_bytes([buf[3 + host_len], buf[3 + host_len + 1]]);
        if port == 0 {
            return Err(StreamBodyError::Body("port 0 reserved"));
        }
        Ok(Self {
            stream_id,
            host,
            port,
        })
    }
}

/// Encoded `DATA` body: `[stream_id u16 BE, bytes...]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataBody {
    /// Stream this data belongs to.
    pub stream_id: StreamId,
    /// Application bytes.
    pub bytes: Vec<u8>,
}

impl DataBody {
    /// Encode to wire bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + self.bytes.len());
        out.extend_from_slice(&self.stream_id.to_be_bytes());
        out.extend_from_slice(&self.bytes);
        out
    }

    /// Decode from wire bytes.
    pub fn decode(buf: &[u8]) -> Result<Self, StreamBodyError> {
        if buf.len() < 2 {
            return Err(StreamBodyError::Body("DATA body too short"));
        }
        let stream_id = u16::from_be_bytes([buf[0], buf[1]]);
        Ok(Self {
            stream_id,
            bytes: buf[2..].to_vec(),
        })
    }
}

/// Encoded `END` body: `[stream_id u16 BE]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EndBody {
    /// Stream that is closing.
    pub stream_id: StreamId,
}

impl EndBody {
    /// Encode to wire bytes.
    pub fn encode(self) -> [u8; 2] {
        self.stream_id.to_be_bytes()
    }

    /// Decode from wire bytes.
    pub fn decode(buf: &[u8]) -> Result<Self, StreamBodyError> {
        if buf.len() != 2 {
            return Err(StreamBodyError::Body("END body wrong length"));
        }
        Ok(Self {
            stream_id: u16::from_be_bytes([buf[0], buf[1]]),
        })
    }
}
