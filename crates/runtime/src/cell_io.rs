//! Cell I/O primitives.
//!
//! Phase 2E first step: read / write Mirage circuit cells over
//! any `AsyncRead` + `AsyncWrite` duplex. The caller supplies the
//! underlying byte stream - typically a post-handshake
//! `mirage_session::SessionStream` (AEAD'd by the session layer)
//! or a `tokio::io::DuplexStream` for tests.
//!
//! Cells are fixed-size ([`mirage_circuit::CIRCUIT_CELL_LEN`] =
//! 1024 bytes), so framing is trivial: each cell is exactly one
//! `read_exact(1024)` / `write_all(1024)`.

use mirage_circuit::{Cell, CellError, CIRCUIT_CELL_LEN};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Cell-I/O errors.
#[derive(Debug, Error)]
pub enum CellIoError {
    /// Underlying stream I/O failed.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// Cell wire-format violation (decoder rejected the bytes).
    #[error("cell: {0}")]
    Cell(#[from] CellError),
}

/// Read exactly one [`Cell`] from `reader`. Returns the parsed
/// cell or an error if the stream closes mid-cell, the bytes
/// don't decode, or the underlying I/O fails.
pub async fn read_cell<R>(reader: &mut R) -> Result<Cell, CellIoError>
where
    R: AsyncRead + Unpin,
{
    let mut buf = [0u8; CIRCUIT_CELL_LEN];
    reader.read_exact(&mut buf).await?;
    Ok(Cell::decode(&buf)?)
}

/// Write one [`Cell`] to `writer`. Encodes the cell to its
/// 1024-byte wire form and writes it atomically (one
/// `write_all` call). Caller is responsible for flushing if
/// using a buffered writer.
pub async fn write_cell<W>(writer: &mut W, cell: &Cell) -> Result<(), CellIoError>
where
    W: AsyncWrite + Unpin,
{
    let bytes = cell.encode()?;
    writer.write_all(&bytes).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use mirage_circuit::CMD_CREATE;
    use tokio::io::duplex;

    #[tokio::test]
    async fn write_then_read_roundtrips() {
        let (mut a, mut b) = duplex(2048);
        let original = Cell::new(7, CMD_CREATE, vec![0xAB; 100]).unwrap();
        write_cell(&mut a, &original).await.unwrap();
        let recovered = read_cell(&mut b).await.unwrap();
        assert_eq!(recovered.circ_id, original.circ_id);
        assert_eq!(recovered.command, original.command);
        assert_eq!(recovered.body, original.body);
    }

    #[tokio::test]
    async fn read_from_closed_stream_returns_io_error() {
        let (a, mut b) = duplex(1024);
        drop(a); // close write side
        let err = read_cell(&mut b).await.unwrap_err();
        assert!(matches!(err, CellIoError::Io(_)));
    }

    #[tokio::test]
    async fn read_from_truncated_cell_returns_io_error() {
        let (mut a, mut b) = duplex(2048);
        // Write only 100 bytes then close - short of 1024.
        a.write_all(&[0u8; 100]).await.unwrap();
        drop(a);
        let err = read_cell(&mut b).await.unwrap_err();
        assert!(matches!(err, CellIoError::Io(_)));
    }

    #[tokio::test]
    async fn read_from_garbage_bytes_returns_cell_error() {
        // Write 1024 bytes of garbage that fail Cell::decode
        // (circ_id = 0 is reserved).
        let (mut a, mut b) = duplex(2048);
        a.write_all(&[0u8; CIRCUIT_CELL_LEN]).await.unwrap();
        let err = read_cell(&mut b).await.unwrap_err();
        assert!(matches!(err, CellIoError::Cell(_)));
    }

    #[tokio::test]
    async fn many_cells_in_sequence() {
        let (mut a, mut b) = duplex(8 * CIRCUIT_CELL_LEN);
        let writer = tokio::spawn(async move {
            for i in 1..=4u32 {
                let cell = Cell::new(i, CMD_CREATE, vec![i as u8; 50]).unwrap();
                write_cell(&mut a, &cell).await.unwrap();
            }
        });
        for i in 1..=4u32 {
            let cell = read_cell(&mut b).await.unwrap();
            assert_eq!(cell.circ_id, i);
            assert_eq!(cell.body[0], i as u8);
        }
        writer.await.unwrap();
    }

    #[tokio::test]
    async fn write_cell_atomicity_on_partial_write_failure() {
        // duplex(N) buffers up to N bytes. If we write a cell to
        // a 512-byte buffer with no reader, write_all blocks
        // until the buffer drains. This test verifies the API
        // doesn't accidentally split a cell across calls (it
        // shouldn't - we use write_all).
        let (mut a, mut b) = duplex(512);
        let cell = Cell::new(7, CMD_CREATE, vec![0xCC; 500]).unwrap();
        let writer = tokio::spawn(async move {
            write_cell(&mut a, &cell).await.unwrap();
        });
        // Reader drains as the writer pumps.
        let recovered = read_cell(&mut b).await.unwrap();
        assert_eq!(recovered.circ_id, 7);
        assert_eq!(recovered.body.len(), 500);
        writer.await.unwrap();
    }
}
