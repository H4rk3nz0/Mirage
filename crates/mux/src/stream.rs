//! Stream identifiers + role-based ID allocation.
//!
//! Per RFC convention (HTTP/2 RFC 7540 §5.1.1, QUIC RFC 9000 §2.1):
//! initiator and responder allocate from disjoint subsets of the
//! u32 stream-id space so simultaneous opens never collide.
//!
//! Mirage:
//! - **Initiator** uses **even** IDs (2, 4, 6, ...).
//! - **Responder** uses **odd** IDs (1, 3, 5, ...).
//! - ID `0` is reserved for connection-level frames (e.g., a
//!   future-use connection-window-update). [`StreamId::new`]
//!   rejects 0.

use std::sync::atomic::{AtomicU32, Ordering};

/// Role at the mux connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamRole {
    /// Initiator side - opens streams with even IDs.
    Initiator,
    /// Responder side - opens streams with odd IDs.
    Responder,
}

/// Strongly-typed stream ID. Wraps a `u32` but rejects 0 at
/// construction so the connection-reserved value can't slip into
/// a per-stream code path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StreamId(u32);

impl StreamId {
    /// Construct from a raw u32. Returns `None` if `id == 0`.
    pub fn new(id: u32) -> Option<Self> {
        if id == 0 {
            None
        } else {
            Some(Self(id))
        }
    }

    /// Raw u32 value.
    pub fn raw(self) -> u32 {
        self.0
    }

    /// True iff this ID belongs to the initiator's allocation
    /// space (even).
    pub fn is_initiator(self) -> bool {
        self.0 % 2 == 0
    }

    /// True iff this ID belongs to the responder's allocation
    /// space (odd).
    pub fn is_responder(self) -> bool {
        self.0 % 2 == 1
    }
}

/// Per-role stream-id allocator. Hands out fresh IDs by
/// monotonically incrementing within the role's subset of the u32
/// space. Wraps around at `u32::MAX` (which we treat as
/// "exhausted" - caller MUST tear down the connection rather than
/// re-using a wrapped ID).
pub struct StreamIdAllocator {
    role: StreamRole,
    next: AtomicU32,
}

impl StreamIdAllocator {
    /// New allocator. Initiators start at 2; responders at 1.
    pub fn new(role: StreamRole) -> Self {
        let start = match role {
            StreamRole::Initiator => 2,
            StreamRole::Responder => 1,
        };
        Self {
            role,
            next: AtomicU32::new(start),
        }
    }

    /// Allocate a fresh stream ID. Returns `None` when the role's
    /// subset is exhausted (after `~2^31` allocations - practically
    /// unreachable for legitimate clients but the connection must
    /// tear down if this ever happens).
    pub fn next(&self) -> Option<StreamId> {
        // Atomically grab the current value, advance by 2.
        let id = self.next.fetch_add(2, Ordering::Relaxed);
        // Detect wrap. fetch_add doesn't fail; we infer from the
        // returned value being lower than expected by checking
        // the parity (even for initiator, odd for responder). If
        // wrap caused parity flip, the role's space is exhausted.
        let ok = match self.role {
            StreamRole::Initiator => id % 2 == 0 && id != 0,
            StreamRole::Responder => id % 2 == 1,
        };
        if !ok {
            return None;
        }
        StreamId::new(id)
    }

    /// The role this allocator serves.
    pub fn role(&self) -> StreamRole {
        self.role
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stream_id_zero_rejected() {
        assert!(StreamId::new(0).is_none());
        assert!(StreamId::new(1).is_some());
    }

    #[test]
    fn parity_split_initiator_even_responder_odd() {
        assert!(StreamId::new(2).unwrap().is_initiator());
        assert!(StreamId::new(4).unwrap().is_initiator());
        assert!(StreamId::new(1).unwrap().is_responder());
        assert!(StreamId::new(3).unwrap().is_responder());
        assert!(!StreamId::new(2).unwrap().is_responder());
        assert!(!StreamId::new(1).unwrap().is_initiator());
    }

    #[test]
    fn allocator_initiator_yields_even_monotonic() {
        let a = StreamIdAllocator::new(StreamRole::Initiator);
        let ids: Vec<u32> = (0..5).map(|_| a.next().unwrap().raw()).collect();
        assert_eq!(ids, vec![2, 4, 6, 8, 10]);
    }

    #[test]
    fn allocator_responder_yields_odd_monotonic() {
        let a = StreamIdAllocator::new(StreamRole::Responder);
        let ids: Vec<u32> = (0..5).map(|_| a.next().unwrap().raw()).collect();
        assert_eq!(ids, vec![1, 3, 5, 7, 9]);
    }

    #[test]
    fn allocator_concurrent_yields_unique_ids() {
        use std::sync::Arc;
        use std::thread;
        let a = Arc::new(StreamIdAllocator::new(StreamRole::Initiator));
        let mut handles = Vec::new();
        for _ in 0..8 {
            let a = Arc::clone(&a);
            handles.push(thread::spawn(move || {
                let mut local = Vec::new();
                for _ in 0..100 {
                    local.push(a.next().unwrap().raw());
                }
                local
            }));
        }
        let mut all = Vec::new();
        for h in handles {
            all.extend(h.join().unwrap());
        }
        let unique: std::collections::HashSet<u32> = all.iter().copied().collect();
        assert_eq!(unique.len(), all.len(), "no duplicates across threads");
        for id in &all {
            assert_eq!(id % 2, 0, "all initiator IDs even");
        }
    }
}
