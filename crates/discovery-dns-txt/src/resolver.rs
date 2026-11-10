//! Pluggable DNS TXT resolver trait + in-memory test mock.
//!
//! A real-world resolver is any crate that can do
//! `resolve(name) -> Vec<Vec<String>>` - inner list is one TXT `RRset`
//! (i.e., all character strings within one record). The trait is
//! intentionally minimal; a `hickory-resolver`-backed impl is
//! ~30 lines and lands in a follow-up iteration.

use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Mutex;

/// Errors surfaced by a [`DnsTxtResolver`] implementation.
#[derive(Debug, thiserror::Error)]
pub enum ResolverError {
    /// Underlying network / system resolver error.
    #[error("transport: {0}")]
    Transport(String),
    /// Name exists but has no TXT records (NODATA).
    /// Distinct from NXDOMAIN so the channel can fan out to a
    /// mirror apex - "no Mirage announcement here" is not an error.
    #[error("no TXT records at {0}")]
    NoRecords(String),
    /// Name does not exist (NXDOMAIN).
    #[error("NXDOMAIN: {0}")]
    NxDomain(String),
    /// Resolution timed out.
    #[error("timeout")]
    Timeout,
}

/// Abstraction over a DNS resolver that can look up TXT records.
///
/// One call to `resolve` returns every TXT RRset at the name.
/// Mirage's channel typically publishes one RRset per name, but
/// the trait preserves multi-RRset semantics so a later multi-
/// operator-at-same-name scheme (v0.2 mesh discovery) can layer on.
///
/// Object-safe via `async_trait` so [`crate::DnsTxtChannel`] can
/// hold an `Arc<dyn DnsTxtResolver>`.
#[async_trait]
pub trait DnsTxtResolver: Send + Sync {
    /// Return every TXT record at `name`. Each inner `Vec<String>`
    /// is one DNS TXT RR (may carry >=1 character string per
    /// RFC 1035 §3.3.14).
    async fn resolve(&self, name: &str) -> Result<Vec<Vec<String>>, ResolverError>;

    /// Diagnostic label.
    fn name(&self) -> &'static str;

    /// Health signal. Default: always up.
    fn is_healthy(&self) -> bool {
        true
    }
}

/// In-memory mock resolver. Tests + integration demos seed data
/// via [`InMemoryDnsTxt::insert`]; the channel under test then
/// calls `resolve` and receives the mock's returns.
///
/// Thread-safe. Intended for tests only; a real deployment uses
/// a `hickory-resolver` adapter.
pub struct InMemoryDnsTxt {
    records: Mutex<HashMap<String, Vec<Vec<String>>>>,
    fail_next: Mutex<Option<ResolverError>>,
}

impl InMemoryDnsTxt {
    /// Construct an empty mock.
    pub fn new() -> Self {
        Self {
            records: Mutex::new(HashMap::new()),
            fail_next: Mutex::new(None),
        }
    }

    /// Publish a TXT `RRset` at `name`.
    pub fn insert(&self, name: &str, rrset: Vec<String>) {
        self.records
            .lock()
            .expect("poisoned")
            .entry(name.to_lowercase())
            .or_default()
            .push(rrset);
    }

    /// Program the mock to return a given error on the next `resolve`.
    /// Used to exercise the channel's failure-handling paths.
    pub fn fail_next_resolve_with(&self, err: ResolverError) {
        *self.fail_next.lock().expect("poisoned") = Some(err);
    }

    /// Clear everything.
    pub fn clear(&self) {
        self.records.lock().expect("poisoned").clear();
        *self.fail_next.lock().expect("poisoned") = None;
    }
}

impl Default for InMemoryDnsTxt {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl DnsTxtResolver for InMemoryDnsTxt {
    async fn resolve(&self, name: &str) -> Result<Vec<Vec<String>>, ResolverError> {
        if let Some(e) = self.fail_next.lock().expect("poisoned").take() {
            return Err(e);
        }
        let map = self.records.lock().expect("poisoned");
        match map.get(&name.to_lowercase()) {
            Some(rrsets) if !rrsets.is_empty() => Ok(rrsets.clone()),
            _ => Err(ResolverError::NoRecords(name.to_string())),
        }
    }

    fn name(&self) -> &'static str {
        "in-memory-dns-txt"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn insert_and_resolve() {
        let dns = InMemoryDnsTxt::new();
        dns.insert("foo.example.", vec!["hello".to_string()]);
        let r = dns.resolve("foo.example.").await.unwrap();
        assert_eq!(r, vec![vec!["hello".to_string()]]);
    }

    #[tokio::test]
    async fn case_insensitive_lookup() {
        let dns = InMemoryDnsTxt::new();
        dns.insert("FOO.example.", vec!["hi".to_string()]);
        let r = dns.resolve("foo.EXAMPLE.").await.unwrap();
        assert_eq!(r, vec![vec!["hi".to_string()]]);
    }

    #[tokio::test]
    async fn unknown_name_returns_norecords() {
        let dns = InMemoryDnsTxt::new();
        let err = dns.resolve("missing.example.").await.unwrap_err();
        assert!(matches!(err, ResolverError::NoRecords(_)));
    }

    #[tokio::test]
    async fn fail_next_consumed_once() {
        let dns = InMemoryDnsTxt::new();
        dns.insert("x.example.", vec!["hi".to_string()]);
        dns.fail_next_resolve_with(ResolverError::Timeout);
        let err = dns.resolve("x.example.").await.unwrap_err();
        assert!(matches!(err, ResolverError::Timeout));
        // Second call - fail-next consumed; real records returned.
        let ok = dns.resolve("x.example.").await.unwrap();
        assert_eq!(ok, vec![vec!["hi".to_string()]]);
    }
}
