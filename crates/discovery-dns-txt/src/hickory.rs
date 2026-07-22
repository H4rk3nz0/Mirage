//! `hickory-resolver`-backed [`DnsTxtResolver`].
//!
//! Gated behind the `hickory` feature. Drop this in wherever the
//! in-memory mock is used in production code - no other changes needed.
//!
//! # Resolver selection
//!
//! [`HickoryDnsTxtResolver::new_system`] reads `/etc/resolv.conf` (Linux/macOS)
//! or the Windows registry, falling back to Google's public resolvers on parse
//! error.
//!
//! [`HickoryDnsTxtResolver::new_with_google`] and
//! [`HickoryDnsTxtResolver::new_with_cloudflare`] use hardcoded well-known
//! resolvers - useful when the system resolver is controlled by the censor.
//!
//! # Threat model notes
//!
//! The resolver is UNTRUSTED (see crate-level docs). Every blob returned
//! by the channel is verified end-to-end (`seal::open` + operator
//! Ed25519 sig) before Mirage trusts it. Use `DoT` or `DoH` for transport
//! privacy when the on-path resolver observer is adversarial.

use async_trait::async_trait;
use hickory_resolver::{
    config::{ResolverConfig, ResolverOpts},
    TokioAsyncResolver,
};
use tracing::debug;

use crate::resolver::{DnsTxtResolver, ResolverError};

/// Real DNS TXT resolver backed by `hickory-resolver`.
///
/// Object-safe; wrap in `Arc<dyn DnsTxtResolver>` when needed.
pub struct HickoryDnsTxtResolver {
    inner: TokioAsyncResolver,
    label: &'static str,
}

impl HickoryDnsTxtResolver {
    /// Construct from an existing `TokioAsyncResolver`.
    pub fn new(inner: TokioAsyncResolver, label: &'static str) -> Self {
        Self { inner, label }
    }

    /// Use the system resolver config (`/etc/resolv.conf` or equivalent).
    /// Falls back to Google's resolvers when system config cannot be read.
    pub fn new_system() -> Self {
        let inner = TokioAsyncResolver::tokio_from_system_conf().unwrap_or_else(|_| {
            TokioAsyncResolver::tokio(ResolverConfig::google(), ResolverOpts::default())
        });
        Self::new(inner, "hickory-system")
    }

    /// Hardcoded Google resolvers (`8.8.8.8`, `8.8.4.4`).
    /// Use when the system resolver is adversarially controlled.
    pub fn new_with_google() -> Self {
        Self::new(
            TokioAsyncResolver::tokio(ResolverConfig::google(), ResolverOpts::default()),
            "hickory-google",
        )
    }

    /// Hardcoded Cloudflare resolvers (`1.1.1.1`, `1.0.0.1`).
    pub fn new_with_cloudflare() -> Self {
        Self::new(
            TokioAsyncResolver::tokio(ResolverConfig::cloudflare(), ResolverOpts::default()),
            "hickory-cloudflare",
        )
    }
}

#[async_trait]
impl DnsTxtResolver for HickoryDnsTxtResolver {
    /// Resolve all TXT records at `name`.
    ///
    /// Return value: `Vec<Vec<String>>` where the outer `Vec` has one entry
    /// per DNS TXT RR, and the inner `Vec<String>` holds all character-string
    /// segments of that record. Non-UTF-8 bytes are lossy-converted (DNS
    /// allows arbitrary bytes in TXT data; Mirage chunks are ASCII+base64).
    async fn resolve(&self, name: &str) -> Result<Vec<Vec<String>>, ResolverError> {
        let lookup = self.inner.txt_lookup(name).await.map_err(|e| {
            use hickory_resolver::error::ResolveErrorKind;
            match e.kind() {
                ResolveErrorKind::NoRecordsFound { .. } => {
                    ResolverError::NoRecords(name.to_string())
                }
                ResolveErrorKind::Timeout => ResolverError::Timeout,
                _ => ResolverError::Transport(e.to_string()),
            }
        })?;

        let rrsets: Vec<Vec<String>> = lookup
            .iter()
            .map(|rec| {
                rec.txt_data()
                    .iter()
                    .map(|seg| String::from_utf8_lossy(seg).into_owned())
                    .collect()
            })
            .collect();

        debug!(
            target: "mirage_discovery_dns_txt",
            name = %name,
            rrsets = rrsets.len(),
            "resolved TXT"
        );

        if rrsets.is_empty() {
            return Err(ResolverError::NoRecords(name.to_string()));
        }
        Ok(rrsets)
    }

    fn name(&self) -> &'static str {
        self.label
    }

    fn is_healthy(&self) -> bool {
        true
    }
}
