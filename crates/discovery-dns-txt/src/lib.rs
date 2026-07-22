//! Signed DNS TXT record discovery channel for Mirage.
//!
//! # Why
//!
//! DNS is pervasive infrastructure. A censor blocking DNS entirely
//! disrupts nearly every internet-connected application on the
//! network; blocking "only Mirage's DNS queries" requires deep-
//! inspecting DNS traffic which itself signals the censor's
//! presence. A Mirage client that can fall back to DNS TXT lookups
//! for discovery has a channel of last resort when Nostr, DHT, and
//! other paths are all shuttered.
//!
//! # Status (v0.1p)
//!
//! This crate ships the wire format + chunking primitives + a
//! pluggable resolver trait + an in-memory mock. It does NOT ship
//! actual DNS I/O - a real `hickory-resolver` adapter is the v0.2
//! item when we pick the resolver crate. The architectural
//! surface is the load-bearing piece; dropping in a real resolver
//! is ~50 lines of `impl DnsTxtResolver for ...` once wired.
//!
//! # Wire shape
//!
//! A Mirage discovery blob (sealed announcement, ~800 B) is
//! encoded as one or more TXT record strings under a **Mirage-
//! specific subdomain of an operator-controlled apex**:
//!
//! ```text
//!   <label(info_hash)>.<apex.zone.example.>  IN  TXT "<base64...>"
//!                                                    "<base64...>"
//!                                                    "<base64...>"
//! ```
//!
//! - The leading label is derived from a per-epoch keyed BLAKE3 secret, so the
//!   name is un-enumerable to keyless observers. There is deliberately NO
//!   `_mirage` marker and NO cleartext `mchunk/` tag - either would re-identify
//!   the record; the name is Mirage-exclusive by construction.
//! - One DNS name per `info_hash`; all chunks live in one `RRset`.
//! - Each TXT string is plain standard (padded) base64 - NO schema tag and NO
//!   `<index>/<total>` header (finding #7: claiming a `v=DKIM1` schema at a name
//!   with no `_domainkey` label is a high-precision passive-DNS tell). The whole
//!   sealed blob is base64-encoded once and spilled across <=255 B TXT strings.
//! - At decode, the strings are concatenated in `RRset` order (wire-significant,
//!   preserved by resolvers), base64-decoded, and handed to the seal layer,
//!   which authenticates the reassembled announcement.
//! - Multiple ANNOUNCEMENTS at one `info_hash` are supported via
//!   distinct DNS NAMES: operators publish each announcement under
//!   a unique subdomain (usually salted by bridge identity). For
//!   v0.1p the resolver API returns ALL TXT RRs at a name as one
//!   group; the channel reassembles the single announcement at
//!   that name.
//!
//! # Threat-model notes
//!
//! - **Resolvers are untrusted.** A compromised recursive resolver
//!   can withhold records, inject garbage, or return stale data.
//!   Mirage's existing end-to-end sig + seal checks (operator Ed25519
//!   signature, per-epoch AEAD) protect against all three: injected
//!   garbage fails AEAD, withheld records just look like "no data"
//!   (the [`DiscoveryRouter`] treats as empty, not failure).
//! - **DNS is observable.** The resolver sees the query name. For
//!   Mirage that name encodes the epoch info-hash - a known-to-
//!   everyone-with-the-invite value. A dragnet resolver operator
//!   who also holds the invite can enumerate who queried; one who
//!   doesn't can't decrypt the response. Use `DoH` / `DoT` to hide the
//!   query name from on-path observers.
//! - **Zone updates are out of band.** The operator pushes new TXT
//!   records via whatever zone-authority API their nameserver
//!   exposes (Route 53 API, Cloudflare API, nsupdate, etc.).
//!   Mirage's `OperatorPublisher` won't auto-publish to DNS - an
//!   operator-side glue script reads the published ciphertext and
//!   uploads it. This keeps the daemon free of a DNS authority
//!   dependency.
//!
//! [`DiscoveryRouter`]: mirage_discovery::DiscoveryRouter

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod channel;
pub mod chunk;
pub mod hickory;
pub mod resolver;

pub use channel::{info_hash_to_label, DnsTxtChannel, DnsTxtChannelError, MAX_ANNOUNCEMENT_SIZE};
pub use chunk::{blob_to_chunks, ChunkError};
pub use chunk::{chunks_to_blob, MAX_TXT_STRING_LEN};
pub use hickory::HickoryDnsTxtResolver;
pub use resolver::{DnsTxtResolver, InMemoryDnsTxt, ResolverError};
