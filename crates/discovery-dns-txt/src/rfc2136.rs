//! Publishing announcements into a DNS zone with RFC 2136 dynamic UPDATE.
//!
//! # Why this exists
//!
//! A Mirage announcement expires every discovery epoch (1 h). The DNS TXT
//! channel could always be READ, but [`crate::DnsTxtChannel::publish`] refuses -
//! pushing records needs authority over the zone, which a resolver does not
//! have. That left DNS as a channel an operator could only maintain by hand,
//! hourly, which is to say not at all: in practice it degraded to a static
//! anchor while the other channels rotated.
//!
//! # Why RFC 2136 rather than a provider API
//!
//! One protocol against every compliant server (BIND, Knot, PowerDNS, deSEC,
//! and anything else speaking it) instead of one bespoke HTTP client per DNS
//! provider. Provider APIs rot - they change auth, pagination and record
//! semantics on their own schedule - and each one is a dependency that fails
//! silently at 3am. This is the same reasoning that keeps yt-dlp out of the
//! cover recorder: prefer the stable protocol over the convenient integration.
//!
//! # What it writes
//!
//! ONE TXT record whose character-strings are the ordered base64 chunks from
//! [`crate::chunk::blob_to_chunks`]. That layout is not a choice - it is what
//! the fetcher reads: `HickoryDnsTxtResolver` groups `txt_data()` **per record**,
//! and each record is reassembled independently. Splitting the chunks across
//! several TXT records would produce several announcements each of which fails
//! to decode, because RR order within an RRset is not preserved by DNS while
//! character-string order within one RR is.
//!
//! The update is a replace: delete the RRset at the name, then add the new
//! record, in a single message so a reader never observes a half-written state.
//!
//! # Threat-model placement
//!
//! Holds a TSIG key with write authority over one zone. That is strictly less
//! dangerous than the operator Ed25519 key - a TSIG compromise lets an attacker
//! write records, but announcements are still operator-signed, so a forged TXT
//! record fails signature verification at every client. It is not nothing: an
//! attacker can DELETE the records and take the channel offline.

use std::net::SocketAddr;
use std::time::Duration;

use async_trait::async_trait;
use hickory_proto::op::{Message, MessageFinalizer, MessageType, OpCode, Query, UpdateMessage};
use hickory_proto::rr::dnssec::tsig::TSigner;
use hickory_proto::rr::rdata::{NULL, TXT};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use mirage_discovery::channel::{ChannelError, DiscoveryChannel};
use mirage_discovery::derive::INFO_HASH_LEN;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::channel::info_hash_to_label;
use crate::chunk::blob_to_chunks;

/// TSIG algorithms an operator may name. Re-exported so callers need not depend
/// on `hickory-proto` directly.
pub use hickory_proto::rr::dnssec::rdata::tsig::TsigAlgorithm;

/// How long to wait for the authoritative server to answer an UPDATE.
const UPDATE_TIMEOUT: Duration = Duration::from_secs(10);

/// Largest DNS response worth reading. An UPDATE reply is a header plus echoed
/// sections; anything approaching this is a server misbehaving.
const MAX_RESPONSE_LEN: usize = 8192;

/// Clock skew tolerated by the TSIG signature, in seconds. RFC 8945's usual
/// default. Publishing is epoch-aligned, so a host outside this window is
/// already producing announcements for the wrong epoch.
const TSIG_FUDGE: u16 = 300;

/// Errors from a dynamic-update publish.
#[derive(Debug, thiserror::Error)]
pub enum Rfc2136Error {
    /// The zone, apex or key name was not a valid DNS name.
    #[error("bad DNS name: {0}")]
    Name(String),
    /// The announcement could not be chunked into TXT strings.
    #[error("chunk: {0}")]
    Chunk(#[from] crate::chunk::ChunkError),
    /// Building or signing the UPDATE message failed.
    #[error("protocol: {0}")]
    Proto(String),
    /// Talking to the authoritative server failed.
    #[error("transport: {0}")]
    Io(String),
    /// The server answered, and refused.
    #[error("server rejected the update: {0}")]
    Refused(String),
}

impl From<Rfc2136Error> for ChannelError {
    fn from(e: Rfc2136Error) -> Self {
        match e {
            Rfc2136Error::Name(_) | Rfc2136Error::Chunk(_) => ChannelError::Invalid("dns update"),
            _ => ChannelError::Transport(e.to_string()),
        }
    }
}

/// Publishes Mirage announcements into a zone over RFC 2136.
pub struct Rfc2136Publisher {
    /// Authoritative server that accepts the UPDATE.
    server: SocketAddr,
    /// Zone being updated, e.g. `example.org.`
    zone: Name,
    /// Apex the record names hang from. Usually the zone, but a delegated
    /// subdomain (`d.example.org` inside zone `example.org`) is common and is
    /// why this is separate.
    apex: String,
    /// TTL for the published record. Short, because the announcement is only
    /// valid for its epoch anyway, and a long TTL would serve a stale one past
    /// the boundary.
    ttl: u32,
    signer: TSigner,
}

impl Rfc2136Publisher {
    /// Build a publisher.
    ///
    /// `key` is the raw TSIG secret (the decoded bytes of the base64 in a
    /// `key { secret ... }` stanza), NOT the base64 text.
    ///
    /// # Errors
    /// If `zone`, `apex` or `key_name` is not a valid DNS name, or the algorithm
    /// is unsupported by the build.
    pub fn new(
        server: SocketAddr,
        zone: &str,
        apex: &str,
        key_name: &str,
        key: Vec<u8>,
        algorithm: TsigAlgorithm,
        ttl: u32,
    ) -> Result<Self, Rfc2136Error> {
        let zone =
            Name::from_utf8(zone).map_err(|e| Rfc2136Error::Name(format!("zone {zone}: {e}")))?;
        let key_name = Name::from_utf8(key_name)
            .map_err(|e| Rfc2136Error::Name(format!("key {key_name}: {e}")))?;
        let signer = TSigner::new(key, algorithm, key_name, TSIG_FUDGE)
            .map_err(|e| Rfc2136Error::Proto(e.to_string()))?;
        Ok(Self {
            server,
            zone,
            apex: apex.trim_end_matches('.').to_string(),
            ttl,
            signer,
        })
    }

    /// The record name for an info-hash - byte-identical to what
    /// [`crate::DnsTxtChannel`] queries, or the publish lands where nobody looks.
    fn record_name(&self, info_hash: &[u8; INFO_HASH_LEN]) -> Result<Name, Rfc2136Error> {
        let n = format!("{}.{}.", info_hash_to_label(info_hash), self.apex);
        Name::from_utf8(&n).map_err(|e| Rfc2136Error::Name(format!("{n}: {e}")))
    }

    /// Build the replace-in-one-message UPDATE.
    fn build_update(&self, name: &Name, chunks: Vec<String>) -> Result<Message, Rfc2136Error> {
        // The zone goes in the query section, per RFC 2136 s2.3.
        let mut zone = Query::new();
        zone.set_name(self.zone.clone())
            .set_query_class(DNSClass::IN)
            .set_query_type(RecordType::SOA);

        let mut msg = Message::new();
        msg.set_id(rand_u16())
            .set_message_type(MessageType::Query)
            .set_op_code(OpCode::Update)
            .set_recursion_desired(false);
        msg.add_zone(zone);

        // Delete whatever TXT RRset is there: class ANY, TTL 0, NULL rdata.
        // Without this a republish APPENDS, and the name accumulates one stale
        // announcement per epoch until the response stops fitting in a packet.
        let mut del = Record::with(name.clone(), RecordType::TXT, 0);
        del.set_dns_class(DNSClass::ANY);
        del.set_data(Some(RData::NULL(NULL::new())));
        msg.add_update(del);

        // Add the new record: ONE TXT RR carrying every chunk as an ordered
        // character-string. See the module note on why this is not several RRs.
        let mut add = Record::with(name.clone(), RecordType::TXT, self.ttl);
        add.set_dns_class(DNSClass::IN);
        add.set_data(Some(RData::TXT(TXT::new(chunks))));
        msg.add_update(add);

        Ok(msg)
    }

    /// Sign, send over TCP, and check the response code.
    ///
    /// TCP rather than UDP: a full announcement is several hundred base64 bytes
    /// plus a TSIG record, which does not reliably fit a 512-byte UDP datagram,
    /// and a truncated UPDATE is silently not applied.
    async fn send(&self, mut msg: Message) -> Result<(), Rfc2136Error> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let (tsig, _verifier) = self
            .signer
            .finalize_message(&msg, now as u32)
            .map_err(|e| Rfc2136Error::Proto(format!("tsig: {e}")))?;
        for r in tsig {
            msg.add_additional(r);
        }
        let bytes = msg
            .to_bytes()
            .map_err(|e| Rfc2136Error::Proto(format!("encode: {e}")))?;
        if bytes.len() > u16::MAX as usize {
            return Err(Rfc2136Error::Proto("update larger than 65535 bytes".into()));
        }

        let io = async {
            let mut sock = TcpStream::connect(self.server).await?;
            // RFC 1035 s4.2.2: DNS over TCP is length-prefixed.
            let len = u16::try_from(bytes.len()).unwrap_or(u16::MAX);
            sock.write_all(&len.to_be_bytes()).await?;
            sock.write_all(&bytes).await?;
            sock.flush().await?;

            let mut lenbuf = [0u8; 2];
            sock.read_exact(&mut lenbuf).await?;
            let rlen = usize::from(u16::from_be_bytes(lenbuf)).min(MAX_RESPONSE_LEN);
            let mut resp = vec![0u8; rlen];
            sock.read_exact(&mut resp).await?;
            Ok::<Vec<u8>, std::io::Error>(resp)
        };

        let resp = tokio::time::timeout(UPDATE_TIMEOUT, io)
            .await
            .map_err(|_| Rfc2136Error::Io("update timed out".into()))?
            .map_err(|e| Rfc2136Error::Io(e.to_string()))?;

        let reply = Message::from_bytes(&resp)
            .map_err(|e| Rfc2136Error::Proto(format!("decode reply: {e}")))?;
        let code = reply.response_code();
        if code != hickory_proto::op::ResponseCode::NoError {
            // NOTAUTH almost always means the TSIG key is wrong or the server
            // does not consider itself authoritative for the zone; REFUSED means
            // the update policy rejected it. Both are configuration, not bugs,
            // so say which came back rather than a generic failure.
            return Err(Rfc2136Error::Refused(format!("{code}")));
        }
        Ok(())
    }
}

/// A message ID that does not depend on the `rand` crate's presence here.
fn rand_u16() -> u16 {
    let mut b = [0u8; 2];
    getrandom::fill(&mut b).unwrap_or(());
    u16::from_le_bytes(b)
}

#[async_trait]
impl DiscoveryChannel for Rfc2136Publisher {
    fn name(&self) -> &'static str {
        "dns-rfc2136"
    }

    async fn publish(
        &self,
        info_hash: &[u8; INFO_HASH_LEN],
        ciphertext: &[u8],
    ) -> Result<(), ChannelError> {
        let chunks = blob_to_chunks(ciphertext).map_err(Rfc2136Error::from)?;
        let name = self.record_name(info_hash)?;
        let msg = self.build_update(&name, chunks)?;
        self.send(msg).await?;
        Ok(())
    }

    async fn fetch(&self, _info_hash: &[u8; INFO_HASH_LEN]) -> Result<Vec<Vec<u8>>, ChannelError> {
        // Deliberately not implemented: reading is the client's job and goes
        // through a recursive resolver (`DnsTxtChannel`), which is a different
        // trust path from an authenticated write to an authoritative server.
        Err(ChannelError::Invalid(
            "Rfc2136Publisher writes only - fetch via DnsTxtChannel",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn publisher() -> Rfc2136Publisher {
        Rfc2136Publisher::new(
            "127.0.0.1:53".parse().expect("addr"),
            "example.org.",
            "d.example.org",
            "mirage-key.",
            vec![0x42; 32],
            TsigAlgorithm::HmacSha256,
            60,
        )
        .expect("publisher")
    }

    #[test]
    fn the_published_name_matches_what_the_fetcher_queries() {
        // If these ever diverge the publish "succeeds" and no client ever looks
        // at the record, which is the worst possible failure: silent.
        let ih = [7u8; INFO_HASH_LEN];
        let p = publisher();
        let published = p.record_name(&ih).expect("name");
        let queried = format!("{}.d.example.org", info_hash_to_label(&ih));
        assert_eq!(
            published.to_utf8().trim_end_matches('.'),
            queried,
            "publisher and fetcher disagree about where the record lives"
        );
    }

    #[test]
    fn the_update_replaces_rather_than_appends() {
        // Two updates in one message: delete the RRset, then add. Without the
        // delete, a republish every epoch appends, and the name accumulates
        // stale announcements until the answer no longer fits.
        let p = publisher();
        let name = p.record_name(&[1u8; INFO_HASH_LEN]).expect("name");
        let msg = p
            .build_update(&name, vec!["abc".to_string(), "def".to_string()])
            .expect("update");

        assert_eq!(msg.op_code(), OpCode::Update);
        assert_eq!(
            msg.zones().len(),
            1,
            "RFC 2136 puts the zone in the query section"
        );
        assert_eq!(msg.zones()[0].name(), &p.zone);

        let ups = msg.updates();
        assert_eq!(ups.len(), 2, "expected delete + add, got {ups:?}");
        assert_eq!(
            ups[0].dns_class(),
            DNSClass::ANY,
            "delete-RRset uses class ANY"
        );
        assert_eq!(ups[0].ttl(), 0, "delete-RRset uses TTL 0");
        assert_eq!(ups[1].dns_class(), DNSClass::IN);
        assert_eq!(ups[1].ttl(), 60);
    }

    #[test]
    fn every_chunk_rides_one_txt_record_in_order() {
        // The fetcher groups txt_data() PER RECORD and reassembles each record
        // independently, and RR order within an RRset is not preserved by DNS
        // while character-string order within one RR is. So splitting the chunks
        // across records would yield several announcements that each fail to
        // decode.
        let p = publisher();
        let name = p.record_name(&[2u8; INFO_HASH_LEN]).expect("name");
        let chunks: Vec<String> = (0..5).map(|i| format!("chunk{i}")).collect();
        let msg = p.build_update(&name, chunks.clone()).expect("update");
        let add = &msg.updates()[1];
        let Some(RData::TXT(txt)) = add.data() else {
            panic!("expected a TXT record, got {:?}", add.data());
        };
        let got: Vec<String> = txt
            .iter()
            .map(|b| String::from_utf8_lossy(b).into_owned())
            .collect();
        assert_eq!(got, chunks, "chunk order must survive into the record");
    }

    #[test]
    fn what_the_publisher_writes_is_what_the_fetcher_reassembles() {
        // The end-to-end data contract, closed without a server: take the record
        // this publisher would put in the zone, pull its character-strings back
        // out the way `HickoryDnsTxtResolver` does (per record, in order), and
        // reassemble with the fetcher's own decoder. If the chunking, the
        // ordering or the one-record-per-announcement rule is ever wrong, this
        // fails here instead of as an empty discovery result in the field.
        let p = publisher();
        let name = p.record_name(&[9u8; INFO_HASH_LEN]).expect("name");
        // Long enough to span several 255-byte TXT strings.
        let announcement: Vec<u8> = (0..1500u16).map(|i| (i % 251) as u8).collect();

        let chunks = blob_to_chunks(&announcement).expect("chunk");
        assert!(chunks.len() > 1, "test needs a multi-chunk announcement");
        let msg = p.build_update(&name, chunks).expect("update");

        let Some(RData::TXT(txt)) = msg.updates()[1].data() else {
            panic!("expected TXT rdata");
        };
        let as_fetched: Vec<String> = txt
            .iter()
            .map(|b| String::from_utf8_lossy(b).into_owned())
            .collect();
        let round_tripped = crate::chunk::chunks_to_blob(&as_fetched).expect("reassemble");
        assert_eq!(
            round_tripped, announcement,
            "the fetcher cannot reconstruct what the publisher wrote"
        );
    }

    #[tokio::test]
    async fn an_empty_announcement_is_refused_before_it_reaches_the_network() {
        // blob_to_chunks rejects an empty blob; make sure that surfaces as a
        // clean error rather than an UPDATE that writes nothing.
        let p = publisher();
        let err = p.publish(&[3u8; INFO_HASH_LEN], &[]).await.unwrap_err();
        assert!(
            matches!(err, ChannelError::Invalid(_)),
            "expected a validation error, got {err:?}"
        );
    }
}
