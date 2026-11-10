//! `cohort_gossip_demo` - peer-to-peer cooperation between
//! cohort bridges.
//!
//! Run with:
//!
//! ```sh
//! cargo run --example cohort_gossip_demo -p mirage-bridge
//! ```
//!
//! # What this proves
//!
//! Cohort bridges share more than a `RevealStore`: they share
//! live operational signals via a signed peer-to-peer
//! [`mirage_discovery::CohortGossip`] channel. When entry A
//! detects a probe scan, entries B and C soft-block the same
//! source IP within gossip-propagation latency - typically
//! sub-millisecond on a `MemoryGossip` and sub-RTT over any
//! production network transport.
//!
//! Without cooperation, a scanner hammering 3 cohort entries
//! gets 3 independent "first-time-this-IP" responses, each of
//! which leaks the same per-bridge timing signature. WITH
//! cooperation, only the first entry's response leaks - the
//! others have already added the scanner to their
//! [`mirage_bridge::SoftBlockList`].
//!
//! Demo flow:
//!
//! 1. Boot 3 "bridges" (`entry-A`, `entry-B`, `entry-C`). Each
//!    has its own Ed25519 identity key + `ProbeDetector` +
//!    `SoftBlockList`. All 3 share one in-memory `MemoryGossip`.
//! 2. Scanner IP `203.0.113.99` is NOT blocked anywhere.
//! 3. Scanner sends 6 garbage auth attempts at `entry-A`.
//!    `entry-A`'s detector hits the configured threshold of 5
//!    and emits a signed `ProbeScanDetected` event.
//! 4. Within a few milliseconds, `entry-B` and `entry-C` have
//!    the scanner IP in their soft-block lists.
//! 5. Assert all 3 entries block the scanner. Asserts the
//!    cooperation worked end-to-end.

use mirage_bridge::probe_defense::{
    spawn_gossip_to_softblock, ProbeDetector, ProbeDetectorConfig, SoftBlockList,
};
use mirage_crypto::ed25519_dalek::SigningKey;
use mirage_discovery::cohort_gossip::{CohortGossip, GossipEvent, MemoryGossip, SignedGossipEvent};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinHandle;

/// One cohort bridge for the demo. Owns its own probe-detection
/// + soft-block state; shares a `MemoryGossip` with peers.
struct DemoBridge {
    name: &'static str,
    /// Ed25519 identity used to sign outbound gossip events.
    signing_key: SigningKey,
    detector: Arc<ProbeDetector>,
    softblock: Arc<SoftBlockList>,
    gossip: Arc<MemoryGossip>,
    _subscriber: JoinHandle<()>,
}

impl DemoBridge {
    async fn new(name: &'static str, gossip: Arc<MemoryGossip>) -> Self {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).unwrap();
        let signing_key = SigningKey::from_bytes(&seed);
        gossip
            .authorize(signing_key.verifying_key().to_bytes())
            .await;

        let detector = Arc::new(ProbeDetector::new(ProbeDetectorConfig {
            threshold: 5,
            window: Duration::from_secs(60),
            probe_flag_duration: Duration::from_secs(60 * 60),
            ..Default::default()
        }));
        let softblock = Arc::new(SoftBlockList::new());

        let subscriber =
            spawn_gossip_to_softblock(gossip.clone() as Arc<dyn CohortGossip>, softblock.clone());

        Self {
            name,
            signing_key,
            detector,
            softblock,
            gossip,
            _subscriber: subscriber,
        }
    }

    /// Simulate one auth failure (e.g., a malformed msg_1 / bad
    /// token). On the threshold-crossing edge, publish a
    /// signed gossip event so peers can soft-block.
    async fn observe_auth_failure(&self, src_ip: IpAddr) {
        let edge = self.detector.record_auth_failure(src_ip).await;
        if edge {
            println!(
                "[demo] {} flagged {} as a probe -> publishing ProbeScanDetected",
                self.name, src_ip
            );
            let event = GossipEvent::ProbeScanDetected {
                source_ip: src_ip,
                expire_secs: 3600,
                detected_at: unix_now(),
            };
            let signed = SignedGossipEvent::sign(event, &self.signing_key);
            self.gossip.publish(signed).await;
        }
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() {
    println!("[demo] Boot:");
    let gossip = Arc::new(MemoryGossip::new());
    let entry_a = DemoBridge::new("entry-A", gossip.clone()).await;
    let entry_b = DemoBridge::new("entry-B", gossip.clone()).await;
    let entry_c = DemoBridge::new("entry-C", gossip.clone()).await;
    println!("[demo]   3 cohort bridges share one MemoryGossip channel");
    println!();

    // Subscribers may need a moment to be ready before the
    // first publish lands. (Not strictly required - broadcast
    // channels buffer up to capacity - but explicit yields
    // make the demo more deterministic on slow hosts.)
    tokio::time::sleep(Duration::from_millis(20)).await;

    let scanner_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 99));
    println!(
        "[demo] Scanner at {} starts probing entry-A with bad auth attempts.",
        scanner_ip
    );
    println!("[demo] (No bridge has the scanner in its soft-block list yet.)");

    assert!(!entry_a.softblock.should_block(scanner_ip).await);
    assert!(!entry_b.softblock.should_block(scanner_ip).await);
    assert!(!entry_c.softblock.should_block(scanner_ip).await);
    println!(
        "[demo]   entry-A.softblock={} entry-B.softblock={} entry-C.softblock={}",
        entry_a.softblock.should_block(scanner_ip).await,
        entry_b.softblock.should_block(scanner_ip).await,
        entry_c.softblock.should_block(scanner_ip).await,
    );
    println!();

    // Scanner sends 6 garbage probes to entry-A. The 5th
    // crosses the configured threshold and triggers the gossip
    // publish.
    for i in 1..=6 {
        entry_a.observe_auth_failure(scanner_ip).await;
        println!(
            "[demo]   probe {}/6 to entry-A | A.flagged={} | A.softblocks={}",
            i,
            entry_a.detector.is_probe(scanner_ip).await,
            entry_a.softblock.len().await,
        );
    }
    println!();

    // Wait briefly for gossip to propagate through the broadcast
    // channel to entry-B and entry-C subscribers.
    let mut waited_ms = 0u64;
    while waited_ms < 500 {
        if entry_b.softblock.should_block(scanner_ip).await
            && entry_c.softblock.should_block(scanner_ip).await
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
        waited_ms += 10;
    }
    println!("[demo] Gossip propagated to peers after ~{} ms.", waited_ms);

    // Assertions: every cohort entry now soft-blocks the
    // scanner. The scanner gets fast-close from all three even
    // though only entry-A directly observed the probe pattern.
    let blocked_a = entry_a.softblock.should_block(scanner_ip).await;
    let blocked_b = entry_b.softblock.should_block(scanner_ip).await;
    let blocked_c = entry_c.softblock.should_block(scanner_ip).await;
    println!(
        "[demo]   entry-A.softblock={} entry-B.softblock={} entry-C.softblock={}",
        blocked_a, blocked_b, blocked_c
    );
    println!();

    // entry-A also blocks (the gossip event self-loops back via
    // the broadcast channel - its own subscriber picks it up).
    // This is desirable: the local probe-flag and the gossip
    // soft-block expire on independent schedules.
    assert!(blocked_b, "entry-B must soft-block scanner via gossip");
    assert!(blocked_c, "entry-C must soft-block scanner via gossip");

    println!("[demo] [ok] Cohort gossip cooperation demonstrated.");
    println!("[demo]   One bridge's probe detection propagated peer-to-peer");
    println!("[demo]   to every cohort member. A scanner hammering 3 entries");
    println!("[demo]   sequentially can no longer harvest 3 independent");
    println!("[demo]   first-contact responses - entries B and C are");
    println!("[demo]   already in 'fast-close' mode by the time the scanner");
    println!("[demo]   reaches them.");
}
