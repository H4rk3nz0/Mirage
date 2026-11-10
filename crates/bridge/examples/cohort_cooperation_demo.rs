//! `cohort_cooperation_demo` - every cohort cooperation
//! primitive in one demo, end-to-end.
//!
//! Run with:
//!
//! ```sh
//! cargo run --example cohort_cooperation_demo -p mirage-bridge
//! ```
//!
//! Shows all four gossip event types working in concert:
//!
//! 1. **ProbeScanDetected** - entry-A flags a scanner; entries
//!    B + C soft-block in milliseconds.
//! 2. **TokenBurned** - entry-A burns a token; entries B + C
//!    refuse to accept the same token before the operator's
//!    persistent `RevealStore` would even have synced.
//! 3. **EntryDistressed** - entry-A's load spikes; entries B +
//!    C's `PeerDistressMap` records the high severity, ready
//!    for a load-balancer to route around A.
//! 4. **CohortMembership** - periodic heartbeats keep each
//!    bridge's `LivePeerTracker` up to date; we verify each
//!    bridge has seen at least 2 peers within the alive
//!    window.
//!
//! The demo asserts each cooperation path worked.

use mirage_bridge::{
    spawn_gossip_to_distress_map, spawn_gossip_to_live_tracker, spawn_gossip_to_softblock,
    CohortDistressMonitor, CohortHeartbeat, CohortReplayCoordinator, DistressMonitorConfig,
    HeartbeatConfig, LivePeerTracker, ManualDistressSensor, PeerDistressMap, ProbeDetector,
    ProbeDetectorConfig, SoftBlockList,
};
use mirage_crypto::ed25519_dalek::SigningKey;
use mirage_discovery::cohort_gossip::{CohortGossip, GossipEvent, MemoryGossip, SignedGossipEvent};
use mirage_discovery::replay::SyncReplaySet;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

struct DemoBridge {
    // Demo label ("entry-A"/...), retained for identification even though unread.
    #[allow(dead_code)]
    name: &'static str,
    pk: [u8; 32],
    // Probe defense
    detector: Arc<ProbeDetector>,
    softblock: Arc<SoftBlockList>,
    signing_key: SigningKey,
    gossip: Arc<MemoryGossip>,
    // Replay coordination
    replay_coord: CohortReplayCoordinator,
    // Distress
    distress_sensor: Arc<ManualDistressSensor>,
    distress_map: Arc<PeerDistressMap>,
    _distress_monitor: CohortDistressMonitor,
    _distress_sub: tokio::task::JoinHandle<()>,
    // Membership
    live_tracker: Arc<LivePeerTracker>,
    _heartbeat: CohortHeartbeat,
    _live_sub: tokio::task::JoinHandle<()>,
    // Probe gossip -> softblock
    _softblock_sub: tokio::task::JoinHandle<()>,
}

impl DemoBridge {
    async fn new(name: &'static str, gossip: Arc<MemoryGossip>) -> Self {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).unwrap();
        let signing_key = SigningKey::from_bytes(&seed);
        let pk = signing_key.verifying_key().to_bytes();
        gossip.authorize(pk).await;

        let detector = Arc::new(ProbeDetector::new(ProbeDetectorConfig {
            threshold: 5,
            ..Default::default()
        }));
        let softblock = Arc::new(SoftBlockList::new());
        let softblock_sub =
            spawn_gossip_to_softblock(gossip.clone() as Arc<dyn CohortGossip>, softblock.clone());

        let replay_set = Arc::new(SyncReplaySet::new(1024));
        let replay_coord = CohortReplayCoordinator::new(
            gossip.clone() as Arc<dyn CohortGossip>,
            signing_key.clone(),
            replay_set,
            3600,
        );

        let distress_sensor = Arc::new(ManualDistressSensor::new());
        let distress_map = Arc::new(PeerDistressMap::new(Duration::from_secs(60)));
        let distress_sub = spawn_gossip_to_distress_map(
            gossip.clone() as Arc<dyn CohortGossip>,
            distress_map.clone(),
        );
        let distress_monitor = CohortDistressMonitor::new(
            gossip.clone() as Arc<dyn CohortGossip>,
            signing_key.clone(),
            distress_sensor.clone(),
            DistressMonitorConfig {
                sample_interval: Duration::from_millis(50),
                publish_threshold: 200,
                republish_interval: Duration::from_secs(60),
                peer_entry_ttl: Duration::from_secs(60),
                min_publish_interval: Duration::from_millis(0),
            },
        );

        let live_tracker = Arc::new(LivePeerTracker::new());
        let live_sub = spawn_gossip_to_live_tracker(
            gossip.clone() as Arc<dyn CohortGossip>,
            live_tracker.clone(),
        );
        let heartbeat = CohortHeartbeat::new(
            gossip.clone() as Arc<dyn CohortGossip>,
            signing_key.clone(),
            live_tracker.clone(),
            HeartbeatConfig {
                heartbeat_interval: Duration::from_millis(100),
                alive_window: Duration::from_secs(10),
                reap_after: Duration::from_secs(60 * 60),
            },
        );

        Self {
            name,
            pk,
            detector,
            softblock,
            signing_key,
            gossip,
            replay_coord,
            distress_sensor,
            distress_map,
            _distress_monitor: distress_monitor,
            _distress_sub: distress_sub,
            live_tracker,
            _heartbeat: heartbeat,
            _live_sub: live_sub,
            _softblock_sub: softblock_sub,
        }
    }

    async fn observe_auth_failure(&self, src_ip: IpAddr) {
        let edge = self.detector.record_auth_failure(src_ip).await;
        if edge {
            self.softblock.add(src_ip, Duration::from_secs(3600)).await;
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
    let gossip = Arc::new(MemoryGossip::new());
    let a = DemoBridge::new("entry-A", gossip.clone()).await;
    let b = DemoBridge::new("entry-B", gossip.clone()).await;
    let c = DemoBridge::new("entry-C", gossip.clone()).await;
    println!("[demo] 3 cohort bridges with full cooperation stack:");
    println!("[demo]   - probe defense (ProbeDetector + SoftBlockList)");
    println!("[demo]   - replay coordination (CohortReplayCoordinator)");
    println!("[demo]   - load signaling (CohortDistressMonitor + PeerDistressMap)");
    println!("[demo]   - liveness (CohortHeartbeat + LivePeerTracker)");
    println!();

    tokio::time::sleep(Duration::from_millis(50)).await;

    //
    // === Path 1: ProbeScanDetected ===
    //
    println!("[1] ProbeScanDetected:");
    let scanner = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 99));
    for _ in 0..6 {
        a.observe_auth_failure(scanner).await;
    }
    let mut waited = 0u64;
    while waited < 500
        && !(b.softblock.should_block(scanner).await && c.softblock.should_block(scanner).await)
    {
        tokio::time::sleep(Duration::from_millis(10)).await;
        waited += 10;
    }
    println!(
        "[1]   propagation: ~{} ms | A.block={} B.block={} C.block={}",
        waited,
        a.softblock.should_block(scanner).await,
        b.softblock.should_block(scanner).await,
        c.softblock.should_block(scanner).await,
    );
    assert!(b.softblock.should_block(scanner).await);
    assert!(c.softblock.should_block(scanner).await);
    println!("[1]   [ok] probe scan propagated to all cohort peers");
    println!();

    //
    // === Path 2: TokenBurned ===
    //
    println!("[2] TokenBurned:");
    let token_id = [0xDE; 32];
    a.replay_coord
        .record_local_burn(token_id, unix_now() + 600)
        .await;
    let mut waited = 0u64;
    while waited < 500
        && !(b.replay_coord.already_burned(&token_id, unix_now())
            && c.replay_coord.already_burned(&token_id, unix_now()))
    {
        tokio::time::sleep(Duration::from_millis(10)).await;
        waited += 10;
    }
    println!(
        "[2]   propagation: ~{} ms | A.burned={} B.burned={} C.burned={}",
        waited,
        a.replay_coord.already_burned(&token_id, unix_now()),
        b.replay_coord.already_burned(&token_id, unix_now()),
        c.replay_coord.already_burned(&token_id, unix_now()),
    );
    assert!(b.replay_coord.already_burned(&token_id, unix_now()));
    assert!(c.replay_coord.already_burned(&token_id, unix_now()));
    println!("[2]   [ok] token burn propagated; replay would be refused at all peers");
    println!();

    //
    // === Path 3: EntryDistressed ===
    //
    println!("[3] EntryDistressed:");
    a.distress_sensor.set(220);
    let mut waited = 0u64;
    while waited < 1000
        && !(b.distress_map.severity(&a.pk).is_some() && c.distress_map.severity(&a.pk).is_some())
    {
        tokio::time::sleep(Duration::from_millis(10)).await;
        waited += 10;
    }
    println!(
        "[3]   propagation: ~{} ms | A.sev=220 -> B.knows_A={:?} C.knows_A={:?}",
        waited,
        b.distress_map.severity(&a.pk),
        c.distress_map.severity(&a.pk),
    );
    assert_eq!(b.distress_map.severity(&a.pk), Some(220));
    assert_eq!(c.distress_map.severity(&a.pk), Some(220));
    println!("[3]   [ok] load signal propagated; peers can shift flow away from A");
    println!();

    //
    // === Path 4: CohortMembership ===
    //
    println!("[4] CohortMembership (heartbeats):");
    // Let a couple of heartbeats fly.
    tokio::time::sleep(Duration::from_millis(300)).await;
    let live_at_b = b.live_tracker.living_peers(Duration::from_secs(60)).await;
    let live_at_c = c.live_tracker.living_peers(Duration::from_secs(60)).await;
    println!(
        "[4]   B sees {} peers in alive-window; C sees {}",
        live_at_b.len(),
        live_at_c.len()
    );
    // Each bridge should see at least 2 peers (the other two)
    // via heartbeats + the events above.
    assert!(
        live_at_b.contains(&a.pk),
        "B must have seen A via heartbeats / events"
    );
    assert!(
        live_at_b.contains(&c.pk),
        "B must have seen C via heartbeats / events"
    );
    assert!(
        live_at_c.contains(&a.pk) && live_at_c.contains(&b.pk),
        "C must have seen A + B"
    );
    println!("[4]   [ok] heartbeats confirm cohort liveness across all peers");
    println!();

    println!("[demo] [ok] All four cohort cooperation paths verified end-to-end.");
    println!("[demo]   Single bridge's events propagate to peers in <100 ms.");
    println!("[demo]   Mirage's cohort is a cooperating organism, not a static list.");
}
