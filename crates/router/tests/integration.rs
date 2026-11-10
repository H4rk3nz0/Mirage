//! End-to-end integration tests for the v0.2 router + circuit stack.
//!
//! These tests exercise the public APIs of `mirage-router` and
//! `mirage-circuit::builder` composed as the Phase 2 wiring code
//! WILL compose them. The tests don't do any I/O - they simulate
//! the runtime's role with deterministic synthetic completions -
//! but they validate that the state machines click together
//! correctly:
//!
//! 1. **`web_request_full_pipeline`** - a single web request flows
//!    Classifier -> Pool -> Selector -> `CircuitBuilder` -> completed
//!    Circuit, exercising the entire happy path.
//! 2. **`realtime_isolation_from_web`** - concurrent web + realtime
//!    requests use independent pools, profiles, and selections.
//! 3. **`cold_start_storm`** - 100 streams arriving simultaneously
//!    cold de-dup to a small number of builds via the Pending
//!    semantic, then activate together on `record_built`.
//! 4. **`hostile_operator_resilience`** - even with a bridge
//!    catalogue dominated by one operator, no circuit lands more
//!    than 1 of that operator's bridges as hops.
//! 5. **`build_failure_recovery`** - a failing dial cycles cleanly
//!    through the pool's `record_build_failure` path with no leaked
//!    state.

use mirage_circuit::{derive_hop_keys, BuildStep, CircuitBuilder, HopEndpoint, HopSpec};
use mirage_router::{
    AcquireOutcome, BridgeCandidate, CircuitPool, Class, ClassHint, Classifier, HopSelector,
    PoolAction, PoolPolicy, Protocol,
};
use std::time::Instant;

// Synthetic catalogue helpers

/// Realistic catalogue: 12 bridges, 6 distinct operators, mix of
/// transport capabilities, distinct /24s.
fn synthetic_catalogue() -> Vec<BridgeCandidate> {
    vec![
        // Operator 1 - Reality + obfs (general purpose)
        bridge(0x01, 1, &[10, 0, 1, 1], &["reality-v2", "obfs-tcp"]),
        bridge(0x02, 1, &[10, 0, 2, 1], &["reality-v2"]),
        // Operator 2 - MASQUE (CDN-fronted for realtime)
        bridge(0x03, 2, &[10, 0, 3, 1], &["quic-masque", "reality-v2"]),
        bridge(0x04, 2, &[10, 0, 4, 1], &["quic-masque"]),
        // Operator 3 - WebRTC (P2P-style for realtime)
        bridge(0x05, 3, &[10, 0, 5, 1], &["webrtc"]),
        bridge(0x06, 3, &[10, 0, 6, 1], &["webrtc", "obfs-tcp"]),
        // Operator 4 - obfs only (TCP test-bed)
        bridge(0x07, 4, &[10, 0, 7, 1], &["obfs-tcp"]),
        bridge(0x08, 4, &[10, 0, 8, 1], &["obfs-tcp"]),
        // Operator 5 - full mix
        bridge(
            0x09,
            5,
            &[10, 0, 9, 1],
            &["reality-v2", "obfs-tcp", "quic-masque"],
        ),
        bridge(0x0A, 5, &[10, 0, 10, 1], &["reality-v2", "quic-masque"]),
        // Operator 6 - full mix
        bridge(0x0B, 6, &[10, 0, 11, 1], &["reality-v2", "obfs-tcp"]),
        bridge(0x0C, 6, &[10, 0, 12, 1], &["webrtc", "quic-masque"]),
    ]
}

fn bridge(pk_tag: u8, op: u8, addr: &[u8; 4], transports: &[&'static str]) -> BridgeCandidate {
    BridgeCandidate {
        static_pk: [pk_tag; 32],
        endpoint: HopEndpoint::Ipv4 {
            addr: *addr,
            port: 4433,
        },
        operator_id: [op; 16],
        transports: transports.to_vec(),
        last_seen: None,
    }
}

/// Synthetic per-hop completion: produces deterministic `HopKeys`
/// from the hop's `static_pk` so the same builder run yields the
/// same circuit. In real wiring this is the output of
/// `derive_hop_keys` from the per-hop session handshake.
fn synthetic_hop_keys(spec: &HopSpec, hop_idx: usize) -> mirage_circuit::HopKeys {
    let mut i2r = [0u8; 32];
    i2r.copy_from_slice(&spec.static_pk);
    i2r[0] ^= hop_idx as u8;
    let mut r2i = i2r;
    r2i[31] ^= 0xAA;
    derive_hop_keys(&i2r, &r2i)
}

/// Drive a `CircuitBuilder` to completion using synthetic per-hop
/// completions. Mimics what the Phase 2 async runtime will do -
/// minus the actual transport dial / Mirage handshake.
fn drive_builder_to_ready(builder: &mut CircuitBuilder) -> Result<(), String> {
    loop {
        match builder.next_step() {
            BuildStep::Ready => return Ok(()),
            BuildStep::Failed { hop_idx, error } => {
                return Err(format!("build failed at hop {hop_idx}: {error}"));
            }
            BuildStep::DialHop0 { spec } => {
                let keys = synthetic_hop_keys(&spec, 0);
                builder
                    .record_hop_built(0, keys)
                    .map_err(|e| e.to_string())?;
            }
            BuildStep::Extend { hop_idx, spec, .. } => {
                let keys = synthetic_hop_keys(&spec, hop_idx);
                builder
                    .record_hop_built(hop_idx, keys)
                    .map_err(|e| e.to_string())?;
            }
        }
    }
}

// Tests

/// **Scenario 1 - full happy path.**
///
/// A user opens <https://example.com>. Classifier sees TCP/443 ->
/// Interactive. Pool has nothing hot. Selector picks 3 hops from
/// the catalogue (matching `profile.transport_bias` and
/// anti-affinity). Builder progresses through `DialHop0` -> Extend
/// -> Ready. Pool records the built circuit. Stream gets activated.
///
/// This is THE end-to-end happy path that Phase 2's async runtime
/// will trace.
#[test]
fn web_request_full_pipeline() {
    let now = Instant::now();
    let salt = [0x42u8; 16];
    let catalogue = synthetic_catalogue();

    // 1. Ingress: SOCKS5 CONNECT example.com:443.
    let classifier = Classifier::standard();
    let class = classifier.classify(Protocol::Tcp, 443, false, None);
    assert_eq!(class, Class::Interactive);

    // 2. Pool acquire.
    let mut pool = CircuitPool::<u64>::new(PoolPolicy::default());
    pool.set_jitter_picker(mirage_router::pool::zero_jitter);
    let outcome = pool
        .acquire_for_domain(class, "example.com", &salt, now)
        .unwrap();
    let profile = match outcome {
        AcquireOutcome::BuildFirst { profile } => profile,
        other => panic!("expected BuildFirst on cold pool, got {other:?}"),
    };
    assert_eq!(profile.class, Class::Interactive);
    assert_eq!(profile.hop_count, 3);

    // 3. Hop selection.
    let selector = HopSelector::new(salt);
    let hops = selector.select(&profile, &catalogue).unwrap();
    assert_eq!(hops.len(), 3);

    // 4. Circuit build.
    let mut builder = CircuitBuilder::new(hops).unwrap();
    drive_builder_to_ready(&mut builder).unwrap();
    assert!(builder.is_ready());
    let circuit = builder.into_circuit().unwrap();
    assert_eq!(circuit.hop_count(), 3);

    // 5. Pool records built circuit.
    let activated = pool.record_built(7u64, class, now).unwrap();
    assert_eq!(activated, 1, "the originating stream is activated");
    assert_eq!(pool.stream_count(7), Some(1));
    assert_eq!(pool.healthy_count(class), 1);
    assert_eq!(pool.class_of(7), Some(class));
}

/// **Scenario 2 - realtime + web run independent pools.**
///
/// Opening a video call doesn't disturb the web-browsing pool, and
/// vice versa. Profiles, selections, and circuit ids are all
/// distinct.
#[test]
fn realtime_isolation_from_web() {
    let now = Instant::now();
    let salt = [0x42u8; 16];
    let catalogue = synthetic_catalogue();
    let mut pool = CircuitPool::<u64>::new(PoolPolicy::default());
    pool.set_jitter_picker(mirage_router::pool::zero_jitter);
    let selector = HopSelector::new(salt);

    // Web stream.
    let web_class = Classifier::standard().classify_tcp(443);
    let web_outcome = pool.acquire(web_class, now).unwrap();
    let web_profile = match web_outcome {
        AcquireOutcome::BuildFirst { profile } => profile,
        _ => panic!("expected BuildFirst"),
    };
    let web_hops = selector.select(&web_profile, &catalogue).unwrap();
    let mut web_builder = CircuitBuilder::new(web_hops).unwrap();
    drive_builder_to_ready(&mut web_builder).unwrap();
    pool.record_built(101u64, web_class, now).unwrap();

    // Realtime stream (with explicit hint).
    let rt_class =
        Classifier::standard().classify(Protocol::Udp, 50000, false, Some(ClassHint::Realtime));
    assert_eq!(rt_class, Class::Realtime);
    let rt_outcome = pool.acquire(rt_class, now).unwrap();
    let rt_profile = match rt_outcome {
        AcquireOutcome::BuildFirst { profile } => profile,
        _ => panic!("expected BuildFirst for realtime"),
    };
    assert_eq!(rt_profile.hop_count, 2);
    assert!(
        rt_profile.is_anonymity_downgrade(),
        "Realtime is the explicit anonymity downgrade"
    );
    assert!(!rt_profile.transport_bias.allow_fallback);

    let rt_hops = selector.select(&rt_profile, &catalogue).unwrap();
    assert_eq!(rt_hops.len(), 2);
    let mut rt_builder = CircuitBuilder::new(rt_hops).unwrap();
    drive_builder_to_ready(&mut rt_builder).unwrap();
    pool.record_built(202u64, rt_class, now).unwrap();

    // Both pools healthy and isolated.
    assert_eq!(pool.healthy_count(Class::Interactive), 1);
    assert_eq!(pool.healthy_count(Class::Realtime), 1);
    assert_eq!(pool.class_of(101), Some(Class::Interactive));
    assert_eq!(pool.class_of(202), Some(Class::Realtime));
}

/// **Scenario 3 - cold-start storm de-dup.**
///
/// 100 streams arrive simultaneously. Pool's Pending de-dup
/// prevents 100 simultaneous builds. After a small number of
/// builds complete, all queued streams activate.
#[test]
fn cold_start_storm() {
    let now = Instant::now();
    let mut pool = CircuitPool::<u64>::new(PoolPolicy::default());
    pool.set_jitter_picker(mirage_router::pool::zero_jitter);

    let mut build_first = 0;
    let mut pending = 0;
    let mut ready = 0;
    for _ in 0..100 {
        match pool.acquire(Class::Interactive, now).unwrap() {
            AcquireOutcome::BuildFirst { .. } => build_first += 1,
            AcquireOutcome::Pending => pending += 1,
            AcquireOutcome::Ready { .. } => ready += 1,
        }
    }
    // No circuit was ever built -> no Ready.
    assert_eq!(ready, 0);
    // First Building entry serves up to max_streams=64 streams; a
    // second BuildFirst then opens a new Building entry to absorb
    // the remaining 36. So we expect AT MOST 2 BuildFirst.
    assert!(
        build_first <= 2,
        "expected <= 2 BuildFirst for 100 streams, got {build_first}"
    );
    assert_eq!(build_first + pending, 100);

    // Complete the first build -> 64 streams activate at once.
    let activated = pool.record_built(1u64, Class::Interactive, now).unwrap();
    let max_streams = Class::Interactive.default_profile().max_streams;
    assert_eq!(activated, max_streams);
    assert_eq!(pool.stream_count(1), Some(max_streams));
}

/// **Scenario 4 - hostile operator with multiple bridges.**
///
/// A catalogue dominated by one hostile operator (operator 1 runs
/// 5 of 8 bridges) MUST NOT result in a 3-hop circuit landing on
/// 3 of operator 1's nodes. `HopSelector` enforces operator
/// anti-affinity; at most 1 of any single operator's bridges
/// appears in the circuit.
#[test]
fn hostile_operator_resilience() {
    let salt = [0x42u8; 16];
    let selector = HopSelector::new(salt);
    let profile = Class::Interactive.default_profile();

    // Hostile catalogue: operator 1 runs 5 bridges, operators 2/3/4
    // each run 1.
    let catalogue = vec![
        bridge(0x01, 1, &[10, 0, 1, 1], &["reality-v2"]),
        bridge(0x02, 1, &[10, 0, 2, 1], &["reality-v2"]),
        bridge(0x03, 1, &[10, 0, 3, 1], &["reality-v2"]),
        bridge(0x04, 1, &[10, 0, 4, 1], &["reality-v2"]),
        bridge(0x05, 1, &[10, 0, 5, 1], &["reality-v2"]),
        bridge(0x06, 2, &[10, 0, 6, 1], &["reality-v2"]),
        bridge(0x07, 3, &[10, 0, 7, 1], &["reality-v2"]),
        bridge(0x08, 4, &[10, 0, 8, 1], &["reality-v2"]),
    ];

    let hops = selector.select(&profile, &catalogue).unwrap();
    assert_eq!(hops.len(), 3);

    // Hostile bridges have static_pk[0] in 0x01..=0x05.
    let hostile_hops = hops.iter().filter(|h| h.static_pk[0] <= 0x05).count();
    assert!(
        hostile_hops <= 1,
        "hostile operator landed {hostile_hops} of 3 hops; should be <= 1"
    );
}

/// **Scenario 5 - build failure recovery.**
///
/// A circuit build that fails at hop 1 cleanly cycles through the
/// pool's `record_build_failure`, leaving no leaked state. The
/// builder reports the right hops to tear down. A subsequent
/// acquire for the same class operates from a clean slate.
#[test]
fn build_failure_recovery() {
    let now = Instant::now();
    let mut pool = CircuitPool::<u64>::new(PoolPolicy::default());
    pool.set_jitter_picker(mirage_router::pool::zero_jitter);
    let class = Class::Interactive;

    // 1. Acquire -> BuildFirst -> builder runs.
    let outcome = pool.acquire(class, now).unwrap();
    let profile = match outcome {
        AcquireOutcome::BuildFirst { profile } => profile,
        _ => panic!("expected BuildFirst"),
    };
    let catalogue = synthetic_catalogue();
    let selector = HopSelector::new([0x42u8; 16]);
    let hops = selector.select(&profile, &catalogue).unwrap();
    let mut builder = CircuitBuilder::new(hops.clone()).unwrap();

    // 2. First step succeeds - hop 0 dial OK.
    let step = builder.next_step();
    let spec0 = match step {
        BuildStep::DialHop0 { spec } => spec,
        _ => panic!("expected DialHop0"),
    };
    builder
        .record_hop_built(0, synthetic_hop_keys(&spec0, 0))
        .unwrap();

    // 3. Second step - hop 1 extend FAILS.
    let _ = builder.next_step();
    builder
        .record_hop_failure(1, mirage_circuit::BuilderError::HopHandshakeFailed)
        .unwrap();
    assert!(builder.is_failed());

    // 4. Tear-down list correctly identifies hop 0 as built and
    //    needing CMD_DESTROY.
    let to_destroy = builder.hops_to_tear_down();
    assert_eq!(to_destroy.len(), 1);
    assert_eq!(to_destroy[0].static_pk, hops[0].static_pk);

    // 5. Pool sees the failure and clears its Building slot.
    pool.record_build_failure(class).unwrap();
    assert_eq!(pool.pending_count(class), 0);
    assert_eq!(pool.healthy_count(class), 0);

    // 6. A fresh acquire works cleanly - the failure left no
    //    residue in pool state.
    let next = pool.acquire(class, now).unwrap();
    assert!(matches!(next, AcquireOutcome::BuildFirst { .. }));
}

/// **Scenario 6 - pool tick fills the floor.**
///
/// At idle, the pool's tick emits `BuildCircuit` actions to keep
/// every class at its `min_pool_size`. The runtime processes those
/// actions by running the selector + builder; on completion calls
/// `record_built`. After enough builds, the pool reports the
/// expected number of healthy circuits.
#[test]
fn pool_tick_fills_floor() {
    let now = Instant::now();
    let catalogue = synthetic_catalogue();
    let selector = HopSelector::new([0x99u8; 16]);
    let mut pool = CircuitPool::<u64>::new(PoolPolicy::default());
    pool.set_jitter_picker(mirage_router::pool::zero_jitter);

    // Tick on empty pool emits BuildCircuit per class with
    // min_pool_size > 0.
    let actions = pool.tick(now);
    let build_actions: Vec<_> = actions
        .iter()
        .filter_map(|a| match a {
            PoolAction::BuildCircuit { profile } => Some(profile.clone()),
            _ => None,
        })
        .collect();
    assert!(!build_actions.is_empty());

    // Process each: select + drive builder + record_built.
    let mut next_id = 1u64;
    for profile in &build_actions {
        let hops = selector.select(profile, &catalogue).unwrap();
        let mut builder = CircuitBuilder::new(hops).unwrap();
        drive_builder_to_ready(&mut builder).unwrap();
        let _circuit = builder.into_circuit().unwrap();
        pool.record_built(next_id, profile.class, now).unwrap();
        next_id += 1;
    }

    // Floor satisfied: each class with min_pool_size > 0 now has
    // healthy_count == min_pool_size.
    for &class in Class::all() {
        let min = class.default_profile().min_pool_size;
        if min > 0 {
            assert_eq!(
                pool.healthy_count(class),
                min,
                "class {} floor unmet",
                class.name()
            );
        }
    }
}

/// **Scenario 7 - selector + builder produce a usable Circuit.**
///
/// Selector output goes straight into a `CircuitBuilder` which
/// produces a Circuit. That Circuit accepts `relay_seal` - the
/// existing v0.1u onion machinery sees no difference between a
/// circuit built this way and one built with explicit hops.
#[test]
fn selector_to_builder_produces_usable_circuit() {
    let salt = [0x42u8; 16];
    let catalogue = synthetic_catalogue();
    let selector = HopSelector::new(salt);
    let profile = Class::Interactive.default_profile();
    let hops = selector.select(&profile, &catalogue).unwrap();
    let mut builder = CircuitBuilder::new(hops).unwrap();
    drive_builder_to_ready(&mut builder).unwrap();

    let mut circuit = builder.into_circuit().unwrap();
    let pt = b"hello mirage v0.2 stack";
    let ct = circuit.relay_seal(pt).unwrap();
    assert!(!ct.is_empty());
    assert_ne!(ct, pt);
}
