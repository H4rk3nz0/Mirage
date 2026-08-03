//! Mirage hidden services: addressing + service descriptors +
//! rendezvous wire formats.
//!
//! # Why hidden services
//!
//! A hidden service is a destination addressed by its long-term
//! public key, NOT by an IP address. The service is reachable only
//! through the Mirage circuit network; its actual network location
//! is never disclosed. Tor onion services are the canonical
//! reference; Mirage's design follows Tor v3 conceptually with
//! these adaptations:
//!
//! 1. **PQ-hardened identity.** Tor v3 uses Ed25519 for service
//!    identity; we use the same primitive for backward conceptual
//!    parity, with the caveat that PQ signatures are a v0.2 spec
//!    item (roadmap A6) and will replace the identity scheme then.
//! 2. **Multi-channel descriptor publication.** Tor uses HSDIR
//!    (a designated hidden-service-directory subset of relays).
//!    Mirage publishes service descriptors through the existing
//!    [`mirage_discovery`] channel mesh - reuse, not new infra.
//! 3. **Per-epoch info-hash for descriptors.** Same epoch-rolled
//!    pseudorandom info-hash design as bridge announcements.
//!
//! # Address format
//!
//! `<base32(public_key) || base32(checksum)>.mirage`
//!
//! - 32-byte Ed25519 public key + 2-byte checksum (BLAKE3-keyed
//!   over the pk + a fixed label, truncated to 16 bits).
//! - base32 encoding (RFC 4648 lowercase, no padding).
//! - 56 base32 chars total.
//!
//! Tor v3 used `<pk||cksum||version>.onion`; we omit the version
//! byte because the `.mirage` TLD already implies v1 of this scheme.
//!
//! # Service descriptor
//!
//! See [`descriptor`] for the wire format. The service signs a
//! descriptor with its long-term key; the descriptor lists
//! introduction-point bridges and a rendezvous protocol version.
//! Clients fetch via `info_hash = BLAKE3(b"mirage-onion-desc-v1" ||
//! service_pk || epoch_be)`.
//!
//! # [warn] PARTIAL - protocol complete, drivers not built
//!
//! Read this before assuming a `.mirage` address resolves to anything.
//!
//! | Layer | State |
//! |---|---|
//! | Address, descriptor, info-hash wire formats | done, pinned by in-crate vectors |
//! | Descriptor sealing + publish/resolve | done ([`publish_descriptor`] / [`resolve_descriptor`]) |
//! | INTRODUCE cell body | done ([`IntroduceCell`]) |
//! | Introduction-point + rendezvous-point bridge ROLES | done, in `mirage_circuit::rendezvous` |
//! | Cross-session cell routing | done, in `mirage_bridge::rendezvous_router` |
//! | Session-task dispatch of the six cells | done, behind `onion_rendezvous_enabled`, e2e-tested |
//! | INTRODUCE authentication | done - sealed to the service ([`introduce_sealed`]) |
//! | Reaching a meeting bridge both sides know | done - endpoints in the descriptor (v2) |
//! | Client <-> service end-to-end keys | done - [`e2e`], forward-secret, service-authenticated |
//! | Circuit as a byte stream | done - `mirage_runtime::circuit_stream` |
//! | Service-side responder daemon | **NOT BUILT** |
//! | Client `.mirage` resolver + SOCKS interception | **NOT BUILT** |
//!
//! Every PROTOCOL piece now exists and is tested. A bridge can be an
//! introduction and rendezvous point, two sessions can meet through it and
//! exchange traffic, a client can produce an introduction the service accepts and
//! can dial the bridge to deliver it, and the two ends can key past the
//! rendezvous point so it cannot read what it relays.
//!
//! What is left is two DRIVERS - a service daemon that holds introduction points
//! and answers introductions, and a client resolver that recognises a `.mirage`
//! address in SOCKS and walks the exchange. Those are now plumbing over tested
//! pieces rather than the design work they used to be.
//!
//! **They must build MULTI-HOP circuits.** A service reaching an introduction
//! point over one hop has told that bridge its IP address, which is the single
//! property a hidden service exists to protect. `mirage_client`'s
//! `extend_circuit_hop` already builds three-hop circuits, so the mechanism
//! exists; using it is not optional.
//!
//! ## What was fixed, and what it cost
//! ## What was fixed, and what it cost
//!
//! **INTRODUCE was unproducible by a client.** [`IntroduceCell`] carries an
//! Ed25519 signature verified against the descriptor's `intro_auth_key` - a
//! VERIFYING key whose private half never leaves the service. The only signer who
//! passed was the service introducing to itself. Pinned by
//! `service::tests::no_client_can_produce_an_acceptable_introduce_cell`, which is
//! kept because the type is still public.
//!
//! Replaced by [`introduce_sealed`]: the client SEALS the introduction to the
//! service's X25519 key, the way Tor's INTRODUCE1 does. Any holder of the address
//! can connect, the introduction point still cannot read what it forwards, and
//! nothing has to be distributed in advance - the sealing key is in the
//! descriptor the client already fetched. Client authorization remains available
//! as an additive layer rather than being baked in.
//!
//! **A bare identity is not dialable.** Descriptor v2 carries an endpoint per
//! introduction point, because Mirage has no global directory on purpose and
//! resolving an identity works only for bridges the client already knows - which
//! a service's introduction points generally are not. The disclosure is bounded
//! by the descriptor's own seal: reading it requires already holding the
//! `.mirage` address, the same trade Tor makes.
//!
//! v1 descriptors are refused with a reason rather than decoded, since they carry
//! neither the sealing key nor an endpoint and so cannot be acted on.
//!
//! ## The end-to-end layer, and why it is not a Mirage session
//!
//! Running `mirage_session` over the joined circuit was the obvious answer and it
//! does not fit: that layer authenticates a BRIDGE against an operator key and a
//! capability token, and a public hidden service has neither. Inventing one would
//! make every hidden service invite-gated, which is a different product.
//!
//! [`e2e`] does what a client actually needs instead. Both ephemerals were
//! already on the wire and unused - the client's in the sealed INTRODUCE, the
//! service's forwarded by the rendezvous point - so the exchange is an X25519
//! between them plus one Ed25519 signature by the service over a transcript
//! binding both ephemerals, the service identity and the rendezvous cookie.
//!
//! - Forward-secret: both ephemerals are fresh per meeting, so later compromise
//!   of the identity key does not decrypt a recorded session.
//! - The client verifies against the key its `.mirage` ADDRESS names, not the
//!   descriptor's self-declaration - a descriptor comes off a public channel, and
//!   trusting its claim would let whoever published it substitute their own.
//! - Authentication is one-sided on purpose: a public service must accept
//!   strangers. Per-client authorization layers on top rather than replacing it.
//!
//! ## What the two drivers must get right, and why they are not plumbing
//! ## What the two drivers must get right, and why they are not plumbing
//! ## What the two drivers must get right, and why they are not plumbing
//!
//! Both remaining pieces are drivers over machinery that now exists, but two of
//! their requirements are design work, and building them without either would
//! ship something worse than nothing - a hidden service that is not hidden.
//!
//! 1. **The circuits to introduction and rendezvous points MUST be multi-hop.**
//!    A service that reaches its introduction point over a one-hop circuit has
//!    told that bridge its IP address, which is the single property a hidden
//!    service exists to protect. `mirage_client`'s `extend_circuit_hop` already
//!    builds 3-hop circuits, so the mechanism exists; using it is not optional.
//! 2. **The client and service need an end-to-end layer the rendezvous point
//!    cannot read.** [`crate::descriptor`] and
//!    [`mirage_circuit::rendezvous::RendezvousBody`] already carry the service's
//!    ephemeral X25519 key to the client for this purpose, and NOTHING consumes
//!    it yet. Until something does, everything crossing a joined pair is
//!    readable by the bridge hosting the meeting. The natural answer is to run
//!    an ordinary Mirage session over the joined circuit (Noise XX + ML-KEM
//!    already ships), which needs a circuit-as-`AsyncRead`/`AsyncWrite` adapter -
//!    no such adapter exists - and a decision about what authenticates the
//!    service end: the `.mirage` identity key is the obvious candidate, but the
//!    session layer currently authenticates a bridge against an operator key,
//!    which is a different trust model.
//!
//! ## Descriptor sealing - DONE (the former hard prerequisite)
//!
//! [`OnionDescriptor::encode`] emits a **cleartext** structure that begins with
//! the fixed ASCII magic `"MI"` followed by a fixed-layout header (see
//! [`descriptor`]). Published verbatim, that magic + structure is a
//! content-agnostic fingerprint for "this blob is a Mirage onion descriptor" -
//! signatures stop forgery but do nothing to hide it from a passive scraper.
//! [`seal`] closes this: [`seal_descriptor`] wraps the encoded bytes in a
//! ChaCha20-Poly1305 seal keyed by `BLAKE3-keyed(service_pk, epoch)`, so the
//! published blob is indistinguishable from random to anyone who does not
//! already hold the `.mirage` address (the info-hash location is a one-way
//! function of `service_pk`, so a scraper cannot derive the seal key). A
//! resolving client re-derives both the info-hash and the seal key from the
//! address it is looking up. [`publish_descriptor`] / [`resolve_descriptor`]
//! seal / unseal automatically - the publication plane no longer leaks the
//! `MI` magic. Per-CLIENT authorization (only specific clients may resolve) is
//! a separate additive layer, deliberately out of scope.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod address;
pub mod descriptor;
pub mod e2e;
pub mod introduce;
pub mod introduce_sealed;
pub mod publish;
pub mod seal;
pub mod service;

pub use address::{onion_address_to_pk, pk_to_onion_address, AddressError, ONION_ADDRESS_SUFFIX};
pub use descriptor::{
    onion_descriptor_info_hash, IntroPoint, OnionDescriptor, ServiceDescError, MAX_INTRO_POINTS,
};
pub use e2e::{client_side, service_side, E2eError, RendezvousKeys};
pub use introduce::{IntroduceCell, IntroduceError};
pub use introduce_sealed::{
    open_introduce, seal_introduce, Introduction, SealedIntroduceError, SEALED_INTRODUCE_LEN,
};
pub use publish::{publish_descriptor, resolve_descriptor, OnionDiscoveryError};
pub use seal::{seal_descriptor, unseal_descriptor, SealError};
pub use service::{HeldIntro, IntroduceRefusal, ServiceState, TARGET_INTRO_POINTS};
