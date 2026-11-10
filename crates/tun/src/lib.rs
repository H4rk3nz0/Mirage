#![forbid(unsafe_code)]
//! Transparent, system-wide VPN layer for Mirage.
//!
//! Mirage's client is otherwise an application-level SOCKS5 proxy: only
//! proxy-aware apps (a browser configured for `socks5h://127.0.0.1:1080`,
//! `curl --proxy ...`) are protected, and UDP / system traffic leaks. A **TUN
//! device** closes that gap: the OS routes *every* packet into a virtual
//! interface, this crate terminates each TCP flow in a userspace IP stack
//! ([`smoltcp`]) and hands the flow - as a plain byte stream plus its intended
//! `target` (dst ip:port) - to the caller, who tunnels it through Mirage. No
//! per-app configuration; every connection is protected transparently.
//!
//! ```text
//!   apps -> kernel routing -> TUN device -> NetStack (smoltcp)
//!                                              |  terminates TCP
//!                                              v
//!                                   Flow { target, AsyncRead+AsyncWrite }
//!                                              |
//!                                              v  (caller) Mirage tunnel -> bridge -> internet
//! ```
//!
//! # Layering (all testable without a real device or root)
//!
//! - [`TunDevice`] - async read/write of raw IP packets. Production impls open
//!   an OS TUN (Linux/macOS, feature `device`); [`MemoryTun`] backs unit tests
//!   with crafted packets.
//! - [`flow`] - parse the 5-tuple + flags out of an IP/TCP packet (via
//!   `smoltcp`'s safe wire parsers).
//! - [`netstack`] - the smoltcp gateway: SYN -> new flow, established socket ->
//!   `Flow`, and pumps return packets back to the device.
//!
//! The IP-stack is deliberately isolated in its own crate so the
//! `#![forbid(unsafe_code)]` guarantee holds: the only `unsafe` (the TUN
//! `ioctl`) is encapsulated inside the `tun` dependency, never in Mirage code.

mod device;
pub mod flow;
pub mod netstack;
mod os;
mod queue_device;
mod routes;

pub use device::{
    ChannelTun, ChannelTunHandle, ChannelTunSink, MemoryTun, MemoryTunHandle, TunDevice, TunError,
};
pub use flow::{FlowKey, Protocol};
pub use netstack::{Flow, NetStack, NetStackConfig, TcpFlow, UdpFlow, UdpFlowRx, UdpFlowTx};
pub use os::{OsTun, OsTunConfig};
pub use routes::{RouteConfig, RouteGuard};
