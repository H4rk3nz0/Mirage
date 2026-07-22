//! OS routing-table management for TUN VPN mode (audit CRIT #24 / #25 / #29).
//!
//! # Why this exists
//!
//! Opening a TUN device and bringing it `up` does **not** make the kernel send
//! any traffic to it. Before this module, `run_tun` did exactly that and logged
//! "transparent system-wide VPN" - a catastrophic **fail-open**: the interface
//! was up but the routing table still pointed every packet at the physical link,
//! so the user's traffic egressed **in clear** while they believed they were
//! tunnelled.
//!
//! [`RouteGuard::install`] closes that hole:
//!
//! 1. **Bridge exclusion (#25).** For every bridge IP the client dials, install
//!    a host route via the *original* default gateway. The encrypted carrier
//!    packets to the bridge must bypass the tunnel, or they would recurse into
//!    the TUN forever.
//! 2. **Default capture (#24).** Install a *split default* - `0.0.0.0/1` +
//!    `128.0.0.0/1` (and `::/1` + `8000::/1` for v6) - via the TUN. Two `/1`
//!    routes cover the whole address space and take precedence over the system
//!    `/0` default *without deleting it*, so every other flow is captured and
//!    the original default is trivially restorable.
//! 3. **IPv6 (#29).** v6 is captured with the same split-default so a
//!    dual-stack host cannot leak over IPv6 while v4 is tunnelled. If the host
//!    has no v6 default route, v6 capture is skipped (nothing to leak).
//! 4. **Teardown.** [`RouteGuard`]'s `Drop` removes exactly what it added,
//!    restoring the original table.
//!
//! # Fail-closed
//!
//! If any required step fails, `install` tears down whatever it already added
//! and returns `Err`. The caller (`run_tun`) MUST abort on that error: Mirage
//! never claims protection it did not actually install.
//!
//! # Testability
//!
//! Route installation is platform- and privilege-dependent and CANNOT be
//! exercised in a sandboxed CI - running it would mutate the host routing
//! table. So the **argv construction** is factored into pure functions that are
//! unit-tested here, while the impure execution path is validated on a real box
//! with `CAP_NET_ADMIN`/root. On platforms whose routing is not yet wired
//! ([`install`] returns [`TunError`]), the guard fails closed rather than
//! leaving a leaking pseudo-VPN.

use std::net::IpAddr;

use crate::device::TunError;

/// Inputs for installing the VPN routing policy.
#[derive(Debug, Clone)]
pub struct RouteConfig {
    /// The **actual** kernel-assigned TUN interface name. On Linux/Windows this
    /// is the requested name (`mirage0`); on macOS the kernel forces `utunN`, so
    /// this MUST come from [`crate::OsTun::if_name`], not the requested name.
    pub tun_name: String,
    /// Every bridge IP the client will dial, to be excluded from the tunnel.
    /// Both literal endpoint IPs and resolved discovered addresses belong here.
    pub bridge_ips: Vec<IpAddr>,
    /// Capture IPv6 as well as IPv4. When the host has a v6 default route this
    /// prevents a dual-stack leak; when it does not, v6 setup is a no-op.
    pub enable_ipv6: bool,
}

/// A live set of installed routes. Dropping it restores the original table.
#[must_use = "dropping the guard immediately tears the routes back down"]
pub struct RouteGuard {
    /// Commands to run (in order) on teardown, each an argv vector.
    teardown: Vec<Vec<String>>,
}

impl RouteGuard {
    /// Install the VPN routing policy described by `cfg`. Fail-closed: on any
    /// error, everything already installed is rolled back and `Err` is returned.
    ///
    /// Requires root (Linux: `CAP_NET_ADMIN`; Windows: Administrator). Wired on
    /// Linux (`iproute2`), macOS (`/sbin/route`), and Windows (`netsh`). Any
    /// other platform returns an error so the caller fails closed instead of
    /// running a pseudo-VPN that leaks.
    pub fn install(cfg: &RouteConfig) -> Result<Self, TunError> {
        #[cfg(target_os = "linux")]
        {
            Self::install_linux(cfg)
        }
        #[cfg(target_os = "macos")]
        {
            Self::install_macos(cfg)
        }
        #[cfg(target_os = "windows")]
        {
            Self::install_windows(cfg)
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        {
            let _ = cfg;
            Err(TunError::Io(std::io::Error::other(
                "TUN routing is not wired on this platform; refusing to run to \
                 avoid a traffic leak (fail-closed, audit #24)",
            )))
        }
    }

    #[cfg(target_os = "linux")]
    fn install_linux(cfg: &RouteConfig) -> Result<Self, TunError> {
        // Discover the current IPv4 default gateway so bridge traffic can bypass
        // the tunnel. No default route => no way to exclude the bridge => refuse.
        let out = run_capture(&linux_show_default_cmd(4))?;
        let (gw4, dev4) = parse_linux_default(&out).ok_or_else(|| {
            TunError::Io(std::io::Error::other(
                "no IPv4 default route found; cannot install bridge exclusion \
                 (fail-closed, audit #25)",
            ))
        })?;

        let mut guard = RouteGuard {
            teardown: Vec::new(),
        };

        // 1. Bridge exclusion: host route each bridge IP via the original gw.
        for ip in &cfg.bridge_ips {
            if let IpAddr::V4(v4) = ip {
                let cidr = format!("{v4}/32");
                if let Err(e) = guard.apply(linux_add_host_route(&cidr, &gw4, &dev4)) {
                    guard.rollback();
                    return Err(e);
                }
                guard.teardown.push(linux_del_route(&cidr));
            }
        }

        // 2. Default capture: split-default via the TUN.
        for cidr in ["0.0.0.0/1", "128.0.0.0/1"] {
            if let Err(e) = guard.apply(linux_add_dev_route(cidr, &cfg.tun_name)) {
                guard.rollback();
                return Err(e);
            }
            guard.teardown.push(linux_del_route(cidr));
        }

        // 3. IPv6: only if requested AND the host actually has a v6 default
        // (otherwise there is nothing to leak, and adding v6 routes on a
        // v4-only host would spuriously fail-close).
        if cfg.enable_ipv6 {
            if let Ok(out6) = run_capture(&linux_show_default_cmd(6)) {
                // Only act when the host actually has a v6 default (else nothing
                // to leak). Red-team #4/#7: capture must NOT require a parseable
                // gateway - an on-link/gateway-less v6 default would otherwise be
                // silently skipped and leak v6 in clear while v4 is tunnelled.
                if has_default_route(&out6) {
                    // Bridge exclusion needs a gateway; when the default is
                    // on-link, off-link bridges are unreachable over v6 anyway and
                    // on-link ones are bypassed by their more-specific /64 route.
                    if let Some((gw6, dev6)) = parse_linux_default(&out6) {
                        for ip in &cfg.bridge_ips {
                            if let IpAddr::V6(v6) = ip {
                                let cidr = format!("{v6}/128");
                                if let Err(e) =
                                    guard.apply(linux_add_host_route6(&cidr, &gw6, &dev6))
                                {
                                    guard.rollback();
                                    return Err(e);
                                }
                                guard.teardown.push(linux_del_route6(&cidr));
                            }
                        }
                    }
                    // Capture v6 UNCONDITIONALLY once a default exists (routes via
                    // the TUN by interface, no gateway needed).
                    for cidr in ["::/1", "8000::/1"] {
                        if let Err(e) = guard.apply(linux_add_dev_route6(cidr, &cfg.tun_name)) {
                            guard.rollback();
                            return Err(e);
                        }
                        guard.teardown.push(linux_del_route6(cidr));
                    }
                }
            }
        }

        Ok(guard)
    }

    // ---- macOS (utun via /sbin/route; mirrors wg-quick's darwin backend) ----
    #[cfg(target_os = "macos")]
    fn install_macos(cfg: &RouteConfig) -> Result<Self, TunError> {
        // Physical IPv4 default gateway, so bridge traffic bypasses the tunnel.
        // No usable default => cannot exclude the bridge => refuse (fail-closed).
        let out = run_capture(&macos_show_default_cmd(false))?;
        let gw4 = parse_macos_default(&out).ok_or_else(|| {
            TunError::Io(std::io::Error::other(
                "no IPv4 default gateway found; cannot install bridge exclusion \
                 (fail-closed, audit #25)",
            ))
        })?;

        let mut guard = RouteGuard {
            teardown: Vec::new(),
        };

        // 1. Bridge exclusion: host route (bare IP, no /32) via the original gw.
        for ip in &cfg.bridge_ips {
            if let IpAddr::V4(v4) = ip {
                let dst = v4.to_string();
                if let Err(e) = guard.apply(macos_add_host_route(&dst, &gw4, false)) {
                    guard.rollback();
                    return Err(e);
                }
                guard.teardown.push(macos_del_route(&dst, false));
            }
        }
        // 2. Split-default capture via the utun interface.
        for cidr in ["0.0.0.0/1", "128.0.0.0/1"] {
            if let Err(e) = guard.apply(macos_add_dev_route(cidr, &cfg.tun_name, false)) {
                guard.rollback();
                return Err(e);
            }
            guard.teardown.push(macos_del_route(cidr, false));
        }
        // 3. IPv6 (only if a v6 default exists - else nothing to leak). Red-team
        // #4/#7: capture must not require a parseable gateway (on-link default
        // would otherwise leak v6 in clear).
        if cfg.enable_ipv6 {
            if let Ok(out6) = run_capture(&macos_show_default_cmd(true)) {
                if has_default_route(&out6) {
                    if let Some(gw6) = parse_macos_default(&out6) {
                        for ip in &cfg.bridge_ips {
                            if let IpAddr::V6(v6) = ip {
                                let dst = v6.to_string();
                                if let Err(e) = guard.apply(macos_add_host_route(&dst, &gw6, true))
                                {
                                    guard.rollback();
                                    return Err(e);
                                }
                                guard.teardown.push(macos_del_route(&dst, true));
                            }
                        }
                    }
                    for cidr in ["::/1", "8000::/1"] {
                        if let Err(e) = guard.apply(macos_add_dev_route(cidr, &cfg.tun_name, true))
                        {
                            guard.rollback();
                            return Err(e);
                        }
                        guard.teardown.push(macos_del_route(cidr, true));
                    }
                }
            }
        }
        Ok(guard)
    }

    // ---- Windows (Wintun via netsh; mirrors wireguard-windows) ----
    #[cfg(target_os = "windows")]
    fn install_windows(cfg: &RouteConfig) -> Result<Self, TunError> {
        // Physical IPv4 default: next-hop gateway + interface index, so the
        // bridge-exclusion /32 pins to the real uplink. No default => refuse.
        let out = run_capture(&windows_show_default_cmd(false))?;
        let (gw4, phys_idx4) = parse_windows_default(&out).ok_or_else(|| {
            TunError::Io(std::io::Error::other(
                "no IPv4 default route found; cannot install bridge exclusion \
                 (fail-closed, audit #25)",
            ))
        })?;

        let mut guard = RouteGuard {
            teardown: Vec::new(),
        };

        // 1. Bridge exclusion FIRST (so server-bound packets never loop into the
        // tunnel): /32 host route on the physical interface via the real gw.
        for ip in &cfg.bridge_ips {
            if let IpAddr::V4(v4) = ip {
                let prefix = format!("{v4}/32");
                if let Err(e) =
                    guard.apply(windows_add_host_route(&prefix, &phys_idx4, &gw4, false))
                {
                    guard.rollback();
                    return Err(e);
                }
                guard
                    .teardown
                    .push(windows_del_route(&prefix, &phys_idx4, false));
            }
        }
        // 2. Split-default capture into the Wintun adapter (on-link nexthop).
        // Wintun-bound routes vanish when the adapter closes, but we still record
        // explicit teardown so a same-process re-install starts clean.
        for prefix in ["0.0.0.0/1", "128.0.0.0/1"] {
            if let Err(e) = guard.apply(windows_add_dev_route(prefix, &cfg.tun_name, false)) {
                guard.rollback();
                return Err(e);
            }
            guard
                .teardown
                .push(windows_del_dev_route(prefix, &cfg.tun_name, false));
        }
        // 3. IPv6 (only if a v6 default exists). Red-team #4/#7: capture must not
        // require a parseable gateway - an on-link (nexthop=::) v6 default would
        // otherwise be skipped and leak v6 in clear.
        if cfg.enable_ipv6 {
            if let Ok(out6) = run_capture(&windows_show_default_cmd(true)) {
                if windows_default_exists(&out6) {
                    if let Some((gw6, phys_idx6)) = parse_windows_default(&out6) {
                        for ip in &cfg.bridge_ips {
                            if let IpAddr::V6(v6) = ip {
                                let prefix = format!("{v6}/128");
                                if let Err(e) = guard
                                    .apply(windows_add_host_route(&prefix, &phys_idx6, &gw6, true))
                                {
                                    guard.rollback();
                                    return Err(e);
                                }
                                guard
                                    .teardown
                                    .push(windows_del_route(&prefix, &phys_idx6, true));
                            }
                        }
                    }
                    for prefix in ["::/1", "8000::/1"] {
                        if let Err(e) =
                            guard.apply(windows_add_dev_route(prefix, &cfg.tun_name, true))
                        {
                            guard.rollback();
                            return Err(e);
                        }
                        guard
                            .teardown
                            .push(windows_del_dev_route(prefix, &cfg.tun_name, true));
                    }
                }
            }
        }
        Ok(guard)
    }

    /// Run one install command, recording nothing (the caller pushes the paired
    /// teardown only after success).
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    fn apply(&self, argv: Vec<String>) -> Result<(), TunError> {
        run_status(&argv)
    }

    /// Best-effort rollback: run every recorded teardown command, ignoring
    /// individual failures (we are already erroring out; do as much cleanup as
    /// possible). Consumes the teardown list so `Drop` does not repeat it.
    ///
    /// Only the desktop OSes install routes (mobile leaves routing to the OS VPN
    /// API), so this - like [`Self::apply`] - is desktop-only; without the gate
    /// it is dead code on Android/iOS and trips `-D warnings`.
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    fn rollback(&mut self) {
        for argv in std::mem::take(&mut self.teardown).into_iter().rev() {
            let _ = run_status(&argv);
        }
    }
}

impl Drop for RouteGuard {
    fn drop(&mut self) {
        for argv in std::mem::take(&mut self.teardown).into_iter().rev() {
            let _ = run_status(&argv);
        }
    }
}

// Pure argv builders (unit-tested) - Linux `ip` (iproute2).

/// Whether a `default ...` route line is present (Linux `ip route`, macOS
/// `netstat -nr`). Unlike [`parse_linux_default`] / [`parse_macos_default`] this
/// is TRUE even for an on-link (gateway-less) default, so v6 capture is not
/// silently skipped for such hosts (red-team #4/#7).
#[cfg(any(target_os = "linux", target_os = "macos", test))]
fn has_default_route(output: &str) -> bool {
    output
        .lines()
        .any(|l| l.split_whitespace().next() == Some("default"))
}

/// Whether the Windows `Get-NetRoute` discovery one-liner reported a default
/// route AT ALL (including an on-link `::`/`0.0.0.0` next-hop, which
/// [`parse_windows_default`] rejects for exclusion). Used so v6 capture is not
/// skipped on a gateway-less v6 default (red-team #4/#7).
#[cfg(any(target_os = "windows", test))]
fn windows_default_exists(output: &str) -> bool {
    output
        .lines()
        .map(str::trim)
        .any(|l| l.split_whitespace().count() >= 2)
}

/// `ip -N route show default` - query the current default route.
#[cfg(any(target_os = "linux", test))]
fn linux_show_default_cmd(family: u8) -> Vec<String> {
    vec![
        "ip".into(),
        format!("-{family}"),
        "route".into(),
        "show".into(),
        "default".into(),
    ]
}

/// Parse `default via <gw> dev <dev> ...` from `ip route show default` output.
/// Returns `(gateway, device)`. Works for both v4 and v6 output.
#[cfg(any(target_os = "linux", test))]
fn parse_linux_default(output: &str) -> Option<(String, String)> {
    for line in output.lines() {
        let toks: Vec<&str> = line.split_whitespace().collect();
        if toks.first() != Some(&"default") {
            continue;
        }
        let mut gw = None;
        let mut dev = None;
        let mut i = 1;
        while i + 1 < toks.len() + 1 {
            match toks.get(i) {
                Some(&"via") => {
                    gw = toks.get(i + 1).map(|s| (*s).to_string());
                    i += 2;
                }
                Some(&"dev") => {
                    dev = toks.get(i + 1).map(|s| (*s).to_string());
                    i += 2;
                }
                Some(_) => i += 1,
                None => break,
            }
        }
        if let (Some(g), Some(d)) = (gw, dev) {
            return Some((g, d));
        }
    }
    None
}

/// `ip route add <cidr> via <gw> dev <dev>` (IPv4 host route for bridge bypass).
#[cfg(any(target_os = "linux", test))]
fn linux_add_host_route(cidr: &str, gw: &str, dev: &str) -> Vec<String> {
    vec![
        "ip".into(),
        "route".into(),
        "add".into(),
        cidr.into(),
        "via".into(),
        gw.into(),
        "dev".into(),
        dev.into(),
    ]
}

/// `ip -6 route add <cidr> via <gw> dev <dev>` (IPv6 host route for bridge bypass).
#[cfg(any(target_os = "linux", test))]
fn linux_add_host_route6(cidr: &str, gw: &str, dev: &str) -> Vec<String> {
    vec![
        "ip".into(),
        "-6".into(),
        "route".into(),
        "add".into(),
        cidr.into(),
        "via".into(),
        gw.into(),
        "dev".into(),
        dev.into(),
    ]
}

/// `ip route add <cidr> dev <tun>` (IPv4 split-default capture leg).
#[cfg(any(target_os = "linux", test))]
fn linux_add_dev_route(cidr: &str, dev: &str) -> Vec<String> {
    vec![
        "ip".into(),
        "route".into(),
        "add".into(),
        cidr.into(),
        "dev".into(),
        dev.into(),
    ]
}

/// `ip -6 route add <cidr> dev <tun>` (IPv6 split-default capture leg).
#[cfg(any(target_os = "linux", test))]
fn linux_add_dev_route6(cidr: &str, dev: &str) -> Vec<String> {
    vec![
        "ip".into(),
        "-6".into(),
        "route".into(),
        "add".into(),
        cidr.into(),
        "dev".into(),
        dev.into(),
    ]
}

/// `ip route del <cidr>` (IPv4 teardown).
#[cfg(any(target_os = "linux", test))]
fn linux_del_route(cidr: &str) -> Vec<String> {
    vec!["ip".into(), "route".into(), "del".into(), cidr.into()]
}

/// `ip -6 route del <cidr>` (IPv6 teardown).
#[cfg(any(target_os = "linux", test))]
fn linux_del_route6(cidr: &str) -> Vec<String> {
    vec![
        "ip".into(),
        "-6".into(),
        "route".into(),
        "del".into(),
        cidr.into(),
    ]
}

// Pure argv builders (unit-tested) - macOS `/sbin/route` (mirrors wg-quick).

/// `-inet` / `-inet6` address-family flag.
#[cfg(any(target_os = "macos", test))]
fn af_flag(v6: bool) -> &'static str {
    if v6 {
        "-inet6"
    } else {
        "-inet"
    }
}

/// `netstat -nr -f inet[6]` - query the routing table for the default gateway.
#[cfg(any(target_os = "macos", test))]
fn macos_show_default_cmd(v6: bool) -> Vec<String> {
    vec![
        "netstat".into(),
        "-nr".into(),
        "-f".into(),
        if v6 { "inet6".into() } else { "inet".into() },
    ]
}

/// Parse the default gateway from `netstat -nr` output. Mirrors wg-quick: the
/// default row is where col0 == `default` and col1 is NOT a `link#...`
/// (on-link, no next hop - unusable for a bypass). Returns the gateway (keeping
/// any `%zone` scope for v6 link-locals).
#[cfg(any(target_os = "macos", test))]
fn parse_macos_default(output: &str) -> Option<String> {
    for line in output.lines() {
        let toks: Vec<&str> = line.split_whitespace().collect();
        if toks.first() != Some(&"default") {
            continue;
        }
        let gw = toks.get(1)?;
        if gw.starts_with("link#") {
            continue;
        }
        return Some((*gw).to_string());
    }
    None
}

/// `route -q -n add -inet[6] <cidr> -interface <utunN>` - split-default leg.
#[cfg(any(target_os = "macos", test))]
fn macos_add_dev_route(cidr: &str, dev: &str, v6: bool) -> Vec<String> {
    vec![
        "route".into(),
        "-q".into(),
        "-n".into(),
        "add".into(),
        af_flag(v6).into(),
        cidr.into(),
        "-interface".into(),
        dev.into(),
    ]
}

/// `route -q -n add -inet[6] <ip> -gateway <gw>` - bridge bypass (bare host IP,
/// no /32; macOS treats a maskless address as a host route).
#[cfg(any(target_os = "macos", test))]
fn macos_add_host_route(ip: &str, gw: &str, v6: bool) -> Vec<String> {
    vec![
        "route".into(),
        "-q".into(),
        "-n".into(),
        "add".into(),
        af_flag(v6).into(),
        ip.into(),
        "-gateway".into(),
        gw.into(),
    ]
}

/// `route -q -n delete -inet[6] <dest>` - teardown (dest + family only).
#[cfg(any(target_os = "macos", test))]
fn macos_del_route(dest: &str, v6: bool) -> Vec<String> {
    vec![
        "route".into(),
        "-q".into(),
        "-n".into(),
        "delete".into(),
        af_flag(v6).into(),
        dest.into(),
    ]
}

// Pure argv builders (unit-tested) - Windows `netsh` (mirrors wireguard-windows).

/// `ipv4` / `ipv6` netsh sub-context.
#[cfg(any(target_os = "windows", test))]
fn netsh_family(v6: bool) -> &'static str {
    if v6 {
        "ipv6"
    } else {
        "ipv4"
    }
}

/// A PowerShell one-liner that prints `"<NextHop> <ifIndex>"` for the
/// lowest-metric physical default route of the given family. Parsed by
/// [`parse_windows_default`].
#[cfg(any(target_os = "windows", test))]
fn windows_show_default_cmd(v6: bool) -> Vec<String> {
    let (af, prefix) = if v6 {
        ("IPv6", "::/0")
    } else {
        ("IPv4", "0.0.0.0/0")
    };
    let script = format!(
        "Get-NetRoute -AddressFamily {af} -DestinationPrefix '{prefix}' | \
         Sort-Object InterfaceMetric | Select-Object -First 1 | \
         ForEach-Object {{ \"$($_.NextHop) $($_.ifIndex)\" }}"
    );
    vec![
        "powershell".into(),
        "-NoProfile".into(),
        "-Command".into(),
        script,
    ]
}

/// Parse `"<NextHop> <ifIndex>"` from the discovery one-liner. Rejects an
/// on-link (`0.0.0.0` / `::`) next hop - that has no usable gateway to pin a
/// bypass route to.
#[cfg(any(target_os = "windows", test))]
fn parse_windows_default(output: &str) -> Option<(String, String)> {
    let line = output.lines().map(str::trim).find(|l| !l.is_empty())?;
    let mut it = line.split_whitespace();
    let gw = it.next()?.to_string();
    let idx = it.next()?.to_string();
    if gw == "0.0.0.0" || gw == "::" || idx.is_empty() {
        return None;
    }
    Some((gw, idx))
}

/// `netsh interface ipv4 add route prefix=<p> interface=<tun> nexthop=<on-link>
/// metric=0 store=active` - split-default capture leg into the Wintun adapter.
/// On-link next hop (`0.0.0.0` / `::`) because the adapter is point-to-point.
/// `store=active` is MANDATORY (netsh defaults to persistent, which would
/// survive reboot and pollute the table).
#[cfg(any(target_os = "windows", test))]
fn windows_add_dev_route(prefix: &str, tun: &str, v6: bool) -> Vec<String> {
    let onlink = if v6 { "::" } else { "0.0.0.0" };
    vec![
        "netsh".into(),
        "interface".into(),
        netsh_family(v6).into(),
        "add".into(),
        "route".into(),
        format!("prefix={prefix}"),
        format!("interface={tun}"),
        format!("nexthop={onlink}"),
        "metric=0".into(),
        "store=active".into(),
    ]
}

/// `netsh ... delete route prefix=<p> interface=<tun> store=active` - teardown
/// of a capture leg.
#[cfg(any(target_os = "windows", test))]
fn windows_del_dev_route(prefix: &str, tun: &str, v6: bool) -> Vec<String> {
    vec![
        "netsh".into(),
        "interface".into(),
        netsh_family(v6).into(),
        "delete".into(),
        "route".into(),
        format!("prefix={prefix}"),
        format!("interface={tun}"),
        "store=active".into(),
    ]
}

/// `netsh ... add route prefix=<ip>/32 interface=<physIdx> nexthop=<realGw>
/// metric=1 store=active` - bridge bypass on the PHYSICAL interface via the real
/// gateway (a /32 beats the /1 capture by longest prefix).
#[cfg(any(target_os = "windows", test))]
fn windows_add_host_route(prefix: &str, phys_idx: &str, gw: &str, v6: bool) -> Vec<String> {
    vec![
        "netsh".into(),
        "interface".into(),
        netsh_family(v6).into(),
        "add".into(),
        "route".into(),
        format!("prefix={prefix}"),
        format!("interface={phys_idx}"),
        format!("nexthop={gw}"),
        "metric=1".into(),
        "store=active".into(),
    ]
}

/// `netsh ... delete route prefix=<ip>/32 interface=<physIdx> store=active` -
/// teardown of a bridge bypass. This route is on the PHYSICAL interface and does
/// NOT auto-clean when the Wintun adapter closes, so it MUST be deleted.
#[cfg(any(target_os = "windows", test))]
fn windows_del_route(prefix: &str, phys_idx: &str, v6: bool) -> Vec<String> {
    vec![
        "netsh".into(),
        "interface".into(),
        netsh_family(v6).into(),
        "delete".into(),
        "route".into(),
        format!("prefix={prefix}"),
        format!("interface={phys_idx}"),
        "store=active".into(),
    ]
}

// Execution (impure) - not exercised in CI.

/// Run `argv`, returning captured stdout. Errors if the process cannot be
/// spawned or exits non-zero.
fn run_capture(argv: &[String]) -> Result<String, TunError> {
    let (cmd, args) = argv
        .split_first()
        .ok_or_else(|| TunError::Io(std::io::Error::other("empty route command")))?;
    let out = std::process::Command::new(cmd)
        .args(args)
        .output()
        .map_err(|e| TunError::Io(std::io::Error::other(format!("spawn {cmd}: {e}"))))?;
    if !out.status.success() {
        return Err(TunError::Io(std::io::Error::other(format!(
            "`{}` failed: {}",
            argv.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        ))));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Run `argv` for its exit status only.
fn run_status(argv: &[String]) -> Result<(), TunError> {
    run_capture(argv).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ipv4_default_route() {
        let out = "default via 192.168.1.1 dev wlan0 proto dhcp metric 600\n";
        assert_eq!(
            parse_linux_default(out),
            Some(("192.168.1.1".into(), "wlan0".into()))
        );
    }

    #[test]
    fn parses_ipv6_default_route() {
        let out = "default via fe80::1 dev eth0 proto ra metric 1024 pref medium\n";
        assert_eq!(
            parse_linux_default(out),
            Some(("fe80::1".into(), "eth0".into()))
        );
    }

    #[test]
    fn parses_default_among_other_routes() {
        // `ip route show default` only lists defaults, but be robust anyway.
        let out = "10.0.0.0/24 dev eth0 scope link\n\
                   default via 10.0.0.1 dev eth0\n";
        assert_eq!(
            parse_linux_default(out),
            Some(("10.0.0.1".into(), "eth0".into()))
        );
    }

    #[test]
    fn no_default_returns_none() {
        assert_eq!(
            parse_linux_default("10.0.0.0/24 dev eth0 scope link\n"),
            None
        );
        assert_eq!(parse_linux_default(""), None);
        // A default with no gateway (on-link) has no via => not usable for
        // bridge exclusion.
        assert_eq!(parse_linux_default("default dev ppp0\n"), None);
    }

    #[test]
    fn split_default_covers_whole_v4_space() {
        // 0.0.0.0/1 + 128.0.0.0/1 partition all of IPv4 and both point at the tun.
        let a = linux_add_dev_route("0.0.0.0/1", "mirage0");
        let b = linux_add_dev_route("128.0.0.0/1", "mirage0");
        assert_eq!(a, ["ip", "route", "add", "0.0.0.0/1", "dev", "mirage0"]);
        assert_eq!(b, ["ip", "route", "add", "128.0.0.0/1", "dev", "mirage0"]);
    }

    #[test]
    fn bridge_exclusion_is_a_host_route_via_original_gw() {
        let cmd = linux_add_host_route("203.0.113.7/32", "192.168.1.1", "wlan0");
        assert_eq!(
            cmd,
            [
                "ip",
                "route",
                "add",
                "203.0.113.7/32",
                "via",
                "192.168.1.1",
                "dev",
                "wlan0"
            ]
        );
        // Its teardown deletes exactly that prefix.
        assert_eq!(
            linux_del_route("203.0.113.7/32"),
            ["ip", "route", "del", "203.0.113.7/32"]
        );
    }

    #[test]
    fn ipv6_split_default_and_exclusion_shapes() {
        assert_eq!(
            linux_add_dev_route6("::/1", "mirage0"),
            ["ip", "-6", "route", "add", "::/1", "dev", "mirage0"]
        );
        assert_eq!(
            linux_add_host_route6("2001:db8::1/128", "fe80::1", "eth0"),
            [
                "ip",
                "-6",
                "route",
                "add",
                "2001:db8::1/128",
                "via",
                "fe80::1",
                "dev",
                "eth0"
            ]
        );
        assert_eq!(
            linux_show_default_cmd(6),
            ["ip", "-6", "route", "show", "default"]
        );
    }

    // ---- macOS ----

    #[test]
    fn has_default_route_detects_on_link_default() {
        // Red-team #4/#7: an on-link (no `via`) default must still be detected so
        // v6 capture is not skipped, even though parse_*_default returns None.
        assert!(has_default_route("default via fe80::1 dev eth0\n"));
        assert!(has_default_route("default dev ppp0\n")); // on-link, no gateway
        assert!(has_default_route(
            "default            fe80::1%en0        UGcg          en0\n"
        )); // macOS netstat
        assert!(!has_default_route("2001:db8::/64 dev eth0 scope link\n"));
        assert!(!has_default_route(""));
        // Windows on-link default (nexthop ::) is still "exists" for capture.
        assert!(windows_default_exists(":: 8\n"));
        assert!(windows_default_exists("fe80::1 12\n"));
        assert!(!windows_default_exists("\n"));
        assert!(!windows_default_exists("onlyonetoken\n"));
    }

    #[test]
    fn macos_parses_default_gateway_and_rejects_onlink() {
        let v4 = "Routing tables\n\nInternet:\n\
                  Destination        Gateway            Flags        Netif Expire\n\
                  default            192.168.20.1       UGScg          en0\n\
                  127.0.0.1          127.0.0.1          UH             lo0\n";
        assert_eq!(parse_macos_default(v4), Some("192.168.20.1".into()));
        // v6 gateway keeps its %zone scope.
        let v6 = "Internet6:\ndefault    fe80::1%en0    UGcg    en0\n";
        assert_eq!(parse_macos_default(v6), Some("fe80::1%en0".into()));
        // An on-link (link#N) default has no next hop -> unusable for bypass.
        assert_eq!(parse_macos_default("default   link#12   UCS   en0\n"), None);
        assert_eq!(parse_macos_default("no default here\n"), None);
    }

    #[test]
    fn macos_route_shapes() {
        assert_eq!(
            macos_add_dev_route("0.0.0.0/1", "utun5", false),
            [
                "route",
                "-q",
                "-n",
                "add",
                "-inet",
                "0.0.0.0/1",
                "-interface",
                "utun5"
            ]
        );
        assert_eq!(
            macos_add_dev_route("::/1", "utun5", true),
            [
                "route",
                "-q",
                "-n",
                "add",
                "-inet6",
                "::/1",
                "-interface",
                "utun5"
            ]
        );
        // Bridge bypass: bare host IP (no /32), pinned by -gateway.
        assert_eq!(
            macos_add_host_route("203.0.113.7", "192.168.20.1", false),
            [
                "route",
                "-q",
                "-n",
                "add",
                "-inet",
                "203.0.113.7",
                "-gateway",
                "192.168.20.1"
            ]
        );
        assert_eq!(
            macos_del_route("128.0.0.0/1", false),
            ["route", "-q", "-n", "delete", "-inet", "128.0.0.0/1"]
        );
        assert_eq!(
            macos_show_default_cmd(true),
            ["netstat", "-nr", "-f", "inet6"]
        );
    }

    // ---- Windows ----

    #[test]
    fn windows_parses_gateway_and_ifindex_rejects_onlink() {
        assert_eq!(
            parse_windows_default("192.168.1.1 12\n"),
            Some(("192.168.1.1".into(), "12".into()))
        );
        assert_eq!(
            parse_windows_default("  fe80::1 8  \n"),
            Some(("fe80::1".into(), "8".into()))
        );
        // On-link nexthop (no gateway) is rejected.
        assert_eq!(parse_windows_default("0.0.0.0 12\n"), None);
        assert_eq!(parse_windows_default(":: 8\n"), None);
        assert_eq!(parse_windows_default("\n"), None);
    }

    #[test]
    fn windows_route_shapes_use_store_active() {
        // Capture leg: on-link nexthop into the tun, store=active mandatory.
        assert_eq!(
            windows_add_dev_route("0.0.0.0/1", "mirage0", false),
            [
                "netsh",
                "interface",
                "ipv4",
                "add",
                "route",
                "prefix=0.0.0.0/1",
                "interface=mirage0",
                "nexthop=0.0.0.0",
                "metric=0",
                "store=active"
            ]
        );
        assert_eq!(
            windows_add_dev_route("::/1", "mirage0", true),
            [
                "netsh",
                "interface",
                "ipv6",
                "add",
                "route",
                "prefix=::/1",
                "interface=mirage0",
                "nexthop=::",
                "metric=0",
                "store=active"
            ]
        );
        // Bridge bypass: /32 on the physical interface via the real gateway.
        assert_eq!(
            windows_add_host_route("203.0.113.7/32", "12", "192.168.1.1", false),
            [
                "netsh",
                "interface",
                "ipv4",
                "add",
                "route",
                "prefix=203.0.113.7/32",
                "interface=12",
                "nexthop=192.168.1.1",
                "metric=1",
                "store=active"
            ]
        );
        // Teardowns.
        assert_eq!(
            windows_del_dev_route("0.0.0.0/1", "mirage0", false),
            [
                "netsh",
                "interface",
                "ipv4",
                "delete",
                "route",
                "prefix=0.0.0.0/1",
                "interface=mirage0",
                "store=active"
            ]
        );
        assert_eq!(
            windows_del_route("203.0.113.7/32", "12", false),
            [
                "netsh",
                "interface",
                "ipv4",
                "delete",
                "route",
                "prefix=203.0.113.7/32",
                "interface=12",
                "store=active"
            ]
        );
        // Discovery command targets the right family + default prefix.
        assert!(windows_show_default_cmd(false)[3].contains("'0.0.0.0/0'"));
        assert!(windows_show_default_cmd(true)[3].contains("'::/0'"));
    }
}
