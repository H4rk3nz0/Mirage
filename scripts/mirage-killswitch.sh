#!/usr/bin/env bash
# mirage-killswitch - fail-closed egress lock for a Mirage client (Linux/nftables).
#
# The Mirage client is a local SOCKS5 proxy: it does NOT stop non-proxied traffic
# (a browser misconfig, the OS resolver, WebRTC, OCSP, telemetry, or the startup
# window before the tunnel is up) from egressing on your REAL IP. This installs a
# host firewall that DROPS all outbound traffic except:
#   - loopback (the client's SOCKS listener lives here)
#   - established/related return traffic
#   - the Mirage bridge endpoint(s) you allow (the tunnel's only real egress)
#   - optionally your LAN, and a resolver if you must resolve the bridge by name
#
# Result: if the tunnel is down or an app bypasses the proxy, the packet is
# dropped, not sent in the clear. This is the interim fail-closed floor until the
# full TUN VPN mode (mirage-tun) lands.
#
# Usage:
#   sudo mirage-killswitch on  --bridge <ip[,ip...]> [--allow-lan] [--dns <ip[,ip...]>]
#   sudo mirage-killswitch on  --config <client.json>  [--allow-lan] [--dns ...]
#   sudo mirage-killswitch off
#   sudo mirage-killswitch status
#
# Requires: nftables (nft), root. Handles IPv4 + IPv6. Idempotent.

set -euo pipefail

TABLE="mirage_killswitch"

die() { echo "mirage-killswitch: $*" >&2; exit 1; }

need_root() { [ "$(id -u)" -eq 0 ] || die "must run as root (nftables needs CAP_NET_ADMIN)"; }
need_nft()  { command -v nft >/dev/null 2>&1 || die "nft (nftables) not found; install nftables"; }

# Extract "host:port" bridge endpoints from a client.json (invite is opaque, so
# we read the explicit bridge_addr / endpoint hints if present; otherwise the
# operator passes --bridge explicitly). Prints one IP per line.
ips_from_config() {
    local cfg="$1"
    [ -f "$cfg" ] || die "config not found: $cfg"
    # Pull any dotted-quad or bracketed v6 host from bridge-ish fields. This is a
    # best-effort convenience; --bridge is authoritative.
    grep -oE '"(bridge_addr|endpoint|shadow_target)"[[:space:]]*:[[:space:]]*"[^"]+"' "$cfg" 2>/dev/null \
        | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+|\[[0-9a-fA-F:]+\]' \
        | tr -d '[]' | sort -u
}

split_csv() { echo "$1" | tr ',' '\n' | sed '/^$/d'; }

is_v6() { case "$1" in *:*) return 0;; *) return 1;; esac; }

cmd_on() {
    local bridges="" dns="" allow_lan=0 config=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --bridge)   bridges="$2"; shift 2;;
            --dns)      dns="$2"; shift 2;;
            --config)   config="$2"; shift 2;;
            --allow-lan) allow_lan=1; shift;;
            *) die "unknown arg: $1";;
        esac
    done

    local ips=""
    [ -n "$bridges" ] && ips="$(split_csv "$bridges")"
    if [ -n "$config" ]; then
        ips="$ips"$'\n'"$(ips_from_config "$config")"
    fi
    ips="$(echo "$ips" | sed '/^$/d' | sort -u)"
    [ -n "$ips" ] || die "no bridge IPs given. Pass --bridge <ip[,ip...]> (an invite is opaque; use the bridge's real IP)."

    # Partition allow-lists into v4/v6 for nft set elements.
    local v4="" v6=""
    local ip
    for ip in $ips; do
        if is_v6 "$ip"; then v6="$v6 $ip,"; else v4="$v4 $ip,"; fi
    done
    local dns_v4="" dns_v6=""
    if [ -n "$dns" ]; then
        for ip in $(split_csv "$dns"); do
            if is_v6 "$ip"; then dns_v6="$dns_v6 $ip,"; else dns_v4="$dns_v4 $ip,"; fi
        done
    fi

    # Private ranges for --allow-lan.
    local lan_v4="10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16"
    local lan_v6="fc00::/7, fe80::/10"

    cmd_off  # idempotent: clear any prior instance first

    nft -f - <<NFT
table inet ${TABLE} {
    set allow4 { type ipv4_addr; flags interval;${v4:+ elements = {${v4% ,} }} }
    set allow6 { type ipv6_addr; flags interval;${v6:+ elements = {${v6% ,} }} }
    set dns4   { type ipv4_addr;${dns_v4:+ elements = {${dns_v4% ,} }} }
    set dns6   { type ipv6_addr;${dns_v6:+ elements = {${dns_v6% ,} }} }

    chain output {
        type filter hook output priority 100; policy drop;
        oif "lo" accept
        ct state established,related accept
        ip  daddr @allow4 accept
        ip6 daddr @allow6 accept
        ip  daddr @dns4 udp dport 53 accept
        ip  daddr @dns4 tcp dport 53 accept
        ip6 daddr @dns6 udp dport 53 accept
        ip6 daddr @dns6 tcp dport 53 accept
$( [ "$allow_lan" -eq 1 ] && printf '        ip  daddr { %s } accept\n        ip6 daddr { %s } accept\n' "$lan_v4" "$lan_v6" )
        counter comment "dropped-leak"
    }
}
NFT
    echo "mirage-killswitch: ON. Egress restricted to loopback + bridge IPs$( [ "$allow_lan" -eq 1 ] && echo ' + LAN')$( [ -n "$dns" ] && echo ' + DNS' ):"
    echo "$ips" | sed 's/^/    bridge: /'
    echo "  Everything else is DROPPED (fail-closed). Turn off with: sudo mirage-killswitch off"
}

cmd_off() {
    if nft list table inet "${TABLE}" >/dev/null 2>&1; then
        nft delete table inet "${TABLE}"
        echo "mirage-killswitch: OFF (egress lock removed)."
    else
        echo "mirage-killswitch: not active."
    fi
}

cmd_status() {
    if nft list table inet "${TABLE}" >/dev/null 2>&1; then
        echo "mirage-killswitch: ACTIVE"
        nft list table inet "${TABLE}"
    else
        echo "mirage-killswitch: inactive (traffic is NOT leak-protected)"
    fi
}

main() {
    need_nft
    local action="${1:-}"
    case "$action" in
        on)     shift; need_root; cmd_on "$@";;
        off)    need_root; cmd_off;;
        status) cmd_status;;
        ""|-h|--help)
            sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'
            ;;
        *) die "unknown action '$action' (use: on | off | status)";;
    esac
}

main "$@"
