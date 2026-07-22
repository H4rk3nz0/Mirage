#!/usr/bin/env bash
# mirage-jail - fail-closed network-namespace confinement for a Mirage client.
#
# The kill switch (mirage-killswitch) drops leaks with host firewall rules; this
# is the stronger primitive: it runs the client + your apps inside a dedicated
# network namespace whose ONLY routable destinations are the Mirage bridge
# IP(s). Everything else has no route at all, so a WebRTC dial, the OS resolver,
# OCSP, telemetry, or an app that ignores the proxy fails with "network
# unreachable" - leak-proof BY CONSTRUCTION, not by a firewall rule that might
# have a gap. It is the interim confinement until the full TUN VPN (mirage-tun).
#
# Model:
#   [ netns "mirage-jail" ]                      [ host ]
#     lo (client SOCKS here) ----.
#     veth-mj (10.200.200.2/30) --+-- veth-mj-h (10.200.200.1/30) -- NAT -> bridge IP(s)
#     route: ONLY <bridge-ip>/32 via 10.200.200.1   (NO default route)
#
#   -> the client (in the netns) reaches the bridge and nothing else;
#   -> your browser (in the netns) can only egress through the client's SOCKS;
#   -> any non-bridge packet has no route and is dropped by the kernel.
#
# Usage:
#   sudo mirage-jail up   --bridge <ip[,ip...]>                # create the jail
#   sudo mirage-jail run  --bridge <ip[,ip...]> -- <cmd...>    # up + exec + down
#   sudo mirage-jail exec  -- <cmd...>                         # exec in a live jail
#   sudo mirage-jail down                                      # tear down
#   sudo mirage-jail status
#
# Example (two terminals, or use `run`):
#   sudo mirage-jail up --bridge 203.0.113.7
#   sudo ip netns exec mirage-jail sudo -u "$USER" mirage-client --config client.json &
#   sudo ip netns exec mirage-jail sudo -u "$USER" env http_proxy= firefox   # SOCKS5h 127.0.0.1:1080
#   sudo mirage-jail down
#
# Requires: root, iproute2 (ip), nftables (nft) for host NAT. IPv4 bridges.
# Idempotent: re-running `up` tears down a stale jail first.

set -euo pipefail

NS="mirage-jail"
VETH_HOST="veth-mj-h"
VETH_NS="veth-mj"
SUBNET="10.200.200"
HOST_IP="${SUBNET}.1"
NS_IP="${SUBNET}.2"
PREFIX="30"
NFT_TABLE="mirage_jail_nat"

die() { echo "mirage-jail: $*" >&2; exit 1; }
need_root() { [ "$(id -u)" -eq 0 ] || die "must run as root (use sudo)"; }
have() { command -v "$1" >/dev/null 2>&1; }

# ---- argument parsing ------------------------------------------------------

BRIDGES=""
CMD=()
parse_common() {
  while [ $# -gt 0 ]; do
    case "$1" in
      --bridge) shift; [ $# -gt 0 ] || die "--bridge needs ip[,ip...]"; BRIDGES="$1" ;;
      --) shift; CMD=("$@"); return 0 ;;
      *) die "unknown argument: $1" ;;
    esac
    shift
  done
}

validate_ipv4() {
  local ip="$1"
  [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || die "not an IPv4 address: '$ip' (mirage-jail v1 takes bridge IPs, not hostnames)"
  local o; IFS='.' read -ra o <<<"$ip"
  for n in "${o[@]}"; do [ "$n" -le 255 ] || die "invalid IPv4 octet in '$ip'"; done
}

# ---- lifecycle -------------------------------------------------------------

default_uplink() {
  # The host interface with the default route - used as the NAT egress oif.
  ip route show default 2>/dev/null | awk '/default/ {for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}'
}

jail_up() {
  need_root
  have ip || die "iproute2 (ip) not found"
  have nft || die "nftables (nft) not found - needed for host NAT"
  [ -n "$BRIDGES" ] || die "up requires --bridge <ip[,ip...]>"

  local uplink; uplink="$(default_uplink)"
  [ -n "$uplink" ] || die "no default-route interface found (no uplink to NAT through)"

  # Idempotent: clear any stale jail first.
  jail_down_quiet

  # 1. Namespace + veth pair.
  ip netns add "$NS"
  ip link add "$VETH_HOST" type veth peer name "$VETH_NS"
  ip link set "$VETH_NS" netns "$NS"

  # 2. Address the link.
  ip addr add "${HOST_IP}/${PREFIX}" dev "$VETH_HOST"
  ip link set "$VETH_HOST" up
  ip netns exec "$NS" ip addr add "${NS_IP}/${PREFIX}" dev "$VETH_NS"
  ip netns exec "$NS" ip link set "$VETH_NS" up
  ip netns exec "$NS" ip link set lo up

  # 3. Fail-closed routing: NO default route. Add a /32 route to each bridge
  #    IP via the host end. Everything else in the netns is unroutable.
  IFS=',' read -ra BR <<<"$BRIDGES"
  for ip in "${BR[@]}"; do
    validate_ipv4 "$ip"
    ip netns exec "$NS" ip route add "${ip}/32" via "$HOST_IP" dev "$VETH_NS"
  done

  # 4. Empty resolver inside the jail: local DNS must fail (apps use the
  #    client's SOCKS5h for remote resolution through the tunnel). This blocks
  #    the classic OS-resolver leak.
  mkdir -p "/etc/netns/${NS}"
  : > "/etc/netns/${NS}/resolv.conf"

  # 5. Host NAT so the netns->bridge packets egress with the host IP, plus
  #    forwarding. NAT is scoped to the jail subnet and only to bridge IPs.
  sysctl -q -w net.ipv4.ip_forward=1
  nft add table ip "$NFT_TABLE"
  nft add chain ip "$NFT_TABLE" postrouting "{ type nat hook postrouting priority 100 ; }"
  for ip in "${BR[@]}"; do
    nft add rule ip "$NFT_TABLE" postrouting ip saddr "${SUBNET}.0/${PREFIX}" ip daddr "$ip" oifname "$uplink" masquerade
  done
  # Allow forwarding jail<->uplink for the bridge flows (in case a restrictive
  # host FORWARD policy is set).
  nft add chain ip "$NFT_TABLE" forward "{ type filter hook forward priority 0 ; }"
  nft add rule ip "$NFT_TABLE" forward iifname "$VETH_HOST" oifname "$uplink" accept
  nft add rule ip "$NFT_TABLE" forward iifname "$uplink" oifname "$VETH_HOST" ct state established,related accept

  echo "mirage-jail: up. netns=$NS bridge(s)=$BRIDGES uplink=$uplink"
  echo "  run the client + apps inside it, e.g.:"
  echo "    sudo ip netns exec $NS sudo -u \"\$USER\" mirage-client --config client.json"
  echo "    sudo ip netns exec $NS sudo -u \"\$USER\" firefox   # point at SOCKS5h 127.0.0.1:1080"
}

jail_down_quiet() {
  ip netns del "$NS" 2>/dev/null || true
  ip link del "$VETH_HOST" 2>/dev/null || true
  nft delete table ip "$NFT_TABLE" 2>/dev/null || true
  rm -f "/etc/netns/${NS}/resolv.conf" 2>/dev/null || true
  rmdir "/etc/netns/${NS}" 2>/dev/null || true
}

jail_down() {
  need_root
  jail_down_quiet
  echo "mirage-jail: down. netns + veth + NAT removed."
}

jail_exec() {
  need_root
  ip netns list 2>/dev/null | grep -qw "$NS" || die "jail '$NS' is not up (run 'mirage-jail up' first)"
  [ "${#CMD[@]}" -gt 0 ] || die "exec needs a command after '--'"
  exec ip netns exec "$NS" "${CMD[@]}"
}

jail_run() {
  need_root
  [ "${#CMD[@]}" -gt 0 ] || die "run needs a command after '--'"
  # Ensure teardown even if setup or the command fails / is interrupted.
  trap 'jail_down_quiet' EXIT
  jail_up
  set +e
  ip netns exec "$NS" "${CMD[@]}"
  local rc=$?
  set -e
  trap - EXIT
  jail_down_quiet
  echo "mirage-jail: run finished (exit $rc); jail torn down."
  exit "$rc"
}

jail_status() {
  if ip netns list 2>/dev/null | grep -qw "$NS"; then
    echo "mirage-jail: UP (netns '$NS')"
    echo "  routes inside the jail (bridge-only; no default route = fail-closed):"
    ip netns exec "$NS" ip route show 2>/dev/null | sed 's/^/    /'
    echo "  host NAT table:"
    nft list table ip "$NFT_TABLE" 2>/dev/null | sed 's/^/    /' || echo "    (none)"
  else
    echo "mirage-jail: down"
  fi
}

# ---- dispatch --------------------------------------------------------------

[ $# -ge 1 ] || { echo "usage: mirage-jail {up|run|exec|down|status} ..." >&2; exit 2; }
sub="$1"; shift
case "$sub" in
  up)     parse_common "$@"; jail_up ;;
  run)    parse_common "$@"; jail_run ;;
  exec)   parse_common "$@"; jail_exec ;;
  down)   jail_down ;;
  status) jail_status ;;
  *) die "unknown subcommand '$sub' (want up|run|exec|down|status)" ;;
esac
