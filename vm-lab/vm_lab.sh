#!/bin/bash
# Lab glue: route VirtualBox host-only net (vboxnet0) through the AI firewall.
#   sudo ~/FYP/vm-lab/vm_lab.sh up      # host IP, forwarding, NAT, firewall layer
#   sudo ~/FYP/vm-lab/vm_lab.sh down    # remove what 'up' added, stop engine/brain
# Prereq: uvicorn services (:8000-8003) and gateway/proxy.py (:8080) already running.
set -eu

REPO="${REPO:-/home/pentest/FYP/ai_firewall}"
LAB_IF="${LAB_IF:-vboxnet0}"
LAB_NET="${LAB_NET:-192.168.56.0/24}"
LAB_IP="${LAB_IP:-192.168.56.1/24}"
UPLINK="${UPLINK:-wlan0}"

[ "$EUID" -eq 0 ] || { echo "run with sudo"; exit 1; }

ipt() { # idempotent add: ipt <table> <chain> <rule...>
    local t="$1" c="$2"; shift 2
    iptables -t "$t" -C "$c" "$@" 2>/dev/null || iptables -t "$t" -A "$c" "$@"
}
ipt_del() { local t="$1" c="$2"; shift 2; while iptables -t "$t" -C "$c" "$@" 2>/dev/null; do iptables -t "$t" -D "$c" "$@"; done; }

case "${1:-}" in
up)
    # NetworkManager otherwise DHCPs the *host* side of vboxnet0 (grabbing a lease
    # from VBox's own DHCP server) and installs a metric-100 default route via it.
    # On this box the culprit is systemd-networkd (20-ethernet.network: Type=ether,
    # DHCP=yes, RouteMetric=100 matches vboxnet*). Exclude it, and NM for good measure.
    if [ ! -f /etc/systemd/network/10-vboxnet-lab.network ]; then
        printf '[Match]\nName=vboxnet*\n\n[Link]\nUnmanaged=yes\n' > /etc/systemd/network/10-vboxnet-lab.network
        networkctl reload 2>/dev/null || systemctl restart systemd-networkd
        sleep 1
    fi
    nmcli device set "$LAB_IF" managed no 2>/dev/null || true
    ip addr flush dev "$LAB_IF"
    ip addr add "$LAB_IP" dev "$LAB_IF"
    ip link set "$LAB_IF" up
    sysctl -w net.ipv4.ip_forward=1 >/dev/null
    ipt nat    POSTROUTING -s "$LAB_NET" -o "$UPLINK" -j MASQUERADE
    ipt filter FORWARD -i "$LAB_IF" -o "$UPLINK" -j ACCEPT
    ipt filter FORWARD -i "$UPLINK" -o "$LAB_IF" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    ipt filter INPUT   -i "$LAB_IF" -j ACCEPT
    cd "$REPO"
    # start_network.sh calls bare python3 -> must be the venv one (zmq/requests)
    env HOTSPOT_IF="$LAB_IF" INTERNET_IF="$UPLINK" PATH="$REPO/venv/bin:$PATH" ./start_network.sh
    echo; echo "UP. VM gateway = ${LAB_IP%/*}; CA cert: http://${LAB_IP%/*}:8000/ca.crt"
    ;;
down)
    pkill -f firewall_engine || true
    pkill -f network_inspector/ai_brain.py || true
    sleep 1
    ipt_del nat    PREROUTING -i "$LAB_IF" -p tcp --dport 443 -j REDIRECT --to-port 8080
    ipt_del nat    PREROUTING -i "$LAB_IF" -p tcp --dport 80  -j REDIRECT --to-port 8080
    ipt_del filter FORWARD -i "$LAB_IF" -o "$UPLINK" -p udp --dport 53 -j NFQUEUE --queue-num 1 --queue-bypass
    ipt_del filter FORWARD -i "$LAB_IF" -o "$UPLINK" -p tcp --dport 21 -j NFQUEUE --queue-num 1 --queue-bypass
    ipt_del nat    POSTROUTING -s "$LAB_NET" -o "$UPLINK" -j MASQUERADE
    ipt_del filter FORWARD -i "$LAB_IF" -o "$UPLINK" -j ACCEPT
    ipt_del filter FORWARD -i "$UPLINK" -o "$LAB_IF" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    ipt_del filter INPUT   -i "$LAB_IF" -j ACCEPT
    sysctl -w net.ipv4.ip_forward=0 >/dev/null
    echo "DOWN. Rules removed (uvicorn services + proxy left running)."
    ;;
*) echo "usage: sudo $0 up|down"; exit 2 ;;
esac
