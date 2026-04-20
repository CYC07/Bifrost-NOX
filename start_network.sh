#!/bin/bash
# AI Firewall network layer — layers NFQUEUE inspection on top of an
# already-running hotspot (see ../wifi-hotspot.sh). Does NOT flush iptables.
#
# Failure mode is fail-open: --queue-bypass on every NFQUEUE rule means that
# if the C++ engine / ai_brain is not attached to queue 1, packets are
# ACCEPTED instead of dropped. So clients keep working even when the firewall
# is offline, and inspection kicks in automatically once the engine is up.

set -u

if [ "$EUID" -ne 0 ]; then
  echo "ERROR: run with sudo"
  exit 1
fi

HOTSPOT_IF="${HOTSPOT_IF:-wlan1}"
INTERNET_IF="${INTERNET_IF:-wlan0}"
QUEUE_NUM="${QUEUE_NUM:-1}"

echo "[1/3] Enabling IP forwarding..."
sysctl -w net.ipv4.ip_forward=1 >/dev/null

# Idempotent FORWARD NFQUEUE rules — inspect traffic flowing from the
# hotspot client (phone on wlan1) out to the upstream (wlan0).
add_fwd_rule() {
    local proto="$1" dport="$2"
    iptables -C FORWARD -i "$HOTSPOT_IF" -o "$INTERNET_IF" \
        -p "$proto" --dport "$dport" \
        -j NFQUEUE --queue-num "$QUEUE_NUM" --queue-bypass 2>/dev/null \
    || iptables -I FORWARD 1 -i "$HOTSPOT_IF" -o "$INTERNET_IF" \
        -p "$proto" --dport "$dport" \
        -j NFQUEUE --queue-num "$QUEUE_NUM" --queue-bypass
}

echo "[2/3] Installing FORWARD NFQUEUE traps ($HOTSPOT_IF -> $INTERNET_IF) on queue $QUEUE_NUM..."
add_fwd_rule udp 53   # DNS
add_fwd_rule tcp 21   # FTP

# Transparent proxy redirect for hotspot HTTPS/HTTP -> gateway on 8080.
# Idempotent: only added if missing.
echo "Redirecting hotspot HTTPS/HTTP to gateway (127.0.0.1:8080)..."
iptables -t nat -C PREROUTING -i "$HOTSPOT_IF" -p tcp --dport 443 -j REDIRECT --to-port 8080 2>/dev/null \
    || iptables -t nat -A PREROUTING -i "$HOTSPOT_IF" -p tcp --dport 443 -j REDIRECT --to-port 8080
iptables -t nat -C PREROUTING -i "$HOTSPOT_IF" -p tcp --dport 80  -j REDIRECT --to-port 8080 2>/dev/null \
    || iptables -t nat -A PREROUTING -i "$HOTSPOT_IF" -p tcp --dport 80  -j REDIRECT --to-port 8080

echo "Network layer rules applied (hotspot NAT/FORWARD from wifi-hotspot.sh is preserved)."

echo "[3/3] Starting inspection engine..."
echo "  -> AI Brain (ZMQ bridge)"
nohup python3 network_inspector/ai_brain.py > brain.log 2>&1 &
BRAIN_PID=$!
echo "     PID: $BRAIN_PID"
sleep 1

echo "  -> C++ Firewall Engine (binds NFQUEUE $QUEUE_NUM)"
# Background so callers (start_all.sh) aren't blocked. Stop via stop_all.sh
# or `sudo pkill -f firewall_engine`. Watch with `tail -f network.log`.
if [ "${FG:-0}" = "1" ]; then
    ./network_inspector/cpp/firewall_engine
else
    nohup ./network_inspector/cpp/firewall_engine > network.log 2>&1 &
    ENGINE_PID=$!
    echo "     PID: $ENGINE_PID (log: network.log)"
fi
