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

# Everything below uses repo-relative paths; make that true wherever the script is called from.
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_DIR" || exit 1
# shellcheck source=network_inspector/venv_python.sh
source "$REPO_DIR/network_inspector/venv_python.sh"
source "$REPO_DIR/network_inspector/quic_rule.sh"

# Absolute venv interpreter, resolved BEFORE any firewall rule is touched: under sudo a bare python3 is the
# system one, which has no zmq (the brain died at import and the engine then stalled DNS). To use another
# interpreter run:  sudo PYTHON=/abs/path/to/python ./start_network.sh   (sudo resets the environment otherwise)
PYTHON="$(resolve_venv_python "$REPO_DIR")" || exit 1

# Auto-detect which wlan is in AP mode if not supplied by caller.
_ap_iface=""
for _iface in "${HOTSPOT_IF:-wlan1}" wlan0 wlan1; do
    if iw dev "$_iface" info 2>/dev/null | grep -q "type AP"; then
        _ap_iface="$_iface"
        break
    fi
done
if [ -n "$_ap_iface" ]; then
    HOTSPOT_IF="$_ap_iface"
else
    HOTSPOT_IF="${HOTSPOT_IF:-wlan1}"
fi

# Derive internet uplink as the other wlan if not explicitly set.
if [ -z "${INTERNET_IF:-}" ]; then
    if [ "$HOTSPOT_IF" = "wlan0" ]; then
        INTERNET_IF="wlan1"
    else
        INTERNET_IF="wlan0"
    fi
fi
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

# QUIC (HTTP/3, UDP 443) is not covered by the TCP redirect below: a browser that has learned a site supports HTTP/3
# would talk to it directly and nothing would be inspected. Refuse it so browsers fall back to TCP (BLOCK_QUIC=0 = off).
echo "Refusing QUIC (UDP 443) from $HOTSPOT_IF so browsers fall back to inspected TCP..."
block_quic "$HOTSPOT_IF"

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
echo "     python: $PYTHON"
nohup "$PYTHON" network_inspector/ai_brain.py > brain.log 2>&1 &
BRAIN_PID=$!
echo "     PID: $BRAIN_PID"
sleep 1
if ! kill -0 "$BRAIN_PID" 2>/dev/null; then
    echo "ERROR: AI Brain exited during startup; not starting the engine. Last lines of brain.log:" >&2
    tail -n 15 brain.log >&2
    exit 1
fi

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
