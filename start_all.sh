#!/bin/bash
# Start the full AI Firewall stack on top of an already-running hotspot.
#
# Prerequisites:
#   - Hotspot already up: `sudo ../wifi-hotspot.sh` (wlan1 in AP mode, 10.42.0.0/24)
#   - Python venv at ./venv with requirements installed
#   - C++ engine compiled: `cd network_inspector/cpp && make`

set -u
cd "$(dirname "$0")"

# shellcheck source=/dev/null
source /home/cyc0logy/FYP/ai_firewall/venv/bin/activate

HOTSPOT_IF="${HOTSPOT_IF:-wlan1}"

echo "============================================="
echo "   STARTING AI FIREWALL"
echo "============================================="

# --- Preflight ---
echo "[0/4] Preflight checks..."

if ! iw dev "$HOTSPOT_IF" info 2>/dev/null | grep -q "type AP"; then
    echo "  WARN: $HOTSPOT_IF is not in AP mode. Start the hotspot first:"
    echo "        sudo /home/cyc0logy/wifi-hotspot.sh"
    read -r -p "  Continue anyway? [y/N] " ans
    case "$ans" in y|Y|yes) ;; *) exit 1;; esac
else
    echo "  OK: hotspot is up on $HOTSPOT_IF"
fi

if [ ! -x ./network_inspector/cpp/firewall_engine ]; then
    echo "  ERROR: C++ engine not built. Run:  cd network_inspector/cpp && make"
    exit 1
fi
echo "  OK: firewall_engine binary present"

# Cache sudo now so the network step doesn't prompt mid-flight.
sudo -v || { echo "sudo required"; exit 1; }

# --- 1. AI microservices ---
echo "[1/4] Starting AI microservices (orchestrator + image/text/document)..."
./start_services.sh

# --- 2. Gateway MITM proxy ---
echo "[2/4] Starting Gateway Proxy (:8080)..."
if pgrep -f "gateway/proxy.py" >/dev/null; then
    echo "  already running — skipping"
else
    nohup python3 gateway/proxy.py > gateway.log 2>&1 &
    echo "  PID: $! (log: gateway.log)"
fi

# --- 3. Network layer (iptables + ai_brain + C++ engine) ---
# start_network.sh now backgrounds the C++ engine itself, so this returns.
echo "[3/4] Starting Network Layer (sudo)..."
sudo -E HOTSPOT_IF="$HOTSPOT_IF" ./start_network.sh

# --- 4. Summary ---
sleep 1
echo "[4/4] Status:"
pgrep -af 'uvicorn|gateway/proxy.py|ai_brain.py|firewall_engine' | sed 's/^/      /'

echo "============================================="
echo "   SYSTEM RUNNING"
echo "============================================="
echo "Logs:"
echo "  - portal.log        (microservices / master)"
echo "  - gateway.log       (MITM proxy)"
echo "  - brain.log         (AI brain / ZMQ bridge)"
echo "  - network.log       (C++ firewall engine)"
echo ""
echo "Stop with:  sudo ./stop_all.sh"
