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
source venv/bin/activate

# Load .env if present (e.g. VIRUSTOTAL_API_KEY)
if [ -f .env ]; then
    set -a
    # shellcheck source=/dev/null
    source .env
    set +a
fi

HOTSPOT_IF="${HOTSPOT_IF:-wlan1}"

echo "============================================="
echo "   STARTING AI FIREWALL"
echo "============================================="

# --- Preflight ---
echo "[0/4] Preflight checks..."

_ap_iface=""
for _iface in "$HOTSPOT_IF" wlan0 wlan1; do
    if iw dev "$_iface" info 2>/dev/null | grep -q "type AP"; then
        _ap_iface="$_iface"
        break
    fi
done

if [ -z "$_ap_iface" ]; then
    echo "  WARN: neither wlan0 nor wlan1 is in AP mode. Start the hotspot first:"
    echo "        sudo /home/cyc0logy/wifi-hotspot.sh"
    read -r -p "  Continue anyway? [y/N] " ans
    case "$ans" in y|Y|yes) ;; *) exit 1;; esac
else
    HOTSPOT_IF="$_ap_iface"
    # Derive internet uplink as the other wlan interface.
    if [ "$HOTSPOT_IF" = "wlan0" ]; then
        INTERNET_IF="${INTERNET_IF:-wlan1}"
    else
        INTERNET_IF="${INTERNET_IF:-wlan0}"
    fi
    echo "  OK: hotspot is up on $HOTSPOT_IF (uplink: $INTERNET_IF)"
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

_start_svc() {
    local name="$1" module="$2" port="$3" log="$4"
    if pgrep -f "$module" >/dev/null; then
        echo "  $name already running — skipping"
    else
        nohup python3 -m uvicorn "$module" --host 0.0.0.0 --port "$port" > "$log" 2>&1 &
        echo "  $name PID: $! (log: $log)"
    fi
}

_start_svc "Orchestrator  " "master_ai.orchestrator:app"   8000 portal.log
_start_svc "Image service " "image_service.main:app"       8001 image.log
_start_svc "Document svc  " "document_service.main:app"    8002 document.log
_start_svc "Text service  " "text_service.main:app"        8003 text.log
sleep 2

# --- 2. Gateway MITM proxy ---
echo "[2/4] Starting Gateway Proxy (:8080)..."
if pgrep -f "gateway/proxy.py" >/dev/null; then
    echo "  already running — skipping"
else
    nohup env HOTSPOT_IF="$HOTSPOT_IF" python3 gateway/proxy.py > gateway.log 2>&1 &
    echo "  PID: $! (log: gateway.log)"
fi

# --- 3. Network layer (iptables + ai_brain + C++ engine) ---
# start_network.sh now backgrounds the C++ engine itself, so this returns.
echo "[3/4] Starting Network Layer (sudo)..."
sudo -E HOTSPOT_IF="$HOTSPOT_IF" INTERNET_IF="$INTERNET_IF" ./start_network.sh

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
