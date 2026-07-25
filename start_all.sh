#!/bin/bash
# Start the full AI Firewall stack.
#
# Modes (set via env var):
#   GNIREHTET_MODE=1  — phone connected via USB-C + gnirehtet (no USB NIC needed)
#                       tun0 = phone interface, wlan0 = internet uplink
#   (default)         — WiFi hotspot mode: wlan1 AP, wlan0 uplink
#
# Prerequisites (hotspot mode):
#   - Hotspot already up: `sudo ../wifi-hotspot.sh` (wlan1 in AP mode, 10.42.0.0/24)
#   - Python venv at ./venv with requirements installed
#   - C++ engine compiled: `cd network_inspector/cpp && make`
#
# Prerequisites (gnirehtet mode):
#   - adb installed, phone connected via USB-C with USB Debugging enabled
#   - gnirehtet binary in PATH or ./gnirehtet
#   - Run `gnirehtet start` before this script (creates tun0)

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
GNIREHTET_MODE="${GNIREHTET_MODE:-0}"

# Auto-detect gnirehtet mode: relay process running on port 31416.
if [ "$GNIREHTET_MODE" = "0" ] && (ss -tlnp 2>/dev/null | grep -q ':31416' || pgrep -f 'gnirehtet' &>/dev/null); then
    echo "  INFO: gnirehtet relay detected — switching to gnirehtet mode automatically"
    GNIREHTET_MODE=1
fi

echo "============================================="
echo "   STARTING AI FIREWALL"
echo "============================================="

# --- Preflight ---
echo "[0/4] Preflight checks..."

if [ "$GNIREHTET_MODE" = "1" ]; then
    # --- gnirehtet mode ---
    echo "  Mode: gnirehtet (USB-C tethering)"

    # Locate gnirehtet binary.
    _gnirehtet_bin=""
    for _g in gnirehtet ./gnirehtet ./gnirehtet-rust-linux64/gnirehtet; do
        if command -v "$_g" &>/dev/null || [ -x "$_g" ]; then
            _gnirehtet_bin="$_g"
            break
        fi
    done
    if [ -z "$_gnirehtet_bin" ]; then
        echo "  ERROR: gnirehtet binary not found. Download from:"
        echo "         https://github.com/Genymobile/gnirehtet/releases"
        echo "         Place in project root or add to PATH."
        exit 1
    fi
    echo "  OK: gnirehtet found at '$_gnirehtet_bin'"

    # ADB must be installed.
    if ! command -v adb &>/dev/null; then
        echo "  ERROR: adb not found. Install with:  sudo apt install adb"
        exit 1
    fi
    echo "  OK: adb installed"

    # Phone must be connected and authorised.
    _adb_devices=$(adb devices 2>/dev/null | grep -v "^List" | grep "device$")
    if [ -z "$_adb_devices" ]; then
        echo "  ERROR: no ADB device found. Check:"
        echo "         1. USB-C cable connected"
        echo "         2. USB Debugging enabled on phone"
        echo "         3. 'Allow USB Debugging' prompt accepted on phone"
        exit 1
    fi
    echo "  OK: ADB device connected"

    # gnirehtet relay is a userspace proxy — it does NOT create tun0.
    # Check the relay process is running (port 31416 listening).
    if ! ss -tlnp 2>/dev/null | grep -q ':31416' && ! pgrep -f 'gnirehtet' &>/dev/null; then
        echo "  ERROR: gnirehtet relay not running."
        echo "         Start it first:  $_gnirehtet_bin run"
        echo "         Then re-run this script."
        exit 1
    fi
    echo "  OK: gnirehtet relay running (port 31416)"

    HOTSPOT_IF="OUTPUT"
    INTERNET_IF="${INTERNET_IF:-wlan0}"
    echo "  Interfaces: client=$HOTSPOT_IF  uplink=$INTERNET_IF"

else
    # --- WiFi hotspot mode ---
    echo "  Mode: WiFi hotspot"

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
        if [ "$HOTSPOT_IF" = "wlan0" ]; then
            INTERNET_IF="${INTERNET_IF:-wlan1}"
        else
            INTERNET_IF="${INTERNET_IF:-wlan0}"
        fi
        echo "  OK: hotspot is up on $HOTSPOT_IF (uplink: $INTERNET_IF)"
    fi
fi

INTERNET_IF="${INTERNET_IF:-wlan0}"

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
