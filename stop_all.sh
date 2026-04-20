#!/bin/bash
# Stop AI Firewall — non-interactive, idempotent, thorough.
# Removes ONLY the iptables rules this project installed. Does NOT flush
# iptables; the hotspot NAT/FORWARD rules from wifi-hotspot.sh are preserved.
#
# Usage:
#   sudo ./stop_all.sh              # stop processes + remove our iptables rules
#   sudo ./stop_all.sh --keep-net   # stop processes only, leave rules intact

set -u

if [ "$EUID" -ne 0 ]; then
  echo "ERROR: run with sudo"
  exit 1
fi

HOTSPOT_IF="${HOTSPOT_IF:-wlan1}"
INTERNET_IF="${INTERNET_IF:-wlan0}"
QUEUE_NUM="${QUEUE_NUM:-1}"

KEEP_NET=0
for arg in "$@"; do
    case "$arg" in
        --keep-net|--services-only) KEEP_NET=1 ;;
        -h|--help)
            echo "Usage: sudo $0 [--keep-net]"
            echo "  --keep-net   Stop processes only, leave iptables rules intact."
            exit 0
            ;;
        *)
            echo "Unknown argument: $arg"
            echo "Usage: sudo $0 [--keep-net]"
            exit 1
            ;;
    esac
done

# SIGTERM a process pattern, wait up to 3s, then SIGKILL if needed.
stop_pattern() {
    local label="$1" pattern="$2"
    if ! pgrep -f "$pattern" >/dev/null; then
        return 0
    fi
    echo "  stopping $label..."
    pkill -TERM -f "$pattern" 2>/dev/null || true
    for _ in 1 2 3 4 5 6; do
        pgrep -f "$pattern" >/dev/null || return 0
        sleep 0.5
    done
    echo "    still alive after SIGTERM — sending SIGKILL"
    pkill -KILL -f "$pattern" 2>/dev/null || true
    sleep 0.5
}

echo "============================================="
echo "       AI FIREWALL STOP"
echo "============================================="

echo "[1/3] Stopping processes..."
# Order matters: kill the C++ engine first so NFQUEUE releases before we
# remove its iptables rule. Then brain/proxy/uvicorn.
stop_pattern "C++ Firewall Engine"   "firewall_engine"
stop_pattern "AI Brain"              "network_inspector/ai_brain.py"
stop_pattern "Gateway Proxy"         "gateway/proxy.py"
stop_pattern "AI Microservices"      "uvicorn"

if pgrep -af 'uvicorn|gateway/proxy.py|ai_brain.py|firewall_engine' >/dev/null; then
    echo "  WARN: some processes survived:"
    pgrep -af 'uvicorn|gateway/proxy.py|ai_brain.py|firewall_engine' | sed 's/^/    /'
fi

# Remove a rule repeatedly until it's gone (handles accidental duplicates).
del_rule() {
    local table_args=()
    if [ "$1" = "-t" ]; then
        table_args=(-t "$2"); shift 2
    fi
    local chain="$1"; shift
    while iptables "${table_args[@]}" -C "$chain" "$@" 2>/dev/null; do
        iptables "${table_args[@]}" -D "$chain" "$@" 2>/dev/null || break
    done
}

if [ "$KEEP_NET" -eq 1 ]; then
    echo "[2/3] --keep-net: iptables rules left intact."
    echo "[3/3] Done (services stopped, network untouched)."
    exit 0
fi

echo "[2/3] Removing iptables rules we installed..."

# CRITICAL: PREROUTING REDIRECTs. If these outlive the proxy, hotspot clients
# lose all HTTP/HTTPS connectivity (packets land on an unbound port).
del_rule -t nat PREROUTING -i "$HOTSPOT_IF" -p tcp --dport 443 -j REDIRECT --to-port 8080
del_rule -t nat PREROUTING -i "$HOTSPOT_IF" -p tcp --dport 80  -j REDIRECT --to-port 8080

# FORWARD NFQUEUE (DNS + FTP inspection).
del_rule FORWARD -i "$HOTSPOT_IF" -o "$INTERNET_IF" -p udp --dport 53 \
    -j NFQUEUE --queue-num "$QUEUE_NUM" --queue-bypass
del_rule FORWARD -i "$HOTSPOT_IF" -o "$INTERNET_IF" -p tcp --dport 21 \
    -j NFQUEUE --queue-num "$QUEUE_NUM" --queue-bypass

# Legacy INPUT/OUTPUT NFQUEUE rules from earlier versions of start_network.sh.
del_rule INPUT  -p udp --dport 53 -j NFQUEUE --queue-num "$QUEUE_NUM"
del_rule OUTPUT -p udp --dport 53 -j NFQUEUE --queue-num "$QUEUE_NUM"
del_rule INPUT  -p tcp --dport 21 -j NFQUEUE --queue-num "$QUEUE_NUM"
del_rule OUTPUT -p tcp --dport 21 -j NFQUEUE --queue-num "$QUEUE_NUM"

echo "[3/3] Verifying..."
fail=0

# The big one — if any REDIRECT to 8080 is still in PREROUTING, clients break.
if iptables -t nat -S PREROUTING | grep -E "REDIRECT .*(--to-ports?|--to-port) 8080" >/dev/null; then
    echo "  FAIL: PREROUTING still has a REDIRECT -> 8080. Clients will have no web:"
    iptables -t nat -S PREROUTING | grep -E "REDIRECT .*8080" | sed 's/^/    /'
    fail=1
fi

if iptables -S FORWARD | grep -E "NFQUEUE --queue-num $QUEUE_NUM" >/dev/null; then
    echo "  WARN: FORWARD still has NFQUEUE rules on queue $QUEUE_NUM:"
    iptables -S FORWARD | grep "NFQUEUE" | sed 's/^/    /'
    fail=1
fi

if [ "$fail" -eq 0 ]; then
    echo "  OK: our rules are gone. Hotspot NAT/FORWARD preserved."
    echo "Done."
else
    echo ""
    echo "Some rules could not be removed automatically. To see what's left:"
    echo "  sudo iptables -t nat -S PREROUTING"
    echo "  sudo iptables -S FORWARD"
    exit 1
fi
