#!/bin/bash
# Start the AI services (:8000-8003) and the gateway (:8080) WITHOUT touching the network.
#
#   ./start_services.sh            # then, for the VM lab:  sudo vm-lab/vm_lab.sh up
#   DRY_RUN=1 ./start_services.sh  # print what would be started
#
# start_all.sh does the same plus the Wi-Fi hotspot network layer. Anything already running is left alone.
# sudo is not needed. Logs go to portal.log, image.log, document.log, text.log and gateway.log in the repo root.
set -u

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_DIR" || exit 1
# shellcheck source=network_inspector/venv_python.sh
source "$REPO_DIR/network_inspector/venv_python.sh"
PYTHON="$(resolve_venv_python "$REPO_DIR")" || exit 1
if [ -f .env ]; then set -a; source .env; set +a; fi

start() {   # start <name> <pgrep pattern> <log file> <command...>
    local name="$1" pattern="$2" log="$3"
    shift 3
    if pgrep -f "$pattern" >/dev/null 2>&1; then
        echo "  $name already running"
        return 0
    fi
    if [ "${DRY_RUN:-0}" = "1" ]; then
        echo "  would start $name: $* > $log"
        return 0
    fi
    nohup "$@" > "$log" 2>&1 &
    echo "  $name PID $! (log: $log)"
}

echo "Starting the AI services and the gateway (python: $PYTHON)"
start "orchestrator"     "master_ai.orchestrator" portal.log   "$PYTHON" -m uvicorn master_ai.orchestrator:app --host 0.0.0.0 --port 8000
start "image service"    "image_service.main"     image.log    "$PYTHON" -m uvicorn image_service.main:app --host 0.0.0.0 --port 8001
start "document service" "document_service.main"  document.log "$PYTHON" -m uvicorn document_service.main:app --host 0.0.0.0 --port 8002
start "text service"     "text_service.main"      text.log     "$PYTHON" -m uvicorn text_service.main:app --host 0.0.0.0 --port 8003
start "gateway"          "gateway/proxy.py"       gateway.log  "$PYTHON" gateway/proxy.py

[ "${DRY_RUN:-0}" = "1" ] && exit 0

echo "Waiting for the dashboard (:8000) and the gateway (:8080); the models keep loading in the background..."
for _ in $(seq 1 90); do
    if ss -ltn | grep -q ':8000 ' && ss -ltn | grep -q ':8080 '; then break; fi
    sleep 1
done
ss -ltn | grep -E ':800[0-3] |:8080 ' | awk '{print "  listening on", $4}'
echo "Dashboard: http://localhost:8000/dashboard/"
