#!/bin/bash
cd "$(dirname "${BASH_SOURCE[0]}")" || exit 1
source venv/bin/activate

# Start mitmdump (non-interactive mitmproxy) with our script
# Listen on 8080 by default
echo "Starting Gateway on 8080..."
nohup python3 gateway/proxy.py > gateway.log 2>&1 &

# Rule moved to start_network.sh
