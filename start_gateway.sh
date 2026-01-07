#!/bin/bash
source /home/cyc0logy/FYP/ai_firewall/venv/bin/activate

# Start mitmdump (non-interactive mitmproxy) with our script
# Listen on 8080 by default
echo "Starting Gateway on 8080..."
nohup mitmdump -s gateway/proxy.py --allow-hosts ".*" --set block_global=false > gateway.log 2>&1 &
