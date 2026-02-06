#!/bin/bash
source /home/cyc0logy/FYP/ai_firewall/venv/bin/activate

echo "============================================="
echo "   STARTING AI FIREWALL & CAPTIVE PORTAL"
echo "============================================="

# 1. Captive Portal (Disabled for Open Network)
# echo "[1/3] Starting Captive Portal..."

# 2. Start Gateway Proxy (MITM)
echo "[2/3] Starting Gateway Proxy (Port 8080)..."
nohup python3 gateway/proxy.py > gateway.log 2>&1 &
echo "      Proxy PID: $!"

# 3. Start Network Layer (Firewall + Inspector)
# This script sets up iptables and starts main.py
echo "[3/3] Starting Network Layer (Root Required)..."
sudo ./start_network.sh

echo "============================================="
echo "   SYSTEM RUNNING"
echo "============================================="
echo "Logs available in:"
echo " - portal.log"
echo " - gateway.log"
echo " - brain.log"
