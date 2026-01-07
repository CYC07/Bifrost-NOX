#!/bin/bash

# 1. Clean up old rules
iptables -F
iptables -t nat -F

# 2. Setup IP Forwarding (Act as a router)
sysctl -w net.ipv4.ip_forward=1

# 3. Intercept Traffic Strategy
# WE DO NOT INTERCEPT PORT 8080 (Our Gateway) OR 8000-8003 (Our AI Services)
# to avoid infinite loops.

# Define protected ports
AI_PORTS="8000,8001,8002,8003,8080"

# Send Input/Forward traffic to NFQUEUE queue 1
# Exclude loopback
iptables -I INPUT -i lo -j ACCEPT
iptables -I OUTPUT -o lo -j ACCEPT

# Trap generic traffic for Inspection
# We trap DNS (53) and FTP (21) specifically for this demo, 
# or ALL traffic if we are bold, excluding our own management ports.
echo "Setting up traps for DNS and FTP..."

iptables -A INPUT -p udp --dport 53 -j NFQUEUE --queue-num 1
iptables -A OUTPUT -p udp --dport 53 -j NFQUEUE --queue-num 1

iptables -A INPUT -p tcp --dport 21 -j NFQUEUE --queue-num 1
iptables -A OUTPUT -p tcp --dport 21 -j NFQUEUE --queue-num 1

# Note: HTTP/HTTPS (80/443) should be redirected to mitmproxy (8080)
# This is "Transparent Proxying"
# ... (Keep previous iptables rules) ...

echo "Redirecting HTTP/HTTPS to mitmproxy..."
iptables -t nat -A OUTPUT -p tcp --dport 80 -m owner ! --uid-owner $(id -u) -j REDIRECT --to-port 8080
iptables -t nat -A OUTPUT -p tcp --dport 443 -m owner ! --uid-owner $(id -u) -j REDIRECT --to-port 8080

echo "Network Layer Rules Applied."

echo "Starting AI Brain (Python)..."
nohup python3 network_inspector/ai_brain.py > brain.log 2>&1 &

echo "Starting C++ Firewall Engine..."
# Ensure it is compiled: cd network_inspector/cpp && make
./network_inspector/cpp/firewall_engine
