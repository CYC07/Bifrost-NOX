#!/bin/bash

echo "Stopping FYP Hotspot..."

# Kill services
killall hostapd
killall dnsmasq

# Flush iptables
iptables -F
iptables -t nat -F

# Disable IP forwarding
echo 0 > /proc/sys/net/ipv4/ip_forward

# Re-enable NetworkManager
nmcli device set wlan0 managed yes

echo "✓ Hotspot stopped"
