#!/bin/bash

# ================================================
# FYP AI Firewall - Laptop Hotspot Setup Script
# ================================================

# Configuration
HOTSPOT_SSID="FYP-AI-Firewall"
HOTSPOT_PASSWORD="FypDemo2024"  # Change this
HOTSPOT_INTERFACE="wlan0"        # Your laptop's WiFi interface (check with 'ip link')
INTERNET_INTERFACE="eth0"         # USB tethering from phone (check with 'ip link')
HOTSPOT_IP="192.168.50.1"
HOTSPOT_SUBNET="192.168.50.0/24"
DHCP_RANGE_START="192.168.50.10"
DHCP_RANGE_END="192.168.50.100"

# AI Server settings (your laptop)
AI_SERVER_IP="192.168.50.1"  # Laptop's IP on hotspot network
GATEWAY_HTTP_PORT=8080
GATEWAY_HTTPS_PORT=8443

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}FYP AI Firewall - Hotspot Setup${NC}"
echo -e "${GREEN}========================================${NC}"

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}Please run as root (use sudo)${NC}"
    exit 1
fi

# Step 1: Stop NetworkManager from managing the hotspot interface
echo -e "${YELLOW}[1/8] Stopping NetworkManager on $HOTSPOT_INTERFACE...${NC}"
nmcli device set $HOTSPOT_INTERFACE managed no
sleep 2

# Step 2: Configure hotspot interface
echo -e "${YELLOW}[2/8] Configuring $HOTSPOT_INTERFACE...${NC}"
ip link set $HOTSPOT_INTERFACE down
ip addr flush dev $HOTSPOT_INTERFACE
ip addr add $HOTSPOT_IP/24 dev $HOTSPOT_INTERFACE
ip link set $HOTSPOT_INTERFACE up

# Step 3: Configure hostapd (WiFi Access Point)
echo -e "${YELLOW}[3/8] Configuring hostapd...${NC}"
cat > /etc/hostapd/hostapd.conf << EOF
interface=$HOTSPOT_INTERFACE
driver=nl80211
ssid=$HOTSPOT_SSID
hw_mode=g
channel=6
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
wpa=2
wpa_passphrase=$HOTSPOT_PASSWORD
wpa_key_mgmt=WPA-PSK
wpa_pairwise=TKIP
rsn_pairwise=CCMP
EOF

# Step 4: Configure dnsmasq (DHCP + DNS)
echo -e "${YELLOW}[4/8] Configuring dnsmasq...${NC}"
cat > /etc/dnsmasq.conf << EOF
interface=$HOTSPOT_INTERFACE
dhcp-range=$DHCP_RANGE_START,$DHCP_RANGE_END,255.255.255.0,24h
dhcp-option=3,$HOTSPOT_IP  # Gateway
dhcp-option=6,$HOTSPOT_IP  # DNS
server=8.8.8.8
server=1.1.1.1
bind-interfaces
domain-needed
bogus-priv
EOF

# Step 5: Enable IP forwarding
echo -e "${YELLOW}[5/8] Enabling IP forwarding...${NC}"
echo 1 > /proc/sys/net/ipv4/ip_forward
sysctl -w net.ipv4.ip_forward=1

# Step 6: Configure iptables (NAT + AI Firewall rules)
echo -e "${YELLOW}[6/8] Configuring iptables...${NC}"

# Flush existing rules
iptables -F
iptables -t nat -F
iptables -t mangle -F

# Enable NAT (masquerading)
iptables -t nat -A POSTROUTING -o $INTERNET_INTERFACE -j MASQUERADE

# Allow established connections
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow traffic from hotspot to internet
iptables -A FORWARD -i $HOTSPOT_INTERFACE -o $INTERNET_INTERFACE -j ACCEPT

# Redirect HTTP to gateway proxy
iptables -t nat -A PREROUTING -i $HOTSPOT_INTERFACE -p tcp --dport 80 -j REDIRECT --to-port $GATEWAY_HTTP_PORT

# Redirect HTTPS to gateway proxy
iptables -t nat -A PREROUTING -i $HOTSPOT_INTERFACE -p tcp --dport 443 -j REDIRECT --to-port $GATEWAY_HTTPS_PORT

# Send other traffic to NFQUEUE for C++ engine (if needed)
# iptables -A FORWARD -i $HOTSPOT_INTERFACE -m state --state NEW -j NFQUEUE --queue-num 1 --queue-bypass

echo -e "${GREEN}✓ iptables rules configured${NC}"

# Step 7: Start services
echo -e "${YELLOW}[7/8] Starting services...${NC}"

# Kill any existing instances
killall hostapd 2>/dev/null
killall dnsmasq 2>/dev/null

# Start hostapd (WiFi AP)
hostapd /etc/hostapd/hostapd.conf -B

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ hostapd started${NC}"
else
    echo -e "${RED}✗ hostapd failed to start${NC}"
    exit 1
fi

# Start dnsmasq (DHCP/DNS)
dnsmasq -C /etc/dnsmasq.conf

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ dnsmasq started${NC}"
else
    echo -e "${RED}✗ dnsmasq failed to start${NC}"
    exit 1
fi

# Step 8: Setup web portal
echo -e "${YELLOW}[8/8] Setting up web portal...${NC}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Create portal directory and deploy PHP files
mkdir -p /var/www/html/portal
mkdir -p /var/www/html/certs

if [ -d "$SCRIPT_DIR/portal" ]; then
    cp "$SCRIPT_DIR/portal/"*.php /var/www/html/portal/
    chown -R www-data:www-data /var/www/html/portal/
    echo -e "${GREEN}✓ Portal files deployed${NC}"
else
    echo -e "${YELLOW}⚠ Portal directory not found at $SCRIPT_DIR/portal/${NC}"
fi

# Initialize database
sqlite3 /tmp/portal_users.db << 'SQL'
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    registered_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_login DATETIME,
    cert_downloaded INTEGER DEFAULT 0
);
SQL

chmod 644 /tmp/portal_users.db
chown www-data:www-data /tmp/portal_users.db

# Copy your CA certificate
if [ -f "/home/cyc0logy/FYP/ai_firewall/gateway/certs/ca.crt" ]; then
    cp /home/cyc0logy/FYP/ai_firewall/gateway/certs/ca.crt /var/www/html/certs/AI-Firewall-CA.crt
    echo -e "${GREEN}✓ CA certificate copied${NC}"
else
    echo -e "${YELLOW}⚠ CA certificate not found - update path in script${NC}"
fi

# Start Apache
systemctl restart apache2

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}✓ Hotspot is now running!${NC}"
echo -e "${GREEN}========================================${NC}"
echo -e "SSID:     ${YELLOW}$HOTSPOT_SSID${NC}"
echo -e "Password: ${YELLOW}$HOTSPOT_PASSWORD${NC}"
echo -e "Gateway:  ${YELLOW}$HOTSPOT_IP${NC}"
echo -e "Portal:   ${YELLOW}http://$HOTSPOT_IP/portal/login.php${NC}"
echo ""
echo -e "${GREEN}Clients connecting will be redirected to the portal${NC}"
echo -e "${GREEN}Your AI firewall is now active!${NC}"
echo ""
echo -e "To stop: ${YELLOW}sudo ./fyp_hotspot_stop.sh${NC}"
echo -e "${GREEN}========================================${NC}"
