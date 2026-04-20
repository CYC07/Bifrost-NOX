import logging
import time
import threading
from scapy.all import IP, TCP, UDP, DNS, DNSRR, Raw, send
from netfilterqueue import NetfilterQueue
import requests
import sys
import os

# Ensure we can import modules from parent directory
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from gateway.auth_manager import AuthManager
from common.utils import setup_logging

# Setup Logging
setup_logging("network_inspector")
logger = logging.getLogger("network_inspector")

# AI Config
MASTER_AI_URL = "http://localhost:8000/analyze_traffic"

# Auth Manager
auth_manager = AuthManager()

# Flow Tracking (Simple In-Memory State)
# Key: (src_ip, src_port, dst_ip, dst_port, proto)
# Value: {start_time, byte_count, last_seen}
connection_table = {}

def update_flow(packet):
    """
    Tracks connection state (Layer 4 Flow Tracking)
    """
    if IP in packet:
        src = packet[IP].src
        dst = packet[IP].dst
        proto = packet[IP].proto
        sport = 0
        dport = 0
        
        if TCP in packet:
            sport = packet[TCP].sport
            dport = packet[TCP].dport
        elif UDP in packet:
            sport = packet[UDP].sport
            dport = packet[UDP].dport
            
        flow_key = (src, sport, dst, dport, proto)
        
        if flow_key not in connection_table:
            connection_table[flow_key] = {
                "start_time": time.time(),
                "byte_count": 0,
                "packets": 0
            }
        
        connection_table[flow_key]["byte_count"] += len(packet)
        connection_table[flow_key]["packets"] += 1
        connection_table[flow_key]["last_seen"] = time.time()

    
    return True # Accept

def spoof_dns_response(packet):
    """
    Crafts a fake DNS response resolving to the Gateway IP
    """
    # Assuming Gateway IP is the destination of the query (since we intercept it)
    # OR we can hardcode/detect it. 
    # For NFQUEUE on OUTPUT, dst is original server.
    # For NFQUEUE on INPUT (Router), dst is original server.
    # We want to tell the client (src) that the domain is AT the gateway.
    
    # Let's try to detect Gateway IP from the interface or hardcode (172.17.0.1 docker default, or use internal logic)
    # IN A REAL SCENARIO: Get local IP.
    # For this env, we will try to infer or use 0.0.0.0 (works for some OS) or the interface IP.
    # Hack: resolving to the packet.dst might work if packet.dst IS the gateway (if client uses gateway as DNS)
    # But usually packet.dst is 8.8.8.8.
    
    # We will resolve to the GATEWAY IP.
    # Since I don't have an easy way to get the exact LAN IP here without `netifaces`, 
    # I will hardcode a common one OR use a trick.
    # User connects to <GATEWAY_IP>:5000.
    
    GATEWAY_IP = "192.168.1.1" # REPLACE/DETECT THIS IN PROD
    # Improving: use the dst IP if it's local, otherwise ...
    
    try:
        eth = packet.get_payload()
        ip = IP(eth)
        udp = ip[UDP]
        dns = udp[DNS]
        
        # Create Response
        # Swap IP/Port
        resp_ip = IP(src=ip.dst, dst=ip.src)
        resp_udp = UDP(sport=udp.dport, dport=udp.sport)
        resp_dns = DNS(
            id=dns.id,
            qr=1, # Response
            aa=1, # Authoritative
            rd=dns.rd,
            ra=1, # Recursion Available
            qd=dns.qd, # Copy Question
            an=DNSRR(
                rrname=dns.qd.qname,
                ttl=60,
                rdata=GATEWAY_IP # Point to ME
            )
        )
        
        spoofed_pkt = resp_ip/resp_udp/resp_dns
        
        # Send it out!
        # Since we are in NFQUEUE, we can't "inject" back down the stack easily if we are INPUT.
        # But we can use scapy `send(spoofed_pkt, verbose=0)`.
        send(spoofed_pkt, verbose=0)
        logger.info(f"Spoofed DNS for {dns.qd.qname.decode('utf-8')} -> {GATEWAY_IP}")
        
    except Exception as e:
        logger.error(f"DNS Spoofing Failed: {e}")

def inspect_dns(packet, is_authenticated=True):
    """
    Extracts DNS queries.
    If !is_authenticated -> Spoof Response & Drop.
    If is_authenticated -> Check Text Service & Allow/Drop.
    """
    if packet.haslayer(DNS) and packet[DNS].qr == 0: # Query
        qname = packet[DNS].qd.qname.decode('utf-8')
        
        # 1. Unauthenticated Logic
        if not is_authenticated:
             logger.info(f"Unauthenticated DNS Query: {qname} -> SPOOFING")
             spoof_dns_response(packet)
             return False # Drop original query (we answered it)

        # 2. Authenticated Logic
        logger.info(f"Inspecting DNS Query: {qname}")
        
        # Send to AI (Text Service) to check for DGA (Domain Generation Algorithms) or Malicious Domains
        try:
            # We treat the domain as 'text' content
            resp = requests.post(MASTER_AI_URL, data={
                "content_type": "text",
                "source_ip": packet[IP].src,
                "destination_ip": packet[IP].dst,
                "text_content": f"DNS_QUERY:{qname}" 
            }, timeout=0.5)
            
            if resp.status_code == 200:
                verdict = resp.json()
                if verdict.get("status") == "block":
                    logger.warning(f"BLOCKING DNS {qname}: {verdict.get('reason')}")
                    return False # Drop packet
        except Exception as e:
            logger.error(f"AI Check Failed: {e}")
            
    return True # Accept

def process_packet(packet):
    """
    Main Packet Processing Callback
    """
    scapy_packet = IP(packet.get_payload())
    
    # 0. Captive Portal Enforcement
    # Check if Source IP is authenticated
    src_ip = scapy_packet.src
    is_authenticated = auth_manager.is_authenticated(src_ip)
    
    if not is_authenticated:
        # ALLOW: DNS Queries (UDP/53) - We will INSPECT & SPOOF them now
        if scapy_packet.haslayer(DNS):
            pass # Continue to inspect_dns below
            
        # ALLOW: Traffic to Captive Portal (Port 5000)
        elif scapy_packet.haslayer(TCP) and scapy_packet[TCP].dport == 5000:
            pass # Allow flows to login
            
        # ALLOW: Return traffic FROM Captive Portal (Source Port 5000)
        elif scapy_packet.haslayer(TCP) and scapy_packet[TCP].sport == 5000:
            pass
            
        else:
            # BLOCK everything else
            # logger.debug(f"Blocking Unauthenticated User: {src_ip}")
            packet.drop()
            return

    # 1. Flow Tracking
    update_flow(scapy_packet)
    
    # 2. Protocol Dispatch
    verdict = True # Default Accept
    
    # DNS Inspection (UDP/53)
    if scapy_packet.haslayer(DNS):
        # Pass is_authenticated flag
        verdict = inspect_dns(scapy_packet, is_authenticated=is_authenticated)
        
    # FTP/SSH/Raw TCP Inspection
    # Note: For strict DPI, we would reassemble TCP streams here. 
    # For this prototype, we look at individual payloads if they are substantial.
    elif scapy_packet.haslayer(TCP) and scapy_packet.haslayer(Raw):
        payload = scapy_packet[Raw].load
        # Simple signature check (e.g. FTP command)
        if b"USER " in payload or b"PASS " in payload:
            logger.info("FTP Credentials/Command detected.")
            # Could send to AI for anomaly detection
            
    # 3. Decision
    if verdict:
        packet.accept()
    else:
        packet.drop()

def start_network_layer(queue_num=1):
    logger.info(f"Starting Network Inspector on NFQueue {queue_num}...")
    nfqueue = NetfilterQueue()
    nfqueue.bind(queue_num, process_packet)
    try:
        nfqueue.run()
    except KeyboardInterrupt:
        logger.info("Stopping Network Inspector")
        nfqueue.unbind()

if __name__ == "__main__":
    # In a real deploy, we would use argparse
    start_network_layer()
