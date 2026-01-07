import logging
import time
import threading
from scapy.all import IP, TCP, UDP, DNS, Raw
from netfilterqueue import NetfilterQueue
import requests
import sys
import os

# Setup Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - [NET] - %(message)s')
logger = logging.getLogger("network_inspector")

# AI Config
MASTER_AI_URL = "http://localhost:8000/analyze_traffic"

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

def inspect_dns(packet):
    """
    Extracts DNS queries and checks them against Text Service (Mock)
    """
    if packet.haslayer(DNS) and packet[DNS].qr == 0: # Query
        qname = packet[DNS].qd.qname.decode('utf-8')
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
    
    # 1. Flow Tracking
    update_flow(scapy_packet)
    
    # 2. Protocol Dispatch
    verdict = True # Default Accept
    
    # DNS Inspection (UDP/53)
    if scapy_packet.haslayer(DNS):
        verdict = inspect_dns(scapy_packet)
        
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
