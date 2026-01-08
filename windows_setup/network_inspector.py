import pydivert
import threading
import time
import requests
import logging
import sys
import os

# Setup Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - [WIN-NET] - %(message)s')
logger = logging.getLogger("windows_network_inspector")

MASTER_AI_URL = "http://localhost:8000/analyze_traffic"
DIVERT_FILTER = "outbound and (udp.DstPort == 53 or tcp.DstPort == 21) and ip.DstAddr != 127.0.0.1"

# Flow Cache (Simple In-Memory)
flow_cache = {}

def check_ai(payload, ip_src):
    try:
        # Check if payload looks like DNS (basic heuristic)
        # In pydivert, we get raw packets, but parsing DNS is complex without Scapy.
        # For this prototype, we just forward the raw payload to the AI Brain.
        
        # We treat it as generic binary/text check
        data = {
            "content_type": "text",
            "source_ip": ip_src,
            "destination_ip": "unknown",
            "text_content": str(payload) # Crude string conversion
        }
        resp = requests.post(MASTER_AI_URL, data=data, timeout=0.2)
        if resp.status_code == 200:
            return resp.json().get("status") == "allow"
        return True # Default Allow
    except:
        return True

def packet_worker():
    logger.info(f"Starting WinDivert with filter: {DIVERT_FILTER}")
    
    # WinDivert requires Administrator privileges!
    try:
        with pydivert.WinDivert(DIVERT_FILTER) as w:
            for packet in w:
                try:
                    src = packet.src_addr
                    payload = packet.payload
                    
                    # 1. Flow Check
                    # (Simplified: No complex cache for Windows prototype yet)
                    
                    # 2. AI Check
                    if len(payload) > 0:
                        is_allowed = check_ai(payload, src)
                        if not is_allowed:
                            logger.warning(f"BLOCKING packet from {src}")
                            continue # Drop packet (don't call w.send)
                            
                    # 3. Forward
                    w.send(packet)
                    
                except Exception as e:
                    logger.error(f"Packet Error: {e}")
                    w.send(packet) # Fail Open
    except OSError:
        logger.error("Failed to start WinDivert. Make sure you run as ADMINISTRATOR.")

if __name__ == "__main__":
    packet_worker()
