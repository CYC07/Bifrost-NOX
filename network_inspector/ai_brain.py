import zmq
import os
import sys
import logging
import requests

# Setup Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - [BRAIN] - %(message)s')
logger = logging.getLogger("ai_brain")

ZMQ_ENDPOINT = "ipc:///tmp/firewall_pipeline"
MASTER_AI_URL = "http://localhost:8000/analyze_traffic"

def check_traffic_with_master(ip_src, payload):
    """
    Sends data to the Master AI service.
    """
    try:
        # Basic content filtering (Fast Path local)
        if b"malware" in payload or b"cmd.exe" in payload:
            return False

        content_type = "text"
        text_content = ""
        try:
            text_content = payload.decode('utf-8')
        except:
            content_type = "document" 
            
        data = {
            "content_type": content_type,
            "source_ip": ip_src,
            "destination_ip": "unknown",
        }
        
        if content_type == "text":
            data["text_content"] = text_content
            resp = requests.post(MASTER_AI_URL, data=data, timeout=0.2)
        else:
            files = {"file": ("blob", payload, "application/octet-stream")}
            resp = requests.post(MASTER_AI_URL, data=data, files=files, timeout=0.5)

        if resp.status_code == 200:
            verdict = resp.json()
            if verdict.get("status") == "block":
                return False
            return True
        return True 
        
    except Exception as e:
        logger.error(f"Error checking AI: {e}")
        return True 

def start_server():
    context = zmq.Context()
    socket = context.socket(zmq.REP)
    socket.bind(ZMQ_ENDPOINT)
    
    logger.info(f"AI Brain listening on {ZMQ_ENDPOINT} via ZeroMQ...")
    
    while True:
        try:
            # Receive Multi-part: [Header, Payload]
            header = socket.recv_string()
            payload = socket.recv()
            
            parts = header.split(' ')
            if len(parts) < 3 or parts[0] != "check":
                socket.send_string("ALLOW")
                continue
                
            ip_src = parts[1]
            
            is_allowed = check_traffic_with_master(ip_src, payload)
            
            # Respond
            socket.send_string("ALLOW" if is_allowed else "BLOCK")
            
        except Exception as e:
            logger.error(f"ZMQ Error: {e}")

if __name__ == "__main__":
    start_server()
