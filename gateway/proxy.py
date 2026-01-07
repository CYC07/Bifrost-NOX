import logging
from mitmproxy import http
import httpx
import asyncio
import io
import sys
import os

# Ensure we can import from common
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from common.utils import FileSniffer

# Setup Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("mitmproxy_gateway")

MASTER_AI_URL = "http://localhost:8000/analyze_traffic"
# In venv, make sure we have access to common schemas if needed, 
# or just use raw dicts to avoid path issues within mitmproxy's execution context.

class IDPInspector:
    def __init__(self):
        self.client = httpx.AsyncClient()

    async def request(self, flow: http.HTTPFlow):
        """Inspect Outbound Traffic (Employee -> Internet)"""
        # Only inspect POST/PUT bodies or specific content types
        if flow.request.method in ["POST", "PUT"] and flow.request.content:
            await self.process_flow(flow, "outbound")

    async def response(self, flow: http.HTTPFlow):
        """Inspect Inbound Traffic (Internet -> Employee)"""
        # Inspect downloads (images, pdfs, html)
        if flow.response.content:
            await self.process_flow(flow, "inbound")

    async def process_flow(self, flow: http.HTTPFlow, direction: str):
        content_type_header = flow.request.headers.get("Content-Type", "") if direction == "outbound" else flow.response.headers.get("Content-Type", "")
        
        # Get raw payload
        payload = flow.request.content if direction == "outbound" else flow.response.content
        if not payload:
            return

        # --- DEEP TYPE INSPECTION (No AI) ---
        detected_type = FileSniffer.get_true_file_type(payload)
        entropy = FileSniffer.calculate_entropy(payload)
        
        source = flow.client_conn.address[0] if flow.client_conn else "unknown"
        dest = flow.request.host

        logger.info(f"Inspecting {direction} traffic | Header: {content_type_header} | Detected: {detected_type} | Entropy: {entropy:.2f}")

        # 1. SECURITY CHECK: Executables
        if detected_type == "executable":
            logger.warning(f"BLOCKING {direction} traffic. executable detected in stream.")
            self.block_flow(flow, direction, "Executable file transfer is prohibited.")
            return

        # 2. SECURITY CHECK: High Entropy Text (Potential Obfuscation/Encryption)
        if detected_type == "text" and entropy > 7.5:
             # It claims to be text, but it's random noise. Likely encrypted data exfiltration or C2.
            logger.warning(f"BLOCKING {direction} traffic. High entropy text detected (Possible Encryption/Obfuscation).")
            self.block_flow(flow, direction, "High entropy content detected (Suspected Obfuscation).")
            return

        # 3. ROUTING LOGIC
        # Map detected internal type to Service Types
        service_type = "unknown"
        if detected_type == "image":
            service_type = "image"
        elif detected_type == "document":
            service_type = "document"
        elif detected_type == "text":
            service_type = "text"
        else:
            # binary_unknown or similar. 
            # If we are strict, we block. If lenient, we might try document service.
            # For this firewall, let's treat unknown binary as suspicious document.
            service_type = "document"

        # Prepare Payload
        try:
            verdict = await self.send_to_ai(service_type, flow, source, dest, direction)
            
            if verdict.get("status") == "block":
                logger.warning(f"BLOCKING {direction} traffic. Reason: {verdict.get('reason')}")
                self.block_flow(flow, direction, f"Blocked by AI: {verdict.get('reason')}")
            else:
                logger.info("Traffic Allowed.")
        
        except Exception as e:
            logger.error(f"Error checking traffic: {e}")
            # Fail Open or Fail Closed? 
            # "Fail Closed" is safer for firewall.
            # flow.response = http.Response.make(500, b"Firewall Error")

    def block_flow(self, flow: http.HTTPFlow, direction: str, reason: str):
        if direction == "outbound":
            flow.response = http.Response.make(
                403, 
                f"Blocked by AI Firewall: {reason}".encode(), 
                {"Content-Type": "text/plain"}
            )
        else:
            flow.response.content = f"Content Blocked: {reason}".encode()
            flow.response.status_code = 403

    async def send_to_ai(self, c_type, flow, src, dst, direction):
        payload_bytes = flow.request.content if direction == "outbound" else flow.response.content
        
        data = {
            "content_type": c_type,
            "source_ip": src,
            "destination_ip": dst,
        }
        
        files = None
        
        if c_type == "text":
            # Decode text
            try:
                text_content = payload_bytes.decode('utf-8', errors='ignore')
                data["text_content"] = text_content
            except:
                data["text_content"] = ""
        else:
            # Send as file
            files = {"file": ("blob", payload_bytes, "application/octet-stream")}

        # Send to Master AI
        # Note: mitmproxy loop might block if we don't use async properly.
        # mitmproxy supports async handlers.
        
        try:
            resp = await self.client.post(MASTER_AI_URL, data=data, files=files, timeout=5.0)
            if resp.status_code == 200:
                return resp.json()
            else:
                logger.error(f"AI returned {resp.status_code}")
                return {"status": "block", "reason": "AI Error"} 
        except Exception as e:
            logger.error(f"Failed to contact Master AI: {e}")
            return {"status": "block", "reason": "AI Unreachable"}

addons = [
    IDPInspector()
]
