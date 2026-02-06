import logging
import sys
import os
import asyncio
import httpx
from mitm_engine import TransparentProxy

# Ensure we can import from common
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from common.utils import FileSniffer

# Setup Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("gateway")

MASTER_AI_URL = "http://localhost:8000/analyze_traffic"

class IDPInspector:
    def __init__(self):
        self.client = httpx.AsyncClient()

    async def inspect_full(self, headers, body, direction, is_https):
        """Called when a full HTTP message is captured"""
        if not body: return "allow"
        
        # Determine content type from headers or content
        c_type_header = headers.get("content-type", "")
        
        detected_type = FileSniffer.get_true_file_type(body)
        entropy = FileSniffer.calculate_entropy(body)
        
        logger.info(f"Inspecting {direction} ({len(body)} bytes) | Header: {c_type_header} | Type: {detected_type}")
        
        # 1. SECURITY: Executable
        if detected_type == "executable":
            logger.warning("BLOCK: Executable detected.")
            return "block"
            
        # 2. SECURITY: High Entropy Text
        if detected_type == "text" and entropy > 7.5:
            logger.warning("BLOCK: High entropy text.")
            return "block"
            
        # 3. AI Analysis
        service_type = "image" if detected_type == "image" else "text"
        if detected_type not in ["image", "text", "document"]:
             # Ignore others
             return "allow"
             
        # Send to Master AI
        verdict = await self.send_to_ai(service_type, body, direction)
        if verdict.get("status") == "block":
            logger.warning(f"BLOCK AI: {verdict.get('reason')}")
            return "block"
            
        return "allow"

    async def send_to_ai(self, c_type, payload_bytes, direction):
        data = {
            "content_type": c_type,
            "source_ip": "unknown", # We'd need to thread context to get IP
            "destination_ip": "unknown",
        }
        files = None
        if c_type == "text":
            try:
                data["text_content"] = payload_bytes.decode('utf-8', errors='ignore')
            except: 
                data["text_content"] = ""
        else:
            files = {"file": ("blob", payload_bytes, "application/octet-stream")}
            
        try:
            resp = await self.client.post(MASTER_AI_URL, data=data, files=files, timeout=5.0)
            if resp.status_code == 200:
                return resp.json()
        except Exception as e:
            logger.error(f"AI Error: {e}")
        return {"status": "allow"}

if __name__ == "__main__":
    inspector = IDPInspector()
    proxy = TransparentProxy(inspector=inspector)
    loop = asyncio.get_event_loop()
    try:
        loop.run_until_complete(proxy.start())
    except KeyboardInterrupt:
        pass
