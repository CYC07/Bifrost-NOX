import fcntl
import logging
import socket
import struct
import sys
import os
import asyncio
import httpx
from mitm_engine import TransparentProxy

# Ensure we can import from common
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from common.utils import FileSniffer, setup_logging

# Setup Logging
setup_logging("gateway")
logger = logging.getLogger("gateway")

MASTER_AI_URL = "http://localhost:8000/analyze_traffic"
MASTER_LOG_URL = "http://localhost:8000/log_event"

class IDPInspector:
    def __init__(self):
        self.client = httpx.AsyncClient()

    async def log_connection(self, src_ip, dst_ip, dst_port, is_tls, host):
        """Fire-and-forget connection-level event so the dashboard shows
        traffic the moment the proxy accepts a connection, regardless of
        whether HTTP parsing / AI inspection ever runs on it."""
        try:
            await self.client.post(
                MASTER_LOG_URL,
                json={
                    "source_ip": src_ip,
                    "destination_ip": host or dst_ip,
                    "port": str(dst_port),
                    "status": "allow",
                    "reason": f"{'HTTPS' if is_tls else 'HTTP'} connection",
                },
                timeout=1.0,
            )
        except Exception:
            pass

    async def log_block(self, src_ip, dst_ip, dst_port, host, reason):
        """Fire-and-forget BLOCK event. Used when MITM cannot complete
        (e.g. cert pinning on WhatsApp/Snapchat) so the operator sees why
        the connection died and knows to allowlist the host if intentional."""
        try:
            await self.client.post(
                MASTER_LOG_URL,
                json={
                    "source_ip": src_ip,
                    "destination_ip": host or dst_ip,
                    "port": str(dst_port),
                    "status": "block",
                    "risk_level": "high",
                    "reason": reason,
                    "rule": "PINNED-TLS",
                },
                timeout=1.0,
            )
        except Exception:
            pass

    async def inspect_full(self, headers, body, direction, is_https, src_ip="unknown", dst_ip="unknown", dst_port=""):
        """Called when a full HTTP message is captured"""
        if not body: return "allow"

        # Determine content type from headers or content
        c_type_header = headers.get("content-type", "")

        detected_type = FileSniffer.get_true_file_type(body)
        entropy = FileSniffer.calculate_entropy(body)

        logger.info(f"Inspecting {direction} {src_ip} -> {dst_ip}:{dst_port} ({len(body)} bytes) | Header: {c_type_header} | Type: {detected_type}")

        # 1. SECURITY: Executable
        if detected_type == "executable":
            logger.warning(f"BLOCK: Executable detected ({src_ip} -> {dst_ip}).")
            return "block"

        # 2. SECURITY: High Entropy Text
        if detected_type == "text" and entropy > 7.5:
            logger.warning(f"BLOCK: High entropy text ({src_ip} -> {dst_ip}).")
            return "block"

        # 3. AI Analysis
        service_type = "image" if detected_type == "image" else "text"
        if detected_type not in ["image", "text", "document"]:
             # Ignore others
             return "allow"

        # Send to Master AI
        verdict = await self.send_to_ai(service_type, body, direction, src_ip, dst_ip, dst_port)
        if verdict.get("status") == "block":
            logger.warning(f"BLOCK AI ({src_ip} -> {dst_ip}): {verdict.get('reason')}")
            return "block"

        return "allow"

    async def send_to_ai(self, c_type, payload_bytes, direction, src_ip="unknown", dst_ip="unknown", dst_port=""):
        data = {
            "content_type": c_type,
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "port": str(dst_port),
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

def _iface_ip(iface: str) -> str:
    """Return the IPv4 address of *iface*, or '' on any error."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        return socket.inet_ntoa(
            fcntl.ioctl(s.fileno(), 0x8915,  # SIOCGIFADDR
                        struct.pack("256s", iface[:15].encode()))[20:24]
        )
    except Exception:
        return ""


if __name__ == "__main__":
    # Bind only to the hotspot interface so the laptop's own traffic never
    # reaches the proxy.  Falls back to 0.0.0.0 if the interface is absent.
    hotspot_if = os.environ.get("HOTSPOT_IF", "wlan1")
    bind_ip = os.environ.get("PROXY_BIND_IP") or _iface_ip(hotspot_if) or "0.0.0.0"
    if bind_ip != "0.0.0.0":
        logger.info("Proxy binding to %s (%s) — local traffic excluded", bind_ip, hotspot_if)
    else:
        logger.warning("Could not resolve %s IP — binding to 0.0.0.0", hotspot_if)

    inspector = IDPInspector()
    proxy = TransparentProxy(host=bind_ip, inspector=inspector)
    loop = asyncio.get_event_loop()
    try:
        loop.run_until_complete(proxy.start())
    except KeyboardInterrupt:
        pass
