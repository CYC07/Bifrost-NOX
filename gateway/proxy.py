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
from common.trusted_domains import is_trusted_connection
from common.multipart import extract_file_parts
from ml.waf.target import is_interesting as target_is_interesting

# Setup Logging
setup_logging("gateway")
logger = logging.getLogger("gateway")

def _doc_scan_mode() -> str:
    """off = legacy (documents go to the text service); advisory (default) / block = documents
    go to the document service. Advisory vs block is applied by the orchestrator."""
    return os.environ.get("DOC_SCAN_MODE", "advisory").strip().lower()


def _doc_max_bytes() -> int:
    """Documents larger than this are allowed unanalysed (ZIP also covers APK/JAR/archives)."""
    try:
        return int(os.environ.get("DOC_SCAN_MAX_BYTES", str(20 * 1024 * 1024)))
    except ValueError:
        return 20 * 1024 * 1024


def _has_field_content(body: bytes) -> bool:
    """True if a multipart body (file parts already removed) still carries field values, i.e.
    something besides boundary lines and part headers."""
    for line in body.split(b"\r\n"):
        s = line.strip()
        if not s or s.startswith(b"--"):
            continue
        low = s.lower()
        if low.startswith(b"content-disposition:") or low.startswith(b"content-type:"):
            continue
        return True
    return False


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

    async def inspect_full(self, headers, body, direction, is_https, src_ip="unknown", dst_ip="unknown", dst_port="",
                           host="", method="", path="", server_name="", dest_ip=""):
        """Called when a full HTTP message is captured. host/method/path give the
        analysis context (e.g. to tell LLM API traffic from ordinary web traffic)."""
        # Trusted-domain policy (config/trusted_domains.json): Windows/Microsoft infrastructure is
        # normal traffic - no file-type block, no model analysis. The names are client-claimed, so
        # the Host header AND the SNI (when there is one; plain HTTP has none) must both be trusted
        # and the real destination IP must be in Microsoft's ranges.
        names = [host]
        if server_name and server_name != dest_ip:
            names.append(server_name)
        if is_trusted_connection(names, dest_ip):
            return "allow"

        # Request target (path + query string). Attacks there (SQLi/XSS/traversal in a GET) were
        # never inspected: only bodies were, so they were only ever caught by accident via the
        # server's echoed reply. A cheap local pre-filter keeps ordinary URLs off the AI path.
        if direction == "outbound" and path and target_is_interesting(path):
            logger.info(f"Inspecting request target {src_ip} -> {dst_ip}:{dst_port} {method} ({len(path)} chars)")
            tv = await self.send_to_ai("text", path.encode("utf-8", "ignore"), direction, src_ip, dst_ip, dst_port,
                                       host=host, method=method, path=path, kind="url")
            if tv.get("status") == "block":
                logger.warning(f"BLOCK AI target ({src_ip} -> {dst_ip}): {tv.get('reason')}")
                return "block"

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

        # 1b. Uploaded files inside multipart/form-data: the whole body sniffs as text, so each file
        # part is sniffed and routed on its own (document -> document service, image -> image
        # service). The routed bytes are then removed from the body so the remaining fields are
        # analysed without the file content (a PDF's text was being scored by the WAF as an attack).
        if direction == "outbound" and _doc_scan_mode() != "off":
            verdict, remaining = await self._inspect_upload_parts(headers, body, direction, src_ip, dst_ip,
                                                                  dst_port, host, method, path)
            if verdict == "block":
                return "block"
            if remaining is not None:
                if not _has_field_content(remaining):
                    return "allow"
                body = remaining
                detected_type = FileSniffer.get_true_file_type(body)
                entropy = FileSniffer.calculate_entropy(body)

        # 2. SECURITY: High Entropy Text
        if detected_type == "text" and entropy > 7.5:
            logger.warning(f"BLOCK: High entropy text ({src_ip} -> {dst_ip}).")
            return "block"

        # 3. AI Analysis
        if detected_type == "document":
            mode = _doc_scan_mode()
            if mode != "off" and len(body) > _doc_max_bytes():
                logger.info(f"Document {len(body)} bytes over DOC_SCAN_MAX_BYTES; allowed unanalysed")
                return "allow"
            # mode "off" keeps the legacy route (text service)
            service_type = "document" if mode != "off" else "text"
        else:
            service_type = "image" if detected_type == "image" else "text"
        if detected_type not in ["image", "text", "document"]:
             # Ignore others
             return "allow"

        # Send to Master AI
        verdict = await self.send_to_ai(service_type, body, direction, src_ip, dst_ip, dst_port,
                                        host=host, method=method, path=path)
        if verdict.get("status") == "block":
            logger.warning(f"BLOCK AI ({src_ip} -> {dst_ip}): {verdict.get('reason')}")
            return "block"

        return "allow"

    async def _inspect_upload_parts(self, headers, body, direction, src_ip, dst_ip, dst_port, host, method, path):
        """Analyse file parts of a multipart upload.

        Returns (verdict, remaining): remaining is the body with the routed document/image parts
        removed (None when nothing was routed). Parse problems fail open ('allow', None)."""
        remaining = None
        try:
            ctype = headers.get("content-type", "")
            if "multipart/" not in str(ctype).lower():
                return "allow", None
            for part in extract_file_parts(ctype, body, max_part_bytes=_doc_max_bytes()):
                kind = FileSniffer.get_true_file_type(part.data)
                if kind not in ("document", "image"):
                    continue
                logger.info(f"Inspecting uploaded {kind} part {part.filename!r} ({len(part.data)} bytes)")
                v = await self.send_to_ai(kind, part.data, direction, src_ip, dst_ip, dst_port,
                                          host=host, method=method, path=path)
                if v.get("status") == "block":
                    logger.warning(f"BLOCK AI upload part ({src_ip} -> {dst_ip}): {v.get('reason')}")
                    return "block", None
                remaining = (body if remaining is None else remaining).replace(part.data, b"", 1)
        except Exception as exc:
            logger.warning(f"Upload part inspection failed open: {type(exc).__name__}: {exc}")
            return "allow", None
        return "allow", remaining

    async def send_to_ai(self, c_type, payload_bytes, direction, src_ip="unknown", dst_ip="unknown", dst_port="",
                          host="", method="", path="", kind=""):
        data = {
            "content_type": c_type,
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "port": str(dst_port),
            "direction": direction,
            "host": host or "",
            "method": method or "",
            "path": path or "",
            "kind": kind or "",      # "url" = payload is a request target (path+query), not a body
        }
        files = None
        if c_type == "text":
            try:
                data["text_content"] = payload_bytes.decode('utf-8', errors='ignore')
            except: 
                data["text_content"] = ""
        else:
            files = {"file": ("blob", payload_bytes, "application/octet-stream")}
            
        # AI_TIMEOUT: seconds to wait for a verdict. AI_FAIL_MODE: what to do when no
        # verdict arrives (timeout / error / non-200): "open" (default, documented
        # fail-safe design — keep traffic flowing) or "closed" (block it). Fail-open is
        # a bypass whenever analysis is slow, so it is logged loudly either way.
        timeout = float(os.environ.get("AI_TIMEOUT", "10.0"))
        reason = ""
        try:
            resp = await self.client.post(MASTER_AI_URL, data=data, files=files, timeout=timeout)
            if resp.status_code == 200:
                return resp.json()
            reason = f"HTTP {resp.status_code} from analysis service"
        except Exception as e:
            # str(e) is empty for timeouts, which hid them in the logs
            reason = f"{type(e).__name__}: {e}".rstrip(": ")
        mode = os.environ.get("AI_FAIL_MODE", "open").lower()
        logger.error(f"AI verdict unavailable ({reason}) for {direction} {src_ip}->{dst_ip}:{dst_port} — failing {mode}")
        if mode == "closed":
            return {"status": "block", "reason": f"AI analysis unavailable (fail-closed): {reason}"}
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
    try:
        # asyncio.get_event_loop() no longer auto-creates a loop outside one
        # (removed in Python 3.14); asyncio.run() is the modern replacement.
        asyncio.run(proxy.start())
    except KeyboardInterrupt:
        pass
