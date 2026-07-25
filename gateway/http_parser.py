"""Streaming HTTP/1.x message parser for the MITM pipe.

Replaces the old Content-Length-only parser. Handles the framing that real
HTTPS traffic actually uses so the AI inspection path fires instead of silently
buffering to the 10 MB flush:

  * ``Content-Length`` bodies
  * ``Transfer-Encoding: chunked`` bodies (de-chunked for inspection)
  * bodyless messages (GET/HEAD requests, 1xx/204/304 responses)
  * ``Content-Encoding: gzip`` / ``deflate`` (inflated for inspection only)
  * pipelined keep-alive: leftover bytes after one message start the next

Two byte views are kept per message:

  * :attr:`raw`  — the exact wire bytes of the message, forwarded upstream
                   unchanged (never re-compress / re-chunk).
  * :attr:`body` — de-chunked and decompressed body, for content inspection.

The parser is *role-aware* (``"request"`` vs ``"response"``) because framing
differs: a ``GET`` completes at end-of-headers, and 204/304/1xx responses have
no body. Feeding a bodyless message as if it had a body would stall the
connection forever.
"""
from __future__ import annotations

import gzip
import logging
import zlib

logger = logging.getLogger("http_parser")

_HEADER_SEP = b"\r\n\r\n"
_NO_BODY_STATUS = {204, 304}


class HTTPParser:
    def __init__(self, role: str = "response") -> None:
        if role not in ("request", "response"):
            raise ValueError("role must be 'request' or 'response'")
        self.role = role
        self.reset()

    def reset(self) -> None:
        """Clear all per-message state. Call between pipelined messages."""
        self._buf = b""
        self._header_bytes = b""
        self.headers: dict[str, str] = {}
        self.method = ""
        self.path = ""
        self.protocol = ""
        self.status = 0
        self.header_done = False
        self.message_complete = False
        self.raw = b""
        self.body = b""
        self._framing: str | None = None      # length | chunked | none | close
        self._expected = 0                      # remaining CL body bytes
        self._leftover = b""                    # bytes after this message

    # ------------------------------------------------------------------ feed
    def feed(self, data: bytes) -> None:
        """Accumulate wire bytes and advance the state machine.

        After a call, check :attr:`message_complete`. When true, :attr:`raw`
        and :attr:`body` are populated and :meth:`take_leftover` returns any
        pipelined bytes that belong to the next message.
        """
        if self.message_complete:
            self._leftover += data
            return
        self._buf += data
        if not self.header_done:
            self._try_parse_headers()
            if not self.header_done:
                return
        self._advance_body()

    def feed_eof(self) -> None:
        """Signal the peer closed the connection.

        For ``close``-framed responses (no Content-Length, no chunked) the body
        ends at EOF, so finalize whatever we have for a best-effort inspection.
        """
        if self.header_done and not self.message_complete and self._framing == "close":
            self._finalize(self._buf)
            self._buf = b""

    def take_leftover(self) -> bytes:
        lo = self._leftover
        self._leftover = b""
        return lo

    @property
    def unforwarded(self) -> bytes:
        """Bytes fed but not yet emitted as a completed message.

        Used by the pipe to bail out to raw passthrough when a stream is not
        HTTP or a body is too large to buffer for inspection.
        """
        return (self._header_bytes if self.header_done else b"") + self._buf

    # --------------------------------------------------------------- headers
    def _try_parse_headers(self) -> None:
        idx = self._buf.find(_HEADER_SEP)
        if idx == -1:
            return
        header_blob = self._buf[:idx]
        rest = self._buf[idx + len(_HEADER_SEP):]

        lines = header_blob.split(b"\r\n")
        start_line = lines[0].decode("utf-8", errors="ignore")
        parts = start_line.split(" ")
        if self.role == "request":
            if len(parts) >= 3:
                self.method, self.path, self.protocol = parts[0], parts[1], parts[2]
        else:
            if len(parts) >= 2:
                self.protocol = parts[0]
                try:
                    self.status = int(parts[1])
                except ValueError:
                    self.status = 0

        for line in lines[1:]:
            if b":" in line:
                key, val = line.split(b":", 1)
                self.headers[key.decode("utf-8", errors="ignore").strip().lower()] = (
                    val.decode("utf-8", errors="ignore").strip()
                )

        self.header_done = True
        self._header_bytes = self._buf[: idx + len(_HEADER_SEP)]
        self._buf = rest
        self._framing = self._decide_framing()

    def _decide_framing(self) -> str:
        te = self.headers.get("transfer-encoding", "").lower()
        if "chunked" in te:
            return "chunked"
        if "content-length" in self.headers:
            try:
                self._expected = int(self.headers["content-length"])
            except ValueError:
                self._expected = 0
            return "length"
        if self.role == "request":
            return "none"           # request without CL/TE has no body
        if self.status in _NO_BODY_STATUS or 100 <= self.status < 200:
            return "none"           # 1xx/204/304 responses have no body
        return "close"              # response body runs until connection close

    # ------------------------------------------------------------------ body
    def _advance_body(self) -> None:
        if self._framing == "none":
            self._leftover += self._buf   # pipelined next message, if any
            self._buf = b""
            self._finalize(b"")
        elif self._framing == "length":
            if len(self._buf) >= self._expected:
                body = self._buf[: self._expected]
                self._leftover += self._buf[self._expected:]
                self._buf = b""
                self._finalize(body)
        elif self._framing == "chunked":
            self._advance_chunked()
        # "close": wait for feed_eof()

    def _advance_chunked(self) -> None:
        """Detect the terminating 0-length chunk; keep raw body intact."""
        buf = self._buf
        pos = 0
        decoded = bytearray()
        while True:
            nl = buf.find(b"\r\n", pos)
            if nl == -1:
                return  # need more bytes for the chunk-size line
            size_line = buf[pos:nl].split(b";", 1)[0].strip()
            try:
                size = int(size_line, 16)
            except ValueError:
                # Malformed chunk framing — treat what we have as complete.
                self._finalize_chunked(buf, len(buf), bytes(decoded))
                return
            data_start = nl + 2
            if size == 0:
                end = buf.find(b"\r\n", data_start)
                msg_end = (end + 2) if end != -1 else len(buf)
                self._finalize_chunked(buf, msg_end, bytes(decoded))
                return
            data_end = data_start + size
            if len(buf) < data_end + 2:
                return  # chunk body not fully arrived yet
            decoded += buf[data_start:data_end]
            pos = data_end + 2  # skip chunk data + trailing CRLF

    def _finalize_chunked(self, buf: bytes, msg_end: int, decoded: bytes) -> None:
        self.raw = self._header_bytes + buf[:msg_end]
        self._leftover += buf[msg_end:]
        self._buf = b""
        self.body = self._decompress(decoded)
        self.message_complete = True

    # -------------------------------------------------------------- finalize
    def _finalize(self, body_bytes: bytes) -> None:
        self.raw = self._header_bytes + body_bytes
        self.body = self._decompress(body_bytes)
        self.message_complete = True

    def _decompress(self, body: bytes) -> bytes:
        enc = self.headers.get("content-encoding", "").lower()
        if not body or not enc:
            return body
        try:
            if "gzip" in enc:
                return gzip.decompress(body)
            if "deflate" in enc:
                try:
                    return zlib.decompress(body)
                except zlib.error:
                    return zlib.decompress(body, -zlib.MAX_WBITS)
            if "br" in enc:
                try:
                    import brotli  # optional dependency
                    return brotli.decompress(body)
                except Exception:  # noqa: BLE001
                    return body
        except Exception as exc:  # noqa: BLE001 — inspection is best-effort
            logger.debug("decompress(%s) failed: %s", enc, exc)
            return body
        return body
