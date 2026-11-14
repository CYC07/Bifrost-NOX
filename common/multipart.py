"""Extract uploaded file parts from a multipart/form-data body.

An upload arrives as `--boundary\\r\\nContent-Disposition: ...`, so the whole body sniffs as text and
the file inside never reaches the document/image services. This returns the file parts so the
gateway can sniff and route each one. It never raises: any parse problem yields [] and the caller
falls back to whole-body analysis (fail open).
"""
from __future__ import annotations

import re
from dataclasses import dataclass

_BOUNDARY = re.compile(r'boundary\s*=\s*(?:"([^"]+)"|([^;\s]+))', re.I)
_FILENAME = re.compile(r'filename\*?\s*=\s*(?:"([^"]*)"|([^;\s]+))', re.I)
_NAME = re.compile(r'[;\s]name\s*=\s*(?:"([^"]*)"|([^;\s]+))', re.I)

DEFAULT_MAX_PARTS = 16
DEFAULT_MAX_PART_BYTES = 25 * 1024 * 1024


@dataclass(frozen=True)
class FilePart:
    name: str
    filename: str
    content_type: str
    data: bytes


def _boundary(content_type) -> bytes | None:
    if not isinstance(content_type, str) or not content_type.lower().lstrip().startswith("multipart/"):
        return None
    m = _BOUNDARY.search(content_type)
    if not m:
        return None
    b = (m.group(1) or m.group(2) or "").strip()
    return b.encode("latin-1", "ignore") if b else None


def _parse_headers(raw: bytes) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in raw.decode("latin-1", "ignore").split("\r\n"):
        k, sep, v = line.partition(":")
        if sep:
            out[k.strip().lower()] = v.strip()
    return out


def extract_file_parts(content_type, body, max_parts: int = DEFAULT_MAX_PARTS,
                       max_part_bytes: int = DEFAULT_MAX_PART_BYTES) -> list[FilePart]:
    try:
        boundary = _boundary(content_type)
        if not boundary or not isinstance(body, (bytes, bytearray)) or not body:
            return []
        delim = b"\r\n--" + boundary
        data = b"\r\n" + bytes(body)
        pieces = data.split(delim)[1:]          # [0] is the preamble
        parts: list[FilePart] = []
        for piece in pieces:
            if piece.startswith(b"--"):         # closing delimiter
                break
            head, sep, content = piece.partition(b"\r\n\r\n")
            if not sep:
                continue
            headers = _parse_headers(head.lstrip(b"\r\n"))
            disp = headers.get("content-disposition", "")
            ctype = headers.get("content-type", "")
            fm = _FILENAME.search(disp)
            filename = (fm.group(1) if fm and fm.group(1) is not None else (fm.group(2) if fm else "")) or ""
            is_file = bool(filename) or (bool(ctype) and not ctype.lower().startswith("text/"))
            if not is_file or len(content) > max_part_bytes:
                continue
            nm = _NAME.search(" " + disp)
            name = (nm.group(1) if nm and nm.group(1) is not None else (nm.group(2) if nm else "")) or ""
            parts.append(FilePart(name, filename, ctype, content))
            if len(parts) >= max_parts:
                break
        return parts
    except Exception:
        return []
