"""Prepare LLM-bound request bodies for the prompt-injection classifier.

extract_prompts(): pull out the *language* an LLM would read (message contents,
prompt/input/system fields, Gemini parts) instead of scoring the JSON wrapper.
windows(): split long text into overlapping windows. The classifier reads only
~512 tokens, and the old `text[:2000]` truncation let an attacker hide an
injection behind 2000 characters of benign padding.

Limitation: windows are capped (default 16). Past the cap, evenly spaced
windows plus head and tail are scored, so an injection in the *middle* of a very
large (>~16 KB) prompt can still be missed.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass

logger = logging.getLogger("prompt_injection.prompts")

_MIN_LEAF = 20  # fallback for unknown JSON: only free-text-looking strings


@dataclass(frozen=True)
class Segment:
    """One string an LLM would read, with the role of the message it came from."""
    role: str   # system | user | assistant | tool | unknown
    text: str


_ROLE_ALIASES = {"developer": "system", "model": "assistant", "ai": "assistant", "human": "user",
                 "prompter": "user", "function": "tool"}


def _norm_role(role, default: str) -> str:
    if not isinstance(role, str) or not role.strip():
        return default
    r = role.strip().lower()
    return _ROLE_ALIASES.get(r, r)


def _segs(node, role: str) -> list[Segment]:
    """Text from a message-ish value: str, list of str/parts, or {"text"/"content"/"parts"}."""
    if node is None:
        return []
    if isinstance(node, str):
        return [Segment(role, node)] if node.strip() else []
    if isinstance(node, list):
        out: list[Segment] = []
        for item in node:
            out.extend(_segs(item, role))
        return out
    if isinstance(node, dict):
        if node.get("type") in {"image_url", "image", "input_image", "audio", "input_audio"}:
            return []
        out = []
        for key in ("text", "content", "parts", "input_text"):
            if key in node:
                out.extend(_segs(node[key], role))
        return out
    return []


def _messages(node, default: str) -> list[Segment]:
    """A messages/contents list: each element may carry its own role."""
    if isinstance(node, list):
        out: list[Segment] = []
        for item in node:
            r = _norm_role(item.get("role"), default) if isinstance(item, dict) else default
            out.extend(_segs(item, r))
        return out
    return _segs(node, default)


def _leaves(node, out: list[str]) -> None:
    if isinstance(node, str):
        if len(node.strip()) >= _MIN_LEAF:
            out.append(node)
    elif isinstance(node, dict):
        for v in node.values():
            _leaves(v, out)
    elif isinstance(node, list):
        for v in node:
            _leaves(v, out)


def extract_segments(body: str) -> list[Segment]:
    """The language an LLM would read, each string tagged with its message role."""
    if not body or not body.strip():
        return []
    if not body.lstrip().startswith(("{", "[")):
        return [Segment("unknown", body)]
    try:
        obj = json.loads(body)
    except Exception:  # noqa: BLE001 — not JSON after all
        return [Segment("unknown", body)]
    out: list[Segment] = []
    if isinstance(obj, dict):
        for key in ("system", "instructions"):
            out.extend(_segs(obj.get(key), "system"))
        for key in ("prompt", "input"):
            out.extend(_segs(obj.get(key), "user"))
        if "systemInstruction" in obj:
            out.extend(_segs(obj["systemInstruction"], "system"))
        for key in ("messages", "contents"):
            if key in obj:
                out.extend(_messages(obj[key], "user"))
        if out or any(k in obj for k in ("messages", "contents", "prompt", "input")):
            # recognised LLM shape: score only its language, even if that's empty
            return [s for s in out if s.text.strip()]
    leaves: list[str] = []
    _leaves(obj, leaves)
    return [Segment("unknown", t) for t in leaves]


def extract_prompts(body: str) -> list[str]:
    return [s.text for s in extract_segments(body)]


def windows(text: str, size: int = 1500, stride: int = 1000, cap: int = 16) -> list[str]:
    if len(text) <= size:
        return [text]
    starts = list(range(0, len(text) - size, stride))
    starts.append(len(text) - size)                      # always include the tail
    starts = sorted(set(starts))
    if len(starts) > cap:
        logger.info("prompt of %d chars has %d windows; sampling %d (middle may be unscanned)", len(text), len(starts), cap)
        idx = sorted({round(i * (len(starts) - 1) / (cap - 1)) for i in range(cap)})
        starts = [starts[i] for i in idx]
    return [text[s:s + size] for s in starts]
