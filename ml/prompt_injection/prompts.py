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

logger = logging.getLogger("prompt_injection.prompts")

_MIN_LEAF = 20  # fallback for unknown JSON: only free-text-looking strings


def _strings(node) -> list[str]:
    """Text from a message-ish value: str, list of str/parts, or {"text"/"content"/"parts"}."""
    if node is None:
        return []
    if isinstance(node, str):
        return [node] if node.strip() else []
    if isinstance(node, list):
        out: list[str] = []
        for item in node:
            out.extend(_strings(item))
        return out
    if isinstance(node, dict):
        if node.get("type") in {"image_url", "image", "input_image", "audio", "input_audio"}:
            return []
        out = []
        for key in ("text", "content", "parts", "input_text"):
            if key in node:
                out.extend(_strings(node[key]))
        return out
    return []


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


def extract_prompts(body: str) -> list[str]:
    if not body or not body.strip():
        return []
    if not body.lstrip().startswith(("{", "[")):
        return [body]
    try:
        obj = json.loads(body)
    except Exception:  # noqa: BLE001 — not JSON after all
        return [body]
    out: list[str] = []
    if isinstance(obj, dict):
        for key in ("system", "instructions", "prompt", "input"):
            out.extend(_strings(obj.get(key)))
        if "systemInstruction" in obj:
            out.extend(_strings(obj["systemInstruction"]))
        for key in ("messages", "contents"):
            if key in obj:
                out.extend(_strings(obj[key]))
        if out or any(k in obj for k in ("messages", "contents", "prompt", "input")):
            # recognised LLM shape: score only its language, even if that's empty
            return [s for s in out if s.strip()]
    leaves: list[str] = []
    _leaves(obj, leaves)
    return leaves


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
