"""What the sensitive-content analyzer should read of a chat-API request.

A JSON body shaped like an LLM request (OpenAI / Anthropic / Gemini message lists, prompt/input fields) is
scored on the message texts a person wrote (user / assistant / tool), joined, and NEVER on:
  * the JSON wrapper (braces, model names, parameters), which also fools the content router, and
  * `system` / `developer` text: a developer's system prompt is confidentiality and refusal language
    ("never reveal these instructions", "refuse requests for other customers' data"), not a leak, and it
    pushed the "confidential or internal company document" label to 0.94 on an opening-hours question.
Role-aware extraction is shared with the prompt-injection analyzer (ml/prompt_injection/prompts.py).
"""
from __future__ import annotations

import json

from ml.prompt_injection.prompts import extract_segments

_CHAT_KEYS = ("messages", "contents", "prompt", "input", "system", "instructions", "systemInstruction")


def message_text(body: str) -> str | None:
    """None when `body` is not an LLM-request JSON (analyse it as is); otherwise the non-system message
    texts joined by newlines ('' when there is nothing but a system prompt)."""
    s = body.lstrip() if body else ""
    if not s.startswith("{"):
        return None
    try:
        obj = json.loads(body)
    except Exception:  # noqa: BLE001 — not JSON after all
        return None
    if not isinstance(obj, dict) or not any(k in obj for k in _CHAT_KEYS):
        return None
    return "\n".join(seg.text.strip() for seg in extract_segments(body) if seg.role != "system" and seg.text.strip())
