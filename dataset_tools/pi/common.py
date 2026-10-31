"""Shared helpers for the prompt-injection gate evaluation tools."""
from __future__ import annotations

import hashlib
import json
import os
import sys
from dataclasses import dataclass

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if REPO not in sys.path:
    sys.path.insert(0, REPO)

from ml.prompt_injection.html_text import extract_text  # noqa: E402
from ml.prompt_injection.prompts import extract_segments, windows  # noqa: E402

CORPORA = os.path.expanduser(os.getenv("PI_CORPORA", "~/FYP/corpora"))
EVAL_PATH = os.path.join(CORPORA, "pi_eval", "eval.jsonl")
SCORES_DIR = os.path.join(CORPORA, "pi_scores")
MARGINS_PATH = os.path.join(SCORES_DIR, "margins.jsonl")
MAX_WINDOWS = 32            # PromptInjectionClassifier.predict_texts default


def th(text: str) -> str:
    return hashlib.sha1(text.encode("utf-8", "ignore")).hexdigest()


@dataclass(frozen=True)
class Win:
    seg: int        # segment index within the request
    role: str
    idx: int        # window index within the segment
    n: int          # windows in the segment
    seg_len: int    # chars of the segment (post HTML-reduction)
    text: str


def item_windows(body: str) -> list[Win]:
    """All windows the production path would form for this request body, BEFORE the 32-window cap."""
    out: list[Win] = []
    for si, seg in enumerate(extract_segments(body)):
        t = extract_text(seg.text)
        if not t or not t.strip():
            continue
        ws = windows(t)
        for wi, w in enumerate(ws):
            out.append(Win(si, seg.role, wi, len(ws), len(t), w))
    return out


def load_eval(path: str = EVAL_PATH) -> list[dict]:
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f]


def load_margins(path: str = MARGINS_PATH) -> dict[str, float]:
    m: dict[str, float] = {}
    if os.path.exists(path):
        with open(path) as f:
            for line in f:
                try:
                    r = json.loads(line)
                    m[r["h"]] = r["m"]
                except Exception:  # noqa: BLE001 - tolerate a torn last line
                    pass
    return m
