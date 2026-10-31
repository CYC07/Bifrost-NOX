"""Turn per-window model margins into allow / advisory / block.

The model (protectai/deberta-v3-base-prompt-injection-v2) is unchanged; only how its output is
trusted changes. The raw score cannot separate benign page/login text, developer system prompts and
repetitive text from real injections (both saturate), so a block needs more than a score:

  * a score far above the borderline range on its own (`solo`), or
  * a lower score plus a structural cue in the SAME window (override / replace / extract /
    fake-boundary / exfil / addressed-to-assistant, see cues.py)  (`cue`), or
  * a signature hit (handled by signatures.py, outside this module).

Weaker evidence is reported as ADVISORY (the text service turns that into CENSOR: allowed through,
shown as a WARN), never silently dropped. Developer-authored `system` text is advisory-only: the
model card itself warns that the scanner produces false positives on system prompts.

Margins are log-odds, logit(P(INJECTION)) = logit_injection - logit_safe, so thresholds keep their
resolution where the softmax saturates. Pure functions, no model: the offline evaluation
(dataset_tools/pi/analyze.py) and the service run the very same code.
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Iterable, Sequence

ALLOW, ADVISORY, BLOCK = "allow", "advisory", "block"


def margin_of(p: float) -> float:
    """P(INJECTION) -> log-odds margin."""
    p = min(max(p, 1e-12), 1 - 1e-12)
    return math.log(p / (1 - p))


@dataclass(frozen=True)
class GateConfig:
    solo_margin: float            # model-only block at/above this
    cue_margin: float             # block at/above this when the window also carries a cue
    advisory_margin: float        # advisory at/above this (anywhere, any role)
    block_roles: frozenset = frozenset({"user", "tool", "assistant", "unknown"})   # roles that may BLOCK
    solo_per_doubling: float = 0.0   # extra margin demanded of `solo` per doubling of a segment's window count
    agg: str = "max"              # per-segment aggregation over windows: max | top2
    ignore_roles: frozenset = frozenset()  # roles whose windows are neither scored nor reported (e.g. developer `system` text)


@dataclass(frozen=True)
class WindowScore:
    seg: int
    role: str
    n: int                        # windows in this window's segment
    margin: float
    cues: frozenset = frozenset()


@dataclass(frozen=True)
class Decision:
    action: str = ALLOW
    margin: float = -99.0         # the score the decision rests on
    role: str = ""
    cues: tuple = ()
    reason: str = ""

    @property
    def blocked(self) -> bool:
        return self.action == BLOCK

    @property
    def advisory(self) -> bool:
        return self.action == ADVISORY


def _solo_threshold(cfg: GateConfig, n: int) -> float:
    return cfg.solo_margin + (cfg.solo_per_doubling * math.log2(n) if n > 1 else 0.0)


def _segment_scores(wins: Sequence[WindowScore], cfg: GateConfig) -> dict[int, float]:
    by: dict[int, list[float]] = {}
    for w in wins:
        by.setdefault(w.seg, []).append(w.margin)
    out = {}
    for seg, ms in by.items():
        ms = sorted(ms, reverse=True)
        out[seg] = ms[1] if (cfg.agg == "top2" and len(ms) > 1) else ms[0]
    return out


def decide(wins: Iterable[WindowScore], cfg: GateConfig) -> Decision:
    wins = [w for w in wins if w.role not in cfg.ignore_roles]
    if not wins:
        return Decision()
    seg_score = _segment_scores(wins, cfg)

    # --- BLOCK: only windows whose role is allowed to block
    best_block: Decision | None = None
    for w in wins:
        if w.role not in cfg.block_roles:
            continue
        score = seg_score[w.seg]
        if score >= _solo_threshold(cfg, w.n):
            cand = Decision(BLOCK, score, w.role, tuple(sorted(w.cues)), "model")
        elif w.cues and w.margin >= cfg.cue_margin:
            cand = Decision(BLOCK, w.margin, w.role, tuple(sorted(w.cues)), "model+cue")
        else:
            continue
        if best_block is None or cand.margin > best_block.margin:
            best_block = cand
    if best_block is not None:
        return best_block

    # --- ADVISORY: anything borderline, or strong evidence in a role that may not block
    top = max(wins, key=lambda w: w.margin)
    if top.margin >= cfg.advisory_margin:
        why = "role" if top.role not in cfg.block_roles else "borderline"
        return Decision(ADVISORY, top.margin, top.role, tuple(sorted(top.cues)), why)
    return Decision(ALLOW, top.margin, top.role)


# Operating point chosen on the dev halves of the public evaluation (dataset_tools/pi/analyze.py):
#   solo     P(INJECTION) >= 0.999   (margin 6.9)  model alone blocks
#   cue      P(INJECTION) >= 0.9     (margin 2.2)  block only with a structural cue in the same window
#   advisory P(INJECTION) >= 0.9                   weaker evidence is reported (CENSOR), not blocked
# `system` text is not scored (model card: false positives on system prompts); `assistant` turns are
# model output replayed by the client and can only raise an advisory.
DEFAULT = GateConfig(solo_margin=margin_of(0.999), cue_margin=margin_of(0.9), advisory_margin=margin_of(0.9),
                     block_roles=frozenset({"user", "tool", "unknown"}), ignore_roles=frozenset({"system"}))


def default_config() -> GateConfig:
    """DEFAULT with optional env overrides given as P(INJECTION)."""
    import os  # noqa: PLC0415

    def p(name: str, fallback: float) -> float:
        try:
            return margin_of(float(os.environ[name]))
        except (KeyError, ValueError):
            return fallback
    return GateConfig(solo_margin=p("PROMPT_INJECTION_SOLO", DEFAULT.solo_margin),
                      cue_margin=p("PROMPT_INJECTION_CUE", DEFAULT.cue_margin),
                      advisory_margin=p("PROMPT_INJECTION_ADVISORY", DEFAULT.advisory_margin),
                      block_roles=DEFAULT.block_roles, solo_per_doubling=DEFAULT.solo_per_doubling, agg=DEFAULT.agg,
                      ignore_roles=DEFAULT.ignore_roles)
