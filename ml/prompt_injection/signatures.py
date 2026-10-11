"""IDS-style signatures for prompt-injection phrasing.

Cheap, deterministic, explainable — the generic-traffic tier. The transformer
classifier is far better at paraphrases but is scoped to LLM traffic (it
false-positives on ordinary UI text); these signatures are a tripwire for the
stock override phrases everywhere else. Every pattern needs an override verb
AND a specific target ("previous instructions", "system prompt", a named
jailbreak persona), so ordinary uses of the same words ("please disregard this
notice", "ignore any warnings", "you are now logged in") do not match.

Findings carry the signature name and span only — never the matched text.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import unquote_plus

_W = r"\W+"
_ZERO_WIDTH = dict.fromkeys(map(ord, "​‌‍⁠﻿"), None)


@dataclass(frozen=True)
class SignaturePattern:
    name: str
    regex: "re.Pattern[str]"
    severity: str = "high"


@dataclass(frozen=True)
class SignatureFinding:
    kind: str
    severity: str
    span: tuple[int, int]


def _p(name: str, pattern: str, severity: str = "high") -> SignaturePattern:
    return SignaturePattern(name, re.compile(pattern, re.I), severity)


_NOUN = r"(?:instructions?|rules?|prompts?|directions?|guidelines?|context|messages?|commands?|directives?)"
_PRIOR = r"(?:previous|prior|above|earlier|preceding|former|original|initial)"

PATTERNS: list[SignaturePattern] = [
    _p("override_prior_instructions",
       rf"\b(?:ignore|disregard|forget|override|discard)\b{_W}(?:(?:all|any|every|the|your|my|of|these|those){_W})*{_PRIOR}{_W}(?:and{_W}\w+{_W})?{_NOUN}\b"),
    _p("override_everything_above",
       rf"\b(?:ignore|disregard|forget){_W}(?:everything|anything|all){_W}(?:above|before|prior|previously|you(?:'ve|{_W}have)?{_W}(?:been{_W})?(?:told|said|learned))"),
    _p("override_the_above_then_act",
       rf"\b(?:ignore|disregard){_W}(?:all{_W})?(?:of{_W})?the{_W}above{_W}(?:and{_W})?(?:instead|now|just|only|then|output|print|say|reveal|respond|do)\b"),
    _p("reveal_system_prompt",
       rf"\b(?:reveal|print|show|display|repeat|output|leak|expose|disclose|tell{_W}me){_W}(?:me{_W})?(?:all{_W})?(?:of{_W})?(?:your|the){_W}(?:full{_W}|entire{_W}|complete{_W})?system{_W}(?:prompt|message|instructions)"),
    _p("reveal_hidden_instructions",
       rf"\b(?:hidden|secret|confidential){_W}(?:instructions?|rules|prompt|directives?)\b"),
    _p("repeat_text_verbatim",
       rf"\b(?:print|repeat|output|show|reveal){_W}[^.\n]{{0,40}}\b(?:above|before){_W}[^.\n]{{0,30}}\b(?:verbatim|word{_W}for{_W}word)\b"),
    _p("persona_jailbreak",
       rf"\byou{_W}are{_W}now{_W}(?:dan\b|(?:an?{_W})?(?:ai|assistant|chatbot|unrestricted|unfiltered|jailbroken|uncensored|evil)\b)|\bdo{_W}anything{_W}now\b|\b(?:as|called){_W}DAN\b"),
    _p("roleplay_without_restrictions",
       rf"\b(?:pretend|act|behave|imagine)\b[^.\n]{{0,50}}\b(?:without|no|free{_W}(?:of|from)|bypass(?:ing)?){_W}(?:any{_W})?(?:safety{_W}|content{_W}|ethical{_W})?(?:filters?|restrictions?|guidelines?|rules|limits|limitations|safeguards|censorship)\b"),
    _p("fake_system_marker",
       rf"(?:^|\n)\s*(?:#+\s*)?system\s*(?:override|prompt|message)\s*(?:#+|:)|\bnew{_W}(?:system{_W})?(?:instructions?|directives?|orders?)\s*[:—–-]"),
    _p("ignore_system_message",
       rf"\b(?:ignore|disregard|forget){_W}(?:your|the|all){_W}(?:earlier{_W}|previous{_W}|prior{_W})?system{_W}(?:message|prompt|instructions)"),
]


def _normalise(text: str) -> str:
    t = text.translate(_ZERO_WIDTH)
    if "%" in t or "+" in t:
        t = unquote_plus(t)
    return t


def detect(text: str) -> list[SignatureFinding]:
    if not text:
        return []
    t = _normalise(text)
    findings: list[SignatureFinding] = []
    for pat in PATTERNS:
        m = pat.regex.search(t)
        if m:
            findings.append(SignatureFinding(pat.name, pat.severity, m.span()))
    return findings
