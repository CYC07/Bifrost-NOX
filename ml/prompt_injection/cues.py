"""Structural cues that distinguish an instruction aimed at the model from text that merely sounds
like one.

signatures.py is the high-precision tripwire (it blocks outright). The transformer is far better on
paraphrases but saturates on ordinary page text, login forms, repetitive text and developer
system prompts. Its borderline/saturated scores are only trusted when the text ALSO shows how a
real injection is built: it tries to override or replace what the model was told, to extract what
the model was told, to open a fake role/delimiter boundary, to redirect output to an outside
party, or to address "the assistant" from inside content. These cues are deliberately NOT the
signature phrases and NOT bare "you must ..." / "act as ..." imperatives: those are the
dominant shape of legitimate prompts and would add no evidence.

A cue is a family name; detect() returns the families that matched. Cheap regex, no model.
"""
from __future__ import annotations

import re
from urllib.parse import unquote_plus

_ZERO_WIDTH = dict.fromkeys(map(ord, "​‌‍⁠﻿"), None)
_W = r"[\s\W_]{1,6}"


def _c(pattern: str) -> "re.Pattern[str]":
    return re.compile(pattern, re.I | re.S)


_OVERRIDE_VERB = r"(?:ignor(?:e|ing)|disregard(?:ing)?|forget(?:ting)?|overrid(?:e|ing)|bypass(?:ing)?|discard|abandon|neglect|stop\s+following|do\s+not\s+follow|don'?t\s+follow|no\s+longer\s+follow)"
_OVERRIDE_OBJ = (r"(?:instructions?|rules?|guidelines?|directives?|prompts?|tasks?|commands?|training|programming|restrictions?|constraints?|"
                 r"polic(?:y|ies)|safeguards?|filters?|limitations?|context|conversation|everything|anything|above|previous|prior|earlier|"
                 r"preceding|before|system|safety|what\s+(?:i|you|they|we)\s+(?:said|told|wrote|were\s+told))")

FAMILIES: dict[str, "re.Pattern[str]"] = {
    # replace / cancel what the model was told
    "override": _c(rf"\b{_OVERRIDE_VERB}\b[^.\n]{{0,45}}\b{_OVERRIDE_OBJ}\b"),
    "new_instructions": _c(
        r"\b(?:new|real|actual|true|updated|revised|different|secret|hidden|additional)\s+(?:instructions?|task|objective|directives?|orders?|rules?|mission|prompt)\b"
        r"|\bfrom\s+(?:now\s+on|this\s+point\s+(?:on|forward))\b|\bstarting\s+(?:now|immediately)\b"
        r"|\binstead\b[,:]?\s*(?:you\s+(?:must|should|will|shall)\s+)?(?:please\s+)?(?:do|say|output|print|write|respond|reply|answer|tell|send|reveal|give|list|show|provide|visit|email|forward|repeat)\b"
        r"|\byour\s+(?:only|new|real|actual|true|primary|first)\s+(?:task|goal|purpose|job|instruction|objective|priority)\b"
        r"|\b(?:stop|cease)\s+(?:being|acting|answering|responding)\b|\byou\s+are\s+no\s+longer\b"),
    # extract what the model was told / holds
    "extract": _c(
        r"\b(?:reveal|print|output|repeat|show|display|leak|expose|disclose|dump|recite|write\s+out|tell\s+me|give\s+me|share|send\s+me|echo)\b[^.\n]{0,30}"
        r"\b(?:your|the)\s+(?:(?:full|entire|complete|initial|original|hidden|secret|system|internal|exact)\s+)*"
        r"(?:prompt|instructions?|rules|configuration|system\s+(?:prompt|message)|guidelines|password|secret|api[\s_-]?key|credentials?|training\s+data|token)s?\b"
        r"|\b(?:text|everything|content|words)\s+(?:above|before)\s+(?:this|here)\b|\bverbatim\b"),
    # fake role / delimiter boundary
    "boundary": _c(
        r"<\|?(?:im_start|im_end|system|endoftext)\|?>|\[/?INST\]|<<\s*/?SYS\s*>>|</?(?:system|assistant|admin)>"
        r"|(?:^|\n)\s*(?:#{1,4}\s*)?(?:system|assistant|developer|admin|root|human)\s*[:\]>]\s*\S"
        r"|(?:^|\n)\s*#{2,}\s*(?:system|instruction|new|end|override)"
        r"|</(?:document|context|email|text|article|data|input|prompt|user|query)>"
        r"|\b(?:end|begin)\s+of\s+(?:document|text|input|context|system|instructions?)\b|\[(?:system|admin|override|end)\]"),
    # redirect data/output to an outside party
    "exfil": _c(
        r"\b(?:send|post|email|e-mail|forward|upload|submit|exfiltrate|transmit|leak|copy)\b[^.\n]{0,60}(?:https?://|\bto\s+\S+@\S+|\S+@\S+\.\w+|attacker|evil\b)"
        r"|\b(?:visit|go\s+to|open|fetch|navigate\s+to|browse\s+to)\s+(?:https?://|www\.)\S+[^.\n]{0,40}\b(?:and|then)\b[^.\n]{0,20}\b(?:submit|send|post|enter|upload|paste)"),
    # content addressing the model directly
    "addressed": _c(
        r"(?:^|[\s(\[])(?:hey\s+|hi\s+|dear\s+|attention[:,]?\s+|note\s+to\s+)?(?:assistant|ai\s+(?:agent|assistant|model|system)s?|language\s+model|llm|chatbot|gpt|chatgpt|claude|gemini|bot)s?\s*(?:[,:!]|reading|who\s+(?:is\s+)?reading)"
        r"|\b(?:ai|llm|assistant|model)s?\s+(?:that\s+)?(?:is\s+|are\s+)?(?:reading|processing|summari[sz]ing|analy[sz]ing)\s+(?:this|the)\b"),
    # persona / unrestricted-mode setups
    "persona": _c(
        r"\byou\s+(?:are|will\s+be|shall\s+be)\s+(?:now\s+)?(?:going\s+to\s+(?:pretend|act|be)|(?:in|entering)\s+\w+\s+mode)"
        r"|\bdo\s+anything\s+now\b|\bdeveloper\s+mode\b|\bjailbr(?:eak|oken)\b|\bunrestricted\b|\buncensored\b|\bunfiltered\b"
        r"|\b(?:no|without\s+any|without)\s+(?:ethical|moral|safety|content)?\s*(?:restrictions?|guidelines|filters?|limitations?|censorship|boundaries)\b"
        r"|\bnot\s+bound\s+by\b|\bfree\s+(?:of|from)\s+(?:all\s+)?(?:restrictions|rules|limitations)\b"),
    # abandon the user's question for another job
    "task_switch": _c(
        r"\b(?:forget|ignore|drop|abandon|skip)\s+(?:about\s+)?(?:the|that|this|my|your|his|her|their)\s+(?:user'?s?\s+)?(?:question|request|task|query|prompt|problem|summary|translation)\b"
        r"|\binstead\s+of\s+(?:answering|summari[sz]ing|translating|responding|doing|following)\b|\bnew\s+task\b|\bunrelated\s+task\b"),
}


def _normalise(text: str) -> str:
    t = text.translate(_ZERO_WIDTH)
    if "%" in t or "+" in t:
        t = unquote_plus(t)
    return t


def detect(text: str) -> frozenset[str]:
    """Cue families present in `text` (empty set: none)."""
    if not text:
        return frozenset()
    t = _normalise(text)
    return frozenset(name for name, rx in FAMILIES.items() if rx.search(t))
