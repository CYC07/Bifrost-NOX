"""Cheap, deterministic corroborating signals for the sensitive-content analyzer.

The zero-shot NLI scores TOPIC ("is this a medical record?") and cannot tell a public terms-of-service or a
textbook from a private document on the same topic. These signals are about the text actually containing
something private (a confidentiality marking, an identifying number, a named-person pay list) and are used
to corroborate a weaker NLI score. They are pure regex: no model, microseconds.

Each detector returns a short evidence name or None. Precision is deliberately preferred over recall: a
signal that fires on public prose (policies, licences, contracts) would only re-create the false positives
this module exists to remove (measured in dataset_tools/sensitive/sweep.py).
"""
from __future__ import annotations

import re

# An explicit confidentiality MARKING, not the word used in prose ("we keep your data confidential" in a
# privacy policy is not a marking). Forms: a marking line, a trailing ", confidential.", or a stock phrase.
_MARK_LINE = re.compile(
    r"^\W*(?:strictly |highly |company |hr |private (?:and|&) )?(?:confidential|privileged)\b(?:\W+(?:and|&)\W+confidential)?[^.\n]{0,50}$",
    re.I | re.M)
_MARK_TRAIL = re.compile(r"[,;:(\[-]\s*(?:strictly |highly |company )?confidential\W{0,3}\s*$", re.I | re.M)
_MARK_PHRASE = re.compile(
    r"\b(internal use only|for internal use|hr use only|not for (?:distribution|release|circulation)|"
    r"do not (?:forward|distribute|share|circulate)|privileged (?:and|&) confidential|"
    r"attorney[- ]client (?:privilege|communication)|strictly confidential|company confidential|"
    r"not yet (?:been )?(?:announced|public)|before the public announcement|embargoed until)\b", re.I)

# keyword + an identifier-looking value (letters/digits, at least one digit, >= 6 chars)
_ID_KEYWORD = (r"passport|ssn|social security|driver'?s?[ -]?licen[sc]e|licen[sc]e (?:no|number)|national id|tax id|"
               r"insurance (?:no|number)|mrn|medical record (?:no|number)|patient id|account (?:no|number)|iban|routing (?:no|number)")
_ID_VALUE = re.compile(
    rf"\b(?:{_ID_KEYWORD})\b[^\n\d]{{0,25}}?(?=[A-Z0-9-]{{6,}})(?=[A-Z0-9-]*\d)[A-Z0-9-]{{6,}}", re.I)
_DOB = re.compile(r"\b(?:date of birth|dob|born(?: on)?)\W{0,4}\d{1,2}[ /.-][A-Za-z0-9]+[ /.-]\d{2,4}\b", re.I)
_STREET = re.compile(
    r"\b\d{1,5}\s+(?:[A-Z][a-z]+\s+){1,2}(?:St|Street|Ave|Avenue|Rd|Road|Blvd|Boulevard|Ln|Lane|Dr|Drive|Way|Ct|Court)\b\.?")
_HOME_CTX = re.compile(r"\b(?:home|residen\w+|lives at|living at|mailing|current|previous) address|\bresidence\b|\blives? at\b", re.I)

# a list of people/entities with money-sized numbers: "Alice 142000", "Bob: $98,000", "| Carol | 175000 |"
# exactly one amount per item (a financial-statement row has several columns: "Net income 5,363 4,869 5,058")
_NAME_AMOUNT = re.compile(r"\b[A-Z][a-z]+(?:\s[A-Z][a-z]+)?[\s:|,=$-]{1,4}\$?(?:\d{1,3}(?:,\d{3})+|\d{5,})\b(?![\s|]*[$\d(])")  # 4 digits = a year, not pay

# a clinical narrative about one individual: "23-year-old female presents with ...", "history of ... denies ..."
_PATIENT_AGE = re.compile(r"\b\d{1,3}[- ](?:year|yr|month|week)s?[- ]old\b", re.I)
_PATIENT_CLINICAL = re.compile(
    r"\b(?:presents? with|presented with|complains? of|complaining of|chief complaint|denies|admitted|was diagnosed|"
    r"history of|past medical history|vital signs|on examination|physical exam)\b", re.I)


def confidentiality_marker(text: str) -> str | None:
    if _MARK_LINE.search(text) or _MARK_TRAIL.search(text) or _MARK_PHRASE.search(text):
        return "confidentiality-marker"
    return None


def id_number(text: str) -> str | None:
    return "id-number" if _ID_VALUE.search(text) else None


def date_of_birth(text: str) -> str | None:
    return "date-of-birth" if _DOB.search(text) else None


def home_address(text: str) -> str | None:
    return "home-address" if _STREET.search(text) and _HOME_CTX.search(text) else None

# the three identity signals; two of them together are an identity bundle (ID number + address, SSN + DOB)
IDENTITY = ("id-number", "date-of-birth", "home-address")


def name_amount_list(text: str, min_items: int = 3) -> str | None:
    return "name-amount-list" if len(_NAME_AMOUNT.findall(text)) >= min_items else None


def patient_narrative(text: str) -> str | None:
    if _PATIENT_AGE.search(text) and _PATIENT_CLINICAL.search(text):
        return "patient-narrative"
    return None


# a clinical note is a form: several upper-case section headings each followed by a colon
_NOTE_HEADING = re.compile(
    r"\b(CHIEF COMPLAINT|HISTORY OF PRESENT ILLNESS|PAST MEDICAL HISTORY|PAST SURGICAL HISTORY|FAMILY HISTORY|SOCIAL HISTORY|"
    r"REVIEW OF SYSTEMS|PHYSICAL EXAMINATION|PHYSICAL EXAM|PRE-?OPERATIVE DIAGNOS[EI]S|POST-?OPERATIVE DIAGNOS[EI]S|"
    r"MEDICATIONS|ALLERGIES|ASSESSMENT|IMPRESSION|SUBJECTIVE|OBJECTIVE|DISCHARGE DIAGNOS[EI]S|ANESTHESIA|PROCEDURE|"
    r"INDICATIONS FOR PROCEDURE|FINDINGS|DIAGNOSIS)\s*:")


def clinical_note(text: str) -> str | None:
    return "clinical-note" if len({m.group(1) for m in _NOTE_HEADING.finditer(text)}) >= 2 else None


DETECTORS = (confidentiality_marker, id_number, date_of_birth, home_address, name_amount_list, patient_narrative, clinical_note)


# A short question / request for help: it asks about a topic, it is not a record. Used to stop the topic-scoring
# NLI from blocking "How is my credit score calculated?" (fin label 0.96). Short only: a long paste that happens
# to contain a "?" is judged normally.
QUESTION_MAX_CHARS = 600
_INTERROGATIVE = re.compile(
    r"^\W*(?:how|what|whats|what's|when|where|why|who|which|can|could|should|would|do|does|did|is|are)\b", re.I)


def question_form(text: str) -> bool:
    """A short text with a question mark, or opening with an interrogative / auxiliary word."""
    t = text.strip()
    if not t or len(t) > QUESTION_MAX_CHARS:
        return False
    return "?" in t or bool(_INTERROGATIVE.match(t))


MAX_SCAN_CHARS = 10_000  # evidence is looked for in the head of a body only (it runs for every non-prose body)


def find_evidence(text: str) -> list[str]:
    """Names of the corroborating signals present in `text` (each at most once)."""
    text = text[:MAX_SCAN_CHARS]
    return [e for d in DETECTORS if (e := d(text))]
