"""IBAN helpers shared by the text service and the image OCR scan.

Presidio's IbanRecognizer (entity IBAN_CODE) validates country format + mod-97, but its
generic pattern is compiled case-insensitive and greedily takes up to 6 more 4-char groups
plus 1-3 trailing characters. When a BBAN is whole 4-char groups (ES, SE, AT, BE, PL, ...)
the following word joins the match ("ES91 ... 1332 toda" + "y") and its fallback only tries
the capture-group ends, so the checksum is never computed over the bare IBAN: found by
probing, an ES/SE IBAN followed by "today" or "before friday" was missed. presidio_safe()
replaces the single separator between an IBAN-shaped run and a following lowercase word
with a tab (same length, so offsets are unchanged); Presidio itself is unchanged.
"""
import re

# Anything IBAN-shaped (case-sensitive: IBANs are written in capitals), valid or not.
IBAN_SHAPED = re.compile(r"(?<![A-Z0-9])[A-Z]{2}\d{2}(?:[ -]?[A-Z0-9]{4}){2,7}(?:[ -]?[A-Z0-9]{1,3})?(?![A-Z0-9])")
_IBAN_THEN_WORD = re.compile(r"(?<![A-Z0-9])[A-Z]{2}\d{2}(?:[ -]?[A-Z0-9]{4}){2,7}(?:[ -]?[A-Z0-9]{1,3})?"
                             r"(?=[ -][A-Za-z0-9]*[a-z])")


def presidio_safe(text: str) -> str:
    """Same-length copy of `text` in which Presidio's IBAN pattern cannot run into the next word."""
    if not text:
        return text
    chars = None
    for m in _IBAN_THEN_WORD.finditer(text):
        chars = chars or list(text)
        chars[m.end()] = "\t"
    return "".join(chars) if chars else text


def inside_iban_shape(text: str, start: int, end: int) -> bool:
    """True if [start, end) lies inside an IBAN-shaped run (e.g. a 4x4 digit group of an IBAN)."""
    return any(m.start() <= start and end <= m.end() for m in IBAN_SHAPED.finditer(text))
