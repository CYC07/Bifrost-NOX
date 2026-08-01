"""Structural validators for secret patterns whose regex alone is too loose.

A regex like ``eyJ[A-Za-z0-9_-]+\\.eyJ...`` matches the SHAPE of a JWT but
also matches plenty of non-JWT text that happens to start the same way.
Validators here decode/parse the match to confirm it's actually the format
claimed, cutting false positives the regex alone can't.
"""
from __future__ import annotations

import base64
import json


def is_valid_jwt(token: str) -> bool:
    """A real JWT's header and payload segments are base64url-encoded JSON."""
    parts = token.split(".")
    if len(parts) != 3 or not all(parts):
        return False
    for segment in parts[:2]:
        padded = segment + "=" * (-len(segment) % 4)
        try:
            decoded = base64.urlsafe_b64decode(padded)
            json.loads(decoded)
        except Exception:
            return False
    return True
