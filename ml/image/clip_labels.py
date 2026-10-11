"""CLIP zero-shot label taxonomy, group mapping, and per-group cutoffs.

Moved out of image_service/main.py so the labels, their risk grouping, and the
decision thresholds live in one place. Groups:

  pii_nsfw  — identity documents and explicit content: block on their own.
  sensitive — DLP / phishing / proprietary visuals: advisory on their own,
              escalate to block when OCR also flags sensitive text (decided in
              aggregation, not here).
  benign    — logos, emblems, baseline photos: never block.

Cutoffs are the SAME numbers the original argmax code used (pii>0.4,
sensitive>0.6); Task 4 recalibrates them for the multi-label sigmoid path
against the synthetic corpus.
"""

SEMANTIC_LABELS = [
    # --- Sensitive content (original) ---
    "proprietary source code screenshot with api keys",
    "internal financial spreadsheet with sensitive data",
    "server network diagram with ip addresses",
    "official id card passport document",
    "pakistani cnic national identity card",
    "smart identity card with chip",
    "nsfw nude explicit sexual content",
    "pornography and adult content",
    "bikini lingerie or semi-nude person",
    "architectural blueprint of secure facility",

    # --- Generic logo / branding detection ---
    "corporate logo or brand watermark on an image",
    "company logo prominently displayed on a document",
    "brand logo on product packaging or advertisement",
    "generic business trademark or registered brand mark",
    "sports team or athletic brand logo",
    "luxury fashion brand logo",

    # --- Phishing / brand impersonation login pages ---
    "microsoft office 365 or outlook login page with logo",
    "google or gmail account sign in page with logo",
    "apple id icloud sign in page with logo",
    "paypal payment or login page with logo",
    "amazon account sign in page with logo",
    "facebook or meta login page with logo",
    "instagram login page with logo",
    "linkedin login page with logo",
    "netflix or streaming service login with logo",
    "dropbox or cloud storage login page with logo",
    "whatsapp or telegram login page with logo",

    # --- Banking / financial logos ---
    "bank login page with financial institution logo",
    "visa mastercard or credit card company logo",
    "major bank logo like hsbc chase citi bank of america",
    "cryptocurrency exchange logo like binance coinbase kraken",
    "digital wallet or payment app logo",

    # --- Government / official emblems ---
    "government official seal or national emblem",
    "police law enforcement or military badge logo",
    "tax authority or revenue department logo",

    # --- Corporate / DLP relevant ---
    "internal corporate document with company logo header",
    "employee id badge with company logo",
    "corporate presentation slide with company branding",
    "confidential report watermarked with company logo",

    # --- Benign / baseline ---
    "standard photo of nature or animals",
    "public website screenshot without branding",
    "generic bar chart or graph",
    "plain photograph with no logos or branding",
]

# Identity documents + explicit content — block on their own.
PII_NSFW_LABELS = {
    "official id card passport document",
    "pakistani cnic national identity card",
    "smart identity card with chip",
    "nsfw nude explicit sexual content",
    "pornography and adult content",
    "bikini lingerie or semi-nude person",
}

# DLP / phishing / proprietary — advisory alone, escalate with OCR text.
SENSITIVE_LABELS = {
    "proprietary source code screenshot with api keys",
    "internal financial spreadsheet with sensitive data",
    "server network diagram with ip addresses",
    "architectural blueprint of secure facility",
    "microsoft office 365 or outlook login page with logo",
    "google or gmail account sign in page with logo",
    "apple id icloud sign in page with logo",
    "paypal payment or login page with logo",
    "amazon account sign in page with logo",
    "facebook or meta login page with logo",
    "instagram login page with logo",
    "linkedin login page with logo",
    "netflix or streaming service login with logo",
    "dropbox or cloud storage login page with logo",
    "whatsapp or telegram login page with logo",
    "bank login page with financial institution logo",
    "cryptocurrency exchange logo like binance coinbase kraken",
    "internal corporate document with company logo header",
    "employee id badge with company logo",
    "corporate presentation slide with company branding",
    "confidential report watermarked with company logo",
}


def _group_for(label: str) -> str:
    if label in PII_NSFW_LABELS:
        return "pii_nsfw"
    if label in SENSITIVE_LABELS:
        return "sensitive"
    return "benign"


LABEL_GROUP = {label: _group_for(label) for label in SEMANTIC_LABELS}

# Cutoffs apply to the per-group MAX softmax probability (see
# ClipClassifier._group_scores for why max-softmax-prob, not raw-cosine sigmoid).
# These preserve the original argmax thresholds (pii>0.4, sensitive>0.6) while
# enabling multi-label firing.
#
# Measured on the synthetic corpus (2026-08-27), per-group max softmax prob:
#   benign_gradient  pii 0.02  sensitive 0.09   business_doc pii 0.01 sens 0.13
#   exif_gps         pii 0.06  sensitive 0.05   -> benign images stay well under
#   secret_screenshot sensitive 0.96 (true source-code screenshot) -> fires
# CAVEAT: no real ID-card / NSFW / phishing-page images were available to
# calibrate the pii_nsfw / sensitive TRUE-POSITIVE side — cutoffs are set from
# the benign false-positive margin only. A real labeled visual set is the
# follow-up (same "needs real data" honesty as the WAF clean-corpus arc).
GROUP_CUTOFF = {
    "pii_nsfw": 0.4,
    "sensitive": 0.6,
    "benign": 1.0,  # benign never blocks; cutoff unused
}
