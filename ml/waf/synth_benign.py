"""Synthetic benign form/JSON bodies — closes the credential-POST-body gap.

No public dataset carries real login/checkout/API form bodies (privacy), so
the clean corpus never saw `username=admin&password=...`-shaped text and the
retrained DistilBERT still blocks it at 0.999 confidence (see 2026-07-31
retrain notes). Faker fills that gap with structurally varied, non-real data:
several form "domains" (auth, checkout, search, contact, JSON API), each with
multiple key-name variants, so the model learns "structured key=value text is
often benign" rather than memorizing one exact shape.

Usage:
    python -m ml.waf.synth_benign --count 8000 --seed 42
"""
from __future__ import annotations

import argparse
import json
import os
import random

from faker import Faker

_HERE = os.path.dirname(__file__)
EXTERNAL_DIR = os.path.join(_HERE, "data", "external")

# Multiple key-name spellings per field so the model doesn't key off one exact
# name (e.g. always "username") — that would be as shallow as the gap it fixes.
_USER_KEYS = ["username", "user", "login", "uname", "email"]
_PASS_KEYS = ["password", "pass", "pwd", "passwd"]


def _form_safe(value: str) -> str:
    """Unencoded '&'/'=' in a value corrupt key=value structure (a real client
    would percent-encode them). Substitute rather than strip, so the value
    keeps its special-char shape/entropy."""
    return value.replace("&", "!").replace("=", "-")


def _login_form(fake: Faker, rng: random.Random) -> str:
    user_key = rng.choice(_USER_KEYS)
    pass_key = rng.choice(_PASS_KEYS)
    user_val = fake.user_name() if user_key != "email" else fake.email()
    pass_val = _form_safe(fake.password(length=rng.randint(8, 16)))
    extra = f"&remember={rng.choice(['true', 'false', '1', '0'])}" if rng.random() < 0.5 else ""
    return f"{user_key}={user_val}&{pass_key}={pass_val}{extra}"


def _checkout_form(fake: Faker, rng: random.Random) -> str:
    fields = {
        "name": fake.name(), "email": fake.email(), "address": fake.street_address(),
        "city": fake.city(), "zip": fake.postcode(), "card_last4": fake.credit_card_number()[-4:],
        "qty": str(rng.randint(1, 9)), "coupon": rng.choice(["", "SAVE10", "WELCOME5"]),
    }
    keys = rng.sample(list(fields), k=rng.randint(3, len(fields)))
    return "&".join(f"{k}={fields[k]}" for k in keys if fields[k])


def _search_form(fake: Faker, rng: random.Random) -> str:
    fields = {
        "q": " ".join(fake.words(nb=rng.randint(1, 4))),
        "category": rng.choice(["electronics", "books", "clothing", "toys", "sports"]),
        "sort": rng.choice(["price_asc", "price_desc", "newest", "rating"]),
        "page": str(rng.randint(1, 20)),
        "brand": fake.company(),
    }
    keys = rng.sample(list(fields), k=rng.randint(2, len(fields)))
    return "&".join(f"{k}={fields[k]}" for k in keys)


def _contact_form(fake: Faker, rng: random.Random) -> str:
    fields = {
        "name": fake.name(), "email": fake.email(), "subject": fake.sentence(nb_words=4),
        "message": fake.sentence(nb_words=rng.randint(6, 15)), "phone": fake.phone_number(),
    }
    keys = rng.sample(list(fields), k=rng.randint(2, len(fields)))
    return "&".join(f"{k}={fields[k]}" for k in keys)


def _iso8601(rng: random.Random) -> str:
    # Built from our own seeded rng, not Faker's iso8601() — that provider's
    # microsecond field draws from real wall-clock jitter, not the seeded
    # generator, which broke determinism (same seed, different output).
    y, mo, d = rng.randint(1990, 2026), rng.randint(1, 12), rng.randint(1, 28)
    h, mi, s, us = rng.randint(0, 23), rng.randint(0, 59), rng.randint(0, 59), rng.randint(0, 999999)
    return f"{y:04d}-{mo:02d}-{d:02d}T{h:02d}:{mi:02d}:{s:02d}.{us:06d}"


def _api_json(fake: Faker, rng: random.Random) -> str:
    payload = {
        "user_id": rng.randint(1000, 99999),
        "action": rng.choice(["view", "update", "delete", "create", "list"]),
        "token": fake.sha256()[:32],
        "timestamp": _iso8601(rng),
    }
    if rng.random() < 0.5:
        payload["email"] = fake.email()
    return json.dumps(payload)


_DOMAINS = {
    "synth_login": _login_form,
    "synth_checkout": _checkout_form,
    "synth_search": _search_form,
    "synth_contact": _contact_form,
    "synth_api_json": _api_json,
}


def generate(count: int, seed: int = 42) -> list[dict]:
    """Deterministic (same seed -> same output) synthetic benign corpus.

    Faker.seed() (the classmethod) reseeds the shared/default generator that
    ALL Faker() instances draw from process-wide — instance-level
    seed_instance() alone isn't reliably isolated from earlier Faker()
    instantiations in the same process (observed flaky determinism in tests
    when multiple generate() calls with different seeds run back-to-back).
    """
    Faker.seed(seed)
    rng = random.Random(seed)
    fake = Faker()
    fake.seed_instance(seed)
    domains = list(_DOMAINS.items())
    records = []
    for _ in range(count):
        source, fn = domains[rng.randrange(len(domains))]
        records.append({"text": fn(fake, rng), "label": "clean", "source": source})
    return records


def main() -> None:
    ap = argparse.ArgumentParser(prog="ml.waf.synth_benign", description="Generate synthetic benign form/JSON bodies")
    ap.add_argument("--count", type=int, default=8000)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--out", default=os.path.join(EXTERNAL_DIR, "synth_benign_forms.jsonl"))
    args = ap.parse_args()

    records = generate(args.count, seed=args.seed)
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")
    print(f"wrote {len(records)} synthetic benign records -> {args.out}")


if __name__ == "__main__":
    main()
