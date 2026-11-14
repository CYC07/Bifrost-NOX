"""Cue coverage per eval set (regex only, no model): which cue families fire, and how often a cue
fires where signatures.py does not. Use --half dev while designing; test is for confirmation only."""
from __future__ import annotations

import argparse
import collections
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
from dataset_tools.pi.common import load_eval  # noqa: E402
from ml.prompt_injection import cues, signatures  # noqa: E402
from ml.prompt_injection.html_text import extract_text  # noqa: E402
from ml.prompt_injection.prompts import extract_segments  # noqa: E402


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--half", default="dev")
    ap.add_argument("--show", default="", help="set name: print cue-less attacks / cued benign of this set")
    args = ap.parse_args()
    items = [i for i in load_eval() if args.half == "all" or i["half"] == args.half]
    fams = list(cues.FAMILIES)
    by = collections.defaultdict(list)
    for it in items:
        segs = [s for s in extract_segments(it["body"]) if s.role != "system"]
        text = "\n".join(extract_text(s.text) for s in segs)
        by[it["set"]].append((it, cues.detect(text), bool(signatures.detect(text)), text))
    print(f"{'set':26s} {'lab':3s} {'n':>4s} {'sig':>6s} {'ANY':>6s} {'ANY&!sig':>8s} " + " ".join(f"{f[:8]:>8s}" for f in fams))
    for s in sorted(by):
        rows = by[s]
        n = len(rows)
        sig = sum(r[2] for r in rows)
        anyc = sum(bool(r[1]) for r in rows)
        anyns = sum(bool(r[1]) and not r[2] for r in rows)
        print(f"{s:26s} {rows[0][0]['label'][:3]:3s} {n:4d} {100*sig/n:5.1f}% {100*anyc/n:5.1f}% {100*anyns/n:7.1f}% "
              + " ".join(f"{100*sum(f in r[1] for r in rows)/n:7.1f}%" for f in fams))
    if args.show:
        rows = by[args.show]
        lab = rows[0][0]["label"]
        sel = [r for r in rows if (not r[1] and not r[2]) == (lab == "attack")] if lab == "attack" else [r for r in rows if r[1] or r[2]]
        print(f"\n{args.show}: {'cue-less attacks' if lab == 'attack' else 'benign with a cue/signature'} ({len(sel)}/{len(rows)})")
        for r in sel[:40]:
            print("  -", sorted(r[1]), repr(r[3][:200]))


if __name__ == "__main__":
    main()
