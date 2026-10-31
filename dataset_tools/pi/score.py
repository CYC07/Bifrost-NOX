"""Score every window of the eval set ONCE with the raw protectai v2 model and cache the logit margin.

margin = logit(INJECTION) - logit(SAFE); P(INJECTION) = sigmoid(margin). Working in margins
(log-odds) keeps resolution past the float32 softmax saturation (p > 1 - 6e-8) that the
pipeline's score collapses to - exactly where the benign login form (0.99999964) and the
weakest real attack (0.99999380) sit. Tokenisation matches the pipeline: truncation to the
tokenizer's 512 limit, batch of windows, CPU.

Cache: ~/FYP/corpora/pi_scores/margins.jsonl  {"h": sha1(window text), "m": margin}
Every policy experiment (dataset_tools/pi/analyze.py) is then a cheap pass over this cache; texts
not yet cached are scored on demand by `score_texts`. ONE model process at a time (RAM).

Usage: python -I dataset_tools/pi/score.py [--limit N] [--plain]
"""
from __future__ import annotations

import argparse
import collections
import json
import os
import sys
import time

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
from dataset_tools.pi.common import MARGINS_PATH, SCORES_DIR, item_windows, load_eval, load_margins, th  # noqa: E402

MODEL = os.getenv("PROMPT_INJECTION_MODEL", "protectai/deberta-v3-base-prompt-injection-v2")


def score_texts(texts: list[str], batch_size: int = 16, log_every: int = 200, pool: int = 0) -> dict[str, float]:
    """Return {sha1(text): margin} for all texts, scoring only what the cache lacks.
    pool>0: keep the given order at a coarse level (so a partial run covers whole items) and sort by
    length only inside consecutive pools of that many windows (padding efficiency)."""
    import torch  # noqa: PLC0415
    from transformers import AutoModelForSequenceClassification, AutoTokenizer  # noqa: PLC0415
    cache = load_margins()
    todo = {}
    for t in texts:
        h = th(t)
        if h not in cache:
            todo[h] = t
    if todo:
        os.makedirs(SCORES_DIR, exist_ok=True)
        tok = AutoTokenizer.from_pretrained(MODEL)
        model = AutoModelForSequenceClassification.from_pretrained(MODEL).eval()
        inj = [i for i, lab in model.config.id2label.items() if lab.upper() == "INJECTION"][0]
        safe = 1 - inj
        order = list(todo)
        if pool:
            order = [h for i in range(0, len(order), pool) for h in sorted(order[i:i + pool], key=lambda h: len(todo[h]))]
        else:
            order = sorted(order, key=lambda h: len(todo[h]))
        t0, done = time.time(), 0
        with open(MARGINS_PATH, "a") as f, torch.inference_mode():
            for i in range(0, len(order), batch_size):
                hs = order[i:i + batch_size]
                enc = tok([todo[h] for h in hs], truncation=True, max_length=512, padding=True, return_tensors="pt")
                logits = model(**enc).logits.double()
                for h, row in zip(hs, logits):
                    m = float(row[inj] - row[safe])
                    cache[h] = m
                    f.write(json.dumps({"h": h, "m": m}) + "\n")
                f.flush()
                done += len(hs)
                if (done // batch_size) % max(1, log_every // batch_size) == 0:
                    print(f"  scored {done}/{len(order)} ({done / (time.time() - t0):.1f}/s)", flush=True)
    return {th(t): cache[th(t)] for t in texts}


def interleave(items: list[dict], seed: int, budget_chars: int = 300_000, min_per_set: int = 30,
               max_per_set: int = 150, max_long_per_set: int = 15) -> list[dict]:
    """Round-robin over sets (each set shuffled): any prefix of the result is a stratified sample, so a
    run stopped early still yields a usable eval (analyze.py --partial skips unscored items)."""
    import random  # noqa: PLC0415
    rng = random.Random(seed)
    by: dict[str, list[dict]] = {}
    for it in items:
        by.setdefault(it["set"], []).append(it)
    for v in by.values():
        rng.shuffle(v)
    caps = {}
    for name, v in by.items():                   # long items are expensive: fewer of them, same dev/test balance
        avg = sum(len(x["plain"]) for x in v) / len(v)
        caps[name] = min(len(v), min(max_per_set, max(min_per_set, int(budget_chars / max(avg, 1)))))

    def long_item(x: dict) -> bool:
        return any(len(w.text) >= 1000 and w.role != "system" for w in item_windows(x["body"]))

    cheap, long_, kept_long = [], [], collections.Counter()
    for k in range(max(caps.values())):
        for name in sorted(by):
            if k >= caps[name]:
                continue
            x = by[name][k]
            if long_item(x):
                if kept_long[name] < max_long_per_set:
                    kept_long[name] += 1
                    long_.append(x)
            else:
                cheap.append(x)
    return cheap + long_                         # every cheap item first, then a few long ones per set


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--plain", action="store_true", help="also score the plain-text variant of every item")
    ap.add_argument("--only-sets", default="", help="comma list of set names to score (default: all)")
    ap.add_argument("--shuffle", type=int, default=0, help="seed: visit items in random order (partial runs stay usable)")
    args = ap.parse_args()
    items = load_eval()
    if args.only_sets:
        wanted = set(args.only_sets.split(","))
        items = [it for it in items if it["set"] in wanted]
    if args.limit:
        items = items[:args.limit]
    if args.shuffle:
        items = interleave(items, args.shuffle)
    texts = []
    for it in items:
        texts += [w.text for w in item_windows(it["body"])]
        if args.plain:
            texts += [w.text for w in item_windows(it["plain"])]
    uniq = list(dict.fromkeys(texts))
    print(f"{len(items)} items, {len(texts)} windows, {len(uniq)} unique", flush=True)
    score_texts(uniq, pool=128 if args.shuffle else 0)
    print("done", flush=True)


if __name__ == "__main__":
    main()
