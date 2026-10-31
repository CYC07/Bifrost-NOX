"""Score a POOL of NLI hypotheses against every eval text once, so labels / templates / thresholds /
contrastive rules / aggregation can be swept offline (dataset_tools/sensitive/sweep.py) without re-running
the model.

The checkpoint is the production one (MoritzLaurer/deberta-v3-base-zeroshot-v2.0, no swap). With
multi_label=True the transformers zero-shot pipeline scores every (text, hypothesis) pair independently:
P(entailment) from a 2-way softmax [entailment, not_entailment]. So scoring any superset of the
production labels in one go gives, for each label, exactly the production score (checked by --parity).

    python -I dataset_tools/sensitive/nli_pool.py --repo . --eval ~/FYP/corpora/sens_eval/eval.jsonl \
        --out ~/FYP/corpora/sens_eval/pool_s1.jsonl --stage 1   # then --stage 2 -> pool_s2.jsonl

Reads/writes only JSON. One model-loading process at a time (RAM).
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from hypotheses import POOL, STAGE1, STAGE2  # noqa: E402

MODEL = "MoritzLaurer/deberta-v3-base-zeroshot-v2.0"
PROD_CHARS = 2000  # production passes text[:2000]


def load():
    import torch
    from transformers import AutoModelForSequenceClassification, AutoTokenizer
    torch.set_num_threads(int(os.getenv("NLI_THREADS", "4")))
    tok = AutoTokenizer.from_pretrained(MODEL)
    model = AutoModelForSequenceClassification.from_pretrained(MODEL, dtype=torch.float32).eval()
    return tok, model


def score_text(tok, model, text: str, hyps: dict[str, str], bs: int = 16) -> dict[str, float]:
    import torch
    keys = list(hyps)
    out: dict[str, float] = {}
    ent = model.config.label2id["entailment"]
    with torch.inference_mode():
        for i in range(0, len(keys), bs):
            ks = keys[i:i + bs]
            enc = tok([text] * len(ks), [hyps[k] for k in ks], return_tensors="pt", padding=True,
                      truncation="only_first", max_length=512)
            logits = model(**enc).logits  # [n, 2]
            # same as the pipeline: softmax over (not_entailment, entailment) -> P(entailment)
            p = torch.softmax(logits, dim=-1)[:, ent]
            for k, v in zip(ks, p.tolist()):
                out[k] = v
    return out


def window_text(text: str, which: str) -> str | None:
    if which == "first":
        return text[:PROD_CHARS]
    if which == "second":
        return text[PROD_CHARS:2 * PROD_CHARS] if len(text) > PROD_CHARS + 200 else None
    if which == "third":
        return text[2 * PROD_CHARS:3 * PROD_CHARS] if len(text) > 2 * PROD_CHARS + 200 else None
    raise SystemExit(f"unknown window {which}")


def parity(tok, model) -> None:
    """The pool's production-label scores must equal transformers' zero-shot pipeline."""
    import torch
    from transformers import pipeline
    from ml.sensitive.labels import get_labels
    pipe = pipeline("zero-shot-classification", model=MODEL, device=-1, dtype=torch.float32)
    texts = ["Here is the patient's full medical record including diagnosis and HIV status.",
             "Our terms of service describe how we handle your account and data.",
             "Employee salary list: Alice 142000, Bob 98000, Carol 175000, confidential."]
    labels = get_labels()
    worst = 0.0
    for t in texts:
        ref = pipe(t, candidate_labels=labels, multi_label=True, truncation=True)
        ref = dict(zip(ref["labels"], ref["scores"]))
        mine = score_text(tok, model, t, {l: POOL[f"t0:{l}"] for l in labels})
        for l in labels:
            worst = max(worst, abs(ref[l] - mine[l]))
    print(f"parity: max |pipeline - pool| over {len(texts) * len(labels)} scores = {worst:.2e}")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--eval", default=os.path.expanduser("~/FYP/corpora/sens_eval/eval.jsonl"))
    ap.add_argument("--out", default="")
    ap.add_argument("--window", default="first")
    ap.add_argument("--stage", type=int, default=1, help="1 = the six production hypotheses, 2 = the extra pool")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--parity", action="store_true")
    ap.add_argument("--repo", default=os.getcwd())
    a = ap.parse_args()
    sys.path.insert(0, a.repo)
    tok, model = load()
    if a.parity:
        parity(tok, model)
        return
    keys = STAGE1 if a.stage == 1 else STAGE2
    hyps = {k: POOL[k] for k in keys}
    recs = [json.loads(l) for l in open(a.eval, encoding="utf-8")]
    if a.limit:
        recs = recs[:a.limit]
    done: set[str] = set()
    if os.path.exists(a.out):
        done = {json.loads(l)["id"] for l in open(a.out, encoding="utf-8")}
    t0 = time.time()
    n = 0
    with open(a.out, "a", encoding="utf-8") as f:
        for r in recs:
            if r["id"] in done:
                continue
            w = window_text(r["text"], a.window)
            if w is None:
                continue
            s = score_text(tok, model, w, hyps)
            f.write(json.dumps({"id": r["id"], "win": a.window, "s": s}) + "\n")
            f.flush()
            n += 1
            if n % 50 == 0:
                print(f"{n} docs, {(time.time() - t0) / n:.2f}s/doc", flush=True)
    print(f"done {n} docs in {time.time() - t0:.0f}s")


if __name__ == "__main__":
    main()
