"""Build WAF dataset v2.

    python -m ml.waf.v2.build --root ~/FYP/waf_datasets --out ml/waf/data/build_v2

Writes train/val/test/test_ood JSONL (+ DATASET_CARD.md and dataset_v2.zip). Every value (clean or
attack) goes through the same shape recipe; splits are by payload group (no value in two splits);
HELD_OUT shapes appear only in test_ood, built from test-group values.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import zipfile
from collections import Counter

from ml.waf.taxonomy import LABELS
from ml.waf.v2 import benign, payloads, shapes

_HERE = os.path.dirname(__file__)
DATA_DIR = os.path.abspath(os.path.join(_HERE, "..", "data"))
MAX_TEXT = 2048
EXTRA_SHAPES_PER_VALUE = 2


def _group(text: str) -> str:
    return hashlib.sha1(text.encode("utf-8", "ignore")).hexdigest()[:12]


def _split_of(group: str) -> str:
    b = int(group, 16) % 100
    return "train" if b < 70 else "val" if b < 85 else "test"


def _read_jsonl(path: str, limit: int | None = None):
    n = 0
    try:
        with open(path, encoding="utf-8", errors="ignore") as f:
            for line in f:
                try:
                    r = json.loads(line)
                except ValueError:
                    continue
                if isinstance(r, dict) and r.get("text") and r.get("label") in LABELS:
                    yield r
                    n += 1
                    if limit and n >= limit:
                        return
    except OSError:
        return


def _local_attacks() -> list[dict]:
    out = []
    for name in ("seed_attacks.jsonl",):
        out += [r for r in _read_jsonl(os.path.join(DATA_DIR, name)) if r["label"] != "clean"]
    ext = os.path.join(DATA_DIR, "external", "synth_cmdi_raw.jsonl")
    out += [{**r, "source": "local:synth_cmdi_raw"} for r in _read_jsonl(ext) if r["label"] != "clean"]
    return out


def _local_benign_pool(rng: random.Random, n: int) -> list[str]:
    """A sample of URL/query-like benign strings from the local public pools (goodqueries etc.)."""
    pool: list[str] = []
    ext = os.path.join(DATA_DIR, "external")
    for name in ("fwaf_goodqueries.jsonl", "malicious_phish_benign.jsonl", "zanbil_access_log.jsonl"):
        path = os.path.join(ext, name)
        if not os.path.exists(path):
            continue
        reservoir: list[str] = []
        for i, r in enumerate(_read_jsonl(path)):
            t = r["text"]
            if r["label"] != "clean" or len(t) > 300:
                continue
            if len(reservoir) < n:
                reservoir.append(t)
            else:
                j = rng.randint(0, i)
                if j < n:
                    reservoir[j] = t
        pool += reservoir
    return pool


def _denied(text: str, denylist) -> bool:
    low = text.lower()
    return any(d and d.lower() in low for d in denylist)


def build(root: str, out_dir: str, seed: int = 42, n_clean: int = 36000, cap_per_attack: int = 9000,
          include_local_pools: bool = True, denylist: tuple = ()) -> dict:
    rng = random.Random(seed)
    os.makedirs(out_dir, exist_ok=True)

    attacks = payloads.load_attacks(root) + payloads.scanner_probes() + payloads.synth_ssti()
    if include_local_pools:
        attacks += _local_attacks()
    by_label: dict[str, list[dict]] = {}
    seen: set[str] = set()
    for r in attacks:
        t = r["text"]
        if _denied(t, denylist) or len(t) > MAX_TEXT or t.lower() in seen:
            continue
        seen.add(t.lower())
        by_label.setdefault(r["label"], []).append(r)
    values: list[tuple[str, str, str]] = []
    for label, recs in by_label.items():
        rng.shuffle(recs)
        values += [(r["text"], label, r["source"]) for r in recs[:cap_per_attack]]

    pool = _local_benign_pool(rng, 4000) if include_local_pools else []
    pool = [p for p in pool if not _denied(p, denylist)]
    for v in benign.generate(n_clean, seed=seed, pool=pool):
        if v.lower() not in seen and not _denied(v, denylist) and len(v) <= MAX_TEXT:
            seen.add(v.lower())
            values.append((v, "clean", "synthetic:v2"))

    native: dict[str, str] = {}
    for t in benign.credential_forms(600, seed=seed):
        if t.lower() not in seen and not _denied(t, denylist):
            seen.add(t.lower())
            values.append((t, "clean", "synthetic:credential_forms"))
            native[t] = "login"
    if include_local_pools:
        # realistic whole form bodies (login/checkout/contact) are already a complete shape: kept
        # as-is ("native"), not re-wrapped.
        for r in _read_jsonl(os.path.join(DATA_DIR, "external", "synth_benign_forms.jsonl"), limit=8000):
            t = r["text"]
            if r["label"] == "clean" and t.lower() not in seen and not _denied(t, denylist) and len(t) <= MAX_TEXT:
                seen.add(t.lower())
                values.append((t, "clean", "local:synth_benign_forms"))
                native[t] = "native"

    splits: dict[str, list[dict]] = {"train": [], "val": [], "test": [], "test_ood": []}
    for text, label, source in sorted(values):             # sorted -> deterministic
        g = _group(text)
        split = _split_of(g)
        if text in native:
            splits[split].append({"text": text, "label": label, "source": source, "shape": native[text], "group": g})
            continue
        chosen = ["bare"] + rng.sample(shapes.TRAIN_SHAPES, EXTRA_SHAPES_PER_VALUE)
        for shape in chosen:
            wrapped = shapes.SHAPES[shape](text, rng)
            if len(wrapped) <= MAX_TEXT:
                splits[split].append({"text": wrapped, "label": label, "source": source, "shape": shape, "group": g})
        if split == "test":
            oshape = rng.choice(sorted(shapes.HELD_OUT))
            wrapped = shapes.SHAPES[oshape](text, rng)
            if len(wrapped) <= MAX_TEXT:
                splits["test_ood"].append({"text": wrapped, "label": label, "source": source, "shape": oshape, "group": g})
    for recs in splits.values():
        rng.shuffle(recs)

    report = {"seed": seed, "counts": {k: len(v) for k, v in splits.items()},
              "labels": {k: dict(Counter(r["label"] for r in v)) for k, v in splits.items()},
              "shapes_train": dict(Counter(r["shape"] for r in splits["train"])),
              "sources": dict(Counter(r["source"].split(":")[0] for r in splits["train"]))}
    for name, recs in splits.items():
        with open(os.path.join(out_dir, f"{name}.jsonl"), "w", encoding="utf-8") as f:
            for r in recs:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
    with open(os.path.join(out_dir, "DATASET_CARD.md"), "w", encoding="utf-8") as f:
        f.write(_card(report))
    return report


def _card(rep: dict) -> str:
    lab = rep["labels"]["train"]
    lines = ["# WAF dataset v2", "",
             "Shape-balanced: clean and attack values go through identical carrier templates.",
             "Splits are by payload group (a value appears in exactly one split).",
             f"Held-out shapes (test_ood only): {sorted(shapes.HELD_OUT)}.", "",
             f"Seed: {rep['seed']}", "", "## Counts", "```", json.dumps(rep["counts"], indent=1), "```",
             "## Train labels", "```", json.dumps(lab, indent=1), "```",
             "## Train shapes", "```", json.dumps(rep["shapes_train"], indent=1), "```",
             "## Sources", "```", json.dumps(rep["sources"], indent=1), "```", "",
             "## Caveats",
             "- `scanner` is tiny and synthetic (tool user-agent strings); exclude it from ship gates.",
             "- `ssti` is partly synthetic (builtin:synth-ssti delimiter x expression grid); treat its recall as optimistic.",
             "- Kaggle archive.zip (payload_full.csv) was NOT used (needs credentials); public repos replace it.",
             "- Clean values are synthetic (Faker + hand-written hard negatives) plus local public URL pools.",
             "- No captured lab traffic is included."]
    return "\n".join(lines) + "\n"


def make_zip(out_dir: str, zip_path: str | None = None) -> str:
    zip_path = zip_path or os.path.join(out_dir, "dataset_v2.zip")
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as z:
        for n in ("train.jsonl", "val.jsonl", "test.jsonl", "test_ood.jsonl", "DATASET_CARD.md"):
            z.write(os.path.join(out_dir, n), n)
    return zip_path


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=os.path.expanduser("~/FYP/waf_datasets"))
    ap.add_argument("--out", default=os.path.join(DATA_DIR, "build_v2"))
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--n-clean", type=int, default=36000)
    ap.add_argument("--denylist", default=os.environ.get("WAF_V2_DENYLIST", ""),
                    help="comma-separated terms; any record containing one is dropped")
    a = ap.parse_args()
    deny = tuple(t.strip() for t in a.denylist.split(",") if t.strip())
    rep = build(a.root, a.out, seed=a.seed, n_clean=a.n_clean, denylist=deny)
    print(json.dumps(rep, indent=1))
    print("zip:", make_zip(a.out))


if __name__ == "__main__":
    main()
