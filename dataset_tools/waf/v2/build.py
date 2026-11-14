"""Build WAF dataset v2.

    python -m dataset_tools.waf.v2.build --root ~/waf_datasets --out dataset_tools/waf/data/build_v2

Writes train/val/test/test_ood JSONL (+ DATASET_CARD.md and dataset_v2.zip). Every value (clean or
attack) goes through the same shape recipe; splits are by payload group (no value in two splits);
HELD_OUT shapes appear only in test_ood, built from test-group values.

With ``--holdout-source fuzzdb`` a whole payload SOURCE is held out: train/val/test/test_ood contain no
payload from it, and a separate ``test_holdout.jsonl`` holds only those payloads (wrapped in the
training shapes) plus the hand-written probes and realistic benign bodies of ``probes.py``. That file
measures generalisation to payloads the model's corpus never contained, which the group-hash split alone
cannot (near-identical payloads from one repo land in train and test). Without the flag the output is
byte-identical to what this builder wrote before the flag existed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import zipfile
from collections import Counter
from urllib.parse import unquote

from ml.waf.taxonomy import LABELS
from dataset_tools.waf.v2 import benign, benign_real, payloads, probes, shapes

_HERE = os.path.dirname(__file__)
DATA_DIR = os.path.abspath(os.path.join(_HERE, "..", "data"))
MAX_TEXT = 2048
_REAL_BENIGN_SEED_OFFSET = 104729   # real-benign sampling has its own RNG stream; the main one is untouched
EXTRA_SHAPES_PER_VALUE = 2
HOLDOUT_FILE = "test_holdout.jsonl"
_HOLDOUT_SEED_OFFSET = 7919       # the holdout wrapping has its own RNG stream; the main one is untouched


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


def _parse_holdout(holdout_source) -> tuple[str, ...]:
    """'fuzzdb' / 'fuzzdb,seclists' / ['fuzzdb'] -> ('fuzzdb',); None/'' -> ()."""
    if not holdout_source:
        return ()
    items = holdout_source.split(",") if isinstance(holdout_source, str) else list(holdout_source)
    return tuple(i.strip() for i in items if i and i.strip())


def _source_of(rec: dict) -> str:
    return rec["source"].split(":")[0]


def _twin_key(text: str) -> str:
    """Normal form for near-duplicate detection: percent-decoded (twice), lower-cased, whitespace collapsed."""
    for _ in range(2):
        text = unquote(text)
    return " ".join(text.lower().split())


def build(root: str, out_dir: str, seed: int = 42, n_clean: int = 36000, cap_per_attack: int = 9000,
          include_local_pools: bool = True, denylist: tuple = (), holdout_source=None,
          system_text_roots: tuple = ()) -> dict:      # opt-in: the CLI passes /usr/share, library callers/tests do not
    rng = random.Random(seed)
    os.makedirs(out_dir, exist_ok=True)
    holdout = _parse_holdout(holdout_source)
    stale = os.path.join(out_dir, HOLDOUT_FILE)
    if not holdout and os.path.exists(stale):
        os.remove(stale)         # a leftover from an earlier holdout build must not end up in this zip

    # crs before nuclei: on an exact-text collision the earlier record wins, so a held-out crs payload
    # is never dropped in favour of a training copy (and vice versa never leaks: the copy is removed)
    attacks = (payloads.load_attacks(root) + payloads.load_crs(root) + payloads.load_nuclei(root)
               + payloads.scanner_probes() + payloads.synth_ssti())
    if include_local_pools:
        attacks += _local_attacks()
    by_label: dict[str, list[dict]] = {}
    seen: set[str] = set()
    if holdout:
        # hand-written probes / benign bodies are evaluation-only: no generator may emit them
        seen.update(t.lower() for t in probes.all_texts())
    for r in attacks:
        t = r["text"]
        if _denied(t, denylist) or len(t) > MAX_TEXT or t.lower() in seen:
            continue
        seen.add(t.lower())
        by_label.setdefault(r["label"], []).append(r)
    held: list[dict] = []
    dropped_twins = 0
    if holdout:
        for label in list(by_label):
            held += [r for r in by_label[label] if _source_of(r) in holdout]
            by_label[label] = [r for r in by_label[label] if _source_of(r) not in holdout]
        # near-twins: a held-out value that is the percent-encoded / re-spaced / re-cased copy of a value
        # that stays in training would leak through the exact-text dedupe (the loader keeps the encoded
        # variant from one repo and the decoded one from another). Drop them from the holdout.
        kept_keys = {_twin_key(r["text"]) for recs in by_label.values() for r in recs}
        n_held = len(held)
        held = [r for r in held if _twin_key(r["text"]) not in kept_keys]
        dropped_twins = n_held - len(held)
        if not held:
            raise ValueError(f"--holdout-source {','.join(holdout)}: no payload from that source "
                             f"(sources present: {sorted({_source_of(r) for r in attacks})})")
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

    real_rng = random.Random(seed + _REAL_BENIGN_SEED_OFFSET)
    for r in (benign_real.load_loghub(root, real_rng)
              + benign_real.load_system_text(system_text_roots, real_rng, denylist)
              + benign_real.load_tldr(root, real_rng, denylist)
              + benign_real.load_mdn_examples(root, real_rng, denylist)
              + benign_real.load_awesome_compose(root, real_rng, denylist)
              + benign_real.load_sql_create_context(root, real_rng, denylist)):
        t = r["text"]
        if t.lower() not in seen and not _denied(t, denylist) and len(t) <= MAX_TEXT:
            seen.add(t.lower())
            values.append((t, "clean", r["source"]))

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
    if holdout:
        splits["test_holdout"] = _holdout_rows(held, seed, denylist, cap_per_attack)

    report = {"seed": seed, "counts": {k: len(v) for k, v in splits.items()},
              "labels": {k: dict(Counter(r["label"] for r in v)) for k, v in splits.items()},
              "shapes_train": dict(Counter(r["shape"] for r in splits["train"])),
              "sources": dict(Counter(r["source"].split(":")[0] for r in splits["train"]))}
    if holdout:
        report["holdout"] = {"source": list(holdout),
                             "attack_labels": dict(Counter(r["label"] for r in splits["test_holdout"]
                                                           if r["source"].split(":")[0] in holdout)),
                             "shapes": dict(Counter(r["shape"] for r in splits["test_holdout"])),
                             "dropped_near_twins": dropped_twins}
    for name, recs in splits.items():
        with open(os.path.join(out_dir, f"{name}.jsonl"), "w", encoding="utf-8") as f:
            for r in recs:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
    with open(os.path.join(out_dir, "DATASET_CARD.md"), "w", encoding="utf-8") as f:
        f.write(_card(report))
    return report


def _holdout_rows(held: list[dict], seed: int, denylist, cap_per_attack: int) -> list[dict]:
    """test_holdout rows: held-out-source payloads in the TRAINING shapes only (so a failure is source
    shift, not shape shift), the hand-written probes as-is, and each realistic benign body natively
    plus in the same two-extra-shapes recipe. Own RNG: the main build's stream is not consumed."""
    rng = random.Random(seed + _HOLDOUT_SEED_OFFSET)
    rows: list[dict] = []

    def add(text, label, source, shape, group_of, name=None):
        # group = hash of the carried VALUE (as in the main splits), not of the wrapped string
        if len(text) > MAX_TEXT or _denied(text, denylist):
            return
        row = {"text": text, "label": label, "source": source, "shape": shape, "group": _group(group_of)}
        if name:
            row["name"] = name
        rows.append(row)

    by_label: dict[str, list[dict]] = {}
    for r in sorted(held, key=lambda r: (r["label"], r["text"])):
        by_label.setdefault(r["label"], []).append(r)
    for label in sorted(by_label):
        recs = by_label[label]
        rng.shuffle(recs)
        for r in recs[:cap_per_attack]:
            for shape in ["bare"] + rng.sample(shapes.TRAIN_SHAPES, EXTRA_SHAPES_PER_VALUE):
                add(shapes.SHAPES[shape](r["text"], rng), r["label"], r["source"], shape, r["text"])
    for name, label, text in probes.PROBES:
        add(text, label, "handwritten:waf_probe", "probe", text, name)
    for name, text in probes.REALISTIC_BENIGN:
        add(text, "clean", "handwritten:benign_bodies", "native", text, name)
        for shape in rng.sample(shapes.TRAIN_SHAPES, EXTRA_SHAPES_PER_VALUE):
            wrapped = shapes.SHAPES[shape](text, rng)
            if wrapped != text:
                add(wrapped, "clean", "handwritten:benign_bodies", shape, text, name)
    rng.shuffle(rows)
    return rows


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
             "- Clean values are synthetic (Faker + hand-written hard negatives), local public URL pools, loghub log",
             "  excerpts and real shell/config/HTML/JSON/markdown text from the build machine's /usr/share (a",
             "  convenience corpus, not production traffic; secret-looking and denylisted files are dropped).",
             "- Attack sources also include the OWASP CRS regression tests (crs) and Nuclei DAST payload lists (nuclei).",
             "- No captured lab traffic is included."]
    if "holdout" in rep:
        h = rep["holdout"]
        lines += ["", "## Held-out source",
                  f"Source(s) held out: {', '.join(h['source'])}. No payload from them is in train/val/test/test_ood;",
                  "`test_holdout.jsonl` holds only those payloads (bare + two training shapes), plus hand-written",
                  "probes (shape `probe`) and realistic benign bodies (`handwritten:benign_bodies`).",
                  "Attack rows by label: " + json.dumps(h["attack_labels"], sort_keys=True),
                  "Rows by shape: " + json.dumps(h["shapes"], sort_keys=True),
                  f"{h['dropped_near_twins']} held-out value(s) dropped because a percent-decoded / re-cased / re-spaced",
                  "near-twin of them stays in training (exact-text dedupe cannot see those).",
                  "Only the clean rows of this file are independent of the training generators."]
    return "\n".join(lines) + "\n"


def make_zip(out_dir: str, zip_path: str | None = None) -> str:
    zip_path = zip_path or os.path.join(out_dir, "dataset_v2.zip")
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as z:
        names = ["train.jsonl", "val.jsonl", "test.jsonl", "test_ood.jsonl", "DATASET_CARD.md"]
        if os.path.exists(os.path.join(out_dir, HOLDOUT_FILE)):
            names.insert(4, HOLDOUT_FILE)
        for n in names:
            z.write(os.path.join(out_dir, n), n)
    return zip_path


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=os.path.expanduser(os.getenv("WAF_DATASETS_ROOT", "~/waf_datasets")))
    ap.add_argument("--out", default=os.path.join(DATA_DIR, "build_v2"))
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--n-clean", type=int, default=36000)
    ap.add_argument("--holdout-source", default=None,
                    help="payload source to hold out entirely (repo prefix of the record source, e.g. fuzzdb); "
                         "writes test_holdout.jsonl and keeps that source out of every other split")
    ap.add_argument("--system-text-roots", default=",".join(benign_real.DEFAULT_SYSTEM_ROOTS),
                    help="comma-separated directories to sample real benign shell/config/HTML text from "
                         "(empty disables)")
    ap.add_argument("--denylist", default=os.environ.get("WAF_V2_DENYLIST", ""),
                    help="comma-separated terms; any record containing one is dropped")
    a = ap.parse_args()
    deny = tuple(t.strip() for t in a.denylist.split(",") if t.strip())
    roots = tuple(t.strip() for t in a.system_text_roots.split(",") if t.strip())
    rep = build(a.root, a.out, seed=a.seed, n_clean=a.n_clean, denylist=deny, holdout_source=a.holdout_source,
                system_text_roots=roots)
    print(json.dumps(rep, indent=1))
    print("zip:", make_zip(a.out))


if __name__ == "__main__":
    main()
