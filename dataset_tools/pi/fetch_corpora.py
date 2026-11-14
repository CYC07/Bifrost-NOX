"""Fetch the PUBLIC corpora used to evaluate the prompt-injection gate.

Only this script is committed; data lands in ~/FYP/corpora/pi_<name>/ (one directory per
source, never inside the repo) with SOURCE.txt (URL, sha256, licence, dataset creation
date, retrieval date) and a normalised items.jsonl. Downloaded files are only ever read
as bytes / parsed as data (parquet, csv, json) - never executed.

Parquet needs pyarrow, which is not in the firewall venv. Install it somewhere harmless and
point PI_PYLIB at it:
    python -m pip install --target ~/FYP/corpora/_pylib_pi pyarrow
    PI_PYLIB=~/FYP/corpora/_pylib_pi python -I dataset_tools/pi/fetch_corpora.py [name ...]

Normalised row schema (items.jsonl):
    {"id": str, "text": str, "label": "attack"|"benign", "meta": {...}}
WildChat/oasst1/ultrachat additionally carry "turns": [{"role","content"}, ...] (multi-turn).
"""
from __future__ import annotations

import csv
import datetime as dt
import gzip
import hashlib
import json
import os
import random
import sys

CORPORA = os.path.expanduser(os.getenv("PI_CORPORA", "~/FYP/corpora"))
_lib = os.getenv("PI_PYLIB")
if _lib:
    sys.path.insert(0, os.path.expanduser(_lib))


def _parquet_rows(path: str):
    import pyarrow.parquet as pq  # noqa: PLC0415
    return pq.read_table(path).to_pylist()


def _csv_rows(path: str):
    csv.field_size_limit(10_000_000)
    with open(path, "r", encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def _json_rows(path: str):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _jsonl_rows(path: str):
    op = gzip.open if path.endswith(".gz") else open
    with op(path, "rt", encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def _read(path: str):
    if path.endswith(".parquet"):
        return _parquet_rows(path)
    if path.endswith(".csv"):
        return _csv_rows(path)
    if path.endswith((".jsonl", ".jsonl.gz")):
        return _jsonl_rows(path)
    return _json_rows(path)


def _s(x) -> str:
    return x if isinstance(x, str) else ("" if x is None else str(x))


# ---- per-source normalisers: {file: rows} -> iterable of items ---------------------------
def n_deepset(files):
    for fn, rows in files.items():
        split = "test" if "test" in fn else "train"
        for i, r in enumerate(rows):
            yield {"id": f"{split}-{i}", "text": _s(r["text"]),
                   "label": "attack" if str(r["label"]) == "1" else "benign", "meta": {"split": split}}


def n_jackhhao(files):
    for fn, rows in files.items():
        for i, r in enumerate(rows):
            yield {"id": f"full-{i}", "text": _s(r["prompt"]),
                   "label": "attack" if r["type"] == "jailbreak" else "benign", "meta": {}}


def n_xtram1(files):
    for fn, rows in files.items():
        split = "test" if "test" in fn else "train"
        for i, r in enumerate(rows):
            yield {"id": f"{split}-{i}", "text": _s(r["text"]),
                   "label": "attack" if str(r["label"]) == "1" else "benign", "meta": {"split": split}}


def n_promptshield(files):
    for fn, rows in files.items():
        split = fn.split(".")[0]
        for i, r in enumerate(rows):
            yield {"id": f"{split}-{i}", "text": _s(r["prompt"]),
                   "label": "attack" if int(r["label"]) == 1 else "benign", "meta": {"split": split}}


def n_gandalf(files):
    for fn, rows in files.items():
        split = os.path.basename(fn).split("-")[0]
        for i, r in enumerate(rows):
            yield {"id": f"{split}-{i}", "text": _s(r["text"]), "label": "attack", "meta": {"split": split}}


def n_trustairlab(files):
    for fn, rows in files.items():
        jb = fn.startswith("jailbreak")
        for i, r in enumerate(rows):
            yield {"id": f"{fn.split('/')[0]}-{i}", "text": _s(r["prompt"]), "label": "attack" if jb else "benign",
                   "meta": {"platform": _s(r.get("platform")), "source": _s(r.get("source"))}}


def n_spml(files):
    for fn, rows in files.items():
        for i, r in enumerate(rows):
            yield {"id": f"spml-{i}", "text": _s(r["User Prompt"]),
                   "label": "attack" if str(r["Prompt injection"]) == "1" else "benign",
                   "meta": {"system": _s(r["System Prompt"]), "degree": _s(r.get("Degree"))}}


def n_alpaca(files):
    for fn, rows in files.items():
        for i, r in enumerate(rows):
            ins, inp = _s(r["instruction"]), _s(r.get("input"))
            yield {"id": f"alpaca-{i}", "text": ins + ("\n\n" + inp if inp.strip() else ""), "label": "benign", "meta": {}}


def n_dolly(files):
    for fn, rows in files.items():
        for i, r in enumerate(rows):
            ins, ctx = _s(r["instruction"]), _s(r.get("context"))
            yield {"id": f"dolly-{i}", "text": ins + ("\n\n" + ctx if ctx.strip() else ""), "label": "benign",
                   "meta": {"has_context": bool(ctx.strip()), "category": _s(r.get("category"))}}


def n_codealpaca(files):
    for fn, rows in files.items():
        for i, r in enumerate(rows):
            ins, inp = _s(r["instruction"]), _s(r.get("input"))
            yield {"id": f"codealpaca-{i}", "text": ins + ("\n\n" + inp if inp.strip() else ""), "label": "benign", "meta": {}}


def n_oasst1(files):
    for fn, rows in files.items():
        by_id = {r["message_id"]: r for r in rows}
        for r in rows:
            if r.get("role") != "prompter" or r.get("lang") != "en":
                continue
            chain, cur = [], r
            while cur is not None:                       # walk to the root: the real multi-turn history
                chain.append({"role": "user" if cur["role"] == "prompter" else "assistant", "content": _s(cur["text"])})
                cur = by_id.get(cur.get("parent_id"))
            yield {"id": r["message_id"], "text": _s(r["text"]), "label": "benign",
                   "turns": list(reversed(chain)), "meta": {"depth": len(chain)}}


def n_ultrachat(files):
    for fn, rows in files.items():
        for i, r in enumerate(rows):
            msgs = r["messages"]
            yield {"id": _s(r.get("prompt_id")) or f"uc-{i}", "text": _s(msgs[0]["content"]), "label": "benign",
                   "turns": [{"role": m["role"], "content": _s(m["content"])} for m in msgs], "meta": {}}


def n_wildchat(files):
    rng = random.Random(1234)
    keep = []
    for fn, rows in files.items():
        for r in rows:
            if r.get("language") != "English" or r.get("toxic") or r.get("redacted"):
                continue
            conv = r["conversation"]
            if conv and conv[0]["role"] == "user":
                keep.append(r)
    rng.shuffle(keep)
    for r in keep[:8000]:
        turns = [{"role": m["role"], "content": _s(m["content"])} for m in r["conversation"]]
        yield {"id": _s(r["conversation_hash"]), "text": turns[0]["content"], "label": "benign",
               "turns": turns, "meta": {"model": _s(r.get("model")), "n_turns": len(turns)}}


# name -> (repo, files, normaliser)
SOURCES = {
    "deepset": ("deepset/prompt-injections",
                ["data/test-00000-of-00001-701d16158af87368.parquet", "data/train-00000-of-00001-9564e8b05b4757ab.parquet"], n_deepset),
    "jackhhao": ("jackhhao/jailbreak-classification", ["default/jailbreak_dataset_full.csv"], n_jackhhao),
    "xtram1": ("xTRam1/safe-guard-prompt-injection",
               ["data/test-00000-of-00001.parquet", "data/train-00000-of-00001.parquet"], n_xtram1),
    "promptshield": ("hendzh/PromptShield", ["test.json", "validation.json"], n_promptshield),
    "gandalf": ("Lakera/gandalf_ignore_instructions",
                ["data/test-00000-of-00001-bc92128b9288a6d1.parquet", "data/train-00000-of-00001-ded53be747ff55cd.parquet",
                 "data/validation-00000-of-00001-94481a2a09ff2fff.parquet"], n_gandalf),
    "trustairlab": ("TrustAIRLab/in-the-wild-jailbreak-prompts",
                    ["jailbreak_2023_12_25/train-00000-of-00001.parquet", "regular_2023_12_25/train-00000-of-00001.parquet"], n_trustairlab),
    "spml": ("reshabhs/SPML_Chatbot_Prompt_Injection", ["spml_prompt_injection.csv"], n_spml),
    "alpaca": ("tatsu-lab/alpaca", ["data/train-00000-of-00001-a09b74b3ef9c3b56.parquet"], n_alpaca),
    "dolly": ("databricks/databricks-dolly-15k", ["databricks-dolly-15k.jsonl"], n_dolly),
    "codealpaca": ("sahil2801/CodeAlpaca-20k", ["code_alpaca_20k.json"], n_codealpaca),
    "oasst1": ("OpenAssistant/oasst1", ["2023-04-12_oasst_ready.messages.jsonl.gz"], n_oasst1),
    "ultrachat": ("HuggingFaceH4/ultrachat_200k", ["data/test_sft-00000-of-00001-f7dfac4afe5b93f4.parquet"], n_ultrachat),
    "wildchat": ("allenai/WildChat-1M", ["data/train-00000-of-00014.parquet"], n_wildchat),
}


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def fetch(name: str) -> None:
    from huggingface_hub import HfApi, hf_hub_download  # noqa: PLC0415
    repo, files, norm = SOURCES[name]
    out = os.path.join(CORPORA, f"pi_{name}")
    raw = os.path.join(out, "raw")
    os.makedirs(raw, exist_ok=True)
    info = HfApi().dataset_info(repo)
    lic = info.card_data.license if info.card_data else None
    lines, rows_by_file = [], {}
    for fn in files:
        p = hf_hub_download(repo_id=repo, filename=fn, repo_type="dataset", local_dir=raw)
        lines.append(f"file: {fn}\n  url: https://huggingface.co/datasets/{repo}/resolve/main/{fn}\n  sha256: {_sha256(p)}")
        rows_by_file[fn] = _read(p)
    items = list(norm(rows_by_file))
    with open(os.path.join(out, "items.jsonl"), "w", encoding="utf-8") as f:
        for it in items:
            f.write(json.dumps(it, ensure_ascii=False) + "\n")
    with open(os.path.join(out, "SOURCE.txt"), "w") as f:
        f.write(f"source: https://huggingface.co/datasets/{repo}\nlicence: {lic}\n"
                f"dataset_created_at: {info.created_at}\nretrieved: {dt.date.today()}\nrows_normalised: {len(items)}\n"
                + "\n".join(lines) + "\n")
    print(f"{name}: {len(items)} items -> {out}")


if __name__ == "__main__":
    for n in (sys.argv[1:] or list(SOURCES)):
        try:
            fetch(n)
        except Exception as exc:  # noqa: BLE001 - report and continue with the other sources
            print(f"{n}: FAILED {type(exc).__name__}: {str(exc)[:200]}", file=sys.stderr)
