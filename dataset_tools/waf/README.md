# WAF Classifier — our own web-attack model

A trained ML classifier that reads an HTTP request/payload and labels it
`clean` or an attack family (SQLi, XSS, path traversal, command injection, SSTI,
scanner). Replaces the old `eval(`/`exec(` regex heuristic and fills the gap
where the README claimed "SQL injection in text" but no detection existed.

Not hand-written rules — a model that learns the boundary from data and improves
as the dataset grows.

## Layout

```
ml/waf/
├── taxonomy.py          # label space + risk map (7 classes)
├── data/
│   ├── seed_attacks.jsonl   # curated real attack payloads
│   ├── seed_benign.jsonl    # real benign traffic (clean class)
│   ├── external/            # YOU drop labeled *.jsonl here (gitignored)
│   └── build/               # generated train/val/test (gitignored)
├── sources.py           # loaders: JSONL, CSV, markdown-writeup extractor
├── build_dataset.py     # merge + dedupe + stratified split
├── train.py             # char-ngram TF-IDF + LogisticRegression baseline (CPU)
├── predictor.py         # inference wrapper (calibrated decision, fail-open)
└── artifacts/           # trained model (gitignored)
```

## Train

```bash
# from repo root, venv active
python -m dataset_tools.waf.build_dataset    # sources -> data/build/{train,val,test}.jsonl
python -m dataset_tools.waf.train            # -> ml/waf/artifacts/waf_baseline.joblib
```

## Predict

```python
from ml.waf.predictor import get_classifier
p = get_classifier().predict("id=1' OR '1'='1--")
print(p.label, p.score, p.blocked)   # sqli 0.86 True
```

## Grow the dataset (the main quality lever)

The seed is a bootstrap (~114 samples). Add data, rebuild, retrain:

1. **Public datasets** you download (CIC-IDS, CSIC-2010, PayloadsAllTheThings,
   SecLists) — convert to our schema:
   ```python
   from dataset_tools.waf.sources import load_csv
   import json
   rows = load_csv("cicids.csv", text_col="payload", label_col="Label",
                   label_map={"SQLi": "sqli", "BENIGN": "clean"})
   with open("dataset_tools/waf/data/external/cicids.jsonl", "w") as f:
       for r in rows: f.write(json.dumps(r) + "\n")
   ```
2. **VulnHub / manual payloads** — drop a labeled JSONL in `data/external/`:
   `{"text": "<payload>", "label": "sqli", "source": "vulnhub:kioptrix"}`
3. **Writeups (markdown)** — extract candidates, then confirm labels:
   ```python
   from dataset_tools.waf.sources import extract_writeup_candidates
   for c in extract_writeup_candidates("box.md"):
       print(c["hint"], "->", c["text"])   # assign a label, then add
   ```

Record schema (one JSON object per line):
`{"text": <str>, "label": <taxonomy label>, "source": <origin>}`

## Colab transformer upgrade (next)

`train_transformer.ipynb` fine-tunes DistilBERT on the same splits and exports
weights. Point the predictor at them with `WAF_MODEL_PATH=...`. The TF-IDF
baseline stays as fallback + the benchmark to beat.

## Running the v2 bake-off

v2 retrains the WAF on shape-balanced data (clean and attack values share the same carrier templates) and
judges two arms with ship gates that do not depend on the training generators:

* **Arm A** `waf_distilbert_v2.zip` - the same 7-class softmax head as v1 (drop-in).
* **Arm B** `waf_sigmoid_v2.zip` - one sigmoid head per attack family, default-allow. `ml/waf/predictor.py` loads it
  when the directory contains `waf_v2.json` with `"arm": "B_sigmoid6"` (blocks when the largest head is strictly above
  `recommended_threshold`; `clean` is reported as `1 - max head`).

Run all commands from the repo root with the venv active (`PYTHONPATH=.`).

**1. Build the dataset (once).** Needs the public payload clones in `~/FYP/waf_datasets/{patt,seclists,fuzzdb}` and the
local pools in `dataset_tools/waf/data/`. Hold out one whole payload source so recall can be measured on payloads the
training corpus never contained, and pass your deny-list so no engagement/customer string enters the data:

```bash
WAF_V2_DENYLIST="term1,term2" python -m dataset_tools.waf.v2.build \
    --root ~/FYP/waf_datasets --out ~/FYP/waf_datasets/build_v2 --holdout-source fuzzdb
```

This writes `train/val/test/test_ood/test_holdout.jsonl`, `DATASET_CARD.md` and `dataset_v2.zip`. `test_holdout.jsonl`
holds only the held-out source's payloads (wrapped in the training shapes), the 25 hand-written probes and ~45
realistic benign bodies from `dataset_tools/waf/v2/probes.py`; none of them is in any other split. Without
`--holdout-source` the output is byte-identical to the pre-holdout builder, and the notebook then refuses the zip.

**2. Train in Colab.** Open `dataset_tools/waf/train_v2.ipynb` (regenerate with `python -m dataset_tools.waf.v2.make_notebook`),
Runtime -> T4 GPU, run all cells. **Upload** `dataset_v2.zip` when asked. **Download** the three files it offers:
`waf_distilbert_v2.zip`, `waf_sigmoid_v2.zip`, `waf_v2_results.json` (and note the sha256 values it prints).

**3. Unzip each arm into its own directory** - never over the shipping `ml/waf/artifacts/waf_distilbert` (artifacts are
git-ignored; that directory is your rollback):

```bash
mkdir -p ml/waf/artifacts/waf_distilbert_v2 ml/waf/artifacts/waf_sigmoid_v2
unzip waf_distilbert_v2.zip -d ml/waf/artifacts/waf_distilbert_v2
unzip waf_sigmoid_v2.zip    -d ml/waf/artifacts/waf_sigmoid_v2
```

**4. Run the gate once per arm.** It recomputes every verdict from the raw numbers (the notebook's own PASS flags are
ignored), checks the artifact belongs to the results (same arm, same threshold), replays the probes through the real
`text_service` (needs the whole model stack in RAM; run nothing else model-heavy at the same time) and exits non-zero on
any FAIL:

```bash
python -m dataset_tools.waf.v2.gate --results waf_v2_results.json --artifact ml/waf/artifacts/waf_distilbert_v2
python -m dataset_tools.waf.v2.gate --results waf_v2_results.json --artifact ml/waf/artifacts/waf_sigmoid_v2
```

| gate | limit |
|---|---|
| test clean FP / worst carrier shape | <= 1% / <= 3% |
| test recall | >= 90% |
| OOD (held-out carrier shapes) clean FP / recall | <= 2% / >= 80% |
| independent probes: benign flagged / attacks caught | <= 20% of the benign probes / all but one |
| held-out payload source recall | >= 80% |
| held-out benign bodies FP | <= 2% |
| production replay: benign block rate / attack block rate | <= 10% / >= 90% |

The limits live in one place (`GATES` in `dataset_tools/waf/v2/gate.py`); the notebook's cell 9 is generated from it.
`--skip-replay` exists for unit tests only and the run then ends "PASS (INCOMPLETE ...)". To measure any artifact on the
production path without a verdict: `--replay-only --artifact DIR --arm A [--threshold 0.8]`.

**5. Deploy the winner** (only if its gate run printed `RESULT: PASS`). Environment variables, read by `text_service`:

| arm | `WAF_MODEL_PATH` | threshold |
|---|---|---|
| A (softmax) | the unzipped directory | `WAF_ATTACK_THRESHOLD=<recommended_threshold from waf_v2.json>` (text_service default is 0.8; `WAF_THRESHOLD` is not used there) |
| B (sigmoid) | the unzipped directory | taken from `waf_v2.json`; `WAF_THRESHOLD` overrides it; `WAF_ATTACK_THRESHOLD` has **no effect** |

Then re-run `tests/test_waf_scope.py tests/test_request_target.py tests/test_text_target.py`. Rollback = point
`WAF_MODEL_PATH` back at the v1 directory. A directory whose `waf_v2.json` is unreadable or inconsistent with the weights
fails open (the WAF is disabled with a logged error), it is never guessed to be a softmax model.

**What these gates cannot tell you.** The held-out source removes exact-duplicate leakage, not near-duplicates across
repos; `ssti` and `scanner` have no (or only synthetic) held-out payloads, so their recall is unmeasured here; the
independent probes and benign bodies are small hand-written sets (a 2% budget on ~135 clean rows is 2 rows); and every
number is for the model's decision rule in isolation or in the replay - live traffic, other sensors in the gateway and
latency are not covered.
