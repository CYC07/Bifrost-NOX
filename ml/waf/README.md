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
python -m ml.waf.build_dataset    # sources -> data/build/{train,val,test}.jsonl
python -m ml.waf.train            # -> ml/waf/artifacts/waf_baseline.joblib
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
   from ml.waf.sources import load_csv
   import json
   rows = load_csv("cicids.csv", text_col="payload", label_col="Label",
                   label_map={"SQLi": "sqli", "BENIGN": "clean"})
   with open("ml/waf/data/external/cicids.jsonl", "w") as f:
       for r in rows: f.write(json.dumps(r) + "\n")
   ```
2. **VulnHub / manual payloads** — drop a labeled JSONL in `data/external/`:
   `{"text": "<payload>", "label": "sqli", "source": "vulnhub:kioptrix"}`
3. **Writeups (markdown)** — extract candidates, then confirm labels:
   ```python
   from ml.waf.sources import extract_writeup_candidates
   for c in extract_writeup_candidates("box.md"):
       print(c["hint"], "->", c["text"])   # assign a label, then add
   ```

Record schema (one JSON object per line):
`{"text": <str>, "label": <taxonomy label>, "source": <origin>}`

## Colab transformer upgrade (next)

`train_transformer.ipynb` fine-tunes DistilBERT on the same splits and exports
weights. Point the predictor at them with `WAF_MODEL_PATH=...`. The TF-IDF
baseline stays as fallback + the benchmark to beat.
