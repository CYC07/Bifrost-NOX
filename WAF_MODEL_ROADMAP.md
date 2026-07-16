# Bifrost NØX — Model Swap Roadmap

Goal: replace regex/heuristic detectors with **real trained ML models**, behind a
clean model interface so Colab-trained weights drop in later. Hardware upgrade +
Colab training are future; build for that.

**Keepers (already real ML — do NOT touch):** CLIP, YOLOv8, Tesseract (image);
Presidio (text PII).

---

## Decisions locked (this conversation)

- **Strategy:** hybrid — strong model now behind a `ModelInterface`, our own
  Colab-trained weights drop in later, zero code change.
- **Secrets → keep regex/entropy.** Near-100% precision; SOTA DLP keeps a regex
  net too. A model here is a downgrade.
- **Metadata forensics → keep rules.** "Is `C:\Users\x` a path leak" is a fact,
  not a learned judgment. No model fits.
- **Prompt-injection → dropped.** Defends a downstream LLM; Bifrost is a network
  content firewall with none. Would false-positive on security blogs.
- **CodeBERT (insecure-code) → dropped.** Detects vulns *in source code*, not
  payloads in transit; rarely fires on HTTP.
- **Web-attack detection → our own WAF classifier** (SQLi/XSS/traversal/cmdi/
  SSTI/scanner). Fills the README's claimed-but-missing "SQL injection" gap.
- **Aggregation:** each analyzer emits a *calibrated decision* (block bool +
  risk), aggregate decisions — never one global threshold over incomparable
  model scores. Zero-shot uses `multi_label=True`. Per-analyzer fail-open.

---

## Status

### ✅ Done — separate branch `worktree-firewall-fixes` (PR #5, draft)
Correctness/security fixes (not models): real DNS domain filtering, streaming
HTTP parser (chunked/gzip so AI inspection fires), control-plane auth on :8000,
debug flags off. 54 tests pass.

### 🚧 In progress — branch `worktree-waf-model` (this work): our own WAF
- [x] `ml/waf/taxonomy.py` — 7 classes (clean/sqli/xss/path_traversal/command_injection/ssti/scanner) + risk map
- [x] `ml/waf/data/seed_attacks.jsonl` + `seed_benign.jsonl` — curated real-payload seed (114 samples)
- [x] `ml/waf/sources.py` — loaders: JSONL, CSV (with label_map), markdown-writeup extractor, dedupe
- [x] `ml/waf/build_dataset.py` — merge + dedupe + stratified split → train/val/test + stats
- [x] `ml/waf/train.py` — char-n-gram TF-IDF + LogisticRegression baseline (CPU, trains in seconds)
- [x] `ml/waf/predictor.py` — inference wrapper, calibrated decision, fail-open, `WAF_MODEL_PATH` config
- [x] `tests/test_waf.py` — taxonomy, sources, split, predictor decisions + fail-open
- [x] Verified: all 5 attack types blocked, benign allowed, on a real trained model
- [ ] **Run the tests** (was interrupted — `pytest tests/test_waf.py -q`)
- [ ] Commit + push + draft PR for the WAF branch

---

## TODO — finish the WAF (next)

1. **Grow the dataset (biggest quality lever).** Baseline metrics are weak only
   because it's 114 seed samples. Add data via `ml/waf/data/external/`:
   - **You download** public sets (CIC-IDS-2017/2018, CSIC-2010, HIKARI-2021,
     PayloadsAllTheThings, SecLists/fuzzdb) → convert to our schema with
     `sources.load_csv(..., label_map=...)`, save as `data/external/*.jsonl`.
   - **You add VulnHub payloads** — paste them here or drop a labeled JSONL in
     `data/external/`.
   - **Writeups** (from uni portal) → `sources.extract_writeup_candidates()`
     pulls candidates with a heading hint; you confirm labels, then add.
   - Re-run `python -m ml.waf.build_dataset` then `python -m ml.waf.train`.
2. **`ml/waf/train_transformer.ipynb`** — Colab notebook: fine-tune DistilBERT on
   the same splits, export weights, drop into predictor via `WAF_MODEL_PATH`.
   The TF-IDF baseline becomes fallback + the benchmark to beat.
3. **`ml/waf/eval.py`** — standalone eval: per-class P/R/F1 + confusion matrix on
   the test split; compare baseline vs transformer.
4. **Per-class thresholds** — tune (like argus_sentinel's `thresholds.json`)
   instead of one global 0.5; wire into predictor.
5. **A writeup-ingest CLI** — `python -m ml.waf.ingest_writeup <file.md>` → review
   file → labeled JSONL.

---

## TODO — wire models into the services

6. **`common/model_interface.py`** — `TextAnalyzer` ABC (`load()`,
   `analyze(text) -> AnalysisResult`), config-driven `model_id` +
   `local_weights_path`. This is the drop-in glue.
7. **Refactor `text_service/main.py`** to analyzer modules, each fail-open,
   aggregate over decisions:
   - `web_attack` → our WAF predictor (replaces the `eval(`/`exec(` heuristic)
   - `sensitive` → `MoritzLaurer/deberta-v3-base-zeroshot-v2.0`, `multi_label=True`
     (replaces MiniLM cosine-vs-7-phrases)
   - `secrets` → **keep** the regex/entropy (extracted as-is)
   - `pii` → **keep** Presidio
   - **remove** the MiniLM semantic model + the dead `model_context` stub
   - Regression test: benign financial-news snippet must NOT block.
8. **Add `sentencepiece`** to requirements (deberta-v3 tokenizer needs it).
9. **RAM note:** transformers add ~50–300 ms/request on CPU and a few GB
   resident. Lazy-load + enable flags; consider small tier inline vs heavy tier
   on the dashboard AI-intake path until the hardware upgrade.

---

## TODO — later services (not yet started)

10. **Document service:** replace regex keyword `content_model` → reuse the
    sensitive-text classifier on extracted text now; LayoutLMv3 (flag
    `DOC_ENABLE_LAYOUTLM` exists) on Colab later. **Keep** YARA+VirusTotal +
    structural hard-rules; retrain the Isolation Forest on **real** data (it's
    currently fit on `seed=42` synthetic vectors).
11. **Image service:** keepers stay (CLIP/YOLO/Tesseract). Optional later:
    dedicated NSFW model, YOLOv8n → s/m, custom weapon/ID model on Colab.

---

## Audit follow-ups (from the firewall review, not model work)
- IPv6 coverage (C++ engine is AF_INET only; iptables not ip6tables)
- Log/event persistence (all in-memory deques today)
- De-fabricate dashboard geo/threat data (`_country_guess`, `_classify_reason`)
- Live-rig verification of DNS NF_DROP + end-to-end MITM inspection (needs root + hotspot)

---

## How to run (WAF)
```bash
# from repo root, venv active
python -m ml.waf.build_dataset      # merge sources -> train/val/test splits
python -m ml.waf.train              # train baseline -> ml/waf/artifacts/waf_baseline.joblib
pytest tests/test_waf.py -q         # tests
# add your data: drop labeled *.jsonl into ml/waf/data/external/ then rebuild+retrain
```
