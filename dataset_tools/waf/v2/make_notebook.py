"""Generate dataset_tools/waf/train_v2.ipynb (Colab bake-off on dataset_v2.zip).

    python -m dataset_tools.waf.v2.make_notebook

Arm A: same 7-class DistilBERT as v1 (drop-in for ml/waf/predictor.py) on the v2 data.
Arm B: per-attack sigmoid heads, default-allow. Both are scored with the SAME decision rule and a
threshold picked from the validation clean FP budget, then judged against explicit ship gates.
"""
from __future__ import annotations

import inspect
import json
import os

from dataset_tools.waf.v2 import gate

HERE = os.path.dirname(__file__)
OUT = os.path.abspath(os.path.join(HERE, "..", "train_v2.ipynb"))

GATE_CELL_HEAD = """# 9. ship gates. GENERATED from dataset_tools/waf/v2/gate.py (GATES + gate_checks): do not edit here, edit the
# repo and regenerate, so Colab and `python -m dataset_tools.waf.v2.gate` can never disagree. Decide the budgets
# BEFORE looking at the numbers. The production-path replay (text_service, all models) runs offline in gate.py.
import math
GATES = %s

"""

GATE_CELL_TAIL = """

PASS, CHECKS = {}, {}
for k in ARMS:
    CHECKS[k] = gate_checks(dict(test=R[k]["test"], ood=R[k]["ood"], holdout=R[k]["holdout"], ind=IND[k]), GATES)
    PASS[k] = all(ok for _, ok, _ in CHECKS[k])
    print(f"== {k}: {'NOTEBOOK GATES PASS (run gate.py for the production replay)' if PASS[k] else 'FAILS GATES'}")
    for name, ok, detail in CHECKS[k]:
        print("   ", "PASS" if ok else "FAIL", name, f"[{detail}]")"""


def gate_cell() -> str:
    gates = {k: gate.GATES[k] for k in gate.NOTEBOOK_GATE_KEYS}
    return GATE_CELL_HEAD % json.dumps(gates, indent=1) + inspect.getsource(gate.gate_checks).rstrip("\n") + GATE_CELL_TAIL


MD_INTRO = """# Bifrost NØX — WAF v2 bake-off (Colab, GPU runtime)

Trains two DistilBERT arms on `dataset_v2.zip` (shape-balanced: clean and attack values share the same
carrier templates, splits are by payload group, two shapes are held out for OOD tests, and one whole payload
SOURCE is held out in `test_holdout.jsonl`) and judges them against **ship gates** (FP budget on clean traffic,
recall, OOD recall, recall on the held-out payload source, an independent hand-written battery).

* **Arm A** – 7-class softmax, identical to v1's head, so it is a drop-in for `ml/waf/predictor.py`.
* **Arm B** – one sigmoid head per attack family, default-allow (`ml/waf/predictor.py` loads it from `waf_v2.json`).

Runtime → *Change runtime type → T4 GPU*, then run all cells. Upload `dataset_v2.zip` when asked - it MUST be a zip
built with `--holdout-source` (it contains `test_holdout.jsonl`); the notebook stops otherwise.
Nothing here uses lab traffic. `scanner` is tiny/synthetic and is excluded from the gates."""

CELLS = [
("md", MD_INTRO),
("code", r'''# 1. deps
!pip -q install "transformers>=4.44" datasets accelerate scikit-learn'''),
("code", r'''# 2. data
import json, zipfile, os
from google.colab import files
up = files.upload()                      # dataset_v2.zip
zipfile.ZipFile(next(iter(up))).extractall("/content/v2")
def load(n): return [json.loads(l) for l in open(f"/content/v2/{n}.jsonl")]
train, val, test, ood = (load(n) for n in ("train", "val", "test", "test_ood"))
assert os.path.exists("/content/v2/test_holdout.jsonl"), (
    "this dataset_v2.zip has no test_holdout.jsonl - rebuild with `python -m dataset_tools.waf.v2.build --holdout-source fuzzdb` "
    "and upload THAT zip (a default-build zip would silently skip the source-independent gates)")
holdout = load("test_holdout")
hold = [r for r in holdout if r["shape"] != "probe"]           # held-out-source attacks + realistic benign bodies
probe_rows = [r for r in holdout if r["shape"] == "probe"]     # the 25 hand-written probes (independent battery)
assert any(r["label"] != "clean" for r in hold), "test_holdout.jsonl has no held-out-source attack rows"
assert len(probe_rows) >= 20, "test_holdout.jsonl is missing the hand-written probes"
LABELS = ["clean", "sqli", "xss", "path_traversal", "command_injection", "ssti", "scanner"]   # == ml/waf/taxonomy.py
ATTACKS = LABELS[1:]
print({k: len(v) for k, v in dict(train=train, val=val, test=test, ood=ood, hold=hold, probes=probe_rows).items()})
print(open("/content/v2/DATASET_CARD.md").read()[:1500])'''),
("code", r'''# 3. shared setup
import numpy as np, torch
from collections import Counter
from datasets import Dataset
from transformers import (AutoTokenizer, AutoModelForSequenceClassification, TrainingArguments, Trainer,
                          DataCollatorWithPadding)
MODEL, MAX_LEN, EPOCHS = "distilbert-base-uncased", 256, 3      # MAX_LEN must match predictor.TRANSFORMER_MAX_LENGTH
tok = AutoTokenizer.from_pretrained(MODEL)
label2id = {l: i for i, l in enumerate(LABELS)}
def tokenize(batch): return tok(batch["text"], truncation=True, max_length=MAX_LEN)
def ds_single(rows):
    return Dataset.from_dict({"text": [r["text"] for r in rows], "label": [label2id[r["label"]] for r in rows]}).map(tokenize, batched=True)
def ds_multi(rows):
    y = [[1.0 if r["label"] == a else 0.0 for a in ATTACKS] for r in rows]       # clean = all zeros
    return Dataset.from_dict({"text": [r["text"] for r in rows], "labels": y}).map(tokenize, batched=True)
cnt = Counter(r["label"] for r in train)
print("class counts:", dict(cnt))'''),
("code", r'''# 4. ARM A - 7-class softmax (sqrt-damped class weights)
w = torch.tensor([(len(train) / (len(LABELS) * cnt[l])) ** 0.5 for l in LABELS], dtype=torch.float)
class WeightedTrainer(Trainer):
    def compute_loss(self, model, inputs, return_outputs=False, **kw):
        labels = inputs.pop("labels"); out = model(**inputs)
        loss = torch.nn.functional.cross_entropy(out.logits, labels, weight=w.to(out.logits.device))
        return (loss, out) if return_outputs else loss
def args(out):
    return TrainingArguments(output_dir=out, per_device_train_batch_size=32, per_device_eval_batch_size=128,
                             learning_rate=3e-5, num_train_epochs=EPOCHS, weight_decay=0.01,
                             eval_strategy="epoch", save_strategy="no", fp16=torch.cuda.is_available(),
                             logging_steps=200, report_to="none")
model_a = AutoModelForSequenceClassification.from_pretrained(
    MODEL, num_labels=len(LABELS), id2label=dict(enumerate(LABELS)), label2id=label2id)
ta = WeightedTrainer(model=model_a, args=args("/content/armA"), train_dataset=ds_single(train),
                     eval_dataset=ds_single(val), processing_class=tok, data_collator=DataCollatorWithPadding(tok))
ta.train()'''),
("code", r'''# 5. ARM B - per-attack sigmoid heads, default-allow
model_b = AutoModelForSequenceClassification.from_pretrained(
    MODEL, num_labels=len(ATTACKS), problem_type="multi_label_classification",
    id2label=dict(enumerate(ATTACKS)), label2id={a: i for i, a in enumerate(ATTACKS)})
tb = Trainer(model=model_b, args=args("/content/armB"), train_dataset=ds_multi(train), eval_dataset=ds_multi(val),
             processing_class=tok, data_collator=DataCollatorWithPadding(tok))
tb.train()'''),
("code", r'''# 6. one decision rule per arm -> (flag_score, predicted_label)
def _batches(texts, bs=256):
    for i in range(0, len(texts), bs):
        yield texts[i:i + bs]
@torch.no_grad()
def run_logits(model, texts):
    model.eval(); dev = next(model.parameters()).device; outs = []
    for chunk in _batches(texts):
        enc = tok(chunk, truncation=True, max_length=MAX_LEN, padding=True, return_tensors="pt").to(dev)
        outs.append(model(**enc).logits.float().cpu())
    return torch.cat(outs)
def score_a(texts):
    """predictor.py rule: flagged iff argmax class is an attack, score = its softmax prob."""
    p = torch.softmax(run_logits(model_a, texts), -1).numpy()
    top = p.argmax(1)
    flag = np.where(top != 0, p.max(1), 0.0)
    return flag, [LABELS[i] if i != 0 else "clean" for i in top]
def score_b(texts):
    p = torch.sigmoid(run_logits(model_b, texts)).numpy()
    return p.max(1), [ATTACKS[i] for i in p.argmax(1)]
ARMS = {"A_softmax7": score_a, "B_sigmoid6": score_b}

FP_BUDGET = 0.005          # fraction of VALIDATION clean rows allowed to be flagged
def pick_threshold(fn):
    clean = [r["text"] for r in val if r["label"] == "clean"]
    flag, _ = fn(clean)
    return float(np.quantile(flag, 1 - FP_BUDGET))
THR = {k: pick_threshold(f) for k, f in ARMS.items()}
print("thresholds from val clean FP budget:", THR)'''),
("code", r'''# 7. evaluate both arms on test / OOD / the held-out payload source
import collections
def evaluate(name, rows, fn, thr):
    flag, pred = fn([r["text"] for r in rows]); flagged = flag > thr
    clean = [i for i, r in enumerate(rows) if r["label"] == "clean"]
    att = [i for i, r in enumerate(rows) if r["label"] not in ("clean", "scanner")]
    nan = float("nan")
    fp = float(np.mean([flagged[i] for i in clean])) if clean else nan
    rec = float(np.mean([flagged[i] for i in att])) if att else nan
    exact = float(np.mean([flagged[i] and pred[i] == rows[i]["label"] for i in att])) if att else nan
    by_shape = collections.defaultdict(list)
    for i in clean: by_shape[rows[i]["shape"]].append(flagged[i])
    shape_fp = {s: float(np.mean(v)) for s, v in by_shape.items()}
    per_class = {}
    for lab in ATTACKS:
        idx = [i for i, r in enumerate(rows) if r["label"] == lab]
        if idx: per_class[lab] = round(float(np.mean([flagged[i] for i in idx])), 3)
    return dict(fp=fp, recall=rec, exact=exact, n_clean=len(clean), n_attack=len(att), shape_fp=shape_fp,
                per_class_recall=per_class)
R = {}
for k, fn in ARMS.items():
    R[k] = {"test": evaluate(k, test, fn, THR[k]), "ood": evaluate(k, ood, fn, THR[k]),
            "holdout": evaluate(k, hold, fn, THR[k])}
    for split in ("test", "ood", "holdout"):
        r = R[k][split]
        print(f"{k:11s} {split:7s} clean-FP {r['fp']:.2%} (n={r['n_clean']})  recall {r['recall']:.2%} (n={r['n_attack']}, exact class {r['exact']:.2%})")
        print("            FP by shape:", {s: f"{v:.1%}" for s, v in sorted(r['shape_fp'].items())})
        print("            recall by class:", r["per_class_recall"])'''),
("code", r'''# 8. independent hand-written battery: the 25 probes in test_holdout.jsonl (shape "probe"; never in any generator)
BENIGN = {r["name"]: r["text"] for r in probe_rows if r["label"] == "clean"}
ATTACK = {r["name"]: r["text"] for r in probe_rows if r["label"] not in ("clean", "scanner")}     # scanner: excluded from gates
assert len(BENIGN) >= 10 and len(ATTACK) >= 5, "probe rows missing from test_holdout.jsonl"
IND = {}
for k, fn in ARMS.items():
    fb, _ = fn(list(BENIGN.values())); fa, _ = fn(list(ATTACK.values()))
    IND[k] = dict(benign_fp=int((fb > THR[k]).sum()), attacks_caught=int((fa > THR[k]).sum()),
                  n_benign=len(BENIGN), n_attack=len(ATTACK))
    wrong = [n for n, f in zip(BENIGN, fb) if f > THR[k]]
    missed = [n for n, f in zip(ATTACK, fa) if f <= THR[k]]
    print(k, IND[k], "| benign flagged:", wrong, "| attacks missed:", missed)'''),
("code", gate_cell()),
("code", r'''# 10. export (Arm A is the drop-in). Also exports B for the record.
import shutil, hashlib
def export(model, name, extra):
    d = f"/content/{name}"; model.save_pretrained(d); tok.save_pretrained(d)
    json.dump(dict(labels=LABELS, attack_labels=ATTACKS, max_len=MAX_LEN, **extra), open(f"{d}/waf_v2.json", "w"), indent=1)
    shutil.make_archive(d, "zip", d)
    h = hashlib.sha256(open(f"{d}.zip", "rb").read()).hexdigest()
    print(name, "sha256", h); return f"{d}.zip"
za = export(model_a, "waf_distilbert_v2", dict(arm="A_softmax7", recommended_threshold=THR["A_softmax7"], gates=PASS["A_softmax7"]))
zb = export(model_b, "waf_sigmoid_v2", dict(arm="B_sigmoid6", recommended_threshold=THR["B_sigmoid6"], gates=PASS["B_sigmoid6"]))
json.dump(dict(R=R, IND=IND, THR=THR, PASS=PASS, CHECKS=CHECKS), open("/content/waf_v2_results.json", "w"), indent=1, default=float)
from google.colab import files
for f in (za, zb, "/content/waf_v2_results.json"): files.download(f)'''),
("md", """## After download (full steps: dataset_tools/waf/README.md, "Running the v2 bake-off")
1. Keep the current model as `ml/waf/artifacts/waf_distilbert_v1` (rollback). Unzip the arm you want to judge into its own
   directory (e.g. `ml/waf/artifacts/waf_distilbert_v2` or `waf_sigmoid_v2`) - do NOT overwrite the shipping directory yet.
2. Judge it: `python -m dataset_tools.waf.v2.gate --results waf_v2_results.json --artifact ml/waf/artifacts/<dir>`
   (recomputes every gate from the raw numbers and replays the probes through `text_service`; non-zero exit = do not ship).
3. Only if it passes: point `WAF_MODEL_PATH` at the directory. Arm A: also set `WAF_ATTACK_THRESHOLD` (what `text_service`
   reads) to `recommended_threshold`. Arm B: the threshold comes from `waf_v2.json`; `WAF_THRESHOLD` overrides it,
   `WAF_ATTACK_THRESHOLD` has no effect.
4. Re-run `tests/test_waf_scope.py tests/test_request_target.py tests/test_text_target.py`, then the VM battery
   (`vm-lab/fw_tests3.ps1`, 30 checks, 0 mismatches). Record the zip's sha256 (printed above) in the README: artifacts are not in git."""),
]


def build() -> dict:
    cells = []
    for kind, src in CELLS:
        lines = src.strip("\n").splitlines(keepends=True)
        if kind == "md":
            cells.append({"cell_type": "markdown", "metadata": {}, "source": lines})
        else:
            cells.append({"cell_type": "code", "metadata": {}, "execution_count": None, "outputs": [], "source": lines})
    return {"cells": cells,
            "metadata": {"accelerator": "GPU", "colab": {"provenance": []},
                         "kernelspec": {"display_name": "Python 3", "name": "python3"}},
            "nbformat": 4, "nbformat_minor": 5}


def main() -> None:
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(build(), f, indent=1)
    print("wrote", OUT)


if __name__ == "__main__":
    main()
