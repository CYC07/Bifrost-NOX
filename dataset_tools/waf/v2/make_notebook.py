"""Generate dataset_tools/waf/train_v2.ipynb (Colab bake-off on dataset_v2.zip).

    python -m dataset_tools.waf.v2.make_notebook

Arm A: same 7-class DistilBERT as v1 (drop-in for ml/waf/predictor.py) on the v2 data.
Arm B: per-attack sigmoid heads, default-allow. Both are scored with the SAME decision rule and a
threshold picked from the validation clean FP budget, then judged against explicit ship gates.
"""
from __future__ import annotations

import json
import os

HERE = os.path.dirname(__file__)
OUT = os.path.abspath(os.path.join(HERE, "..", "train_v2.ipynb"))

MD_INTRO = """# Bifrost NØX — WAF v2 bake-off (Colab, GPU runtime)

Trains two DistilBERT arms on `dataset_v2.zip` (shape-balanced: clean and attack values share the same
carrier templates, splits are by payload group, two shapes are held out for OOD tests) and judges them
against **ship gates** (FP budget on clean traffic, recall, OOD recall, an independent hand-written battery).

* **Arm A** – 7-class softmax, identical to v1's head, so it is a drop-in for `ml/waf/predictor.py`.
* **Arm B** – one sigmoid head per attack family, default-allow (needs a predictor change to ship).

Runtime → *Change runtime type → T4 GPU*, then run all cells. Upload `dataset_v2.zip` when asked.
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
LABELS = ["clean", "sqli", "xss", "path_traversal", "command_injection", "ssti", "scanner"]   # == ml/waf/taxonomy.py
ATTACKS = LABELS[1:]
print({k: len(v) for k, v in dict(train=train, val=val, test=test, ood=ood).items()})
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
("code", r'''# 7. evaluate both arms on test / OOD
import collections
def evaluate(name, rows, fn, thr):
    flag, pred = fn([r["text"] for r in rows]); flagged = flag > thr
    clean = [i for i, r in enumerate(rows) if r["label"] == "clean"]
    att = [i for i, r in enumerate(rows) if r["label"] not in ("clean", "scanner")]
    fp = float(np.mean([flagged[i] for i in clean])); rec = float(np.mean([flagged[i] for i in att]))
    exact = float(np.mean([flagged[i] and pred[i] == rows[i]["label"] for i in att]))
    by_shape = collections.defaultdict(list)
    for i in clean: by_shape[rows[i]["shape"]].append(flagged[i])
    shape_fp = {s: float(np.mean(v)) for s, v in by_shape.items()}
    per_class = {}
    for lab in ATTACKS:
        idx = [i for i, r in enumerate(rows) if r["label"] == lab]
        if idx: per_class[lab] = round(float(np.mean([flagged[i] for i in idx])), 3)
    return dict(fp=fp, recall=rec, exact=exact, shape_fp=shape_fp, per_class_recall=per_class)
R = {}
for k, fn in ARMS.items():
    R[k] = {"test": evaluate(k, test, fn, THR[k]), "ood": evaluate(k, ood, fn, THR[k])}
    for split in ("test", "ood"):
        r = R[k][split]
        print(f"{k:11s} {split:4s} clean-FP {r['fp']:.2%}  recall {r['recall']:.2%} (exact class {r['exact']:.2%})")
        print("            FP by shape:", {s: f"{v:.1%}" for s, v in sorted(r['shape_fp'].items())})
        print("            recall by class:", r["per_class_recall"])'''),
("code", r'''# 8. independent hand-written battery (never in any generator)
BENIGN = {
 "json login (alice)": json.dumps({"username": "alice", "password": "hunter2"}),
 "json login (email)": json.dumps({"email": "bob@example.com", "password": "S3cure!pass"}),
 "json register": json.dumps({"name": "Carol", "email": "c@example.com", "password": "pw123456", "age": 31}),
 "json search": json.dumps({"query": "best pizza near me", "page": 2}),
 "json token refresh": json.dumps({"refresh_token": "abc123def456", "grant_type": "refresh_token"}),
 "json telemetry": json.dumps({"deviceId": "abc123", "events": [{"t": 1, "n": "heartbeat"}]}),
 "form login": "username=admin&password=secret123&remember=true",
 "form search": "q=best pizza near me&sort=popularity",
 "form contact": "first_name=Michael&last_name=Chen&company=Acme%20Corp",
 "name with apostrophe": json.dumps({"name": "Conan O'Brien"}),
 "url value": json.dumps({"next": "https://example.com/account?tab=billing&id=42"}),
 "prose with sql words": "Please select your plan, then drop us a line or update your profile.",
 "plain prose": "Please contact our support team if you have any questions.",
}
ATTACK = {
 "sqli or": "id=1' OR '1'='1' --", "sqli union": "id=1 UNION SELECT username, password FROM users--",
 "sqli json": json.dumps({"username": "admin' OR '1'='1' --", "password": "x"}),
 "xss script": "q=<script>alert(document.cookie)</script>", "xss img": "name=<img src=x onerror=alert(1)>",
 "traversal": "file=../../../../etc/passwd", "cmdi": "host=127.0.0.1; cat /etc/passwd",
 "cmdi json": json.dumps({"ip": "8.8.8.8 && whoami"}), "ssti": "name={{7*7}}{{config.items()}}",
}
IND = {}
for k, fn in ARMS.items():
    fb, _ = fn(list(BENIGN.values())); fa, _ = fn(list(ATTACK.values()))
    IND[k] = dict(benign_fp=int((fb > THR[k]).sum()), attacks_caught=int((fa > THR[k]).sum()))
    wrong = [n for n, f in zip(BENIGN, fb) if f > THR[k]]
    missed = [n for n, f in zip(ATTACK, fa) if f <= THR[k]]
    print(k, IND[k], "| benign flagged:", wrong, "| attacks missed:", missed)'''),
("code", r'''# 9. ship gates (edit the budgets if you disagree, but decide BEFORE looking at the numbers)
GATES = dict(test_fp=0.01, shape_fp=0.03, recall=0.90, ood_fp=0.02, ood_recall=0.80,
             ind_benign_fp=len(BENIGN) // 5, ind_attacks=len(ATTACK) - 1)
def gate_report(k):
    t, o, i = R[k]["test"], R[k]["ood"], IND[k]
    checks = {
        f"test clean FP <= {GATES['test_fp']:.0%}": t["fp"] <= GATES["test_fp"],
        f"worst shape clean FP <= {GATES['shape_fp']:.0%}": max(t["shape_fp"].values()) <= GATES["shape_fp"],
        f"test recall >= {GATES['recall']:.0%}": t["recall"] >= GATES["recall"],
        f"OOD clean FP <= {GATES['ood_fp']:.0%}": o["fp"] <= GATES["ood_fp"],
        f"OOD recall >= {GATES['ood_recall']:.0%}": o["recall"] >= GATES["ood_recall"],
        f"independent benign FP <= {GATES['ind_benign_fp']}": i["benign_fp"] <= GATES["ind_benign_fp"],
        f"independent attacks caught >= {GATES['ind_attacks']}": i["attacks_caught"] >= GATES["ind_attacks"],
    }
    return checks
PASS = {}
for k in ARMS:
    c = gate_report(k); PASS[k] = all(c.values())
    print(f"== {k}: {'SHIP-READY' if PASS[k] else 'FAILS GATES'}")
    for name, ok in c.items(): print("   ", "PASS" if ok else "FAIL", name)'''),
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
json.dump(dict(R=R, IND=IND, THR=THR, PASS=PASS), open("/content/waf_v2_results.json", "w"), indent=1, default=float)
from google.colab import files
for f in (za, zb, "/content/waf_v2_results.json"): files.download(f)'''),
("md", """## After download
1. Keep the current model as `ml/waf/artifacts/waf_distilbert_v1` (rollback).
2. Unzip `waf_distilbert_v2.zip` to `ml/waf/artifacts/waf_distilbert` and set `WAF_THRESHOLD` to `recommended_threshold`.
3. Re-run: `tests/test_waf_scope.py tests/test_request_target.py tests/test_text_target.py`, then the VM battery
   (`vm-lab/fw_tests3.ps1`, 30 checks, 0 mismatches). Convert the strict xfail on URL/apostrophe values to a normal test.
4. Record the zip's sha256 (printed above) in the README: artifacts are not in git."""),
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
