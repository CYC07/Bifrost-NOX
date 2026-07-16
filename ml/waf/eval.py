"""Evaluate a trained WAF model on the held-out test split.

Prints per-class precision/recall/F1 and a confusion matrix, and writes
``artifacts/eval.json`` so you can track metrics across dataset revisions and
compare the baseline against the Colab transformer.

Usage:
    python -m ml.waf.eval
    WAF_MODEL_PATH=ml/waf/artifacts/waf_transformer.joblib python -m ml.waf.eval
"""
from __future__ import annotations

import json
import logging
import os

from sklearn.metrics import classification_report, confusion_matrix

from ml.waf.predictor import DEFAULT_MODEL_PATH, WAFClassifier
from ml.waf.taxonomy import LABELS

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("waf.eval")

_HERE = os.path.dirname(__file__)
BUILD_DIR = os.path.join(_HERE, "data", "build")
ARTIFACTS_DIR = os.path.join(_HERE, "artifacts")


def _load_test() -> tuple[list[str], list[str]]:
    path = os.path.join(BUILD_DIR, "test.jsonl")
    if not os.path.exists(path):
        raise SystemExit("no test split — run `python -m ml.waf.build_dataset` first")
    texts, labels = [], []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                obj = json.loads(line)
                texts.append(obj["text"])
                labels.append(obj["label"])
    return texts, labels


def evaluate(model_path: str = DEFAULT_MODEL_PATH) -> dict:
    clf = WAFClassifier(model_path=model_path)
    if not clf.load():
        raise SystemExit(f"could not load model at {model_path} — train first")

    x_test, y_true = _load_test()
    if not x_test:
        raise SystemExit("test split is empty")

    y_pred = [clf.predict(t).label for t in x_test]
    present = [lab for lab in LABELS if lab in set(y_true) | set(y_pred)]

    report_txt = classification_report(y_true, y_pred, labels=present, zero_division=0)
    logger.info("WAF eval (%d samples):\n%s", len(x_test), report_txt)

    cm = confusion_matrix(y_true, y_pred, labels=present).tolist()
    logger.info("confusion matrix (rows=true, cols=pred) order=%s:", present)
    for lab, row in zip(present, cm):
        logger.info("  %-17s %s", lab, row)

    report_dict = classification_report(
        y_true, y_pred, labels=present, zero_division=0, output_dict=True
    )
    result = {
        "model_path": model_path,
        "n_test": len(x_test),
        "labels": present,
        "confusion_matrix": cm,
        "report": report_dict,
        "macro_f1": report_dict.get("macro avg", {}).get("f1-score", 0.0),
        "accuracy": report_dict.get("accuracy", 0.0),
    }
    os.makedirs(ARTIFACTS_DIR, exist_ok=True)
    with open(os.path.join(ARTIFACTS_DIR, "eval.json"), "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)
    logger.info("macro-F1=%.3f accuracy=%.3f -> artifacts/eval.json", result["macro_f1"], result["accuracy"])
    return result


if __name__ == "__main__":
    evaluate()
