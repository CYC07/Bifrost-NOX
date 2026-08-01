"""Train the content-shape router baseline: char n-gram TF-IDF + LogReg.

Runs on CPU in seconds — unlike ml/waf/'s DistilBERT, this model has to stay
cheap by design (it runs before the analyzers it's gating), so there's no
transformer variant to train here.

Usage:
    python -m ml.router.train
"""
from __future__ import annotations

import json
import logging
import os

import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report
from sklearn.pipeline import Pipeline

from ml.router.taxonomy import LABELS

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("router.train")

_HERE = os.path.dirname(__file__)
BUILD_DIR = os.path.join(_HERE, "data", "build")
ARTIFACTS_DIR = os.path.join(_HERE, "artifacts")


def _load_split(name: str) -> tuple[list[str], list[str]]:
    path = os.path.join(BUILD_DIR, f"{name}.jsonl")
    texts, labels = [], []
    with open(path, encoding="utf-8") as f:
        for line in f:
            row = json.loads(line)
            texts.append(row["text"])
            labels.append(row["label"])
    return texts, labels


def build_pipeline() -> Pipeline:
    return Pipeline([
        ("tfidf", TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 5), min_df=2, sublinear_tf=True)),
        ("clf", LogisticRegression(C=10.0, max_iter=2000, class_weight="balanced")),
    ])


def main() -> None:
    X_tr, y_tr = _load_split("train")
    X_te, y_te = _load_split("test")
    logger.info("train=%d test=%d", len(X_tr), len(X_te))

    pipe = build_pipeline()
    pipe.fit(X_tr, y_tr)

    y_pred = pipe.predict(X_te)
    report = classification_report(y_te, y_pred, labels=LABELS, zero_division=0)
    print(report)

    os.makedirs(ARTIFACTS_DIR, exist_ok=True)
    out_path = os.path.join(ARTIFACTS_DIR, "router_baseline.joblib")
    joblib.dump({"pipeline": pipe, "labels": LABELS}, out_path)
    logger.info("saved -> %s", out_path)


if __name__ == "__main__":
    main()
