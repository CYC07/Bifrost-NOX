"""Train the baseline WAF classifier (our own model, CPU, no GPU).

Char-n-gram TF-IDF + logistic regression. Character n-grams are the right
inductive bias for web-attack payloads — the signal lives in character patterns
(``' OR 1=1``, ``<script``, ``../``, ``;cat``), which a char model captures
regardless of tokenization. This is a real trained classifier, not hand rules;
it learns the boundary from the data and improves as you add samples.

It is also the *fallback and the benchmark* for the DistilBERT transformer you
train on Colab (see train_transformer.ipynb) — both load through the same
predictor interface.

Usage:
    python -m ml.waf.build_dataset   # first, to produce the splits
    python -m ml.waf.train
"""
from __future__ import annotations

import json
import logging
import os
from typing import List, Tuple

import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report
from sklearn.pipeline import Pipeline

from ml.waf.taxonomy import LABELS

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("waf.train")

_HERE = os.path.dirname(__file__)
BUILD_DIR = os.path.join(_HERE, "data", "build")
ARTIFACTS_DIR = os.path.join(_HERE, "artifacts")
MODEL_PATH = os.path.join(ARTIFACTS_DIR, "waf_baseline.joblib")


def _load_split(name: str) -> Tuple[List[str], List[str]]:
    path = os.path.join(BUILD_DIR, f"{name}.jsonl")
    texts: List[str] = []
    labels: List[str] = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            texts.append(obj["text"])
            labels.append(obj["label"])
    return texts, labels


def build_pipeline() -> Pipeline:
    return Pipeline(
        steps=[
            (
                "tfidf",
                TfidfVectorizer(
                    analyzer="char_wb",
                    ngram_range=(2, 5),
                    min_df=1,
                    lowercase=False,      # case matters for payloads (UNION vs union)
                    sublinear_tf=True,
                ),
            ),
            (
                "clf",
                LogisticRegression(
                    C=10.0,
                    max_iter=2000,
                    class_weight="balanced",  # attack classes are minority
                ),
            ),
        ]
    )


def train() -> Pipeline:
    if not os.path.exists(os.path.join(BUILD_DIR, "train.jsonl")):
        raise SystemExit("no splits found — run `python -m ml.waf.build_dataset` first")

    x_train, y_train = _load_split("train")
    logger.info("training on %d samples", len(x_train))

    pipe = build_pipeline()
    pipe.fit(x_train, y_train)

    # Report on the held-out test split if present.
    test_path = os.path.join(BUILD_DIR, "test.jsonl")
    if os.path.exists(test_path):
        x_test, y_test = _load_split("test")
        if x_test:
            preds = pipe.predict(x_test)
            present = sorted(set(y_test) | set(preds), key=LABELS.index)
            logger.info(
                "test report:\n%s",
                classification_report(y_test, preds, labels=present, zero_division=0),
            )

    os.makedirs(ARTIFACTS_DIR, exist_ok=True)
    joblib.dump({"pipeline": pipe, "labels": LABELS}, MODEL_PATH)
    logger.info("saved model -> %s", MODEL_PATH)
    return pipe


if __name__ == "__main__":
    train()
