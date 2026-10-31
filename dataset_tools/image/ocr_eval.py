"""Score an OCR reader against the rendered-screenshot corpus (screens.py).

Metrics per font / theme / size:
  token_recall    exact fake-secret string present in OCR text (whitespace-insensitive)
  detect_recall   the real detectors (ml.image.ocr_scan.scan_ocr_text) raise the same
                  findings on the OCR text as on the pristine secret string
  fp_rate         benign images that the detectors BLOCK
Readers are "module:function" (image -> text). Built-in: baseline.

  PYTHONPATH=. python -m dataset_tools.image.ocr_eval --reader baseline
  PYTHONPATH=. python -m dataset_tools.image.ocr_eval --reader ml.image.ocr_read:read_text
"""
from __future__ import annotations

import argparse
import collections
import importlib
import json
import os
import random
import re
import time
from multiprocessing import Pool

from PIL import Image

DEF_CORPUS = os.path.expanduser("~/FYP/corpora/image_screens")


def baseline(img):
    import pytesseract
    from ml.image import preprocess
    return pytesseract.image_to_string(preprocess.for_ocr(img))


def _load(spec):
    if spec == "baseline":
        return baseline
    mod, fn = spec.split(":")
    return getattr(importlib.import_module(mod), fn)


_READER = None


def _init(spec):
    global _READER
    os.environ["OMP_THREAD_LIMIT"] = "1"
    _READER = _load(spec)


def _work(path):
    t = time.perf_counter()
    with Image.open(path) as im:
        im.load()
        text = _READER(im)
    return path, text, (time.perf_counter() - t) * 1000


def run_ocr(spec, corpus, workers=6, sample=0):
    items = json.load(open(os.path.join(corpus, "manifest.json")))["images"]
    if sample:  # seeded random subset keeping both labels (manifest order alternates labels)
        items = random.Random(0).sample(items, sample)
    paths = [os.path.join(corpus, i["file"]) for i in items]
    with Pool(workers, _init, (spec,)) as p:
        res = p.map(_work, paths, chunksize=4)
    texts = {os.path.basename(a): (b, c) for a, b, c in res}
    return items, texts


def score(items, texts):
    from presidio_analyzer import AnalyzerEngine
    from ml.image import ocr_scan
    pres = AnalyzerEngine()
    cache = {}

    def scan(t):
        if t not in cache:
            r = ocr_scan.scan_ocr_text(t, pres)
            cache[t] = (frozenset(re.sub(r"\s*\(.*\)$", "", f) for f in r.findings if "keyword" not in f), r.blocked)
        return cache[t]

    agg = collections.defaultdict(collections.Counter)
    fps = []
    for it in items:
        text, _ms = texts[it["file"]]
        keys = [("font", it["font"]), ("theme", it["theme"]), ("size", it["size"]), ("all", "all")]
        flat = "".join(text.split())
        got, blocked = scan(text)
        if it["label"] == "secret":
            for s in it["secrets"]:
                truth = scan(s["text"])[0]
                ok_tok = "".join(s["text"].split()) in flat
                ok_det = bool(truth) and truth <= got
                for k in keys:
                    agg[k]["n"] += 1
                    agg[k]["tok"] += ok_tok
                    agg[k]["det"] += ok_det
        else:
            for k in keys:
                agg[k]["nb"] += 1
                agg[k]["fp"] += blocked
            if blocked:
                fps.append(it["file"])
    lat = [t[1] for t in texts.values()]
    return agg, fps, sum(lat) / len(lat)


def report(agg, fps, lat):
    for dim in ("font", "theme", "size", "all"):
        print(f"--- by {dim}")
        for (d, v), c in sorted(agg.items(), key=lambda x: str(x[0])):
            if d != dim:
                continue
            print(f"{str(v):16s} token={100*c['tok']/max(c['n'],1):5.1f}% detect={100*c['det']/max(c['n'],1):5.1f}% "
                  f"(n={c['n']}) benign_FP={c['fp']}/{c['nb']}")
    print("false-positive files:", fps)
    print(f"mean OCR ms/image: {lat:.0f}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--reader", default="baseline")
    ap.add_argument("--corpus", default=DEF_CORPUS)
    ap.add_argument("--workers", type=int, default=6)
    ap.add_argument("--sample", type=int, default=0, help="seeded random subset size (0=all)")
    ap.add_argument("--dump", help="write texts json here")
    a = ap.parse_args()
    items, texts = run_ocr(a.reader, a.corpus, a.workers, a.sample)
    if a.dump:
        json.dump(texts, open(a.dump, "w"))
    report(*score(items, texts))


if __name__ == "__main__":
    main()
