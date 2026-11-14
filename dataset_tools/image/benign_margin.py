"""Measure the BENIGN false-positive margin of the CLIP group cutoffs and the
stego statistic on a directory of benign images (byte-read only).

Only the negative side is measurable: with no labelled real positives, the
cutoffs in ml.image.clip_labels.GROUP_CUTOFF cannot be calibrated here, and this
tool deliberately proposes no thresholds.

  PYTHONPATH=. python -m dataset_tools.image.benign_margin DIR [DIR ...]
"""
from __future__ import annotations

import os
import sys

import numpy as np
from PIL import Image

from ml.image import clip_labels, stego


def _pct(a, q):
    return float(np.percentile(a, q)) if len(a) else float("nan")


def main(dirs):
    from transformers import CLIPModel, CLIPProcessor
    from ml.image.clip_classifier import ClipClassifier
    mid = "openai/clip-vit-base-patch32"
    clf = ClipClassifier(CLIPModel.from_pretrained(mid), CLIPProcessor.from_pretrained(mid))
    for d in dirs:
        files = sorted(os.path.join(d, f) for f in os.listdir(d) if f.lower().endswith((".png", ".jpg", ".jpeg", ".gif")))
        scores = {"pii_nsfw": [], "sensitive": []}
        chis, fired, n = [], {"pii_nsfw": 0, "sensitive": 0}, 0
        for f in files:
            try:
                with Image.open(f) as im:
                    im.load()
                    im = im.convert("RGB")
            except Exception:
                continue
            n += 1
            r = clf.classify(im)
            gs = (r.raw_data or {}).get("group_scores", {})
            for g in scores:
                scores[g].append(gs.get(g, 0.0))
                fired[g] += gs.get(g, 0.0) > clip_labels.GROUP_CUTOFF[g]
            chis.append(stego.chi_square_lsb(im).raw_data.get("chi_over_dof", float("nan")))
        print(f"== {d}  n={n}")
        for g, v in scores.items():
            print(f"  {g:9s} cutoff={clip_labels.GROUP_CUTOFF[g]}  p50={_pct(v,50):.3f} p90={_pct(v,90):.3f} "
                  f"p99={_pct(v,99):.3f} max={max(v):.3f}  over_cutoff={fired[g]}/{n}")
        print(f"  stego chi/dof p5={_pct(chis,5):.3f} p50={_pct(chis,50):.3f} min={min(chis):.3f}  "
              f"(strict-mode flag is <0.25: {sum(c < 0.25 for c in chis)}/{n}; stego never blocks)")


if __name__ == "__main__":
    main(sys.argv[1:])
