"""Cheap, NLI-free features per eval text, computed with the REAL text_service functions:

  route_{raw,json,html}   what text_service._route() says for the bare text, the text wrapped as a JSON API body
                          {"message": ...} and as an HTML page (a server reply / form post carrier)
  pat_out / pat_in        model_patterns(text, direction): Presidio PII verdict (blocked / advisory / entity list)
  sec_out / sec_in        model_code_analysis(text, direction): regex secret verdict

    python -I dataset_tools/sensitive/features.py --repo . [--eval ...] [--out .../features.jsonl]

Loads only the router joblib and Presidio (not the NLI / WAF / PI models).
"""
from __future__ import annotations

import argparse
import html
import json
import logging
import os
import sys
import time


def carriers(text: str) -> dict[str, str]:
    return {
        "raw": text,
        "json": json.dumps({"message": text, "lang": "en"}),
        "html": "<!doctype html><html><head><title>Page</title></head><body><div class=\"content\"><p>"
                + html.escape(text).replace("\n", "<br>\n") + "</p></div></body></html>",
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", default=os.getcwd())
    ap.add_argument("--eval", default=os.path.expanduser("~/FYP/corpora/sens_eval/eval.jsonl"))
    ap.add_argument("--out", default=os.path.expanduser("~/FYP/corpora/sens_eval/features.jsonl"))
    a = ap.parse_args()
    sys.path.insert(0, a.repo)
    logging.disable(logging.CRITICAL)
    from presidio_analyzer import AnalyzerEngine

    from ml.router.predictor import RouterClassifier
    from text_service import main as svc

    router = RouterClassifier()
    assert router.load(), "router artifact missing (symlink ml/router/artifacts)"
    svc.router_classifier = router
    svc.presidio_analyzer = AnalyzerEngine()
    recs = []
    for p in (a.eval, os.path.join(os.path.dirname(a.eval), "tiny.jsonl")):
        recs += [json.loads(l) for l in open(p, encoding="utf-8")]
    t0 = time.time()
    with open(a.out, "w", encoding="utf-8") as f:
        for i, r in enumerate(recs):
            t = r["text"]
            row = {"id": r["id"]}
            for name, body in carriers(t).items():
                d = router.route(body)
                row[f"route_{name}"] = d.route
                row[f"rscore_{name}"] = round(d.score, 3)
            for dirn, tag in (("outbound", "out"), ("inbound", "in")):
                pr = svc.model_patterns(t, dirn)
                row[f"pat_{tag}"] = {"blocked": pr.blocked, "advisory": bool((pr.raw_data or {}).get("advisory")), "findings": pr.findings}
                sr = svc.model_code_analysis(t, dirn)
                row[f"sec_{tag}"] = {"blocked": sr.blocked, "advisory": bool((sr.raw_data or {}).get("advisory")), "findings": sr.findings}
            f.write(json.dumps(row) + "\n")
            if (i + 1) % 500 == 0:
                print(i + 1, f"{time.time() - t0:.0f}s", flush=True)
    print("done", len(recs))


if __name__ == "__main__":
    main()
