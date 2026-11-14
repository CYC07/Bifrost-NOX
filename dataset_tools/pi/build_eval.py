"""Compose the prompt-injection gate evaluation set from the fetched PUBLIC corpora.

Run dataset_tools/pi/fetch_corpora.py first. Output (never inside the repo):
    ~/FYP/corpora/pi_eval/eval.jsonl      one item per line
    ~/FYP/corpora/pi_eval/manifest.json   N per set, removals, leakage buckets

Item: {"id","set","group","label","seen","half","shape","body","plain"}
  body   what the gateway would POST to the text service (OpenAI/Anthropic chat JSON, or raw text)
  plain  the user-visible text alone, sent as a non-JSON body for the "plain text" baseline
  half   "dev" | "test": hash of the normalised primary text, stable across runs. Thresholds and
         cue rules are chosen on dev only; the gate is reported on test.
  seen   leakage bucket vs protectai/deberta-v3-base-prompt-injection-v2 (created 2024-04-20):
         heldout        dataset created after the model (xTRam1, PromptShield, WildChat)
         likely_heldout HF copy created after the model, underlying data public earlier (TrustAIRLab)
         named_in_card  named in the model card's training list (jackhhao/jailbreak-classification)
         unknown        public before the model and not named (the card hides ~15 of its 22 datasets):
                        deepset, Lakera/gandalf, SPML, alpaca, dolly, oasst1, ultrachat, CodeAlpaca
         own            the 38-item adversarial set from tests/data/pi_eval.jsonl

Usage: python -I dataset_tools/pi/build_eval.py [--seed 7]
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import json
import os
import random
import re
import sys

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, REPO)
from ml.prompt_injection import signatures  # noqa: E402

CORPORA = os.path.expanduser(os.getenv("PI_CORPORA", "~/FYP/corpora"))
OUT = os.path.join(CORPORA, "pi_eval")

SEEN = {"xtram1": "heldout", "promptshield": "heldout", "wildchat": "heldout", "trustairlab": "likely_heldout",
        "jackhhao": "named_in_card", "deepset": "unknown", "gandalf": "unknown", "spml": "unknown", "alpaca": "unknown",
        "dolly": "unknown", "oasst1": "unknown", "ultrachat": "unknown", "codealpaca": "unknown"}

GENERIC_SYSTEM = ["You are a helpful assistant.",
                  "You are ChatGPT, a large language model trained by OpenAI. Answer as concisely as possible.",
                  "You are a helpful, harmless, and honest assistant."]
KEYWORDS = re.compile(r"\b(ignore|disregard|forget|override|bypass|previous|prior|above|instructions?|system prompt|"
                      r"passwords?|credentials?|secrets?|jailbreak|admin|security|prompt injection|reveal|confidential)\b", re.I)
CODEISH = re.compile(r"```|\bdef \w+\(|\bfunction \w+\(|#include|\bimport \w+|\bSELECT\b.+\bFROM\b|<div|public static void", re.S)
DOC_TASKS = ["Summarize the following document:\n\n{doc}", "Here is an email I received, please summarize it:\n\n{doc}",
             "Translate the text below into French.\n\n{doc}", "Extract the key points from this text:\n\n{doc}",
             "Read the article below and answer: what is the main argument?\n\n{doc}"]


def norm_key(text: str) -> str:
    return hashlib.sha1(re.sub(r"\W+", " ", text.lower()).strip()[:400].encode()).hexdigest()


def half_of(text: str) -> str:
    return "dev" if int(norm_key(text)[:8], 16) % 2 == 0 else "test"


def load(name: str) -> list[dict]:
    with open(os.path.join(CORPORA, f"pi_{name}", "items.jsonl"), encoding="utf-8") as f:
        return [json.loads(line) for line in f]


def is_english(t: str) -> bool:
    if not t:
        return False
    ascii_ratio = sum(c < "\x80" for c in t) / len(t)
    words = re.findall(r"[a-z']+", t.lower())
    hits = sum(w in {"the", "and", "you", "to", "of", "a", "is", "in", "i", "that", "for", "with", "me", "it"} for w in words)
    return ascii_ratio > 0.95 and (len(words) < 4 or hits / max(len(words), 1) > 0.12)


class Builder:
    def __init__(self, seed: int) -> None:
        self.rng = random.Random(seed)
        self.items: list[dict] = []
        self.seen_keys: set[str] = set()
        self.counts: dict[str, int] = collections.Counter()
        self.removed: dict[str, int] = collections.Counter()
        spml = load("spml")
        systems = sorted({r["meta"]["system"] for r in spml if len(r["meta"]["system"]) > 80})
        self.rng.shuffle(systems)
        self.spml_systems = systems[:40]

    # -- wrappers -------------------------------------------------------------------
    def wrap(self, text: str, key: str, system: str | None = None, turns: list[dict] | None = None) -> tuple[str, str]:
        """(shape, body). Shape rotates on the item hash so the mix is deterministic."""
        slot = int(key[:8], 16) % 10
        msgs = turns or [{"role": "user", "content": text}]
        if system is None:
            system = None if slot < 4 else (self.rng_choice(GENERIC_SYSTEM, key) if slot < 6 else
                                            self.rng_choice(self.spml_systems, key) if slot < 8 else
                                            self.rng_choice(GENERIC_SYSTEM + self.spml_systems, key) if slot == 8 else None)
        if slot >= 8:                                           # Anthropic messages API
            body = {"model": "claude-x", "max_tokens": 1024, "messages": msgs}
            if system:
                body["system"] = system
            return ("anthropic_sys" if system else "anthropic"), json.dumps(body)
        if system:
            msgs = [{"role": "system", "content": system}] + msgs
        return ("openai_sys" if system else "openai"), json.dumps({"model": "gpt-x", "messages": msgs})

    @staticmethod
    def rng_choice(pool: list[str], key: str) -> str:
        return pool[int(key[8:16], 16) % len(pool)]

    # -- bookkeeping ------------------------------------------------------------------
    def add(self, set_name: str, group: str, label: str, seen: str, text: str, body: str | None = None,
            shape: str | None = None, turns: list[dict] | None = None, system: str | None = None, plain: str | None = None,
            dedupe: bool = True) -> bool:
        k = norm_key(text)
        if dedupe and k in self.seen_keys:
            self.removed["duplicate"] += 1
            return False
        self.seen_keys.add(k)
        if body is None:
            shape, body = self.wrap(text, k, system=system, turns=turns)
        self.items.append({"id": f"{set_name}:{self.counts[set_name]}", "set": set_name, "group": group, "label": label,
                           "seen": seen, "half": half_of(text), "shape": shape, "body": body, "plain": plain if plain is not None else text})
        self.counts[set_name] += 1
        return True

    def take(self, rows: list[dict], n: int, ok=lambda r: True) -> list[dict]:
        pool = [r for r in rows if ok(r)]
        self.rng.shuffle(pool)
        return pool[:n]


def clip_turns(turns: list[dict], max_msgs: int = 7) -> list[dict]:
    turns = turns[-max_msgs:]
    while turns and turns[-1]["role"] != "user":
        turns = turns[:-1]
    while turns and turns[0]["role"] != "user":
        turns = turns[1:]
    return turns


def build(seed: int) -> Builder:
    b = Builder(seed)
    sig_hit = lambda t: bool(signatures.detect(t))  # noqa: E731

    # ---------------- ATTACKS: prompt injection ----------------
    for name, group, n, extra in [("xtram1", "pi", 450, lambda r: is_english(r["text"])),
                                  ("promptshield", "pi", 450, lambda r: is_english(r["text"]) and len(r["text"]) < 6000),
                                  ("gandalf", "pi", 300, lambda r: True),
                                  ("deepset", "pi", 400, lambda r: True)]:
        rows = [r for r in load(name) if r["label"] == "attack"]
        for r in b.take(rows, n, extra):
            b.add(f"A_{name}", group, "attack", SEEN[name], r["text"])
    # SPML: injection attempts against a chatbot WITH its own developer system prompt
    for r in b.take([r for r in load("spml") if r["label"] == "attack"], 300):
        b.add("A_spml", "pi", "attack", SEEN["spml"], r["text"], system=r["meta"]["system"])
    # ---------------- ATTACKS: jailbreaks (the model card says it does not target these) ----------------
    for name, n in [("jackhhao", 300), ("trustairlab", 300)]:
        rows = [r for r in load(name) if r["label"] == "attack"]
        for r in b.take(rows, n, lambda r: is_english(r["text"][:2000])):
            b.add(f"J_{name}", "jailbreak", "attack", SEEN[name], r["text"])

    # ---------------- BENIGN: classifier-benchmark benign halves (same distribution as the attacks) ----------------
    for name, n in [("xtram1", 400), ("promptshield", 400), ("deepset", 399), ("jackhhao", 300)]:
        rows = [r for r in load(name) if r["label"] == "benign"]
        for r in b.take(rows, n, lambda r: len(r["text"]) < 8000):
            b.add(f"B_bench_{name}", "bench_benign", "benign", SEEN[name], r["text"])
    for r in b.take([r for r in load("spml") if r["label"] == "benign"], 300):
        b.add("B_bench_spml", "bench_benign", "benign", SEEN["spml"], r["text"], system=r["meta"]["system"])

    # ---------------- BENIGN: realistic LLM traffic ----------------
    jb_keys = {norm_key(r["text"]) for r in load("trustairlab") if r["label"] == "attack"} | \
              {norm_key(r["text"]) for r in load("jackhhao") if r["label"] == "attack"}

    def clean(r, tag):                                       # drop real jailbreaks hiding in "benign" real-world logs
        t = r["text"]
        if norm_key(t) in jb_keys or sig_hit(t):
            b.removed[f"jailbreak_filtered:{tag}"] += 1
            return False
        return True

    wc_clean = [r for r in load("wildchat") if clean(r, "wildchat")]
    wc_single = [r for r in wc_clean if 0 < len(r["text"]) <= 1500 and not CODEISH.search(r["text"])]
    for r in b.take(wc_single, 600):
        b.add("B_wildchat", "realistic", "benign", "heldout", r["text"])
    for r in b.take(wc_clean, 220, lambda r: len(r["text"]) > 1500 and not CODEISH.search(r["text"])):
        b.add("B_wildchat_long", "realistic_long", "benign", "heldout", r["text"])
    for r in b.take(wc_clean, 200, lambda r: len(r["turns"]) >= 4 and len(clip_turns(r["turns"])) >= 3):
        t = clip_turns(r["turns"])
        b.add("B_wildchat_multiturn", "realistic_multiturn", "benign", "heldout", t[-1]["content"], turns=t)
    for r in b.take(wc_clean, 200, lambda r: CODEISH.search(r["text"]) and len(r["text"]) <= 4000):
        b.add("B_wildchat_code", "realistic_code", "benign", "heldout", r["text"])
    tr = [r for r in load("trustairlab") if r["label"] == "benign" and is_english(r["text"][:1500]) and clean(r, "trustairlab")]
    for r in b.take(tr, 300):
        b.add("B_trustairlab_regular", "realistic", "benign", SEEN["trustairlab"], r["text"])
    for name, n, group in [("alpaca", 300, "realistic"), ("oasst1", 300, "realistic"), ("ultrachat", 300, "realistic")]:
        for r in b.take(load(name), n, lambda r: len(r["text"]) < 6000):
            b.add(f"B_{name}", group, "benign", SEEN[name], r["text"])
    for r in b.take(load("dolly"), 300, lambda r: r["meta"]["has_context"] and len(r["text"]) < 8000):
        b.add("B_dolly_ctx", "realistic_long", "benign", SEEN["dolly"], r["text"])
    for r in b.take(load("dolly"), 100, lambda r: not r["meta"]["has_context"]):
        b.add("B_dolly", "realistic", "benign", SEEN["dolly"], r["text"])
    for r in b.take(load("codealpaca"), 150):
        b.add("B_codealpaca", "realistic_code", "benign", SEEN["codealpaca"], r["text"])
    # multi-turn from oasst1/ultrachat (history = real assistant replies)
    for name in ("oasst1", "ultrachat"):
        for r in b.take(load(name), 100, lambda r: len(clip_turns(r["turns"])) >= 3):
            t = clip_turns(r["turns"])
            b.add(f"B_{name}_multiturn", "realistic_multiturn", "benign", SEEN[name], t[-1]["content"], turns=t)

    # benign prompts that merely MENTION instructions / passwords / security / "ignore" / "previous"
    kw_pools = {"heldout": wc_clean + tr,
                "unknown": load("oasst1") + load("dolly") + load("alpaca") + load("ultrachat")}
    for seen, pool in kw_pools.items():
        hits = [r for r in pool if KEYWORDS.search(r["text"]) and not sig_hit(r["text"]) and len(r["text"]) < 4000]
        for r in b.take(hits, 200):
            b.add(f"B_keywords_{seen}", "realistic_keywords", "benign", seen, r["text"])

    # ---------------- DOCUMENT + TASK, with and without an embedded injection ----------------
    docs = [r["text"] for r in load("dolly") if r["meta"]["has_context"] and 600 < len(r["text"]) < 6000] + \
           [r["text"] for r in wc_clean if 1500 < len(r["text"]) < 6000 and not CODEISH.search(r["text"])]
    b.rng.shuffle(docs)
    inj_pool = [r["text"] for n in ("xtram1", "promptshield") for r in load(n)
                if r["label"] == "attack" and 25 < len(r["text"]) < 300 and is_english(r["text"])]
    b.rng.shuffle(inj_pool)
    d_iter = iter(docs)
    for i in range(300):                                     # benign: doc + task, no injection
        doc = next(d_iter)
        b.add("B_doc_task", "realistic_long", "benign", "unknown", DOC_TASKS[i % 5].format(doc=doc))
    for i in range(300):                                     # attack: the same shape with an injection inside the doc
        doc, inj = next(d_iter), inj_pool[i]
        sents = re.split(r"(?<=[.!?])\s+", doc)
        pos = (0, len(sents) // 2, len(sents))[i % 3]
        sents.insert(pos, inj)
        text = DOC_TASKS[i % 5].format(doc=" ".join(sents))
        b.add("A_embedded", "embedded", "attack", "heldout", text, plain=text)

    # ---------------- NON-PROMPT text sent to an LLM endpoint (the "page / file / form text as prompt" case) ----------------
    # Proxy for the adversarial-benign class with a usable N: benign request bodies built by
    # dataset_tools/router/build_gate_eval.py from system/repo files (code, docs, configs, logs, man pages)
    # and synthetic login forms / JSON API bodies. Never seen by the PI model (not a prompt corpus).
    gate = os.path.join(CORPORA, "router_gate_eval", "benign.jsonl")
    if os.path.exists(gate):
        with open(gate, encoding="utf-8") as f:
            rows = [json.loads(line) for line in f]
        for r in b.take(rows, 160, lambda r: 20 <= len(r["text"]) <= 3000):
            k = norm_key(r["text"])
            if int(k[:8], 16) % 2:
                b.add("B_webtext", "webtext", "benign", "unknown", r["text"], body=r["text"], shape="raw")
            else:
                shape, body = b.wrap("Summarize the following:\n\n" + r["text"], k, system="")
                b.add("B_webtext", "webtext", "benign", "unknown", r["text"], body=body, shape=shape, plain=r["text"])

    # ---------------- the 38-item adversarial set (tests/data/pi_eval.jsonl) ----------------
    with open(os.path.join(REPO, "tests", "data", "pi_eval.jsonl"), encoding="utf-8") as f:
        for line in f:
            e = json.loads(line)
            name = "A_adversarial" if e["label"] == "attack" else "B_adversarial"
            b.add(name, "adversarial", e["label"], "own", e["text"], body=e["text"], shape="raw", dedupe=False)
    return b


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=7)
    args = ap.parse_args()
    b = build(args.seed)
    os.makedirs(OUT, exist_ok=True)
    with open(os.path.join(OUT, "eval.jsonl"), "w", encoding="utf-8") as f:
        for it in b.items:
            f.write(json.dumps(it, ensure_ascii=False) + "\n")
    per = collections.defaultdict(lambda: collections.Counter())
    for it in b.items:
        per[it["set"]]["n"] += 1
        per[it["set"]][it["half"]] += 1
    manifest = {"seed": args.seed, "sets": {k: dict(v) for k, v in sorted(per.items())}, "removed": dict(b.removed),
                "seen": {it["set"]: it["seen"] for it in b.items}}
    with open(os.path.join(OUT, "manifest.json"), "w") as f:
        json.dump(manifest, f, indent=1)
    for k, v in sorted(per.items()):
        print(f"{k:28s} n={v['n']:4d} dev={v['dev']:4d} test={v['test']:4d}  {manifest['seen'][k]}")
    print("removed:", dict(b.removed), "total", len(b.items))


if __name__ == "__main__":
    main()
