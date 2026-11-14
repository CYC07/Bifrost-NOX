"""Build the sensitive-content evaluation set from the PUBLIC corpora fetched by fetch.py.

    python -I dataset_tools/sensitive/build_eval.py [--root ~/FYP/corpora] [--out ~/FYP/corpora/sens_eval] [--seed 7]

Writes <out>/eval.jsonl (+ tiny.jsonl, SOURCE.txt, stats.json); never anything inside the repo.

Record: {id, set, label: pos|neg, confusable: bool, synthetic: bool, marked: bool, split: dev|test, text}
  * label pos = text a data-loss control SHOULD stop leaving the network (private medical / financial /
    contract / PII-bearing / internal email); neg = public or ordinary prose that must pass.
  * confusable = public-facing legal / medical / financial prose: the topic is the same as a positive, only
    the confidentiality differs. This is where a topic detector confuses public with confidential.
  * synthetic = generated here (Faker) or by the corpus authors (Gretel); marked = carries an explicit
    confidentiality marker ("confidential", "privileged", ...). Recall on marked positives is inflated for any
    rule that keys on the marker, so it is always reported separately.
  * split: deterministic 50/50 by the text hash. Labels / thresholds / rules are chosen on dev only and the gate
    is reported on test.
Texts are the first <=1000 chars of the document (cut at a paragraph/sentence boundary), i.e. what the analyzer
sees of a body (it reads text[:2000]).
"""
from __future__ import annotations

import argparse
import ast
import csv
import glob
import hashlib
import json
import lzma
import os
import random
import re
import sys

import polars as pl

csv.field_size_limit(1 << 26)

LO, HI = 120, 1000
MARKER = re.compile(
    r"\b(privileged|confidential(?:ity)?|proprietary|attorney[- ]client|do not (?:forward|distribute|share)|"
    r"internal use only|not for (?:distribution|release)|hr use only|restricted)\b", re.I)


def norm(t: str) -> str:
    t = t.replace("\r\n", "\n").replace("\r", "\n").replace(" ", " ")
    t = re.sub(r"[ \t]+", " ", t)
    t = re.sub(r" *\n *", "\n", t)
    t = re.sub(r"\n{3,}", "\n\n", t)
    return t.strip()


def cut(t: str, lo: int = LO, hi: int = HI) -> str | None:
    t = norm(t)
    if len(t) < lo:
        return None
    if len(t) <= hi:
        return t
    head = t[:hi]
    for sep in ("\n\n", "\n", ". ", " "):
        i = head.rfind(sep, int(hi * 0.6))
        if i > 0:
            return head[:i + (1 if sep == ". " else 0)].strip()
    return head.strip()


def rid(set_: str, text: str) -> str:
    return hashlib.sha1((set_ + "\0" + text).encode("utf-8", "ignore")).hexdigest()[:14]


class Builder:
    def __init__(self, seed: int, scale: float = 1.0, exclude: set[str] | None = None) -> None:
        self.seed = seed
        self.scale = scale
        self.records: list[dict] = []
        self.seen: set[str] = set(exclude or ())

    def add(self, set_: str, label: str, texts: list[str], n: int, *, confusable: bool = False,
            synthetic: bool = False, cutter=cut) -> None:
        rng = random.Random(f"{self.seed}:{set_}")
        n = max(1, round(n * self.scale))
        pool = []
        for t in texts:
            c = cutter(t) if cutter else t
            if c and c not in self.seen:
                pool.append(c)
        rng.shuffle(pool)
        for c in pool[:n]:
            self.seen.add(c)
            self.records.append({
                "id": rid(set_, c), "set": set_, "label": label, "confusable": confusable,
                "synthetic": synthetic, "marked": bool(MARKER.search(c)),
                "split": "dev" if int(rid(set_, c), 16) % 2 == 0 else "test", "text": c})
        print(f"  {set_:28s} want {n:4d} have {len(pool):6d} -> {min(n, len(pool))}")


# ----------------------------------------------------------------------------- loaders
def g(root: str, pat: str) -> list[str]:
    return sorted(glob.glob(os.path.join(root, pat), recursive=True))


def load_mtsamples(root):
    df = pl.read_csv(g(root, "sens_mtsamples/raw/*/mtsamples.csv")[0], ignore_errors=True)
    return [str(t).replace(":,", ":").replace(",  ", ", ") for t in df["transcription"].drop_nulls().to_list()]


GRETEL_PRIVATE = {"Financial Statement", "Loan Application", "Insurance Policy", "Policyholder's Report", "Tax Return",
                  "Payment Confirmation", "Health Insurance Claim Form", "Credit Card Application",
                  "Employment Contract", "Mortgage Amortization Schedule", "Tax Assessment Notice",
                  "Financial Aid Application", "Pension Plan Agreement", "Trade Confirmation", "MT940",
                  "Business Plan", "BAI Format", "Customer support conversational log"}


def load_gretel(root):
    df = pl.read_parquet(g(root, "sens_gretel_fin/raw/*/data/English_test*.parquet")[0])
    df = df.filter(pl.col("document_type").is_in(sorted(GRETEL_PRIVATE)))
    return df["generated_text"].to_list()


def load_cuad(root):
    d = json.load(open(g(root, "sens_cuad/raw/*/CUAD_v1/CUAD_v1.json")[0], encoding="utf-8"))
    return [p["paragraphs"][0]["context"].lstrip() for p in d["data"]]


def _ai4(root):
    rows = []
    with open(g(root, "sens_ai4privacy/raw/*/PII43k.csv")[0], newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            rows.append((r["Template"], r["Filled Template"]))
    return rows


HIGH_VALUE = re.compile(r"\[(ACCOUNTNUMBER|CREDITCARDNUMBER|CREDITCARDCVV|IBAN|BIC|PIN|PASSWORD|STREETADDRESS|"
                        r"MASKEDNUMBER|BITCOINADDRESS|ETHEREUMADDRESS)_\d+\]")


def load_ai4_high(root):
    return [f for t, f in _ai4(root) if HIGH_VALUE.search(t)]


def load_ai4_nameonly(root):
    return [f for t, f in _ai4(root) if not HIGH_VALUE.search(t) and re.search(r"\[(FULLNAME|NAME|FIRSTNAME|EMAIL|CITY)_\d+\]", t)]


def _aeslc(root):
    out = []
    for p in g(root, "sens_aeslc/raw/*/data/*.parquet"):
        out += pl.read_parquet(p)["email_body"].to_list()
    return out


def load_aeslc_marked(root):
    return [t for t in _aeslc(root) if MARKER.search(t)]


def load_aeslc_plain(root):
    return [t for t in _aeslc(root) if not MARKER.search(t)]


# --- synthetic positives (Faker, seeded) ---------------------------------------------------------
def gen_hr_fin(seed: int, n: int, marked: bool) -> list[str]:
    from faker import Faker
    fk = Faker("en_US")
    Faker.seed(seed + (1 if marked else 2))
    rng = random.Random(seed + (11 if marked else 12))
    marks = ["CONFIDENTIAL", "Confidential - HR use only", "Privileged & Confidential", "INTERNAL USE ONLY - do not forward",
             "Strictly confidential, not for distribution"]
    out = []
    for _ in range(n):
        kind = rng.choice(["salary", "payroll", "bonus", "offer", "unreleased", "account"])
        k = rng.randint(4, 9)
        names = [fk.name() for _ in range(k)]
        if kind == "salary":
            body = rng.choice(["Employee salary list", "Compensation review", "Annual pay scale", "Salary bands by employee"]) + ":\n"
            body += "\n".join(f"{nm}: {rng.randint(48, 210) * 1000}" for nm in names)
        elif kind == "payroll":
            body = "EmpID | Name | Gross | Tax | Net\n" + "\n".join(
                f"{rng.randint(1000, 9999)} | {nm} | {(g_ := rng.randint(3200, 14000))} | {int(g_ * rng.uniform(.18, .32))} | {int(g_ * rng.uniform(.6, .78))}"
                for nm in names)
        elif kind == "bonus":
            body = f"{fk.year()} bonus allocation, " + fk.company() + " engineering:\n" + "\n".join(
                f"- {nm}: ${rng.randint(2, 60) * 1000:,} (rating {rng.choice(['Exceeds', 'Meets', 'Outstanding'])})" for nm in names)
        elif kind == "offer":
            nm = names[0]
            body = (f"Offer letter for {nm}, {fk.street_address()}, {fk.city()}. Base salary ${rng.randint(70, 240) * 1000:,} per year, "
                    f"signing bonus ${rng.randint(5, 40) * 1000:,}, {rng.randint(1000, 40000)} stock options vesting over 4 years. "
                    f"Start date {fk.date_this_year()}. Please keep these terms between you and {fk.company()}.")
        elif kind == "unreleased":
            body = (f"Draft Q{rng.randint(1, 4)} results ahead of the earnings call: revenue ${rng.randint(120, 940)}M "
                    f"(guidance was ${rng.randint(100, 900)}M), EBITDA ${rng.randint(10, 300)}M, net loss ${rng.randint(1, 40)}M. "
                    f"Headcount reduction of {rng.randint(40, 600)} planned for {fk.month_name()}. Not yet announced to the market.")
        else:
            acct = fk.bban()
            body = f"Account statement for {names[0]}, account {acct}, balance ${rng.randint(1, 90) * 1000 + rng.randint(0, 999):,}.{rng.randint(10, 99)}\n" + "\n".join(
                f"{fk.date_this_year()}  {fk.company()[:24]:24s}  {rng.choice(['-', '+'])}{rng.randint(5, 4000)}.{rng.randint(10, 99)}" for _ in range(rng.randint(4, 8)))
        if marked:
            body = (rng.choice(marks) + "\n" if rng.random() < .5 else "") + body + ("\n" + rng.choice(marks) if rng.random() < .6 else "")
            if not MARKER.search(body):
                body += "\n" + rng.choice(marks)
        out.append(body)
    return out


def gen_pii_ids(seed: int, n: int) -> list[str]:
    from faker import Faker
    fk = Faker("en_US")
    Faker.seed(seed + 3)
    rng = random.Random(seed + 13)
    out = []
    for _ in range(n):
        pp = rng.choice(["X", "A", "K", "N", "C"]) + "".join(str(rng.randint(0, 9)) for _ in range(rng.choice([7, 8])))
        ssn = fk.ssn()
        dob = fk.date_of_birth(minimum_age=19, maximum_age=80).strftime("%d %B %Y")
        addr = f"{fk.street_address()}, {fk.city()}"
        nm = fk.name()
        dl = rng.choice(["D", "S", "R"]) + "".join(str(rng.randint(0, 9)) for _ in range(8))
        tpl = rng.choice([
            "My passport number is {pp} and my home address is {addr}.",
            "Hi, it's {nm}. Passport {pp}, born {dob}, living at {addr}. Please update my file.",
            "Applicant: {nm}\nDate of birth: {dob}\nPassport no.: {pp}\nResidence: {addr}",
            "For the visa form: full name {nm}, passport number {pp}, date of birth {dob}, current address {addr}.",
            "{nm} (SSN {ssn}) lives at {addr}; driver licence {dl}.",
            "Please verify my identity: name {nm}, social security number {ssn}, date of birth {dob}.",
            "Here are the details you asked for - licence number {dl}, home address {addr}, birthday {dob}. Name on file: {nm}.",
            "Tenant record: {nm}, DOB {dob}, ID {dl}, previous address {addr}, SSN {ssn}.",
        ])
        out.append(tpl.format(pp=pp, ssn=ssn, dob=dob, addr=addr, nm=nm, dl=dl))
    return out


# --- benign loaders ------------------------------------------------------------------------------
def load_tos_online(root):
    rows = [json.loads(l) for l in open(g(root, "sens_tos/raw/joelniklaus__online_terms_of_service/test.jsonl")[0], encoding="utf-8")]
    by: dict[str, list] = {}
    for r in rows:
        if r["language"] == "en":
            by.setdefault(r["company"], []).append((int(r["line_number"]), r["sentence"].strip()))
    out = []
    for comp, ls in by.items():
        ls.sort()
        buf = ""
        for _, s in ls:
            if len(s) < 25 or s.startswith("http"):
                continue
            buf = (buf + " " + s).strip()
            if len(buf) > 700:
                out.append(buf)
                buf = ""
        if len(buf) > LO:
            out.append(buf)
    return out


def load_tos_opp(root):
    df = pl.read_parquet(g(root, "sens_tos/raw/alzoubi36__opp_115/data/*.parquet")[0])
    return list(dict.fromkeys(t.strip() for t in df["text"].to_list()))


def load_tos_privacyqa(root):
    df = pl.read_parquet(g(root, "sens_tos/raw/alzoubi36__privacy_qa/data/*.parquet")[0])
    segs = list(dict.fromkeys(t.strip() for t in df["text"].to_list() if len(t.strip()) >= 100))
    return segs


def load_tos_github(root):
    out = []
    files = [p for p in g(root, "sens_githubpolicy/repo/Policies/**/*.md")
             if "github-terms" in p or "privacy-policies" in p or "acceptable-use" in p or "other-site" in p]
    rng = random.Random(5)
    for p in sorted(files):
        t = open(p, encoding="utf-8", errors="replace").read()
        t = re.sub(r"\A---.*?---\n", "", t, flags=re.S)
        t = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", t)
        t = re.sub(r"[#*_`>]+", "", t)
        paras = [x.strip() for x in re.split(r"\n\s*\n", t) if len(x.strip()) > 60]
        picks = []
        buf = ""
        for x in paras:
            buf = (buf + "\n\n" + x).strip()
            if len(buf) > 600:
                picks.append(buf)
                buf = ""
        rng.shuffle(picks)
        out += picks[:3]  # at most 3 paragraphs per document: diversity over volume
    return out


def load_cnn(root):
    df = pl.read_parquet(g(root, "sens_news_cnn/raw/*/3.0.0/*.parquet")[0])
    return [re.sub(r"^(?:.{0,60}?\(CNN\)\s*(?:--\s*)?)", "", a) for a in df["article"].to_list()]


def load_xsum(root):
    return pl.read_parquet(g(root, "sens_news_xsum/raw/*/data/*.parquet")[0])["document"].to_list()


def _detok(t: str) -> str:
    t = t.replace(" @-@ ", "-").replace(" @,@ ", ",").replace(" @.@ ", ".")
    t = re.sub(r" ([,.;:?!%)])", r"\1", t)
    t = re.sub(r"([(\$]) ", r"\1", t)
    return t.replace(" 's", "'s").replace(" n't", "n't")


def load_wiki(root):
    df = pl.read_parquet(g(root, "sens_wiki/raw/*/wikitext-103-raw-v1/test*.parquet")[0])
    return [_detok(t.strip()) for t in df["text"].to_list() if len(t.strip()) > 300 and not t.strip().startswith("=")]


def load_blogs(root):
    return pl.read_parquet(g(root, "sens_blogs/raw/*/*/validation/0000.parquet")[0])["text"].head(8000).to_list()


def load_recipes(root):
    return pl.read_parquet(g(root, "sens_recipes/raw/*/data/*.parquet")[0])["input"].head(20000).to_list()


def load_fin_news(root):
    df = pl.read_csv(g(root, "sens_fin_news/raw/*/bbc-text.csv")[0])
    return df.filter(pl.col("category") == "business")["text"].to_list()


def load_fin_filings(root):
    seen, out = set(), []
    for l in open(g(root, "sens_fin_filings/raw/*/financebench_merged.jsonl")[0], encoding="utf-8"):
        for ev in json.loads(l).get("evidence") or []:
            t = norm(re.sub(r"\n \n", "\n", ev.get("evidence_text", "")))
            if t not in seen:
                seen.add(t)
                out.append(t)
    return out


def load_med_text(root):
    out = []
    for fn in ("Biochemistry_Lippincott", "Pathology_Robbins", "Pediatrics_Nelson"):
        for l in open(g(root, f"sens_med_public/raw/MedRAG__textbooks/chunk/{fn}.jsonl")[0], encoding="utf-8"):
            out.append(json.loads(l)["content"])
    return out


def load_medquad(root):
    return [str(a) for a in pl.read_csv(g(root, "sens_med_public/raw/*MedQuad*/medDataset_processed.csv")[0], ignore_errors=True)["Answer"].drop_nulls().to_list()]


def load_eurlex(root):
    return pl.read_parquet(g(root, "sens_legal_public/raw/*lex_glue/eurlex/*.parquet")[0])["text"].to_list()


def _pile(root, name):
    out = []
    with lzma.open(g(root, f"sens_legal_public/raw/*/data/train.{name}.jsonl.xz")[0], "rt", encoding="utf-8") as f:
        for i, l in zip(range(400), f):
            t = json.loads(l)["text"]
            if t.startswith(("b'", 'b"')):
                try:
                    t = ast.literal_eval(t).decode("utf-8", "replace")
                except Exception:  # noqa: BLE001
                    pass
            out.append(t)
    return out


def load_licenses(root):
    seen, out = set(), []
    for p in g(root, "sens_localdocs/licenses/*"):
        t = open(p, encoding="utf-8", errors="replace").read()
        k = hashlib.md5(t.encode()).hexdigest()
        if k not in seen:
            seen.add(k)
            out.append(t)
    return out


def load_man(root):
    # groff/grotty renders bold/underline as overstrike (X BS X); strip it to what a reader would see
    return [re.sub(r".\x08", "", open(p, encoding="utf-8", errors="replace").read()) for p in g(root, "sens_localdocs/man/*")]


def load_readme(root):
    return [open(p, encoding="utf-8", errors="replace").read() for p in g(root, "sens_localdocs/readme/*")]


TINY_BENIGN = ["The quarterly meeting is on Tuesday at 3pm in room 4.", "Our terms of service describe how we handle your account and data.",
               "Recipe: mix flour, eggs and milk, then bake for 20 minutes.", "Please review the attached project timeline.",
               "The weather tomorrow will be sunny with a light breeze.", "Privacy policy: we respect your privacy and use cookies to improve the site.",
               "Click here to reset your password if you forgot it.", "Invoice #4021 is due on the 15th of next month."]
TINY_SENS = ["Here is the patient's full medical record including diagnosis and HIV status.",
             "Employee salary list: Alice 142000, Bob 98000, Carol 175000, confidential.",
             "Attached are our unreleased Q4 earnings figures before the public announcement.",
             "My passport number is X1234567 and my home address is 12 Elm St."]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=os.path.expanduser("~/FYP/corpora"))
    ap.add_argument("--out", default=os.path.expanduser("~/FYP/corpora/sens_eval"))
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--scale", type=float, default=1.0, help="multiply every set size (the holdout run uses a new seed and --exclude)")
    ap.add_argument("--exclude", default="", help="eval.jsonl whose texts must not be re-drawn (fresh holdout)")
    a = ap.parse_args()
    root = a.root
    excl = {json.loads(l)["text"] for l in open(a.exclude, encoding="utf-8")} if a.exclude else set()
    b = Builder(a.seed, a.scale, excl)
    print("POSITIVES")
    b.add("pos_medical_mtsamples", "pos", load_mtsamples(root), 40)
    b.add("pos_fin_gretel", "pos", load_gretel(root), 35, synthetic=True)
    b.add("pos_contract_cuad", "pos", load_cuad(root), 30)
    b.add("pos_pii_ai4_highvalue", "pos", load_ai4_high(root), 35, synthetic=True, cutter=lambda t: cut(t, 40))
    b.add("pos_pii_ai4_nameonly", "pos", load_ai4_nameonly(root), 15, synthetic=True, cutter=lambda t: cut(t, 40))
    b.add("pos_pii_synth_ids", "pos", gen_pii_ids(a.seed, 120), 30, synthetic=True, cutter=lambda t: cut(t, 40))
    b.add("pos_email_enron_marked", "pos", load_aeslc_marked(root), 20)
    b.add("pos_email_enron_plain", "pos", load_aeslc_plain(root), 25)
    b.add("pos_synth_hrfin_marked", "pos", gen_hr_fin(a.seed, 80, True), 20, synthetic=True, cutter=lambda t: cut(t, 60))
    b.add("pos_synth_hrfin_unmarked", "pos", gen_hr_fin(a.seed, 80, False), 20, synthetic=True, cutter=lambda t: cut(t, 60))
    print("BENIGN")
    b.add("neg_tos_online", "neg", load_tos_online(root), 20, confusable=True)
    b.add("neg_tos_opp115_privacy", "neg", load_tos_opp(root), 15, confusable=True)
    b.add("neg_tos_privacyqa", "neg", load_tos_privacyqa(root), 15, confusable=True, cutter=lambda t: cut(t, 100))
    b.add("neg_tos_github", "neg", load_tos_github(root), 25, confusable=True)
    b.add("neg_news_cnn", "neg", load_cnn(root), 20)
    b.add("neg_news_xsum", "neg", load_xsum(root), 10)
    b.add("neg_wiki", "neg", load_wiki(root), 20)
    b.add("neg_blogs", "neg", load_blogs(root), 15)
    b.add("neg_recipes", "neg", load_recipes(root), 10)
    b.add("neg_fin_news_bbc", "neg", load_fin_news(root), 25, confusable=True)
    b.add("neg_fin_filings_sec", "neg", load_fin_filings(root), 25, confusable=True)
    b.add("neg_med_textbook", "neg", load_med_text(root), 25, confusable=True)
    b.add("neg_med_nih_qa", "neg", load_medquad(root), 25, confusable=True)
    b.add("neg_legal_eurlex", "neg", load_eurlex(root), 15, confusable=True)
    b.add("neg_legal_constitutions", "neg", _pile(root, "constitutions"), 8, confusable=True)
    b.add("neg_legal_cfpb_cardagr", "neg", _pile(root, "cfpb_cc"), 20, confusable=True)
    b.add("neg_legal_licenses", "neg", load_licenses(root), 15, confusable=True)
    b.add("neg_docs_man", "neg", load_man(root), 15)
    b.add("neg_docs_readme", "neg", load_readme(root), 8)

    os.makedirs(a.out, exist_ok=True)
    random.Random(a.seed).shuffle(b.records)  # any prefix of the file is a stratified-ish sample (the NLI pass is slow)
    with open(os.path.join(a.out, "eval.jsonl"), "w", encoding="utf-8") as f:
        for r in b.records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    with open(os.path.join(a.out, "tiny.jsonl"), "w", encoding="utf-8") as f:
        for i, t in enumerate(TINY_BENIGN):
            f.write(json.dumps({"id": f"tinyb{i}", "set": "tiny_benign", "label": "neg", "text": t, "split": "tiny", "confusable": False, "synthetic": False, "marked": bool(MARKER.search(t))}) + "\n")
        for i, t in enumerate(TINY_SENS):
            f.write(json.dumps({"id": f"tinys{i}", "set": "tiny_sens", "label": "pos", "text": t, "split": "tiny", "confusable": False, "synthetic": False, "marked": bool(MARKER.search(t))}) + "\n")
    stats: dict[str, dict] = {}
    for r in b.records:
        s = stats.setdefault(r["set"], {"n": 0, "label": r["label"], "len": [], "dev": 0, "test": 0})
        s["n"] += 1
        s["len"].append(len(r["text"]))
        s[r["split"]] += 1
    for k, s in stats.items():
        L = sorted(s.pop("len"))
        s["len_median"], s["len_min"], s["len_max"] = L[len(L) // 2], L[0], L[-1]
    json.dump(stats, open(os.path.join(a.out, "stats.json"), "w"), indent=1)
    with open(os.path.join(a.out, "SOURCE.txt"), "w") as f:
        f.write("derived evaluation set built by dataset_tools/sensitive/build_eval.py from the sens_* corpora next to it "
                f"(see each SOURCE.txt); seed {a.seed}. Contains text from public datasets only plus Faker-synthetic positives.\n")
    npos = sum(1 for r in b.records if r["label"] == "pos")
    print(f"total {len(b.records)}  pos {npos}  neg {len(b.records) - npos}")


if __name__ == "__main__":
    main()
