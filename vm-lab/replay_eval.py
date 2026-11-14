"""Replay tests/data/pi_eval.jsonl through the real text-service pipeline in both scopes."""
import asyncio, json, logging, os, sys
logging.disable(logging.CRITICAL)
sys.path.insert(0, os.getcwd())
from text_service import main as svc

asyncio.run(svc.load_models())
E = [json.loads(l) for l in open("tests/data/pi_eval.jsonl")]

def run(text, scope):
    return svc._analyze_sync(text, scope)

rows = []
for e in E:
    out_ws = run(e["text"], False)
    out_ls = run(e["text"], True)
    rows.append((e["label"], e["text"], out_ws["status"], out_ws["reason"], out_ls["status"], out_ls["reason"]))

def short(t): return t.replace("\n", " ")[:58]
print(f"{'label':7s} {'NON-LLM':8s} {'LLM':6s} text")
for lab, t, s1, r1, s2, r2 in rows:
    print(f"{lab:7s} {str(s1):8s} {str(s2):6s} {short(t)}")

A = [r for r in rows if r[0] == "attack"]; B = [r for r in rows if r[0] == "benign"]
blk = lambda s: str(s).lower().endswith("block")
print()
print(f"BENIGN  non-LLM scope: blocked {sum(blk(r[2]) for r in B)}/{len(B)}   advisory {sum('censor' in str(r[2]).lower() for r in B)}")
print(f"BENIGN  LLM scope    : blocked {sum(blk(r[4]) for r in B)}/{len(B)}")
print(f"ATTACKS LLM scope    : blocked {sum(blk(r[4]) for r in A)}/{len(A)}")
print(f"ATTACKS non-LLM scope: blocked {sum(blk(r[2]) for r in A)}/{len(A)}  advisory {sum('censor' in str(r[2]).lower() for r in A)}  silent {sum(str(r[2]).lower().endswith('allow') for r in A)}")
print("\nBenign items blocked in non-LLM scope (should be none):")
for r in B:
    if blk(r[2]): print("  ", short(r[1]), "->", r[3])
print("Attacks NOT blocked in LLM scope:")
for r in A:
    if not blk(r[4]): print("  ", short(r[1]), "->", r[4])
