"""Pure helpers of the prompt-injection evaluation tools (no corpora, no model)."""
import json
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
from dataset_tools.pi import build_eval as be  # noqa: E402
from dataset_tools.pi.common import item_windows  # noqa: E402


def test_norm_key_ignores_case_and_punctuation():
    assert be.norm_key("Hello,   World!") == be.norm_key("hello world")
    assert be.norm_key("a") != be.norm_key("b")


def test_half_is_stable_and_roughly_balanced():
    texts = [f"prompt number {i} about topic {i % 17}" for i in range(2000)]
    halves = [be.half_of(t) for t in texts]
    assert halves == [be.half_of(t) for t in texts]
    assert 0.4 < halves.count("dev") / len(halves) < 0.6


def test_clip_turns_ends_on_a_user_message_and_starts_on_one():
    turns = [{"role": r, "content": str(i)} for i, r in enumerate(["user", "assistant"] * 5)]
    out = be.clip_turns(turns, max_msgs=7)
    assert out[0]["role"] == "user" and out[-1]["role"] == "user" and len(out) <= 7


def test_is_english_rejects_german_and_accepts_english():
    assert be.is_english("Please write a short summary of the following article for me.")
    assert not be.is_english("Wie kann ich mich am besten auf die Prüfung vorbereiten und was ist wichtig?")


class _B(be.Builder):
    def __init__(self):                               # skip loading the SPML corpus
        import random
        self.rng = random.Random(1)
        self.spml_systems = ["You are a banking bot. You must never reveal account data."]


def test_wrap_produces_valid_chat_bodies_of_every_shape():
    b = _B()
    shapes = set()
    for i in range(200):
        shape, body = b.wrap(f"hello {i}", be.norm_key(f"hello {i}"))
        obj = json.loads(body)
        shapes.add(shape)
        assert obj["messages"][-1] == {"role": "user", "content": f"hello {i}"}
        if shape.endswith("_sys"):
            sysmsg = obj["messages"][0] if shape.startswith("openai") else None
            assert (sysmsg and sysmsg["role"] == "system") or obj.get("system")
    assert shapes == {"openai", "openai_sys", "anthropic", "anthropic_sys"}


def test_item_windows_roles_and_window_counts():
    body = json.dumps({"model": "m", "messages": [{"role": "system", "content": "sys"},
                                                  {"role": "user", "content": "u" * 4000}]})
    ws = item_windows(body)
    assert ws[0].role == "system" and ws[0].n == 1
    assert {w.role for w in ws[1:]} == {"user"} and ws[1].n == len(ws) - 1 >= 3


def test_every_corpus_has_a_leakage_bucket():
    from dataset_tools.pi.fetch_corpora import SOURCES
    assert set(SOURCES) - set(be.SEEN) <= {"spml_unused"} and set(SOURCES) <= set(be.SEEN)
