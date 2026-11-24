"""The dashboard shows the Bifrost NØX symbol: the ink version on the light theme, the paper version on the dark one.

The theme is a `data-theme` attribute on <html> (index.html / app.jsx). The swap is pure CSS so it follows the theme
instantly and covers both places the brand mark is rendered (sidebar layout and topbar layout).
"""
import os
import re
import sys
import xml.etree.ElementTree as ET

import pytest
from starlette.testclient import TestClient

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DASH = os.path.join(ROOT, "dashboard")
INK = "bifrost-nox-symbol-small-ink.svg"
PAPER = "bifrost-nox-symbol-small-paper.svg"
CSS = re.sub(r"/\*.*?\*/", "", open(os.path.join(DASH, "styles.css"), encoding="utf-8").read(), flags=re.S)


def _rule(selector: str) -> str:
    """Declarations of the rule whose selector list is exactly `selector` (whitespace-insensitive)."""
    for m in re.finditer(r"([^{}]+)\{([^{}]*)\}", CSS):
        sels = [re.sub(r"\s+", " ", s.strip()) for s in m.group(1).split(",")]
        if selector in sels:
            return m.group(2)
    return ""


@pytest.mark.parametrize("name,fill", [(INK, "#1A1714"), (PAPER, "#FAF8F4")])
def test_symbol_files_are_present_valid_and_safe(name, fill):
    path = os.path.join(DASH, "assets", name)
    assert os.path.exists(path), f"{name} missing from dashboard/assets"
    raw = open(path, encoding="utf-8").read()
    root = ET.fromstring(raw)
    assert root.tag.endswith("svg")
    assert f'fill="{fill}"' in raw                         # ink on light, paper on dark: the right file under the right name
    low = raw.lower()
    assert "<script" not in low and "onload" not in low and "href=\"http" not in low   # a static image only


def test_light_theme_uses_the_ink_symbol():
    assert INK in _rule(".brand-mark") and PAPER not in _rule(".brand-mark")


def test_dark_theme_uses_the_paper_symbol():
    dark = _rule('[data-theme="dark"] .brand-mark')
    assert PAPER in dark and INK not in dark


def test_old_drawn_placeholder_is_gone():
    base = _rule(".brand-mark")
    assert "var(--ink)" not in base                         # no solid square behind the symbol
    assert ".brand-mark::before" not in CSS and ".brand-mark::after" not in CSS


def test_the_symbol_keeps_its_proportions_and_does_not_shrink_in_the_flex_row():
    base = _rule(".brand-mark")
    assert re.search(r"background[^;]*(contain)", base) and "no-repeat" in base
    assert "flex-shrink: 0" in base


@pytest.mark.parametrize("name", [INK, PAPER])
def test_orchestrator_serves_the_symbols(name, monkeypatch):
    monkeypatch.chdir(ROOT)                                 # the dashboard mount is relative to the repo root
    sys.path.insert(0, ROOT)
    from master_ai import orchestrator as orch
    r = TestClient(orch.app, client=("127.0.0.1", 50000)).get(f"/dashboard/assets/{name}")
    assert r.status_code == 200 and r.headers["content-type"].startswith("image/svg+xml")
    assert b"<svg" in r.content
