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


# ---------------------------------------------------------------- wordmark next to the symbol

W_INK = "bifrost-nox-wordmark-ink.svg"
W_PAPER = "bifrost-nox-wordmark-paper.svg"
APP = open(os.path.join(DASH, "app.jsx"), encoding="utf-8").read()


@pytest.mark.parametrize("name,fill", [(W_INK, "#1A1714"), (W_PAPER, "#FAF8F4")])
def test_wordmark_files_are_present_valid_and_safe(name, fill):
    raw = open(os.path.join(DASH, "assets", name), encoding="utf-8").read()
    assert ET.fromstring(raw).tag.endswith("svg") and f'fill="{fill}"' in raw
    low = raw.lower()
    assert "<script" not in low and "onload" not in low and "href=\"http" not in low


def test_wordmark_is_ink_on_light_and_paper_on_dark():
    assert W_INK in _rule(".brand-name") and W_PAPER not in _rule(".brand-name")
    dark = _rule('[data-theme="dark"] .brand-name')
    assert W_PAPER in dark and W_INK not in dark


def test_wordmark_keeps_its_proportions_and_fits_the_sidebar():
    base = _rule(".brand-name")
    assert re.search(r"background[^;]*contain", base) and "no-repeat" in base and "flex-shrink: 0" in base
    w = float(re.search(r"width:\s*([\d.]+)px", base).group(1))
    h = float(re.search(r"height:\s*([\d.]+)px", base).group(1))
    assert abs(w / h - 721.77 / 80.06) < 0.15              # the file's own aspect ratio (no stretching)
    assert 26 + 10 + w >= 120                                # kit minimum for symbol + wordmark: 120 px
    assert w <= 156                                          # 232 px sidebar - 2x20 padding - 26 symbol - 10 gap


def test_brand_text_is_replaced_by_the_wordmark_in_both_layouts_and_stays_accessible():
    assert '<div className="brand-name">AI Firewall</div>' not in APP
    assert APP.count('className="brand-name"') == 2                       # sidebar + top bar
    assert APP.count('role="img" aria-label="Bifrost NØX"') == 2          # a screen reader still hears the name


@pytest.mark.parametrize("name", [W_INK, W_PAPER])
def test_orchestrator_serves_the_wordmarks(name, monkeypatch):
    monkeypatch.chdir(ROOT)
    sys.path.insert(0, ROOT)
    from master_ai import orchestrator as orch
    r = TestClient(orch.app, client=("127.0.0.1", 50000)).get(f"/dashboard/assets/{name}")
    assert r.status_code == 200 and r.headers["content-type"].startswith("image/svg+xml")


# ---------------------------------------------------------------- the name is Bifrost NØX everywhere the user can see it

OVERVIEW = open(os.path.join(DASH, "page_overview.jsx"), encoding="utf-8").read()
INDEX = open(os.path.join(DASH, "index.html"), encoding="utf-8").read()
RAW_CSS = open(os.path.join(DASH, "styles.css"), encoding="utf-8").read()
VISIBLE = {"app.jsx": APP, "page_overview.jsx": OVERVIEW, "index.html": INDEX,
           "page_core.jsx": open(os.path.join(DASH, "page_core.jsx"), encoding="utf-8").read(),
           "page_uploads.jsx": open(os.path.join(DASH, "page_uploads.jsx"), encoding="utf-8").read(),
           "components.jsx": open(os.path.join(DASH, "components.jsx"), encoding="utf-8").read()}


def test_the_fyp_badge_is_gone_from_the_brand_area():
    assert "brand-env" not in APP and "brand-env" not in RAW_CSS      # markup and the now-dead CSS rule
    for name, text in VISIBLE.items():
        assert "FYP" not in text, f"'FYP' still shown in {name}"


def test_breadcrumb_root_is_the_product_name():
    m = re.search(r'<div className="crumbs">\s*<span>([^<]+)</span>', APP)
    assert m and m.group(1) == "Bifrost NØX"


def test_overview_subtitle_uses_the_product_name():
    sub = re.search(r'<div className="sub">(.*?)</div>', OVERVIEW, re.S).group(1)
    assert "Bifrost NØX" in sub and "AI Firewall" not in sub


def test_page_title_is_the_product_name():
    assert re.search(r"<title>Bifrost NØX — Dashboard</title>", INDEX)


def test_no_visible_text_still_says_ai_firewall():
    for name, text in VISIBLE.items():
        assert "AI Firewall" not in text, f"'AI Firewall' still present in {name}"
