"""Structural anomaly detection for documents.

Extracts structural features from PDF and Office-ZIP files and scores them with
an Isolation Forest fitted on a small synthetic distribution of benign feature
vectors. Hard-rule overrides ensure known macro/JS carriers are never soft-passed.
"""

from __future__ import annotations

import io
import logging
import os
import re
import sys
import zipfile
from dataclasses import dataclass, field
from typing import Dict, List, Optional

import numpy as np

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from common.schemas import AnalysisResult
from common.utils import FileSniffer

logger = logging.getLogger("document_service.structure")

try:
    import fitz  # PyMuPDF
except Exception as exc:  # pragma: no cover - environment dependent
    fitz = None
    logger.warning("PyMuPDF (fitz) unavailable: %s", exc)

try:
    from sklearn.ensemble import IsolationForest
except Exception as exc:  # pragma: no cover - environment dependent
    IsolationForest = None  # type: ignore[assignment]
    logger.warning("scikit-learn unavailable: %s", exc)


# Feature ordering must stay stable — Isolation Forest is trained on this layout.
FEATURE_NAMES: List[str] = [
    "javascript",
    "openaction",
    "aa",
    "launch",
    "embeddedfile",
    "xfa",
    "acroform",
    "object_count",
    "stream_count",
    "page_count",
    "entropy",
    "vba_project",
    "ole_object",
    "external_rels",
    "embedded_files",
    "openaction_active",
    "embedded_exe",
    "dde",
    "remote_ole",
    "catalog_aa_active",
    "js_nametree",
]

# A bare /OpenAction ("open at page 1, fit width") is extremely common in benign
# PDFs and is NOT a hard block. Only an OpenAction that resolves to an active
# action (JavaScript / Launch / SubmitForm or URI to executable content) is
# recorded as ``openaction_active``.
HARD_BLOCK_FEATURES = {
    "javascript", "openaction_active", "launch", "vba_project", "embedded_exe", "dde", "remote_ole",
}

# Name delimiters: a PDF name ends at whitespace / delimiter, so "/JS" must not
# match "/JSONData", and "/Launch" must not match "/LaunchXYZ".
_NAME_END = r"(?![A-Za-z0-9_.\-#])"
_RE_JS = re.compile(r"/(?:JavaScript|JS)" + _NAME_END)
_RE_LAUNCH = re.compile(r"/Launch" + _NAME_END)
_RE_URI_EXEC = re.compile(
    r"\.(?:exe|scr|bat|cmd|com|pif|msi|js|jse|vbs|vbe|wsf|hta|ps1|jar|lnk|dll|cpl|sh|apk)\b", re.IGNORECASE
)
_RE_DDE_FIELD = re.compile(r'(?:<w:instrText[^>]*>|w:instr=")\s*DDE(?:AUTO)?\b', re.I)
_RE_REL = re.compile(r"<Relationship\b[^>]*>", re.I)
_REMOTE_REL_TYPES = ("/oleobject", "/attachedtemplate", "/frame")
_RE_REF = re.compile(r"(\d+)\s+\d+\s+R")
_RE_JS_NAMETREE = re.compile(r"/JavaScript\s*(?:<<|\d+\s+\d+\s+R)")
_RE_AF_HELPER = re.compile(r"\(AF[A-Z][A-Za-z]*_[A-Za-z]+\\?\(")
_RE_JS_DANGER = re.compile(r"eval\s*\(|unescape|launchURL|exportDataObject|submitForm|getURL|importDataObject|util\.stream|SOAP", re.I)
_EXEC_MAGICS = (b"MZ", b"\x7fELF", b"\xca\xfe\xba\xbe", b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa")


@dataclass(frozen=True)
class StructureFeatures:
    values: Dict[str, float] = field(default_factory=dict)

    def vector(self) -> np.ndarray:
        return np.array(
            [float(self.values.get(name, 0.0)) for name in FEATURE_NAMES],
            dtype=np.float64,
        )

    def non_zero_findings(self) -> List[str]:
        return [
            f"{name}={int(v) if float(v).is_integer() else round(float(v), 3)}"
            for name, v in self.values.items()
            if v
        ]


_isolation_forest: Optional["IsolationForest"] = None


def load_model() -> None:
    """Fit the Isolation Forest on a synthetic benign distribution.

    We don't have a labelled corpus on disk, so we synthesise plausible benign
    feature vectors (no JS, no macros, modest object counts, normal entropy)
    and let the forest learn that "envelope". Real anomalous documents will
    fall outside it.
    """
    global _isolation_forest
    if IsolationForest is None:
        logger.warning("Skipping Isolation Forest fit — sklearn missing")
        return

    rng = np.random.default_rng(seed=42)
    n_pdf, n_office = 768, 768
    idx = FEATURE_NAMES.index
    n_samples = n_pdf + n_office
    benign = np.zeros((n_samples, len(FEATURE_NAMES)))

    def log_int(lo: float, hi: float, n: int) -> np.ndarray:
        return np.floor(np.exp(rng.uniform(np.log(lo), np.log(hi), n)))

    # PDFs: from one-page memos to multi-thousand-page manuals (log-uniform so big
    # legitimate documents are not "anomalous" merely for being big).
    pdf = benign[:n_pdf]
    pdf[:, idx("object_count")] = log_int(3, 200_000, n_pdf)
    pdf[:, idx("page_count")] = np.minimum(log_int(1, 5_000, n_pdf), pdf[:, idx("object_count")])
    pdf[:, idx("stream_count")] = np.floor(pdf[:, idx("object_count")] * rng.uniform(0, 1, n_pdf))
    pdf[:, idx("entropy")] = rng.uniform(4.5, 8.0, n_pdf)
    pdf[:, idx("acroform")] = (rng.random(n_pdf) < 0.15).astype(float)
    pdf[:, idx("openaction")] = (rng.random(n_pdf) < 0.35).astype(float)  # "open at page 1"
    pdf[:, idx("embeddedfile")] = (rng.random(n_pdf) < 0.05).astype(float)

    # Office/OOXML/ODF/zip containers: entropy is ~7.9 (deflate) and there is no page count.
    off = benign[n_pdf:]
    off[:, idx("object_count")] = log_int(3, 20_000, n_office)
    off[:, idx("entropy")] = rng.uniform(5.0, 8.0, n_office)
    off[:, idx("external_rels")] = np.where(rng.random(n_office) < 0.4, log_int(1, 200, n_office), 0)
    off[:, idx("embedded_files")] = np.where(rng.random(n_office) < 0.1, log_int(1, 20, n_office), 0)
    off[:, idx("ole_object")] = np.where(rng.random(n_office) < 0.03, log_int(1, 5, n_office), 0)

    model = IsolationForest(
        n_estimators=200,
        contamination=0.05,
        random_state=42,
    )
    model.fit(benign)
    _isolation_forest = model
    logger.info("Isolation Forest fitted on %d synthetic benign samples", n_samples)


def _is_executable_blob(blob: bytes) -> bool:
    head = blob[:4096]
    if head.startswith(b"MZ"):
        return b"PE\x00\x00" in head or b"This program" in head
    return head.startswith(_EXEC_MAGICS[1:])


def _balanced(text: str) -> str:
    """Return the leading ``<<...>>`` or ``[...]`` group of *text* (or a short prefix)."""
    text = text.lstrip()
    opener = {"<<": ">>", "[": "]"}
    for o, c in opener.items():
        if text.startswith(o):
            depth, i = 0, 0
            while i < len(text) and i < 8192:
                if text.startswith(o, i) and o == "<<":
                    depth += 1
                    i += 2
                    continue
                if text.startswith(c, i) and c == ">>":
                    depth -= 1
                    i += 2
                    if depth == 0:
                        return text[:i]
                    continue
                if o == "[":
                    if text[i] == "[":
                        depth += 1
                    elif text[i] == "]":
                        depth -= 1
                        if depth == 0:
                            return text[: i + 1]
                i += 1
            return text[:8192]
    return text[:64]


def _openaction_is_active(doc, catalog_src: str, depth: int = 0) -> bool:
    """Resolve the catalog /OpenAction and decide whether it runs something."""
    m = re.search(r"/OpenAction" + _NAME_END + r"\s*(.*)", catalog_src, re.DOTALL)
    if not m:
        return False
    rest = m.group(1)
    ref = re.match(r"\s*(\d+)\s+\d+\s+R", rest)
    if ref:
        try:
            body = doc.xref_object(int(ref.group(1)), compressed=False) or ""
        except Exception:
            return False
        return _action_text_is_active(doc, body, depth + 1)
    return _action_text_is_active(doc, _balanced(rest), depth)


def _catalog_aa_is_active(doc, catalog_src: str) -> bool:
    """Document-level additional actions (/AA in the catalog) that run JavaScript.

    Widget-level /AA (form-field keystroke / format / calculate scripts) is NOT
    document auto-run and is deliberately ignored here.
    """
    m = re.search(r"/AA" + _NAME_END + r"\s*(.*)", catalog_src, re.DOTALL)
    if not m:
        return False
    rest = m.group(1)
    ref = re.match(r"\s*(\d+)\s+\d+\s+R", rest)
    if ref:
        try:
            rest = doc.xref_object(int(ref.group(1)), compressed=False) or ""
        except Exception:
            return False
    else:
        rest = _balanced(rest)
    if _action_text_is_active(doc, rest, 0):
        return True
    for r in list(_RE_REF.finditer(rest))[:20]:
        try:
            body = doc.xref_object(int(r.group(1)), compressed=False) or ""
        except Exception:
            continue
        if _action_text_is_active(doc, body, 1):
            return True
    return False


def _action_text_is_active(doc, text: str, depth: int) -> bool:
    if _RE_JS.search(text) or _RE_LAUNCH.search(text):
        return True
    if re.search(r"/S\s*/(?:URI|SubmitForm)" + _NAME_END, text) and _RE_URI_EXEC.search(text):
        return True
    if depth < 4:
        for nxt in re.finditer(r"/Next\s*(\d+)\s+\d+\s+R", text):
            try:
                body = doc.xref_object(int(nxt.group(1)), compressed=False) or ""
            except Exception:
                continue
            if _action_text_is_active(doc, body, depth + 1):
                return True
    return False


def _extract_pdf_features(data: bytes) -> StructureFeatures:
    if fitz is None:
        return StructureFeatures()
    values: Dict[str, float] = {}
    try:
        doc = fitz.open(stream=data, filetype="pdf")
    except Exception as exc:
        logger.warning("PyMuPDF failed to open PDF: %s", exc)
        return StructureFeatures()

    try:
        if doc.needs_pass or doc.is_encrypted:
            # Contents unreadable; fall through with whatever the xref gives us.
            pass
        values["object_count"] = float(doc.xref_length())
        values["page_count"] = float(doc.page_count)

        stream_count = 0
        simple_keys = {
            "/EmbeddedFile": "embeddedfile",
            "/XFA": "xfa",
            "/AcroForm": "acroform",
        }
        name_keys = {
            "javascript": _RE_JS,
            "launch": _RE_LAUNCH,
            "aa": re.compile(r"/AA" + _NAME_END),
            "openaction": re.compile(r"/OpenAction" + _NAME_END),
        }
        catalog_xref = 0
        try:
            catalog_xref = doc.pdf_catalog()
        except Exception:
            pass
        # Walk every indirect object once.
        for xref in range(1, doc.xref_length()):
            try:
                obj_src = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                continue
            if "stream" in obj_src:
                stream_count += 1
            for needle, feat in simple_keys.items():
                if needle in obj_src:
                    values[feat] = values.get(feat, 0.0) + 1.0
            for feat, rx in name_keys.items():
                if feat == "javascript" and rx.search(obj_src):
                    # Acrobat field-formatting helpers are benign form plumbing.
                    if _RE_AF_HELPER.search(obj_src) and not _RE_JS_DANGER.search(obj_src):
                        continue
                if rx.search(obj_src):
                    values[feat] = values.get(feat, 0.0) + 1.0
            if xref == catalog_xref:
                if "/OpenAction" in obj_src and _openaction_is_active(doc, obj_src):
                    values["openaction_active"] = 1.0
                if "/AA" in obj_src and _catalog_aa_is_active(doc, obj_src):
                    values["catalog_aa_active"] = 1.0
            if _RE_JS_NAMETREE.search(obj_src) and not _RE_AF_HELPER.search(obj_src):
                values["js_nametree"] = 1.0  # /Names /JavaScript tree: runs when the file opens
        values["stream_count"] = float(stream_count)

        # Embedded files: decompressed content is what YARA cannot see.
        try:
            names = doc.embfile_names()
        except Exception:
            names = []
        for name in names[:50]:
            try:
                blob = doc.embfile_get(name)
            except Exception:
                continue
            if _is_executable_blob(blob):
                values["embedded_exe"] = values.get("embedded_exe", 0.0) + 1.0
    finally:
        doc.close()

    values["entropy"] = FileSniffer.calculate_entropy(data)
    return StructureFeatures(values=values)


def _extract_office_zip_features(data: bytes) -> StructureFeatures:
    values: Dict[str, float] = {"entropy": FileSniffer.calculate_entropy(data)}
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            names = zf.namelist()
    except zipfile.BadZipFile:
        return StructureFeatures(values=values)

    values["object_count"] = float(len(names))

    vba = sum(1 for n in names if n.endswith("vbaProject.bin"))
    ole = sum(1 for n in names if "oleObject" in n and n.endswith(".bin"))
    embedded = sum(1 for n in names if n.startswith("word/embeddings/"))

    values["vba_project"] = float(vba)
    values["ole_object"] = float(ole)
    values["embedded_files"] = float(embedded)

    # Inspect relationship targets for external links.
    external_rels = 0
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            for rels_name in (n for n in names if n.endswith(".rels")):
                try:
                    rels = zf.read(rels_name).decode("utf-8", errors="ignore")
                except KeyError:
                    continue
                external_rels += rels.lower().count('targetmode="external"')
    except zipfile.BadZipFile:
        pass
    values["external_rels"] = float(external_rels)

    # DDE fields / DDE links and remotely linked OLE objects or templates: no macro
    # needed, but both can fetch or execute content when the document is opened.
    dde = remote = 0
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            for n in names:
                low = n.lower()
                if low.endswith(".rels"):
                    for rel in _RE_REL.findall(zf.read(n)[:2_000_000].decode("utf-8", "ignore")):
                        rl = rel.lower()
                        if 'targetmode="external"' in rl and any(t in rl for t in _REMOTE_REL_TYPES):
                            remote += 1
                elif low.startswith("word/") and low.endswith(".xml") and "/" not in low[5:]:
                    if _RE_DDE_FIELD.search(zf.read(n)[:5_000_000].decode("utf-8", "ignore")):
                        dde += 1
                elif low.startswith("xl/externallinks/") and low.endswith(".xml"):
                    if b"<ddeLink" in zf.read(n)[:2_000_000]:
                        dde += 1
    except (zipfile.BadZipFile, KeyError, RuntimeError):
        pass
    values["dde"] = float(dde)
    values["remote_ole"] = float(remote)
    return StructureFeatures(values=values)


def extract_features(data: bytes) -> StructureFeatures:
    """Dispatch to the right extractor based on file magic."""
    file_type = FileSniffer.get_true_file_type(data)
    if b"%PDF" in data[:1024]:  # readers accept the header anywhere in the first 1 KiB
        return _extract_pdf_features(data)
    if file_type == "document" and data.startswith(b"PK\x03\x04"):
        return _extract_office_zip_features(data)
    # Unknown / non-document binary — only entropy is meaningful.
    return StructureFeatures(values={"entropy": FileSniffer.calculate_entropy(data)})


def _isolation_score(features: StructureFeatures) -> float:
    if _isolation_forest is None:
        return 0.0
    try:
        raw = float(_isolation_forest.decision_function(features.vector().reshape(1, -1))[0])
    except Exception as exc:
        logger.warning("Isolation Forest scoring failed: %s", exc)
        return 0.0
    # decision_function: higher = more normal, ~[-0.3, 0.3]. Only treat clearly
    # negative scores as anomalous so borderline-benign vectors stay near zero.
    # Capped well below the block threshold: statistical oddness alone must never
    # block a document, it only contributes to the weighted score.
    return max(0.0, min(0.6, -raw * 5.0))


def analyze(data: bytes) -> AnalysisResult:
    try:
        features = extract_features(data)
        anomaly = _isolation_score(features)
        score = anomaly
        findings: List[str] = []

        non_zero = features.non_zero_findings()
        if non_zero:
            findings.append("Structural features: " + ", ".join(non_zero))

        # Hard rules. Active content that runs without user interaction is a
        # block-level signal (>0.8); passive indicators only raise the soft score.
        v = features.values
        triggered = [name for name in HARD_BLOCK_FEATURES if v.get(name)]
        if triggered:
            has_trigger = bool(
                v.get("openaction") or v.get("catalog_aa_active") or v.get("openaction_active") or v.get("js_nametree")
            )
            auto_run = (
                v.get("openaction_active") or v.get("launch") or v.get("embedded_exe")
                or v.get("vba_project") or v.get("dde") or v.get("remote_ole") or (v.get("javascript") and has_trigger)
            )
            score = max(score, 0.85 if auto_run else 0.7)
            findings.append(
                "Hard-rule structure trigger: " + ", ".join(sorted(triggered))
            )

        return AnalysisResult(
            module="structure",
            score=float(score),
            findings=findings,
            raw_data={"features": features.values, "anomaly": anomaly},
        )
    except Exception as exc:
        logger.exception("structure model failed: %s", exc)
        return AnalysisResult(
            module="structure",
            score=0.0,
            findings=[f"structure error: {exc}"],
        )
