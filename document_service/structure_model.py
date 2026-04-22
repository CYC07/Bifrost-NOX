"""Structural anomaly detection for documents.

Extracts structural features from PDF and Office-ZIP files and scores them with
an Isolation Forest fitted on a small synthetic distribution of benign feature
vectors. Hard-rule overrides ensure known macro/JS carriers are never soft-passed.
"""

from __future__ import annotations

import io
import logging
import os
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
]

HARD_BLOCK_FEATURES = {"javascript", "openaction", "vba_project"}


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
    n_samples = 1024
    benign = np.zeros((n_samples, len(FEATURE_NAMES)))
    # object_count: cover both tiny single-page docs and large reports.
    benign[:, FEATURE_NAMES.index("object_count")] = rng.integers(3, 400, n_samples)
    # stream_count: zero is normal for tiny PDFs, larger for image-heavy docs.
    benign[:, FEATURE_NAMES.index("stream_count")] = rng.integers(0, 80, n_samples)
    # page_count
    benign[:, FEATURE_NAMES.index("page_count")] = rng.integers(1, 60, n_samples)
    # entropy: real benign documents range widely (4.5 text-only → 7.6 image-heavy).
    benign[:, FEATURE_NAMES.index("entropy")] = rng.uniform(4.5, 7.6, n_samples)
    # acroform: occasional benign forms
    benign[:, FEATURE_NAMES.index("acroform")] = (rng.random(n_samples) < 0.15).astype(
        float
    )

    model = IsolationForest(
        n_estimators=200,
        contamination=0.05,
        random_state=42,
    )
    model.fit(benign)
    _isolation_forest = model
    logger.info("Isolation Forest fitted on %d synthetic benign samples", n_samples)


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
        values["object_count"] = float(doc.xref_length())
        values["page_count"] = float(doc.page_count)

        stream_count = 0
        suspicious_keys = {
            "/JavaScript": "javascript",
            "/JS": "javascript",
            "/OpenAction": "openaction",
            "/AA": "aa",
            "/Launch": "launch",
            "/EmbeddedFile": "embeddedfile",
            "/XFA": "xfa",
            "/AcroForm": "acroform",
        }
        # Walk every indirect object once.
        for xref in range(1, doc.xref_length()):
            try:
                obj_src = doc.xref_object(xref, compressed=False) or ""
            except Exception:
                continue
            if "stream" in obj_src:
                stream_count += 1
            for needle, feat in suspicious_keys.items():
                if needle in obj_src:
                    values[feat] = values.get(feat, 0.0) + 1.0
        values["stream_count"] = float(stream_count)
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
    return StructureFeatures(values=values)


def extract_features(data: bytes) -> StructureFeatures:
    """Dispatch to the right extractor based on file magic."""
    file_type = FileSniffer.get_true_file_type(data)
    if data.startswith(b"%PDF"):
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
    anomaly = max(0.0, min(1.0, -raw * 5.0))
    return anomaly


def analyze(data: bytes) -> AnalysisResult:
    try:
        features = extract_features(data)
        anomaly = _isolation_score(features)
        score = anomaly
        findings: List[str] = []

        non_zero = features.non_zero_findings()
        if non_zero:
            findings.append("Structural features: " + ", ".join(non_zero))

        # Hard-rule override: known dangerous keys / macro carrier.
        triggered = [name for name in HARD_BLOCK_FEATURES if features.values.get(name)]
        if triggered:
            score = max(score, 0.7)
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
