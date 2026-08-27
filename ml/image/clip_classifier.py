"""CLIP zero-shot classifier with cached label embeddings.

The original code re-encoded all ~43 label strings through the CLIP text
encoder on every request. This precomputes them once at construction and reuses
them, runs under torch.inference_mode(), and keeps the decision logic isolated
from the Starlette handler.

Task 3 (this file's first form) preserves the original argmax decision exactly:
  - argmax label over softmax; pii_nsfw label >0.4  -> BLOCK critical
  - sensitive label >0.6                             -> advisory MEDIUM (the
    OCR cross-check that could escalate it to a block moves to aggregation)
  - otherwise                                        -> allow
Task 4 replaces the argmax/softmax path with multi-label sigmoid.
"""
import logging

import torch

from common.schemas import AnalysisResult, RiskLevel
from ml.image import clip_labels

logger = logging.getLogger("image_service")


class ClipClassifier:
    def __init__(self, model, processor):
        self.model = model
        self.processor = processor
        self.labels = list(clip_labels.SEMANTIC_LABELS)
        self.text_embeds = self._encode_labels()

    def _encode_labels(self):
        """Encode + L2-normalize the label texts once; cache for reuse."""
        with torch.inference_mode():
            inputs = self.processor(
                text=self.labels, return_tensors="pt", padding=True
            )
            feats = self.model.get_text_features(**inputs)
            feats = feats / feats.norm(p=2, dim=-1, keepdim=True)
        return feats

    def _image_logits(self, image):
        """Cosine similarities (scaled by CLIP's logit_scale) image vs cached
        label embeddings — same quantity as logits_per_image, without
        re-encoding the labels."""
        with torch.inference_mode():
            inputs = self.processor(images=image, return_tensors="pt")
            img_feats = self.model.get_image_features(**inputs)
            img_feats = img_feats / img_feats.norm(p=2, dim=-1, keepdim=True)
            logit_scale = self.model.logit_scale.exp()
            logits = logit_scale * img_feats @ self.text_embeds.t()
        return logits[0]

    def classify(self, image) -> AnalysisResult:
        if self.model is None or self.processor is None:
            return AnalysisResult(module="semantic_clip", score=0.0, findings=["Model not loaded"])
        try:
            logits = self._image_logits(image)
            probs = logits.softmax(dim=-1).detach().numpy()
            best_idx = int(probs.argmax())
            best_label = self.labels[best_idx]
            best_score = float(probs[best_idx])
            group = clip_labels.LABEL_GROUP[best_label]
            findings = [f"Classified as: {best_label} ({best_score:.2f})"]
            logger.info(f"CLIP: {best_label} score={best_score} group={group}")

            blocked = False
            risk = RiskLevel.SAFE
            score = 0.0
            if group == "pii_nsfw" and best_score > clip_labels.GROUP_CUTOFF["pii_nsfw"]:
                blocked = True
                risk = RiskLevel.CRITICAL
                score = 0.95
                findings.append(f"CRITICAL: PII/NSFW visual '{best_label}' (strict block)")
            elif group == "sensitive" and best_score > clip_labels.GROUP_CUTOFF["sensitive"]:
                # Advisory only — aggregation decides whether the OCR text signal
                # escalates this to a block.
                risk = RiskLevel.MEDIUM
                score = 0.5
                findings.append(f"WARNING: sensitive visual '{best_label}' (advisory)")

            return AnalysisResult(
                module="semantic_clip",
                score=score,
                findings=findings,
                raw_data={"top_label": best_label, "confidence": best_score, "group": group},
                blocked=blocked,
                risk=risk,
            )
        except Exception as e:
            logger.error(f"CLIP Error: {e}")
            return AnalysisResult(module="semantic_clip", score=0.0, findings=[f"CLIP Error: {str(e)}"])
