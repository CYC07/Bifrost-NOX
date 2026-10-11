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
import os

import torch

from common.schemas import AnalysisResult, RiskLevel
from ml.image import clip_labels, preprocess

logger = logging.getLogger("image_service")

# Multi-crop max-pooling raises every group score monotonically, so it would
# invalidate the single-view cutoffs in clip_labels.GROUP_CUTOFF. Kept OFF until
# recalibrated against a real labelled image set.
MULTICROP = os.getenv("IMAGE_CLIP_MULTICROP", "").lower() in ("1", "true", "yes")


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

    def _group_scores(self, probs):
        """Per-group score = max softmax prob among that group's labels, plus
        the winning label per group. Raw cosine similarities do NOT calibrate
        across groups for CLIP ViT-B/32 (they cluster in 0.20-0.30 regardless);
        the discriminative signal lives in the softmax's relative ranking, so
        the per-group MAX of the softmax distribution is the calibratable
        quantity — and unlike a single argmax it lets several groups fire at
        once (an image can be an ID card AND explicit AND a logo)."""
        best = {"pii_nsfw": (0.0, None), "sensitive": (0.0, None), "benign": (0.0, None)}
        for label, pr in zip(self.labels, probs):
            g = clip_labels.LABEL_GROUP[label]
            if float(pr) > best[g][0]:
                best[g] = (float(pr), label)
        return best

    def _best_over_views(self, image):
        """Per-group best (score, label) over one or several crops (max-pool).
        Single whole-image view unless IMAGE_CLIP_MULTICROP is enabled."""
        views = preprocess.crops(image) if MULTICROP else [image]
        merged = {"pii_nsfw": (0.0, None), "sensitive": (0.0, None), "benign": (0.0, None)}
        for view in views:
            probs = self._image_logits(view).softmax(dim=-1).detach().numpy()
            best = self._group_scores(probs)
            for g, (s, lbl) in best.items():
                if s > merged[g][0]:
                    merged[g] = (s, lbl)
        return merged

    def classify(self, image) -> AnalysisResult:
        if self.model is None or self.processor is None:
            return AnalysisResult(module="semantic_clip", score=0.0, findings=["Model not loaded"])
        try:
            best = self._best_over_views(image)
            group_scores = {g: round(v[0], 4) for g, v in best.items()}

            findings = []
            groups_fired = []
            blocked = False
            risk = RiskLevel.SAFE
            score = 0.0

            pii_score, pii_label = best["pii_nsfw"]
            sens_score, sens_label = best["sensitive"]

            # Identity/NSFW visuals block on their own (multi-label: evaluated
            # independently, not gated by being the single argmax winner).
            if pii_score > clip_labels.GROUP_CUTOFF["pii_nsfw"]:
                groups_fired.append("pii_nsfw")
                blocked = True
                risk = RiskLevel.CRITICAL
                score = max(score, float(pii_score))
                findings.append(f"CRITICAL: PII/NSFW visual '{pii_label}' ({pii_score:.2f}, strict block)")

            # Sensitive/DLP visuals are advisory alone; aggregation escalates
            # them to a block when OCR also flags sensitive text.
            if sens_score > clip_labels.GROUP_CUTOFF["sensitive"]:
                groups_fired.append("sensitive")
                if risk == RiskLevel.SAFE:
                    risk = RiskLevel.MEDIUM
                score = max(score, 0.5)
                findings.append(f"WARNING: sensitive visual '{sens_label}' ({sens_score:.2f}, advisory)")

            if not findings:
                top_g = max(best, key=lambda g: best[g][0])
                findings.append(f"Classified as: {best[top_g][1]} ({best[top_g][0]:.2f})")

            logger.info(f"CLIP groups={group_scores} fired={groups_fired}")
            return AnalysisResult(
                module="semantic_clip",
                score=score,
                findings=findings,
                raw_data={"group_scores": group_scores, "groups_fired": groups_fired},
                blocked=blocked,
                risk=risk,
            )
        except Exception as e:
            logger.error(f"CLIP Error: {e}")
            return AnalysisResult(module="semantic_clip", score=0.0, findings=[f"CLIP Error: {str(e)}"])
