"""CLIP compatibility with transformers 5.

transformers>=5 returns a `BaseModelOutputWithPooling` from `get_text_features` /
`get_image_features` instead of a tensor, so `ClipClassifier(...)` raised inside
`image_service.main.load_models` (the exception is swallowed) and the classifier stayed None.

The fix must not change behaviour. Shape alone cannot prove the right field was taken (the text
hidden size is also 512 for ViT-B/32), so these tests compare against CLIP's own forward pass:
the cached-embedding logits must equal `model(...).logits_per_image`.
"""
import io
import os
import sys

import pytest
import torch
from PIL import Image

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from ml.image import clip_classifier as cc  # noqa: E402
from dataset_tools.image import synth_cases  # noqa: E402

CLIP_ID = os.getenv("CLIP_MODEL_ID", "openai/clip-vit-base-patch32")


@pytest.fixture(scope="module")
def clip():
    from transformers import CLIPModel, CLIPProcessor
    model = CLIPModel.from_pretrained(CLIP_ID).eval()
    return model, CLIPProcessor.from_pretrained(CLIP_ID)


@pytest.fixture(scope="module")
def image():
    return Image.open(io.BytesIO(synth_cases.SYNTH_CASES["benign_gradient"])).convert("RGB")


def test_feature_helpers_return_projected_embeddings(clip, image):
    model, proc = clip
    dim = model.config.projection_dim
    with torch.inference_mode():
        t = cc.text_features(model, proc(text=["a cat", "a dog"], return_tensors="pt", padding=True))
        i = cc.image_features(model, proc(images=image, return_tensors="pt"))
    assert isinstance(t, torch.Tensor) and t.shape == (2, dim)
    assert isinstance(i, torch.Tensor) and i.shape == (1, dim)


def test_helpers_match_clips_own_projection(clip, image):
    """Independent of the helper: project the pooled outputs by hand and compare."""
    model, proc = clip
    with torch.inference_mode():
        enc = proc(text=["a photo of a cat"], return_tensors="pt", padding=True)
        pooled = model.text_model(**enc).pooler_output
        expected = model.text_projection(pooled)
        got = cc.text_features(model, enc)
        vin = proc(images=image, return_tensors="pt")
        vexp = model.visual_projection(model.vision_model(**vin).pooler_output)
        vgot = cc.image_features(model, vin)
    assert torch.allclose(got, expected, atol=1e-5)
    assert torch.allclose(vgot, vexp, atol=1e-5)


def test_classifier_constructs_and_caches_unit_norm_embeddings(clip):
    model, proc = clip
    clf = cc.ClipClassifier(model, proc)
    assert clf.text_embeds is not None
    assert clf.text_embeds.shape == (len(clf.labels), model.config.projection_dim)
    assert torch.allclose(clf.text_embeds.norm(dim=-1), torch.ones(len(clf.labels)), atol=1e-4)


def test_cached_logits_equal_clips_own_logits_per_image(clip, image):
    model, proc = clip
    clf = cc.ClipClassifier(model, proc)
    with torch.inference_mode():
        enc = proc(text=clf.labels, images=image, return_tensors="pt", padding=True)
        reference = model(**enc).logits_per_image[0]
    ours = clf._image_logits(image)
    assert ours.shape == reference.shape
    assert torch.allclose(ours, reference, atol=1e-3, rtol=1e-3), (ours[:4], reference[:4])
