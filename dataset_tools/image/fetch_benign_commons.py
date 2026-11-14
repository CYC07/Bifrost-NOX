"""Fetch a small public-domain / CC0 benign image set from Wikimedia Commons.

Only files whose extmetadata LicenseShortName is 'Public domain' or 'CC0' are
kept. Images are written (never opened/executed here) to --out together with
SOURCE.txt recording URL, sha256 and licence per file.

  python -m dataset_tools.image.fetch_benign_commons --out ~/FYP/corpora/image_benign --n 320
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import time
import urllib.parse
import urllib.request

API = "https://commons.wikimedia.org/w/api.php"
UA = "bifrost-eval/0.1 (research; benign image false-positive measurement)"
CATEGORIES = [
    "Category:Featured pictures on Wikimedia Commons", "Category:Quality images", "Category:Pictures of the day (photographs)",
    "Category:Screenshots of Linux", "Category:Screenshots of Windows", "Category:Screenshots of websites",
    "Category:Public domain photographs", "Category:CC-Zero",
    "Category:Images from the NASA", "Category:Maps", "Category:Diagrams", "Category:Charts",
]
OK_LICENSES = {"public domain", "cc0", "cc-zero", "cc0 1.0"}


def _get(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.read()


def _api(**params) -> dict:
    params.update(format="json")
    return json.loads(_get(API + "?" + urllib.parse.urlencode(params)))


def candidates(category: str, limit: int = 120):
    cont = {}
    got = 0
    while got < limit:
        data = _api(action="query", generator="categorymembers", gcmtitle=category, gcmtype="file", gcmlimit=50,
                    prop="imageinfo", iiprop="url|extmetadata|mime|size", iiurlwidth=640, **cont)
        for page in (data.get("query", {}).get("pages", {})).values():
            info = (page.get("imageinfo") or [{}])[0]
            lic = (info.get("extmetadata", {}).get("LicenseShortName", {}).get("value") or "").strip().lower()
            if lic in OK_LICENSES and info.get("mime") in ("image/jpeg", "image/png"):
                yield page["title"], info.get("thumburl") or info["url"], info["descriptionurl"], lic
            got += 1
        if "continue" not in data:
            break
        cont = data["continue"]
        time.sleep(0.5)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=os.path.expanduser("~/FYP/corpora/image_benign"))
    ap.add_argument("--n", type=int, default=320)
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    seen, rows = set(), []
    for cat in CATEGORIES:
        if len(rows) >= a.n:
            break
        try:
            for title, url, page, lic in candidates(cat):
                if title in seen or len(rows) >= a.n:
                    continue
                seen.add(title)
                try:
                    blob = _get(url)
                except Exception:
                    continue
                digest = hashlib.sha256(blob).hexdigest()
                ext = ".png" if url.lower().endswith(".png") else ".jpg"
                with open(os.path.join(a.out, digest[:16] + ext), "wb") as fh:
                    fh.write(blob)
                rows.append(f"{digest}  {digest[:16]}{ext}  {lic}  {page}  {url}")
                time.sleep(0.2)
        except Exception as e:  # noqa: BLE001 - keep going with other categories
            print("category failed", cat, e)
    with open(os.path.join(a.out, "SOURCE.txt"), "w") as fh:
        fh.write("Wikimedia Commons, images whose LicenseShortName is Public domain or CC0 (checked via API extmetadata).\n"
                 "Format: sha256  file  licence  description page  download url (640px thumbnail)\n")
        fh.write("\n".join(rows) + "\n")
    print(f"downloaded {len(rows)} images to {a.out}")


if __name__ == "__main__":
    main()
