#!/usr/bin/env python3
"""Refresh config/microsoft_ip_ranges.json from Microsoft's published data.

Sources (public, no auth):
  * Azure IP Ranges and Service Tags (weekly JSON; the file URL is scraped from the download page)
  * Microsoft 365 endpoints web service (IPs of first-party Office/Windows services)

Included: the AzureCloud tag (covers Windows Update / WNS / telemetry front ends, ~80 % of the
Microsoft destinations seen in the lab) plus first-party tags. NOTE: Azure address space can be
rented by anyone, so this raises the bar for spoofing a trusted name from "set a header" to
"run a VM in Azure"; it is not a proof of Microsoft ownership. CDN-fronted hosts (Akamai,
Cloudflare) are not covered and fall back to normal inspection.

Usage: python scripts/update_microsoft_ranges.py [--out PATH]
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import sys
import time
import urllib.request
import uuid

DOWNLOAD_PAGE = "https://www.microsoft.com/en-us/download/details.aspx?id=56519"
O365_URL = "https://endpoints.office.com/endpoints/worldwide?clientrequestid={}"
TAGS = ("AzureCloud", "AzureActiveDirectory", "AzureUpdateDelivery", "AzureDeviceUpdate",
        "MicrosoftDefenderForEndpoint", "MicrosoftCloudAppSecurity", "AzureFrontDoor.FirstParty",
        "AzureFrontDoor.Frontend", "AzureTrafficManager", "Windows365", "WindowsVirtualDesktop")
DEFAULT_OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "config", "microsoft_ip_ranges.json")


def build(tags_doc: dict, o365_doc: list, min_ranges: int = 1) -> dict:
    found: set[str] = set()

    def add(prefixes):
        for p in prefixes or []:
            try:
                net = ipaddress.ip_network(str(p).strip(), strict=False)
            except ValueError:
                continue
            if net.prefixlen > 0:
                found.add(str(net))

    for v in tags_doc.get("values", []):
        if v.get("name") in TAGS:
            add(v.get("properties", {}).get("addressPrefixes"))
    for entry in o365_doc or []:
        add(entry.get("ips"))
    if len(found) < min_ranges:
        raise ValueError(f"only {len(found)} ranges found (< {min_ranges}); refusing to publish")
    return {
        "generated": time.strftime("%Y-%m-%d", time.gmtime()),
        "changeNumber": tags_doc.get("changeNumber"),
        "source": "Microsoft Azure IP Ranges and Service Tags + Microsoft 365 endpoints",
        "ranges": sorted(found, key=lambda r: (":" in r, ipaddress.ip_network(r).network_address)),
    }


def _get(url: str, timeout: int = 120) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (ranges-updater)"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=DEFAULT_OUT)
    out_path = os.path.abspath(ap.parse_args(argv).out)
    page = _get(DOWNLOAD_PAGE).decode("utf-8", "ignore")
    m = re.search(r"https://download\.microsoft\.com/download/[^\"']+ServiceTags_Public_\d+\.json", page)
    if not m:
        print("could not find the ServiceTags download link", file=sys.stderr)
        return 1
    tags = json.loads(_get(m.group(0)))
    o365 = json.loads(_get(O365_URL.format(uuid.uuid4())))
    doc = build(tags, o365, min_ranges=500)       # a real run yields thousands
    tmp = out_path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(doc, f, indent=0)
    os.replace(tmp, out_path)
    print(f"wrote {len(doc['ranges'])} ranges (changeNumber {doc['changeNumber']}) to {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
