"""Data-exfiltration lure detector.

The canonical RAG-exfil trick: plant a markdown image whose URL template gets
filled with conversation data when the client auto-renders it, silently beaconing
secrets to an attacker host. We flag:

* Markdown/HTML image beacons pointing at an external host, especially with query
  parameters or obvious ``{placeholder}`` / ``$var`` templating (ISW030).
* URLs that carry base64-ish blobs or data-exfil query keys (ISW031).
"""

from __future__ import annotations

import re

from ..models import ExtractedDocument, Finding
from ._common import make_finding

_HTML_IMG = re.compile(r"<img\b[^>]*\bsrc\s*=\s*[\"']([^\"']+)[\"']", re.I)
_TEMPLATE = re.compile(r"(\{[^}]+\}|\$\{?[a-zA-Z_]\w*\}?|%[0-9a-fA-F]{2})")
_B64_IN_URL = re.compile(r"[?/=]([A-Za-z0-9+/]{24,}={0,2})(?:[&#/]|$)")
_EXFIL_KEYS = re.compile(r"[?&](?:data|q|prompt|secret|token|leak|c|payload)=", re.I)
_URL = re.compile(r"https?://[^\s\"'<>)]+", re.I)


def _external(url: str) -> bool:
    return url.lower().startswith(("http://", "https://"))


def _check_image_url(url: str, seg, raw: str, findings: list[Finding]) -> None:
    if not _external(url):
        return
    has_query = "?" in url
    templated = bool(_TEMPLATE.search(url))
    if has_query or templated:
        why = []
        if templated:
            why.append("contains a templated placeholder that could be filled with chat data")
        if has_query:
            why.append("carries query parameters usable as an exfil channel")
        findings.append(make_finding(
            "ISW030", seg,
            f"Image beacon to external host {url!r} " + " and ".join(why) + ".",
            evidence=raw or url,
            detector="exfil",
        ))


def detect(document: ExtractedDocument) -> list[Finding]:
    findings: list[Finding] = []
    for seg in document.segments:
        # Markdown images surfaced by the markdown extractor.
        if seg.layer == "md_image":
            _check_image_url(seg.text, seg, seg.meta.get("raw", ""), findings)
            continue

        # HTML <img> tags anywhere in a text/raw segment.
        for m in _HTML_IMG.finditer(seg.text):
            _check_image_url(m.group(1), seg, m.group(0), findings)

        # Suspicious URLs (base64 blobs / exfil query keys) in any segment.
        for m in _URL.finditer(seg.text):
            url = m.group(0)
            if _B64_IN_URL.search(url) or _EXFIL_KEYS.search(url):
                reason = ("embeds a base64-like blob" if _B64_IN_URL.search(url)
                          else "uses data-exfil query parameters")
                findings.append(make_finding(
                    "ISW031", seg,
                    f"Suspicious URL {url!r} {reason}.",
                    evidence=url,
                    detector="exfil",
                ))
    return findings
