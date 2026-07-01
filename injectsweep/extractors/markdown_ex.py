"""Markdown extractor.

Markdown is treated as text, but two markdown-specific layers are surfaced:

* HTML comments embedded in markdown (``<!-- ... -->``) -- a hidden layer, since
  rendered markdown never shows them but a RAG chunker keeps them.
* Image/link targets -- surfaced with an ``md_link`` layer so the exfil detector
  can inspect beacon URLs.

Fenced code blocks are still scanned (payloads love to hide as "example" code),
but tagged so reporting stays honest about provenance.
"""

from __future__ import annotations

import re

from ..models import ExtractedDocument

_HTML_COMMENT = re.compile(r"<!--(.*?)-->", re.DOTALL)
_IMAGE = re.compile(r"!\[(?P<alt>[^\]]*)\]\((?P<url>[^)\s]+)(?:\s+\"[^\"]*\")?\)")
_LINK = re.compile(r"(?<!\!)\[(?P<text>[^\]]+)\]\((?P<url>[^)\s]+)(?:\s+\"[^\"]*\")?\)")


def _decode(data: bytes) -> str:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("utf-8", errors="replace")


def extract(path: str, data: bytes) -> ExtractedDocument:
    doc = ExtractedDocument(path=path, format="markdown")
    text = _decode(data)
    doc.raw_text = text

    # Hidden layer: HTML comments inside markdown.
    for m in _HTML_COMMENT.finditer(text):
        body = m.group(1).strip()
        if body:
            line = text.count("\n", 0, m.start()) + 1
            doc.add("html_comment", body, location=f"line {line}")

    # Strip comments before line extraction so we don't double count them.
    stripped = _HTML_COMMENT.sub("", text)
    for i, line in enumerate(stripped.splitlines(), start=1):
        if line.strip() == "":
            continue
        doc.add("visible", line, location=f"line {i}")

    # Surface image/link targets for the exfil detector.
    for m in _IMAGE.finditer(text):
        doc.add(
            "md_image",
            m.group("url"),
            location="image",
            alt=m.group("alt"),
            raw=m.group(0),
        )
    for m in _LINK.finditer(text):
        doc.add(
            "md_link",
            m.group("url"),
            location="link",
            anchor=m.group("text"),
            raw=m.group(0),
        )
    return doc
