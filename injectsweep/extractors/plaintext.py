"""Plain text extractor.

Plain text has no hidden layers, but it can still smuggle instructions via
invisible unicode, encoding or homoglyphs -- so every line becomes a visible
segment for the detectors to inspect byte-for-byte.
"""

from __future__ import annotations

from ..models import ExtractedDocument


def _decode(data: bytes) -> str:
    for enc in ("utf-8", "utf-16", "latin-1"):
        try:
            return data.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return data.decode("utf-8", errors="replace")


def extract(path: str, data: bytes) -> ExtractedDocument:
    doc = ExtractedDocument(path=path, format="text")
    text = _decode(data)
    doc.raw_text = text
    for i, line in enumerate(text.splitlines(), start=1):
        if line.strip() == "":
            continue
        doc.add("visible", line, location=f"line {i}")
    return doc
