"""PDF extractor.

Uses pypdf to pull three real layers out of a PDF:

* ``visible``        -- the page content-stream text (what most viewers show).
* ``pdf_annotation`` -- text hidden in annotation ``/Contents`` (comments, free
                        text, link tooltips). Humans rarely open every
                        annotation; an LLM ingests them all.
* ``metadata``       -- document info dictionary (Title/Author/Subject/Keywords),
                        a classic smuggling spot.

Note on "white text": PDF text colour lives in the content stream operators and
is not reliably recoverable per-glyph with pypdf. injectsweep's philosophy is
that *any* extractable-but-human-invisible instruction is the threat -- so we
extract the full text and let the imperative/unicode detectors catch the payload
regardless of how it was visually hidden.
"""

from __future__ import annotations

import io

from pypdf import PdfReader
from pypdf.generic import IndirectObject

from ..models import ExtractedDocument


def extract(path: str, data: bytes) -> ExtractedDocument:
    doc = ExtractedDocument(path=path, format="pdf")
    try:
        reader = PdfReader(io.BytesIO(data))
    except Exception as exc:  # pragma: no cover - corrupt file guard
        doc.errors.append(f"pdf parse error: {exc}")
        return doc

    # Document metadata.
    try:
        meta = reader.metadata or {}
        for key in ("/Title", "/Author", "/Subject", "/Keywords", "/Producer"):
            val = meta.get(key)
            if val:
                doc.add("metadata", str(val), location=f"info{key}")
    except Exception as exc:  # pragma: no cover
        doc.errors.append(f"pdf metadata error: {exc}")

    text_parts: list[str] = []
    for page_no, page in enumerate(reader.pages, start=1):
        try:
            page_text = page.extract_text() or ""
        except Exception as exc:  # pragma: no cover
            doc.errors.append(f"page {page_no} extract error: {exc}")
            page_text = ""
        if page_text.strip():
            text_parts.append(page_text)
            for line in page_text.splitlines():
                if line.strip():
                    doc.add("visible", line, location=f"page {page_no}")

        # Annotations.
        annots = page.get("/Annots")
        if annots:
            try:
                items = annots.get_object() if isinstance(annots, IndirectObject) else annots
                for annot in items:
                    obj = annot.get_object()
                    contents = obj.get("/Contents")
                    if contents:
                        doc.add(
                            "pdf_annotation",
                            str(contents),
                            location=f"page {page_no} annotation",
                            subtype=str(obj.get("/Subtype", "")),
                        )
            except Exception as exc:  # pragma: no cover
                doc.errors.append(f"page {page_no} annotation error: {exc}")

    doc.raw_text = "\n".join(text_parts)
    return doc
