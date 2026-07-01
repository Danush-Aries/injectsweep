"""DOCX extractor.

Reads a real .docx (a zip of XML parts) with python-docx and surfaces:

* ``visible``   -- normal paragraph runs.
* ``hidden_css``-- runs marked with the ``<w:vanish/>`` (hidden text) property,
                   or coloured white. Word's "Hidden" font effect removes text
                   from the rendered page but keeps it in the file.
* ``metadata``  -- core properties (author, title, subject, comments, keywords).
"""

from __future__ import annotations

import io

import docx
from docx.oxml.ns import qn

from ..models import ExtractedDocument


def _run_is_hidden(run) -> bool:
    rpr = run._element.rPr
    if rpr is None:
        return False
    # w:vanish -> Word "Hidden" text effect.
    if rpr.find(qn("w:vanish")) is not None:
        return True
    # White font colour on the (assumed white) page.
    color = rpr.find(qn("w:color"))
    if color is not None:
        val = color.get(qn("w:val"))
        if val and val.lower() in {"ffffff", "fefefe"}:
            return True
    return False


def extract(path: str, data: bytes) -> ExtractedDocument:
    doc = ExtractedDocument(path=path, format="docx")
    try:
        document = docx.Document(io.BytesIO(data))
    except Exception as exc:  # pragma: no cover
        doc.errors.append(f"docx parse error: {exc}")
        return doc

    # Core properties / metadata.
    try:
        cp = document.core_properties
        for name in ("author", "title", "subject", "comments", "keywords", "category"):
            val = getattr(cp, name, None)
            if val:
                doc.add("metadata", str(val), location=f"core.{name}")
    except Exception as exc:  # pragma: no cover
        doc.errors.append(f"docx metadata error: {exc}")

    parts: list[str] = []
    for p_idx, para in enumerate(document.paragraphs, start=1):
        for run in para.runs:
            text = run.text
            if not text or not text.strip():
                continue
            parts.append(text)
            if _run_is_hidden(run):
                doc.add("hidden_css", text, location=f"paragraph {p_idx}", reason="docx_hidden_run")
            else:
                doc.add("visible", text, location=f"paragraph {p_idx}")

    # Tables (cells are common ingestion fodder too).
    for t_idx, table in enumerate(document.tables, start=1):
        for row in table.rows:
            for cell in row.cells:
                txt = cell.text.strip()
                if txt:
                    parts.append(txt)
                    doc.add("visible", txt, location=f"table {t_idx}")

    doc.raw_text = "\n".join(parts)
    return doc
