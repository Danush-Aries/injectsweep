"""CSV extractor.

Every cell becomes its own segment. RAG pipelines routinely flatten CSV rows
into text chunks, so a single poisoned cell (e.g. a customer "note" field with a
zero-width-tag-smuggled instruction) is a real ingestion threat.
"""

from __future__ import annotations

import csv
import io

from ..models import ExtractedDocument


def _decode(data: bytes) -> str:
    for enc in ("utf-8-sig", "utf-8", "latin-1"):
        try:
            return data.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return data.decode("utf-8", errors="replace")


def extract(path: str, data: bytes) -> ExtractedDocument:
    doc = ExtractedDocument(path=path, format="csv")
    text = _decode(data)
    doc.raw_text = text

    reader = csv.reader(io.StringIO(text))
    header: list[str] = []
    for row_idx, row in enumerate(reader):
        if row_idx == 0:
            header = row
        for col_idx, cell in enumerate(row):
            if cell.strip() == "":
                continue
            col_name = header[col_idx] if row_idx > 0 and col_idx < len(header) else f"col{col_idx}"
            loc = f"row {row_idx + 1}, {col_name!r}"
            doc.add("csv_cell", cell, location=loc)
    return doc
