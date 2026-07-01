"""Format extractors.

Each extractor performs *real* parsing of *real* file bytes and returns an
:class:`~injectsweep.models.ExtractedDocument` whose segments are tagged with a
provenance layer (visible vs. hidden). Detectors then run over those segments.
"""

from __future__ import annotations

import os
from typing import Callable

from ..models import ExtractedDocument
from . import csv_ex, docx_ex, html_ex, markdown_ex, pdf_ex, plaintext

# Map file extension -> extractor callable(path, data) -> ExtractedDocument
_BY_EXT: dict[str, Callable[[str, bytes], ExtractedDocument]] = {
    ".pdf": pdf_ex.extract,
    ".html": html_ex.extract,
    ".htm": html_ex.extract,
    ".xhtml": html_ex.extract,
    ".docx": docx_ex.extract,
    ".md": markdown_ex.extract,
    ".markdown": markdown_ex.extract,
    ".csv": csv_ex.extract,
    ".txt": plaintext.extract,
    ".text": plaintext.extract,
    ".log": plaintext.extract,
}

SUPPORTED_EXTENSIONS = frozenset(_BY_EXT)


def extractor_for(path: str) -> Callable[[str, bytes], ExtractedDocument] | None:
    ext = os.path.splitext(path)[1].lower()
    return _BY_EXT.get(ext)


def is_supported(path: str) -> bool:
    return extractor_for(path) is not None


def extract(path: str, data: bytes | None = None) -> ExtractedDocument:
    """Extract from a path (reading bytes if ``data`` not supplied).

    Falls back to the plaintext extractor for unknown extensions so that
    arbitrary text files can still be linted.
    """
    if data is None:
        with open(path, "rb") as fh:
            data = fh.read()
    fn = extractor_for(path) or plaintext.extract
    return fn(path, data)


__all__ = [
    "extract",
    "extractor_for",
    "is_supported",
    "SUPPORTED_EXTENSIONS",
]
