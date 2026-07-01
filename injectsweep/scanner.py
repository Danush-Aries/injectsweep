"""Scan orchestration and the public library API.

``pre_ingest`` is the function you call from a RAG ingestion pipeline as an input
firewall, *before* a document is chunked and embedded into your vector store.
"""

from __future__ import annotations

import os
from typing import Iterable

from . import detectors, extractors
from .models import FileResult, ScanReport, Severity

_DEFAULT_IGNORES = {".git", ".venv", "venv", "__pycache__", "node_modules", ".mypy_cache"}


def scan_bytes(data: bytes, filename: str = "<bytes>") -> FileResult:
    """Scan an in-memory document. ``filename`` drives extractor selection."""
    doc = extractors.extract(filename, data)
    findings = detectors.run_all(doc)
    return FileResult(path=filename, format=doc.format, findings=findings, errors=doc.errors)


def scan_file(path: str) -> FileResult:
    """Scan a single file on disk."""
    with open(path, "rb") as fh:
        data = fh.read()
    return scan_bytes(data, filename=path)


def pre_ingest(path_or_bytes: str | bytes | os.PathLike, filename: str | None = None) -> FileResult:
    """Input-firewall API for RAG pipelines.

    Accepts a filesystem path or raw bytes and returns a :class:`FileResult`.
    Typical use::

        result = pre_ingest(doc_path)
        if result.max_severity >= Severity.HIGH:
            reject(doc_path, result)
    """
    if isinstance(path_or_bytes, (bytes, bytearray)):
        return scan_bytes(bytes(path_or_bytes), filename=filename or "<bytes>")
    path = os.fspath(path_or_bytes)
    return scan_file(path)


def iter_files(root: str, recursive: bool = True) -> Iterable[str]:
    """Yield scannable files under ``root`` (or just ``root`` if it is a file)."""
    if os.path.isfile(root):
        yield root
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _DEFAULT_IGNORES]
        for name in sorted(filenames):
            full = os.path.join(dirpath, name)
            if extractors.is_supported(full):
                yield full
        if not recursive:
            break


def scan_path(path: str, recursive: bool = True) -> ScanReport:
    """Scan a file or directory and return an aggregate report."""
    report = ScanReport()
    for file_path in iter_files(path, recursive=recursive):
        report.results.append(scan_file(file_path))
    return report


__all__ = [
    "pre_ingest",
    "scan_bytes",
    "scan_file",
    "scan_path",
    "iter_files",
    "Severity",
]
