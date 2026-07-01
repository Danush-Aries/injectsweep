"""injectsweep -- a static pre-ingestion linter for prompt-injection payloads.

injectsweep scans the *documents* entering a RAG pipeline (PDF, HTML, DOCX,
Markdown, CSV, text) and flags hidden prompt-injection payloads before they can
poison a vector index (OWASP LLM01: indirect prompt injection).

Public API::

    from injectsweep import pre_ingest, Severity

    result = pre_ingest("some_document.pdf")
    if result.max_severity >= Severity.HIGH:
        reject(result)
"""

from __future__ import annotations

__version__ = "0.1.0"

from .models import Finding, FileResult, ScanReport, Severity  # noqa: E402
from .scanner import pre_ingest, scan_bytes, scan_file, scan_path  # noqa: E402

__all__ = [
    "__version__",
    "pre_ingest",
    "scan_file",
    "scan_bytes",
    "scan_path",
    "Severity",
    "Finding",
    "FileResult",
    "ScanReport",
]
