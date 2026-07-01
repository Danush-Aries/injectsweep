"""Core data models for injectsweep.

These are the shared vocabulary used by extractors, detectors and reporters.
Everything downstream operates on real, extracted document content -- there is
no synthetic or randomised data anywhere in the pipeline.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any


class Severity(enum.IntEnum):
    """Ordered severity levels. Ordering lets us implement ``--fail-on``."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str) -> "Severity":
        try:
            return cls[value.strip().upper()]
        except KeyError as exc:  # pragma: no cover - defensive
            valid = ", ".join(s.name.lower() for s in cls)
            raise ValueError(
                f"unknown severity {value!r}; expected one of: {valid}"
            ) from exc

    @property
    def label(self) -> str:
        return self.name.lower()

    def to_sarif_level(self) -> str:
        """Map a severity to a SARIF ``level`` (error / warning / note)."""
        if self >= Severity.HIGH:
            return "error"
        if self == Severity.MEDIUM:
            return "warning"
        return "note"


# A "layer" describes *where* in the document a piece of text came from.
# Non-visible layers are inherently suspicious for a RAG corpus because a human
# reviewer of the document would never see them, yet an LLM ingests them fully.
VISIBLE_LAYERS = frozenset({"visible", "csv_cell", "body"})


@dataclass(frozen=True)
class Segment:
    """A single unit of extracted text plus provenance metadata."""

    layer: str
    text: str
    location: str = ""  # human readable location, e.g. "page 2" or "line 14"
    meta: dict[str, Any] = field(default_factory=dict)

    @property
    def is_hidden(self) -> bool:
        return self.layer not in VISIBLE_LAYERS


@dataclass
class ExtractedDocument:
    """The full result of parsing one file with a format extractor."""

    path: str
    format: str
    segments: list[Segment] = field(default_factory=list)
    raw_text: str = ""
    errors: list[str] = field(default_factory=list)

    def add(self, layer: str, text: str, location: str = "", **meta: Any) -> None:
        if text is None:
            return
        self.segments.append(Segment(layer=layer, text=text, location=location, meta=meta))


@dataclass
class Finding:
    """A single detection. Detectors emit these; reporters render them."""

    rule_id: str
    name: str
    severity: Severity
    message: str
    detector: str
    layer: str = "visible"
    location: str = ""
    evidence: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "severity": self.severity.label,
            "message": self.message,
            "detector": self.detector,
            "layer": self.layer,
            "location": self.location,
            "evidence": self.evidence,
        }


@dataclass
class FileResult:
    """All findings for a single scanned file."""

    path: str
    format: str
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def max_severity(self) -> Severity:
        if not self.findings:
            return Severity.INFO
        return max(f.severity for f in self.findings)

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "format": self.format,
            "max_severity": self.max_severity.label,
            "findings": [f.to_dict() for f in self.findings],
            "errors": self.errors,
        }


@dataclass
class ScanReport:
    """The aggregate result of scanning one or more files."""

    results: list[FileResult] = field(default_factory=list)

    @property
    def findings(self) -> list[Finding]:
        return [f for r in self.results for f in r.findings]

    @property
    def max_severity(self) -> Severity:
        if not self.findings:
            return Severity.INFO
        return max(f.severity for f in self.findings)

    def exceeds(self, threshold: Severity) -> bool:
        """True when any finding is at or above ``threshold``."""
        return any(f.severity >= threshold for f in self.findings)

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": "injectsweep",
            "summary": {
                "files_scanned": len(self.results),
                "files_with_findings": sum(1 for r in self.results if r.findings),
                "total_findings": len(self.findings),
                "max_severity": self.max_severity.label,
            },
            "results": [r.to_dict() for r in self.results],
        }
