"""Shared helpers for detectors."""

from __future__ import annotations

from ..models import Finding, Segment, Severity
from .rules import rule


def snippet(text: str, limit: int = 120) -> str:
    text = text.replace("\n", "\\n").replace("\r", "")
    if len(text) > limit:
        return text[:limit] + "..."
    return text


def make_finding(rule_id: str, segment: Segment, message: str, evidence: str = "",
                 detector: str = "", severity: Severity | None = None) -> Finding:
    r = rule(rule_id)
    return Finding(
        rule_id=r.id,
        name=r.name,
        severity=severity if severity is not None else r.severity,
        message=message,
        detector=detector or r.name,
        layer=segment.layer,
        location=segment.location,
        evidence=evidence or snippet(segment.text),
    )
