"""Output reporters: table (rich), json, and SARIF 2.1.0."""

from __future__ import annotations

from ..models import ScanReport
from . import json_reporter, sarif, table


def render(report: ScanReport, fmt: str) -> str:
    fmt = fmt.lower()
    if fmt == "json":
        return json_reporter.render(report)
    if fmt == "sarif":
        return sarif.render(report)
    if fmt == "table":
        return table.render(report)
    raise ValueError(f"unknown format {fmt!r}; expected table|json|sarif")


__all__ = ["render", "json_reporter", "sarif", "table"]
