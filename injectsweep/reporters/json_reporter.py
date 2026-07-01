"""JSON reporter -- stable machine-readable output."""

from __future__ import annotations

import json

from ..models import ScanReport


def render(report: ScanReport) -> str:
    return json.dumps(report.to_dict(), indent=2, ensure_ascii=False)
