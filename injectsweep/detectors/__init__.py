"""Static detectors for prompt-injection payloads in extracted documents.

Every detector is a callable ``detect(document) -> list[Finding]`` operating on an
:class:`~injectsweep.models.ExtractedDocument`. They perform genuine static
analysis of the extracted bytes/text -- no model calls, no network, no
randomness. The order below is also the order findings are produced in.
"""

from __future__ import annotations

from typing import Callable

from ..models import ExtractedDocument, Finding
from . import encoded, exfil, hidden_layer, homoglyph, imperative, invisible_unicode
from .rules import RULES

Detector = Callable[[ExtractedDocument], list[Finding]]

DETECTORS: list[Detector] = [
    invisible_unicode.detect,
    homoglyph.detect,
    hidden_layer.detect,
    imperative.detect,
    exfil.detect,
    encoded.detect,
]


def run_all(document: ExtractedDocument) -> list[Finding]:
    findings: list[Finding] = []
    for det in DETECTORS:
        findings.extend(det(document))
    return findings


__all__ = ["DETECTORS", "run_all", "RULES", "Detector"]
