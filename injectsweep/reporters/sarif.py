"""SARIF 2.1.0 reporter.

Emits a valid Static Analysis Results Interchange Format log so injectsweep drops
straight into GitHub code scanning (Security tab) or any SARIF-aware viewer.
"""

from __future__ import annotations

import json
import os

from .. import __version__
from ..detectors.rules import RULES
from ..models import ScanReport

SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
SARIF_VERSION = "2.1.0"
INFO_URI = "https://github.com/Danush-Aries/injectsweep"


def _rules_metadata() -> list[dict]:
    out = []
    for r in RULES.values():
        out.append({
            "id": r.id,
            "name": r.name,
            "shortDescription": {"text": r.short},
            "fullDescription": {"text": r.short},
            "helpUri": r.help_uri,
            "defaultConfiguration": {"level": r.severity.to_sarif_level()},
            "properties": {"security-severity": _security_severity(r.severity.label)},
        })
    return out


def _security_severity(label: str) -> str:
    # GitHub code scanning uses a 0.0-10.0 CVSS-like score.
    return {
        "critical": "9.5",
        "high": "8.0",
        "medium": "5.5",
        "low": "3.0",
        "info": "1.0",
    }.get(label, "1.0")


def _uri(path: str) -> str:
    return path.replace(os.sep, "/")


def build(report: ScanReport) -> dict:
    results = []
    for file_result in report.results:
        for f in file_result.findings:
            results.append({
                "ruleId": f.rule_id,
                "level": f.severity.to_sarif_level(),
                "message": {"text": f.message},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": _uri(file_result.path)},
                        "region": {"startLine": 1, "snippet": {"text": f.evidence}},
                    },
                    "logicalLocations": [{"name": f.layer, "kind": "layer"}],
                }],
                "properties": {
                    "layer": f.layer,
                    "detector": f.detector,
                    "location": f.location,
                    "severity": f.severity.label,
                },
            })

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [{
            "tool": {
                "driver": {
                    "name": "injectsweep",
                    "informationUri": INFO_URI,
                    "version": __version__,
                    "rules": _rules_metadata(),
                }
            },
            "results": results,
        }],
    }


def render(report: ScanReport) -> str:
    return json.dumps(build(report), indent=2, ensure_ascii=False)
