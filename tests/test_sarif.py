"""SARIF 2.1.0 output validity.

Validates against the official OASIS/SchemaStore SARIF 2.1.0 JSON schema, which
is vendored at tests/sarif-schema-2.1.0.json so the check runs fully offline.
"""

from __future__ import annotations

import json
import os

import pytest

from injectsweep.reporters import sarif
from injectsweep.scanner import scan_path

SCHEMA_PATH = os.path.join(os.path.dirname(__file__), "sarif-schema-2.1.0.json")


def _corpus_report():
    from tests.conftest import CORPUS

    return scan_path(CORPUS)


def test_sarif_basic_shape():
    doc = sarif.build(_corpus_report())
    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["tool"]["driver"]["name"] == "injectsweep"
    assert doc["runs"][0]["tool"]["driver"]["rules"], "rules metadata missing"
    assert doc["runs"][0]["results"], "expected results on the corpus"


def test_sarif_levels_are_valid():
    doc = sarif.build(_corpus_report())
    for res in doc["runs"][0]["results"]:
        assert res["level"] in {"error", "warning", "note"}
        assert res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]


@pytest.mark.skipif(not os.path.exists(SCHEMA_PATH), reason="SARIF schema not vendored")
def test_sarif_validates_against_official_schema():
    jsonschema = pytest.importorskip("jsonschema")
    with open(SCHEMA_PATH, encoding="utf-8") as fh:
        schema = json.load(fh)
    doc = sarif.build(_corpus_report())
    jsonschema.validate(doc, schema)


def test_sarif_is_json_serializable():
    text = sarif.render(_corpus_report())
    parsed = json.loads(text)
    assert parsed["$schema"].endswith("sarif-2.1.0.json") or "sarif" in parsed["$schema"]
