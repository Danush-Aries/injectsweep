"""Shared pytest fixtures.

The corpus is committed to the repo, but we regenerate it once per test session
so the suite also proves the generator produces detectable payloads on the
current machine (and never relies on stale bytes).
"""

from __future__ import annotations

import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CORPUS = os.path.join(ROOT, "corpus")


@pytest.fixture(scope="session", autouse=True)
def ensure_corpus():
    sys.path.insert(0, CORPUS)
    import _generate  # type: ignore

    _generate.main()
    return CORPUS


@pytest.fixture(scope="session")
def labels():
    with open(os.path.join(CORPUS, "labels.json"), encoding="utf-8") as fh:
        return json.load(fh)


@pytest.fixture
def scan_corpus_file():
    from injectsweep.scanner import scan_file

    def _scan(name: str):
        return scan_file(os.path.join(CORPUS, name))

    return _scan
