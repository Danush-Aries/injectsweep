"""Zero-false-positive guarantee on the clean control documents."""

from __future__ import annotations

import pytest

CLEAN = [
    "clean_resume.pdf",
    "clean_memo.docx",
    "clean_article.html",
    "clean_notes.md",
    "clean_data.csv",
    "clean_readme.txt",
]


@pytest.mark.parametrize("fname", CLEAN)
def test_clean_control_has_no_findings(scan_corpus_file, fname):
    result = scan_corpus_file(fname)
    assert result.findings == [], (
        f"{fname} is a clean control but produced: "
        f"{[(f.rule_id, f.severity.label, f.layer) for f in result.findings]}"
    )
