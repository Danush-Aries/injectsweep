"""Format matrix: every extractor parses real bytes and tags layers correctly."""

from __future__ import annotations

import pytest

from injectsweep.extractors import extract, is_supported

FORMATS = [
    ("resume_whitetext.pdf", "pdf"),
    ("kb_article_comment.html", "html"),
    ("onboarding.docx", "docx"),
    ("notes_base64.md", "markdown"),
    ("customers.csv", "csv"),
    ("support_zerowidth.txt", "text"),
]


@pytest.mark.parametrize("fname,fmt", FORMATS)
def test_extractor_format_matrix(scan_corpus_file, fname, fmt):
    import os

    from tests.conftest import CORPUS

    doc = extract(os.path.join(CORPUS, fname))
    assert doc.format == fmt
    assert doc.segments, f"{fname}: extractor produced no segments"
    assert not doc.errors, f"{fname}: extractor errors {doc.errors}"


def test_html_classifies_hidden_layers():
    import os

    from tests.conftest import CORPUS

    doc = extract(os.path.join(CORPUS, "landing_offscreen.html"))
    layers = {s.layer for s in doc.segments}
    assert "offscreen" in layers
    assert "visible" in layers  # the benign copy is still tagged visible


def test_html_comment_is_hidden_layer():
    import os

    from tests.conftest import CORPUS

    doc = extract(os.path.join(CORPUS, "kb_article_comment.html"))
    comments = [s for s in doc.segments if s.layer == "html_comment"]
    assert comments and comments[0].is_hidden


def test_docx_hidden_run_detected():
    import os

    from tests.conftest import CORPUS

    doc = extract(os.path.join(CORPUS, "onboarding.docx"))
    hidden = [s for s in doc.segments if s.layer == "hidden_css"]
    assert hidden, "vanished run not surfaced as a hidden layer"


def test_pdf_annotation_extracted():
    import os

    from tests.conftest import CORPUS

    doc = extract(os.path.join(CORPUS, "invoice_annotation.pdf"))
    annots = [s for s in doc.segments if s.layer == "pdf_annotation"]
    assert annots, "PDF annotation contents not extracted"


def test_extension_support():
    assert is_supported("a.pdf")
    assert is_supported("a.HTML")
    assert is_supported("a.docx")
    assert is_supported("a.md")
    assert is_supported("a.csv")
    assert is_supported("a.txt")
    assert not is_supported("a.exe")
