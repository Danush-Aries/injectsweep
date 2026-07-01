"""Golden-file assertions: one payload class per corpus file."""

from __future__ import annotations

import pytest

from injectsweep.models import Severity

# (corpus filename, rule that MUST fire, minimum severity for that rule)
GOLDEN = [
    ("support_zerowidth.txt", "ISW001", Severity.MEDIUM),
    ("contract_tagsmuggle.txt", "ISW002", Severity.CRITICAL),
    ("customers.csv", "ISW002", Severity.CRITICAL),
    ("review_bidi.txt", "ISW003", Severity.HIGH),
    ("announcement_varsel.txt", "ISW004", Severity.MEDIUM),
    ("faq_homoglyph.md", "ISW005", Severity.LOW),
    ("kb_article_comment.html", "ISW010", Severity.MEDIUM),
    ("product_page_whitetext.html", "ISW011", Severity.MEDIUM),
    ("blog_tinyfont.html", "ISW012", Severity.MEDIUM),
    ("landing_offscreen.html", "ISW013", Severity.MEDIUM),
    ("onboarding.docx", "ISW014", Severity.MEDIUM),
    ("records.csv", "ISW020", Severity.HIGH),
    ("resume_whitetext.pdf", "ISW020", Severity.HIGH),
    ("product_page_whitetext.html", "ISW021", Severity.HIGH),
    ("memo_exfil.md", "ISW030", Severity.HIGH),
    ("notes_base64.md", "ISW041", Severity.CRITICAL),
    ("readme_rot13.md", "ISW041", Severity.CRITICAL),
    ("data_hex.txt", "ISW041", Severity.CRITICAL),
]


@pytest.mark.parametrize("fname,rule_id,min_sev", GOLDEN)
def test_payload_class_detected(scan_corpus_file, fname, rule_id, min_sev):
    result = scan_corpus_file(fname)
    matches = [f for f in result.findings if f.rule_id == rule_id]
    assert matches, f"{fname}: expected rule {rule_id}, got {[f.rule_id for f in result.findings]}"
    assert max(f.severity for f in matches) >= min_sev


def test_imperative_in_hidden_layer_is_critical(scan_corpus_file):
    """An imperative inside an invisible layer must escalate to CRITICAL."""
    result = scan_corpus_file("kb_article_comment.html")
    imp = [f for f in result.findings if f.rule_id == "ISW020"]
    assert imp and imp[0].severity == Severity.CRITICAL
    assert imp[0].layer == "html_comment"


def test_unicode_tag_payload_is_decoded(scan_corpus_file):
    """The Tag-block smuggler must recover the hidden ASCII instruction."""
    result = scan_corpus_file("contract_tagsmuggle.txt")
    tag = [f for f in result.findings if f.rule_id == "ISW002"]
    assert tag
    assert "ignore all previous instructions" in tag[0].message.lower()
