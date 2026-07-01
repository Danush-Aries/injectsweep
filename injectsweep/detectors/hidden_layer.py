"""Hidden-layer detector.

Flags the mere *presence* of meaningful text in a layer a human reviewer would
never see: HTML comments, white/tiny/off-screen CSS text, PDF annotations,
document metadata, and Word "vanished" runs. This is deliberately independent of
the imperative detector -- even a benign-looking hidden sentence is a red flag in
a RAG corpus, and content detectors add higher-severity findings on top.
"""

from __future__ import annotations

from ..models import ExtractedDocument, Finding
from ._common import make_finding

# layer -> rule id for the structural finding.
#
# Only layers that should never legitimately contain prose are flagged purely on
# presence. Metadata, PDF annotations and document titles routinely hold benign
# descriptive text, so those layers are left to the *content* detectors
# (imperative / encoded / exfil), which escalate to CRITICAL on a hidden layer.
LAYER_RULE = {
    "html_comment": "ISW010",
    "white_text": "ISW011",
    "tiny_font": "ISW012",
    "offscreen": "ISW013",
    "hidden_css": "ISW014",
}

# Ignore trivially short hidden strings (icons, single words, tracking ids).
_MIN_WORDS = 3


def _looks_meaningful(text: str) -> bool:
    words = [w for w in text.split() if any(ch.isalpha() for ch in w)]
    return len(words) >= _MIN_WORDS


def detect(document: ExtractedDocument) -> list[Finding]:
    findings: list[Finding] = []
    for seg in document.segments:
        rule_id = LAYER_RULE.get(seg.layer)
        if not rule_id:
            continue
        if not _looks_meaningful(seg.text):
            continue
        reason = seg.meta.get("reason", seg.layer)
        findings.append(make_finding(
            rule_id, seg,
            f"Human-invisible text found in the '{seg.layer}' layer "
            f"(reason: {reason}); a reader of this document would never see it, "
            "but a RAG ingester keeps it verbatim.",
            detector="hidden-layer",
        ))
    return findings
