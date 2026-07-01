"""Imperative-injection detector.

Regex catalog of the phrasings indirect prompt-injection payloads use to seize
control of an LLM: instruction overrides ("ignore previous instructions"), role
redefinition ("you are now DAN"), secrecy directives ("do not tell the user"),
and system-prompt exfiltration ("reveal your system prompt").

Findings on a hidden layer are escalated to CRITICAL: a human-invisible imperative
is the textbook indirect-injection primitive.
"""

from __future__ import annotations

import re

from ..models import ExtractedDocument, Finding, Severity
from ._common import make_finding, snippet

# (compiled pattern, rule_id, label)
_PATTERNS: list[tuple[re.Pattern[str], str, str]] = [
    (re.compile(r"ignore\s+(?:all\s+|any\s+)?(?:the\s+)?(?:previous|prior|above|earlier|preceding)\s+(?:instructions?|prompts?|context|messages?)", re.I), "ISW020", "ignore-previous-instructions"),
    (re.compile(r"disregard\s+(?:all\s+|any\s+)?(?:the\s+|your\s+)?(?:previous|prior|above|earlier|prior|system)\s+(?:instructions?|prompts?|rules?|guidelines?)", re.I), "ISW020", "disregard-instructions"),
    (re.compile(r"forget\s+(?:everything|all|your|the)\s+(?:previous|prior|above|instructions?|rules?|you\s+were\s+told)", re.I), "ISW020", "forget-instructions"),
    (re.compile(r"do\s+not\s+(?:tell|inform|mention|reveal\s+to|warn)\s+the\s+user", re.I), "ISW020", "conceal-from-user"),
    (re.compile(r"without\s+(?:telling|informing|alerting)\s+(?:the\s+)?user", re.I), "ISW020", "conceal-from-user"),
    (re.compile(r"(?:new|updated|revised|real|actual)\s+(?:instructions?|task|directive)\s*:", re.I), "ISW020", "injected-new-instructions"),
    (re.compile(r"override\s+(?:your\s+|the\s+|all\s+)?(?:previous\s+|prior\s+|system\s+)?(?:instructions?|settings?|rules?|guardrails?)", re.I), "ISW020", "override-instructions"),
    # role / system-prompt redefinition -> ISW021
    (re.compile(r"you\s+are\s+now\s+(?:a|an|in|the|no\s+longer|going\s+to|\w+)", re.I), "ISW021", "role-redefinition"),
    (re.compile(r"from\s+now\s+on[, ]+you\s+(?:are|will|must|should|shall)", re.I), "ISW021", "role-redefinition"),
    (re.compile(r"(?:act|behave|respond|pretend\s+to\s+be)\s+as\s+(?:if\s+you\s+are\s+|a\s+|an\s+|the\s+)?(?:dan|developer\s+mode|jailbroken|unrestricted|admin)", re.I), "ISW021", "jailbreak-persona"),
    (re.compile(r"(?:reveal|print|repeat|output|show|display|leak)\s+(?:your\s+|the\s+)?(?:system\s+prompt|initial\s+instructions?|hidden\s+(?:prompt|instructions?))", re.I), "ISW021", "system-prompt-exfil"),
    (re.compile(r"system\s+prompt\s+(?:override|injection|is\s+now)", re.I), "ISW021", "system-prompt-override"),
    (re.compile(r"enable\s+(?:developer|dan|god|admin)\s+mode", re.I), "ISW021", "jailbreak-persona"),
]


def scan_text(text: str) -> list[tuple[str, str, str]]:
    """Return (rule_id, label, matched_span) tuples for a raw string."""
    hits: list[tuple[str, str, str]] = []
    for pattern, rule_id, label in _PATTERNS:
        m = pattern.search(text)
        if m:
            hits.append((rule_id, label, m.group(0)))
    return hits


def detect(document: ExtractedDocument) -> list[Finding]:
    findings: list[Finding] = []
    for seg in document.segments:
        for rule_id, label, span in scan_text(seg.text):
            severity = None
            note = ""
            if seg.is_hidden:
                severity = Severity.CRITICAL
                note = " (found in a human-invisible layer -- classic indirect injection)"
            findings.append(make_finding(
                rule_id, seg,
                f"Prompt-injection phrasing [{label}]: {snippet(span, 90)!r}{note}",
                evidence=snippet(span, 120),
                detector="imperative-injection",
                severity=severity,
            ))
    return findings
