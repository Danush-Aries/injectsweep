"""Central catalog of detection rules.

Keeping rule metadata in one place lets the SARIF reporter emit a complete
``tool.driver.rules`` array and gives every finding a stable, documented ID.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..models import Severity


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    severity: Severity
    short: str
    help_uri: str = "https://github.com/Danush-Aries/injectsweep#detector-catalog"


_DEF: list[Rule] = [
    # --- invisible unicode ---
    Rule("ISW001", "zero-width-characters", Severity.MEDIUM,
         "Zero-width / invisible characters that can smuggle hidden text."),
    Rule("ISW002", "unicode-tag-smuggling", Severity.CRITICAL,
         "Unicode Tag block (U+E0000-E007F) carrying a hidden ASCII instruction."),
    Rule("ISW003", "bidi-override", Severity.HIGH,
         "Bidirectional override characters that visually reorder text."),
    Rule("ISW004", "variation-selector-smuggling", Severity.MEDIUM,
         "Variation selectors used to hide data alongside visible glyphs."),
    # --- homoglyph ---
    Rule("ISW005", "homoglyph-confusable", Severity.LOW,
         "Mixed-script confusable characters impersonating ASCII letters."),
    # --- hidden layers ---
    Rule("ISW010", "hidden-html-comment", Severity.MEDIUM,
         "Instruction-like text hidden inside an HTML comment."),
    Rule("ISW011", "white-on-white-text", Severity.MEDIUM,
         "Text rendered in the background colour (invisible to humans)."),
    Rule("ISW012", "tiny-font-text", Severity.MEDIUM,
         "Text set at an illegible font size (<=4px)."),
    Rule("ISW013", "offscreen-text", Severity.MEDIUM,
         "Text positioned outside the viewport / indented off-canvas."),
    Rule("ISW014", "hidden-layer-text", Severity.MEDIUM,
         "Text present in a non-visible layer (metadata, annotation, vanished run)."),
    # --- imperative injection ---
    Rule("ISW020", "imperative-injection", Severity.HIGH,
         "Imperative prompt-injection phrasing (e.g. 'ignore previous instructions')."),
    Rule("ISW021", "system-prompt-override", Severity.HIGH,
         "Attempt to redefine the assistant's role or system prompt."),
    # --- exfiltration ---
    Rule("ISW030", "data-exfil-image-beacon", Severity.HIGH,
         "Markdown/HTML image whose URL can beacon data to an external host."),
    Rule("ISW031", "suspicious-url", Severity.MEDIUM,
         "URL carrying encoded payloads or data-exfil query parameters."),
    # --- encoded / layered ---
    Rule("ISW040", "encoded-payload", Severity.LOW,
         "Base64/hex/rot13 encoded blob embedded in document text."),
    Rule("ISW041", "nested-encoded-injection", Severity.CRITICAL,
         "Injection phrasing recovered after recursively decoding an encoded blob."),
]

RULES: dict[str, Rule] = {r.id: r for r in _DEF}


def rule(rule_id: str) -> Rule:
    return RULES[rule_id]
