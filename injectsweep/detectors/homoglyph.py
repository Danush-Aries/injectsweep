"""Homoglyph / confusable detector.

Attackers swap ASCII letters for visually identical Cyrillic/Greek codepoints so
that a keyword filter ("ignore instructions") misses the payload while the text
still reads normally to a human -- and to the LLM. We flag *mixed-script tokens*:
a single word that combines ASCII letters with confusable non-ASCII lookalikes.
Requiring the mix inside one token keeps false positives near zero (legitimate
multilingual documents keep scripts in separate words).
"""

from __future__ import annotations

import re

from ..models import ExtractedDocument, Finding
from ._common import make_finding

# Common confusables mapping non-ASCII lookalike -> ASCII letter it imitates.
CONFUSABLES = {
    # Cyrillic
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y",
    "і": "i", "ѕ": "s", "ј": "j", "ԁ": "d", "ո": "n", "м": "m", "т": "t",
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O",
    "Р": "P", "С": "C", "Т": "T", "Х": "X",
    # Greek
    "ο": "o", "α": "a", "ε": "e", "ρ": "p", "ν": "v", "ι": "i", "κ": "k",
    "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I", "Κ": "K",
    "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X",
}

_TOKEN = re.compile(r"\S+")


def _ascii_letter(ch: str) -> bool:
    return ("a" <= ch <= "z") or ("A" <= ch <= "Z")


def detect(document: ExtractedDocument) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    for seg in document.segments:
        for m in _TOKEN.finditer(seg.text):
            token = m.group(0)
            confusables = [c for c in token if c in CONFUSABLES]
            ascii_letters = [c for c in token if _ascii_letter(c)]
            if confusables and ascii_letters:
                normalized = "".join(CONFUSABLES.get(c, c) for c in token)
                key = (seg.location, token)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(make_finding(
                    "ISW005", seg,
                    f"Mixed-script token {token!r} uses confusable characters that "
                    f"imitate ASCII (normalizes to {normalized!r}); often used to "
                    "slip an instruction past keyword filters.",
                    evidence=f"{token!r} -> {normalized!r}",
                    detector="homoglyph",
                ))
    return findings
