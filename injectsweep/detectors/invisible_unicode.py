"""Invisible / non-printing unicode detector.

Catches four real smuggling channels:

* Zero-width characters (ZWSP, ZWNJ, ZWJ, word joiner, BOM, Mongolian vowel sep).
* The Unicode **Tag** block (U+E0000-E007F). Tag characters render as nothing but
  map 1:1 onto ASCII, so an attacker can hide a whole instruction "under" a
  single visible emoji. We decode the tag run back to ASCII and report it.
* Bidirectional overrides (RLO/LRO/PDF and isolates) which visually reorder text.
* Variation selectors (U+FE00-FE0F, U+E0100-E01EF) abused to hide bytes.

Character maps are declared by codepoint (chr(...)) so the source file stays free
of literal invisible glyphs.
"""

from __future__ import annotations

from ..models import ExtractedDocument, Finding
from ._common import make_finding

ZERO_WIDTH = {
    chr(0x200B): "ZERO WIDTH SPACE",
    chr(0x200C): "ZERO WIDTH NON-JOINER",
    chr(0x200D): "ZERO WIDTH JOINER",
    chr(0x2060): "WORD JOINER",
    chr(0xFEFF): "ZERO WIDTH NO-BREAK SPACE (BOM)",
    chr(0x180E): "MONGOLIAN VOWEL SEPARATOR",
    chr(0x00AD): "SOFT HYPHEN",
}

BIDI = {
    chr(0x202A): "LEFT-TO-RIGHT EMBEDDING",
    chr(0x202B): "RIGHT-TO-LEFT EMBEDDING",
    chr(0x202C): "POP DIRECTIONAL FORMATTING",
    chr(0x202D): "LEFT-TO-RIGHT OVERRIDE",
    chr(0x202E): "RIGHT-TO-LEFT OVERRIDE",
    chr(0x2066): "LEFT-TO-RIGHT ISOLATE",
    chr(0x2067): "RIGHT-TO-LEFT ISOLATE",
    chr(0x2068): "FIRST STRONG ISOLATE",
    chr(0x2069): "POP DIRECTIONAL ISOLATE",
}


def _is_tag(ch: str) -> bool:
    return 0xE0000 <= ord(ch) <= 0xE007F


def _is_variation_selector(ch: str) -> bool:
    cp = ord(ch)
    return 0xFE00 <= cp <= 0xFE0F or 0xE0100 <= cp <= 0xE01EF


def _decode_tags(text: str) -> str:
    """Decode Unicode Tag characters to the ASCII they mirror."""
    out = []
    for ch in text:
        cp = ord(ch)
        if 0xE0020 <= cp <= 0xE007E:  # tag space .. tag tilde
            out.append(chr(cp - 0xE0000))
    return "".join(out)


def detect(document: ExtractedDocument) -> list[Finding]:
    findings: list[Finding] = []
    for seg in document.segments:
        text = seg.text

        zw = sorted({ch for ch in text if ch in ZERO_WIDTH})
        if zw:
            names = ", ".join(ZERO_WIDTH[c] for c in zw)
            findings.append(make_finding(
                "ISW001", seg,
                f"Found {len(zw)} kind(s) of zero-width character ({names}); "
                "these can hide an instruction inside otherwise clean text.",
                evidence=f"zero-width chars: {names}",
                detector="invisible-unicode",
            ))

        tag_chars = [ch for ch in text if _is_tag(ch)]
        if tag_chars:
            hidden = _decode_tags(text)
            msg = (
                f"Unicode Tag block characters smuggle a hidden ASCII message: {hidden!r}"
                if hidden
                else "Unicode Tag block characters present (invisible instruction channel)."
            )
            findings.append(make_finding(
                "ISW002", seg, msg,
                evidence=f"decoded tag payload: {hidden!r}" if hidden else "tag chars present",
                detector="invisible-unicode",
            ))

        bidi = sorted({ch for ch in text if ch in BIDI})
        if bidi:
            names = ", ".join(BIDI[c] for c in bidi)
            findings.append(make_finding(
                "ISW003", seg,
                f"Bidirectional override characters ({names}) can visually reorder "
                "text so the rendered line differs from what the model ingests.",
                evidence=f"bidi controls: {names}",
                detector="invisible-unicode",
            ))

        vs = [ch for ch in text if _is_variation_selector(ch)]
        # A couple of emoji variation selectors are normal; flag suspicious runs.
        if len(vs) >= 3:
            findings.append(make_finding(
                "ISW004", seg,
                f"{len(vs)} variation selectors detected -- can encode hidden bytes "
                "alongside a single visible glyph.",
                evidence=f"variation selectors: {len(vs)}",
                detector="invisible-unicode",
            ))
    return findings
