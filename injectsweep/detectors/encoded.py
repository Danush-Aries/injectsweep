"""Layered / encoded-payload detector.

Injection payloads are frequently wrapped so a naive keyword scan misses them:
base64, hex, or rot13 -- sometimes stacked (base64(rot13(payload))). This detector
recursively decodes candidate blobs (up to a bounded depth), re-running the
imperative scan after every decode step. If injection phrasing surfaces from the
decoded bytes, that is a high-confidence ISW041 (nested-encoded-injection).

A decodable blob that does *not* contain injection phrasing is reported at LOW
(ISW040) as an encoded payload worth a human glance.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import re

from ..models import ExtractedDocument, Finding, Severity
from ._common import make_finding, snippet
from .imperative import scan_text as imperative_scan

_B64 = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
_HEX = re.compile(r"(?:[0-9a-fA-F]{2}){10,}")
_MAX_DEPTH = 3


def _printable_ratio(s: str) -> float:
    if not s:
        return 0.0
    printable = sum(1 for c in s if c.isprintable() or c in "\n\t ")
    return printable / len(s)


def _try_base64(blob: str) -> str | None:
    if len(blob) % 4 != 0:
        return None
    try:
        raw = base64.b64decode(blob, validate=True)
    except (binascii.Error, ValueError):
        return None
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if len(text) >= 6 and _printable_ratio(text) >= 0.85:
        return text
    return None


def _try_hex(blob: str) -> str | None:
    try:
        raw = bytes.fromhex(blob)
    except ValueError:
        return None
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if len(text) >= 6 and _printable_ratio(text) >= 0.85:
        return text
    return None


def _rot13(text: str) -> str:
    return codecs.encode(text, "rot_13")


def _candidates(text: str) -> list[tuple[str, str]]:
    """Yield (scheme, decoded_text) for every blob we can decode from ``text``."""
    out: list[tuple[str, str]] = []
    for m in _B64.finditer(text):
        dec = _try_base64(m.group(0))
        if dec is not None:
            out.append(("base64", dec))
    for m in _HEX.finditer(text):
        dec = _try_hex(m.group(0))
        if dec is not None:
            out.append(("hex", dec))
    # rot13 applies to the whole string (no blob boundary).
    rot = _rot13(text)
    if rot != text:
        out.append(("rot13", rot))
    return out


def _recurse(text: str, depth: int, chain: list[str], seg, findings: list[Finding],
             reported: set[str]) -> None:
    if depth > _MAX_DEPTH:
        return
    for scheme, decoded in _candidates(text):
        new_chain = chain + [scheme]
        hits = imperative_scan(decoded)
        if hits:
            key = f"{seg.location}:{decoded[:40]}"
            if key not in reported:
                reported.add(key)
                chain_str = " -> ".join(new_chain)
                labels = ", ".join(sorted({h[1] for h in hits}))
                findings.append(make_finding(
                    "ISW041", seg,
                    f"Injection phrasing recovered after decoding [{chain_str}]: "
                    f"{snippet(decoded, 90)!r} (matched: {labels}).",
                    evidence=f"[{chain_str}] -> {snippet(decoded, 120)!r}",
                    detector="encoded-payload",
                ))
            # Once we've proven a nested injection, keep unwrapping in case of
            # further layers but stop emitting duplicate ISW040 noise.
            _recurse(decoded, depth + 1, new_chain, seg, findings, reported)
            continue

        # No injection yet; if it's a base64/hex blob, note it and keep unwrapping.
        if scheme in ("base64", "hex"):
            key = f"{seg.location}:enc:{decoded[:40]}"
            if key not in reported and depth == 1:
                reported.add(key)
                findings.append(make_finding(
                    "ISW040", seg,
                    f"Encoded ({scheme}) blob decodes to readable text: "
                    f"{snippet(decoded, 80)!r}; worth a manual look.",
                    evidence=f"{scheme} -> {snippet(decoded, 120)!r}",
                    detector="encoded-payload",
                    severity=Severity.LOW,
                ))
            _recurse(decoded, depth + 1, new_chain, seg, findings, reported)


def detect(document: ExtractedDocument) -> list[Finding]:
    findings: list[Finding] = []
    reported: set[str] = set()
    for seg in document.segments:
        _recurse(seg.text, 1, [], seg, findings, reported)
    return findings
