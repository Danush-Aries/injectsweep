"""HTML extractor.

This is where most "invisible to humans, visible to the LLM" tricks live. We
parse real HTML with BeautifulSoup and classify each text node by whether a
human viewing the rendered page would actually see it:

* ``html_comment``  -- ``<!-- ... -->`` nodes.
* ``hidden_css``    -- ``display:none`` / ``visibility:hidden`` / ``hidden`` attr
                       / ``aria-hidden``.
* ``white_text``    -- foreground colour equal (or near) to the background.
* ``tiny_font``     -- font-size at or below a legibility floor (~4px).
* ``offscreen``     -- absolute/fixed positioning pushed outside the viewport,
                       or text-indent / negative margins used to park text.
* ``visible``       -- everything else.

The ``meta['reason']`` field records *why* a node was judged hidden, which the
reporter surfaces to the analyst.
"""

from __future__ import annotations

import re

from bs4 import BeautifulSoup, Comment

from ..models import ExtractedDocument

_SKIP_TAGS = {"script", "style", "head", "title", "meta", "link"}

_COLOR_HEX = re.compile(r"#([0-9a-fA-F]{3}|[0-9a-fA-F]{6})")
_FONT_SIZE = re.compile(r"font-size\s*:\s*([0-9.]+)\s*(px|pt|em|rem|%)?", re.I)
_TEXT_INDENT = re.compile(r"text-indent\s*:\s*(-?[0-9.]+)\s*(px|pt|em|rem)?", re.I)
_LEFT = re.compile(r"(?:left|top)\s*:\s*(-?[0-9.]+)\s*(px|pt|em|rem)?", re.I)
_MARGIN_NEG = re.compile(r"margin(?:-left|-top)?\s*:\s*(-[0-9.]+)", re.I)


def _decode(data: bytes) -> str:
    for enc in ("utf-8", "latin-1"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace")


def _parse_style(style: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for decl in style.split(";"):
        if ":" in decl:
            k, _, v = decl.partition(":")
            out[k.strip().lower()] = v.strip().lower()
    return out


def _hex_to_rgb(value: str) -> tuple[int, int, int] | None:
    m = _COLOR_HEX.search(value)
    if not m:
        named = {
            "white": (255, 255, 255),
            "black": (0, 0, 0),
            "transparent": (255, 255, 255),
        }
        return named.get(value.strip().lower())
    h = m.group(1)
    if len(h) == 3:
        h = "".join(c * 2 for c in h)
    return int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)


def _to_px(num: float, unit: str | None) -> float:
    unit = (unit or "px").lower()
    return {
        "px": num,
        "pt": num * 96 / 72,
        "em": num * 16,
        "rem": num * 16,
        "%": num / 100 * 16,
    }.get(unit, num)


def _hidden_reason(styles: list[dict[str, str]], attrs_hidden: bool) -> str | None:
    """Inspect the inherited-ish style chain and return why text is hidden."""
    if attrs_hidden:
        return "hidden_attribute"

    merged: dict[str, str] = {}
    for st in styles:
        merged.update(st)

    display = merged.get("display", "")
    visibility = merged.get("visibility", "")
    opacity = merged.get("opacity", "")
    if "none" in display:
        return "display_none"
    if visibility in ("hidden", "collapse"):
        return "visibility_hidden"
    if opacity and _safe_float(opacity) == 0.0:
        return "opacity_zero"

    # tiny font
    for st in styles:
        fs = st.get("font-size")
        if fs:
            m = _FONT_SIZE.match(f"font-size:{fs}")
            if m:
                px = _to_px(float(m.group(1)), m.group(2))
                if px <= 4.0:
                    return "tiny_font"

    # white-on-white (default background is white)
    color = merged.get("color")
    bg = merged.get("background-color") or merged.get("background")
    if color:
        fg = _hex_to_rgb(color)
        back = _hex_to_rgb(bg) if bg else (255, 255, 255)
        if fg and back and _near(fg, back):
            return "low_contrast_text"

    # offscreen positioning
    position = merged.get("position", "")
    if position in ("absolute", "fixed"):
        joined = ";".join(f"{k}:{v}" for k, v in merged.items())
        for m in _LEFT.finditer(joined):
            if _to_px(float(m.group(1)), m.group(2)) <= -1000:
                return "offscreen_position"
    joined = ";".join(f"{k}:{v}" for k, v in merged.items())
    m = _TEXT_INDENT.search(joined)
    if m and _to_px(float(m.group(1)), m.group(2)) <= -1000:
        return "offscreen_text_indent"
    if _MARGIN_NEG.search(joined):
        for m in _MARGIN_NEG.finditer(joined):
            if float(m.group(1)) <= -1000:
                return "offscreen_margin"
    return None


def _safe_float(v: str) -> float:
    try:
        return float(re.sub(r"[^0-9.\-]", "", v) or "1")
    except ValueError:
        return 1.0


def _near(a: tuple[int, int, int], b: tuple[int, int, int], tol: int = 24) -> bool:
    return all(abs(x - y) <= tol for x, y in zip(a, b))


def extract(path: str, data: bytes) -> ExtractedDocument:
    doc = ExtractedDocument(path=path, format="html")
    html = _decode(data)
    doc.raw_text = html
    soup = BeautifulSoup(html, "html.parser")

    # 1. HTML comments (a hidden layer regardless of styling).
    for comment in soup.find_all(string=lambda t: isinstance(t, Comment)):
        body = str(comment).strip()
        if body:
            doc.add("html_comment", body, location="comment")

    # 2. <meta> content is a frequently overlooked injection surface.
    for meta in soup.find_all("meta"):
        content = meta.get("content")
        if content and meta.get("name", "").lower() in {"description", "keywords", "author"}:
            doc.add("metadata", content, location=f"meta[{meta.get('name')}]")

    # 3. Walk text nodes, tracking the style chain of ancestors.
    for text_node in soup.find_all(string=True):
        if isinstance(text_node, Comment):
            continue
        parent = text_node.parent
        if parent is None or parent.name in _SKIP_TAGS:
            continue
        content = str(text_node).strip()
        if not content:
            continue

        styles: list[dict[str, str]] = []
        attrs_hidden = False
        node = parent
        while node is not None and getattr(node, "name", None):
            style_attr = node.get("style") if hasattr(node, "get") else None
            if style_attr:
                styles.append(_parse_style(style_attr))
            if hasattr(node, "has_attr"):
                if node.has_attr("hidden"):
                    attrs_hidden = True
                if node.get("aria-hidden", "").lower() == "true":
                    attrs_hidden = True
            node = node.parent

        reason = _hidden_reason(styles, attrs_hidden)
        if reason:
            layer = {
                "hidden_attribute": "hidden_css",
                "display_none": "hidden_css",
                "visibility_hidden": "hidden_css",
                "opacity_zero": "hidden_css",
                "tiny_font": "tiny_font",
                "low_contrast_text": "white_text",
                "offscreen_position": "offscreen",
                "offscreen_text_indent": "offscreen",
                "offscreen_margin": "offscreen",
            }[reason]
            doc.add(layer, content, location=parent.name, reason=reason)
        else:
            doc.add("visible", content, location=parent.name)

    return doc
