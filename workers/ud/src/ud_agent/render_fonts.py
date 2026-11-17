"""Embed verified font bytes and reject missing Unicode glyph coverage offline."""
import base64
from html.parser import HTMLParser
import struct
import unicodedata

from .errors import WorkerError


class _Visible(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.hidden = 0
        self.points = set()

    def handle_starttag(self, tag, attrs):
        if tag in {"style", "script", "title"}:
            self.hidden += 1

    def handle_endtag(self, tag):
        if tag in {"style", "script", "title"} and self.hidden:
            self.hidden -= 1

    def handle_data(self, data):
        if not self.hidden:
            self.points.update(ord(char) for char in data if not char.isspace() and unicodedata.category(char) not in {"Cc", "Cf"}
                               and not 0xFE00 <= ord(char) <= 0xFE0F and not 0xE0100 <= ord(char) <= 0xE01EF)


def _covers(data, points):
    """Read Unicode cmap formats4/12/13 from a bounded verified SFNT font."""
    def u16(offset):
        return struct.unpack_from(">H", data, offset)[0]
    def u32(offset):
        return struct.unpack_from(">I", data, offset)[0]
    try:
        if data[:4] not in {b"\x00\x01\x00\x00", b"OTTO", b"true"} or len(data) < 12:
            raise ValueError()
        count = u16(4)
        if count > 4096 or 12 + 16 * count > len(data):
            raise ValueError()
        cmap = None
        glyph_count = None
        for index in range(count):
            entry = 12 + 16 * index
            start, length = u32(entry + 8), u32(entry + 12)
            if start + length > len(data):
                raise ValueError()
            if data[entry:entry + 4] == b"cmap":
                cmap = (start, start + length)
            elif data[entry:entry + 4] == b"maxp":
                if length < 6:
                    raise ValueError()
                glyph_count = u16(start + 4)
        if cmap is None or glyph_count is None or glyph_count < 1:
            raise ValueError()
        start, end = cmap
        tables = u16(start + 2)
        if start + 4 + 8 * tables > end:
            raise ValueError()
        covered = set()
        for index in range(tables):
            entry = start + 4 + 8 * index
            platform, encoding, offset = u16(entry), u16(entry + 2), start + u32(entry + 4)
            if platform != 0 and not (platform == 3 and encoding in {1, 10}):
                continue
            if offset + 4 > end:
                raise ValueError()
            kind = u16(offset)
            if kind in {12, 13}:
                if offset + 16 > end:
                    raise ValueError()
                length, groups = u32(offset + 4), u32(offset + 12)
                if length < 16 or offset + length > end or 16 + 12 * groups > length:
                    raise ValueError()
                previous = -1
                for group in range(groups):
                    pos = offset + 16 + 12 * group
                    first, last, glyph = u32(pos), u32(pos + 4), u32(pos + 8)
                    if first > last or first <= previous or last > 0x10FFFF:
                        raise ValueError()
                    previous = last
                    covered.update(point for point in points - covered if first <= point <= last and 0 < (glyph if kind == 13 else glyph + point - first) < glyph_count)
            elif kind == 4:
                if offset + 16 > end:
                    raise ValueError()
                length, segments = u16(offset + 2), u16(offset + 6) // 2
                if length < 16 or offset + length > end or 16 + 8 * segments > length:
                    raise ValueError()
                ends = offset + 14
                starts = ends + 2 * segments + 2
                deltas = starts + 2 * segments
                ranges = deltas + 2 * segments
                for index in range(segments):
                    first, last, delta, distance = u16(starts + 2 * index), u16(ends + 2 * index), u16(deltas + 2 * index), u16(ranges + 2 * index)
                    for point in points - covered:
                        if first <= point <= last:
                            if distance:
                                position = ranges + 2 * index + distance + 2 * (point - first)
                                if position + 2 > offset + length:
                                    raise ValueError()
                                glyph = u16(position)
                                glyph = (glyph + delta) & 0xFFFF if glyph else 0
                            else:
                                glyph = (point + delta) & 0xFFFF
                            if 0 < glyph < glyph_count:
                                covered.add(point)
        return covered
    except (ValueError, struct.error, IndexError) as exc:
        raise WorkerError("RENDER_FONT_INVALID", "a verified font has an invalid Unicode character map") from exc


def embed_fonts(html, fonts):
    if not fonts:
        raise WorkerError("RENDER_FONT_PACK_REQUIRED", "the verified renderer must include pinned offline fonts")
    visible = _Visible()
    try:
        text = html.decode("utf-8", errors="strict")
        visible.feed(text)
    except (ValueError, UnicodeError) as exc:
        raise WorkerError("RENDER_REQUEST_INVALID", "render document is not valid UTF-8 HTML") from exc
    missing = visible.points
    if len(missing) > 16384:
        raise WorkerError("RENDER_REQUEST_INVALID", "render document exceeds its distinct glyph budget")
    styles, families = [], []
    for index, data in enumerate(fonts):
        missing = missing - _covers(data, missing)
        family = f"ud-agent-font-{index}"
        families.append('"' + family + '"')
        styles.append('@font-face{font-family:"' + family + '";src:url(data:font/sfnt;base64,' + base64.b64encode(data).decode("ascii") + ');font-style:normal;font-weight:100 900;font-display:block}')
    if missing:
        codes = ", ".join(f"U+{point:04X}" for point in sorted(missing)[:16])
        raise WorkerError("RENDER_FONT_COVERAGE_MISSING", "pinned offline fonts do not cover requested glyphs: " + codes)
    styles.append('html,body,svg,text,tspan,pre,code,*{font-family:' + ",".join(families) + '!important}')
    markup = "<style>" + "".join(styles) + "</style>"
    text = text.replace("</head>", markup + "</head>", 1) if "</head>" in text else markup + text
    return text.encode("utf-8")
