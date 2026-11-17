"""Offline, non-executable HTML and SVG previews of UD dependency examples.

The worker returns encoded artifacts only. A host broker must authorize and
export the requested destinations. This renderer never starts a browser or
loads external assets, and makes no claim to implement the full UD docs site.
"""
from __future__ import annotations

from hashlib import sha256
from html import escape
from html.parser import HTMLParser
from pathlib import Path
import re
from typing import Any

from ..conllu.core import EMPTY, MWT, WORD, Sentence
from ..errors import InvalidInput, PrerequisiteMissing
from ._artifacts import artifact, output_destination
from ._common import root_path, scoped_path

MAX_SOURCE_BYTES = 1024 * 1024
MAX_TOTAL_SOURCE_BYTES = 4 * 1024 * 1024
MAX_DOCUMENTS = 64
MAX_WORDS = 200
MAX_WIDTH = 32000
FENCE = re.compile(r"^\s*(`{3,}|~{3,})\s*([A-Za-z0-9_-]*)\s*$")
EDGE = re.compile(r"^([A-Za-z][A-Za-z0-9_:.-]*)\((.*)-(\d+),\s*(.*)-(\d+)\)\s*$")
STYLE = """body{font:16px system-ui,sans-serif;line-height:1.5;max-width:90rem;margin:2rem auto;padding:0 1rem;color:#17212b}pre{white-space:pre-wrap;background:#f2f4f7;padding:1rem;overflow-wrap:anywhere}svg{max-width:100%;height:auto}section{margin-bottom:2rem} .diagram{overflow-x:auto;border:1px solid #d1d9e0;padding:.5rem} .diagnostic{color:#8c1d18}"""


def _valid_xml_text(value: str) -> bool:
    return all(c in "\t\n\r" or 0x20 <= ord(c) <= 0xD7FF or 0xE000 <= ord(c) <= 0xFFFD or 0x10000 <= ord(c) <= 0x10FFFF for c in value)


def _required_text(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value or not _valid_xml_text(value):
        raise InvalidInput(f"{name} must be nonempty XML-compatible text")
    if len(value.encode("utf-8")) > MAX_SOURCE_BYTES:
        raise InvalidInput(f"{name} exceeds the rendering size limit")
    return value


def _source(root: Path, value: Any) -> tuple[str, str]:
    path = scoped_path(root, value)
    if path.stat().st_size > MAX_SOURCE_BYTES:
        raise InvalidInput("render input exceeds the source size limit")
    try:
        text = path.read_bytes().decode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise InvalidInput("render input must be UTF-8") from exc
    return _required_text(text, "render source"), sha256(text.encode("utf-8")).hexdigest()


def _sentence(raw: Any) -> tuple[list[dict[str, str]], dict[str, Any]]:
    text = _required_text(raw, "sentence_conllu")
    if re.search(r"\r?\n[ \t]*\r?\n\s*\S", text):
        raise InvalidInput("sentence rendering accepts exactly one CoNLL-U sentence")
    try:
        sent = Sentence(text)
    except ValueError as exc:
        raise InvalidInput(str(exc)) from exc
    words = [row for _, row in sent.rows() if WORD.fullmatch(row[0])]
    if not words or len(words) > MAX_WORDS:
        raise InvalidInput(f"sentence must contain between 1 and {MAX_WORDS} words")
    if [row[0] for row in words] != [str(i) for i in range(1, len(words) + 1)]:
        raise InvalidInput("sentence word IDs must be contiguous and ordered")
    ids = {row[0] for row in words}
    parents: dict[str, str] = {}
    roots = 0
    for row in words:
        ident, form, head, rel = row[0], row[1], row[6], row[7]
        if not form or form == "_" or len(form) > 200:
            raise InvalidInput("each word must have a drawable form of at most 200 characters")
        if head not in ids | {"0"} or head == ident or not rel or rel == "_":
            raise InvalidInput("each word needs an existing basic head and relation")
        if (head == "0") != (rel == "root"):
            raise InvalidInput("zero basic head must correspond to the root relation")
        roots += head == "0"
        parents[ident] = head
    if roots != 1:
        raise InvalidInput("sentence must contain exactly one basic root")
    for ident in parents:
        visited = set()
        cursor = ident
        while cursor != "0":
            if cursor in visited or cursor not in parents:
                raise InvalidInput("basic dependencies must form an acyclic tree")
            visited.add(cursor)
            cursor = parents[cursor]
    results = [{"id": row[0], "form": row[1], "upos": row[3], "head": row[6], "deprel": row[7]} for row in words]
    multi = sum(bool(MWT.fullmatch(row[0])) for _, row in sent.rows())
    empty = sum(bool(EMPTY.fullmatch(row[0])) for _, row in sent.rows())
    enhanced = any(row[8] not in ("", "_") for _, row in sent.rows())
    return results, {"multiword_rows_not_drawn": multi, "empty_nodes_not_drawn": empty, "enhanced_edges_not_drawn": enhanced,
                     "sent_id": next(iter(sent.metadata("sent_id")), None)}


def _diagram(words: list[dict[str, str]], title: str) -> str:
    widths = [max(76, len(token["form"]) * 9 + 28) for token in words]
    total_width = sum(widths) + 40
    if total_width > MAX_WIDTH:
        raise InvalidInput("rendered sentence exceeds the width limit")
    xs = []
    cursor = 20
    for width in widths:
        xs.append(cursor + width // 2)
        cursor += width
    positions = {token["id"]: xs[index] for index, token in enumerate(words)}
    levels = [min(240, 35 + abs(int(token["id"]) - int(token["head"])) * 20) for token in words if token["head"] != "0"]
    arc_top = max(levels, default=35)
    baseline = arc_top + 55
    height = baseline + 78
    out = [f'<svg xmlns="http://www.w3.org/2000/svg" role="img" viewBox="0 0 {total_width} {height}" width="{total_width}" height="{height}">',
           f"<title>{escape(title)}</title>",
           '<defs><marker id="arrow" markerWidth="7" markerHeight="7" refX="5" refY="3.5" orient="auto"><path d="M0,0 L7,3.5 L0,7 Z" fill="#34495e"/></marker></defs>',
           '<g fill="none" stroke="#34495e" stroke-width="1.5" marker-end="url(#arrow)">']
    labels = []
    for token in words:
        x = positions[token["id"]]
        if token["head"] == "0":
            out.append(f'<path d="M{x},{baseline-45} L{x},{baseline-10}"/>')
            labels.append(f'<text x="{x+5}" y="{baseline-48}" font-size="12" fill="#34495e">root</text>')
        else:
            hx = positions[token["head"]]
            lift = min(240, 35 + abs(int(token["id"]) - int(token["head"])) * 20)
            top = baseline - lift
            out.append(f'<path d="M{hx},{baseline-10} Q{(hx+x)/2:.1f},{top} {x},{baseline-10}"/>')
            labels.append(f'<text x="{(hx+x)/2:.1f}" y="{(baseline-10+top)/2-3:.1f}" text-anchor="middle" font-size="12" fill="#34495e">{escape(token["deprel"])}</text>')
    out.append("</g>")
    out.extend(labels)
    out.append('<g text-anchor="middle" fill="#17212b" font-family="sans-serif">')
    for index, token in enumerate(words):
        x = xs[index]
        out.append(f'<text x="{x}" y="{baseline+13}" font-size="15">{escape(token["form"])}</text>')
        out.append(f'<text x="{x}" y="{baseline+32}" font-size="11" fill="#566573">{escape(token["upos"])} · {escape(token["id"])}</text>')
    out.extend(["</g>", "</svg>"])
    return "".join(out)


def _html(title: str, body: str) -> bytes:
    content = ('<!doctype html><html lang="en"><head><meta charset="utf-8">'
               '<meta name="viewport" content="width=device-width,initial-scale=1">'
               '<meta http-equiv="Content-Security-Policy" content="default-src &#39;none&#39;; style-src &#39;unsafe-inline&#39;; font-src data:">'
               f'<title>{escape(title)}</title><style>{STYLE}</style></head><body>{body}</body></html>')
    return content.encode("utf-8")


def _sdparse(source: str) -> str:
    lines = [line.strip() for line in source.splitlines() if line.strip() and not line.lstrip().startswith("#")]
    if len(lines) < 2:
        raise InvalidInput("sdparse example needs token text and dependency relations")
    forms = lines[0].split()
    if not forms or len(forms) > MAX_WORDS:
        raise InvalidInput("sdparse word count is out of bounds")
    edges: dict[int, tuple[int, str]] = {}
    for line in lines[1:]:
        match = EDGE.fullmatch(line)
        if not match:
            raise InvalidInput("unsupported sdparse dependency syntax")
        relation, head_form, head, dep_form, dependent = match.groups()
        head, dependent = int(head), int(dependent)
        if dependent < 1 or dependent > len(forms) or head < 0 or head > len(forms) or dependent in edges:
            raise InvalidInput("sdparse edge references invalid or duplicated word IDs")
        if dep_form != forms[dependent - 1] or (head and head_form != forms[head - 1]) or (not head and head_form != "ROOT"):
            raise InvalidInput("sdparse edge text does not match its token ID")
        edges[dependent] = (head, relation)
    unassigned = [index for index in range(1, len(forms) + 1) if index not in edges]
    if len(unassigned) == 1 and all(head != 0 for head, _ in edges.values()):
        edges[unassigned[0]] = (0, "root")
    elif unassigned:
        raise InvalidInput("sdparse root or dependency assignments are ambiguous")
    rows = []
    for index, form in enumerate(forms, 1):
        head, relation = edges[index]
        rows.append(f"{index}\t{form}\t_\t_\t_\t_\t{head}\t{relation}\t_\t_")
    return "\n".join(rows) + "\n\n"


def _render_example(kind: str, text: str) -> tuple[str, dict[str, Any]]:
    raw = _sdparse(text) if kind == "sdparse" else text
    words, limitations = _sentence(raw)
    svg = _diagram(words, f"Dependency graph: {' '.join(w['form'] for w in words)}")
    return svg, {"kind": kind, "word_count": len(words), "coverage": limitations}


def _markdown(source: str) -> tuple[str, list[dict[str, Any]], list[str]]:
    lines = source.splitlines()
    output = []
    examples = []
    diagnostics = []
    i = 0
    while i < len(lines):
        line = lines[i]
        start = FENCE.fullmatch(line)
        if start:
            marker, kind = start.groups()
            end = i + 1
            while end < len(lines) and not re.fullmatch(r"\s*" + re.escape(marker[0]) + r"{" + str(len(marker)) + r",}\s*", lines[end]):
                end += 1
            body = "\n".join(lines[i + 1:end])
            if end >= len(lines):
                diagnostics.append(f"Unterminated code fence at line {i + 1}.")
            kind = kind.lower()
            if kind in ("conllu", "sdparse"):
                try:
                    svg, info = _render_example(kind, body)
                except InvalidInput as exc:
                    diagnostics.append(f"Example at line {i + 1}: {exc}")
                    output.append('<p class="diagnostic">' + escape(diagnostics[-1]) + "</p>")
                else:
                    examples.append({**info, "line": i + 1})
                    output.append('<div class="diagram">' + svg + "</div>")
            output.append("<pre><code>" + escape(body) + "</code></pre>")
            i = end + 1
            continue
        heading = re.match(r"^(#{1,6})\s+(.+)$", line)
        if heading:
            level = len(heading.group(1))
            output.append(f"<h{level}>{escape(heading.group(2))}</h{level}>")
        elif line.strip():
            output.append("<p>" + escape(line) + "</p>")
        i += 1
    return "".join(output), examples, diagnostics


class _SdparseHTML(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.depth = 0
        self.text: list[str] = []
        self.blocks: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if self.depth:
            if tag in {"br", "p"}:
                self.text.append("\n")
            if tag not in {"br", "hr", "img", "input", "meta", "link"}:
                self.depth += 1
        elif tag == "div" and "sd-parse" in (dict(attrs).get("class") or "").split():
            self.depth = 1
            self.text = []

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if self.depth and tag == "br":
            self.text.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if self.depth:
            self.depth -= 1
            if self.depth == 0:
                self.blocks.append("".join(self.text))

    def handle_data(self, data: str) -> None:
        if self.depth:
            self.text.append(data)


def sentence_render(args: dict[str, Any]) -> dict[str, Any]:
    root_path(args)
    fmt = args.get("output_format")
    if not isinstance(fmt, str):
        raise InvalidInput("output_format must be a string")
    if fmt in {"jpeg", "webp"}:
        raise PrerequisiteMissing("this render pack exports PNG and PDF raster/browser formats")
    if fmt not in {"svg", "html", "png", "pdf"}:
        raise InvalidInput("sentence rendering supports svg, html, png or pdf")
    output_path = args.get("output_path")
    if not isinstance(output_path, str) or not output_path or "\0" in output_path:
        raise InvalidInput("output_path must be a nonempty host destination")
    words, coverage = _sentence(args.get("sentence_conllu"))
    svg = _diagram(words, f"Dependency graph: {' '.join(w['form'] for w in words)}")
    html = _html("UD dependency graph", '<main><div class="diagram">' + svg + "</div></main>")
    data = svg.encode("utf-8") if fmt == "svg" else html
    browser_receipt = None
    if fmt in {"png", "pdf"}:
        from ..render_browser import browser_export
        width = int(re.search(r'width="(\d+)"', svg).group(1))
        height = int(re.search(r'height="(\d+)"', svg).group(1))
        # A static, isolated document avoids responsive CSS and browser chrome
        # altering the requested viewport or introducing remote resources.
        html = ('<!doctype html><html><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" '
                'content="default-src &#39;none&#39;; style-src &#39;unsafe-inline&#39;; font-src data:">'
                '<style>html,body{margin:0;padding:0}svg{display:block}</style></head><body>' + svg + '</body></html>').encode("utf-8")
        data, browser_receipt = browser_export(html, fmt, width, height)
    mime = {"svg": "image/svg+xml", "html": "text/html", "png": "image/png", "pdf": "application/pdf"}[fmt]
    return {"status": "complete", "output_path": output_path, "requires_broker_export": True,
            "artifacts": [artifact("sentence." + fmt, data, mime)],
            **({"provenance": {"render_manifest_sha256": browser_receipt}} if browser_receipt else {}),
            "coverage": {"basic_dependencies": "drawn", **coverage},
            "limitations": ["The diagram renders basic word dependencies; it is not an official validation result.",
                            "Multiword rows, empty nodes, and enhanced edges are not drawn."]}


def documentation_preview(args: dict[str, Any]) -> dict[str, Any]:
    root = root_path(args)
    options = args.get("options") or {}
    if not isinstance(options, dict) or set(options) - {"file_paths"}:
        raise InvalidInput("documentation preview supports only the file_paths option")
    paths = options.get("file_paths")
    if paths is None:
        paths = ["README.md"] if (root / "README.md").is_file() and not (root / "README.md").is_symlink() else []
    if not isinstance(paths, list) or not paths or len(paths) > MAX_DOCUMENTS or any(not isinstance(path, str) or not path.endswith(".md") for path in paths):
        raise InvalidInput("file_paths must select 1–64 Markdown files")
    if len(set(paths)) != len(paths):
        raise InvalidInput("duplicate documentation file")
    sections, files, diagnostics = [], [], []
    total = 0
    for name in paths:
        source, fingerprint = _source(root, name)
        total += len(source.encode("utf-8"))
        if total > MAX_TOTAL_SOURCE_BYTES:
            raise InvalidInput("combined documentation exceeds the rendering size limit")
        rendered, examples, errors = _markdown(source)
        files.append({"file_path": name, "sha256": fingerprint, "examples": examples})
        diagnostics.extend({"file_path": name, "message": error} for error in errors)
        sections.append(f'<section><h1>{escape(name)}</h1>{rendered}</section>')
    data = _html("Documentation preview", "<main>" + "".join(sections) + "</main>")
    return {"status": "incomplete" if diagnostics else "complete", "output_dir_path": output_destination(args),
            "requires_broker_export": True, "files": files, "diagnostics": diagnostics,
            "artifacts": [artifact("index.html", data, "text/html")],
            "limitations": ["Safe offline Markdown subset: raw HTML, remote assets, and full site generation are not executed."]}


def guideline_example_preview(args: dict[str, Any]) -> dict[str, Any]:
    root = root_path(args)
    options = args.get("options") or {}
    if not isinstance(options, dict) or options:
        raise InvalidInput("guideline example preview does not support options")
    path = args.get("example_markup_path")
    source, fingerprint = _source(root, path)
    rendered, examples, diagnostics = _markdown(source)
    parser = _SdparseHTML()
    try:
        parser.feed(source)
        parser.close()
        if parser.depth:
            raise ValueError("unterminated sd-parse element")
    except (ValueError, RecursionError) as exc:
        raise InvalidInput("invalid example markup") from exc
    for index, block in enumerate(parser.blocks, 1):
        try:
            svg, info = _render_example("sdparse", block)
        except InvalidInput as exc:
            diagnostics.append(f"HTML sd-parse example {index}: {exc}")
        else:
            examples.append({**info, "html_example": index})
            rendered += '<div class="diagram">' + svg + "</div>"
    if not examples and not diagnostics:
        if "\t" in source:
            svg, info = _render_example("conllu", source)
        elif any(EDGE.fullmatch(line.strip()) for line in source.splitlines()):
            svg, info = _render_example("sdparse", source)
        else:
            raise InvalidInput("no supported conllu or sdparse examples found")
        examples.append(info)
        rendered += '<div class="diagram">' + svg + "</div>"
    page = _html("Guideline example preview", "<main>" + rendered + "</main>")
    return {"status": "incomplete" if diagnostics else "complete", "output_dir_path": output_destination(args),
            "requires_broker_export": True, "source": {"file_path": path, "sha256": fingerprint},
            "examples": examples, "diagnostics": diagnostics,
            "artifacts": [artifact("index.html", page, "text/html")],
            "limitations": ["Supports basic CoNLL-U and sdparse graphs; raw HTML and scripts are not executed."]}
