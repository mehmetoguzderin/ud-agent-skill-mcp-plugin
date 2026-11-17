#!/usr/bin/env python3
"""Record the installed immutable browser, font and asset inventory after offline installation."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import struct

FONT_NAMES = ("NotoSansMono-Regular.ttf", "NotoSans-Regular.ttf", "NotoSansArabic-Regular.ttf", "NotoSansHebrew-Regular.ttf", "NotoSansDevanagari-Regular.ttf", "NotoSansThai-Regular.ttf", "NotoSansArmenian-Regular.ttf", "NotoSansGeorgian-Regular.ttf", "NotoSansBengali-Regular.ttf", "NotoSansTamil-Regular.ttf", "NotoSansTelugu-Regular.ttf", "NotoSansEthiopic-Regular.ttf")


def standalone_font(collection: bytes) -> bytes:
    """Materialize font zero of a bounded TTC without changing glyph tables."""
    if len(collection) < 16 or len(collection) > 64 * 1024 * 1024 or collection[:4] != b"ttcf":
        raise ValueError("invalid bounded Noto font collection")
    count, start = struct.unpack_from(">II", collection, 8)
    if not 1 <= count <= 64 or start + 12 > len(collection):
        raise ValueError("font collection directory is invalid")
    header = collection[start:start + 12]
    tables = struct.unpack_from(">H", header, 4)[0]
    if not 1 <= tables <= 4096 or start + 12 + 16 * tables > len(collection):
        raise ValueError("font table inventory is invalid")
    records, bodies, seen = bytearray(), bytearray(), set()
    offset = 12 + 16 * tables
    head_offset = None
    for index in range(tables):
        tag, checksum, position, size = struct.unpack_from(">4sIII", collection, start + 12 + 16 * index)
        if tag in seen or position + size > len(collection) or size > 64 * 1024 * 1024:
            raise ValueError("font collection table is duplicated or out of bounds")
        seen.add(tag)
        data = bytearray(collection[position:position + size])
        if tag == b"head":
            if size < 12:
                raise ValueError("font head table is incomplete")
            data[8:12] = bytes(4)
            head_offset = offset + 8
        records.extend(struct.pack(">4sIII", tag, checksum, offset, size))
        bodies.extend(data)
        padding = (-size) % 4
        bodies.extend(bytes(padding))
        offset += size + padding
    result = bytearray(header + records + bodies)
    if head_offset is None:
        raise ValueError("font collection has no checksum head")
    checksum = sum(value[0] for value in struct.iter_unpack(">I", result)) & 0xFFFFFFFF
    struct.pack_into(">I", result, head_offset, (0xB1B0AFBA - checksum) & 0xFFFFFFFF)
    return bytes(result)


def pinned_fonts(directory: Path, generated: Path, required: bool = True) -> list[Path]:
    available = {}
    for path in directory.rglob("*"):
        if path.is_file() and not path.is_symlink():
            if path.name in available:
                raise ValueError("pinned font family is ambiguous")
            available[path.name] = path
    selected = [available[name] for name in FONT_NAMES if name in available]
    collection = available.get("NotoSansCJK-Regular.ttc")
    if collection is not None:
        generated.parent.mkdir(parents=True, exist_ok=True)
        content = standalone_font(collection.read_bytes())
        if generated.exists() and generated.read_bytes() != content:
            raise ValueError("generated Noto font differs from its verified collection")
        if not generated.exists():
            generated.write_bytes(content)
            generated.chmod(0o444)
        selected.append(generated)
    if required and (len(selected) != len(FONT_NAMES) + 1 or sum(path.stat().st_size for path in selected) > 64 * 1024 * 1024):
        raise ValueError("complete bounded pinned font selection is missing")
    return selected


def manifest(root: Path, executable: str = "/usr/lib/chromium/chromium", require_fonts: bool = False) -> dict:
    selected = set()
    fonts = pinned_fonts(root / "usr/share/fonts", root / "opt/ud-agent/render/fonts/NotoSansCJK-Regular.otf", require_fonts)
    selected.update(fonts)
    for logical in ("/usr/lib/chromium", "/usr/share/fonts", "/usr/share/fontconfig/conf.avail", "/etc/fonts/fonts.conf", "/opt/ud-agent/render/dependency-lock.json"):
        source = root / logical.lstrip("/")
        if not source.exists():
            raise ValueError("required browser asset location is missing: " + logical)
        paths = source.rglob("*") if source.is_dir() else [source]
        for path in paths:
            if path.is_symlink():
                target = path.resolve(strict=True)
                if root.resolve() != target and root.resolve() not in target.parents:
                    raise ValueError("browser asset link escapes the image root")
                if target.is_file():
                    selected.add(target)
            elif path.is_file():
                selected.add(path)
    binary = root / executable.lstrip("/")
    if binary.is_symlink() or not binary.is_file() or not binary.stat().st_mode & 0o111 or binary.stat().st_mode & 0o022:
        raise ValueError("browser executable is absent or writable")
    selected.add(binary)
    if not 1 <= len(selected) <= 10000:
        raise ValueError("browser inventory exceeds its count bound")
    files, total = [], 0
    for path in sorted(selected):
        info = path.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_size > 512 * 1024 * 1024:
            raise ValueError("browser asset is not a bounded regular file")
        total += info.st_size
        if total > 2 * 1024 * 1024 * 1024:
            raise ValueError("browser asset closure exceeds its size bound")
        with path.open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        files.append({"path": "/" + path.relative_to(root).as_posix(), "sha256": digest, "size_bytes": info.st_size})
    return {"schema_version": 1, "executable": executable, "files": files, "fonts": ["/" + path.relative_to(root).as_posix() for path in fonts]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("/"))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    data = manifest(args.root, require_fonts=True)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as target:
        json.dump(data, target, sort_keys=True, indent=2)
        target.write("\n")


if __name__ == "__main__":
    main()
