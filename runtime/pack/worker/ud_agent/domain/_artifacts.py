"""Bounded staged bytes and broker-export artifact descriptions."""
from __future__ import annotations

import base64
from hashlib import sha256
import io
import json
from pathlib import Path, PurePosixPath
import tarfile
from typing import Any

from ..errors import InvalidInput
from ._common import scoped_path

MAX_FILES = 10000
MAX_BYTES = 64 * 1024 * 1024


def json_bytes(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")


def parse_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_bytes().decode("utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise InvalidInput(f"expected a UTF-8 JSON object: {path.name}") from exc
    if not isinstance(value, dict):
        raise InvalidInput(f"expected a JSON object: {path.name}")
    return value


def relative_name(name: str) -> str:
    if not isinstance(name, str) or not name or "\\" in name or "\0" in name:
        raise InvalidInput("artifact path must be a nonempty POSIX relative path")
    path = PurePosixPath(name)
    if path.is_absolute() or any(part in (".", "..") for part in path.parts):
        raise InvalidInput("artifact path must remain beneath its destination")
    return path.as_posix()


def collect(root: Path, names: list[str]) -> dict[str, bytes]:
    if not isinstance(names, list) or len(names) > MAX_FILES or any(not isinstance(x, str) for x in names):
        raise InvalidInput("file selection must be a bounded list of paths")
    result = {}
    size = 0
    for name in names:
        clean = relative_name(name)
        if clean in result:
            raise InvalidInput("duplicate input path")
        path = scoped_path(root, clean)
        if path.stat().st_size > MAX_BYTES - size:
            raise InvalidInput("input size exceeds the worker packaging limit")
        with path.open("rb") as stream:
            content = stream.read(MAX_BYTES - size + 1)
        size += len(content)
        if size > MAX_BYTES:
            raise InvalidInput("input size exceeds the worker packaging limit")
        result[clean] = content
    return result


def manifest(files: dict[str, bytes]) -> list[dict[str, Any]]:
    return [{"path": name, "size_bytes": len(content), "sha256": sha256(content).hexdigest()}
            for name, content in sorted(files.items())]


def artifact(name: str, content: bytes, mime: str) -> dict[str, Any]:
    if len(content) > MAX_BYTES:
        raise InvalidInput("artifact exceeds the worker output limit")
    return {"relative_path": relative_name(name), "mime_type": mime, "size_bytes": len(content),
            "sha256": sha256(content).hexdigest(), "content_base64": base64.b64encode(content).decode("ascii")}


def archive(files: dict[str, bytes]) -> bytes:
    if len(files) > MAX_FILES or sum(map(len, files.values())) > MAX_BYTES:
        raise InvalidInput("archive exceeds worker limits")
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.PAX_FORMAT) as archive_file:
        for name, data in sorted(files.items()):
            info = tarfile.TarInfo(relative_name(name))
            info.size = len(data)
            info.mode = 0o644
            info.uid = info.gid = 0
            info.mtime = 0
            archive_file.addfile(info, io.BytesIO(data))
    return output.getvalue()


def read_archive(content: bytes) -> dict[str, bytes]:
    if len(content) > MAX_BYTES:
        raise InvalidInput("archive exceeds worker limits")
    result = {}
    size = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(content), mode="r:*") as archive_file:
            for member in archive_file:
                if len(result) >= MAX_FILES or not member.isfile():
                    raise InvalidInput("archive contains nonregular or excessive members")
                name = relative_name(member.name)
                if name in result:
                    raise InvalidInput("archive contains duplicate paths")
                size += member.size
                if member.size < 0 or size > MAX_BYTES:
                    raise InvalidInput("expanded archive exceeds worker limits")
                stream = archive_file.extractfile(member)
                if stream is None:
                    raise InvalidInput("cannot read archive member")
                data = stream.read(member.size + 1)
                if len(data) != member.size:
                    raise InvalidInput("archive member size mismatch")
                result[name] = data
    except (tarfile.TarError, OSError, ValueError) as exc:
        raise InvalidInput("invalid archive") from exc
    return result


def output_destination(args: dict[str, Any]) -> str:
    value = args.get("output_dir_path")
    if not isinstance(value, str) or not value or "\0" in value:
        raise InvalidInput("output_dir_path must be a nonempty host destination")
    return value
