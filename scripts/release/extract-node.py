#!/usr/bin/env python3
"""Extract only the verified Node executable and license from one distribution."""
from __future__ import annotations
import argparse
import hashlib
import os
from pathlib import Path
import re
import stat
import tarfile
import zipfile


def extract(archive: Path, output: Path, platform: str, version: str, expected: str) -> None:
    if not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise ValueError("invalid Node archive checksum")
    if archive.is_symlink() or not archive.is_file():
        raise ValueError("Node distribution is not a regular file")
    with archive.open("rb") as stream:
        if hashlib.file_digest(stream, "sha256").hexdigest() != expected:
            raise ValueError("Node distribution checksum mismatch")
    if platform not in {"darwin-arm64", "darwin-x64", "linux-arm64", "linux-x64", "win32-arm64", "win32-x64"} or not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise ValueError("unsupported Node platform or version")
    dist_platform = platform.replace("win32-", "win-")
    prefix = f"node-v{version}-{dist_platform}/"
    executable = "node.exe" if platform.startswith("win32-") else "bin/node"
    wanted = {prefix + executable: output / "bin" / ("node.exe" if platform.startswith("win32-") else "node"),
              prefix + "LICENSE": output / "LICENSE"}
    data = {}
    if platform.startswith("win32-"):
        with zipfile.ZipFile(archive) as source:
            for entry in source.infolist():
                if entry.filename not in wanted:
                    continue
                mode = entry.external_attr >> 16
                if entry.filename in data or entry.is_dir() or stat.S_ISLNK(mode) or entry.file_size > 256 * 1024 * 1024:
                    raise ValueError("invalid Node archive member")
                data[entry.filename] = source.read(entry)
    else:
        with tarfile.open(archive, "r:xz") as source:
            for entry in source:
                if entry.name not in wanted:
                    continue
                if entry.name in data or not entry.isfile() or entry.size > 256 * 1024 * 1024:
                    raise ValueError("invalid Node archive member")
                stream = source.extractfile(entry)
                if stream is None:
                    raise ValueError("Node archive member cannot be read")
                data[entry.name] = stream.read(entry.size + 1)
                if len(data[entry.name]) != entry.size:
                    raise ValueError("Node archive member length mismatch")
    if set(data) != set(wanted):
        raise ValueError("Node archive is missing its executable or license")
    if output.exists() or output.is_symlink():
        raise ValueError("Node output directory already exists")
    for name, target in wanted.items():
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("xb") as stream:
            stream.write(data[name])
        target.chmod(0o755 if target.parent.name == "bin" else 0o644)
        os.utime(target, (0, 0))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--platform", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--sha256", required=True)
    args = parser.parse_args()
    extract(args.archive, args.output, args.platform, args.version, args.sha256)


if __name__ == "__main__":
    main()
