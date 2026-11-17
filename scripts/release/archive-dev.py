#!/usr/bin/env python3
"""Create a deterministic, local-only candidate archive from a contained tree."""
from __future__ import annotations
import argparse
import gzip
import importlib.util
import os
from pathlib import Path
import tarfile
import zipfile

ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location('ud_release_archive_unicode', ROOT / 'workers/ud/src/ud_agent/unicode_paths.py')
_paths = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_paths)


def executable(item: Path) -> bool:
    # libuv reports no execute bits for regular Windows files. Python adds
    # synthetic bits for executable extensions; omit those to match fileReceipt.
    return os.name != 'nt' and bool(item.stat().st_mode & 0o111)


def _record_path(seen: dict, logical: str, directory: bool) -> None:
    _paths.validate_path(logical)
    components = logical.split('/')
    for count in range(1, len(components) + 1):
        current = '/'.join(components[:count])
        current_directory = directory if count == len(components) else True
        key = _paths.path_key(current)
        prior = seen.get(key)
        if prior is not None and not (prior[1] and current_directory):
            raise ValueError(f"archive source contains a Unicode16 file or directory conflict: {prior[0]} and {current}")
        if prior is None:
            seen[key] = (current, current_directory)


def archive(source: Path, output: Path, fmt: str) -> None:
    if source.is_symlink() or not source.is_dir() or output.exists() or output.is_symlink():
        raise ValueError("invalid source or existing output")
    entries = [];seen = {}
    for directory, dirs, files in os.walk(source, followlinks=False):
        base = Path(directory)
        for name in sorted(dirs + files):
            item = base / name
            if item.is_symlink() or not (item.is_file() or item.is_dir()):
                raise ValueError("archive source contains an unsafe entry")
            logical = item.relative_to(source).as_posix()
            _record_path(seen, logical, item.is_dir())
            entries.append(item)
    entries.sort(key=lambda item: item.relative_to(source).as_posix())
    output.parent.mkdir(parents=True, exist_ok=True)
    if fmt == "zip":
        with zipfile.ZipFile(output, "x", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as stream:
            for item in entries:
                name = item.relative_to(source).as_posix() + ("/" if item.is_dir() else "")
                info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
                info.create_system = 3
                info.external_attr = ((0o40755 if item.is_dir() else (0o100755 if executable(item) else 0o100644)) << 16)
                info.compress_type = zipfile.ZIP_DEFLATED
                stream.writestr(info, b"" if item.is_dir() else item.read_bytes())
    elif fmt == "tar.gz":
        with output.open("xb") as raw:
            with gzip.GzipFile(filename="", fileobj=raw, mode="wb", mtime=0, compresslevel=9) as compressed:
                with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as stream:
                    for item in entries:
                        name = item.relative_to(source).as_posix()
                        info = tarfile.TarInfo(name + ("/" if item.is_dir() else ""))
                        info.mtime = info.uid = info.gid = 0
                        info.uname = info.gname = ""
                        info.mode = 0o755 if item.is_dir() or executable(item) else 0o644
                        if item.is_dir():
                            info.type = tarfile.DIRTYPE
                            stream.addfile(info)
                        else:
                            info.size = item.stat().st_size
                            with item.open("rb") as data:
                                stream.addfile(info, data)
    else:
        raise ValueError("unsupported candidate archive format")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--format", choices=("zip", "tar.gz"), required=True)
    args = parser.parse_args()
    archive(args.source, args.output, args.format)


if __name__ == "__main__":
    main()
