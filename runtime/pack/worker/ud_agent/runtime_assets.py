"""Extract only a hash-bound, closed render dependency inventory."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import stat
import tarfile

if __package__:
    from .unicode_paths import path_key as shared_path_key, validate_path
else:
    # Setup invokes this verified product file directly with Python -I. Resolve
    # its adjacent verified helper explicitly, never through ambient sys.path.
    _spec = importlib.util.spec_from_file_location('_ud_agent_asset_paths', Path(__file__).with_name('unicode_paths.py'))
    if _spec is None or _spec.loader is None:
        raise RuntimeError('RENDER_ARCHIVE_PATH_RULES_UNAVAILABLE')
    _paths = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_paths)
    shared_path_key, validate_path = _paths.path_key, _paths.validate_path

MAX_TOTAL = 2 * 1024**3
MAX_FILE = 512 * 1024**2


def relative(value: str) -> str:
    try:
        return validate_path(value)
    except ValueError as exc:
        raise ValueError("RENDER_ARCHIVE_PATH_INVALID") from exc


def extract(archive: str, expected: str, size: int, directory: str, manifest: str) -> None:
    """The destination is a newly owned empty directory; links are forbidden."""
    manifest = relative(manifest)
    root = Path(directory)
    if root.is_symlink() or not root.is_dir() or any(root.iterdir()):
        raise ValueError("RENDER_ARCHIVE_DESTINATION_INVALID")
    descriptor = os.open(archive, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        with os.fdopen(descriptor, "rb", closefd=False) as source:
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode) or before.st_size != size:
                raise ValueError("RENDER_ARCHIVE_INTEGRITY_FAILED")
            digest = hashlib.file_digest(source, "sha256").hexdigest()
            after = os.fstat(descriptor)
            if ("sha256:" + digest != expected or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                    != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
                raise ValueError("RENDER_ARCHIVE_INTEGRITY_FAILED")
            source.seek(0)
            with tarfile.open(fileobj=source, mode="r:gz") as bundle:
                members, names, total = [], set(), 0
                for item in bundle:
                    name = relative(item.name.rstrip("/") if item.isdir() else item.name)
                    key = shared_path_key(name)
                    if key in names or len(names) >= 20000 or not (item.isdir() or item.isfile()) or item.size < 0 or item.size > MAX_FILE:
                        raise ValueError("RENDER_ARCHIVE_MEMBER_INVALID")
                    names.add(key)
                    total += item.size
                    if total > MAX_TOTAL:
                        raise ValueError("RENDER_ARCHIVE_LIMIT_EXCEEDED")
                    members.append((name, item))
                kinds = {shared_path_key(name): item.isdir() for name, item in members}
                for name, _ in members:
                    parts = shared_path_key(name).split('/')
                    if any(kinds.get('/'.join(parts[:index])) is False for index in range(1, len(parts))):
                        raise ValueError("RENDER_ARCHIVE_MEMBER_INVALID")
                selected = next((item for name, item in members if name == manifest and item.isfile()), None)
                if selected is None or selected.size > 1024**2:
                    raise ValueError("RENDER_ARCHIVE_MANIFEST_MISSING")
                reader = bundle.extractfile(selected)
                if reader is None:
                    raise ValueError("RENDER_ARCHIVE_MANIFEST_MISSING")
                with reader:
                    receipt = json.load(reader)
                if not isinstance(receipt, dict) or receipt.get("schema_version") != 1 or not isinstance(receipt.get("files"), list):
                    raise ValueError("RENDER_ARCHIVE_MANIFEST_INVALID")
                parent = PurePosixPath(manifest).parent
                expected_files = {}
                for item in receipt["files"]:
                    if not isinstance(item, dict) or set(item) != {"path", "sha256", "size_bytes"}:
                        raise ValueError("RENDER_ARCHIVE_MANIFEST_INVALID")
                    name = str(parent / relative(item["path"]))
                    if name in expected_files or name == manifest or not isinstance(item["size_bytes"], int) or isinstance(item["size_bytes"], bool) or not 0 <= item["size_bytes"] <= MAX_FILE:
                        raise ValueError("RENDER_ARCHIVE_MANIFEST_INVALID")
                    expected_files[name] = item
                executable = str(parent / relative(receipt.get("executable")))
                deferred = receipt.get('deferred_browser')
                if deferred is not None:
                    google = isinstance(deferred, dict) and deferred.get('provider') == 'google-chrome-for-testing'
                    if (not isinstance(deferred, dict)
                            or set(deferred) != ({'provider', 'recipe', 'directory'} if google else {'provider', 'recipe', 'decoder', 'directory'})
                            or deferred.get('provider') not in {'microsoft-edge', 'google-chrome-for-testing'}):
                        raise ValueError('RENDER_ARCHIVE_DEFERRED_BROWSER_INVALID')
                    recipe_name = str(parent / relative(deferred['recipe']))
                    decoder_name = None if google else str(parent / relative(deferred['decoder']))
                    browser_directory = str(parent / relative(deferred['directory']))
                    if (recipe_name not in expected_files or (not google and (decoder_name not in expected_files or recipe_name == decoder_name))
                            or (not google and executable != browser_directory + '/msedge.exe')
                            or (google and (not executable.startswith(browser_directory + '/') or executable == browser_directory + '/'))
                            or any(name == browser_directory or name.startswith(browser_directory + '/') for name in expected_files)):
                        raise ValueError('RENDER_ARCHIVE_DEFERRED_BROWSER_INVALID')
                if ((deferred is None and executable not in expected_files)
                        or set(expected_files) | {manifest} != {name for name, item in members if item.isfile()}):
                    raise ValueError("RENDER_ARCHIVE_INVENTORY_MISMATCH")
                # Validate the whole inventory before creating any destination file.
                for name, item in members:
                    if not item.isfile() or name == manifest:
                        continue
                    expected_file = expected_files[name]
                    reader = bundle.extractfile(item)
                    if reader is None:
                        raise ValueError("RENDER_ARCHIVE_INTEGRITY_FAILED")
                    with reader:
                        digest = hashlib.file_digest(reader, "sha256").hexdigest()
                    if item.size != expected_file["size_bytes"] or digest != expected_file["sha256"]:
                        raise ValueError("RENDER_ARCHIVE_INTEGRITY_FAILED")
                for name, item in members:
                    target = root.joinpath(*name.split("/"))
                    if item.isdir():
                        target.mkdir(parents=True, exist_ok=True, mode=0o700)
                        continue
                    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                    reader = bundle.extractfile(item)
                    if reader is None:
                        raise ValueError("RENDER_ARCHIVE_INTEGRITY_FAILED")
                    with reader, target.open("xb") as output:
                        for chunk in iter(lambda: reader.read(1024**2), b""):
                            output.write(chunk)
                        output.flush()
                        os.fsync(output.fileno())
                    target.chmod(0o700 if name == executable or item.mode & 0o111 else 0o600)
    finally:
        os.close(descriptor)


if __name__ == "__main__":
    import sys
    extract(sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4], sys.argv[5])
