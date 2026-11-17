"""Receive bounded snapshot frames for authenticated, isolated worker jobs.

Wire: newline-terminated UTF-8 JSON objects corresponding to the TypeScript
SnapshotFrame contract. The only mapping is chunk.bytes -> chunk.bytes_base64
(canonical padded RFC 4648 base64). The trusted expected manifest digest is a
separate argument from the authenticated broker, never derived from frames.
Successful staging is not proof of a read-only mount or engine isolation.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import secrets
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

MAX_FRAME = 8 * 1024 * 1024
MAX_FILES = 10_000
MAX_FILE = 64 * 1024 * 1024
MAX_TOTAL = 512 * 1024 * 1024
MAX_CHUNK = 64 * 1024
MAX_PATH = 4096

# Same standalone-safe frozen implementation is used by runtime asset setup.
from .unicode_paths import assigned16 as _assigned16, frozen_nfc as _frozen_nfc, path_key as _path_key, validate_path as _validate_path


def _bad(message: str) -> ValueError:
    return ValueError(f"SNAPSHOT_TRANSFER_INVALID: {message}")


def _object_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise _bad("duplicate JSON object key")
        result[key] = value
    return result


def _frames(stream: BinaryIO):
    while True:
        line = stream.readline(MAX_FRAME + 1)
        if not line:
            return
        if len(line) > MAX_FRAME or not line.endswith(b"\n"):
            raise _bad("oversized or truncated frame")
        try:
            frame = json.loads(line.decode("utf-8", "strict"), object_pairs_hook=_object_pairs,
                               parse_constant=lambda _: (_ for _ in ()).throw(_bad("invalid number")))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise _bad("invalid JSON frame") from exc
        if not isinstance(frame, dict):
            raise _bad("frame is not an object")
        yield frame


def _path(value: object) -> str:
    try:
        return _validate_path(value)
    except ValueError as exc:
        raise _bad(str(exc)) from exc


def _digest(value: object) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(ch in "0123456789abcdef" for ch in value)


def _manifest(value: object, expected: str) -> list[dict[str, object]]:
    if not isinstance(value, list) or len(value) > MAX_FILES:
        raise _bad("invalid manifest")
    files = []
    normalized = set()
    previous = None
    total = 0
    file_paths = set()
    for item in value:
        if not isinstance(item, dict) or set(item) != {"path", "size", "sha256"}:
            raise _bad("invalid manifest entry")
        name = _path(item["path"])
        sort_key = name.encode("utf-16-be")  # JavaScript compares UTF-16 code units.
        key = _path_key(name)
        if (previous is not None and sort_key <= previous) or key in normalized:
            raise _bad("duplicate, unsorted or colliding path")
        previous = sort_key
        normalized.add(key)
        size = item["size"]
        if type(size) is not int or size < 0 or size > MAX_FILE or not _digest(item["sha256"]):
            raise _bad("invalid manifest size or digest")
        total += size
        if total > MAX_TOTAL:
            raise _bad("total size limit")
        files.append({"path": name, "size": size, "sha256": item["sha256"]})
        file_paths.add(key)
    for name in file_paths:
        parts = name.split("/")
        if any("/".join(parts[:i]) in file_paths for i in range(1, len(parts))):
            raise _bad("file and directory path conflict")
    # This matches JSON.stringify for the restricted strings and exact key order.
    encoded = json.dumps(files, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
    if hashlib.sha256(encoded).hexdigest() != expected:
        raise _bad("manifest digest mismatch")
    return files


def _remove_contents(directory: int) -> None:
    for name in os.listdir(directory):
        info = os.stat(name, dir_fd=directory, follow_symlinks=False)
        if stat.S_ISDIR(info.st_mode):
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            try:
                _remove_contents(child)
            finally:
                os.close(child)
            os.rmdir(name, dir_fd=directory)
        else:
            os.unlink(name, dir_fd=directory)


@dataclass
class StagedSnapshot:
    """Owns a tentative directory; caller must cleanup even after success."""
    parent_fd: int
    directory_fd: int
    name: str
    path: str
    _closed: bool = False

    def promote(self, name: str) -> None:
        """Move a verified snapshot to a fixed name in its owned parent.

        This is used by a short-lived OCI loader before a separate worker
        mounts that volume read-only. The caller owns the destination volume.
        """
        if self._closed or name != "data":
            raise RuntimeError("SNAPSHOT_TRANSFER_PROMOTION_INVALID")
        original = os.fstat(self.directory_fd)
        current = os.stat(self.name, dir_fd=self.parent_fd, follow_symlinks=False)
        if (original.st_dev, original.st_ino) != (current.st_dev, current.st_ino):
            raise RuntimeError("SNAPSHOT_TRANSFER_PROMOTION_UNVERIFIED")
        try:
            os.stat(name, dir_fd=self.parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise RuntimeError("SNAPSHOT_TRANSFER_PROMOTION_CONFLICT")
        os.rename(self.name, name, src_dir_fd=self.parent_fd, dst_dir_fd=self.parent_fd)
        self.name = name
        self.path = os.path.join(os.path.dirname(self.path), name)
        os.fsync(self.parent_fd)
        os.close(self.directory_fd)
        os.close(self.parent_fd)
        self._closed = True

    def cleanup(self) -> None:
        if self._closed:
            return
        try:
            _remove_contents(self.directory_fd)
            original = os.fstat(self.directory_fd)
            current = os.stat(self.name, dir_fd=self.parent_fd, follow_symlinks=False)
            if (original.st_dev, original.st_ino) != (current.st_dev, current.st_ino):
                raise RuntimeError("SNAPSHOT_TRANSFER_CLEANUP_UNVERIFIED")
            os.rmdir(self.name, dir_fd=self.parent_fd)
        finally:
            os.close(self.directory_fd)
            os.close(self.parent_fd)
            self._closed = True

    def __enter__(self) -> "StagedSnapshot":
        return self

    def __exit__(self, *_args: object) -> None:
        self.cleanup()



def _windows_directory(path: str) -> os.stat_result:
    info = os.lstat(path)
    if not stat.S_ISDIR(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
        raise _bad("staging directory is a reparse point or is not a directory")
    return info


def _remove_windows_contents(path: str) -> None:
    identity = _windows_directory(path)
    for entry in os.scandir(path):
        info = entry.stat(follow_symlinks=False)
        if getattr(info, "st_file_attributes", 0) & 0x400:
            raise RuntimeError("SNAPSHOT_TRANSFER_CLEANUP_UNVERIFIED")
        if stat.S_ISDIR(info.st_mode):
            _remove_windows_contents(entry.path)
            os.rmdir(entry.path)
        elif stat.S_ISREG(info.st_mode):
            os.unlink(entry.path)
        else:
            raise RuntimeError("SNAPSHOT_TRANSFER_CLEANUP_UNVERIFIED")
    current = _windows_directory(path)
    if (identity.st_dev, identity.st_ino) != (current.st_dev, current.st_ino):
        raise RuntimeError("SNAPSHOT_TRANSFER_CLEANUP_UNVERIFIED")


@dataclass
class WindowsStagedSnapshot:
    """Private userspace staging; its ACL is verified by the native launcher."""
    parent_path: str
    name: str
    path: str
    parent_identity: tuple[int, int]
    identity: tuple[int, int]
    _closed: bool = False

    @property
    def directory_fd(self) -> str:
        return self.path

    def cleanup(self) -> None:
        if self._closed:
            return
        parent = _windows_directory(self.parent_path)
        current = _windows_directory(self.path)
        if ((parent.st_dev, parent.st_ino) != self.parent_identity
                or (current.st_dev, current.st_ino) != self.identity):
            raise RuntimeError("SNAPSHOT_TRANSFER_CLEANUP_UNVERIFIED")
        _remove_windows_contents(self.path)
        os.rmdir(self.path)
        self._closed = True

    def __enter__(self) -> "WindowsStagedSnapshot":
        return self

    def __exit__(self, *_args: object) -> None:
        self.cleanup()


    def promote(self, name: str) -> None:
        if self._closed or name != "data":
            raise RuntimeError("SNAPSHOT_TRANSFER_PROMOTION_INVALID")
        parent = _windows_directory(self.parent_path)
        current = _windows_directory(self.path)
        if ((parent.st_dev, parent.st_ino) != self.parent_identity
                or (current.st_dev, current.st_ino) != self.identity):
            raise RuntimeError("SNAPSHOT_TRANSFER_PROMOTION_UNVERIFIED")
        destination = os.path.join(self.parent_path, name)
        if os.path.lexists(destination):
            raise RuntimeError("SNAPSHOT_TRANSFER_PROMOTION_CONFLICT")
        os.rename(self.path, destination)
        self.name, self.path, self._closed = name, destination, True


def _create_file(stage_fd: int | str, path: str) -> int:
    parts = path.split("/")
    if isinstance(stage_fd, str):
        _windows_directory(stage_fd)
        parent = stage_fd
        for part in parts[:-1]:
            parent = os.path.join(parent, part)
            try:
                os.mkdir(parent, 0o700)
            except FileExistsError:
                pass
            _windows_directory(parent)
        return os.open(os.path.join(parent, parts[-1]), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
    parent = os.dup(stage_fd)
    try:
        for part in parts[:-1]:
            try:
                os.mkdir(part, 0o700, dir_fd=parent)
            except FileExistsError:
                pass
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            os.close(parent)
            parent = child
        return os.open(parts[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
    finally:
        os.close(parent)


def receive_snapshot(stream: BinaryIO, expected_sha256: str, staging_parent: str,
                     *, stop_at_end: bool = False) -> StagedSnapshot | WindowsStagedSnapshot:
    """Verify all frames and stage files; cleanup is mandatory for the caller."""
    if not _digest(expected_sha256) or not os.path.isabs(staging_parent):
        raise _bad("trusted digest or staging directory is invalid")
    if os.name == "nt":
        info = _windows_directory(staging_parent)
        name = f"snapshot-{secrets.token_hex(16)}"
        stage_path = os.path.join(staging_parent, name)
        os.mkdir(stage_path, 0o700)
        stage_info = _windows_directory(stage_path)
        stage = WindowsStagedSnapshot(staging_parent, name, stage_path,
                                     (info.st_dev, info.st_ino), (stage_info.st_dev, stage_info.st_ino))
    else:
        parent_fd = os.open(staging_parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        info = os.fstat(parent_fd)
        if not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o077 or info.st_uid != os.geteuid():
            os.close(parent_fd)
            raise _bad("staging parent is not private and user-owned")
        try:
            name = f"snapshot-{secrets.token_hex(16)}"
            os.mkdir(name, 0o700, dir_fd=parent_fd)
            try:
                stage_fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
            except BaseException:
                os.rmdir(name, dir_fd=parent_fd)
                raise
        except BaseException:
            os.close(parent_fd)
            raise
        stage = StagedSnapshot(parent_fd, stage_fd, name, os.path.join(staging_parent, name))
    active_fd = None
    try:
        files = None
        index = 0
        offset = 0
        hasher = hashlib.sha256()
        ended = False
        for frame in _frames(stream):
            if ended:
                raise _bad("frame after end")
            kind = frame.get("type")
            if files is None:
                if set(frame) != {"type", "manifest", "snapshot_sha256"} or kind != "begin" or frame["snapshot_sha256"] != expected_sha256:
                    raise _bad("missing or mismatched begin")
                files = _manifest(frame["manifest"], expected_sha256)
                continue
            if kind == "end":
                if set(frame) != {"type", "snapshot_sha256"} or frame["snapshot_sha256"] != expected_sha256 or index != len(files) or active_fd is not None:
                    raise _bad("premature or mismatched end")
                ended = True
                if stop_at_end:
                    break
                continue
            if index >= len(files):
                raise _bad("unexpected file frame")
            file = files[index]
            if kind == "chunk":
                if set(frame) != {"type", "path", "offset", "bytes_base64"} or frame["path"] != file["path"] or type(frame["offset"]) is not int or frame["offset"] != offset or not isinstance(frame["bytes_base64"], str) or len(frame["bytes_base64"]) > ((MAX_CHUNK + 2) // 3) * 4:
                    raise _bad("invalid chunk")
                try:
                    data = base64.b64decode(frame["bytes_base64"], validate=True)
                except (binascii.Error, ValueError) as exc:
                    raise _bad("invalid chunk encoding") from exc
                if not data or len(data) > MAX_CHUNK or base64.b64encode(data).decode("ascii") != frame["bytes_base64"] or offset + len(data) > file["size"]:
                    raise _bad("invalid chunk size or encoding")
                if active_fd is None:
                    active_fd = _create_file(stage.directory_fd, file["path"])
                remaining = memoryview(data)
                while remaining:
                    count = os.write(active_fd, remaining)
                    if count <= 0:
                        raise OSError("short write")
                    remaining = remaining[count:]
                hasher.update(data)
                offset += len(data)
            elif kind == "file_end":
                if set(frame) != {"type", "path"} or frame["path"] != file["path"] or offset != file["size"] or hasher.hexdigest() != file["sha256"]:
                    raise _bad("file size or digest mismatch")
                if active_fd is None:
                    active_fd = _create_file(stage.directory_fd, file["path"])
                os.close(active_fd)
                active_fd = None
                index += 1
                offset = 0
                hasher = hashlib.sha256()
            else:
                raise _bad("unexpected frame")
        if files is None or not ended:
            raise _bad("incomplete transfer")
        return stage
    except BaseException:
        close_error = None
        if active_fd is not None:
            try:
                os.close(active_fd)
            except OSError as exc:
                close_error = exc
        try:
            stage.cleanup()
        except BaseException as exc:
            raise RuntimeError("SNAPSHOT_TRANSFER_CLEANUP_UNVERIFIED") from exc
        if close_error is not None:
            raise RuntimeError("SNAPSHOT_TRANSFER_CLEANUP_UNVERIFIED") from close_error
        raise
