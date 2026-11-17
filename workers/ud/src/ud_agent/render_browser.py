"""Verified, bounded offline Chromium exports for generated static documents."""
from __future__ import annotations

import hashlib
import json
import os
import platform
from pathlib import Path
import stat
import struct
import subprocess
import sys
import tempfile
import zlib

from .errors import PrerequisiteMissing, WorkerError

MAX_OUTPUT = 64 * 1024 * 1024
MAX_RECEIPT = 1024 * 1024
DEFAULT_RECEIPT = "/opt/ud-agent/render/manifest.json"
MAX_PIXELS = 16_000_000


def _png(data: bytes, width: int, height: int) -> bool:
    """Check chunk integrity and bounded complete pixel data, not just magic."""
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        return False
    offset, chunks, compressed, header = 8, [], [], None
    while offset + 12 <= len(data):
        size = struct.unpack(">I", data[offset:offset + 4])[0]
        kind = data[offset + 4:offset + 8]
        end = offset + 12 + size
        if end > len(data):
            return False
        payload = data[offset + 8:offset + 8 + size]
        checksum = struct.unpack(">I", data[offset + 8 + size:end])[0]
        if zlib.crc32(kind + payload) & 0xFFFFFFFF != checksum:
            return False
        if kind == b"IHDR":
            if chunks or size != 13:
                return False
            header = struct.unpack(">IIBBBBB", payload)
        elif kind == b"IDAT":
            compressed.append(payload)
        elif kind == b"IEND":
            if size != 0 or end != len(data):
                return False
        elif not kind[0] & 0x20:
            return False
        chunks.append(kind)
        offset = end
    if (offset != len(data) or not chunks or chunks[-1] != b"IEND" or not compressed or header is None
            or header[:3] != (width, height, 8) or header[3] not in (2, 6) or header[4:] != (0, 0, 0)):
        return False
    stride = width * (3 if header[3] == 2 else 4) + 1
    maximum = stride * height
    try:
        decoder = zlib.decompressobj()
        pixels = decoder.decompress(b"".join(compressed), maximum + 1)
        if len(pixels) != maximum or not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:
            return False
    except zlib.error:
        return False
    return all(pixels[index] <= 4 for index in range(0, len(pixels), stride))


def _regular(path: str, maximum: int) -> tuple[bytes, os.stat_result]:
    value = Path(path)
    if not value.is_absolute() or ".." in value.parts:
        raise WorkerError("RENDER_INTEGRITY_FAILED", "render paths must be absolute")
    current = Path(value.anchor)
    for component in value.parts[1:]:
        current = current / component
        if current.is_symlink():
            raise WorkerError("RENDER_INTEGRITY_FAILED", "render paths cannot contain symbolic links")
    descriptor = os.open(value, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size > maximum or getattr(before, "st_file_attributes", 0) & 0x400:
            raise WorkerError("RENDER_INTEGRITY_FAILED", "render file is not a bounded ordinary file")
        with os.fdopen(descriptor, "rb", closefd=False) as source:
            data = source.read(maximum + 1)
        after = os.fstat(descriptor)
        if (len(data) != before.st_size or len(data) > maximum
                or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
            raise WorkerError("RENDER_INTEGRITY_FAILED", "render file changed during verification")
        return data, before
    finally:
        os.close(descriptor)


def _pack_path(value: str, directory: Path) -> str:
    if Path(value).is_absolute():
        return value
    if (not value or "\\" in value or ":" in value or "\x00" in value
            or any(part in ("", ".", "..") for part in value.split("/"))):
        raise WorkerError("RENDER_INTEGRITY_FAILED", "relative render paths must remain inside their pack")
    return str(directory.joinpath(*value.split("/")))


def _verified_pack(installation_root: str | None = None) -> tuple[str, str, list[bytes], list[str], list[str], dict[str, str]]:
    """Read only a bootstrap-selected product receipt, never project options."""
    filename = os.environ.get("UD_AGENT_RENDER_MANIFEST", DEFAULT_RECEIPT)
    try:
        raw, _ = _regular(filename, MAX_RECEIPT)
    except FileNotFoundError as exc:
        raise PrerequisiteMissing("a verified offline browser renderer is required in the render pack") from exc
    try:
        receipt = json.loads(raw)
    except (ValueError, UnicodeError) as exc:
        raise WorkerError("RENDER_INTEGRITY_FAILED", "render receipt is invalid JSON") from exc
    if (not isinstance(receipt, dict) or receipt.get("schema_version") != 1
            or not isinstance(receipt.get("executable"), str)
            or not isinstance(receipt.get("files"), list) or not 1 <= len(receipt["files"]) <= 10000):
        raise WorkerError("RENDER_INTEGRITY_FAILED", "render receipt is incomplete")
    seen, total = set(), 0
    requested_fonts = receipt.get("fonts", [])
    if (not isinstance(requested_fonts, list) or len(requested_fonts) > 16
            or any(not isinstance(item, str) for item in requested_fonts) or len(set(requested_fonts)) != len(requested_fonts)):
        raise WorkerError("RENDER_INTEGRITY_FAILED", "render font selection must contain at most sixteen distinct paths")
    selected_fonts = {_pack_path(item, Path(filename).parent) for item in requested_fonts}
    font_data = {}
    directory = Path(filename).parent
    executable = _pack_path(receipt["executable"], directory)
    loader = receipt.get("loader")
    prefix = []
    loader_executable = None
    loader_directories = []
    direct = False
    if loader is not None:
        direct = isinstance(loader, dict) and loader.get("mode") == "direct"
        if (sys.platform != "linux" or not isinstance(loader, dict)
                or set(loader) != ({"executable", "library_dirs", "mode", "installed_root"} if direct else {"executable", "library_dirs"})
                or not isinstance(loader["executable"], str) or not isinstance(loader["library_dirs"], list)
                or not 1 <= len(loader["library_dirs"]) <= 64
                or any(not isinstance(value, str) or Path(value).is_absolute() for value in [loader["executable"], *loader["library_dirs"]])
                or len(set(loader["library_dirs"])) != len(loader["library_dirs"])):
            raise WorkerError("RENDER_INTEGRITY_FAILED", "private render loader receipt is invalid")
        loader_executable = _pack_path(loader["executable"], directory)
        loader_directories = [_pack_path(value, directory) for value in loader["library_dirs"]]
        prefix = [loader_executable, "--inhibit-cache", "--library-path", os.pathsep.join(loader_directories)]
        if any(os.pathsep in value for value in loader_directories):
            raise WorkerError("RENDER_INTEGRITY_FAILED", "render library paths contain the loader separator")
        if direct:
            installed_root = loader["installed_root"]
            projected = installation_root if installation_root is not None else str(directory)
            if (not isinstance(installed_root, str) or not isinstance(projected, str)
                    or not Path(installed_root).is_absolute() or not Path(projected).is_absolute()
                    or ".." in Path(installed_root).parts or ".." in Path(projected).parts
                    or Path(installed_root) != Path(projected)):
                raise WorkerError("RENDER_INTEGRITY_FAILED", "render interpreter is bound to another installation root")
            prefix = []
    loader_verified = loader_executable is None
    executable_verified = False
    elf_requirements = set()
    fontconfig = receipt.get("fontconfig")
    configuration = {}
    if fontconfig is not None:
        if sys.platform != "linux" or not isinstance(fontconfig, str) or Path(fontconfig).is_absolute():
            raise WorkerError("RENDER_INTEGRITY_FAILED", "private Fontconfig configuration is invalid")
        fontconfig = _pack_path(fontconfig, directory)
        configuration = {"FONTCONFIG_FILE": fontconfig, "FONTCONFIG_PATH": str(Path(fontconfig).parent)}
    if direct and not configuration:
        raise WorkerError("RENDER_INTEGRITY_FAILED", "private Fontconfig configuration is required")
    for item in receipt["files"]:
        if (not isinstance(item, dict) or set(item) != {"path", "sha256", "size_bytes"}
                or not isinstance(item["path"], str)
                or not isinstance(item["sha256"], str) or len(item["sha256"]) != 64
                or any(char not in "0123456789abcdef" for char in item["sha256"])
                or not isinstance(item["size_bytes"], int) or isinstance(item["size_bytes"], bool)
                or not 0 <= item["size_bytes"] <= 512 * 1024 * 1024):
            raise WorkerError("RENDER_INTEGRITY_FAILED", "render file receipt is invalid")
        file = _pack_path(item["path"], directory)
        if file in seen:
            raise WorkerError("RENDER_INTEGRITY_FAILED", "render receipt contains a duplicate file")
        data, info = _regular(file, 512 * 1024 * 1024)
        total += len(data)
        if total > 2 * 1024 * 1024 * 1024 or len(data) != item["size_bytes"] or hashlib.sha256(data).hexdigest() != item["sha256"]:
            raise WorkerError("RENDER_INTEGRITY_FAILED", "render file does not match its receipt")
        if file == executable:
            if os.name != "nt" and (not info.st_mode & 0o111 or info.st_mode & 0o022):
                raise WorkerError("RENDER_INTEGRITY_FAILED", "render executable permissions are unsafe")
            executable_verified = True
        if direct and data.startswith(b"\x7fELF"):
            from .elf_runtime import inspect as inspect_elf
            try:
                elf_info = inspect_elf(data)
            except (ValueError, UnicodeError) as error:
                raise WorkerError("RENDER_INTEGRITY_FAILED", "render ELF inventory is invalid") from error
            # A shared libc may itself carry PT_INTERP for its optional version
            # command. Only the admitted browser executable is kernel-executed;
            # DT_NEEDED libraries use the already admitted loader.
            if elf_info["search_paths"] or (file == executable and elf_info["interpreter"] != str(Path(loader["installed_root"]) / loader["executable"])):
                raise WorkerError("RENDER_INTEGRITY_FAILED", "render ELF interpreter or search paths differ from their receipt")
            machine = platform.machine().lower()
            expected_machine = 183 if machine in {"arm64", "aarch64"} else 62 if machine in {"amd64", "x86_64"} else None
            if elf_info["machine"] != expected_machine:
                raise WorkerError("RENDER_INTEGRITY_FAILED", "render ELF architecture differs from the selected host")
            elf_requirements.update(elf_info["needed"])
        if file == loader_executable:
            if os.name != "nt" and (not info.st_mode & 0o111 or info.st_mode & 0o022):
                raise WorkerError("RENDER_INTEGRITY_FAILED", "render loader permissions are unsafe")
            loader_verified = True
        if file in selected_fonts:
            if Path(file).suffix.lower() not in {".ttf", ".otf"} or sum(map(len, font_data.values())) + len(data) > 64 * 1024 * 1024:
                raise WorkerError("RENDER_INTEGRITY_FAILED", "render fonts must be bounded individual SFNT font files")
            font_data[file] = data
        seen.add(file)
    if not executable_verified:
        raise WorkerError("RENDER_INTEGRITY_FAILED", "render executable is not in the verified file inventory")
    if selected_fonts != set(font_data):
        raise WorkerError("RENDER_INTEGRITY_FAILED", "render fonts are absent from the verified file inventory")
    if not loader_verified or any(not any(Path(file).parent == Path(value) for file in seen) for value in loader_directories):
        raise WorkerError("RENDER_INTEGRITY_FAILED", "render loader closure is absent from the verified file inventory")
    for value in loader_directories:
        path = Path(value)
        if path.is_symlink() or not path.is_dir():
            raise WorkerError("RENDER_INTEGRITY_FAILED", "render loader directory is unsafe")
        for child in path.iterdir():
            if child.is_symlink() or not child.is_file() or str(child) not in seen:
                raise WorkerError("RENDER_INTEGRITY_FAILED", "render loader directory contains an unverified entry")
    if direct:
        available = {Path(file).name for file in seen if str(Path(file).parent) in loader_directories}
        if not elf_requirements <= available:
            raise WorkerError("RENDER_INTEGRITY_FAILED", "render ELF dependency is absent from the verified private library directories")
    if fontconfig is not None and fontconfig not in seen:
        raise WorkerError("RENDER_INTEGRITY_FAILED", "private Fontconfig configuration is absent from its inventory")
    return executable, hashlib.sha256(raw).hexdigest(), [font_data[_pack_path(item, directory)] for item in requested_fonts], prefix, loader_directories if direct else [], configuration


def verified_renderer(*, installation_root: str | None = None) -> tuple[str, str]:
    executable, receipt_hash, _, _, _, _ = _verified_pack(installation_root)
    return executable, receipt_hash


def browser_export(html: bytes, output_format: str, width: int, height: int) -> tuple[bytes, str]:
    if (output_format not in {"png", "pdf"} or not 1 <= width <= 32000 or not 1 <= height <= 32000
            or width * height > MAX_PIXELS):
        raise WorkerError("RENDER_REQUEST_INVALID", "render format or dimensions are invalid")
    executable, receipt_hash, fonts, prefix, private_libraries, configuration = _verified_pack()
    from .render_fonts import embed_fonts
    html = embed_fonts(html, fonts)
    with tempfile.TemporaryDirectory(prefix="ud-render-") as temporary:
        directory = Path(temporary).resolve(strict=True)
        source = directory / "document.html"
        destination = directory / ("output." + output_format)
        source.write_bytes(html)
        source.chmod(0o400)
        command = [*prefix, executable, "--headless", "--no-first-run", "--no-default-browser-check",
                   "--disable-background-networking", "--disable-component-update", "--disable-default-apps",
                   "--disable-extensions", "--disable-sync", "--metrics-recording-only", "--password-store=basic",
                   "--disable-dev-shm-usage", "--disable-gpu", "--disable-software-rasterizer",
                   "--renderer-process-limit=1", "--num-raster-threads=1",
                   "--hide-scrollbars", "--force-device-scale-factor=1", f"--user-data-dir={directory / 'profile'}",
                   f"--window-size={width},{height}", "--virtual-time-budget=1000"]
        if output_format == "png":
            command.append(f"--screenshot={destination}")
        else:
            command.extend([f"--print-to-pdf={destination}", "--no-pdf-header-footer"])
        command.append(source.as_uri())
        env = {"HOME": temporary, "USERPROFILE": temporary, "PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}
        env.update(configuration)
        if os.name == "nt" and "SystemRoot" in os.environ:
            env["SystemRoot"] = os.environ["SystemRoot"]
        try:
            execution = command
            if sys.platform == "linux":
                # The wrapper owns only its Chromium descendants, adopts orphaned
                # helpers, and verifies their cleanup before this worker proceeds.
                module_root = str(Path(__file__).resolve().parents[1])
                bootstrap = "import sys;sys.path.insert(0," + repr(module_root) + ");from ud_agent.render_process import main;raise SystemExit(main())"
                framed = {"command": command, "library_dirs": private_libraries} if private_libraries else command
                execution = [sys.executable, "-I", "-B", "-c", bootstrap, json.dumps(framed, ensure_ascii=False)]
            result = subprocess.run(execution, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                    timeout=60, check=False, env=env, cwd=directory)
        except subprocess.TimeoutExpired as exc:
            raise WorkerError("RENDER_TIMEOUT", "offline browser export timed out") from exc
        except OSError as exc:
            raise WorkerError("RENDER_FAILED", "offline browser could not start") from exc
        if result.returncode == 124:
            raise WorkerError("RENDER_TIMEOUT", "offline browser export timed out after verified owned-process cleanup")
        if result.returncode != 0:
            raise WorkerError("RENDER_FAILED", "offline browser did not complete with its sandbox enabled")
        try:
            data, _ = _regular(str(destination), MAX_OUTPUT)
        except (OSError, WorkerError) as exc:
            raise WorkerError("RENDER_OUTPUT_INVALID", "offline browser produced no bounded ordinary output") from exc
        if output_format == "png":
            if not _png(data, width, height):
                raise WorkerError("RENDER_OUTPUT_INVALID", "browser output is not the requested PNG")
        elif not data.startswith(b"%PDF-") or b"%%EOF" not in data[-1024:]:
            raise WorkerError("RENDER_OUTPUT_INVALID", "browser output is not a complete PDF")
        return data, receipt_hash
