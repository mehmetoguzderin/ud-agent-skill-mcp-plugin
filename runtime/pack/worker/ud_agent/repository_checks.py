"""Structured adapters for the pinned check_files.pl/udlib check families."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import stat
from typing import Any

from .errors import InvalidInput, PrerequisiteMissing, WorkerError


def _context_assets(manifest_path: Path, repository: Any) -> tuple[Path, Path, dict[str, str]]:
    if not isinstance(repository, dict) or not isinstance(repository.get("assets"), dict) or not repository["assets"]:
        raise PrerequisiteMissing("repository context has no cryptographic data inventory")
    directory = manifest_path.parent.resolve(strict=True)
    fixed_product = str(manifest_path).startswith("/opt/ud-agent/context/")
    trusted_root = os.environ.get("UD_AGENT_CONTEXT_ASSET_ROOT")
    product_root = Path(trusted_root).resolve(strict=True) if trusted_root else Path("/opt/ud-agent") if fixed_product else None

    def asset(value):
        if not isinstance(value, str) or not value or "\x00" in value:
            raise InvalidInput("repository context asset path is invalid")
        path = Path(value)
        if path.is_absolute():
            if product_root is None or ".." in path.parts:
                raise InvalidInput("custom repository context assets must use confined relative paths")
            boundary = product_root
            try:
                relative = path.relative_to(boundary)
            except ValueError as exc:
                raise InvalidInput("repository context asset leaves the verified product root") from exc
        else:
            if "\\" in value or ":" in value or any(part in ("", ".", "..") for part in value.split("/")):
                raise InvalidInput("repository context asset leaves its snapshot")
            boundary, relative = directory, Path(*value.split("/"))
        current = boundary
        for part in relative.parts:
            current = current / part
            if current.is_symlink():
                raise InvalidInput("repository context assets cannot contain symbolic links")
        return current

    languages, docs = asset(repository.get("languages_path")), asset(repository.get("docs_path"))
    inventory, total = {}, 0
    if len(repository["assets"]) > 10000:
        raise InvalidInput("repository context inventory exceeds its limit")
    for name, record in repository["assets"].items():
        path = asset(name)
        if (not isinstance(record, dict) or set(record) != {"sha256", "size_bytes"}
                or not isinstance(record["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", record["sha256"])
                or not isinstance(record["size_bytes"], int) or isinstance(record["size_bytes"], bool)
                or not 0 <= record["size_bytes"] <= 64 * 1024 * 1024 or str(path) in inventory):
            raise InvalidInput("repository context asset receipt is invalid")
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode) or before.st_size != record["size_bytes"]:
                raise InvalidInput("repository context asset does not match its receipt")
            with os.fdopen(descriptor, "rb", closefd=False) as stream:
                data = stream.read(record["size_bytes"] + 1)
            after = os.fstat(descriptor)
            if ((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                    != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
                    or len(data) != record["size_bytes"] or hashlib.sha256(data).hexdigest() != record["sha256"]):
                raise InvalidInput("repository context asset does not match its receipt")
        finally:
            os.close(descriptor)
        total += len(data)
        if total > 64 * 1024 * 1024:
            raise InvalidInput("repository context assets exceed their byte limit")
        inventory[str(path)] = record["sha256"]
    if str(languages) not in inventory or not docs.is_dir():
        raise PrerequisiteMissing("pinned repository context files are unavailable")
    for directory in docs.iterdir():
        if directory.name.startswith("_"):
            if directory.is_symlink():
                raise InvalidInput("documentation assets cannot contain symbolic links")
            index = directory / "index.md"
            if index.is_symlink() or (index.exists() and str(index) not in inventory):
                raise InvalidInput("documentation summary is not in the verified asset inventory")
    return languages, docs, inventory


def repository_checks(root: Path, context: str, options: dict[str, Any], families: list[str]) -> dict[str, Any]:
    name = options.get("repository_name", root.name)
    if not isinstance(name, str) or not re.fullmatch(r"UD_[A-Za-z][A-Za-z0-9_]*(?:-[A-Za-z0-9_]+)?", name):
        raise InvalidInput("repository checks require an explicit logical UD repository_name")
    manifest_path = Path(context)
    if not manifest_path.is_file():
        raise PrerequisiteMissing("repository checks require a pinned context manifest")
    try:
        manifest = json.loads(manifest_path.read_bytes())
        repository = manifest["repository_checks"]
    except (KeyError, TypeError, ValueError, UnicodeError) as exc:
        raise PrerequisiteMissing("context has no complete repository/documentation data receipt") from exc
    languages, docs, asset_hashes = _context_assets(manifest_path, repository)
    if not languages.is_absolute() or not languages.is_file() or not docs.is_absolute() or not docs.is_dir():
        raise PrerequisiteMissing("pinned repository/documentation context is unavailable")
    tools = Path(os.environ.get("UD_AGENT_UDTOOLS", "/opt/ud-agent/upstream"))
    from .perl_runtime import oci_runtime
    image_perl = oci_runtime() if "UD_AGENT_PERL" not in os.environ else None
    perl = Path(os.environ.get("UD_AGENT_PERL", image_perl["executable"] if image_perl else "/usr/bin/perl"))
    bridge = Path(__file__).resolve().parent / "perl/repository_bridge.pl"
    if not tools.is_absolute() or not (tools / "udlib.pm").is_file() or not perl.is_absolute() or not perl.is_file():
        raise PrerequisiteMissing("the pinned Perl repository-check adapter is unavailable")
    with tempfile.TemporaryDirectory(prefix="ud-repository-checks-") as temporary:
        layout = Path(temporary).resolve(strict=True)
        from .domain._artifacts import collect, MAX_FILES
        names, directories = [], []
        for base, child_directories, files in os.walk(root, followlinks=False):
            child_directories[:] = sorted(name for name in child_directories if name not in {".git", ".ud-agent-inputs"})
            for child in child_directories:
                path = Path(base) / child
                if path.is_symlink():
                    raise InvalidInput("repository snapshot cannot contain symbolic links")
                directories.append(path.relative_to(root).as_posix())
            for child in files:
                names.append((Path(base) / child).relative_to(root).as_posix())
            if len(names) + len(directories) > MAX_FILES:
                raise InvalidInput("repository snapshot exceeds its inventory limit")
        captured = collect(root, names)
        bank = layout / name
        bank.mkdir()
        for directory in directories:
            (bank / directory).mkdir(parents=True, exist_ok=True)
        for relative, data in captured.items():
            target = bank / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        request = {"repository_name": name, "layout_root": str(layout), "languages_path": str(languages), "docs_path": str(docs), "check_families": families}
        env = {"PATH": "/usr/bin:/bin", "HOME": str(layout), "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}
        from .perl_runtime import command as perl_command
        invocation = perl_command(perl, bridge, tools)
        env["LANG"] = "C"
        env["LC_ALL"] = "C"
        if os.name == "nt" and "SystemRoot" in os.environ:
            env["SystemRoot"] = os.environ["SystemRoot"]
            env["PATH"] = str(Path(os.environ["SystemRoot"]) / "System32")
        try:
            process = subprocess.run(invocation, input=json.dumps(request).encode("utf-8"),
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=layout, env=env, timeout=120, check=False)
        except subprocess.TimeoutExpired as exc:
            raise WorkerError("REPOSITORY_CHECK_TIMEOUT", "repository/documentation checks timed out") from exc
        except OSError as exc:
            raise WorkerError("REPOSITORY_CHECK_FAILED", "repository/documentation adapter could not start") from exc
    if process.returncode != 0 or len(process.stdout) > 16 * 1024 * 1024 or len(process.stderr) > 1024 * 1024:
        raise WorkerError("REPOSITORY_CHECK_FAILED", "repository/documentation adapter did not complete")
    try:
        result = json.loads(process.stdout)
    except (ValueError, UnicodeError) as exc:
        raise WorkerError("REPOSITORY_CHECK_INCOMPLETE", "repository adapter returned invalid structured output") from exc
    reports = result.get("reports") if isinstance(result, dict) else None
    if not isinstance(reports, list) or [item.get("family") for item in reports if isinstance(item, dict)] != families:
        raise WorkerError("REPOSITORY_CHECK_INCOMPLETE", "repository adapter did not report every requested family")
    incidents = []
    passed = True
    for report in reports:
        if (not isinstance(report.get("passed"), bool) or not isinstance(report.get("error_count"), int)
                or isinstance(report["error_count"], bool) or report["error_count"] < 0
                or not isinstance(report.get("incidents"), list) or any(not isinstance(item, str) for item in report["incidents"])
                or report["passed"] != (report["error_count"] == 0)
                or (report["error_count"] > 0 and not report["incidents"])):
            raise WorkerError("REPOSITORY_CHECK_INCOMPLETE", "repository adapter returned inconsistent coverage")
        passed = passed and report["passed"]
        incidents.extend({"testid": "UD_" + report["family"].upper(), "level": 0, "check_family": report["family"], "message": message}
                         for message in report["incidents"])
    return {"passed": passed, "incidents": incidents, "coverage": {family: "completed" for family in families},
            "provenance": {"repository_name": name, "adapter": "pinned udlib check_files/check_metadata/check_documentation",
                           "languages_sha256": asset_hashes[str(languages)]}}
