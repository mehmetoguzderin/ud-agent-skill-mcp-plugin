"""Reconcile frozen Perl inputs with Debian's signed snapshot, then stage offline."""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile

_HEX = re.compile(r"^[0-9a-f]{64}$")
_DEB = re.compile(r"^[A-Za-z0-9+_.:~%-]+\.deb$")
_FINGERPRINT = re.compile(r"^[0-9A-F]{40}$")
_ARCHES = ("amd64", "arm64")
_MAX_INDEX = 100 * 1024 * 1024
_MAX_ARCHIVE = 64 * 1024 * 1024
_MAX_PACKAGE = 256 * 1024 * 1024


def _read(path: Path, size: int, digest: str, maximum: int) -> bytes:
    if not isinstance(size, int) or isinstance(size, bool) or size < 0 or size > maximum or not isinstance(digest, str) or not _HEX.fullmatch(digest):
        raise ValueError("invalid locked Perl input size or digest")
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"missing or unsafe locked Perl input: {path}")
    data = path.read_bytes()
    if len(data) != size or sha256(data).hexdigest() != digest:
        raise ValueError(f"locked Perl input does not match: {path}")
    return data


def _safe_filename(value: object, *, deb: bool = False) -> str:
    if not isinstance(value, str) or not value or Path(value).name != value or "/" in value or "\\" in value or value in (".", ".."):
        raise ValueError("invalid Perl input filename")
    if deb and not _DEB.fullmatch(value):
        raise ValueError("invalid Debian package filename")
    return value


def _release_hashes(data: bytes) -> dict[str, tuple[str, int]]:
    try:
        lines = data.decode("utf-8").splitlines()
        start = lines.index("SHA256:") + 1
    except (ValueError, UnicodeDecodeError) as exc:
        raise ValueError("signed Debian release has no SHA256 section") from exc
    result: dict[str, tuple[str, int]] = {}
    for line in lines[start:]:
        if not line.startswith(" "):
            break
        parts = line.split()
        if len(parts) != 3 or not _HEX.fullmatch(parts[0]) or not parts[1].isdigit() or parts[2] in result:
            raise ValueError("malformed signed Debian index record")
        result[parts[2]] = (parts[0], int(parts[1]))
    return result


def _package_records(data: bytes, needed: set[tuple[str, str, str]]) -> dict[tuple[str, str, str], dict[str, str]]:
    result: dict[tuple[str, str, str], dict[str, str]] = {}
    try:
        paragraphs = data.decode("utf-8").split("\n\n")
    except UnicodeDecodeError as exc:
        raise ValueError("Debian package index is not UTF-8") from exc
    for paragraph in paragraphs:
        fields: dict[str, str] = {}
        for line in paragraph.splitlines():
            if line and not line[0].isspace() and ": " in line:
                key, value = line.split(": ", 1)
                if key in fields:
                    raise ValueError("duplicate Debian package field")
                fields[key] = value
        key = (fields.get("Package", ""), fields.get("Version", ""), fields.get("Architecture", ""))
        if key in needed:
            if key in result:
                raise ValueError("duplicate Debian package identity in index")
            result[key] = fields
    return result


def _verify_release(path: Path, keyring: Path, allowed: list[str]) -> None:
    if not isinstance(allowed, list) or not allowed or any(not isinstance(value, str) or not _FINGERPRINT.fullmatch(value) for value in allowed):
        raise ValueError("invalid Debian signer inventory")
    try:
        result = subprocess.run(["gpgv", "--status-fd", "1", "--keyring", str(keyring.resolve()), str(path.resolve())],
                                capture_output=True, text=True, timeout=30, check=False)
    except FileNotFoundError:
        # Debian 13 ships apt with sqv, so gpgv may be absent. gpg --verify
        # with a private empty home emits the same VALIDSIG status lines, and
        # the same exact signing-key checks below apply.
        try:
            with tempfile.TemporaryDirectory(prefix="ud-gpg-") as home:
                result = subprocess.run(["gpg", "--batch", "--no-options", "--homedir", home, "--no-default-keyring", "--status-fd", "1", "--keyring", str(keyring.resolve()), "--verify", str(path.resolve())],
                                        capture_output=True, text=True, timeout=30, check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ValueError("Debian signature verifier unavailable") from exc
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValueError("Debian signature verifier unavailable") from exc
    signatures = set(re.findall(r"^\[GNUPG:\] VALIDSIG ([A-F0-9]{40}) ", result.stdout, re.MULTILINE))
    if result.returncode != 0 or not signatures.intersection(allowed) or re.search(r"^\[GNUPG:\] (?:BADSIG|ERRSIG|EXPSIG|REVKEYSIG)", result.stdout, re.MULTILINE):
        raise ValueError("Debian release signature is not trusted")


def _verify_debian(root: Path, arch: str, config: dict, signers: dict, *, cache_name: str = "perl-debs") -> list[tuple[dict, Path]]:
    if cache_name not in ("perl-debs", "render-debs") or arch not in _ARCHES:
        raise ValueError("invalid Debian input cache")
    base = root / ".artifacts" / cache_name / arch
    evidence = base / "evidence"
    index_dir = root / ".artifacts/perl-index" / arch
    files = config.get("evidence")
    indexes = config.get("indexes")
    packages = config.get("packages")
    if not isinstance(files, list) or not isinstance(indexes, list) or not isinstance(packages, list) or not packages:
        raise ValueError("incomplete Perl package provenance")
    locked_files = {}
    for item in files:
        filename = _safe_filename(item["file"])
        if filename in locked_files:
            raise ValueError("duplicate Debian evidence")
        locked_files[filename] = _read(evidence / filename, item["size"], item["sha256"], _MAX_INDEX)
    keyring_name = "debian-archive-keyring.gpg"
    if keyring_name not in locked_files:
        raise ValueError("Debian keyring receipt missing")
    releases = {}
    for source in ("main", "security"):
        pattern = "_debian-security_" if source == "security" else "_debian_"
        names = [name for name in locked_files if pattern in name and name.endswith("_InRelease")]
        if len(names) != 1:
            raise ValueError("Debian signed release is missing or ambiguous")
        _verify_release(evidence / names[0], evidence / keyring_name, signers[source])
        releases[source] = _release_hashes(locked_files[names[0]])
    needed: set[tuple[str, str, str]] = set()
    names: set[str] = set()
    for item in packages:
        filename = _safe_filename(item["file"], deb=True)
        key = (item["name"], item["version"], item["architecture"])
        if filename in names or key in needed or item["architecture"] not in (arch, "all"):
            raise ValueError("duplicate or wrong-architecture Debian package")
        names.add(filename)
        needed.add(key)
    found = {}
    for index in indexes:
        source = index["source"]
        if source not in releases or index["release_path"] != f"main/binary-{arch}/Packages":
            raise ValueError("invalid Debian package index origin")
        filename = _safe_filename(index["file"])
        data = _read(index_dir / filename, index["size"], index["sha256"], _MAX_INDEX)
        if releases[source].get(index["release_path"]) != (index["sha256"], index["size"]):
            raise ValueError("Debian package index differs from signed release")
        for key, fields in _package_records(data, needed).items():
            existing = found.setdefault(key, [])
            if any(any(previous.get(name) != fields.get(name) for name in ("SHA256", "Size")) for _, previous in existing):
                raise ValueError("Debian package identity has conflicting origins")
            if any(previous_source == source for previous_source, _ in existing):
                raise ValueError("duplicate Debian package index origin")
            existing.append((source, fields))
    output = []
    for item in packages:
        key = (item["name"], item["version"], item["architecture"])
        origins = [fields for source, fields in found.get(key, []) if source == item["source"]]
        if len(origins) != 1:
            raise ValueError("Debian package is missing from its signed index")
        fields = origins[0]
        if fields.get("SHA256") != item["sha256"] or fields.get("Size") != str(item["size"]) or fields.get("Filename") != item["repository_path"]:
            raise ValueError("Debian package differs from its signed index")
        filename = _safe_filename(item["file"], deb=True)
        package = base / "debs" / filename
        _read(package, item["size"], item["sha256"], _MAX_PACKAGE)
        output.append((item, package))
    return output


def _extract_interset(archive: Path, record: dict, destination: Path) -> None:
    commit = record.get("commit")
    if not isinstance(commit, str) or not re.fullmatch(r"[0-9a-f]{40}", commit) or record.get("repository") != "https://github.com/dan-zeman/interset":
        raise ValueError("invalid Interset source identity")
    _read(archive, record["archive_size"], record["archive_sha256"], _MAX_ARCHIVE)
    prefix = f"interset-{commit}/"
    destination.mkdir(parents=True)
    seen: set[str] = set()
    total = 0
    with tarfile.open(archive, "r:gz") as stream:
        for member in stream:
            if not member.name.startswith(prefix):
                if member.name == prefix[:-1] and member.isdir():
                    continue
                raise ValueError("Interset archive has an unexpected root")
            rel = member.name[len(prefix):]
            if not rel or any(part in ("", ".", "..") for part in rel.split("/")) or "\\" in rel:
                raise ValueError("unsafe Interset archive path")
            if not (rel == "LICENSE.txt" or rel.startswith("lib/")):
                continue
            if rel in seen or not (member.isdir() or member.isfile()) or member.size > _MAX_ARCHIVE:
                raise ValueError("unsafe or duplicate Interset archive member")
            seen.add(rel)
            if member.isdir():
                continue
            total += member.size
            if total > _MAX_ARCHIVE:
                raise ValueError("Interset archive exceeds size budget")
            source = stream.extractfile(member)
            if source is None:
                raise ValueError("cannot read Interset archive member")
            data = source.read(member.size + 1)
            if len(data) != member.size:
                raise ValueError("truncated Interset archive member")
            target = destination.joinpath(*rel.split("/"))
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open("xb") as output:
                output.write(data)
    if "LICENSE.txt" not in seen or "lib/Lingua/Interset/Converter.pm" not in seen:
        raise ValueError("Interset source or license is missing")


def stage(root: Path, destination: Path) -> dict:
    lock_path = root / "runtime/perl-deps.lock.json"
    if lock_path.is_symlink() or not lock_path.is_file():
        raise ValueError("Perl dependency lock is unavailable")
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    if lock.get("schema_version") != 1 or lock.get("state") != "frozen-inputs" or set(lock["debian"]["architectures"]) != set(_ARCHES):
        raise ValueError("Perl dependency lock is incomplete")
    image = json.loads((root / "runtime/core-image.lock.json").read_text(encoding="utf-8"))
    if lock.get("base_image") != f'{image.get("image")}@{image.get("index_digest")}':
        raise ValueError("Perl dependencies are bound to a different base image")
    checked = {arch: _verify_debian(root, arch, lock["debian"]["architectures"][arch], lock["debian"]["signed_by"]) for arch in _ARCHES}
    if destination.exists() or destination.is_symlink():
        raise ValueError("Perl build destination already exists")
    destination.mkdir(parents=True)
    try:
        for arch in _ARCHES:
            dest = destination / "debs" / arch
            dest.mkdir(parents=True)
            lines = []
            for record, source in checked[arch]:
                shutil.copyfile(source, dest / record["file"])
                lines.append(f'{record["sha256"]}  {record["file"]}')
            (dest / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")
        source = lock["interset"]
        archive = root / ".artifacts/perl-sources" / _safe_filename(source["archive"])
        _extract_interset(archive, source, destination / "interset")
    except Exception:
        shutil.rmtree(destination)
        raise
    return {"lock_sha256": sha256(lock_path.read_bytes()).hexdigest(), "interset_commit": lock["interset"]["commit"],
            "packages": {arch: len(checked[arch]) for arch in _ARCHES}}
