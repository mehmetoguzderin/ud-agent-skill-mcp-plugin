#!/usr/bin/env python3
"""Assemble reproducible, hash-locked private userspace assets for selected native hosts."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import struct
import subprocess
import tarfile
import tempfile
import tomllib
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener
import zipfile

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("ud_userspace_core_builder", Path(__file__).with_name("prepare-core-build.py"))
core = importlib.util.module_from_spec(spec)
spec.loader.exec_module(core)
HOSTS = {"darwin/arm64", "darwin/x64", "linux/arm64", "linux/x64", "win32/arm64", "win32/x64"}
SHA = re.compile(r"^sha256:[a-f0-9]{64}$")


def digest(path: Path) -> str:
    with path.open("rb") as source:
        return "sha256:" + hashlib.file_digest(source, "sha256").hexdigest()


def relative(value: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value or ":" in value or "\0" in value or value.startswith("/") or any(part in ("", ".", "..") for part in value.split("/")):
        raise ValueError("unsafe userspace asset path")
    return value


def verify_derived_uv_source_declaration(source_root: Path, host: str, descriptor: dict, original: dict, declaration: dict) -> None:
    """Replay retained build/linkage evidence without the private compiler SDK.

    The release caller admits the exact independent source-duty review first.
    Original UV/crate/Rust archives and the independent STL proof remain separate
    mandatory binders. This checks their binary/link-map join, not a fresh build.
    """
    definition = {key: value for key, value in declaration.items() if key != 'definition_sha256'}
    encoded = json.dumps(definition, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()
    choices = [row for row in original.get('records', []) if row.get('platform') == host]
    if len(choices) != 1 or hashlib.sha256(encoded).hexdigest() != declaration.get('definition_sha256'):
        raise ValueError('source-built uv retained component definition differs')
    record = choices[0]
    expected_build = {'source_commit': original.get('source_commit'), 'version': original.get('version'), 'source_receipt_sha256': original.get('source_receipt_sha256'), 'build_receipt_sha256': original.get('build_receipt_sha256'), 'linkage_receipt_sha256': descriptor['sha256'][7:], 'target_execution': False}
    if (declaration.get('platform') != host or declaration.get('binary_name') != 'uv'
            or declaration.get('binary_sha256') != record['binary']['sha256']
            or declaration.get('original_source_build') != expected_build
            or declaration.get('system_imports') != record.get('imports')
            or declaration.get('license') != 'LicenseRef-Microsoft-VisualStudio-2026-CRT'
            or declaration.get('classification') != 'proprietary-static-object-code'
            or declaration.get('publisher_redistribution_authority') != 'unverified-external'):
        raise ValueError('source-built uv retained source/linkage identity differs')
    declared = [*declaration.get('static_libraries', []), *declaration.get('other_static_components', [])]
    libraries = record.get('libraries', [])
    names = [row['library'] for row in libraries]
    if len(names) != 4 or set(names) != {'libcmt', 'libucrt', 'libvcruntime', 'libcpmt'} or len(declared) != 4:
        raise ValueError('source-built uv retained static library inventory differs')
    objects = []
    for library in libraries:
        matches = [row for row in declared if row.get('library') == library['library']]
        if len(matches) != 1 or any(matches[0].get(key) != value for key, value in {'archive_sha256': library['archive']['sha256'], 'archive_size_bytes': library['archive']['size_bytes'], 'members': library['members']}.items()):
            raise ValueError('source-built uv retained static object identity differs')
        for member in library['members']:
            objects.append({'library': library['library'], 'object': member['name']})
    link_map = declaration.get('link_map', {})
    file = source_root
    for part in relative(link_map.get('path')).split('/'):
        file /= part
        if file.is_symlink(): raise ValueError('source-built uv retained link map contains a link')
    if (link_map.get('sha256') != record['map']['sha256'] or link_map.get('size') != record['map']['size_bytes']
            or not file.is_file() or file.stat().st_size != link_map['size'] or digest(file) != 'sha256:' + link_map['sha256']):
        raise ValueError('source-built uv retained link map differs')
    module = (ROOT / 'scripts/release/windows-linkage.mjs').as_uri()
    code = "import{readFileSync}from'node:fs';import{staticCrtObjectMembers}from" + json.dumps(module) + ";console.log(JSON.stringify(staticCrtObjectMembers(readFileSync(process.argv[1],'utf8'))))"
    checked = subprocess.run(['node', '--input-type=module', '-e', code, str(file)], cwd=ROOT, capture_output=True, timeout=60)
    expected = sorted(objects, key=lambda row: (row['library'], row['object']))
    if checked.returncode or len(checked.stdout) > 8 * 1024 ** 2 or json.loads(checked.stdout) != expected:
        raise ValueError('source-built uv retained link map object inventory differs')


def select_derived_uv(root: Path, host: str, descriptor: dict, *, source_replay: tuple[Path, dict] | None = None) -> tuple[Path, dict]:
    """Select an explicit owned source build without relabeling vendor bytes."""
    if host not in {'win32/arm64', 'win32/x64'} or not isinstance(descriptor, dict) or set(descriptor) != {'path', 'sha256', 'size'} or not SHA.fullmatch(descriptor.get('sha256', '')) or type(descriptor.get('size')) is not int or not 0 < descriptor['size'] <= 8 * 1024 ** 2:
        raise ValueError('invalid explicit source-built uv receipt override')
    file = root
    for part in relative(descriptor['path']).split('/'):
        file /= part
        if file.is_symlink(): raise ValueError('source-built uv receipt path contains a link')
    if not file.is_file() or file.stat().st_size != descriptor['size'] or digest(file) != descriptor['sha256']:
        raise ValueError('source-built uv receipt override is stale')
    original = json.loads(file.read_bytes())
    if source_replay is None:
        module = (ROOT / 'scripts/runtime/finalize-windows-uv.mjs').as_uri()
        code = "import{verifyWindowsUv}from" + json.dumps(module) + ";console.log(JSON.stringify(verifyWindowsUv(process.argv[1])))"
        checked = subprocess.run(['node', '--input-type=module', '-e', code, str(file.parent)], cwd=ROOT, capture_output=True, timeout=300)
        if checked.returncode or len(checked.stdout) > 8 * 1024 ** 2 or json.loads(checked.stdout) != original or digest(file) != descriptor['sha256']:
            raise ValueError('source-built uv original source/linkage verification failed')
    else:
        verify_derived_uv_source_declaration(source_replay[0], host, descriptor, original, source_replay[1])
    if original.get('schema_version') != 1 or original.get('qualification') != 'original-source-crossbuild-linkage-not-native-acceptance' or original.get('source_commit') != '316c827e058c16b71d5c507a20729c2995a7bcce' or original.get('version') != '0.13.7' or original.get('publisher_redistribution_authority') != 'unverified-external':
        raise ValueError('source-built uv source/version/authority differs')
    choices = [row for row in original['records'] if row['platform'] == host]
    if len(choices) != 1 or choices[0].get('target_execution') is not False or choices[0].get('profile') != 'static-msvc-crt' or choices[0].get('private_crt_dlls') != []:
        raise ValueError('source-built uv target inventory differs')
    row = choices[0]['binary']; binary = file.parent
    for part in relative(row['path']).split('/'):
        binary /= part
        if binary.is_symlink(): raise ValueError('source-built uv executable path contains a link')
    if not binary.is_file() or binary.stat().st_size != row['size_bytes'] or digest(binary) != 'sha256:' + row['sha256']:
        raise ValueError('source-built uv executable bytes differ')
    spec = importlib.util.spec_from_file_location('ud_derived_uv_pe', Path(__file__).with_name('windows_pe.py')); pe = importlib.util.module_from_spec(spec); spec.loader.exec_module(pe)
    inspected = pe.inspect_pe(binary.read_bytes(), host.split('/')[1])
    if inspected['imports'] != choices[0]['imports'] or not all(pe.system_dll(name) for name in inspected['imports']):
        raise ValueError('source-built uv imports differ from its exact source recipe')
    return binary, {'kind': 'owned-original-source-crossbuild', 'upstream_source_commit': original['source_commit'], 'upstream_version': original['version'], 'linkage_receipt': descriptor, 'source_receipt_sha256': original['source_receipt_sha256'], 'build_receipt_sha256': original['build_receipt_sha256'], 'publisher_redistribution_authority': 'unverified-external', 'target_execution': False, **({'verification': 'retained-reviewed-source-build-and-link-map'} if source_replay is not None else {})}


class SafeRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, target):
        url = urlsplit(target)
        if url.scheme != "https" or url.hostname not in {"github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com", "files.pythonhosted.org"} or url.username or url.password:
            raise ValueError("userspace acquisition redirected outside its trusted publishers")
        return super().redirect_request(req, fp, code, msg, headers, target)


def acquire(record: dict, cache: Path, download: bool) -> Path:
    url = urlsplit(record.get("url", ""))
    if (url.scheme != "https" or url.hostname not in {"github.com", "files.pythonhosted.org"} or url.username or url.password or url.query or url.fragment
            or not SHA.fullmatch(record.get("sha256", "")) or not isinstance(record.get("size"), int) or not 0 < record["size"] <= 512 * 1024 * 1024):
        raise ValueError("invalid userspace acquisition receipt")
    cache.mkdir(parents=True, exist_ok=True)
    target = cache / record["sha256"][7:]

    def check(path):
        if path.is_symlink() or not path.is_file() or path.stat().st_size != record["size"] or digest(path) != record["sha256"]:
            raise ValueError("userspace acquisition integrity mismatch")

    if target.exists() or target.is_symlink():
        check(target)
        return target
    if not download:
        raise ValueError("verified userspace input is absent from the offline cache")
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(prefix=".userspace-download-", dir=cache, delete=False) as output:
            temporary = Path(output.name)
            with build_opener(SafeRedirect()).open(Request(record["url"], headers={"User-Agent": "ud-agent-build/1"}), timeout=60) as response:
                size = 0
                while chunk := response.read(1024 * 1024):
                    size += len(chunk)
                    if size > record["size"]:
                        raise ValueError("userspace input exceeds its locked size")
                    output.write(chunk)
        check(temporary)
        try:
            os.link(temporary, target)
        except FileExistsError:
            check(target)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return target


def core_packages(uv: dict, tools_commit: str) -> list[dict]:
    packages = {item["name"]: item for item in uv["package"]}
    if not str(packages["udtools"].get("source", {}).get("git", "")).endswith("#" + tools_commit):
        raise ValueError("userspace tools revision differs from the dependency lock")
    pending, found = ["udtools"], set()
    while pending:
        name = pending.pop()
        if name in found:
            continue
        found.add(name)
        if name not in packages:
            raise ValueError("userspace dependency closure is incomplete")
        for dependency in packages[name].get("dependencies", []):
            if set(dependency) != {"name"}:
                raise ValueError("conditional userspace dependencies require an explicit reviewed selector")
            pending.append(dependency["name"])
    return [packages[name] for name in sorted(found - {"udtools"})]


def select_wheels(package: dict, host: str) -> list[dict]:
    os_name, arch = host.split("/")
    native = {"darwin": "arm64" if arch == "arm64" else "x86_64", "linux": "aarch64" if arch == "arm64" else "x86_64", "win32": "win_arm64" if arch == "arm64" else "win_amd64"}[os_name]
    wheels = package.get("wheels", [])
    pure = [item for item in wheels if re.search(r"-(?:py3|py2\.py3)-none-any\.whl$", urlsplit(item["url"]).path)]
    if len(pure) == 1:
        selected = pure
    elif pure:
        raise ValueError("ambiguous pure Python wheel")
    else:
        selected = []
        for abi in ("cp314", "cp315"):
            choices = []
            for item in wheels:
                filename = urlsplit(item["url"]).path.rsplit("/", 1)[-1]
                if f"-{abi}-{abi}-" not in filename:
                    continue
                compatible = ((os_name == "darwin" and "-macosx_" in filename and filename.endswith(f"_{native}.whl"))
                              or (os_name == "linux" and "-manylinux" in filename and filename.endswith(f"_{native}.whl"))
                              or (os_name == "win32" and filename.endswith(f"-{native}.whl")))
                if compatible:
                    choices.append(item)
            if len(choices) != 1:
                raise ValueError(f"missing or ambiguous {abi} wheel for {package['name']} on {host}")
            selected.extend(choices)
    result = []
    for item in selected:
        result.append({"url": item["url"], "sha256": item["hash"], "size": item["size"], "filename": urlsplit(item["url"]).path.rsplit("/", 1)[-1]})
    return result


def extract_uv(archive: Path, record: dict, output: Path, windows: bool) -> None:
    expected = "uv.exe" if windows else "uv"
    matches = []
    if windows:
        with zipfile.ZipFile(archive) as source:
            for item in source.infolist():
                if PurePosixPath(item.filename).name != expected:
                    continue
                if item.is_dir() or item.file_size > 128 * 1024 * 1024 or ((item.external_attr >> 16) & 0o170000) not in (0, 0o100000):
                    raise ValueError("uv archive contains an unsafe executable")
                matches.append(source.read(item))
    else:
        with tarfile.open(archive, "r:gz") as source:
            for item in source:
                if PurePosixPath(item.name).name != expected:
                    continue
                if not item.isfile() or item.size > 128 * 1024 * 1024:
                    raise ValueError("uv archive contains an unsafe executable")
                matches.append(source.extractfile(item).read(item.size + 1))
    if len(matches) != 1:
        raise ValueError("uv archive does not contain exactly one executable")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(matches[0])
    output.chmod(0o755)


def copy_dependency(root: Path, descriptor: dict, destination: Path) -> dict:
    source = root / relative(descriptor["root"])
    if source.is_symlink() or not source.is_dir() or not isinstance(descriptor.get("files"), list) or not descriptor["files"]:
        raise ValueError("native userspace dependency has no verified file inventory")
    seen = set()
    for item in descriptor["files"]:
        name = relative(item["path"])
        if name in seen or not SHA.fullmatch(item.get("sha256", "")):
            raise ValueError("native dependency file identity is invalid")
        seen.add(name)
        path = source / name
        cursor = source
        for component in name.split("/"):
            cursor = cursor / component
            if cursor.is_symlink():
                raise ValueError("native dependency contains a link")
        if not path.is_file() or path.stat().st_size != item["size"] or digest(path) != item["sha256"]:
            raise ValueError("native userspace dependency differs from its receipt")
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, target)
        target.chmod(0o755 if path.stat().st_mode & 0o111 else 0o644)
    return {key: value for key, value in descriptor.items() if key not in ("root", "files")}


def vendor_uv_download(archive: Path, descriptor: dict) -> dict:
    if archive.stat().st_size > 32 * 1024 * 1024:
        raise ValueError("Windows uv archive exceeds the verified runtime reader limit")
    with archive.open("rb") as source, zipfile.ZipFile(source) as package:
        matches = [item for item in package.infolist() if item.filename == "uv.exe"]
        if len(matches) != 1:
            raise ValueError("Windows uv archive must contain one uv.exe")
        member = matches[0]
        mode = member.external_attr >> 16
        if member.flag_bits != 0 or member.compress_type != zipfile.ZIP_DEFLATED or not 0 < member.file_size <= 32 * 1024 * 1024 or (mode & 0o170000) not in (0, 0o100000):
            raise ValueError("Windows uv executable has an unsupported archive representation")
        body = package.read(member)
        source.seek(member.header_offset + 26)
        name_bytes, extra_bytes = struct.unpack("<HH", source.read(4))
        offset = member.header_offset + 30 + name_bytes + extra_bytes
        if not 0 < offset < offset + member.compress_size <= descriptor["size"]:
            raise ValueError("Windows uv executable compressed range is invalid")
    return {
        **{key: descriptor[key] for key in ("url", "sha256", "size")},
        "executable": {
            "sha256": "sha256:" + hashlib.sha256(body).hexdigest(),
            "size": member.file_size,
            "offset": offset,
            "compressed_size": member.compress_size,
        },
    }


def prepare(root: Path, output: Path, hosts: list[str], dependency_lock: Path, download: bool = False, core_only: bool = False) -> dict:
    if output.exists() or output.is_symlink() or not hosts or len(set(hosts)) != len(hosts) or not set(hosts) <= HOSTS:
        raise ValueError("userspace output must be new and platforms must be explicit supported hosts")
    inputs = json.loads((root / "runtime/userspace-inputs.lock.json").read_text())
    if inputs.get("schema_version") != 1 or inputs.get("state") != "frozen-inputs" or set(inputs.get("platforms", {})) != HOSTS:
        raise ValueError("userspace bootstrap inputs are incomplete")
    for receipt in inputs.get("release_receipts", []):
        file = root / relative(receipt["path"])
        if file.is_symlink() or not file.is_file() or file.stat().st_size != receipt["size"] or digest(file) != receipt["sha256"]:
            raise ValueError("userspace publisher receipt differs from its lock")
    dependencies = json.loads(dependency_lock.read_text())
    if dependencies.get("schema_version") != 1 or dependencies.get("state") != "frozen-inputs":
        raise ValueError("native userspace dependency inputs must be frozen")
    source = json.loads((root / "runtime/ud-sources.lock.json").read_text())
    tools = next(item for item in source["sources"] if item["repository"] == "UniversalDependencies/tools")
    packages = core_packages(tomllib.loads((root / "uv.lock").read_text()), tools["commit"])
    cross = json.loads((root / ".artifacts/cross-build-receipt.json").read_text())
    cache = root / ".artifacts/userspace-inputs/cache"
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".userspace-pack-", dir=output.parent) as temporary:
        stage = Path(temporary) / "pack"
        stage.mkdir()
        common = stage / "runtime/pack"
        core.copy_worker(root, common / "worker")
        extracted = Path(temporary) / "upstream"
        rules = core.extract_verified_tools(root / ".artifacts/sources" / f'tools-{tools["commit"]}.tar.gz', tools, extracted)
        upstream = common / "upstream"
        upstream.mkdir(parents=True)
        shutil.copytree(extracted / "udtools/src/udtools", upstream / "udtools")
        for item in extracted.iterdir():
            if item.is_file():
                shutil.copyfile(item, upstream / item.name)
        context = common / "context"
        repository_sources = core.stage_repository_sources(root, source, context)
        hashes = source["tools_rule_sha256"]
        for name, data in rules.items():
            if hashlib.sha256(data).hexdigest() != hashes[name]:
                raise ValueError("userspace rule input differs from the source lock")
            target = context / "rules" / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        repository_assets = {f"{name}/{relative}": {"sha256": value, "size_bytes": (context / name / relative).stat().st_size} for name, receipt in repository_sources.items() for relative, value in receipt["files"].items()}
        context_data = {"schema_version": 1, "rules": hashes, "rule_dir": "rules", "tools_commit": tools["commit"], "context_sha256": hashlib.sha256(json.dumps(hashes, sort_keys=True, separators=(",", ":")).encode()).hexdigest(), "repository_checks": {"languages_path": "docs-automation/codes_and_flags.yaml", "docs_path": "docs", "source_receipts": repository_sources, "assets": repository_assets}}
        (context / "context.json").write_text(json.dumps(context_data, sort_keys=True, indent=2) + "\n")
        manifest = {"schema_version": 1, "format_revision": 2, "product_version": "0.1.0-beta.1", "state": "frozen", "platforms": {}, "bootstrap_assets": []}
        common_files = [path for path in common.rglob("*") if path.is_file()]
        for host in hosts:
            bootstrap = inputs["platforms"][host]
            native = dependencies.get("platforms", {}).get(host)
            if not isinstance(native, dict) or "perl" not in native or (not core_only and not ("render" in native or "lazy_render" in native)):
                raise ValueError(f"native Perl and render dependency contracts are required for {host}")
            slug = host.replace("/", "-")
            guard = cross.get("platforms", {}).get(slug, {}).get("ud-agent-guard")
            if not guard or digest(root / relative(guard["path"])) != "sha256:" + guard["sha256"]:
                raise ValueError("userspace native helper receipt is absent or stale")
            guard_path = stage / "runtime/helpers" / host / ("ud-agent-guard.exe" if host.startswith("win32/") else "ud-agent-guard")
            guard_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(root / guard["path"], guard_path)
            guard_path.chmod(0o755)
            wheels_dir = common / "wheels" / slug
            wheels_dir.mkdir(parents=True)
            lines = []
            for package in packages:
                wheels = select_wheels(package, host)
                for wheel in wheels:
                    shutil.copyfile(acquire(wheel, cache, download), wheels_dir / wheel["filename"])
                lines.append(f'{package["name"]}=={package["version"]} ' + " ".join("--hash=" + value for value in sorted({item["sha256"] for item in wheels})))
            requirements = common / "requirements" / (slug + ".txt")
            requirements.parent.mkdir(parents=True, exist_ok=True)
            requirements.write_text("\n".join(lines) + "\n")
            uv_path = stage / "runtime/bootstrap" / ("uv-" + slug + (".exe" if host.startswith("win32/") else ""))
            override = native.get('derived_uv', inputs.get('derived_uv', {}).get(host))
            if native.get('derived_uv') is not None and inputs.get('derived_uv', {}).get(host) is not None and native['derived_uv'] != inputs['derived_uv'][host]: raise ValueError('conflicting source-built uv overrides')
            if host.startswith("win32/") and override is None:
                uv_archive = acquire(bootstrap["uv_archive"], cache, download)
                uv_download = {"uv_vendor_download": vendor_uv_download(uv_archive, bootstrap["uv_archive"])}
            else:
                origin = {'kind': 'upstream-vendor-binary', 'archive': bootstrap['uv_archive']}
                if override is not None:
                    original_binary, origin = select_derived_uv(root, host, override)
                    uv_path.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(original_binary, uv_path)
                    uv_path.chmod(0o755)
                else:
                    uv_archive = acquire(bootstrap["uv_archive"], cache, download)
                    extract_uv(uv_archive, bootstrap["uv_archive"], uv_path, False)
                asset = {"url": "https://github.com/mehmetoguzderin/ud-agent-skill-mcp-plugin/releases/download/v0.1.0-beta.1/" + uv_path.name, "sha256": digest(uv_path), "size": uv_path.stat().st_size}
                manifest["bootstrap_assets"].append({"id": "uv-" + slug, "path": uv_path.relative_to(stage).as_posix(), **asset, 'origin': origin})
                uv_download = {"uv_download": asset}
            perl_dir = common / "native" / slug / "perl"
            perl = copy_dependency(root, native["perl"], perl_dir)
            loader = perl.get("loader")
            deferred_runtime = perl.get('deferred_runtime')
            perl = {"executable": (perl_dir / relative(perl["executable"])).relative_to(stage).as_posix(), "library_dirs": [(perl_dir / relative(name)).relative_to(stage).as_posix() for name in perl["library_dirs"]]}
            supplier_perl = False
            if deferred_runtime is not None:
                if host not in ('win32/arm64', 'win32/x64') or set(deferred_runtime) != {'provider', 'recipe'} or deferred_runtime['provider'] != 'conda-vc-runtime':
                    raise ValueError('private Perl vendor dependency contract is invalid')
                vendor_recipe = perl_dir / relative(deferred_runtime['recipe'])
                perl['deferred_runtime'] = {'provider': deferred_runtime['provider'], 'recipe': vendor_recipe.relative_to(stage).as_posix()}
                supplier = json.loads(vendor_recipe.read_bytes()).get('supplier')
                if supplier is not None:
                    supplier_perl = any((vendor_recipe.parent / relative(row['path'])).relative_to(stage).as_posix() == perl["executable"] for row in supplier['files'])
                    if not supplier_perl or (stage / perl["executable"]).exists():
                        raise ValueError('private Perl supplier recipe does not replace the executable')
            if loader is not None:
                if not isinstance(loader, dict) or set(loader) != {"executable", "library_dirs"} or not isinstance(loader["library_dirs"], list) or not loader["library_dirs"]:
                    raise ValueError("private Perl loader contract is invalid")
                perl["loader"] = {"executable": (perl_dir / relative(loader["executable"])).relative_to(stage).as_posix(), "library_dirs": [(perl_dir / relative(name)).relative_to(stage).as_posix() for name in loader["library_dirs"]]}
            executable = stage / perl["executable"]
            if (not supplier_perl and (not executable.is_file() or not executable.stat().st_mode & 0o111)) or any(not (stage / name).is_dir() for name in perl["library_dirs"]):
                raise ValueError("private Perl executable or module directories are missing")
            item = {"packs": ["core"], "worker": "runtime/pack/worker", "upstream": "runtime/pack/upstream", "context": "runtime/pack/context/context.json", "bootstrap": "runtime/pack/worker/ud_agent/userspace_bootstrap.py", "guard": guard_path.relative_to(stage).as_posix(), "requirements": requirements.relative_to(stage).as_posix(), "wheels": wheels_dir.relative_to(stage).as_posix(), **uv_download, "python_download": bootstrap["python_download"], "perl": perl}
            native_files = [path for path in perl_dir.rglob("*") if path.is_file()]
            if "render" in native:
                render_dir = common / "native" / slug / "render"
                render = copy_dependency(root, native["render"], render_dir)
                item["render"] = {"manifest": (render_dir / relative(render["manifest"])).relative_to(stage).as_posix()}
                item["packs"].append("render")
                native_files.extend(path for path in render_dir.rglob("*") if path.is_file())
            elif "lazy_render" in native:
                lazy = native["lazy_render"]
                if (not isinstance(lazy, dict) or set(lazy) != {"url", "sha256", "size", "manifest"}
                        or lazy["url"] != f"https://github.com/mehmetoguzderin/ud-agent-skill-mcp-plugin/releases/download/v0.1.0-beta.1/ud-agent-render-{slug}.tar.gz"
                        or not SHA.fullmatch(lazy.get("sha256", "")) or not isinstance(lazy.get("size"), int) or not 0 < lazy["size"] <= 2 * 1024 * 1024 * 1024):
                    raise ValueError("lazy render acquisition contract is invalid")
                relative(lazy["manifest"])
                item["lazy_render"] = native["lazy_render"]
            files = common_files + [guard_path, requirements] + list(wheels_dir.iterdir()) + native_files
            item["files"] = [{"path": path.relative_to(stage).as_posix(), "sha256": digest(path), "size": path.stat().st_size} for path in sorted(files)]
            manifest["platforms"][host] = item
        (stage / "runtime/userspace.lock.json").write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n")
        os.rename(stage, output)
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--dependencies", type=Path, required=True)
    parser.add_argument("--platform", action="append", choices=sorted(HOSTS))
    parser.add_argument("--download", action="store_true")
    parser.add_argument("--core-only", action="store_true", help="build an explicitly core-only development pack; render remains unavailable")
    args = parser.parse_args()
    published = json.loads((ROOT / 'packages/npm-distribution/platforms.json').read_bytes())
    hosts = args.platform or [platform.replace('-', '/') for platform in published]
    data = prepare(ROOT, args.output, hosts, args.dependencies, args.download, args.core_only)
    print(json.dumps({"output": str(args.output), "platforms": sorted(data["platforms"]), "userspace_sha256": digest(args.output / "runtime/userspace.lock.json")}))


if __name__ == "__main__":
    main()
