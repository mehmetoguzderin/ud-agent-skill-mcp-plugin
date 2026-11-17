#!/usr/bin/env python3
"""Build a private relocatable Perl interpreter and pinned UD module closure."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shutil
import subprocess
import tarfile
import tempfile
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("ud_native_perl_modules", ROOT / "scripts/quality/prepare-perl-parser.py")
modules = importlib.util.module_from_spec(spec)
spec.loader.exec_module(modules)
MODULE_ROOTS = ["Moose", "MooseX::SemiAffordanceAccessor", "namespace::autoclean", "List::MoreUtils", "YAML", "JSON::Parse", "File::Which", "LWP::Simple", "Exporter::Easy"]


def source_lock(filename):
    info = modules.fetch_json("https://fastapi.metacpan.org/v1/release/perl")
    if info.get("status") != "latest" or info.get("maturity") != "released" or not re.fullmatch(r"[a-f0-9]{64}", info.get("checksum_sha256", "")):
        raise ValueError("Perl source is not a current stable verified release")
    record = {"schema_version": 1, "state": "frozen-inputs", "name": info["name"], "version": str(info["version"]), "url": info["download_url"], "sha256": info["checksum_sha256"], "license": info.get("license", []), "configuration": ["-des", "-Duserelocatableinc", "-Uuseshrplib", "-Dman1dir=none", "-Dman3dir=none"], "windows_configuration": ["CCTYPE=MSVC145", "USE_NO_REGISTRY=define", "DEFAULT_INC_EXCLUDES_DOT=define", "USE_SITECUST=undef"]}
    with filename.open("x", encoding="utf-8") as target:
        json.dump(record, target, sort_keys=True, indent=2); target.write("\n")
    return record


def build_commands(record, source, install, system, target=None):
    if system == "Windows":
        if target is not None and target not in ("win32/arm64", "win32/x64"):
            raise ValueError("Windows Perl target requires Windows arm64 or x64")
        configuration = record.get("windows_configuration")
        if configuration != ["CCTYPE=MSVC145", "USE_NO_REGISTRY=define", "DEFAULT_INC_EXCLUDES_DOT=define", "USE_SITECUST=undef"]:
            raise ValueError("a frozen supported MSVC Windows recipe is required")
        architecture = target.rsplit("/", 1)[1] if target else ("arm64" if platform.machine().lower() in ("arm64", "aarch64") else "x64")
        selected = [*configuration, "WIN64=define", "PROCESSOR_ARCHITECTURE=" + ("ARM64" if architecture == "arm64" else "AMD64")]
        return source / "win32", [["nmake", "/NOLOGO", "/f", "Makefile", *selected, "INST_TOP=" + str(install)], ["nmake", "/NOLOGO", "/f", "Makefile", *selected, "INST_TOP=" + str(install), "install"]]
    if system not in ("Darwin", "Linux"):
        raise ValueError("native Perl requires a supported native build host")
    prefix=[]
    flags=[]
    if target is not None:
        expected={'Darwin':{'darwin/arm64','darwin/x64'},'Linux':{'linux/arm64','linux/x64'}}[system]
        if target not in expected: raise ValueError('native Perl target requires its matching operating system')
        actual='arm64' if platform.machine().lower() in ('arm64','aarch64') else 'x64'
        if target.rsplit('/',1)[1]!=actual:
            if system!='Darwin' or target!='darwin/x64': raise ValueError('native Perl cross-architecture build requires a verified native or emulated provider')
            subprocess.run(['arch','-x86_64','/usr/bin/true'],check=True,timeout=10)
            prefix=['arch','-x86_64']
            flags=['-Dcc=clang -arch x86_64','-Dld=clang -arch x86_64','-Dccflags=-arch x86_64','-Dldflags=-arch x86_64']
    return source, [[*prefix,"sh", "Configure", *record["configuration"], *flags, "-Dprefix=" + str(install)], [*prefix,"make", "-j4"], [*prefix,"make", "install"]]


def build(record, output, download, target=None, build_timeout=900):
    selected_target = target
    if not isinstance(build_timeout,(int,float))or not 1<=build_timeout<=7200:
        raise ValueError('native Perl build timeout must be bounded')
    if output.exists() or output.is_symlink() or record.get("schema_version") != 1 or record.get("state") != "frozen-inputs":
        raise ValueError("native Perl output must be new and source inputs frozen")
    cache = ROOT / ".artifacts/native-perl/cache"
    cache.mkdir(parents=True, exist_ok=True)
    archive = cache / (record["name"] + ".tar.gz")
    if not archive.exists():
        if not download:
            raise ValueError("Perl source is missing from the offline cache")
        with urlopen(record["url"], timeout=60) as source:
            data = source.read(64 * 1024 * 1024 + 1)
        if len(data) > 64 * 1024 * 1024 or hashlib.sha256(data).hexdigest() != record["sha256"]:
            raise ValueError("Perl source hash mismatch")
        with archive.open("xb") as target:
            target.write(data)
    if archive.is_symlink() or hashlib.sha256(archive.read_bytes()).hexdigest() != record["sha256"]:
        raise ValueError("Perl source differs from its frozen receipt")
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".native-perl-", dir=output.parent) as temporary:
        work = Path(temporary)
        source = work / "source"
        source.mkdir()
        seen, total = set(), 0
        with tarfile.open(archive, "r:gz") as tar:
            for item in tar:
                parts = PurePosixPath(item.name).parts
                if len(parts) == 1 and item.isdir():
                    continue
                if not parts or parts[0] != record["name"] or ".." in parts or item.name.startswith("/") or "\\" in item.name:
                    raise ValueError("Perl source archive contains an unsafe path")
                relative = "/".join(parts[1:])
                if relative in seen or len(seen) > 100000:
                    raise ValueError("Perl source archive inventory is invalid")
                seen.add(relative)
                target = source / relative
                if item.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                elif item.isfile() and item.size <= 16 * 1024 * 1024:
                    total += item.size
                    if total > 512 * 1024 * 1024:
                        raise ValueError("Perl source archive exceeds its size bound")
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(tar.extractfile(item).read(item.size + 1))
                    target.chmod(0o755 if item.mode & 0o111 else 0o644)
                elif item.issym():
                    # Source symlinks are materialized only when their final
                    # regular target is within the verified source archive.
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.symlink_to(item.linkname)
                else:
                    raise ValueError("Perl source archive contains a special file")
        for link in source.rglob("*"):
            if link.is_symlink() and source.resolve() not in link.resolve(strict=True).parents:
                raise ValueError("Perl source link escapes its verified root")
        install = work / "runtime"
        env = {key: value for key, value in os.environ.items() if key not in ("PERL5LIB", "PERL5OPT", "PERL_MM_OPT", "PERL_MB_OPT") and not re.search("TOKEN|PASSWORD|SECRET|CREDENTIAL", key, re.I)}
        env["HOME"] = str(work)
        working_directory, commands = build_commands(record, source, install, platform.system(), selected_target)
        for args in commands:
            result = subprocess.run(args, cwd=working_directory, env=env, capture_output=True, text=True, timeout=build_timeout)
            with (output.parent / (record["name"] + "-build.log")).open("a", encoding="utf-8") as log:
                log.write(result.stdout + "\n" + result.stderr)
            if result.returncode:
                raise ValueError("native Perl build failed: " + result.stderr[-1000:])
        shutil.copytree(install, output, symlinks=False)
        licenses = output / "share/licenses/perl"
        licenses.mkdir(parents=True)
        for name in ("Artistic", "Copying", "README"):
            shutil.copyfile(source / name, licenses / name)
        return str((output / ("bin/perl.exe" if platform.system() == "Windows" else "bin/perl")).resolve(strict=True))


def finalize(record, lock, output, module_output):
    """Complete and inspect the product-owned runtime after verified builds."""
    output = output.resolve(strict=True)
    def merge(source, destination):
        for path in sorted(source.rglob("*")):
            if path.is_symlink():
                raise ValueError("private Perl assets cannot contain links")
            target = destination / path.relative_to(source)
            if path.is_dir():
                target.mkdir(parents=True, exist_ok=True)
            elif path.is_file():
                target.parent.mkdir(parents=True, exist_ok=True)
                if target.exists():
                    if target.is_symlink() or not target.is_file():
                        raise ValueError("private Perl asset destination is not a regular file")
                    if target.read_bytes() == path.read_bytes():
                        continue
                    target.unlink()
                shutil.copyfile(path, target)
                target.chmod(0o755 if path.stat().st_mode & 0o111 else 0o644)
    merge(module_output / "lib/perl5", output / "lib/perl5")
    archive = ROOT / ".artifacts/native-perl/cache" / (record["name"] + ".tar.gz")
    if archive.is_symlink() or hashlib.sha256(archive.read_bytes()).hexdigest() != record["sha256"]:
        raise ValueError("native Perl license source differs from the lock")
    with tarfile.open(archive, "r:gz") as source:
        for name in ("Artistic", "Copying", "README"):
            member = source.getmember(record["name"] + "/" + name)
            if not member.isfile() or member.size > 1024 * 1024:
                raise ValueError("native Perl license is not bounded regular content")
            path = output / "share/licenses/perl" / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(source.extractfile(member).read(member.size + 1))
    interset = json.loads((ROOT / "runtime/perl-deps.lock.json").read_text())["interset"]
    spec = importlib.util.spec_from_file_location("ud_native_interset", ROOT / "scripts/runtime/perl_build.py")
    bridge = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(bridge)
    with tempfile.TemporaryDirectory(prefix=".interset-", dir=output.parent) as temporary:
        destination = Path(temporary) / "interset"
        bridge._extract_interset(ROOT / ".artifacts/perl-sources" / interset["archive"], interset, destination)
        merge(destination / "lib", output / "lib/perl5")
        license_dir = output / "share/licenses/interset"
        license_dir.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(destination / "LICENSE.txt", license_dir / "LICENSE.txt")
    for name, release in lock["releases"].items():
        archive = ROOT / ".artifacts/perl-mutation/cache" / (release["sha256"] + ".tar.gz")
        if archive.is_symlink() or hashlib.sha256(archive.read_bytes()).hexdigest() != release["sha256"]:
            raise ValueError("native module license source differs from the lock")
        with tarfile.open(archive, "r:gz") as source:
            for member in source:
                parts = PurePosixPath(member.name).parts
                if len(parts) == 2 and parts[0] == name and re.fullmatch(r"(?:LICENSE(?:\.[A-Za-z0-9_-]+)?|COPYING(?:\.[A-Za-z0-9_-]+)?|Artistic|README(?:\.[A-Za-z0-9_-]+)?)", parts[1], re.I):
                    if not member.isfile() or member.size > 1024 * 1024:
                        raise ValueError("native module license is not bounded regular content")
                    path = output / "share/licenses" / name / parts[1]
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(source.extractfile(member).read(member.size + 1))
    # The core and XS trees resolve relative to the interpreter and private
    # module library. Deliberately do not preserve ambient site/vendor paths.
    executable = "bin/perl.exe" if platform.system() == "Windows" else "bin/perl"
    perl = output / executable
    windows_imports = None
    if platform.system() == "Windows":
        # Resolve app-local redistributables before the first interpreter probe.
        # Never borrow DLLs from PATH, an installed application, or System32.
        import struct
        spec = importlib.util.spec_from_file_location("ud_native_windows_cross", ROOT / "scripts/runtime/prepare-windows-perl.py")
        cross = importlib.util.module_from_spec(spec); spec.loader.exec_module(cross)
        body = perl.read_bytes(); offset = struct.unpack_from("<I", body, 60)[0]; machine = struct.unpack_from("<H", body, offset + 4)[0]
        architecture = {0xAA64: "arm64", 0x8664: "x64"}.get(machine)
        if architecture is None:
            raise ValueError("private Windows Perl has an unsupported PE architecture")
        redistributables = json.loads((ROOT / "runtime/windows-perl-distributions.lock.json").read_text())["platforms"][architecture]["redistributables"]
        with tempfile.TemporaryDirectory(prefix=".native-vc-runtime-", dir=output.parent) as temporary:
            providers = []
            for index, receipt in enumerate(redistributables):
                archive = cross.verified(ROOT / ".artifacts/native-perl/cache/windows" / receipt["filename"], receipt)
                directory = Path(temporary) / str(index); directory.mkdir(); cross.extract(archive, directory)
                providers.append(directory / "Library/bin")
                cross.copy_tree(directory / "info/licenses", output / "share/licenses" / ("vc-runtime-" + str(index)))
            windows_imports = cross.PE.close_runtime_imports(output, architecture, providers)
    libraries = ["lib/perl5", "lib/perl5/" + subprocess.check_output([str(perl), "-MConfig", "-e", 'print $Config{archname}'], text=True)]
    libraries = [name for name in libraries if (output / name).is_dir()]
    env = {"PATH": "/usr/bin:/bin" if os.name != "nt" else str(Path(os.environ["SystemRoot"]) / "System32"), "LC_ALL": "C", "HOME": str(output.parent), **({"SystemRoot": os.environ["SystemRoot"]} if os.name == "nt" else {})}
    core = subprocess.check_output([str(perl), "-e", 'print join("\\0", @INC)'], env=env, timeout=30).decode("utf-8").split("\0")
    for raw in core:
        candidate = Path(raw)
        if not candidate.exists():
            continue
        if not candidate.is_absolute() or candidate.is_symlink() or not candidate.is_dir():
            raise ValueError("private Perl core search path is not an absolute ordinary directory")
        canonical = candidate.resolve(strict=True)
        if not canonical.is_relative_to(output):
            raise ValueError("private Perl core search path escapes the owned runtime")
        # Empty site directories have no dependency bytes and npm drops empty
        # directories. Omit them rather than requiring ambient placeholders.
        if not any(file.is_file() for file in canonical.rglob("*")):
            continue
        relative = canonical.relative_to(output).as_posix()
        if relative not in libraries:
            libraries.append(relative)
    probe = 'BEGIN { @INC = @ARGV; @ARGV=(); } use Moose; use MooseX::SemiAffordanceAccessor; use namespace::autoclean; use List::MoreUtils; use YAML; use JSON::Parse; use File::Which; use LWP::Simple; use Lingua::Interset; print "private-perl-ok\\n";'
    result = subprocess.run([str(perl), "-e", probe, *[str(output / name) for name in libraries]], env=env, capture_output=True, text=True, timeout=30)
    if result.returncode or result.stdout != "private-perl-ok\n" or result.stderr:
        raise ValueError("private Perl dependency closure probe failed: " + result.stderr[-2000:])
    files = [{"path": path.relative_to(output).as_posix(), "sha256": "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest(), "size": path.stat().st_size} for path in sorted(output.rglob("*")) if path.is_file()]
    receipt = {"schema_version": 1, "state": "frozen-inputs", "source_sha256": hashlib.sha256(json.dumps(record, sort_keys=True, separators=(",", ":")).encode()).hexdigest(), "modules_sha256": hashlib.sha256(json.dumps(lock, sort_keys=True, separators=(",", ":")).encode()).hexdigest(), "interset_commit": interset["commit"], "executable": executable, "library_dirs": libraries, "files": files, "probe": {"status": "passed", "ambient_modules": False}}
    if windows_imports is not None:
        receipt["pe_imports"] = windows_imports
    (output.parent / (output.name + "-receipt.json")).write_text(json.dumps(receipt, sort_keys=True, indent=2) + "\n")
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-lock", type=Path, default=ROOT / "runtime/native-perl-source.lock.json")
    parser.add_argument("--module-lock", type=Path, default=ROOT / "runtime/native-perl-modules.lock.json")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--resolve", action="store_true")
    parser.add_argument("--target", choices=["darwin/arm64","darwin/x64","linux/arm64","linux/x64","win32/arm64","win32/x64"])
    parser.add_argument("--download", action="store_true")
    parser.add_argument("--build-timeout",type=int,default=900,help="bounded development compiler timeout per build step")
    args = parser.parse_args()
    record = source_lock(args.source_lock) if args.resolve else json.loads(args.source_lock.read_text())
    perl = build(record, args.output, args.download, args.target,args.build_timeout)
    lock = modules.resolve(perl, args.module_lock, MODULE_ROOTS, "UDPerlRuntime") if args.resolve else json.loads(args.module_lock.read_text())
    module_output = args.output.parent / (args.output.name + "-modules")
    modules.prepare(lock, perl, module_output, args.download)
    finalize(record, lock, args.output, module_output)
    print(json.dumps({"perl": perl, "source_version": record["version"], "modules": len(lock["releases"])}))


if __name__ == "__main__":
    main()
