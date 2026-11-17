#!/usr/bin/env python3
"""Resolve once and build a private hash-locked PPI parser for mutation tooling."""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tarfile
import tempfile
from urllib.parse import quote, urlsplit
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[2]


def fetch_json(url):
    with urlopen(url, timeout=60) as source:
        return json.loads(source.read(8 * 1024 * 1024))


def core_module(perl, module):
    result = subprocess.run([perl, "-MModule::CoreList", "-e", 'print Module::CoreList::is_core($ARGV[0], undef, $]) ? "yes" : "no"', module], capture_output=True, text=True, check=True)
    return result.stdout == "yes"


def resolve(perl, filename, roots=None, tool="PPI"):
    records, modules, visiting = {}, {}, set()

    def visit(module):
        if module in modules or core_module(perl, module):
            return
        info = fetch_json("https://fastapi.metacpan.org/v1/module/" + quote(module, safe=""))
        release = fetch_json("https://fastapi.metacpan.org/v1/release/" + quote(info["distribution"], safe=""))
        if release.get("maturity") != "released" or release.get("status") != "latest" or not re.fullmatch(r"[a-f0-9]{64}", release.get("checksum_sha256", "")):
            raise ValueError("Perl parser dependency is not a current stable hashed release")
        name = release["name"]
        modules[module] = name
        if name in records or name in visiting:
            return
        visiting.add(name)
        dependencies = []
        for dependency in release.get("dependency", []):
            if dependency.get("phase") in ("runtime", "configure", "build") and dependency.get("relationship") == "requires" and dependency["module"] != "perl":
                if not core_module(perl, dependency["module"]):
                    visit(dependency["module"])
                    dependencies.append(modules[dependency["module"]])
        url = release["download_url"]
        if urlsplit(url).scheme != "https" or urlsplit(url).hostname not in {"cpan.metacpan.org", "cpan.org", "www.cpan.org"}:
            raise ValueError("Perl parser dependency has an untrusted source")
        records[name] = {"name": name, "distribution": release["distribution"], "version": str(release["version"]), "url": url, "sha256": release["checksum_sha256"], "license": release.get("license", []), "dependencies": sorted(set(dependencies))}
        visiting.remove(name)

    roots = roots or ["PPI"]
    for module in roots:
        visit(module)
    value = {"schema_version": 1, "tool": tool, "state": "frozen-inputs", "root_releases": sorted({modules[module] for module in roots if module in modules}), "modules": modules, "releases": records}
    if "PPI" in modules:
        value["parser_release"] = modules["PPI"]
    with filename.open("x", encoding="utf-8") as target:
        json.dump(value, target, sort_keys=True, indent=2)
        target.write("\n")
    return value


def prepare(lock, perl, output, download):
    if lock.get("schema_version") != 1 or lock.get("state") != "frozen-inputs" or lock.get("tool") not in ("PPI", "UDPerlRuntime") or not lock.get("releases"):
        raise ValueError("invalid frozen Perl parser dependency lock")
    if output.exists() or output.is_symlink():
        raise ValueError("private Perl parser output already exists")
    output.parent.mkdir(parents=True, exist_ok=True)
    make = subprocess.check_output([perl, "-MConfig", "-e", 'print $Config{make}'], text=True).strip()
    if not make or any(character in make for character in ("\n", "\r", "\0")):
        raise ValueError("private Perl interpreter has no valid configured build tool")
    cache = ROOT / ".artifacts/perl-mutation/cache"
    cache.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".ppi-build-", dir=output.parent) as temporary:
        work = Path(temporary)
        install = work / "install"
        install.mkdir()
        env = {key: value for key, value in os.environ.items() if key not in ("PERL5LIB", "PERL5OPT", "PERL_MM_OPT", "PERL_MB_OPT") and not re.search("TOKEN|SECRET|PASSWORD|CREDENTIAL", key, re.I)}
        env.update({"HOME": str(work), "PERL5LIB": str(install / "lib/perl5"), "PERL_MM_USE_DEFAULT": "1", "NONINTERACTIVE_TESTING": "1"})
        built = set()

        def build(name):
            if name in built:
                return
            record = lock["releases"][name]
            for dependency in record["dependencies"]:
                build(dependency)
            archive = cache / (record["sha256"] + ".tar.gz")
            if not archive.exists():
                if not download:
                    raise ValueError("private Perl parser source is absent from the offline cache")
                with urlopen(record["url"], timeout=60) as source:
                    data = source.read(64 * 1024 * 1024 + 1)
                if len(data) > 64 * 1024 * 1024 or hashlib.sha256(data).hexdigest() != record["sha256"]:
                    raise ValueError("Perl parser source integrity mismatch")
                with archive.open("xb") as target:
                    target.write(data)
            if archive.is_symlink() or hashlib.sha256(archive.read_bytes()).hexdigest() != record["sha256"]:
                raise ValueError("Perl parser cached source differs from its lock")
            source_dir = work / name
            source_dir.mkdir()
            seen, total = set(), 0
            with tarfile.open(archive, "r:gz") as source:
                for item in source:
                    parts = PurePosixPath(item.name).parts
                    if len(parts) == 1 and item.isdir():
                        continue
                    if len(parts) < 2 or parts[0] != name or any(part in ("..", ".") for part in parts) or item.name.startswith("/") or "\\" in item.name:
                        raise ValueError("Perl parser source archive escapes its root")
                    relative = "/".join(parts[1:])
                    if relative in seen or len(seen) > 50000:
                        raise ValueError("Perl parser source archive has duplicate entries")
                    seen.add(relative)
                    target = source_dir / relative
                    if item.isdir():
                        target.mkdir(parents=True, exist_ok=True)
                    elif item.isfile() and item.size <= 16 * 1024 * 1024:
                        total += item.size
                        if total > 128 * 1024 * 1024:
                            raise ValueError("Perl parser source archive exceeds its size limit")
                        target.parent.mkdir(parents=True, exist_ok=True)
                        target.write_bytes(source.extractfile(item).read(item.size + 1))
                    else:
                        raise ValueError("Perl parser source contains a link or special file")
            commands = ([perl, "Makefile.PL", "INSTALL_BASE=" + str(install)], [make], [make, "install"]) if (source_dir / "Makefile.PL").is_file() else ([perl, "Build.PL", "--install_base", str(install)], [perl, "Build"], [perl, "Build", "install"])
            if not (source_dir / "Makefile.PL").is_file() and not (source_dir / "Build.PL").is_file():
                raise ValueError("locked Perl source has no supported native build recipe")
            for args in commands:
                result = subprocess.run(args, cwd=source_dir, env=env, capture_output=True, text=True, timeout=300)
                with (work / (name + ".log")).open("a", encoding="utf-8") as target:
                    target.write(result.stdout + "\n" + result.stderr)
                if result.returncode:
                    raise ValueError(f"private Perl parser build failed for {name}: {result.stderr[-1000:]}")
            built.add(name)

        for name in lock.get("root_releases", [lock.get("parser_release")]):
            build(name)
        # Library files are relocated as a unit. MakeMaker's bookkeeping records
        # retain the build prefix but are not used by the parser at runtime.
        shutil.copytree(install, output)
        files = [{"path": path.relative_to(output).as_posix(), "sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "size": path.stat().st_size} for path in sorted(output.rglob("*")) if path.is_file()]
        receipt = {"schema_version": 1, "lock_sha256": hashlib.sha256(json.dumps(lock, sort_keys=True, separators=(",", ":")).encode()).hexdigest(), "parser_release": lock.get("parser_release"), "files": files, "perl_version": subprocess.check_output([perl, "-e", "print $^V"], text=True)}
        (output / "parser-receipt.json").write_text(json.dumps(receipt, sort_keys=True, indent=2) + "\n")
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lock", type=Path, default=ROOT / "quality/perl-parser.lock.json")
    parser.add_argument("--perl", default=shutil.which("perl"))
    parser.add_argument("--resolve", action="store_true")
    parser.add_argument("--download", action="store_true")
    parser.add_argument("--output", type=Path, default=ROOT / ".artifacts/perl-mutation/parser")
    args = parser.parse_args()
    perl = str(Path(args.perl).resolve(strict=True))
    lock = resolve(perl, args.lock) if args.resolve else json.loads(args.lock.read_text())
    print(json.dumps(prepare(lock, perl, args.output, args.download)))


if __name__ == "__main__":
    main()
