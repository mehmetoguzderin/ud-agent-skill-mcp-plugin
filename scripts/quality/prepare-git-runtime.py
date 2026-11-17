"""Close the original Git fixture tool from the pinned native ARM Actions image.

This is a private development input, not a product Git or source-rights claim.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('git_fixture_elf', ROOT / 'scripts/runtime/elf_dependencies.py')
elf = importlib.util.module_from_spec(spec); spec.loader.exec_module(elf)
PREFIX = '/opt/mutation/git'
SEARCH = ['/lib/aarch64-linux-gnu', '/usr/lib/aarch64-linux-gnu', '/lib64', '/usr/lib64', '/lib', '/usr/lib', '/usr/local/lib']


def sha(file):
    with file.open('rb') as stream: return hashlib.file_digest(stream, 'sha256').hexdigest()


def git_probe(git):
    env = {'PATH': '/usr/bin:/bin', 'HOME': '/tmp', 'LANG': 'C', 'LC_ALL': 'C', 'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_SYSTEM': '/dev/null', 'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_TERMINAL_PROMPT': '0'}
    rows = []
    with tempfile.TemporaryDirectory(prefix='ud-original-git-probe-') as temporary:
        commands = [[str(git), '--version', '--build-options'], [str(git), '--exec-path']]
        commands.extend([str(git), 'init', '--quiet', '--initial-branch=main', '--object-format=' + objects, '--ref-format=' + refs, str(Path(temporary) / (objects + '-' + refs))] for objects in ('sha1', 'sha256') for refs in ('files', 'reftable'))
        for command in commands:
            result = subprocess.run(command, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
            row = {'argv': command, 'status': result.returncode, 'stdout': result.stdout.decode('utf-8'), 'stderr': result.stderr.decode('utf-8')}; rows.append(row)
            if result.returncode: raise ValueError('Original Git lacks required fixture features: ' + json.dumps(row))
    if not re.match(r'git version [0-9]+\.[0-9]+\.[0-9]+\n', rows[0]['stdout']) or 'cpu: aarch64\n' not in rows[0]['stdout']: raise ValueError('Git probe is not the original native ARM tool')
    return rows


def launcher(program, argv0, loader):
    fixed = ['#!/bin/sh', 'export GIT_EXEC_PATH=' + shlex.quote(PREFIX + '/libexec'), 'export GIT_TEMPLATE_DIR=' + shlex.quote(PREFIX + '/share/templates'), 'export GITPERLLIB=' + shlex.quote(PREFIX + '/share/perl5'), 'export GIT_CONFIG_NOSYSTEM=1', 'export GIT_CONFIG_SYSTEM=/dev/null', 'export GIT_CONFIG_GLOBAL=/dev/null']
    args = [PREFIX + '/' + loader, '--inhibit-cache', '--library-path', PREFIX + '/lib', '--argv0', PREFIX + '/' + argv0, PREFIX + '/' + program]
    return ('\n'.join([*fixed, 'exec ' + ' '.join(map(shlex.quote, args)) + ' "$@"']) + '\n').encode()


def prepare(output, provider):
    if sys.platform != 'linux' or os.uname().machine != 'aarch64' or not re.fullmatch(r'[^\s]+@sha256:[a-f0-9]{64}', provider): raise ValueError('Git extraction requires the pinned native ARM provider')
    lock = json.loads((ROOT / 'quality/act.lock.json').read_bytes())
    if provider != lock['linux_runner']['nonroot_image']: raise ValueError('Git provider differs from the existing pinned Actions runner')
    if output.exists(): raise ValueError('Private Git output must be new')
    git = Path('/usr/bin/git').resolve(strict=True); probes = git_probe(git)
    libexec = Path(probes[1]['stdout'].strip())
    if libexec != Path('/usr/lib/git-core') or not libexec.is_dir(): raise ValueError('Git libexec location differs from the original package')
    output.mkdir(mode=0o755); origins = []; pending = []; libraries = {}; loader = None; programs = {}; mappings = []

    def copy(file, target, *, executable=False):
        source = file.resolve(strict=True)
        if not source.is_file() or source.stat().st_size > 128 * 1024**2: raise ValueError('Original Git input is not a bounded ordinary file')
        before = source.stat(); data = source.read_bytes(); after = source.stat()
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns): raise ValueError('Original Git input changed')
        source_hash = hashlib.sha256(data).hexdigest()
        if data[:4] == b'\x7fELF':
            info = elf.inspect(data)
            if info['machine'] != 183: raise ValueError('Git input contains a foreign ELF')
            if info['search_paths']: data = elf.without_search_paths(data)
            pending.append((source, info))
        destination = output / target; destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists():
            if destination.read_bytes() != data: raise ValueError('Private Git destination has conflicting bytes')
        else:
            destination.write_bytes(data); destination.chmod(0o555 if executable else 0o444)
        origins.append({'path': str(file), 'canonical_path': str(source), 'sha256': source_hash, 'size_bytes': len(data), 'private_path': target, 'private_sha256': hashlib.sha256(data).hexdigest(), 'removed_search_paths': elf.inspect(source.read_bytes())['search_paths'] if data[:4] == b'\x7fELF' else []})
        return destination

    candidates = [('bin/git', git)]
    candidates.extend(('libexec/' + file.relative_to(libexec).as_posix(), file) for file in sorted(libexec.rglob('*')) if file.is_file())
    for name, file in candidates:
        with file.open('rb') as stream: native = stream.read(4) == b'\x7fELF'
        if native:
            target = 'programs/' + sha(file); copy(file, target, executable=True); programs[name] = target
        else: copy(file, name, executable=bool(file.stat().st_mode & 0o111))
    for base, prefix in [(Path('/usr/share/git-core/templates'), 'share/templates'), (Path('/usr/share/perl5/Git'), 'share/perl5/Git')]:
        if not base.is_dir(): raise ValueError('Original Git supporting files are missing')
        for file in sorted(base.rglob('*')):
            if file.is_file(): copy(file, prefix + '/' + file.relative_to(base).as_posix(), executable=bool(file.stat().st_mode & 0o111))
    copy(Path('/usr/share/perl5/Git.pm'), 'share/perl5/Git.pm')
    processed = set()
    while pending:
        source, info = pending.pop()
        if source in processed: continue
        processed.add(source)
        if info['interpreter']:
            original = Path(info['interpreter']).resolve(strict=True); relative = 'loader/' + original.name
            if loader is not None and loader != relative: raise ValueError('Original Git ELF interpreters disagree')
            loader = relative
            if not (output / relative).exists(): copy(original, relative, executable=True)
        for dependency in info['needed']:
            if not re.fullmatch(r'[A-Za-z0-9_.+-]{1,255}', dependency): raise ValueError('Git has an unconfined ELF dependency')
            choices = [(Path(folder) / dependency).resolve(strict=True) for folder in SEARCH if (Path(folder) / dependency).is_file()]
            if not choices or len({sha(file) for file in choices}) != 1: raise ValueError('Git ELF dependency is absent or ambiguous: ' + dependency)
            original = choices[0]
            if dependency not in libraries:
                copy(original, 'lib/' + dependency, executable=True); libraries[dependency] = sha(original)
            elif libraries[dependency] != sha(original): raise ValueError('Git ELF dependency changed')
    if loader is None: raise ValueError('Original Git has no private ELF loader')
    for name, program in sorted(programs.items()):
        file = output / name; file.parent.mkdir(parents=True, exist_ok=True); file.write_bytes(launcher(program, name, loader)); file.chmod(0o555)
    owners = set()
    for row in origins:
        result = subprocess.run(['dpkg-query', '-S', row['canonical_path']], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
        if result.returncode: raise ValueError('Original Git file has no retained package ownership: ' + row['canonical_path'])
        owners.update(line.split(': ', 1)[0] for line in result.stdout.decode().splitlines())
    packages = []; notices = []
    for owner in sorted(owners):
        package = owner.split(':')[0]
        status = subprocess.run(['dpkg-query', '-W', '-f=${Package}\t${Version}\t${Architecture}\t${Source}\n', owner], stdout=subprocess.PIPE, check=True, timeout=10).stdout.decode()
        copyright = Path('/usr/share/doc') / package / 'copyright'
        if not copyright.is_file(): raise ValueError('Original Git dependency copyright is missing: ' + package)
        file = copy(copyright, 'licenses/' + package + '-copyright'); notices.append({'path': file.relative_to(output).as_posix(), 'sha256': sha(file), 'size_bytes': file.stat().st_size}); packages.append({'package': owner, 'status': status})
    common = Path('/usr/share/common-licenses')
    for name in ('GPL-2', 'GPL-3', 'LGPL-2', 'LGPL-2.1', 'LGPL-3'):
        if (common / name).is_file(): copy(common / name, 'licenses/' + name)
    files = [{'path': file.relative_to(output).as_posix(), 'sha256': sha(file), 'size_bytes': file.stat().st_size, 'mode': stat.S_IMODE(file.stat().st_mode)} for file in sorted(output.rglob('*')) if file.is_file()]
    receipt = {'schema_version': 1, 'qualification': 'private-native-arm-Git-fixture-tool-not-product-runtime', 'platform': 'linux/arm64', 'provider': provider, 'provider_arm64_manifest': lock['linux_runner']['nonroot_arm64_manifest'], 'generator_sha256': sha(Path(__file__)), 'elf_generator_sha256': sha(ROOT / 'workers/ud/src/ud_agent/elf_runtime.py'), 'version': probes[0]['stdout'].splitlines()[0].removeprefix('git version '), 'probe': probes, 'executable': 'bin/git', 'loader': loader, 'libraries': libraries, 'programs': programs, 'origins': origins, 'packages': packages, 'notices': notices, 'files': files, 'scope': 'Original developer fixture Git with private ELF loading, exact original package notices and immutable provider identity. No product shipping, binary reproduction, source completeness or publisher redistribution authority is inferred.'}
    (output.parent / (output.name + '-receipt.json')).write_text(json.dumps(receipt, indent=2) + '\n')
    return receipt


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('--output', type=Path, required=True); parser.add_argument('--provider', required=True); args = parser.parse_args()
    value = prepare(args.output, args.provider); print(json.dumps({'version': value['version'], 'files': len(value['files']), 'libraries': len(value['libraries'])}))
