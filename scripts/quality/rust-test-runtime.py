#!/opt/mutation/python/bin/python3
"""Immutable Cargo compiler/test adapters for protected native ARM64 mutation jobs."""
from __future__ import annotations
import ctypes
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import signal
import stat
import sys
import unicodedata
import uuid

TARGET = 'aarch64-unknown-linux-gnu'
PRODUCTS = ('ud-agent', 'ud-agent-guard')
MAX_JSON = 32 * 1024**2
WORKSPACES = {
    'Cargo.toml': {'id': 'launcher', 'package': 'ud-agent-launcher', 'cwd': 'packages/launcher', 'products': {'ud-agent': 'src/main.rs', 'ud-agent-guard': 'src/fs_guard.rs'}},
    'scripts/quality/rust-assertion-parser/Cargo.toml': {'id': 'assertion-parser', 'package': 'ud-rust-assertion-parser', 'cwd': 'scripts/quality/rust-assertion-parser', 'products': {'ud-rust-assertion-parser': 'src/main.rs'}},
}


def workspace(manifest):
    if manifest not in WORKSPACES:raise ValueError('Rust workspace is outside the frozen manifest contracts')
    return WORKSPACES[manifest]


def relative(value):
    if not isinstance(value, str) or not value or len(value.encode('utf-8')) > 4096 or unicodedata.normalize('NFC', value) != value or value.startswith('/') or any(part in ('', '.', '..') for part in value.split('/')) or any(character in value for character in '\\\0:'):
        raise ValueError('Rust runtime path is not a confined relative member')
    return value


def file_hash(file, *, limit=128 * 1024**2, executable=False, immutable=False):
    descriptor = os.open(file, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_mode & 0o022 or before.st_size > limit or executable and before.st_mode & 0o111 == 0 or immutable and (before.st_mode & 0o222 or not os.fstatvfs(descriptor).f_flag & os.ST_RDONLY):
            raise ValueError('Rust control input is not a bounded coordinator-owned file')
        digest, size = hashlib.sha256(), 0
        while part := os.read(descriptor, 1024**2):
            size += len(part)
            if size > before.st_size:
                raise ValueError('Rust control file changed during verification')
            digest.update(part)
        after = os.fstat(descriptor)
        if size != before.st_size or any(getattr(before, key) != getattr(after, key) for key in ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_size', 'st_mtime_ns', 'st_ctime_ns')):
            raise ValueError('Rust control file changed during verification')
        return digest.hexdigest(), size
    finally:
        os.close(descriptor)


def read_json(file):
    descriptor = os.open(file, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_mode & 0o022 or before.st_nlink != 1 or before.st_size > MAX_JSON:
            raise ValueError('Rust control JSON is not bounded private coordinator data')
        data = bytearray()
        while part := os.read(descriptor, 1024**2):
            data.extend(part)
            if len(data) > before.st_size:
                raise ValueError('Rust control JSON grew during decoding')
        after = os.fstat(descriptor)
        if len(data) != before.st_size or any(getattr(before, key) != getattr(after, key) for key in ('st_dev', 'st_ino', 'st_mode', 'st_size', 'st_mtime_ns', 'st_ctime_ns')):
            raise ValueError('Rust control JSON changed during decoding')
    finally:
        os.close(descriptor)
    def pairs(values):
        result = {}
        for key, value in values:
            if key in result:
                raise ValueError('Rust control JSON has duplicate keys')
            result[key] = value
        return result
    return json.loads(data, object_pairs_hook=pairs)


def compiler_environment(environment, arguments):
    """Relocate test-only Cargo constants; production compilation is unchanged."""
    result = dict(environment)
    source = environment.get('UD_MUTATION_RUST_SOURCE_ROOT', '')
    if not (source.startswith('/state/') or source.startswith('/tmp/ud-mutation-jobs/') and source.endswith('/tree')) or str(PurePosixPath(source)) != source:
        raise ValueError('Rust compiler source root is outside the owned state')
    if '--test' not in arguments:
        return result
    selected = workspace(environment.get('UD_MUTATION_RUST_WORKSPACE', 'Cargo.toml'))
    if environment.get('CARGO_PKG_NAME') != selected['package'] or environment.get('CARGO_MANIFEST_DIR') != source + '/' + selected['cwd']:
        raise ValueError('Rust test compiler is not bound to the declared package')
    for key, value in environment.items():
        if not key.startswith('CARGO_BIN_EXE_'):
            continue
        name = key.removeprefix('CARGO_BIN_EXE_')
        target = environment.get('CARGO_TARGET_DIR', source + '/target')
        if not isinstance(target, str) or str(PurePosixPath(target)) != target or not target.startswith(('/state/', '/tmp/ud-mutation-jobs/')) or name not in selected['products'] or value != target + '/' + TARGET + '/debug/' + name:
            raise ValueError('Rust integration binary is not the same compiled candidate')
        result[key] = '../' * len(selected['cwd'].split('/')) + 'target/' + TARGET + '/debug/' + name
    result['CARGO_MANIFEST_DIR'] = '.'
    return result


def compiler(arguments):
    if os.geteuid() < 100001 or not arguments or arguments[0] != '/opt/mutation/rust/bin/rustc':
        raise ValueError('Rust compiler adapter requires the immutable trusted compiler')
    status = Path('/proc/self/status').read_text().splitlines()
    if any(next(line for line in status if line.startswith(key + ':')).split()[1] != '0000000000000000' for key in ['CapEff', 'CapPrm', 'CapInh', 'CapAmb', 'CapBnd']) or next(line for line in status if line.startswith('NoNewPrivs:')).split()[1] != '1':
        raise ValueError('Rust compiler retained capabilities or privilege acquisition')
    receipt = read_json('/opt/mutation/rust-input-receipt.json')
    expected = next(item for item in receipt['files'] if item['path'] == 'bin/rustc')
    if file_hash(arguments[0], executable=True, immutable=True) != (expected['sha256'], expected['size']):
        raise ValueError('Rust compiler differs from its frozen input receipt')
    environment = compiler_environment(os.environ, arguments[1:])
    os.execve(arguments[0], arguments, environment)


def candidate(raw):
    if not isinstance(raw, dict) or not {'schema_version', 'source_root', 'cwd', 'files', 'artifacts', 'phase_id'} <= set(raw) or set(raw) - {'schema_version', 'source_root', 'cwd', 'files', 'artifacts', 'phase_id', 'compile_source_root', 'workspace_manifest'} or 'compile_source_root' in raw and (not isinstance(raw['compile_source_root'], str) or not raw['compile_source_root'].startswith('/tmp/ud-mutation-jobs/') or not raw['compile_source_root'].endswith('/tree') or str(PurePosixPath(raw['compile_source_root'])) != raw['compile_source_root']) or type(raw['schema_version']) is not int or raw['schema_version'] != 1 or not isinstance(raw['source_root'], str) or not raw['source_root'].startswith('/state/rust-candidates/') or raw['cwd'] != workspace(raw.get('workspace_manifest', 'Cargo.toml'))['cwd'] or not isinstance(raw['phase_id'], str) or len(raw['phase_id']) != 32 or any(character not in '0123456789abcdef' for character in raw['phase_id']) or not isinstance(raw['files'], list) or not isinstance(raw['artifacts'], list) or not raw['artifacts']:
        raise ValueError('Rust candidate receipt is invalid')
    seen, hashes, folded, total = set(), {}, set(), 0
    if len(raw['files']) > 200000:
        raise ValueError('Rust candidate file inventory is unbounded')
    for entry in raw['files']:
        if not isinstance(entry, dict) or set(entry) != {'path', 'sha256', 'size', 'mode'} or type(entry['size']) is not int or not 0 <= entry['size'] <= 128 * 1024**2 or type(entry['mode']) is not int or not 0 <= entry['mode'] <= 0o777 or not isinstance(entry['sha256'], str) or len(entry['sha256']) != 64 or any(character not in '0123456789abcdef' for character in entry['sha256']):
            raise ValueError('Rust candidate file entry is invalid')
        name = relative(entry['path'])
        if name.casefold() in folded:
            raise ValueError('Rust candidate file inventory is duplicate or colliding')
        folded.add(name.casefold())
        hashes[name] = entry
        total += entry['size']
        if total > 2 * 1024**3:
            raise ValueError('Rust candidate file inventory exceeds its byte bound')
    for artifact in raw['artifacts']:
        if not isinstance(artifact, dict) or set(artifact) not in ({'source_path', 'path', 'sha256', 'size', 'kind'}, {'source_path', 'path', 'sha256', 'size', 'kind', 'id'}) or artifact.get('id') is not None and relative(artifact['id']) != artifact['id'] or artifact['kind'] not in ('test', 'product') or not isinstance(artifact['source_path'], str) or not artifact['source_path'].startswith('/state/') or artifact['source_path'] in seen or relative(artifact['path']) not in hashes or hashes[artifact['path']]['sha256'] != artifact['sha256'] or hashes[artifact['path']]['size'] != artifact['size']:
            raise ValueError('Rust candidate executable is unbound or duplicate')
        seen.add(artifact['source_path'])
    return raw


def child(arguments):
    if len(arguments) < 4 or os.geteuid() < 100001:
        raise ValueError('Rust test child requires a fresh confined UID')
    root, name, digest, size, *test_arguments = arguments
    root = Path(root)
    name = relative(name)
    file = root / name
    if not root.is_relative_to('/tmp/ud-mutation-jobs') or root.name != 'tree' or Path.cwd() != root / workspace(os.environ.get('UD_MUTATION_RUST_WORKSPACE', 'Cargo.toml'))['cwd']:
        raise ValueError('Rust test CWD is outside its private source handoff')
    status = Path('/proc/self/status').read_text().splitlines()
    if any(next(line for line in status if line.startswith(key + ':')).split()[1] != '0000000000000000' for key in ['CapEff', 'CapPrm', 'CapInh', 'CapAmb', 'CapBnd']) or next(line for line in status if line.startswith('NoNewPrivs:')).split()[1] != '1':
        raise ValueError('Rust test child retained capabilities or privilege acquisition')
    descriptor = os.open(file, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_nlink != 1 or before.st_size != int(size) or before.st_size > 128 * 1024**2 or before.st_mode & 0o111 == 0 or before.st_mode & 0o222:
            raise ValueError('Rust test executable is not its owned candidate copy')
        content = bytearray()
        while part := os.read(descriptor, 1024**2):
            content.extend(part)
            if len(content) > before.st_size:
                raise ValueError('Rust test executable grew during verification')
        after = os.fstat(descriptor)
        if len(content) != before.st_size or hashlib.sha256(content).hexdigest() != digest or content[:6] != b'\x7fELF\x02\x01' or int.from_bytes(content[18:20], 'little') != 183 or any(getattr(before, key) != getattr(after, key) for key in ('st_dev', 'st_ino', 'st_mode', 'st_size', 'st_mtime_ns', 'st_ctime_ns')):
            raise ValueError('Rust test executable differs from its same-variant receipt')
        os.execve(descriptor, [str(file), *test_arguments], dict(os.environ))
    finally:
        os.close(descriptor)


def run(arguments):
    if os.geteuid() != 0 or not arguments or not Path(arguments[0]).is_absolute() or arguments[1:] not in (['--test-threads=1'], ['--list', '--format', 'terse']):
        raise ValueError('Rust test adapter requires a complete unfiltered invocation')
    original_parent = os.getppid()
    def cancel(_signal, _frame):
        raise InterruptedError('Rust test supervisor cancelled')
    signal.signal(signal.SIGTERM, cancel)
    signal.signal(signal.SIGINT, cancel)
    if ctypes.CDLL(None, use_errno=True).prctl(1, signal.SIGTERM) != 0 or os.getppid() != original_parent:
        raise InterruptedError('Rust test supervisor lost its Cargo parent')
    raw = candidate(read_json(os.environ['UD_MUTATION_RUST_CANDIDATE']))
    matches = [item for item in raw['artifacts'] if item['source_path'] == arguments[0] and item['kind'] == 'test']
    if len(matches) != 1:
        raise ValueError('Cargo invoked an unscheduled Rust test artifact')
    artifact = matches[0]
    if file_hash(arguments[0], executable=True) != (artifact['sha256'], artifact['size']):
        raise ValueError('Cargo test artifact changed after candidate publication')
    spec = importlib.util.spec_from_file_location('ud_rust_fixed_exec', '/opt/mutation/harness/oci-exec.py')
    boundary = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(boundary)
    environment = {'PATH': '/opt/mutation/rust/bin:/opt/mutation/node/bin:/opt/mutation/python/bin:/usr/bin:/bin', 'LANG': 'C.UTF-8', 'PYTHONDONTWRITEBYTECODE': '1', 'CARGO_MANIFEST_DIR': '.', 'UD_MUTATION_RUST_WORKSPACE': raw.get('workspace_manifest', 'Cargo.toml')}
    outcome = boundary.execute(['/opt/mutation/python/bin/python3', '-I', '-B', '/opt/mutation/harness/rust-test-runtime.py', '--child', '{workspace}', artifact['path'], artifact['sha256'], str(artifact['size']), *arguments[1:]],
                               state='/state', environment=environment, timeout=120, workspace={'root': raw['source_root'], 'cwd': raw['cwd'], 'files': raw['files'], 'readonly_links': [], 'readonly_tree': True})
    destination = Path('/state/rust-invocations') / raw['phase_id']
    destination.mkdir(mode=0o700, parents=True, exist_ok=True)
    (destination / (uuid.uuid4().hex + '.json')).write_text(json.dumps({'schema_version': 1, 'artifact': artifact, 'arguments': arguments[1:], 'outcome': outcome}) + '\n')
    sys.stdout.write(outcome['stderr'])
    sys.stdout.flush()
    if outcome['timed_out'] or outcome.get('cancelled') or outcome['owned_descendants_cancelled']:
        raise RuntimeError('Rust test invocation did not finish with clean ownership')
    return outcome['status'] if outcome['status'] >= 0 else 125


def main():
    if sys.platform != 'linux' or len(sys.argv) < 2:
        raise ValueError('Rust mutation adapters execute only in the native Linux OCI image')
    mode, arguments = sys.argv[1], sys.argv[2:]
    if mode == '/opt/mutation/rust/bin/rustc':
        compiler([mode, *arguments])
    elif mode == '--compiler':
        compiler(arguments)
    elif mode == '--runner':
        return run(arguments)
    elif mode == '--child':
        child(arguments)
    else:
        raise ValueError('unknown Rust mutation adapter mode')


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        sys.stderr.write('RUST_EXEC_BOUNDARY_ERROR: ' + str(error) + '\n')
        raise SystemExit(125)
