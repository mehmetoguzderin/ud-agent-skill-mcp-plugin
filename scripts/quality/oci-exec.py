"""Fixed native OCI boundary for non-pytest mutation test processes."""
import importlib.util
import hashlib
import json
import os
import errno
import re
from pathlib import Path
import resource
import select
import signal
import stat
import time
import unicodedata
import uuid

spec = importlib.util.spec_from_file_location('ud_exec_isolation', Path(__file__).with_name('oci-isolation.py'))
isolation = importlib.util.module_from_spec(spec)
spec.loader.exec_module(isolation)

MAX_MANIFEST = 32 * 1024**2
MAX_FILE = 128 * 1024**2
MAX_WORKSPACE = 2 * 1024**3
_DEPENDENCIES = {}  # One trusted controller lifetime; never a writable disk cache.


def materializations(workspace, files):
    values = workspace.get('materializations', [])
    if not isinstance(values, list) or len(values) > 1 or values and workspace.get('readonly_tree') is not True:
        raise ValueError('mutation materialization requires one sealed immutable source')
    result = {}
    for item in values:
        if not isinstance(item, dict) or set(item) != {'path', 'before_sha256', 'after_sha256', 'size', 'bytes'}:
            raise ValueError('mutation materialization contract is invalid')
        name = relative(item['path'])
        if name not in files or not (name == 'packages/npm-distribution/cli.cjs' or re.match(r'^(?:packages/[^/]+/src/|scripts/|workers/[^/]+/src/|evals/)', name)) or any(part in ('test', 'tests', '__tests__') for part in name.split('/')):
            raise ValueError('mutation materialization is outside the closed source inventory')
        if item['before_sha256'] != files[name]['sha256'] or not isinstance(item['bytes'], bytes) or type(item['size']) is not int or not 0 <= item['size'] <= MAX_FILE or len(item['bytes']) != item['size'] or hashlib.sha256(item['bytes']).hexdigest() != item['after_sha256']:
            raise ValueError('mutation materialization differs from its exact before/after byte identities')
        result[name] = item
    if sum(item['size'] for item in files.values()) + sum(item['size'] - files[name]['size'] for name, item in result.items()) > MAX_WORKSPACE:
        raise ValueError('mutation materialization exceeds the workspace bound')
    return result


def handoff_definition(workspace):
    result = dict(workspace)
    if 'materializations' in result:
        result['materializations'] = [{key: value for key, value in item.items() if key != 'bytes'} for item in result['materializations']]
    return result


def handoff_fingerprints(workspace):
    definition = handoff_definition(workspace)
    source = {key: value for key, value in definition.items() if key != 'materializations'}
    digest = lambda value: hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    return {'inventory_sha256': digest(definition), 'source_inventory_sha256': digest(source)}


def relative(value):
    if not isinstance(value, str) or not value or len(value.encode('utf-8')) > 4096 or value.startswith('/') or any(character in value for character in '\\\0:') or unicodedata.normalize('NFC', value) != value or any(part in ('', '.', '..') for part in value.split('/')):
        raise ValueError('mutation handoff path is not a canonical relative path')
    return value


def _fingerprint(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _directory(root):
    """No component of an authority path may be an alias supplied by a child."""
    value = os.fspath(root)
    if not os.path.isabs(value) or os.path.normpath(value) != value:
        raise ValueError('mutation handoff root must be an absolute canonical path')
    descriptor = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in value.split('/')[1:]:
            if not part:
                continue
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        info = os.fstat(descriptor)
        if info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('mutation handoff directory is not coordinator-owned')
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _open_at(root, value):
    parts = relative(value).split('/')
    parent = os.dup(root)
    try:
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            os.close(parent)
            parent = child
            info = os.fstat(parent)
            if info.st_uid != 0 or info.st_mode & 0o022:
                raise ValueError('mutation handoff parent is not coordinator-owned')
        return os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    finally:
        os.close(parent)


def _read_at(root, entry, *, output=None, owner=0, limit=MAX_FILE, collect=True):
    descriptor = _open_at(root, entry['path'])
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_uid != owner or before.st_nlink != 1 or before.st_size != entry['size'] or before.st_size > limit or stat.S_IMODE(before.st_mode) != entry['mode']:
            raise ValueError('mutation handoff file identity or metadata differs')
        digest, size, collected = hashlib.sha256(), 0, bytearray()
        while True:
            part = os.read(descriptor, 1024**2)
            if not part:
                break
            size += len(part)
            if size > entry['size']:
                raise ValueError('mutation handoff file changed during read')
            digest.update(part)
            if output is not None:
                output.write(part)
            elif collect:
                collected.extend(part)
        if size != entry['size'] or digest.hexdigest() != entry['sha256'] or _fingerprint(before) != _fingerprint(os.fstat(descriptor)):
            raise ValueError('mutation handoff file hash or stable identity differs')
        return bytes(collected)
    finally:
        os.close(descriptor)


def _file_entries(value):
    if not isinstance(value, list) or len(value) > 200000:
        raise ValueError('mutation handoff file inventory is unbounded')
    result, names, total = {}, set(), 0
    for entry in value:
        if not isinstance(entry, dict) or set(entry) != {'path', 'sha256', 'size', 'mode'} or not isinstance(entry['sha256'], str) or len(entry['sha256']) != 64 or any(character not in '0123456789abcdef' for character in entry['sha256']) or type(entry['size']) is not int or not 0 <= entry['size'] <= MAX_FILE or type(entry['mode']) is not int or not 0 <= entry['mode'] <= 0o777:
            raise ValueError('mutation handoff file entry is invalid')
        name = relative(entry['path'])
        folded = name.casefold()
        if folded in names:
            raise ValueError('mutation handoff duplicate or colliding path')
        names.add(folded)
        result[name] = entry
        total += entry['size']
        if total > MAX_WORKSPACE:
            raise ValueError('mutation handoff file inventory exceeds its byte bound')
    return result


def _inventory(root, files, links):
    """Permit declared directory casing aliases, but never leaf collisions."""
    found_files, found_links, folded = set(), set(), {}
    directories = {name.rsplit('/', 1)[0] for name in (*files, *links) if '/' in name}
    for name in tuple(directories):
        parts = name.split('/')
        directories.update('/'.join(parts[:index]) for index in range(1, len(parts)))
    def visit(directory, prefix=''):
        for name in sorted(os.listdir(directory)):
            full = relative(prefix + name)
            key = full.casefold()
            info = os.stat(name, dir_fd=directory, follow_symlinks=False)
            directory_member = stat.S_ISDIR(info.st_mode)
            # Exact file/link inventories remain casefold-unique. Distinct
            # ordinary directory spellings may contain disjoint declared
            # leaves (the original Linux Perl Pod/ and pod/ are one example).
            if key in folded and not (folded[key] and directory_member):
                raise ValueError('mutation handoff has colliding paths')
            folded[key] = directory_member
            if info.st_uid != 0:
                raise ValueError('mutation handoff member is not coordinator-owned')
            if stat.S_ISDIR(info.st_mode):
                if info.st_mode & 0o022 or full not in directories:
                    raise ValueError('mutation handoff has an unlisted or writable directory')
                descriptor = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
                try:
                    if _fingerprint(os.fstat(descriptor)) != _fingerprint(info):
                        raise ValueError('mutation handoff directory changed')
                    visit(descriptor, full + '/')
                finally:
                    os.close(descriptor)
            elif stat.S_ISREG(info.st_mode) and full in files:
                found_files.add(full)
            elif stat.S_ISLNK(info.st_mode) and full in links and os.readlink(name, dir_fd=directory) == links[full]:
                found_links.add(full)
            else:
                raise ValueError('mutation handoff contains an unlisted or substituted member')
    visit(root)
    if found_files != set(files) or found_links != set(links):
        raise ValueError('mutation handoff is missing declared members')


def _dependency(root, receipt):
    if not isinstance(receipt, dict) or set(receipt) != {'path', 'sha256', 'size_bytes'} or type(receipt['size_bytes']) is not int or not 1 <= receipt['size_bytes'] <= MAX_MANIFEST:
        raise ValueError('mutation immutable dependency receipt is invalid')
    descriptor = _directory(root)
    try:
        if not os.fstatvfs(descriptor).f_flag & os.ST_RDONLY:
            raise ValueError('mutation dependencies require an actual read-only filesystem')
        receipt_path = Path(receipt['path'])
        parent = _directory(receipt_path.parent)
        try:
            entry = {'path': receipt_path.name, 'sha256': receipt['sha256'], 'size': receipt['size_bytes'], 'mode': 0o444}
            payload = _read_at(parent, entry, limit=MAX_MANIFEST)
        finally:
            os.close(parent)
        key = (root, _fingerprint(os.fstat(descriptor)), receipt['sha256'], receipt['size_bytes'])
        if key in _DEPENDENCIES:
            return
        data = json.loads(payload)
        if not isinstance(data, dict) or set(data) != {'schema_version', 'files', 'links'} or type(data['schema_version']) is not int or data['schema_version'] != 1 or not isinstance(data['links'], list) or len(data['links']) > 200000:
            raise ValueError('mutation immutable dependency manifest is invalid')
        files = _file_entries(data['files'])
        links = {}
        for item in data['links']:
            if not isinstance(item, dict) or set(item) != {'path', 'target'}:
                raise ValueError('mutation dependency link is invalid')
            name, target = relative(item['path']), item['target']
            if name in links or name in files or not isinstance(target, str) or not target or target.startswith('/') or '\\' in target or '\0' in target or len(target) > 4096:
                raise ValueError('mutation dependency link is invalid')
            links[name] = target
        _inventory(descriptor, files, links)
        for entry in files.values():
            if entry['mode'] & 0o222:
                raise ValueError('mutation dependency mode is writable')
            _read_at(descriptor, entry, collect=False)
        canonical = Path(root)
        for name in links:
            resolved = (canonical / name).resolve(strict=True)
            if not resolved.is_relative_to(canonical) or not (resolved.is_file() or resolved.is_dir()):
                raise ValueError('mutation dependency link escapes its immutable closure')
        _DEPENDENCIES[key] = True
    finally:
        os.close(descriptor)


def _handoff(workspace, job, uid):
    if not isinstance(workspace, dict) or not {'root', 'files', 'readonly_links'} <= set(workspace) or set(workspace) - {'root', 'files', 'readonly_links', 'cwd', 'readonly_tree', 'materializations'} or type(workspace.get('readonly_tree', False)) is not bool or not isinstance(workspace['readonly_links'], list) or len(workspace['readonly_links']) > 8:
        raise ValueError('mutation workspace handoff contract is invalid')
    selected_cwd = relative(workspace['cwd']) if 'cwd' in workspace else None
    files = _file_entries(workspace['files'])
    patches = materializations(workspace, files)
    links = {}
    for link in workspace['readonly_links']:
        if not isinstance(link, dict) or set(link) != {'path', 'target', 'closure_receipt'}:
            raise ValueError('mutation workspace immutable link contract is invalid')
        name = relative(link['path'])
        if name in links or name in files or any(name.casefold() == item.casefold() or item.startswith(name + '/') or name.startswith(item + '/') for item in (*files, *links)):
            raise ValueError('mutation workspace link collides with another member')
        _dependency(link['target'], link['closure_receipt'])
        links[name] = link['target']
    descriptor = _directory(workspace['root'])
    tree = job / 'tree'
    tree.mkdir(mode=0o700)
    try:
        # The source may contain the exact read-only links or omit them. Their
        # authority comes exclusively from the separately verified contract.
        present = {}
        for name, target in links.items():
            candidate = Path(workspace['root']) / name
            try:
                info = candidate.lstat()
            except FileNotFoundError:
                continue
            if not stat.S_ISLNK(info.st_mode) or candidate.resolve(strict=True) != Path(target):
                raise ValueError('mutation source dependency link was substituted')
            present[name] = os.readlink(candidate)
        _inventory(descriptor, files, present)
        for entry in files.values():
            destination = tree / entry['path']
            destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            with destination.open('xb') as output:
                if entry['path'] in patches:
                    _read_at(descriptor, entry, collect=False)
                    output.write(patches[entry['path']]['bytes'])
                else:
                    _read_at(descriptor, entry, output=output)
            destination.chmod((0o555 if entry['mode'] & 0o111 else 0o444) if workspace.get('readonly_tree') else entry['mode'])
        for name, target in links.items():
            destination = tree / name
            destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            destination.symlink_to(target)
        for directory, directories, members in os.walk(tree, followlinks=False):
            if workspace.get('readonly_tree'):
                # Root retains the entire source/test namespace. The fresh
                # child can write its job cache, never rewrite or unlink tests.
                os.chmod(directory, 0o555)
            else:
                os.chown(directory, uid, uid)
                for name in members + directories:
                    os.chown(Path(directory) / name, uid, uid, follow_symlinks=False)
        if selected_cwd:
            cwd = tree / selected_cwd
            for parent in (cwd, *cwd.parents):
                if parent == tree:
                    break
                if not parent.is_dir() or parent.is_symlink():
                    raise ValueError('mutation workspace CWD is not a closed ordinary directory')
        return tree
    finally:
        os.close(descriptor)


def _result(file, uid, limit):
    descriptor = os.open(file, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_uid != uid or before.st_nlink != 1 or before.st_size > limit:
            raise ValueError('mutation child result is not a bounded owned regular file')
        value = bytearray()
        while True:
            part = os.read(descriptor, min(1024**2, limit + 1 - len(value)))
            if not part:
                break
            value.extend(part)
            if len(value) > limit:
                raise ValueError('mutation child result exceeds its bound')
        if len(value) != before.st_size or _fingerprint(before) != _fingerprint(os.fstat(descriptor)):
            raise ValueError('mutation child result changed during collection')
        return bytes(value)
    finally:
        os.close(descriptor)


def quiesce(uid):
    leftovers = []
    for attempt in range(32):
        observed = []
        for path in Path('/proc').glob('[0-9]*/status'):
            try:
                identity = isolation.process_identity(int(path.parent.name))
                if identity['uid'] == uid:
                    observed.append(identity)
            except (FileNotFoundError, ProcessLookupError):
                pass
        if not observed:
            return leftovers
        for identity in observed:
            isolation.cancel_exact(identity)
            leftovers.append(identity)
    raise RuntimeError('mutation exec UID did not become quiescent')


def execute(command, *, state, environment, timeout=30, workspace=None, request=None, result=None, cancel_fd=None):
    """Run an exact command with immutable input paths and a private writable CWD.

    The trusted caller assembles argv and input files. No caller-provided preexec
    code or writable shared CWD is accepted. Descendants inherit the same kernel
    restrictions; finding leaked descendants invalidates the result.
    """
    if os.geteuid() != 0 or not isinstance(command, list) or not command or len(command) > 256 or not all(isinstance(item, str) and '\0' not in item and len(item) <= 65536 for item in command) or sum(map(len, command)) > 1024**2 or not Path(command[0]).is_absolute() or type(timeout) is not int or not 1 <= timeout <= 600:
        raise ValueError('mutation exec requires the trusted OCI coordinator and an exact bounded command')
    if not isinstance(environment, dict) or len(environment) > 256 or any(not isinstance(key, str) or not isinstance(value, str) or not key or '=' in key or '\0' in key + value or len(key) > 512 or len(value) > 65536 for key, value in environment.items()) or sum(len(key) + len(value) for key, value in environment.items()) > 1024**2:
        raise ValueError('mutation exec environment is not a bounded string mapping')
    for contract, fields in [(request, {'basename', 'bytes'}), (result, {'basename', 'max_bytes'})]:
        if contract is not None and (not isinstance(contract, dict) or set(contract) != fields or '/' in relative(contract['basename']) or contract['basename'] in ('tree', 'exec-output.log')):
            raise ValueError('mutation exec request/result contract is invalid')
    if request is not None and (not isinstance(request['bytes'], bytes) or len(request['bytes']) > MAX_MANIFEST):
        raise ValueError('mutation exec request is not bounded bytes')
    if result is not None and (type(result['max_bytes']) is not int or not 1 <= result['max_bytes'] <= MAX_MANIFEST):
        raise ValueError('mutation exec result bound is invalid')
    if request is not None and result is not None and request['basename'] == result['basename']:
        raise ValueError('mutation exec request and result names collide')
    cancellation = None
    if cancel_fd is not None:
        if type(cancel_fd) is not int or cancel_fd < 0:
            raise ValueError('mutation exec cancellation descriptor is invalid')
        os.fstat(cancel_fd)
        cancellation = select.poll()
        cancellation.register(cancel_fd, select.POLLHUP | select.POLLERR | select.POLLNVAL)
    state = Path(state).resolve(strict=True)
    controls, uid = isolation.control(state)
    jobs = Path('/tmp/ud-mutation-jobs')
    jobs.mkdir(mode=0o711, exist_ok=True)
    info = jobs.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o711:
        raise ValueError('mutation job root is not a private coordinator-owned directory')
    nonce = uuid.uuid4().hex
    job = jobs / nonce
    job.mkdir(mode=0o700)
    sealed = isinstance(workspace, dict) and workspace.get('readonly_tree') is True
    writable = job
    if sealed:
        # A child-owned parent would allow rename(tree) despite root-owned
        # files. Retain this namespace and expose only a separate owned cache.
        job.chmod(0o755)
        writable = job / 'cache'
        writable.mkdir(mode=0o700)
        os.chown(writable, uid, uid)
    else:
        os.chown(job, uid, uid)
    logfile = job / 'exec-output.log'
    if sealed:
        logfile.touch(mode=0o600)
        os.chown(logfile, uid, uid)
    record = controls / 'jobs' / (nonce + '.exec.json')
    env = {**environment, 'HOME': str(writable), 'TMPDIR': str(writable), 'USER': 'ud-mutation', 'LOGNAME': 'ud-mutation'}
    try:
        tree = _handoff(workspace, job, uid) if workspace is not None else job
        cwd = tree / workspace['cwd'] if workspace is not None and 'cwd' in workspace else tree
        tokens = {'{workspace}': str(tree)}
        if request is not None:
            request_file = job / request['basename']
            with request_file.open('xb') as output:
                output.write(request['bytes'])
            request_file.chmod(0o444)
            tokens['{request}'] = str(request_file)
        if result is not None:
            tokens['{result}'] = str(job / result['basename'])
            if sealed:
                result_file = Path(tokens['{result}'])
                result_file.touch(mode=0o600)
                os.chown(result_file, uid, uid)
        for token in ('{workspace}', '{request}', '{result}'):
            if token in command and token not in tokens:
                raise ValueError('mutation exec argument requests an absent contract')
        command = [tokens.get(argument, argument) for argument in command]
    except BaseException:
        __import__('shutil').rmtree(job)
        raise
    started = time.monotonic()
    release_read, release_write = os.pipe()
    blocked_signals = {signal.SIGTERM, signal.SIGINT}
    previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, blocked_signals)
    try:
        pid = os.fork()
    except BaseException:
        os.close(release_read)
        os.close(release_write)
        __import__('shutil').rmtree(job)
        signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
        raise
    if pid == 0:
        try:
            signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
            os.close(release_write)
            if os.read(release_read, 1) != b'1':
                os._exit(125)
            os.close(release_read)
            os.chdir(cwd)
            os.umask(0o077)
            resource.setrlimit(resource.RLIMIT_NOFILE, (128, 128))
            resource.setrlimit(resource.RLIMIT_NPROC, (64, 64))
            resource.setrlimit(resource.RLIMIT_CPU, (timeout, timeout + 1))
            isolation.drop_privileges(uid)
            isolation.confine_writes(job)
            status = Path('/proc/self/status').read_text()
            if any(next(line for line in status.splitlines() if line.startswith(name + ':')).split()[1] != '0000000000000000' for name in ['CapEff', 'CapPrm', 'CapInh', 'CapAmb', 'CapBnd']) or 'NoNewPrivs:\t1' not in status:
                raise RuntimeError('mutation exec retained capabilities or privilege acquisition')
            with logfile.open('w', buffering=1) as output:
                isolation.close_inherited_descriptors(output)
                # Python wrappers are noninheritable; only job-bound OS stdio
                # reaches exec, with no pre-opened coordinator descriptors.
                for name in list(Path('/proc/self/fd').iterdir()):
                    descriptor = int(name.name)
                    if descriptor > 2:
                        try:
                            os.close(descriptor)
                        except OSError as error:
                            if error.errno != errno.EBADF:
                                raise
                os.execve(command[0], command, env)
        except BaseException:
            os._exit(125)
    timed_out, cancelled, status, identity, recorded = False, False, None, None, False
    try:
        os.close(release_read)
        release_read = None
        identity = isolation.process_identity(pid)
        record.write_text(json.dumps({'qualification': 'protected-exec', 'identity': identity, 'uid': uid, 'directory': str(job), 'command': command, 'resource_limits': {'file_write_quota': False}, 'status': 'running'}) + '\n')
        os.write(release_write, b'1')
        os.close(release_write)
        release_write = None
        # Deliver a pending supervisor cancellation only after cleanup has a
        # pinned pre-drop child identity and an established finally block.
        signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
        while True:
            waited, observed = os.waitpid(pid, os.WNOHANG)
            if waited:
                status = observed
                break
            cancelled = bool(cancellation and cancellation.poll(0))
            if cancelled or time.monotonic() - started >= timeout:
                timed_out = not cancelled
                try:
                    current = isolation.process_identity(pid)
                    if current['start_ticks'] == identity['start_ticks'] and current['uid'] in (identity['uid'], uid):
                        isolation.cancel_exact(current)
                except (FileNotFoundError, ProcessLookupError):
                    pass
                _, status = os.waitpid(pid, 0)
                break
            time.sleep(0.01)
        leftovers = quiesce(uid)
        output = isolation.child_file(logfile, uid).decode('utf-8', errors='replace') if logfile.exists() else ''
        code = os.waitstatus_to_exitcode(status)
        outcome = {'status': code, 'stdout': '', 'stderr': output, 'timed_out': timed_out, 'owned_descendants_cancelled': leftovers,
                   'elapsed_seconds': time.monotonic() - started, 'uid': uid, 'execution_id': nonce,
                   'resource_limits': {'file_write_quota': False}}
        if workspace is not None:
            outcome['handoff'] = {'cwd': workspace.get('cwd', '.'), 'files': len(workspace['files']),
                                  **handoff_fingerprints(workspace)}
            if workspace.get('readonly_tree'):
                outcome['handoff']['readonly_tree'] = True
            if workspace.get('materializations'):
                outcome['handoff']['materializations'] = handoff_definition(workspace)['materializations']
        if cancelled:
            outcome['cancelled'] = True
        if result is not None:
            result_file = job / result['basename']
            try:
                value = _result(result_file, uid, result['max_bytes'])
            except FileNotFoundError:
                value = None
            outcome.update({'result_bytes': value, 'result_size': len(value) if value is not None else None,
                            'result_sha256': hashlib.sha256(value).hexdigest() if value is not None else None})
        record.write_text(json.dumps({'qualification': 'protected-exec', 'identity': identity, 'uid': uid, 'command': command,
                                      **{key: value for key, value in outcome.items() if key != 'result_bytes'}, 'collected': True}) + '\n')
        recorded = True
        if leftovers or code == 125:
            raise RuntimeError('mutation exec leaked descendants or failed to establish its execution boundary')
        return outcome
    finally:
        signal.pthread_sigmask(signal.SIG_BLOCK, blocked_signals)
        for descriptor in (release_read, release_write):
            if descriptor is not None:
                os.close(descriptor)
        if status is None:
            # InterruptedError/EOF cleanup also covers the pre-drop root child;
            # the assigned-UID scan alone cannot authorize that transition.
            try:
                current = isolation.process_identity(pid)
                # Before the first identity capture the unreaped direct child
                # still pins this PID: it cannot be reused by another process.
                if identity is None or current['start_ticks'] == identity['start_ticks'] and current['uid'] in (identity['uid'], uid):
                    isolation.cancel_exact(current)
            except (FileNotFoundError, ProcessLookupError):
                pass
            try:
                os.waitpid(pid, 0)
            except ChildProcessError:
                pass
        try:
            quiesce(uid)
            __import__('shutil').rmtree(job)
            if not recorded:
                record.write_text(json.dumps({'qualification': 'protected-exec', 'identity': identity, 'uid': uid, 'command': command,
                                              'status': 'runner-error', 'reason': 'supervisor-interrupted-or-invalid-result',
                                              'child_reaped': True, 'collected': True}) + '\n')
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)


def prove_execution(state, interpreter, immutable_file):
    """Run an actual exec canary; source-copy isolation alone is insufficient."""
    import tempfile
    with tempfile.TemporaryDirectory(prefix='ud-mutation-exec-proof-') as temporary:
        challenge = Path(temporary)
        challenge.chmod(0o755)
        parent_file = challenge / 'parent-metadata'
        parent_file.write_bytes(b'immutable parent challenge')
        parent_file.chmod(0o666)
        descriptor = os.open(parent_file, os.O_RDWR)
        info = os.fstat(descriptor)
        program = r'''
import errno,json,os,sys
from pathlib import Path
outside,immutable,old_fd,device,inode,parent=sys.argv[1:]
denied=[]
for name in [outside,immutable]:
 try:fd=os.open(name,os.O_WRONLY|os.O_NOFOLLOW)
 except OSError as error:
  allowed=(errno.EACCES,errno.EPERM,errno.EROFS)if name==immutable else(errno.EACCES,errno.EPERM)
  if error.errno not in allowed:raise
  denied.append(name)
 else:os.close(fd)
try:
 info=os.fstat(int(old_fd));survived=(info.st_dev,info.st_ino)==(int(device),int(inode))
except OSError as error:
 if error.errno!=errno.EBADF:raise
 survived=False
try:os.kill(int(parent),0);parent_denied=False
except PermissionError:parent_denied=True
Path('permitted').write_bytes(b'own job only')
status=Path('/proc/self/status').read_text().splitlines()
caps={key:next(line for line in status if line.startswith(key+':')).split()[1]for key in ['CapEff','CapPrm','CapInh','CapAmb','CapBnd','NoNewPrivs']}
print(json.dumps({'denied':denied,'inherited_parent_fd_survived':survived,'parent_signal_denied':parent_denied,'own_job_bytes':Path('permitted').read_text(),'kernel_status':caps}))
'''
        try:
            result = execute([str(interpreter), '-I', '-B', '-c', program, str(parent_file), str(immutable_file), str(descriptor), str(info.st_dev), str(info.st_ino), str(os.getpid())], state=state, environment={'PATH': '/opt/mutation/bin:/opt/mutation/python/bin:/usr/bin:/bin'}, timeout=10)
        finally:
            os.close(descriptor)
        if result['status'] != 0 or result['timed_out']:
            raise RuntimeError('mutation exec security probe failed to execute')
        observed = json.loads(result['stderr'])
        if observed != {'denied': [str(parent_file), str(immutable_file)], 'inherited_parent_fd_survived': False, 'parent_signal_denied': True,
                        'own_job_bytes': 'own job only', 'kernel_status': {**{key: '0000000000000000' for key in ['CapEff', 'CapPrm', 'CapInh', 'CapAmb', 'CapBnd']}, 'NoNewPrivs': '1'}} or parent_file.read_bytes() != b'immutable parent challenge':
            raise RuntimeError('mutation exec boundary failed its independent permissions challenge')
        timeout = execute([str(interpreter), '-I', '-B', '-c', 'import time;time.sleep(60)'], state=state, environment={'PATH': '/usr/bin:/bin'}, timeout=1)
        if timeout['timed_out'] is not True or timeout['status'] != -signal.SIGKILL:
            raise RuntimeError('mutation exec timeout did not cancel the exact owned child')
        return {'schema_version': 1, 'status': 'passed', 'permissions': observed, 'timeout': timeout,
                'handoff': prove_handoff(state, interpreter), 'cancellation': prove_cancellation(state, interpreter)}


def prove_cancellation(state, interpreter):
    """EOF and SIGTERM must reap the child and prove assigned-UID quiescence."""
    import threading
    def on_started(action):
        initial = set((Path(state) / 'control/jobs').glob('*.exec.json'))
        errors = []
        def watch():
            try:
                end = time.monotonic() + 10
                while time.monotonic() < end:
                    for record in set((Path(state) / 'control/jobs').glob('*.exec.json')) - initial:
                        try:
                            data = json.loads(record.read_bytes())
                            log = Path(data['directory']) / 'exec-output.log'
                            if log.exists() and log.read_bytes().startswith(b'child-started\n'):
                                action()
                                return
                        except (FileNotFoundError, json.JSONDecodeError):
                            pass
                    time.sleep(0.01)
                raise RuntimeError('cancellation proof child did not reach its execution barrier')
            except BaseException as error:
                errors.append(error)
        thread = threading.Thread(target=watch, daemon=True)
        thread.start()
        return thread, errors
    command = [str(interpreter), '-I', '-B', '-c', 'import time;print("child-started",flush=True);time.sleep(60)']
    read, write = os.pipe()
    thread, errors = on_started(lambda: os.close(write))
    try:
        eof = execute(command, state=state, environment={'PATH': '/usr/bin:/bin'}, timeout=15, cancel_fd=read)
    finally:
        os.close(read)
        thread.join(11)
    if errors or thread.is_alive() or eof.get('cancelled') is not True or eof['timed_out'] or eof['status'] != -signal.SIGKILL or quiesce(eof['uid']):
        raise RuntimeError('parent EOF did not cancel and reap the exact owned test child')
    def interrupted(_signal, _frame):
        raise InterruptedError('supervisor cancellation proof')
    previous = signal.signal(signal.SIGTERM, interrupted)
    thread, errors = on_started(lambda: os.kill(os.getpid(), signal.SIGTERM))
    caught = False
    try:
        execute(command, state=state, environment={'PATH': '/usr/bin:/bin'}, timeout=15)
    except InterruptedError:
        caught = True
    finally:
        thread.join(11)
        signal.signal(signal.SIGTERM, previous)
    if not caught or errors or thread.is_alive():
        raise RuntimeError('supervisor SIGTERM did not complete execution cleanup')
    return {'status': 'passed', 'parent_eof': 'cancelled-reaped-and-quiescent', 'supervisor_sigterm': 'interrupted-after-owned-cleanup'}


def prove_handoff(state, interpreter):
    """Exercise copied source, immutable dependencies, JSON and hostile results."""
    import tempfile
    receipt = Path('/opt/mutation/node-dependencies.json')
    payload = receipt.read_bytes()
    descriptor = {'path': str(receipt), 'sha256': hashlib.sha256(payload).hexdigest(), 'size_bytes': len(payload)}
    with tempfile.TemporaryDirectory(prefix='ud-mutation-handoff-proof-') as temporary:
        source = Path(temporary)
        original = b'parent source bytes\r\n'
        (source / 'source.txt').write_bytes(original)
        (source / 'source.txt').chmod(0o644)
        workspace = {'root': str(source), 'files': [{'path': 'source.txt', 'sha256': hashlib.sha256(original).hexdigest(), 'size': len(original), 'mode': 0o644}],
                     'readonly_links': [{'path': 'node_modules', 'target': '/opt/mutation/node_modules', 'closure_receipt': descriptor}]}
        program = r'''
import errno,json,os,sys
from pathlib import Path
request,result,parent=sys.argv[1:]
assert Path.cwd().name=='tree' and Path('source.txt').read_bytes()==b'parent source bytes\r\n'
assert json.loads(Path(request).read_bytes())=={'operation':'handoff-proof'}
denied=[]
for name in [parent,request,str(Path('node_modules/.package-lock.json'))]:
 try:fd=os.open(name,os.O_WRONLY|os.O_NOFOLLOW)
 except OSError as error:
  assert error.errno in (errno.EACCES,errno.EPERM,errno.EROFS);denied.append(name)
 else:os.close(fd);raise AssertionError('outside or immutable write opened')
Path('source.txt').write_bytes(b'private child mutation')
Path(result).write_text(json.dumps({'request':'verified','private_source':'changed','denied':len(denied)}))
'''
        outcome = execute([str(interpreter), '-I', '-B', '-c', program, '{request}', '{result}', str(source / 'source.txt')],
                          state=state, environment={'PATH': '/usr/bin:/bin'}, timeout=30, workspace=workspace,
                          request={'basename': 'request.json', 'bytes': b'{"operation":"handoff-proof"}'},
                          result={'basename': 'result.json', 'max_bytes': 4096})
        if outcome['status'] != 0 or outcome['timed_out'] or json.loads(outcome['result_bytes'] or b'null') != {'request': 'verified', 'private_source': 'changed', 'denied': 3} or (source / 'source.txt').read_bytes() != original:
            raise RuntimeError('mutation workspace handoff failed its independent source/dependency challenge')
        (source / 'package').mkdir(mode=0o700)
        (source / 'package/input.txt').write_bytes(b'crate-local source')
        (source / 'package/input.txt').chmod(0o644)
        scoped = {**workspace, 'cwd': 'package', 'files': [*workspace['files'], {'path': 'package/input.txt', 'sha256': hashlib.sha256(b'crate-local source').hexdigest(), 'size': 18, 'mode': 0o644}]}
        scoped_result = execute([str(interpreter), '-I', '-B', '-c', 'import sys;from pathlib import Path;assert Path.cwd().name=="package";assert Path("input.txt").read_bytes()==b"crate-local source";assert Path(sys.argv[1],"package/input.txt").read_bytes()==b"crate-local source"', '{workspace}'],
                                state=state, environment={'PATH': '/usr/bin:/bin'}, timeout=10, workspace=scoped)
        if scoped_result['status'] != 0 or scoped_result['handoff']['cwd'] != 'package':
            raise RuntimeError('mutation workspace CWD escaped its closed handoff')
        immutable_program = r'''
import errno,json,os,sys
from pathlib import Path
root=Path.cwd();source=root/'source.txt'
assert source.read_bytes()==b'parent source bytes\r\n' and source.stat().st_uid==0
denied=[]
for operation in [lambda:source.write_bytes(b'changed'),lambda:source.chmod(0o666),lambda:source.unlink(),lambda:root.rename(root.with_name('substituted-tree'))]:
 try:operation()
 except OSError as error:
  assert error.errno in (errno.EACCES,errno.EPERM,errno.EROFS);denied.append(True)
 else:raise AssertionError('immutable test tree or namespace was mutable')
Path(os.environ['TMPDIR'],'own-cache').write_bytes(b'allowed')
Path(sys.argv[1]).write_text(json.dumps({'denied':len(denied),'cache':'allowed'}))
'''
        (source / 'source.txt').chmod(0o600)
        sealed_files = [{**item, 'mode': 0o600} if item['path'] == 'source.txt' else item for item in scoped['files']]
        immutable = execute([str(interpreter), '-I', '-B', '-c', immutable_program, '{result}'],
                            state=state, environment={'PATH': '/usr/bin:/bin'}, timeout=10,
                            workspace={**workspace, 'files': sealed_files, 'readonly_tree': True}, result={'basename': 'result.json', 'max_bytes': 4096})
        if immutable['status'] != 0 or immutable['timed_out'] or json.loads(immutable['result_bytes'] or b'null') != {'denied': 4, 'cache': 'allowed'} or immutable['handoff'].get('readonly_tree') is not True:
            raise RuntimeError('immutable mutation tests or their parent namespace were writable')
        patched_name = 'packages/coordinator/src/canary.ts'
        patched_source = source / patched_name
        patched_source.parent.mkdir(parents=True)
        patched_source.write_bytes(b'answer = true;\r\n');patched_source.chmod(0o644)
        patch = {'path': patched_name, 'before_sha256': hashlib.sha256(patched_source.read_bytes()).hexdigest(),
                 'after_sha256': hashlib.sha256(b'answer = false;\r\n').hexdigest(), 'size': 17, 'bytes': b'answer = false;\r\n'}
        materialized = execute([str(interpreter), '-I', '-B', '-c', 'import os;from pathlib import Path;p=Path("packages/coordinator/src/canary.ts");assert p.read_bytes()==b"answer = false;\\r\\n";assert p.stat().st_uid==0 and p.stat().st_mode&0o222==0'],
                               state=state, environment={'PATH': '/usr/bin:/bin'}, timeout=10,
                               workspace={**workspace, 'files': [*sealed_files, {'path': patched_name, 'sha256': patch['before_sha256'], 'size': 16, 'mode': 0o644}], 'readonly_tree': True, 'materializations': [patch]})
        if materialized['status'] != 0 or materialized['timed_out'] or patched_source.read_bytes() != b'answer = true;\r\n' or materialized['handoff']['materializations'][0]['after_sha256'] != patch['after_sha256']:
            raise RuntimeError('exact source materialization escaped its sealed private copy')
        rejected = []
        for kind, statement in [('symlink', 'os.symlink(sys.argv[2],sys.argv[1])'), ('hardlink', 'Path("owned").write_bytes(b"aliased");os.link("owned",sys.argv[1])'), ('oversize', 'Path(sys.argv[1]).write_bytes(b"x"*4097)')]:
            try:
                execute([str(interpreter), '-I', '-B', '-c', 'import os,sys;from pathlib import Path;' + statement, '{result}', str(source / 'source.txt')],
                        state=state, environment={'PATH': '/usr/bin:/bin'}, timeout=10,
                        result={'basename': 'result.json', 'max_bytes': 4096})
            except (ValueError, OSError):
                rejected.append(kind)
            else:
                raise RuntimeError('mutation result collection admitted an unsafe child result')
        return {'status': 'passed', 'source_sha256': hashlib.sha256(original).hexdigest(),
                'dependency_receipt_sha256': descriptor['sha256'], 'result_sha256': outcome['result_sha256'],
                'rejected_results': rejected, 'source_unchanged': True, 'scoped_cwd': scoped_result['handoff'],
                'readonly_tree': {'status': 'passed', 'rewrite_chmod_unlink_and_parent_rename': 'denied', 'private_cache': 'writable', 'owner_only_input_readable_after_seal': True},
                'materialization': materialized['handoff']['materializations'][0]}


def prove_sparse_file_writes(state, interpreter):
    """Run the ordinary 70 MiB sparse fixture through the protected boundary."""
    program = r"""
import json,os
from pathlib import Path
length=70*1024**2
path=Path('finite-sparse-fixture')
fd=os.open(path,os.O_RDWR|os.O_CREAT|os.O_EXCL,0o600)
try:
 os.ftruncate(fd,length)
 os.lseek(fd,length-1,os.SEEK_SET)
 assert os.write(fd,b'x')==1
 os.lseek(fd,length-1,os.SEEK_SET)
 sentinel=os.read(fd,1)==b'x'
 info=os.fstat(fd)
finally:os.close(fd)
path.unlink()
print(json.dumps({'logical_size':info.st_size,'sentinel_verified':sentinel,'removed':not path.exists()}))
"""
    outcome = execute([str(interpreter), '-I', '-c', program], state=state, environment={}, timeout=10)
    lines = outcome['stderr'].strip().splitlines()
    proof = json.loads(lines[-1]) if lines else None
    if outcome['status'] != 0 or outcome['timed_out'] or outcome['owned_descendants_cancelled'] or proof is None or proof.get('logical_size') != 70 * 1024**2 or proof.get('sentinel_verified') is not True or proof.get('removed') is not True:
        raise RuntimeError('finite protected sparse-write proof failed')
    return {'qualification': 'protected-exec-finite-sparse-write', 'proof': proof, 'execution': outcome}
