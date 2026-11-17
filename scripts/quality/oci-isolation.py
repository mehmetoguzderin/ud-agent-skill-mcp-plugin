"""Kernel isolation for test children; only the trusted parent owns metadata."""
import ctypes
import errno
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import select
import shutil
import signal
import stat
import struct
import sys
import tempfile
import time
import uuid

_REQUIRED_IPC = ()


def checked(result, label):
    if result < 0:
        raise RuntimeError(label + ': ' + os.strerror(ctypes.get_errno()))
    return result


def process_identity(pid):
    """Read UID and Linux start ticks from one bounded proc identity observation."""
    root = Path('/proc') / str(pid)
    before = (root / 'stat').read_text()
    status = (root / 'status').read_text()
    after = (root / 'stat').read_text()
    def start(value):
        return int(value[value.rindex(')') + 2:].split()[19])
    if start(before) != start(after):
        raise ProcessLookupError('process changed during identity observation')
    uid = int(next(line for line in status.splitlines() if line.startswith('Uid:')).split()[1])
    return {'pid': pid, 'uid': uid, 'start_ticks': start(after)}


def alive(identity):
    try:
        return process_identity(identity['pid']) == identity
    except (FileNotFoundError, ProcessLookupError):
        return False


def cancel_exact(identity):
    """Open a pidfd, then recheck the original identity before signalling it."""
    try:
        descriptor = os.pidfd_open(identity['pid'])
    except ProcessLookupError:
        return
    try:
        if not alive(identity):
            return
        signal.pidfd_send_signal(descriptor, signal.SIGKILL)
        if not select.select([descriptor], [], [], 10)[0]:
            raise RuntimeError('owned mutation descendant did not terminate')
    finally:
        os.close(descriptor)


def confine_writes(directory):
    libc = ctypes.CDLL(None, use_errno=True)
    checked(libc.prctl(38, 1, 0, 0, 0), 'mutation no_new_privs')
    abi = checked(libc.syscall(444, 0, 0, 1), 'mutation Landlock unavailable')
    if abi < 3:
        raise RuntimeError('Mutation isolation requires Landlock truncate control')
    writes = sum(1 << bit for bit in (1, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14))
    ruleset = ctypes.c_uint64(writes)
    descriptor = checked(libc.syscall(444, ctypes.byref(ruleset), ctypes.sizeof(ruleset), 0), 'mutation Landlock create')
    try:
        for name, access in [(str(directory), writes), ('/dev/null', 1 << 1)]:
            target = os.open(name, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                rule = ctypes.create_string_buffer(struct.pack('=Qi', access, target))
                checked(libc.syscall(445, descriptor, 1, ctypes.byref(rule), 0), 'mutation Landlock rule')
            finally:
                os.close(target)
        checked(libc.syscall(446, descriptor, 0), 'mutation Landlock enforce')
    finally:
        os.close(descriptor)


def drop_privileges(uid):
    libc = ctypes.CDLL(None, use_errno=True)
    for capability in range(64):
        if libc.prctl(24, capability, 0, 0, 0) < 0 and ctypes.get_errno() != errno.EINVAL:
            raise RuntimeError('mutation capability bounding-set drop failed')
    os.setgroups([])
    os.setgid(uid)
    os.setuid(uid)


def close_inherited_descriptors(output):
    """Landlock cannot revoke old FDs; retain only explicit result pipes."""
    allowed = set(_REQUIRED_IPC)
    for descriptor in allowed:
        if descriptor < 3 or not stat.S_ISFIFO(os.fstat(descriptor).st_mode):
            raise RuntimeError('mutation result channel is not the explicit private pipe')
    null = os.open('/dev/null', os.O_RDONLY)
    os.dup2(null, 0)
    os.close(null)
    os.dup2(output.fileno(), 1)
    os.dup2(output.fileno(), 2)
    allowed.update((0, 1, 2, output.fileno()))
    for name in list(Path('/proc/self/fd').iterdir()):
        descriptor = int(name.name)
        if descriptor not in allowed:
            try:
                os.close(descriptor)
            except OSError as error:
                if error.errno != errno.EBADF:
                    raise
    # Replace inherited Python file objects too; they may refer to a closed
    # coordinator CaptureOutput file even after fd1/fd2 have been rebound.
    sys.stdout = os.fdopen(os.dup(1), 'w', buffering=1)
    sys.stderr = os.fdopen(os.dup(2), 'w', buffering=1)


def control(root):
    directory = root / 'control'
    directory.mkdir(mode=0o700, exist_ok=True)
    (directory / 'jobs').mkdir(mode=0o700, exist_ok=True)
    with (directory / 'next-uid').open('a+b') as stream:
        fcntl.flock(stream, fcntl.LOCK_EX)
        stream.seek(0)
        value = int(stream.read() or b'100000') + 1
        if value >= 2**31:
            raise RuntimeError('mutation uid inventory exhausted')
        stream.seek(0)
        stream.truncate()
        stream.write(str(value).encode())
        stream.flush()
        os.fsync(stream.fileno())
    return directory, value


def child_file(file, uid):
    info = file.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != uid or info.st_nlink != 1 or info.st_size > 8*1024*1024:
        raise RuntimeError('mutation child evidence is not a bounded owned file')
    return file.read_bytes()


def uid_processes(uid):
    observed = []
    for path in Path('/proc').glob('[0-9]*/status'):
        try:
            identity = process_identity(int(path.parent.name))
            if identity['uid'] == uid:
                observed.append(identity)
        except (FileNotFoundError, ProcessLookupError):
            pass
    return observed


def collect_finished(state, events):
    for record in (state / 'control/jobs').glob('*.json'):
        data = json.loads(record.read_text())
        try:
            current = process_identity(data['identity']['pid'])
            owner_alive = current['start_ticks'] == data['identity']['start_ticks'] and current['uid'] in (data['identity']['uid'], data['uid'])
        except (FileNotFoundError, ProcessLookupError):
            owner_alive = False
        if data.get('collected') or owner_alive:
            continue
        leftovers = []
        for attempt in range(32):
            observed = uid_processes(data['uid'])
            if not observed:
                break
            for identity in observed:
                cancel_exact(identity)
                leftovers.append(identity)
        else:
            raise RuntimeError('mutation job UID did not become quiescent after bounded cleanup')
        job = Path(data['directory'])
        evidence = job / 'pytest-events.jsonl'
        if evidence.exists():
            with events.open('ab') as target:
                target.write(child_file(evidence, data['uid']))
        logfile = job / 'pytest-output.log'
        if logfile.exists():
            with (state / 'child-output.log').open('ab') as target:
                target.write(('\nOWNED MUTATION CHILD ' + record.stem + '\n').encode())
                target.write(child_file(logfile, data['uid']))
        data.update(collected=True, owned_descendants_cancelled=leftovers)
        record.write_text(json.dumps(data) + '\n')
        shutil.rmtree(job)
        if leftovers:
            raise RuntimeError('mutation job leaked owned descendants')


def projection_selection(params, active):
    """Translate the fixed upstream runner states into explicit SDK requests."""
    if not isinstance(active, str) or len(active) > 16384 or '\0' in active:
        raise ValueError('mutation projection selection is invalid')
    collecting = '--collect-only' in params
    if collecting:
        if active not in ('', 'mutant_generation', 'list_all_tests'):
            raise ValueError('mutation projection collection has an active test selection')
        return 'collection', None
    modes = {'': 'baseline', 'stats': 'stats', 'fail': 'forced-fail'}
    if active in modes:
        return modes[active], None
    if active in ('mutant_generation', 'list_all_tests'):
        raise ValueError('mutation projection generation state cannot execute tests')
    return 'active', active


def validate_runtime_projection(projection):
    location = Path('/opt/mutation/harness/python-runtime-projection.py')
    if (getattr(projection, '__file__', None) != str(location)
            or getattr(projection, 'VERSION', None) != 'ud-python-inert-projection-1'
            or not callable(getattr(projection, 'prepare_runtime', None))
            or not callable(getattr(projection, 'issue_runtime_context', None))):
        raise RuntimeError('mutation projection requires the shared fixed SDK module')
    info = location.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or info.st_mode & 0o022:
        raise RuntimeError('mutation projection SDK helper is not a protected ordinary file')
    return projection


def admit_projection_job(work, state, events, jobs, projection, params, active):
    """Materialize only after every older UID is quiescent, before any UID drop."""
    if os.geteuid() != 0:
        raise RuntimeError('mutation projection requires the trusted coordinator')
    mode, key = projection_selection(params, active)
    controls = state / 'control'
    descriptor = os.open(controls / 'projection-admission.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise RuntimeError('another mutation projection admission is active') from error
        collect_finished(state, events)
        for record in (controls / 'jobs').glob('*.json'):
            previous = json.loads(record.read_text())
            if not previous.get('collected') or uid_processes(previous['uid']):
                raise RuntimeError('prior mutation job is not quiescent before projection')
        witness = projection.prepare_runtime(work, state, mode, key)
        if (not isinstance(witness, dict) or witness.get('schema_version') != 1
                or witness.get('version') != 'ud-python-inert-projection-1'
                or witness.get('mode') != mode or witness.get('active_key') != key
                or witness.get('guard_exit_code') != 125):
            raise RuntimeError('mutation projection returned an inconsistent admission witness')
        controls, uid = control(state)
        witness = {**witness, 'projection_sequence': uid}
        projection_bytes = json.dumps(witness, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()
        projection_sha256 = hashlib.sha256(projection_bytes).hexdigest()
        context = projection.issue_runtime_context(work, state, uid, witness)
        if (not isinstance(context, dict) or set(context) != {'path', 'sha256', 'size_bytes'}
                or context.get('path') != 'work/mutants/.ud-runtime-projection.json'
                or not isinstance(context.get('sha256'), str) or len(context['sha256']) != 64
                or any(value not in '0123456789abcdef' for value in context['sha256'])
                or type(context.get('size_bytes')) is not int or not 0 < context['size_bytes'] <= 64 * 1024 ** 2
                or hashlib.sha256(json.dumps(witness, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()).hexdigest() != projection_sha256):
            raise RuntimeError('mutation projection context receipt or admitted witness changed')
        nonce = uuid.uuid4().hex
        job = jobs / nonce
        job.mkdir(mode=0o700)
        os.chown(job, uid, uid)
        (job / 'tmp').mkdir(mode=0o700)
        os.chown(job / 'tmp', uid, uid)
        record = {'identity': process_identity(os.getpid()), 'uid': uid, 'directory': str(job), 'collected': False,
                  'projection_sequence': uid, 'projection_sha256': projection_sha256, 'projection': witness, 'projection_context': context}
        record_fd = os.open(controls / 'jobs' / f'{nonce}.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        with os.fdopen(record_fd, 'w') as output:
            output.write(json.dumps(record, allow_nan=False) + '\n')
            output.flush()
            os.fsync(output.fileno())
        return uid, job
    finally:
        os.close(descriptor)


def bounded_json_fork(function, *args, **kwargs):
    """Untrusted children return bounded JSON, never pickle executable objects."""
    global _REQUIRED_IPC
    read_fd, write_fd = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(read_fd)
        _REQUIRED_IPC = (write_fd,)
        try:
            payload = {'ok': True, 'value': function(*args, **kwargs)}
        except BaseException as error:
            payload = {'ok': False, 'error': str(error)[:16384]}
        try:
            data = json.dumps(payload, allow_nan=False).encode()
            if len(data) > 32*1024*1024:
                raise ValueError('mutation result exceeds JSON bound')
            with os.fdopen(write_fd, 'wb') as channel:
                channel.write(data)
            os._exit(0 if payload['ok'] else 1)
        except BaseException:
            os._exit(1)
    os.close(write_fd)
    data = bytearray()
    deadline = time.monotonic() + 600
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([read_fd], [], [], remaining)[0]:
                os.kill(pid, signal.SIGKILL)
                raise ChildProcessError('mutation child result deadline exceeded')
            chunk = os.read(read_fd, 1024*1024)
            if not chunk:
                break
            data.extend(chunk)
            if len(data) > 32*1024*1024:
                os.kill(pid, signal.SIGKILL)
                raise ChildProcessError('mutation child result exceeds JSON bound')
    finally:
        os.close(read_fd)
        _, status = os.waitpid(pid, 0)
    if status != 0:
        raise ChildProcessError('mutation child execution failed: ' + data.decode(errors='replace')[:16384])
    result = json.loads(data)
    if not isinstance(result, dict) or set(result) != {'ok', 'value'} or result['ok'] is not True:
        raise ChildProcessError('mutation child result is invalid')
    return result['value']


def prove_isolation(state, immutable_file):
    """Exercise the exact child boundary before trusting any mutation outcome."""
    controls, uid = control(state)
    jobs = Path('/tmp/ud-mutation-jobs')
    jobs.mkdir(mode=0o711, exist_ok=True)
    nonce = uuid.uuid4().hex
    job = jobs / nonce
    job.mkdir(mode=0o700)
    os.chown(job, uid, uid)
    challenge = Path(tempfile.mkdtemp(prefix='ud-mutation-proof-'))
    challenge.chmod(0o755)
    outside = challenge / 'parent-metadata'
    outside.write_bytes(b'coordinator metadata must remain unchanged')
    outside.chmod(0o666)  # Prove kernel confinement independently of DAC.
    inherited = os.open(outside, os.O_RDWR)
    expected_identity = (outside.stat().st_dev, outside.stat().st_ino)
    immutable_hash = __import__('hashlib').sha256(immutable_file.read_bytes()).hexdigest()
    def child():
        os.environ.update(HOME=str(job), TMPDIR=str(job))
        os.chdir(job)
        drop_privileges(uid)
        confine_writes(job)
        with (job / 'proof.log').open('w', buffering=1) as output:
            close_inherited_descriptors(output)
            try:
                info = os.fstat(inherited)
                inherited_survived = (info.st_dev, info.st_ino) == expected_identity
            except OSError as error:
                if error.errno != errno.EBADF:
                    raise
                inherited_survived = False
            denied, denial_errnos = [], {}
            for target in [outside, immutable_file]:
                try:
                    descriptor = os.open(target, os.O_WRONLY | os.O_NOFOLLOW)
                except OSError as error:
                    permitted_denials = (errno.EACCES, errno.EPERM, errno.EROFS) if target == immutable_file else (errno.EACCES, errno.EPERM)
                    if error.errno not in permitted_denials:
                        raise
                    denied.append(str(target))
                    denial_errnos[str(target)] = error.errno
                else:
                    os.close(descriptor)
            own = job / 'permitted'
            own.write_bytes(b'only own job is writable')
            status = Path('/proc/self/status').read_text().splitlines()
            capabilities = {key: next(line for line in status if line.startswith(key + ':')).split()[1]
                            for key in ['CapEff', 'CapPrm', 'CapInh', 'CapAmb', 'CapBnd', 'NoNewPrivs']}
            return {'uid': os.getuid(), 'denied': denied, 'denial_errnos': denial_errnos,
                    'inherited_parent_fd_survived': inherited_survived,
                    'own_job_bytes': own.read_text(), 'kernel_status': capabilities}
    try:
        observation = bounded_json_fork(child)
        expected_denials = [str(outside), str(immutable_file)]
        if observation['uid'] != uid or observation['denied'] != expected_denials or observation['inherited_parent_fd_survived'] or observation['own_job_bytes'] != 'only own job is writable' or observation['kernel_status'] != {**{key: '0000000000000000' for key in ['CapEff', 'CapPrm', 'CapInh', 'CapAmb', 'CapBnd']}, 'NoNewPrivs': '1'}:
            raise RuntimeError('mutation isolation self-probe did not establish its required controls')
        if outside.read_bytes() != b'coordinator metadata must remain unchanged' or __import__('hashlib').sha256(immutable_file.read_bytes()).hexdigest() != immutable_hash:
            raise RuntimeError('mutation isolation self-probe altered protected bytes')
        return {'schema_version': 1, 'status': 'passed', **observation}
    finally:
        os.close(inherited)
        shutil.rmtree(job)
        shutil.rmtree(challenge)


def install(runner, work, state, events, *, projection):
    if os.name != 'posix' or not Path('/proc/self/status').is_file() or os.geteuid() != 0:
        raise RuntimeError('full mutation tests require the protected OCI coordinator')
    jobs = Path('/tmp/ud-mutation-jobs')
    jobs.mkdir(mode=0o711, exist_ok=True)
    control(state)
    projection = validate_runtime_projection(projection)
    execute = runner.PytestRunner.execute_pytest
    def isolated(instance, params, **kwargs):
        if os.geteuid() != 0:
            raise RuntimeError('nested test runner tried to re-enter a privileged mutation coordinator')
        from mutmut.mutation.trampoline import get_mutant_under_test
        active = get_mutant_under_test()
        uid, job = admit_projection_job(work, state, events, jobs, projection, params, active)
        current = Path.cwd()
        absolute = []
        for value in params:
            first, separator, suffix = value.partition('::')
            absolute.append(str((current / first).resolve()) + separator + suffix if not value.startswith('-') and (current / first).exists() else value)
        os.environ.update(HOME=str(job), TMPDIR=str(job / 'tmp'), USER='ud-mutation', LOGNAME='ud-mutation', UD_MUTATION_PYTEST_EVIDENCE=str(job / 'pytest-events.jsonl'))
        tempfile.tempdir = None
        os.chdir(job)
        os.umask(0o077)
        drop_privileges(uid)
        confine_writes(job)
        status = Path('/proc/self/status').read_text()
        if any(next(line for line in status.splitlines() if line.startswith(name + ':')).split()[1] != '0000000000000000' for name in ['CapEff', 'CapPrm', 'CapInh', 'CapAmb', 'CapBnd']) or 'NoNewPrivs:\t1' not in status:
            raise RuntimeError('mutation child retained capabilities or privilege acquisition')
        baseline_options = ['--maxfail=0', *(['-v'] if active == 'stats' else [])]
        with (job / 'pytest-output.log').open('w', buffering=1) as output:
            close_inherited_descriptors(output)
            kwargs['plugins'] = fixed_pytest_plugins(kwargs.get('plugins', []))
            result = execute(instance, [*absolute, '--rootdir=' + str(work / 'mutants'), '-c', str(work / 'pyproject.toml'), '-p', 'no:cacheprovider', *baseline_options], **kwargs)
            sys.stdout.flush()
            sys.stderr.flush()
            return result
    runner.PytestRunner.execute_pytest = isolated
    from mutmut.configuration import config, ForkServerWarmup, ProcessIsolation
    config().forkserver_warmup = ForkServerWarmup.NONE
    config().process_isolation = ProcessIsolation.FORKSERVER
    import mutmut.workers.isolation as workers
    workers.run_in_fork_with_result = bounded_json_fork
    register = runner._register_mutant_result
    def registered(*args, **kwargs):
        result = register(*args, **kwargs)
        collect_finished(state, events)
        return result
    runner._register_mutant_result = registered
    return lambda: collect_finished(state, events)


def fixed_pytest_plugins(plugins):
    """Load the immutable grader only in the already confined test child."""
    if os.geteuid() == 0:
        raise RuntimeError('pytest evidence must load after the test UID drop')
    location = Path('/opt/mutation/harness/pytest_evidence.py')
    info = location.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or info.st_mode & 0o222:
        raise RuntimeError('pytest evidence is not the fixed protected SDK module')
    os.environ.pop('PYTEST_PLUGINS', None)
    spec = importlib.util.spec_from_file_location('ud_fixed_pytest_evidence', location)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return [*plugins, module]
