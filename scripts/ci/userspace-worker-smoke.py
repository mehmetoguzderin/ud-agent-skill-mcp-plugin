#!/usr/bin/env python3
"""Exercise the native Linux worker supervisor with real process descendants."""
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile


def main():
    guard = str(Path(sys.argv[1]).resolve(strict=True))
    python = str(Path(sys.executable).resolve(strict=True))
    with tempfile.TemporaryDirectory(prefix='ud-worker-supervisor-') as temporary:
        root = Path(temporary)
        bootstrap = root / 'bootstrap.py'
        bootstrap.write_text('''import json,os,subprocess,sys,time
assert os.read(3,64)==b"snapshot-frames"
assert sys.stdin.buffer.readline()==b"request\\n"
child=subprocess.Popen([sys.executable,"-c","import time;time.sleep(300)"],start_new_session=True)
print(json.dumps({"child":child.pid}),flush=True)
if sys.argv[2].endswith("/cancel"):time.sleep(300)
''')
        venv = root / 'private-venv'
        subprocess.run([python, '-I', '-m', 'venv', '--without-pip', str(venv)], check=True)
        alias = venv / 'bin/python'
        assert alias.is_symlink(), 'worker fixture must use a real executable alias'
        bootstrap.write_text('import sys;assert sys.prefix==' + repr(str(venv)) + '\n' + bootstrap.read_text())
        digest = lambda filename: hashlib.sha256(Path(filename).read_bytes()).hexdigest()
        for cancel in (False, True):
            read_fd, write_fd = os.pipe()
            assert read_fd == 3, 'fixture fd3 must be the native snapshot channel'
            command = [guard, 'contained-run', '--executable', str(alias), '--executable-sha256', digest(python),
                       '--bootstrap', str(bootstrap), '--bootstrap-sha256', digest(bootstrap),
                       '--worker', str(root), '--upstream', 'cancel' if cancel else str(root),
                       '--context', str(root), '--snapshot-sha256', '0' * 64, '--staging', str(root)]
            # --upstream is a real directory; use its basename as the fixture mode.
            selected = root / ('cancel' if cancel else 'normal')
            selected.mkdir()
            command[command.index('--upstream') + 1] = str(selected)
            command[command.index('--bootstrap-sha256') + 1] = digest(bootstrap)
            child = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, pass_fds=(read_fd,))
            os.close(read_fd)
            os.write(write_fd, b'snapshot-frames')
            os.close(write_fd)
            child.stdin.write(b'request\n')
            child.stdin.close()
            response = json.loads(child.stdout.readline())
            if cancel:
                child.send_signal(signal.SIGTERM)
            code = child.wait(timeout=40)
            assert code == (125 if cancel else 0), (code, child.stderr.read())
            try:
                os.kill(response['child'], 0)
            except ProcessLookupError:
                pass
            else:
                raise AssertionError('worker descendant survived or was not reaped')
        rejected = command.copy()
        rejected[rejected.index('--executable-sha256') + 1] = '0'*64
        invalid = subprocess.run(rejected, capture_output=True, timeout=10)
        assert invalid.returncode != 0 and b'IDENTITY_CHANGED' in invalid.stderr
        linked = root / 'linked-bootstrap.py'
        linked.symlink_to(bootstrap)
        rejected = command.copy()
        rejected[rejected.index('--bootstrap') + 1] = str(linked)
        invalid = subprocess.run(rejected, capture_output=True, timeout=10)
        assert invalid.returncode != 0, 'bootstrap symlinks must remain rejected'
        print(json.dumps({'normal_exit': 'passed', 'venv_alias_prefix': 'passed', 'wrong_interpreter_hash': 'passed', 'bootstrap_symlink_rejection': 'passed', 'cancelled_tree': 'passed', 'detached_descendant_reaping': 'passed', 'fd3_framing': 'passed'}))


if __name__ == '__main__':
    main()
