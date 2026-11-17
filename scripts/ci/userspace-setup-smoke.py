#!/usr/bin/env python3
"""Actual Linux setup supervision, including escaped groups and orphan reaping."""
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time

guard = str(Path(sys.argv[1]).resolve(strict=True))
python = str(Path(sys.executable).resolve(strict=True))
with tempfile.TemporaryDirectory(prefix='ud-setup-supervision-') as temporary:
    root = Path(temporary)
    def launch(code, executable=python, expected=None):
        arguments = ['-I', '-c', code]
        return subprocess.Popen([guard, 'contained-setup', '--executable', executable, '--executable-sha256', expected or hashlib.sha256(Path(executable).read_bytes()).hexdigest(), '--arguments-json', json.dumps(arguments), '--staging', str(root)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    def finish(process, expected):
        assert process.wait(timeout=10) == expected, process.stderr.read().decode()
        output, errors = process.stdout.read(), process.stderr.read()
        process.stdin.close()
        assert not errors, errors
        return output
    normal = launch('print("owned-setup-ok")')
    assert finish(normal, 0) == b'owned-setup-ok\n'
    venv = root / 'private-venv'
    subprocess.run([python, '-I', '-m', 'venv', '--without-pip', str(venv)], check=True)
    alias = venv / 'bin/python'
    assert alias.is_symlink(), 'fixture must exercise a genuine virtualenv executable alias'
    prefixed = launch('import sys;print(sys.prefix)', str(alias))
    assert finish(prefixed, 0).decode().strip() == str(venv)
    wrong = launch('raise AssertionError("unverified interpreter executed")', str(alias), '0'*64)
    assert wrong.wait(timeout=10) != 0
    assert b'IDENTITY_CHANGED' in wrong.stderr.read()
    wrong.stdin.close()
    swapped = root / 'replaced-python'
    swapped.write_bytes(b'\x7fELFwrong interpreter')
    swapped.chmod(0o700)
    alias.unlink()
    alias.symlink_to(swapped)
    changed = launch('raise AssertionError("changed interpreter executed")', str(alias), hashlib.sha256(Path(python).read_bytes()).hexdigest())
    assert changed.wait(timeout=10) != 0
    assert b'IDENTITY_CHANGED' in changed.stderr.read()
    changed.stdin.close()
    for orphan in (False, True):
        marker = root / ('orphan' if orphan else 'cancel')
        code = 'import os,subprocess,sys,time; p=subprocess.Popen([sys.executable,"-I","-c","import time;time.sleep(60)"],start_new_session=True);open('+repr(str(marker))+',"w").write(str(os.getpid())+" "+str(p.pid));'+('' if orphan else 'time.sleep(60)')
        process = launch(code)
        deadline = time.monotonic()+5
        while not marker.exists() and time.monotonic()<deadline:
            time.sleep(.01)
        assert marker.exists(), 'setup child did not start'
        pids = list(map(int,marker.read_text().split()))
        if not orphan:
            process.send_signal(signal.SIGTERM)
        finish(process, 0 if orphan else 125)
        for pid in pids:
            try: os.kill(pid,0)
            except ProcessLookupError: pass
            else: raise AssertionError('setup descendant was not reaped: '+str(pid))
print(json.dumps({'status':'passed','provider':'local-docker','worker_architecture':os.uname().machine,'checks':['normal_exit','venv_alias_prefix','wrong_interpreter_hash','replaced_alias_target','cancelled_tree','escaped_process_group','adopted_orphan_reaping']}))
