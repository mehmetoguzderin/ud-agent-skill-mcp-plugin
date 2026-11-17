"""Original-test token ownership policy and native Windows process lifecycle."""
import contextlib
import ctypes
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

SCRIPT = Path(__file__).resolve().parents[2] / 'scripts/quality/windows-original-token.py'
spec = importlib.util.spec_from_file_location('windows_original_token', SCRIPT)
launcher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(launcher)
USER = bytes.fromhex('010100000000000515000000')
DEBUG, SYMLINK = 20, 35


def token(owner=launcher.ADMIN_SID):
    return {'user': USER, 'owner': owner, 'primary_group': USER, 'groups': ((USER, 7),),
            'privileges': ((DEBUG, 0), (SYMLINK, 2)), 'dacl': b'caller-only fixture'}


def child(parent):
    return {**parent, 'owner': parent['user'], 'privileges': tuple(row for row in parent['privileges'] if row[0] != DEBUG)}


class OriginalWindowsTokenTests(unittest.TestCase):
    def test_child_token_changes_only_default_owner_and_removes_debug(self):
        parent = token(); expected = child(parent)
        launcher.verify_token(parent, expected, {DEBUG})
        for field, replacement in [('owner', launcher.ADMIN_SID), ('user', b'foreign'), ('groups', ()),
                                   ('privileges', ()), ('dacl', b'foreign'), ('primary_group', b'foreign')]:
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'differs beyond'):
                launcher.verify_token(parent, {**expected, field: replacement}, {DEBUG})
        self.assertIn((SYMLINK, 2), expected['privileges'])

    def test_restricted_copy_never_adjusts_parent_and_preserves_symlink_privilege(self):
        native = launcher.Native.__new__(launcher.Native); parent = token(); expected = child(parent); calls = []
        def lookup(system, name, output):
            self.assertEqual(name, 'SeDebugPrivilege'); output._obj.low = DEBUG; return 1
        def restricted(source, flags, disable_count, disabled, delete_count, deleted, restrict_count, restricted_sids, output):
            self.assertEqual((source, flags, disable_count, disabled, delete_count, restrict_count, restricted_sids), (10, 0, 0, None, 1, 0, None))
            self.assertEqual(deleted._obj.luid.low, DEBUG); output._obj.value = 20; calls.append('duplicate'); return 1
        def owner(handle, kind, info, size):
            self.assertEqual((handle.value, kind, size), (20, 4, ctypes.sizeof(ctypes.c_void_p)))
            self.assertEqual(ctypes.string_at(info._obj.value, len(USER)), USER); calls.append('new-owner'); return 1
        native.k = SimpleNamespace(CloseHandle=Mock())
        native.a = SimpleNamespace(LookupPrivilegeValueW=lookup, CreateRestrictedToken=restricted, SetTokenInformation=owner)
        native.snapshot = Mock(side_effect=[expected, parent])
        with contextlib.ExitStack() as resources:
            self.assertEqual(native.child_token(10, parent, resources), (20, {DEBUG}))
            native.k.CloseHandle.assert_not_called()
        self.assertEqual(calls, ['duplicate', 'new-owner']); native.k.CloseHandle.assert_called_once_with(20)
        with contextlib.ExitStack() as resources:
            native.a = SimpleNamespace()
            self.assertEqual(native.child_token(10, token(USER), resources), (None, set()))
            with self.assertRaisesRegex(ValueError, 'neither caller nor Administrators'):
                native.child_token(10, token(b'foreign'), resources)

    def test_elevated_copy_refuses_missing_debug_or_unexpected_parent_change(self):
        native = launcher.Native.__new__(launcher.Native); native.k = SimpleNamespace(CloseHandle=Mock())
        def lookup(system, name, output): output._obj.low = DEBUG; return 1
        native.a = SimpleNamespace(LookupPrivilegeValueW=lookup)
        with contextlib.ExitStack() as resources, self.assertRaisesRegex(ValueError, 'no removable debug'):
            native.child_token(10, {**token(), 'privileges': ((SYMLINK, 2),)}, resources)
        # The policy rejects a same-user clone that silently loses capabilities.
        with self.assertRaisesRegex(ValueError, 'differs beyond'):
            launcher.verify_token(token(), {**child(token()), 'privileges': ()}, {DEBUG})

    def model(self, *, assigned=True, wait=0, exit_code=7, child_snapshot=None):
        native = launcher.Native.__new__(launcher.Native); before = token(); events = []
        def in_job(process, job, output): output._obj.value = assigned; events.append('job'); return 1
        def resume(thread): events.append('resume'); return 1
        def exited(process, output): output._obj.value = exit_code; events.append('exit'); return 1
        native.k = SimpleNamespace(IsProcessInJob=in_job, CloseHandle=Mock(), ResumeThread=resume,
                                   WaitForSingleObject=Mock(return_value=wait), GetExitCodeProcess=exited,
                                   TerminateProcess=Mock(return_value=1))
        native.token = Mock(return_value=30)
        def snapshot(handle):
            events.append('child-token' if handle == 30 else 'parent-token')
            return (child_snapshot if child_snapshot is not None else child(before)) if handle == 30 else before
        native.snapshot = snapshot
        native.reap = Mock(side_effect=lambda job: events.append('reap'))
        return native, before, events

    def supervise(self, native, before, timeout=5):
        with contextlib.ExitStack() as resources, contextlib.redirect_stderr(io.StringIO()):
            return native.supervise(10, before, {DEBUG}, 40, launcher.ProcessInfo(50, 60, 70, 80), resources, timeout, True)

    def test_supervision_checks_token_and_job_before_resume_and_reaps_on_exit(self):
        for timeout, wait in [(5, 5000), (None, launcher.INFINITE)]:
            with self.subTest(timeout=timeout):
                native, before, events = self.model()
                self.assertEqual(self.supervise(native, before, timeout), 7)
                self.assertEqual(events, ['job', 'child-token', 'parent-token', 'resume', 'exit', 'reap', 'parent-token'])
                native.k.WaitForSingleObject.assert_called_once_with(50, wait)
                native.k.CloseHandle.assert_called_once_with(30)

    def test_supervision_never_resumes_wrong_owner_and_still_reaps(self):
        native, before, events = self.model(child_snapshot=token())
        with self.assertRaisesRegex(ValueError, 'differs beyond'): self.supervise(native, before)
        self.assertNotIn('resume', events); native.reap.assert_called_once_with(40)
        native, before, events = self.model(assigned=False)
        with self.assertRaisesRegex(ValueError, 'job assignment'): self.supervise(native, before)
        self.assertNotIn('resume', events); native.k.TerminateProcess.assert_called_once_with(50, 137)
        native.k.WaitForSingleObject.assert_called_once_with(50, 30000); native.reap.assert_called_once_with(40)

    def test_timeout_and_cleanup_failures_remain_failed_outcomes(self):
        native, before, events = self.model(wait=launcher.WAIT_TIMEOUT)
        with self.assertRaisesRegex(TimeoutError, 'exceeded its deadline'): self.supervise(native, before)
        native.reap.assert_called_once_with(40)
        native, before, events = self.model(exit_code=0)
        native.reap.side_effect = ValueError('cleanup refusal')
        with self.assertRaisesRegex(ValueError, 'cleanup refusal'): self.supervise(native, before)
        native, before, events = self.model(wait=launcher.WAIT_TIMEOUT)
        native.reap.side_effect = ValueError('cleanup refusal')
        with self.assertRaisesRegex(RuntimeError, 'exceeded its deadline; cleanup: cleanup refusal'):
            self.supervise(native, before)

    def test_command_validation_preserves_exact_arguments_and_rejects_ambient_selection(self):
        with tempfile.TemporaryDirectory() as directory:
            args = [sys.executable, '-c', 'print("literal $() and backticks `")', 'a b', 'quote"', 'back\\']
            self.assertEqual(launcher.validate_command(args, directory, 10), subprocess.list2cmdline(args))
            self.assertEqual(launcher.validate_command(args, directory, None), subprocess.list2cmdline(args))
            self.assertEqual(launcher.validate_command(args, directory, 7201), subprocess.list2cmdline(args))
            for args, cwd, timeout in [(['python'], directory, 10), ([sys.executable, '\0'], directory, 10),
                                       ([sys.executable], '.', 10), ([sys.executable], directory, 0),
                                       ([sys.executable], directory, True), ([sys.executable], directory, 1.5),
                                       ([sys.executable], directory, launcher.INFINITE // 1000 + 1), ([sys.executable, 'x' * 33000], directory, 10)]:
                with self.subTest(args=args[:1], timeout=timeout), self.assertRaises(ValueError):
                    launcher.validate_command(args, cwd, timeout)
        self.assertEqual(ctypes.sizeof(launcher.Privilege), 12)
        if ctypes.sizeof(ctypes.c_void_p) == 8:
            self.assertEqual([ctypes.sizeof(row) for row in [launcher.Startup, launcher.StartupEx, launcher.ProcessInfo, launcher.JobLimits]], [104, 112, 24, 144])

    def test_native_stdio_new_object_owner_and_parent_identity(self):
        # Portable policy is exercised everywhere; the real API branch adds
        # Windows evidence without relabelling a model as native execution.
        parent = token(); launcher.verify_token(parent, child(parent), {DEBUG})
        if os.name != 'nt': return
        native = launcher.Native(); original = native.token(native.k.GetCurrentProcess())
        before = native.snapshot(original)
        try:
            with tempfile.TemporaryDirectory() as directory:
                checker = SCRIPT.with_name('windows-storage-acl.py')
                acl_spec = importlib.util.spec_from_file_location('native_token_acl_fixture', checker)
                acl = importlib.util.module_from_spec(acl_spec); acl_spec.loader.exec_module(acl)
                private = Path(directory) / 'private'
                acl.WindowsStorage().create(str(private), 'directory')
                code = f'''import importlib.util,json,pathlib,sys
s=importlib.util.spec_from_file_location('acl',{str(checker)!r});m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
p=pathlib.Path('new-owned');p.mkdir();f=p/'file';f.write_bytes(b'exact bytes')
a=m.WindowsStorage();a.inspect(str(p.resolve()),'directory',False);a.inspect(str(f.resolve()),'file',False)
print(json.dumps({{'input':sys.stdin.read(),'cwd':str(pathlib.Path.cwd().resolve()),'bytes':f.read_text()}}))
print('owned-child-stderr',file=sys.stderr)
'''
                result = subprocess.run([sys.executable, '-I', '-B', str(SCRIPT), '--cwd', str(private), '--', sys.executable, '-I', '-B', '-c', code],
                                        input='exact stdin', text=True, capture_output=True, timeout=20)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads(result.stdout), {'input': 'exact stdin', 'cwd': str(private.resolve()), 'bytes': 'exact bytes'})
                self.assertIn('owned-child-stderr', result.stderr)
                diagnostic = json.loads(result.stderr.splitlines()[0]); self.assertTrue(diagnostic['parent_unchanged'])
                self.assertEqual(diagnostic['restricted_copy'], before['owner'] != before['user'])
                self.assertEqual(native.snapshot(original), before)
        finally: native.k.CloseHandle(original)

    def test_native_job_reaps_descendants_on_parent_exit_and_launcher_termination(self):
        native_model, before, events = self.model(exit_code=0)
        self.assertEqual(self.supervise(native_model, before), 0)
        native_model.reap.assert_called_once_with(40)
        if os.name != 'nt': return
        native = launcher.Native()
        native.k.OpenProcess.argtypes = [launcher.DWORD, launcher.LONG, launcher.DWORD]
        native.k.OpenProcess.restype = launcher.HANDLE
        for exit_early in [True, False]:
            temporary = tempfile.TemporaryDirectory()
            with self.subTest(exit_early=exit_early), temporary as directory:
                checker = SCRIPT.with_name('windows-storage-acl.py')
                acl_spec = importlib.util.spec_from_file_location('native_token_reaping_acl_fixture', checker)
                acl = importlib.util.module_from_spec(acl_spec); acl_spec.loader.exec_module(acl)
                private = Path(directory) / 'private'; acl.WindowsStorage().create(str(private), 'directory')
                code = '''import json,os,pathlib,subprocess,sys,time
child=subprocess.Popen([sys.executable,'-I','-B','-c','import time;time.sleep(120)'],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
pathlib.Path('pids.json').write_text(json.dumps([os.getpid(),child.pid]))
''' + ('''deadline=time.monotonic()+15
while not pathlib.Path('release').exists():
 if time.monotonic()>deadline:raise RuntimeError('native fixture release deadline')
 time.sleep(0.02)
''' if exit_early else 'time.sleep(120)\n')
                process = subprocess.Popen([sys.executable, '-I', '-B', str(SCRIPT), '--cwd', str(private), '--', sys.executable, '-I', '-B', '-c', code],
                                           stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                held = []
                try:
                    record = private / 'pids.json'; deadline = time.monotonic() + 10; pids = None
                    while process.poll() is None and time.monotonic() < deadline:
                        try: pids = json.loads(record.read_text()); break
                        except (FileNotFoundError, json.JSONDecodeError): time.sleep(0.02)
                    self.assertTrue(pids, process.communicate(timeout=5) if process.poll() is not None else 'child did not start')
                    for pid in pids:
                        handle = native.k.OpenProcess(0x100000, False, pid)
                        self.assertTrue(handle); held.append(handle)
                    if exit_early: (private / 'release').write_text('release')
                    else: process.terminate()
                    stdout, stderr = process.communicate(timeout=10)
                    if exit_early:
                        self.assertEqual(process.returncode, 0, stderr)
                        self.assertTrue(any(json.loads(line).get('original_windows_cleanup') == 'verified' for line in stderr.splitlines()))
                    else: self.assertNotEqual(process.returncode, 0)
                    for handle in held: self.assertEqual(native.k.WaitForSingleObject(handle, 10000), 0)
                finally:
                    if process.poll() is None: process.kill(); process.communicate(timeout=10)
                    for handle in held: native.k.CloseHandle(handle)
                    # Allow this exited fixture's Windows sharing lock to clear.
                    # Cleanup still fails if the lock persists beyond the deadline.
                    deadline = time.monotonic() + 5
                    while True:
                        try: temporary.cleanup(); break
                        except PermissionError as error:
                            if error.winerror != 32 or time.monotonic() >= deadline: raise
                            time.sleep(0.05)


if __name__ == '__main__': unittest.main()
