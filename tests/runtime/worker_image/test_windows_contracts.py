"""Portable Windows policy/API fixtures; these are not native Windows evidence."""
import ctypes
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from ud_agent import snapshot_receiver as receiver
from ud_agent.userspace_bootstrap import _verify_windows_job


class WindowsSnapshotContracts(unittest.TestCase):
    def test_directory_policy_rejects_every_reparse_or_non_directory(self):
        for mode, attributes, valid in [(stat.S_IFDIR, 0, True), (stat.S_IFDIR, 0x20, True),
                                         (stat.S_IFDIR, 0x400, False), (stat.S_IFREG, 0, False),
                                         (stat.S_IFLNK, 0, False), (0, 0, False)]:
            info = SimpleNamespace(st_mode=mode, st_file_attributes=attributes)
            with self.subTest(mode=mode, attributes=attributes), mock.patch.object(receiver.os, 'lstat', return_value=info):
                if valid:
                    self.assertIs(receiver._windows_directory('owned'), info)
                else:
                    with self.assertRaisesRegex(ValueError, 'reparse point'):
                        receiver._windows_directory('owned')

    def test_real_directory_creation_cleanup_and_context_lifetime(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            stage = parent / 'snapshot'
            stage.mkdir()
            fd = receiver._create_file(str(stage), 'nested/data.conllu')
            os.write(fd, b'preserved\r\n')
            os.close(fd)
            self.assertEqual((stage / 'nested/data.conllu').read_bytes(), b'preserved\r\n')
            with self.assertRaises(FileExistsError):
                receiver._create_file(str(stage), 'nested/data.conllu')
            pi, si = parent.stat(), stage.stat()
            snapshot = receiver.WindowsStagedSnapshot(str(parent), 'snapshot', str(stage), (pi.st_dev, pi.st_ino), (si.st_dev, si.st_ino))
            self.assertEqual(snapshot.directory_fd, str(stage))
            with snapshot as selected:
                self.assertIs(selected, snapshot)
            self.assertTrue(snapshot._closed)
            self.assertFalse(stage.exists())
            snapshot.cleanup()

    def test_promote_changes_only_the_owned_staging_name_and_preserves_data(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            stage = parent / 'snapshot'
            stage.mkdir()
            (stage / 'a').write_bytes(b'bytes')
            pi, si = parent.stat(), stage.stat()
            value = receiver.WindowsStagedSnapshot(str(parent), 'snapshot', str(stage), (pi.st_dev, pi.st_ino), (si.st_dev, si.st_ino))
            with self.assertRaisesRegex(RuntimeError, 'PROMOTION_INVALID'):
                value.promote('escape')
            (parent / 'data').write_bytes(b'foreign')
            with self.assertRaisesRegex(RuntimeError, 'PROMOTION_CONFLICT'):
                value.promote('data')
            (parent / 'data').unlink()
            value.promote('data')
            self.assertEqual(value.name, 'data')
            self.assertEqual(value.path, str(parent / 'data'))
            self.assertEqual((parent / 'data/a').read_bytes(), b'bytes')
            self.assertTrue(value._closed)
            value.cleanup()
            with self.assertRaisesRegex(RuntimeError, 'PROMOTION_INVALID'):
                value.promote('data')

    def test_identity_changes_block_cleanup_and_promotion_before_host_mutation(self):
        for method in ['cleanup', 'promote']:
            for parent, current in [(SimpleNamespace(st_dev=9, st_ino=2), SimpleNamespace(st_dev=3, st_ino=4)),
                                    (SimpleNamespace(st_dev=1, st_ino=9), SimpleNamespace(st_dev=3, st_ino=4)),
                                    (SimpleNamespace(st_dev=1, st_ino=2), SimpleNamespace(st_dev=9, st_ino=4)),
                                    (SimpleNamespace(st_dev=1, st_ino=2), SimpleNamespace(st_dev=3, st_ino=9))]:
                value = receiver.WindowsStagedSnapshot('parent', 'snapshot', 'parent/snapshot', (1, 2), (3, 4))
                with self.subTest(method=method, parent=parent, current=current), mock.patch.object(receiver, '_windows_directory', side_effect=[parent, current]), mock.patch.object(receiver, '_remove_windows_contents') as remove, mock.patch.object(receiver.os, 'rename') as rename:
                    with self.assertRaisesRegex(RuntimeError, '_UNVERIFIED'):
                        getattr(value, method)(*(['data'] if method == 'promote' else []))
                    remove.assert_not_called()
                    rename.assert_not_called()
                    self.assertFalse(value._closed)

    def test_recursive_cleanup_rejects_reparse_special_files_and_changed_directory(self):
        identity = SimpleNamespace(st_dev=1, st_ino=2)
        for mode, attributes in [(stat.S_IFDIR, 0x400), (stat.S_IFREG, 0x400), (stat.S_IFIFO, 0)]:
            entry = SimpleNamespace(path='owned/entry', stat=lambda follow_symlinks: SimpleNamespace(st_mode=mode, st_file_attributes=attributes))
            with self.subTest(mode=mode, attributes=attributes), mock.patch.object(receiver, '_windows_directory', return_value=identity), mock.patch.object(receiver.os, 'scandir', return_value=[entry]), mock.patch.object(receiver.os, 'unlink') as unlink, mock.patch.object(receiver.os, 'rmdir') as rmdir:
                with self.assertRaisesRegex(RuntimeError, 'CLEANUP_UNVERIFIED'):
                    receiver._remove_windows_contents('owned')
                unlink.assert_not_called()
                rmdir.assert_not_called()
        for changed in [SimpleNamespace(st_dev=9, st_ino=2), SimpleNamespace(st_dev=1, st_ino=9)]:
            with mock.patch.object(receiver, '_windows_directory', side_effect=[identity, changed]), mock.patch.object(receiver.os, 'scandir', return_value=[]):
                with self.assertRaisesRegex(RuntimeError, 'CLEANUP_UNVERIFIED'):
                    receiver._remove_windows_contents('owned')


class WindowsJobContracts(unittest.TestCase):
    def verify(self, changes=None, fail=None):
        changes = changes or {}
        calls = []
        class Query:
            def __call__(self, handle, kind, pointer, size, returned):
                self_case.assertIsNone(handle)
                self_case.assertIsNone(returned)
                self_case.assertEqual(size, ctypes.sizeof(pointer._obj))
                calls.append(kind)
                if kind == fail:
                    return False
                if kind == 9:
                    value = pointer._obj
                    value.basic.flags = changes.get('flags', 0x2000 | 0x100 | 0x200 | 8 | 2 | 4)
                    value.basic.processes = changes.get('processes', 128)
                    value.process_memory = changes.get('process_memory', 2 * 1024**3)
                    value.job_memory = changes.get('job_memory', 2 * 1024**3)
                    value.basic.process_time = changes.get('process_time', 300 * 10_000_000)
                    value.basic.job_time = changes.get('job_time', 300 * 10_000_000)
                elif kind == 15:
                    pointer._obj[0] = changes.get('cpu_flags', 5)
                    pointer._obj[1] = changes.get('cpu_rate', 10000)
                else:
                    raise AssertionError('unexpected native job query')
                return True
        self_case = self
        query = Query()
        kernel = SimpleNamespace(QueryInformationJobObject=query)
        with mock.patch.object(ctypes, 'WinDLL', return_value=kernel, create=True) as loader:
            _verify_windows_job()
            loader.assert_called_once_with('kernel32', use_last_error=True)
        self.assertEqual(calls, [9, 15])
        self.assertEqual(len(query.argtypes), 5)

    def test_effective_current_job_accepts_exact_limits_and_stricter_nonzero_bounds(self):
        self.verify()
        self.verify(dict(processes=1, process_memory=1, job_memory=1, process_time=1, job_time=1, cpu_rate=1))

    def test_missing_controls_and_each_independent_limit_failure_are_rejected(self):
        required = 0x2000 | 0x100 | 0x200 | 8 | 2 | 4
        cases = [{'flags': required ^ flag} for flag in [0x2000, 0x100, 0x200, 8, 2, 4]]
        for name, maximum in [('processes', 128), ('process_memory', 2 * 1024**3), ('job_memory', 2 * 1024**3), ('process_time', 300 * 10_000_000), ('job_time', 300 * 10_000_000), ('cpu_rate', 10000)]:
            cases.extend([{name: 0}, {name: maximum + 1}])
        cases.extend({'cpu_flags': flags} for flags in [0, 1, 4])
        for values in cases:
            with self.subTest(values=values), self.assertRaisesRegex(RuntimeError, 'RESOURCE_LIMIT_UNAVAILABLE'):
                self.verify(values)
        with self.assertRaisesRegex(RuntimeError, 'PROCESS_CONTAINMENT_UNVERIFIED'):
            self.verify(fail=9)
        with self.assertRaisesRegex(RuntimeError, 'RESOURCE_LIMIT_UNAVAILABLE'):
            self.verify(fail=15)


if __name__ == '__main__':
    unittest.main()
