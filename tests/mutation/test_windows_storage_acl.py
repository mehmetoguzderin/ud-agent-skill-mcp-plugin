"""Original quality-storage ACL policy and native Windows handle checks. MIT."""
from __future__ import annotations
import ctypes
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('windows_storage_acl', ROOT / 'scripts/quality/windows-storage-acl.py')
ACL = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(ACL)


class WindowsStorageAclTests(unittest.TestCase):
    def test_native_epoch_and_readonly_deletion_hold_exact_private_inodes(self):
        if os.name != 'nt':
            with self.assertRaisesRegex(ValueError, 'native Windows'): ACL.WindowsStorage()
            return
        native = ACL.WindowsStorage()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve() / 'private'; native.create(str(root), 'directory')
            file = root / 'sealed'; native.create(str(file), 'file', b'unchanged'); file.chmod(0o444)
            before = file.stat(); expected = (before.st_dev, before.st_ino)
            with self.assertRaisesRegex(ValueError, 'identity changed'):
                native.set_epoch(str(file), 'file', (expected[0], expected[1] + 1))
            self.assertEqual(file.stat().st_mtime_ns, before.st_mtime_ns)
            native.set_epoch(str(file), 'file', expected)
            self.assertEqual(file.stat().st_mtime_ns, 0); self.assertEqual(file.read_bytes(), b'unchanged')
            self.assertEqual((file.stat().st_dev, file.stat().st_ino), expected)
            self.assertFalse(file.stat().st_mode & 0o222)
            native.set_epoch(str(root), 'directory'); self.assertEqual(root.stat().st_mtime_ns, 0)
            alias = root / 'alias'; alias.symlink_to(file)
            with self.assertRaises((ValueError, OSError)): native.set_epoch(str(alias), 'file')
            with self.assertRaises((ValueError, OSError)): native.unlink_readonly(str(alias))
            self.assertEqual(file.read_bytes(), b'unchanged'); alias.unlink()
            hardlink = root / 'hardlink'; os.link(file, hardlink)
            with self.assertRaisesRegex(ValueError, 'linked'): native.unlink_readonly(str(file))
            self.assertEqual(file.read_bytes(), b'unchanged'); self.assertFalse(file.stat().st_mode & 0o222)
            file.chmod(0o600); hardlink.unlink(); file.chmod(0o444)
            with self.assertRaisesRegex(ValueError, 'identity changed'):
                native.unlink_readonly(str(file), (expected[0], expected[1] + 1))
            self.assertEqual(file.read_bytes(), b'unchanged')
            native.unlink_readonly(str(file), expected); self.assertFalse(file.exists())
            # Ordinary build outputs inherit read access from TEMP. Their
            # timestamp/cleanup operations require no foreign writer, while
            # private journal admission retains the stronger policy.
            readable = Path(temporary) / 'context'; readable.write_bytes(b'public build input'); readable.chmod(0o444)
            native.set_epoch(str(readable), 'file'); self.assertEqual(readable.stat().st_mtime_ns, 0)
            self.assertEqual(readable.read_bytes(), b'public build input')
            native.unlink_readonly(str(readable)); self.assertFalse(readable.exists())

    def setUp(self):
        self.caller = ACL.sid(5, 21, 100, 200, 300, 1001)
        self.other = ACL.sid(5, 21, 100, 200, 300, 1002)
        self.allow = (0, ACL.FULL, self.caller)

    def test_private_policy_matches_guard_trusted_principals(self):
        ACL.verify_acl(self.caller, self.caller, [self.allow, (0, ACL.FULL, ACL.SYSTEM), (0, ACL.FULL, ACL.ADMINS)], True)
        ACL.verify_acl(self.caller, self.caller, [(0, 0x10000000, self.caller)], True)
        with self.assertRaisesRegex(ValueError, 'another principal'):
            ACL.verify_acl(self.caller, self.caller, [self.allow, (0, 0x120089, self.other)], True)

    def test_ordinary_mutation_owner_check_does_not_admit_foreign_owned_objects(self):
        ACL.verify_owner(self.caller, self.caller)
        with self.assertRaisesRegex(ValueError, 'current user'):
            ACL.verify_owner(self.other, self.caller)
        # Permission-policy admission remains strict for private state and
        # control parents even though ordinary held mutations use ownership.
        for private in (True, False):
            with self.subTest(private=private), self.assertRaisesRegex(ValueError, 'another principal'):
                ACL.verify_acl(self.caller, self.caller, [self.allow, (0, ACL.FULL, self.other)], private)

    def test_control_parent_may_be_readable_but_not_writable_by_others(self):
        ACL.verify_acl(self.caller, self.caller, [self.allow, (0, 0x1200A9, self.other)], False)
        for mask in (2, 4, 16, 64, 256, 0x10000, 0x40000, 0x80000, 0x40000000, 0x10000000):
            with self.subTest(mask=mask), self.assertRaisesRegex(ValueError, 'another principal'):
                ACL.verify_acl(self.caller, self.caller, [self.allow, (0, mask, self.other)], False)

    def test_owner_null_dacl_missing_authority_and_unknown_aces_fail_closed(self):
        for owner, aces, message in [(self.other, [self.allow], 'current user'), (self.caller, None, 'DACL'),
                                     (self.caller, [], 'full control'), (self.caller, [(0, 1, self.caller)], 'full control'),
                                     (self.caller, [(0, ACL.FULL, self.caller, 8)], 'full control'),
                                     (self.caller, [self.allow, (5, ACL.FULL, self.caller)], 'unsupported')]:
            with self.subTest(message=message), self.assertRaisesRegex(ValueError, message):
                ACL.verify_acl(owner, self.caller, aces, True)

    def test_short_spelling_expansion_must_still_match_the_held_target(self):
        ACL.verify_final_path(r'C:\Users\RUNNER~1\Temp\owned', r'C:\Users\runneradmin\Temp\owned', '\\\\?\\C:\\Users\\runneradmin\\Temp\\owned')
        ACL.verify_final_path(r'\\server\share\OWNED', r'\\server\share\OWNED', '\\\\?\\UNC\\server\\share\\owned')
        with self.assertRaisesRegex(ValueError, 'contains an alias') as raised:
            ACL.verify_final_path(r'C:\Users\RUNNER~1\Temp\owned', r'C:\Users\runneradmin\Temp\owned', '\\\\?\\D:\\foreign\\owned')
        self.assertIn('requested', str(raised.exception)); self.assertIn('actual', str(raised.exception))
        with self.assertRaises(ValueError) as bounded:
            ACL.verify_final_path('x' * 10000, 'y' * 10000, 'z' * 10000)
        self.assertLess(len(str(bounded.exception)), 600)

    def test_native_windows_creates_owned_controls_and_preserves_existing_files(self):
        if os.name != 'nt':
            with self.assertRaisesRegex(ValueError, 'native Windows'): ACL.WindowsStorage()
            return
        native = ACL.WindowsStorage()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve(); directory = root / 'private'; filename = directory / 'reservation.json'
            native.create(str(directory), 'directory')
            native.create(str(filename), 'file', b'{"owned":true}\n')
            for value, kind in ((directory, 'directory'), (filename, 'file')):
                observed = native.inspect(str(value), kind)
                info = value.stat()
                # Node/libuv uses the low32-bit volume serial and64-bit file
                # index; current Python also exposes the extended128-bit ID.
                self.assertEqual(observed, {'device': str(info.st_dev & 0xFFFFFFFF), 'inode': str(info.st_ino & 0xFFFFFFFFFFFFFFFF)})
            short_name = native.kernel.GetShortPathNameW
            short_name.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint32]; short_name.restype = ctypes.c_uint32
            short = ctypes.create_unicode_buffer(32768)
            count = short_name(str(filename), short, len(short))
            self.assertTrue(0 < count < len(short))
            # Windows may disable 8.3 names. Exercise the alias only when the
            # filesystem actually supplies one; the portable case above models it.
            if os.path.normcase(short.value) != os.path.normcase(str(filename)):
                self.assertEqual(native.inspect(short.value, 'file'), native.inspect(str(filename), 'file'))
            with self.assertRaises(OSError): native.create(str(filename), 'file', b'overwritten')
            self.assertEqual(filename.read_bytes(), b'{"owned":true}\n')
            alias = directory / 'hard-link'; os.link(filename, alias)
            with self.assertRaisesRegex(ValueError, 'linked'): native.inspect(str(filename), 'file')
            self.assertEqual(alias.read_bytes(), b'{"owned":true}\n')

    def test_native_windows_reparse_paths_do_not_gain_spelling_credit(self):
        if os.name != 'nt':
            with self.assertRaisesRegex(ValueError, 'native Windows'): ACL.WindowsStorage()
            return
        native = ACL.WindowsStorage()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve(); actual = root / 'actual'; native.create(str(actual), 'directory')
            native.create(str(actual / 'journal.json'), 'file', b'owned')
            alias = root / 'linked'; alias.symlink_to(actual, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, 'linked|alias'): native.inspect(str(alias), 'directory')
            with self.assertRaisesRegex(ValueError, 'alias'): native.inspect(str(alias / 'journal.json'), 'file')
            self.assertEqual((actual / 'journal.json').read_bytes(), b'owned')

    def test_native_windows_rejects_a_journal_acl_modified_after_creation(self):
        if os.name != 'nt':
            with self.assertRaisesRegex(ValueError, 'native Windows'): ACL.WindowsStorage()
            return
        native = ACL.WindowsStorage()
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary).resolve() / 'private'; native.create(str(directory), 'directory')
            filename = directory / 'journal.json'; native.create(str(filename), 'file', b'unchanged')
            # Modify only this test-owned file, using a held no-reparse handle.
            handle = native.kernel.CreateFileW(str(filename), 0x40000 | 0x20000, 1 | 2, None, 3, 0x00200000, None)
            if handle == ctypes.c_void_p(-1).value: raise ctypes.WinError(ctypes.get_last_error())
            descriptor = ctypes.c_void_p()
            try:
                native.require(native.security.ConvertStringSecurityDescriptorToSecurityDescriptorW('D:P(A;;FA;;;WD)', 1, ctypes.byref(descriptor), None))
                setter = native.security.SetKernelObjectSecurity
                setter.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p]; setter.restype = ctypes.c_int
                native.require(setter(handle, 4 | 0x80000000, descriptor))
            finally:
                if descriptor: native.kernel.LocalFree(descriptor)
                native.kernel.CloseHandle(handle)
            with self.assertRaisesRegex(ValueError, 'another principal'): native.inspect(str(filename), 'file')
            self.assertEqual(filename.read_bytes(), b'unchanged')


if __name__ == '__main__': unittest.main()
