"""Native context timestamp normalization preserves ordinary input identity."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location('context_timestamps_test', ROOT / 'scripts/runtime/context_timestamps.py')
timestamps = importlib.util.module_from_spec(spec); spec.loader.exec_module(timestamps)


class ContextTimestampTests(unittest.TestCase):
    def test_windows_handoff_keeps_identity_captured_before_helper_loading(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); file = root / 'input'; file.write_bytes(b'original')
            before = file.stat(); expected = before.st_dev, before.st_ino
            def substitute(_):
                file.rename(root / 'retained'); file.write_bytes(b'foreign')
            def mutation(filename, kind, captured):
                self.assertEqual(captured, expected)
                current = Path(filename).stat()
                if (current.st_dev, current.st_ino) != captured: raise ValueError('identity changed')
                self.fail('replacement must not become timestamp authority')
            spec = SimpleNamespace(loader=SimpleNamespace(exec_module=substitute))
            native = SimpleNamespace(WindowsStorage=lambda: SimpleNamespace(set_epoch=mutation))
            with mock.patch.object(timestamps, 'os', SimpleNamespace(name='nt')), \
                    mock.patch.object(timestamps.importlib.util, 'spec_from_file_location', return_value=spec), \
                    mock.patch.object(timestamps.importlib.util, 'module_from_spec', return_value=native), \
                    self.assertRaisesRegex(ValueError, 'identity changed'):
                timestamps.set_epoch(file)
            self.assertEqual(file.read_bytes(), b'foreign'); self.assertEqual((root / 'retained').read_bytes(), b'original')

    def test_native_epoch_preserves_file_bytes_identity_and_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve(); file = root / 'input'; file.write_bytes(b'original\r\n\x00bytes'); file.chmod(0o444)
            before = file.stat()
            timestamps.set_epoch(file); timestamps.set_epoch(root)
            after = file.stat()
            self.assertEqual((before.st_dev, before.st_ino, before.st_mode), (after.st_dev, after.st_ino, after.st_mode))
            self.assertEqual(after.st_mtime_ns, 0); self.assertEqual(root.stat().st_mtime_ns, 0)
            self.assertEqual(file.read_bytes(), b'original\r\n\x00bytes')

    def test_foreign_symlink_timestamp_is_refused_without_changing_target(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve(); target = root / 'foreign'; target.write_bytes(b'retained')
            alias = root / 'alias'; alias.symlink_to(target)
            before = target.stat()
            with self.assertRaisesRegex(ValueError, 'not ordinary'): timestamps.set_epoch(alias)
            after = target.stat()
            self.assertEqual((before.st_dev, before.st_ino, before.st_mtime_ns), (after.st_dev, after.st_ino, after.st_mtime_ns))
            self.assertEqual(target.read_bytes(), b'retained')
