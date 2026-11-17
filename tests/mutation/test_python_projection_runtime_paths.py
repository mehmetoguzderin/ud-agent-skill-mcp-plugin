"""Original path-identity data checks; generated modules are never executed."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('ud_projection_runtime_path_data', ROOT / 'scripts/quality/python-runtime-projection.py')
projection = importlib.util.module_from_spec(spec)
spec.loader.exec_module(projection)


def function_at(file):
    # A data stand-in for a code object's filename, never compiled or executed.
    return SimpleNamespace(__code__=SimpleNamespace(co_filename=str(file)))


class PythonProjectionRuntimePathTests(unittest.TestCase):
    def test_actual_release_parent_spelling_binds_the_exact_canonical_runtime_module(self):
        with tempfile.TemporaryDirectory() as temporary:
            runtime = Path(temporary).resolve() / 'work/mutants'
            (runtime / 'scripts/release').mkdir(parents=True)
            module = runtime / 'scripts/runtime/private_perl.py'
            module.parent.mkdir()
            content = b'# authored ordinary source data\n'
            module.write_bytes(content)
            context = runtime / projection.CONTEXT
            context_data = json.dumps({
                'schema_version': 1, 'version': projection.VERSION, 'uid': 100001,
                'projection_sequence': 100001,
                'helper_sha256': hashlib.sha256(Path(projection.__file__).read_bytes()).hexdigest(),
                'mode': 'collection', 'active_key': None,
                'files': [{'path': 'scripts/runtime/private_perl.py', 'size_bytes': len(content),
                           'projected_sha256': hashlib.sha256(content).hexdigest()}],
            }).encode()
            context.write_bytes(context_data)
            raw = runtime / 'scripts/release/../runtime/private_perl.py'
            trampoline = SimpleNamespace()
            trampoline._ud_projection_context = (100001, hashlib.sha256(context_data).hexdigest())
            original_lstat = Path.lstat
            def owned(path):
                info = original_lstat(path)
                # Model only the root-owned Linux namespace on native hosts.
                return SimpleNamespace(st_dev=info.st_dev, st_ino=info.st_ino,
                    st_mode=(stat.S_IFDIR | 0o755) if stat.S_ISDIR(info.st_mode) else (stat.S_IFREG | 0o444),
                    st_uid=0, st_nlink=1, st_size=info.st_size,
                    st_mtime_ns=info.st_mtime_ns, st_ctime_ns=info.st_ctime_ns)
            reads = []
            def ordinary(path, *args, **kwargs):
                reads.append(Path(path))
                if path == context:
                    return context_data
                if path == module:
                    return content
                raise AssertionError('unexpected runtime identity read: ' + str(path))
            projection._RUNTIME_CACHE.clear()
            with mock.patch.object(projection, '_runtime_uid', return_value=100001), \
                    mock.patch.object(Path, 'lstat', owned), \
                    mock.patch.object(projection, '_ordinary', side_effect=ordinary):
                actual = projection._bind_runtime_context(function_at(raw), trampoline)
            self.assertEqual(actual, 'scripts.runtime.private_perl')
            self.assertEqual(reads, [context, module])

    def test_relative_filename_is_rejected_before_any_canonicalization(self):
        with mock.patch.object(Path, 'resolve', side_effect=AssertionError('relative path must not be resolved')) as resolve:
            with self.assertRaisesRegex(ValueError, 'no absolute runtime source identity'):
                projection._bind_runtime_context(function_at('scripts/runtime/private_perl.py'), SimpleNamespace())
        resolve.assert_not_called()

    def test_existing_absolute_file_outside_issued_namespace_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            outside = Path(temporary).resolve() / 'private_perl.py'
            outside.write_text('# outside data\n')
            with mock.patch.object(projection, '_ordinary') as ordinary:
                with self.assertRaisesRegex(ValueError, 'outside its issued runtime namespace'):
                    projection._bind_runtime_context(function_at(outside), SimpleNamespace())
            ordinary.assert_not_called()

    def test_symlink_escape_resolves_outside_namespace_and_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            outside = root / 'outside.py'
            outside.write_text('# outside data\n')
            link = root / 'work/mutants/scripts/runtime/private_perl.py'
            link.parent.mkdir(parents=True)
            original_resolve = Path.resolve
            def escaped(path, strict=False):
                if path == link:
                    self.assertIs(strict, True)
                    return outside
                return original_resolve(path, strict=strict)
            if os.name != 'nt':
                link.symlink_to(outside)
            # Windows models only the same filesystem resolution, avoiding a
            # privileged symlink operation. There are no skipped policy cases.
            resolution = mock.patch.object(Path, 'resolve', escaped) if os.name == 'nt' else mock.patch.object(projection, '_runtime_uid', return_value=100001)
            with resolution, mock.patch.object(projection, '_ordinary') as ordinary:
                with self.assertRaisesRegex(ValueError, 'outside its issued runtime namespace'):
                    projection._bind_runtime_context(function_at(link), SimpleNamespace())
            ordinary.assert_not_called()


if __name__ == '__main__':
    unittest.main()
