"""Original child-loader models; no pytest, generated module or UID drop runs."""
import importlib.util
import os
from pathlib import Path
import stat
import sys
import types
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('ud_fixed_pytest_plugin_model', ROOT / 'scripts/quality/oci-isolation.py')
isolation = importlib.util.module_from_spec(spec)
with patch.dict(sys.modules, {'fcntl': types.SimpleNamespace()} if os.name == 'nt' else {}):
    spec.loader.exec_module(isolation)


class FixedPytestPluginTests(unittest.TestCase):
    def test_fixed_original_load_is_child_only_and_preserves_existing_collection_and_stats_plugins(self):
        existing = [object(), object()]
        fixed = types.SimpleNamespace()
        loader = types.SimpleNamespace(exec_module=Mock())
        specification = types.SimpleNamespace(loader=loader)
        ordinary = types.SimpleNamespace(st_mode=stat.S_IFREG | 0o444, st_uid=0, st_nlink=1)
        with patch.object(isolation.os, 'geteuid', return_value=100001, create=True), \
                patch.object(isolation.Path, 'lstat', return_value=ordinary), \
                patch.dict(os.environ, {'PYTEST_PLUGINS': 'candidate_tree_plugin'}), \
                patch.object(isolation.importlib.util, 'spec_from_file_location', return_value=specification) as admitted, \
                patch.object(isolation.importlib.util, 'module_from_spec', return_value=fixed):
            actual = isolation.fixed_pytest_plugins(existing)
            self.assertNotIn('PYTEST_PLUGINS', os.environ)
        self.assertEqual(actual, [existing[0], existing[1], fixed])
        self.assertEqual(existing, actual[:2])
        admitted.assert_called_once_with('ud_fixed_pytest_evidence', Path('/opt/mutation/harness/pytest_evidence.py'))
        loader.exec_module.assert_called_once_with(fixed)

    def test_root_and_unprotected_or_linked_modules_refuse_before_import(self):
        ordinary = {'st_mode': stat.S_IFREG | 0o444, 'st_uid': 0, 'st_nlink': 1}
        with patch.object(isolation.os, 'geteuid', return_value=0, create=True), \
                patch.object(isolation.importlib.util, 'spec_from_file_location') as imported:
            with self.assertRaisesRegex(RuntimeError, 'after the test UID drop'):
                isolation.fixed_pytest_plugins([])
            imported.assert_not_called()
        for changed in ({'st_mode': stat.S_IFLNK | 0o444}, {'st_uid': 100001}, {'st_nlink': 2}, {'st_mode': stat.S_IFREG | 0o644}):
            with self.subTest(changed=changed), \
                    patch.object(isolation.os, 'geteuid', return_value=100001, create=True), \
                    patch.object(isolation.Path, 'lstat', return_value=types.SimpleNamespace(**{**ordinary, **changed})), \
                    patch.object(isolation.importlib.util, 'spec_from_file_location') as imported:
                with self.assertRaisesRegex(RuntimeError, 'fixed protected SDK module'):
                    isolation.fixed_pytest_plugins([])
                imported.assert_not_called()


if __name__ == '__main__':
    unittest.main()
