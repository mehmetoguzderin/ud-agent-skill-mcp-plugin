"""Original SDK config loading only; no generated program is executed."""
import importlib.util
from contextlib import contextmanager
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock

from mutmut import configuration

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('ud_original_exec_config', ROOT / 'scripts/quality/python-runtime-projection.py')
projection = importlib.util.module_from_spec(spec)
spec.loader.exec_module(projection)


class PythonProjectionExecConfigTests(unittest.TestCase):
    def setUp(self):
        self.previous = configuration._config
        configuration.reset_config()

    def tearDown(self):
        configuration._config = self.previous

    @contextmanager
    def root_metadata(self, modes=None):
        original = Path.lstat
        def owned(path):
            values = list(original(path))
            values[0] = (stat.S_IFDIR | 0o755) if stat.S_ISDIR(values[0]) else (stat.S_IFREG | 0o644)
            values[0] = (modes or {}).get(path, values[0])
            values[4] = 0  # Model the OCI-owned ordinary inputs on native hosts.
            return os.stat_result(values)
        # Windows can load the original config too; model only the POSIX
        # metadata/flags of the protected input, never claim native isolation.
        with mock.patch.object(Path, 'lstat', owned), \
                mock.patch.object(projection.os, 'O_NOFOLLOW', getattr(os, 'O_NOFOLLOW', 0), create=True), \
                mock.patch.object(projection.os, 'O_CLOEXEC', getattr(os, 'O_CLOEXEC', 0), create=True):
            yield

    def test_fresh_exec_uses_real_work_config_and_restores_private_job_cwd(self):
        with tempfile.TemporaryDirectory() as temporary:
            work, job = Path(temporary).resolve() / 'work', Path(temporary).resolve() / 'job'
            work.mkdir(); job.mkdir()
            (work / 'pyproject.toml').write_text('[tool.mutmut]\nsource_paths = ["scripts"]\nonly_mutate = ["scripts/*.py"]\n')
            original = Path.cwd()
            try:
                os.chdir(job)
                with self.root_metadata():
                    projection._initialize_stats_config(work)
                actual = configuration.config()
                self.assertEqual(actual.source_paths, [Path('scripts')])
                self.assertEqual(actual.resolved_mutated_source_paths, [work / 'mutants/scripts'])
                self.assertEqual(actual.only_mutate, ['scripts/*.py'])
                self.assertEqual(Path.cwd(), job)
            finally:
                os.chdir(original)

    def test_inherited_config_is_preserved_and_failed_load_restores_cwd(self):
        inherited = object()
        configuration._config = inherited
        projection._initialize_stats_config(Path('/absent-config-must-not-be-opened'))
        self.assertIs(configuration._config, inherited)
        configuration.reset_config()
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            (work / 'pyproject.toml').write_text('[tool.mutmut]\nsource_paths = ["scripts"]\nprocess_isolation = "invalid"\n')
            original = Path.cwd()
            with self.root_metadata(), self.assertRaisesRegex(ValueError, 'process_isolation'):
                projection._initialize_stats_config(work)
            self.assertEqual(Path.cwd().resolve(), original.resolve())
            self.assertIsNone(configuration._config)

    def test_writable_config_and_symlink_cannot_supply_exec_configuration(self):
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            config = work / 'pyproject.toml'
            config.write_text('[tool.mutmut]\nsource_paths = ["scripts"]\n')
            with self.root_metadata({config: stat.S_IFREG | 0o666}), self.assertRaisesRegex(ValueError, 'protected root-owned'):
                projection._initialize_stats_config(work)
            with self.root_metadata({config: stat.S_IFLNK | 0o777}), self.assertRaisesRegex(ValueError, 'protected root-owned'):
                projection._initialize_stats_config(work)
            self.assertIsNone(configuration._config)


if __name__ == '__main__':
    unittest.main()
