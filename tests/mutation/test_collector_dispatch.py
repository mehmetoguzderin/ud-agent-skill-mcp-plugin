"""Original fixed-command dispatch models, never native confinement evidence."""
import importlib.util
import json
import os
from pathlib import Path
import sys
import stat
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('shared_collector_dispatch', ROOT / 'scripts/quality/secondary-child.py')
child = importlib.util.module_from_spec(spec); spec.loader.exec_module(child)


class CollectorDispatchTests(unittest.TestCase):
    def test_both_inventory_routes_use_the_same_fixed_collector_python_and_git_profile(self):
        for runner in ('acceptance-collect', 'vitest-collect'):
            with self.subTest(runner=runner), tempfile.TemporaryDirectory() as temporary:
                parent = Path(temporary).resolve(); root = parent / 'tree'; root.mkdir(); cache = parent / 'cache'; cache.mkdir(mode=0o700)
                request = parent / 'request.json'; result = parent / 'result.data'; result.touch(mode=0o600)
                request.write_text(json.dumps({'schema_version': 1, 'runner': runner, 'selection': 'all', 'mutation': None}))
                ordinary = Path.lstat
                def cache_metadata(path, *args, **kwargs):
                    value = ordinary(path, *args, **kwargs)
                    if path == cache:
                        return types.SimpleNamespace(st_uid=1000, st_mode=stat.S_IFDIR | 0o700)
                    return value
                with patch.object(child.os, 'getuid', return_value=1000, create=True), patch.object(Path, 'lstat', cache_metadata), patch.object(child.sys, 'argv', ['fixed-child', str(request), str(result)]), patch.object(child.Path, 'cwd', return_value=root), patch.object(child, 'fresh_job'), patch.dict(child.os.environ, {'TMPDIR': str(cache), 'PATH': '/fixed/ordinary/bin'}), patch.object(child.subprocess, 'run', return_value=types.SimpleNamespace(returncode=0)) as run:
                    self.assertEqual(child.main(), 0)
                expected = ['/opt/mutation/node/bin/node', '/opt/mutation/harness/collect-mutation-tests.mjs', '--python', sys.executable, '--result', str(result)]
                if runner == 'vitest-collect': expected += ['--result-format', 'vitest-tests']
                self.assertEqual(run.call_args.args[0], expected)
                self.assertEqual(run.call_args.kwargs['env']['PATH'], '/opt/mutation/git/bin:/fixed/ordinary/bin')

    def test_neither_inventory_route_accepts_a_filter_or_child_materialization(self):
        for runner in ('acceptance-collect', 'vitest-collect'):
            for values in ({'selection': 'tests/one.test.mjs'}, {'mutation': {'path': 'source'}}):
                with self.subTest(runner=runner, values=values), self.assertRaisesRegex(ValueError, 'complete pristine'):
                    child.prepare({'schema_version': 1, 'runner': runner, 'selection': 'all', 'mutation': None, **values}, Path('/not-executed'))


if __name__ == '__main__': unittest.main()
