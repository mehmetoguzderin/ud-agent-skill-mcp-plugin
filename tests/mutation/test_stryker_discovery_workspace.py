"""Original orchestration regression; no Stryker/test bodies execute here."""
from contextlib import ExitStack
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('stryker_workspace_original', ROOT / 'scripts/quality/oci-stryker.py')
backend = importlib.util.module_from_spec(spec); spec.loader.exec_module(backend)
fixture_spec = importlib.util.spec_from_file_location('stryker_workspace_boundary_fixture', Path(__file__).with_name('test_oci_exec.py'))
fixture = importlib.util.module_from_spec(fixture_spec); fixture_spec.loader.exec_module(fixture)
alias_spec = importlib.util.spec_from_file_location('stryker_workspace_posix_model', Path(__file__).with_name('test_oci_directory_aliases.py'))
alias = importlib.util.module_from_spec(alias_spec); alias_spec.loader.exec_module(alias)


class StrykerDiscoveryWorkspaceTests(unittest.TestCase):
    def exercise(self, mode):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve(); state = base / 'state'; work = state / 'work'; work.mkdir(parents=True)
            sdk = base / 'sdk'; (sdk / 'harness').mkdir(parents=True)
            entries = []
            for name, content in [('stryker.config.mjs', b'export default {};\n'), ('packages/example/src/main.ts', b'export const answer = true;\n')]:
                file = work / name; file.parent.mkdir(parents=True, exist_ok=True); file.write_bytes(content); file.chmod(0o644)
                entries.append(fixture.entry(name, content))
            receipt = {'source_tree_sha256': 'a' * 64, 'files': entries}
            harness = []
            for name in ['stryker-protected-runner.mjs', 'stryker-child.mjs', 'stryker-exec.py', 'oci-exec.py']:
                file = sdk / 'harness' / name; file.write_bytes(b'original harness identity fixture\n'); file.chmod(0o444)
                harness.append({'path': name, 'sha256': hashlib.sha256(file.read_bytes()).hexdigest()})
            (sdk / 'input-receipt.json').write_text(json.dumps({'harness': harness}))
            configuration = work / '.ud-protected-stryker.config.mjs'; events = []
            def pristine(phase):
                self.assertFalse(configuration.exists(), phase + ' must see the exact pristine source')
                if os.name == 'nt':
                    nodes = {file.relative_to(work).as_posix(): ('dir' if file.is_dir() else 'file', {}) for file in work.rglob('*')}
                    alias.inspect(nodes, {row['path']: row for row in entries})
                else:
                    with fixture.modeled_coordinator_owner():
                        descriptor = fixture.boundary._directory(str(work))
                        try: fixture.boundary._inventory(descriptor, {row['path']: row for row in entries}, {})
                        finally: fixture.boundary.os.close(descriptor)
                events.append(phase)
            def generation(argv, **_):
                pristine('operator-discovery')
                self.assertEqual(argv[1], str(work / 'scripts/quality/discover-stryker.mjs'))
                (state / 'stryker-generation.json').write_text(json.dumps({'mutants': [{'id': 'original-definition'}]}))
            test = self
            class Jobs:
                def __init__(self, *_): pass
                def run(self, runner, **kwargs):
                    test.assertEqual(runner, 'vitest-collect'); pristine('complete-test-discovery')
                    return {'status': 0, 'timed_out': False}, b'[{"id":"original-test"}]'
            def spec_for(name, *_):
                def load(module):
                    if name == 'ud_stryker_discovery_jobs': module.Jobs = Jobs
                    elif name == 'ud_stryker_discovery_exec': module.execute = lambda *_: None
                    else: raise AssertionError('unrelated module import')
                return types.SimpleNamespace(loader=types.SimpleNamespace(exec_module=load))
            def schedule(plan):
                pristine('frozen-schedule-verification'); self.assertTrue(plan['scope_complete'])
                self.assertEqual(plan['tests'], [{'id': 'original-test'}])
                if mode == 'rejected': raise ValueError('frozen schedule rejected')
            class Child:
                def wait(self, **_): return 0
                def poll(self): return 0
            def execute(argv, **_):
                events.append('actual-execution')
                self.assertEqual(argv[-1], str(configuration))
                self.assertEqual(configuration.read_text(), 'execution-only configuration\n')
                return Child()
            def mapped_path(name):
                value = str(name)
                if value == '/state': return state
                if value.startswith('/opt/mutation/'): return sdk / value.removeprefix('/opt/mutation/')
                return Path(name)
            with ExitStack() as stack:
                stack.enter_context(patch.object(backend.sys, 'platform', 'linux'))
                stack.enter_context(patch.object(backend.platform, 'machine', return_value='aarch64'))
                stack.enter_context(patch.object(backend.os, 'geteuid', return_value=0, create=True))
                stack.enter_context(patch.object(backend, 'Path', side_effect=mapped_path))
                stack.enter_context(patch.object(backend, 'verify_inputs', return_value=sdk / 'bin/ud-agent-guard'))
                stack.enter_context(patch.object(backend, 'diagnostic_configuration', return_value=('execution-only configuration\n', None)))
                stack.enter_context(patch.object(backend.subprocess, 'run', side_effect=generation))
                stack.enter_context(patch.object(backend.subprocess, 'Popen', side_effect=execute))
                stack.enter_context(patch.object(backend.importlib.util, 'spec_from_file_location', side_effect=spec_for))
                stack.enter_context(patch.object(backend.importlib.util, 'module_from_spec', side_effect=lambda _: types.SimpleNamespace()))
                if mode == 'rejected':
                    with self.assertRaisesRegex(ValueError, 'frozen schedule rejected'): backend.run(work, state, receipt, verify_schedule=schedule)
                else:
                    self.assertEqual(backend.run(work, state, receipt, inventory_only=mode == 'inventory', verify_schedule=schedule if mode == 'execute' else None), 0)
            if mode == 'execute':
                self.assertEqual(events, ['operator-discovery', 'complete-test-discovery', 'frozen-schedule-verification', 'actual-execution'])
            else:
                self.assertFalse(configuration.exists())
                self.assertNotIn('actual-execution', events)
            return events

    def test_inventory_only_keeps_operator_and_test_discovery_workspace_exactly_closed(self):
        self.assertEqual(self.exercise('inventory'), ['operator-discovery', 'complete-test-discovery'])

    def test_rejected_frozen_schedule_does_not_create_an_execution_configuration(self):
        self.assertEqual(self.exercise('rejected'), ['operator-discovery', 'complete-test-discovery', 'frozen-schedule-verification'])

    def test_execution_configuration_is_created_only_after_full_discovery_and_schedule_admission(self):
        self.exercise('execute')


if __name__ == '__main__': unittest.main()
