import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location('ud_build_workers_test', ROOT / 'scripts/runtime/build-workers.py')
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)


class BuildWorkerTests(unittest.TestCase):
    def test_foreign_architecture_and_remote_endpoints_never_start_a_build(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / 'output'
            with patch.dict(builder.os.environ, {'DOCKER_HOST': 'ssh://remote'}, clear=True), patch.object(builder, 'run') as run:
                with self.assertRaisesRegex(ValueError, 'local Unix'):
                    builder.build(output)
                run.assert_not_called()
            with patch.dict(builder.os.environ, {'DOCKER_HOST': 'unix:///owned.sock'}, clear=True), patch.object(builder, 'run', return_value=json.dumps({'OSType': 'linux', 'Architecture': 'x86_64'}).encode()) as run, patch.object(builder.host_platform, 'machine', return_value='arm64'):
                with self.assertRaisesRegex(ValueError, 'foreign-architecture'):
                    builder.build(output)
                self.assertEqual(run.call_count, 1)
                self.assertFalse(output.exists())

    def test_native_builds_are_offline_attestation_free_and_export_both_worker_packs(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / 'output'
            commands = []
            def run(command, **options):
                commands.append(command)
                return json.dumps({'OSType': 'linux', 'Architecture': 'aarch64'}).encode() if command[1] == 'info' else b''
            def prepare_core(root, cache, target, download, selected):
                self.assertEqual(selected, ['linux/arm64'])
                self.assertFalse(download)
                target.mkdir()
                (target / 'Containerfile').write_text('fixed core')
            def prepare_render(root, target):
                target.mkdir()
                (target / 'Containerfile').write_text('fixed render')
            def export(root, target, images, selected):
                self.assertEqual(set(images), {'core', 'render'})
                self.assertEqual(selected, ['linux/arm64'])
                return {'packs': {name:{'index_digest': 'sha256:' + value*64, 'index_transport':{'path':'exact-archive'}, 'images':{'linux/arm64':{'digest':'sha256:'+value*64}}}for name,value in [('core','a'),('render','b')]}}
            modules = {'prepare-core-build': types.SimpleNamespace(prepare=prepare_core,content_addressed_manifest=lambda context:'build-input/'+'c'*64+'.json'), 'prepare-render-build': types.SimpleNamespace(prepare=prepare_render), 'export-workers': types.SimpleNamespace(export=export), 'verify-worker-contents':types.SimpleNamespace(verify=lambda *arguments:{'status':'passed'})}
            with patch.dict(builder.os.environ, {'DOCKER_HOST': 'unix:///owned.sock'}, clear=True), patch.object(builder, 'run', side_effect=run), patch.object(builder.host_platform, 'machine', return_value='arm64'), patch.object(builder.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0)), patch.object(builder, 'load', side_effect=lambda name: modules[name]):
                result = builder.build(output)
            self.assertEqual(result['deferred_platforms'], ['linux/amd64'])
            self.assertEqual(result['qualification'], 'native-build-unaccepted')
            builds = [value for value in commands if value[1] == 'build']
            self.assertEqual(len(builds), 2)
            self.assertIn('INPUT_MANIFEST_PATH=build-input/'+'c'*64+'.json',builds[0])
            self.assertTrue(all('--provenance=false' in value and '--pull=false' in value and value[value.index('--network')+1] == 'none' and value[value.index('--platform')+1] == 'linux/arm64' for value in builds))
            self.assertFalse((output / 'INCOMPLETE').exists())


if __name__ == '__main__':
    unittest.main()
