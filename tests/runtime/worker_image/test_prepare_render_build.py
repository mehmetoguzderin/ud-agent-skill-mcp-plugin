import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'scripts/runtime'))
spec = importlib.util.spec_from_file_location('ud_render_prepare_test', ROOT / 'scripts/runtime/prepare-render-build.py')
render = importlib.util.module_from_spec(spec)
spec.loader.exec_module(render)


class RenderContextTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / 'runtime').mkdir()
        (self.root / 'runtime/Containerfile.render').write_text('offline fixture')
        (self.root / 'scripts/runtime').mkdir(parents=True)
        (self.root / 'scripts/runtime/render_manifest.py').write_text('verified manifest generator fixture\n')
        self.lock = {'schema_version': 1, 'state': 'frozen-inputs', 'qualification': 'unbuilt',
                     'debian': {'architectures': {'arm64': {}, 'amd64': {}}, 'signed_by': {}}}
        self.write_lock()
        self.package = self.root / 'fixture.deb'
        self.package.write_bytes(b'verified fixture')
        self.record = {'file': self.package.name, 'sha256': hashlib.sha256(self.package.read_bytes()).hexdigest()}

    def write_lock(self):
        (self.root / 'runtime/render-deps.lock.json').write_text(json.dumps(self.lock))

    def test_stages_exact_verified_packages_and_honestly_reports_unbuilt(self):
        with mock.patch.object(render.perl_build, '_verify_debian', return_value=[(self.record, self.package)]) as verify:
            out = self.root / 'out'
            receipt = render.prepare(self.root, out)
            self.assertEqual(verify.call_count, 2)
            self.assertFalse(receipt['release_qualified'])
            self.assertEqual(receipt['packages'], {'arm64': 1, 'amd64': 1})
            for arch in ('arm64', 'amd64'):
                folder = out / 'render/debs' / arch
                self.assertEqual((folder / self.package.name).read_bytes(), self.package.read_bytes())
                self.assertEqual((folder / 'SHA256SUMS').read_text(), f"{self.record['sha256']}  fixture.deb\n")
            self.assertEqual(json.loads((out / 'input-manifest.json').read_text()), receipt)
            with self.assertRaisesRegex(ValueError, 'already exists'):
                render.prepare(self.root, out)

    def test_bad_lock_or_failed_verification_never_creates_output(self):
        self.lock['debian']['architectures'].pop('arm64')
        self.write_lock()
        with self.assertRaisesRegex(ValueError, 'invalid render'):
            render.prepare(self.root, self.root / 'bad')
        self.assertFalse((self.root / 'bad').exists())
        self.lock['debian']['architectures']['arm64'] = {}
        self.write_lock()
        with mock.patch.object(render.perl_build, '_verify_debian', side_effect=ValueError('tampered input')):
            with self.assertRaisesRegex(ValueError, 'tampered'):
                render.prepare(self.root, self.root / 'bad')
        self.assertFalse((self.root / 'bad').exists())
