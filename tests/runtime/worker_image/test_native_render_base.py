import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import zipfile

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location('ud_native_render_base_test', ROOT / 'scripts/runtime/prepare-native-render.py')
render = importlib.util.module_from_spec(spec)
spec.loader.exec_module(render)


class NativeRenderBaseTests(unittest.TestCase):
    def fixture(self, root, platform='darwin/arm64'):
        (root / 'runtime').mkdir()
        (root / 'runtime/render-deps.lock.json').write_text(json.dumps({'debian': {'architectures': {'arm64': {'packages': []}}}}))
        (root / 'workers/ud/src').mkdir(parents=True)
        # The recipe generator uses the real security-reviewed standalone ZIP
        # resolver; only immutable font data is replaced by a tiny fixture.
        (root / 'workers/ud/src/ud_agent').symlink_to(ROOT / 'workers/ud/src/ud_agent', target_is_directory=True)
        slug = 'linux-arm64' if platform.startswith('linux') else 'mac-arm64'
        archive = root / 'publisher.zip'
        with zipfile.ZipFile(archive, 'w') as source:
            source.writestr('chrome-headless-shell-' + slug + '/chrome-headless-shell', b'vendor-only-binary')
            source.writestr('chrome-headless-shell-' + slug + '/icudtl.dat', b'vendor-only-assets')
        record = {'schema_version': 1, 'state': 'frozen-inputs', 'platform': platform, 'version': '157.0.8103.38',
                  'url': f'https://storage.googleapis.com/chrome-for-testing-public/157.0.8103.38/{slug}/chrome-headless-shell-{slug}.zip',
                  'sha256': render.digest(archive), 'size_bytes': archive.stat().st_size}
        return record, archive

    @staticmethod
    def fonts(directory, _):
        directory.mkdir(parents=True, exist_ok=True)
        file = directory / 'tiny.ttf'
        file.write_bytes(b'pinned-font')
        return [file]

    def test_published_base_contains_recipe_and_fonts_without_vendor_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            record, archive = self.fixture(root)
            with mock.patch.object(render.font_manifest, 'pinned_fonts', side_effect=self.fonts):
                result = render.prepare(root, record, archive, root / 'base', root / 'base.tar.gz')
            manifest = json.loads((root / 'base/manifest.json').read_text())
            self.assertEqual(manifest['deferred_browser'], {'provider': 'google-chrome-for-testing', 'recipe': 'vendor-browser-recipe.json', 'directory': 'browser'})
            self.assertEqual(manifest['executable'], 'browser/chrome-headless-shell')
            self.assertFalse((root / 'base/browser').exists())
            recipe = json.loads((root / 'base/vendor-browser-recipe.json').read_text())
            self.assertEqual([item['path'] for item in recipe['files']], ['chrome-headless-shell', 'icudtl.dat'])
            self.assertEqual(recipe['archive']['sha256'], hashlib.sha256(archive.read_bytes()).hexdigest())
            self.assertEqual(len(result['files']), 4)
            self.assertFalse(any(b'vendor-only-binary' in file.read_bytes() or b'vendor-only-assets' in file.read_bytes() for file in (root / 'base').rglob('*') if file.is_file()))

    def test_linux_base_uses_only_receipt_bound_os_libraries_and_rejects_vendor_origins(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            record, archive = self.fixture(root, 'linux/arm64')
            closure = root / 'closure'
            (closure / 'elf/loader').mkdir(parents=True)
            (closure / 'elf/lib').mkdir()
            (closure / 'elf/loader/ld.so').write_bytes(b'OS-loader')
            (closure / 'elf/lib/libc.so').write_bytes(b'OS-libc')
            (closure / 'browser').mkdir()
            (closure / 'browser/chrome-headless-shell').write_bytes(b'vendor-only-binary')
            (closure / 'elf-closure.json').write_text(json.dumps({'libraries': {'elf/lib/libc.so': {'image_path': 'usr/lib/libc.so'}}}))
            (closure / 'manifest.json').write_text(json.dumps({'loader': {'executable': 'elf/loader/ld.so', 'library_dirs': ['elf/lib']}}))
            def receipt():
                file = root / 'closure-receipt.json'
                file.write_text(json.dumps({'schema_version': 1, 'platform': 'linux/arm64', 'root': 'closure', 'files': [{'path': item.relative_to(closure).as_posix(), 'sha256': 'sha256:' + render.digest(item), 'size': item.stat().st_size} for item in closure.rglob('*') if item.is_file()]}))
                return file
            with mock.patch.object(render.font_manifest, 'pinned_fonts', side_effect=self.fonts):
                render.prepare(root, record, archive, root / 'base', root / 'base.tar.gz', receipt())
                self.assertEqual((root / 'base/elf/lib/libc.so').read_bytes(), b'OS-libc')
                self.assertFalse((root / 'base/browser').exists())
                manifest = json.loads((root / 'base/manifest.json').read_text())
                self.assertEqual(manifest['fontconfig'], 'fontconfig/fonts.conf')
                self.assertIn('<dir prefix="relative">../fonts</dir>', (root / 'base/fontconfig/fonts.conf').read_text())
                recipe = json.loads((root / 'base/vendor-browser-recipe.json').read_text())
                self.assertEqual(recipe['linux_loader'], {'executable': 'elf/loader/ld.so', 'library_dirs': ['elf/lib'], 'materialization': 'elf-interpreter-v1'})
                (closure / 'elf-closure.json').write_text(json.dumps({'libraries': {'elf/lib/libc.so': {'browser_path': 'browser/libc.so'}}}))
                with self.assertRaisesRegex(ValueError, 'vendor browser bytes'):
                    render.prepare(root, record, archive, root / 'bad', root / 'bad.tar.gz', receipt())
                (closure / 'elf/lib/libc.so').write_bytes(b'corrupt')
                with self.assertRaisesRegex(ValueError, 'exact receipt'):
                    render.prepare(root, record, archive, root / 'corrupt', root / 'corrupt.tar.gz', root / 'closure-receipt.json')


if __name__ == '__main__':
    unittest.main()
