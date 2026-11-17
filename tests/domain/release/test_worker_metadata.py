import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location('worker_metadata_tests', ROOT / 'scripts/release/bind-worker-metadata.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def core_fixture(root):
    source, assets, context = root / 'source', root / 'assets', root / 'context'
    for name in ['workers', 'runtime', 'licenses', 'scripts/runtime']:
        (source / name).mkdir(parents=True, exist_ok=True)
    for name in ['LICENSE', 'NOTICE', 'uv.lock']:
        (source / name).write_text('original source input\n')
    (assets / '.artifacts').mkdir(parents=True)
    (context / 'wheels').mkdir(parents=True)
    body = {'schema_version': 1, 'build_platforms': ['linux/arm64'], 'source': 'original'}
    encoded = json.dumps(body, sort_keys=True, indent=2) + '\n'
    (context / 'input-manifest.json').write_text(encoded, newline='')
    program = '''import json
def prepare(root,cache,output,download,platforms):
 if download: raise ValueError('acquisition forbidden')
 body={'schema_version':1,'build_platforms':['linux/arm64'],'source':'original'}
 output.mkdir()
 names=['context/context.json','perl/arm64/runtime.json','perl/arm64/source-receipt.json','requirements.txt']
 for name in names:
  file=output/name;file.parent.mkdir(parents=True,exist_ok=True);file.write_text('original '+name+'\\n',newline='')
 (output/'input-manifest.json').write_text(json.dumps(body,sort_keys=True,indent=2)+'\\n',newline='')
 return body
'''
    (source / 'scripts/runtime/prepare-core-build.py').write_text(program)
    return source, assets, context


class FakeFilesystem:
    def __init__(self, root):
        self.root = root
        self.inventory = {}
    def add(self, name, content=None):
        if content is None:
            self.inventory[name] = ('dir', None)
        else:
            file = self.root / str(len(self.inventory))
            file.write_bytes(content)
            self.inventory[name] = ('file', file)
    def resolve(self, name, allow_directory=False):
        kind, file = self.inventory[name]
        if kind == 'dir' and not allow_directory: raise ValueError('not a file')
        return name, file


def render_fixture(root):
    fs = FakeFilesystem(root)
    for name in ['usr/lib/chromium', 'usr/share/fonts', 'usr/share/fontconfig/conf.avail']:
        fs.add(name)
    for name, body in [('usr/lib/chromium/chromium', b'original browser bytes'), ('usr/share/fonts/Original.ttf', b'original font'), ('usr/share/fonts/NotoSansCJK-Regular.ttc', b'collection'), ('opt/ud-agent/render/fonts/NotoSansCJK-Regular.otf', b'derived collection'), ('etc/fonts/fonts.conf', b'original font config'), ('opt/ud-agent/render/dependency-lock.json', b'{}')]:
        fs.add(name, body)
    generator = SimpleNamespace(FONT_NAMES=('Original.ttf',), standalone_font=lambda value: b'derived ' + value)
    return fs, generator


class WorkerMetadataTests(unittest.TestCase):
    def test_original_producer_reconstructs_all_five_exact_metadata_forms_without_source_writes(self):
        with tempfile.TemporaryDirectory() as temporary:
            source, assets, context = core_fixture(Path(temporary))
            before = {str(file.relative_to(source)): file.read_bytes() for file in source.rglob('*') if file.is_file()}
            with patch.object(m.sys, 'dont_write_bytecode', False):
                values = m.reconstructed_core(source, assets, context, 'linux/arm64')
                self.assertFalse(m.sys.dont_write_bytecode)
            self.assertEqual(set(values), set(m.CORE_NAMES))
            self.assertEqual(values['opt/ud-agent/input-manifest.json'], (context / 'input-manifest.json').read_bytes())
            self.assertEqual(values['tmp/ud-agent-requirements.txt'], b'original requirements.txt\n')
            self.assertEqual({str(file.relative_to(source)): file.read_bytes() for file in source.rglob('*') if file.is_file()}, before)

    def test_source_or_cached_manifest_and_platform_changes_do_not_gain_metadata_authority(self):
        with tempfile.TemporaryDirectory() as temporary:
            source, assets, context = core_fixture(Path(temporary))
            with self.assertRaisesRegex(ValueError, 'platform differs'):
                m.reconstructed_core(source, assets, context, 'linux/amd64')
            file = context / 'input-manifest.json'
            body = json.loads(file.read_bytes())
            body['source'] = 'foreign replacement'
            file.write_text(json.dumps(body, sort_keys=True, indent=2) + '\n')
            with self.assertRaisesRegex(ValueError, 'does not reconstruct'):
                m.reconstructed_core(source, assets, context, 'linux/arm64')

    def test_render_inventory_reconstructs_exact_font_and_asset_bytes_only(self):
        with tempfile.TemporaryDirectory() as temporary:
            fs, generator = render_fixture(Path(temporary))
            fs.add('etc/unrelated-program.so', b'foreign program')
            value = json.loads(m.render_form(fs, generator))
            names = [row['path'] for row in value['files']]
            self.assertEqual(value['executable'], '/usr/lib/chromium/chromium')
            self.assertEqual(value['fonts'], ['/usr/share/fonts/Original.ttf', '/opt/ud-agent/render/fonts/NotoSansCJK-Regular.otf'])
            self.assertNotIn('/etc/unrelated-program.so', names)
            self.assertIn('/etc/fonts/fonts.conf', names)
            self.assertEqual(next(row for row in value['files'] if row['path'] == '/usr/lib/chromium/chromium')['sha256'], m.digest(fs.resolve('usr/lib/chromium/chromium')[1]))

    def test_ambiguous_fonts_or_changed_generated_font_cannot_issue_a_manifest(self):
        with tempfile.TemporaryDirectory() as temporary:
            fs, generator = render_fixture(Path(temporary))
            fs.resolve('opt/ud-agent/render/fonts/NotoSansCJK-Regular.otf')[1].write_bytes(b'foreign replacement')
            with self.assertRaisesRegex(ValueError, 'generated font differs'):
                m.render_form(fs, generator)
            fs.resolve('opt/ud-agent/render/fonts/NotoSansCJK-Regular.otf')[1].write_bytes(b'derived collection')
            fs.add('usr/share/fonts/other/Original.ttf', b'duplicate')
            with self.assertRaisesRegex(ValueError, 'ambiguous'):
                m.render_form(fs, generator)


if __name__ == '__main__':
    unittest.main()
