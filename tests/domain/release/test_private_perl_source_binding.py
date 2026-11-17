import copy
import hashlib
import importlib.util
import json
import io
import tarfile
from pathlib import Path
import struct
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location('private_perl_binding', ROOT / 'scripts/release/bind-private-perl-sources.py')
binding = importlib.util.module_from_spec(spec); spec.loader.exec_module(binding)


class PrivatePerlSourceBindingTests(unittest.TestCase):
    def fixture(self, root):
        (root / 'runtime').mkdir(); pack = root / 'pack'; (pack / 'bin').mkdir(parents=True); (pack / 'share/licenses').mkdir(parents=True)
        binary = bytearray(64); binary[:6] = b'\x7fELF\x02\x01'; struct.pack_into('<H', binary, 18, 183); (pack / 'bin/perl').write_bytes(binary); (pack / 'share/licenses/Copying').write_bytes(b'Original license\n')
        archives = {}
        inputs = [('perl', 'perl-5.44.0', {'Artistic': b'Original Artistic terms\n', 'Copying': b'Original GPL terms\n'}), ('cpan', 'Fixture-1.0', {'README': b'Original module copyright and license\n'}), ('ud', 'interset-' + 'a' * 40, {'LICENSE.txt': b'Original Interset terms\n'})]
        for family, prefix, members in inputs:
            target = root / (family + '.source')
            with tarfile.open(target, 'w:gz') as archive:
                for leaf, body in members.items():
                    item = tarfile.TarInfo(prefix + '/' + leaf); item.size = len(body); archive.addfile(item, io.BytesIO(body))
                    name = 'share/licenses/' + ('perl' if family == 'perl' else 'Fixture-1.0' if family == 'cpan' else 'interset') + '/' + leaf
                    file = pack / name; file.parent.mkdir(parents=True, exist_ok=True); file.write_bytes(body)
            archives[family] = target
        core = {'name': 'perl-5.44.0', 'version': '5.044000', 'sha256': binding.sha(archives['perl'])}; modules = {'releases': {'Fixture-1.0': {'name': 'Fixture-1.0', 'version': '1.0', 'sha256': binding.sha(archives['cpan'])}}}; interset = {'commit': 'a' * 40, 'archive_sha256': binding.sha(archives['ud'])}
        for name, value in [('native-perl-source.lock.json', core), ('native-perl-modules.lock.json', modules), ('perl-deps.lock.json', {'interset': interset}), ('windows-perl-distributions.lock.json', {})]: (root / 'runtime' / name).write_text(json.dumps(value))
        for name in ['prepare-native-perl.py', 'prepare-windows-perl.py', 'windows_pe.py', 'prepare-linux-perl.py', 'build-linux-perl.py', 'perl_build.py', 'close-linux-elf.py', 'prepare-perl-vendor-runtime.py']:
            file = root / 'scripts/runtime' / name; file.parent.mkdir(parents=True, exist_ok=True); file.write_text('# independently bound original fixture recipe\n')
        definition = {'schema_version': 1, 'state': 'frozen-inputs', 'platform': 'linux/arm64', 'source_sha256': hashlib.sha256(binding.canonical(core)).hexdigest(), 'modules_sha256': hashlib.sha256(binding.canonical(modules)).hexdigest(), 'interset_commit': interset['commit'], 'executable': 'bin/perl', 'files': [{'path': file.relative_to(pack).as_posix(), 'sha256': 'sha256:' + binding.sha(file), 'size': file.stat().st_size} for file in sorted(pack.rglob('*')) if file.is_file()]}
        file = root / 'binary.json'; file.write_text(json.dumps(definition)); sources = []
        for family, name, version in [('perl', core['name'], core['version']), ('cpan', 'Fixture-1.0', '1.0'), ('ud', 'dan-zeman/interset', interset['commit'])]:
            target = archives[family]; sources.append({'family': family, 'name': name, 'version': version, 'path': target.name, 'sha256': binding.sha(target), 'size_bytes': target.stat().st_size})
        collection = root / 'sources.json'; collection.write_text(json.dumps({'schema_version': 1, 'status': 'passed', 'qualification': 'exact-locked-source-subinventory', 'files': sources})); return pack, file, collection

    def test_component_coverage_is_derived_from_complete_bytes_sources_and_notices(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); pack, file, collection = self.fixture(root); result = binding.derive(root, pack, file, [collection]); self.assertTrue(result['complete_component_coverage']); self.assertFalse(result['complete_product_coverage']); self.assertEqual(len(result['sources']), 3); self.assertEqual(result['platform'], 'linux/arm64'); self.assertFalse(result['target_execution'])

    def test_amd64_native_build_receipt_matches_x64_release_target(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pack, receipt, collection = self.fixture(root)
            executable = pack / 'bin/perl'
            body = bytearray(executable.read_bytes())
            struct.pack_into('<H', body, 18, 62)
            executable.write_bytes(body)
            definition = json.loads(receipt.read_bytes())
            definition['platform'] = 'linux/amd64'
            binary = next(row for row in definition['files'] if row['path'] == 'bin/perl')
            binary['sha256'] = 'sha256:' + binding.sha(executable)
            receipt.write_text(json.dumps(definition))

            result = binding.derive(root, pack, receipt, [collection])
            self.assertTrue(result['complete_component_coverage'])
            self.assertEqual(result['platform'], 'linux/x64')
            self.assertEqual(result['binary_recipe']['platform'], 'linux/amd64')

    def test_extra_bytes_missing_module_stale_recipe_and_foreign_architecture_fail(self):
        for mode in ('extra', 'missing-source', 'stale', 'wrong-arch', 'no-license'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary); pack, file, collection = self.fixture(root); definition = json.loads(file.read_bytes())
                if mode == 'extra': (pack / 'bin/unlisted').write_bytes(b'extra')
                elif mode == 'missing-source': data = json.loads(collection.read_bytes()); data['files'].pop(); collection.write_text(json.dumps(data))
                elif mode == 'stale': definition['modules_sha256'] = '0' * 64
                elif mode == 'no-license':
                    definition['files'] = [row for row in definition['files'] if not row['path'].startswith('share/licenses/')]
                    for notice in (pack / 'share/licenses').rglob('*'):
                        if notice.is_file(): notice.unlink()
                else:
                    body = bytearray((pack / 'bin/perl').read_bytes()); struct.pack_into('<H', body, 18, 62); (pack / 'bin/perl').write_bytes(body); definition['files'][0]['sha256'] = 'sha256:' + binding.sha(pack / 'bin/perl')
                file.write_text(json.dumps(definition))
                with self.assertRaises(ValueError): binding.derive(root, pack, file, [collection])

    def test_unshipped_source_bytes_are_not_replay_inputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); pack, file, collection = self.fixture(root)
            data = json.loads(collection.read_bytes()); data['files'].append({'family': 'node', 'name': 'unshipped-other-runtime', 'version': '1', 'path': 'intentionally-absent', 'sha256': 'a' * 64, 'size_bytes': 3}); collection.write_text(json.dumps(data))
            result = binding.derive(root, pack, file, [collection]); self.assertEqual(len(result['sources']), 3)
            (root / 'cpan.source').unlink()
            with self.assertRaises((ValueError, OSError)): binding.derive(root, pack, file, [collection])


if __name__ == '__main__': unittest.main()
