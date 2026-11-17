import hashlib
import importlib.util
import io
import json
from pathlib import Path
import shutil
import struct
import tarfile
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location('packaged_data', ROOT / 'scripts/release/bind-packaged-data.py')
packaged = importlib.util.module_from_spec(spec); spec.loader.exec_module(packaged)


def capture(path, body, artifact='source-archive'):
    return {'subjects': [{'id': artifact, 'members': [{'path': path, **packaged.content(body)}]}]}


def regex_fixture(root, *, tag=None, architecture='arm64', machine=None, extra=False, missing_build=False):
    version = '2026.11.7'; sources = root / 'sources'; sources.mkdir()
    platform_tag, native_machine = {'arm64': ('win_arm64', 0xaa64), 'x64': ('win_amd64', 0x8664)}[architecture]
    if machine is None: machine = native_machine
    original = sources / 'regex.tar.gz'
    with tarfile.open(original, 'w:gz') as bundle:
        for name in ['pyproject.toml', 'setup.py', 'src/_regex.c', 'src/_regex.h', 'src/_regex_unicode.c', 'src/_regex_unicode.h', 'LICENSE.txt']:
            if missing_build and name == 'src/_regex_unicode.h': continue
            body = ('Original synthetic regex fixture ' + name + '\n').encode(); member = tarfile.TarInfo('regex-' + version + '/' + name); member.size = len(body); bundle.addfile(member, io.BytesIO(body))
    body = original.read_bytes(); source = {'family': 'python-package', 'name': 'regex', 'version': version, 'url': 'https://files.pythonhosted.org/fixture/regex.tar.gz', 'path': original.name, **packaged.content(body), 'notice_files': packaged.locked.source_notices(original)}
    (sources / 'receipt.json').write_text(json.dumps({'schema_version': 1, 'qualification': 'exact-locked-source-subinventory', 'status': 'passed', 'files': [source]}))
    (root / 'runtime/materials').mkdir(parents=True); (root / 'runtime/materials/component-source-replay.json').write_text(json.dumps({'families': [{'kind': 'python-wheels', 'sources': 'sources/receipt.json'}]}))
    cache = root / '.artifacts/userspace-inputs/cache'; cache.mkdir(parents=True)
    wheels = []; members = []
    for abi in ['cp314', 'cp315']:
        stream = io.BytesIO(); pe = bytearray(128); pe[:2] = b'MZ'; struct.pack_into('<I', pe, 60, 64); pe[64:68] = b'PE\0\0'; struct.pack_into('<H', pe, 68, machine)
        with zipfile.ZipFile(stream, 'w') as wheel:
            wheel.writestr(f'regex/_regex.{abi}-{platform_tag}.pyd', pe)
            wheel.writestr(f'regex-{version}.dist-info/METADATA', f'Name: regex\nVersion: {version}\n')
            wheel.writestr(f'regex-{version}.dist-info/WHEEL', f'Wheel-Version: 1.0\nRoot-Is-Purelib: false\nTag: {tag or f"{abi}-{abi}-{platform_tag}"}\nGenerator: original synthetic fixture\n')
            wheel.writestr(f'regex-{version}.dist-info/licenses/LICENSE.txt', 'Original wheel notice\n')
            if extra: wheel.writestr('regex/foreign.dll', pe)
        body = stream.getvalue(); fingerprint = hashlib.sha256(body).hexdigest(); (cache / fingerprint).write_bytes(body)
        name = f'regex-{version}-{abi}-{abi}-{platform_tag}.whl'; wheels.append({'url': 'https://files.pythonhosted.org/fixture/' + name, 'hash': 'sha256:' + fingerprint, 'size': len(body)}); members.append({'path': f'runtime/pack/wheels/win32-{architecture}/' + name, **packaged.content(body)})
    (root / 'uv.lock').write_text('[[package]]\nname="regex"\nversion=' + json.dumps(version) + '\nsdist={url=' + json.dumps(source['url']) + ',hash="sha256:' + source['sha256'] + '",size=' + str(source['size_bytes']) + '}\nwheels=[' + ','.join('{url=' + json.dumps(w['url']) + ',hash=' + json.dumps(w['hash']) + ',size=' + str(w['size']) + '}' for w in wheels) + ']\n')
    return {'subjects': [{'id': 'native-windows-' + ('amd64' if architecture == 'x64' else architecture), 'members': members}]}, source


class PackagedDataTests(unittest.TestCase):
    def successful(self, action, *args):
        try: return action(*args)
        except ValueError as error: self.fail('Valid packaged fixture rejected: ' + str(error))

    def test_real_source_fixture_archives_are_specific_readable_sources_with_original_notices(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); (root / 'tests/fixtures/source-materials').mkdir(parents=True); shutil.copyfile(ROOT / 'LICENSE', root / 'LICENSE')
            for basename in ['go-units-v0.5.0', 'npm-public-fixture']:
                extension = '.zip' if basename.startswith('go-') else '.tgz'; name = 'tests/fixtures/source-materials/' + basename + extension
                for suffix in [extension, '.json']: shutil.copyfile(ROOT / 'tests/fixtures/source-materials' / (basename + suffix), root / 'tests/fixtures/source-materials' / (basename + suffix))
                result = self.successful(packaged.fixture_binding, root, capture(name, (root / name).read_bytes()), name)
                self.assertIsInstance(result, dict); self.assertEqual(result['content'], packaged.content((root / name).read_bytes())); self.assertTrue(result['notices']); self.assertEqual(result['required_materials'], [])
                self.assertIn('form', result['sources'][0])
                (root / name).write_bytes(b'changed')
                with self.assertRaisesRegex(ValueError, 'retained descriptor'): packaged.fixture_binding(root, capture(name, b'changed'), name)

    def test_authored_fixture_descriptor_cannot_bless_an_extra_foreign_binary(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); folder = root / 'tests/fixtures/source-materials'; folder.mkdir(parents=True); name = 'tests/fixtures/source-materials/npm-public-fixture.tgz'
            with tarfile.open(root / name, 'w:gz') as archive:
                member = tarfile.TarInfo('package/foreign.dll'); member.size = 2; archive.addfile(member, io.BytesIO(b'MZ'))
            proof = json.loads((ROOT / 'tests/fixtures/source-materials/npm-public-fixture.json').read_bytes()); proof.update(packaged.content((root / name).read_bytes())); (folder / 'npm-public-fixture.json').write_text(json.dumps(proof))
            with self.assertRaisesRegex(ValueError, 'unknown, binary or special'): packaged.fixture_binding(root, capture(name, (root / name).read_bytes()), name)

    def test_npm_plugin_is_rederived_from_exact_candidate_owned_generator_and_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in ['scripts/release/host-adapters.mjs', 'release/identity.yaml', 'release/product.yaml', 'LICENSE']:
                target = root / name; target.parent.mkdir(parents=True, exist_ok=True); shutil.copyfile(ROOT / name, target)
            expected = {'sha256': '023df5061d83ec11d34ec361ee7f37cbc1aebf83a9446ba1a64d437608e8231e', 'size_bytes': 447}
            discovery = {'subjects': [{'id': 'npm', 'members': [{'path': 'plugin.json', **expected}]}]}
            result = self.successful(packaged.plugin_binding, root, discovery)
            self.assertIsInstance(result, dict); self.assertEqual(result['content'], expected); self.assertEqual(len(result['sources'][0]['inputs']), 3)
            discovery['subjects'][0]['members'][0]['sha256'] = 'f' * 64
            with self.assertRaisesRegex(ValueError, 'exact source/build input'): packaged.plugin_binding(root, discovery)
            (root / 'scripts/release/host-adapters.mjs').write_text('changed generator')
            with self.assertRaisesRegex(ValueError, 'candidate-own source'): packaged.plugin_binding(root, discovery)

    def test_regex_wheels_bind_exact_abis_arm_pe_and_actual_source_build_definitions(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); discovery, source = regex_fixture(root)
            result = self.successful(packaged.regex_bindings, root, root, discovery, set())
            self.assertIsInstance(result, list); self.assertEqual(len(result), 2)
            self.assertEqual([row['sources'][1]['abi'] for row in result], ['cp314', 'cp315'])
            wanted = {(row['sha256'], row['size_bytes']) for row in discovery['subjects'][0]['members']}
            derived = self.successful(packaged.derive, root, root, root, discovery, wanted)
            self.assertEqual(derived['status'], 'passed')
            self.assertEqual(derived['qualification'], 'independently-derived-finite-packaged-content-bindings-not-product-completeness')
            for row in result:
                self.assertEqual(row['required_materials'][0]['sha256'], source['sha256']); self.assertEqual(len(row['sources'][1]['actual_PE_members']), 1); self.assertEqual(len(row['sources'][1]['source_build_inputs']), 6)
                self.assertEqual(len(row['notices']), 2); self.assertIn('not-binary-reproduction', row['sources'][1]['form']); self.assertIn('No compiler/CRT provenance', row['sources'][1]['limitations'])
            file = root / '.artifacts/userspace-inputs/cache' / discovery['subjects'][0]['members'][0]['sha256']; file.write_bytes(b'x' * file.stat().st_size)
            with self.assertRaisesRegex(ValueError, 'hash or identity'): packaged.regex_bindings(root, root, discovery, set())

    def test_unknown_compiled_members_wrong_abi_or_wrong_arm_machine_remain_rejected(self):
        for options in [{'tag': 'cp314-cp314-win_amd64'}, {'machine': 0x8664}, {'architecture': 'x64', 'machine': 0xaa64}, {'extra': True}]:
            with self.subTest(options=options), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary); discovery, _ = regex_fixture(root, **options)
                with self.assertRaisesRegex(ValueError, 'architecture|metadata|unknown compiled'): packaged.regex_bindings(root, root, discovery, set())

    def test_regex_wheels_bind_both_x64_abis_to_exact_original_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); discovery, source = regex_fixture(root, architecture='x64')
            wanted = {(row['sha256'], row['size_bytes']) for row in discovery['subjects'][0]['members']}
            result = self.successful(packaged.derive, root, root, root, discovery, wanted)
            self.assertEqual([(row['sources'][1]['platform'], row['sources'][1]['abi']) for row in result['bindings']], [('win32/x64', 'cp314'), ('win32/x64', 'cp315')])
            self.assertEqual({row['required_materials'][0]['sha256'] for row in result['bindings']}, {source['sha256']})

    def test_regex_source_receipt_and_real_build_input_omissions_do_not_get_a_wheel_fact(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); discovery, _ = regex_fixture(root); receipt = root / 'sources/receipt.json'; data = json.loads(receipt.read_bytes()); data['files'][0]['version'] = 'different'; receipt.write_text(json.dumps(data))
            with self.assertRaisesRegex(ValueError, 'exact uv lock'): packaged.regex_bindings(root, root, discovery, set())
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); discovery, _ = regex_fixture(root, missing_build=True)
            with self.assertRaisesRegex(ValueError, 'setup/C source input closure'): packaged.regex_bindings(root, root, discovery, set())


if __name__ == '__main__': unittest.main()
