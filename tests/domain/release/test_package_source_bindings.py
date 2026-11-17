import base64
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location('package_bindings', ROOT / 'scripts/release/bind-package-sources.py')
binding = importlib.util.module_from_spec(spec); spec.loader.exec_module(binding)


class PackageSourceBindingTests(unittest.TestCase):
    def fixture(self, root):
        rows = []
        for family, name, version, prefix in [('npm', 'fixture-js', '1.0.0', 'package'), ('cargo', 'fixture-rs', '1.0.0', 'fixture-rs-1.0.0')]:
            file = root / (family + '.tgz'); license = b'Original fixture copyright and MIT terms\n'
            with tarfile.open(file, 'w:gz') as archive:
                for path, body in [(prefix + '/LICENSE', license), (prefix + '/source.txt', b'original source bytes\n')]:
                    row = tarfile.TarInfo(path); row.size = len(body); archive.addfile(row, io.BytesIO(body))
            notice = root / (family + '.license'); notice.write_bytes(license)
            url = 'https://registry.npmjs.org/fixture-js/-/fixture-js-1.0.0.tgz' if family == 'npm' else 'https://static.crates.io/crates/fixture-rs/fixture-rs-1.0.0.crate'
            rows.append({'family': family, 'name': name, 'version': version, 'path': file.name, 'sha256': binding.sha(file), 'size_bytes': file.stat().st_size, 'url': url, 'notices': [{'source_path': prefix + '/LICENSE', 'path': notice.name, 'sha256': binding.sha(notice), 'size_bytes': len(license)}]})
        npm = rows[0]; integrity = 'sha512-' + base64.b64encode(hashlib.sha512((root / npm['path']).read_bytes()).digest()).decode()
        (root / 'package-lock.json').write_text(json.dumps({'packages': {'': {}, 'node_modules/fixture-js': {'version': '1.0.0', 'resolved': npm['url'], 'integrity': integrity, 'license': 'MIT'}}}))
        cargo = 'version = 4\n[[package]]\nname = "fixture-rs"\nversion = "1.0.0"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\nchecksum = "' + rows[1]['sha256'] + '"\n'
        (root / 'Cargo.lock').write_text(cargo); file = root / 'scripts/quality/rust-assertion-parser/Cargo.lock'; file.parent.mkdir(parents=True); file.write_text(cargo)
        receipt = root / 'receipt.json'; receipt.write_text(json.dumps({'schema_version': 1, 'qualification': 'complete-locked-npm-cargo-source-and-notice-subinventory', 'status': 'passed', 'files': rows})); return receipt

    def replay_inputs(self, root, receipt):
        body = receipt.read_bytes(); inventory = json.loads(body)
        collection = {'id': 'package-sources', 'qualification': inventory['qualification'], 'receipt_sha256': hashlib.sha256(body).hexdigest(), 'receipt_size_bytes': len(body), 'members': [
            {'original_path': row['path'], 'path': 'blobs/' + row['sha256'], 'sha256': row['sha256'], 'size_bytes': row['size_bytes']}
            for row in inventory['files']
        ]}
        paths = ['package-lock.json', 'Cargo.lock', 'scripts/quality/rust-assertion-parser/Cargo.lock']
        source = {'files': [{'path': name, 'sha256': binding.sha(root / name), 'size': (root / name).stat().st_size} for name in paths]}
        return source, body, collection

    def test_all_lock_sources_and_original_notices_are_reconciled(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); receipt = self.fixture(root); result = binding.derive(root, receipt)
            self.assertEqual({row['family'] for row in result['bindings']}, {'npm', 'cargo'}); self.assertEqual(len(result['bindings']), 2); self.assertTrue(all(len(row['notices']) == 1 for row in result['bindings'])); self.assertTrue(result['complete_component_coverage']); self.assertFalse(result['complete_product_coverage'])

    def test_missing_sources_publisher_drift_hash_and_notice_omissions_fail(self):
        for mode in ('missing', 'publisher', 'bytes', 'sri', 'notice'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary); receipt = self.fixture(root); value = json.loads(receipt.read_bytes())
                if mode == 'missing': value['files'].pop()
                elif mode == 'publisher': value['files'][0]['url'] = 'https://attacker.invalid/fixture.tgz'
                elif mode == 'bytes': (root / value['files'][0]['path']).write_bytes(b'wrong')
                elif mode == 'sri': lock = json.loads((root / 'package-lock.json').read_bytes()); lock['packages']['node_modules/fixture-js']['integrity'] = 'sha512-' + base64.b64encode(bytes(64)).decode(); (root / 'package-lock.json').write_text(json.dumps(lock))
                else: value['files'][0]['notices'] = []
                receipt.write_text(json.dumps(value))
                with self.assertRaises(ValueError): binding.derive(root, receipt)

    def test_actual_npm_inputs_do_not_require_unshipped_cargo_bytes_but_remain_lock_bound(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); receipt = self.fixture(root)
            (root / 'cargo.tgz').unlink(); (root / 'cargo.license').unlink()
            result = binding.derive_npm_inputs(root, receipt, [{'path': 'node_modules/fixture-js/source.txt'}])
            self.assertEqual([(row['family'], row['name']) for row in result['bindings']], [('npm', 'fixture-js')])
            with self.assertRaisesRegex(ValueError, 'no original locked package'):
                binding.derive_npm_inputs(root, receipt, [{'path': 'node_modules/unlocked/program.js'}])
            data = json.loads(receipt.read_bytes()); data['files'].pop(); receipt.write_text(json.dumps(data))
            with self.assertRaisesRegex(ValueError, 'omitted'): binding.derive_npm_inputs(root, receipt, [{'path': 'node_modules/fixture-js/source.txt'}])

    def test_cargo_source_scope_is_derived_from_an_original_lock_consumer(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); receipt = self.fixture(root)
            (root / 'npm.tgz').unlink(); (root / 'npm.license').unlink()
            result = binding.derive(root, receipt, required_cargo_consumers=[root / 'Cargo.lock'])
            self.assertEqual([(row['family'], row['name']) for row in result['bindings']], [('cargo', 'fixture-rs')])
            with self.assertRaisesRegex(ValueError, 'not an original source lock'):
                binding.derive(root, receipt, required_cargo_consumers=[root / 'unowned.lock'])

    def test_compact_package_mapping_uses_lock_consumers_original_archives_and_notices(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); receipt = self.fixture(root)
            source, body, collection = self.replay_inputs(root, receipt)
            mapped = binding.NpmReplaySources(root, source, body, collection, receipt_path='sources/receipt.json')
            self.assertEqual(len(mapped.consumers), 1)
            self.assertEqual(mapped.consumers[0]['consumer'], 'node_modules/fixture-js')
            row = mapped.resolve('node_modules/fixture-js/source.txt')
            self.assertEqual(row['member'], 'package/source.txt')
            self.assertEqual(row['blob_sha256'], binding.sha(root / 'npm.tgz'))
            self.assertEqual(row['blob_size_bytes'], (root / 'npm.tgz').stat().st_size)
            self.assertEqual(row['integrities'], [{'algorithm': 'sha512', 'hex': hashlib.sha512((root / 'npm.tgz').read_bytes()).hexdigest()}])
            with tarfile.open(root / 'npm.tgz', 'r:gz') as archive:
                self.assertEqual(archive.extractfile(row['member']).read(), b'original source bytes\n')
            notice = next(item for item in mapped.notices if item['path'] == 'sources/npm.license')
            self.assertEqual(notice['member'], 'package/LICENSE')
            self.assertEqual(notice['sha256'], binding.sha(root / 'npm.license'))
            self.assertEqual(notice['size_bytes'], (root / 'npm.license').stat().st_size)
            with self.assertRaisesRegex(ValueError, 'no retained locked package'):
                mapped.resolve('node_modules/unlocked/index.js')
            with self.assertRaisesRegex(ValueError, 'unsafe'):
                mapped.resolve('node_modules/fixture-js/../escape')

    def test_compact_notices_preserve_each_distinct_source_origin(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); receipt = self.fixture(root)
            value = json.loads(receipt.read_bytes())
            value['files'][1]['notices'][0]['path'] = value['files'][0]['notices'][0]['path']
            receipt.write_text(json.dumps(value))
            source, body, collection = self.replay_inputs(root, receipt)
            mapped = binding.NpmReplaySources(root, source, body, collection, receipt_path='sources/receipt.json')
            shared = [row for row in mapped.notices if row['path'] == 'sources/npm.license']
            self.assertEqual(len(shared), 2)
            self.assertEqual({(row['blob_sha256'], row['member']) for row in shared}, {
                (binding.sha(root / 'npm.tgz'), 'package/LICENSE'),
                (binding.sha(root / 'cargo.tgz'), 'fixture-rs-1.0.0/LICENSE'),
            })
            self.assertEqual({(row['sha256'], row['size_bytes']) for row in shared}, {
                (binding.sha(root / 'npm.license'), (root / 'npm.license').stat().st_size),
            })
            npm = next(row for row in shared if row['blob_sha256'] == binding.sha(root / 'npm.tgz'))
            self.assertEqual(npm['integrities'], [{'algorithm': 'sha512', 'hex': hashlib.sha512((root / 'npm.tgz').read_bytes()).hexdigest()}])

    def test_collection_member_mapping_reconstructs_only_receipt_selected_paths(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); receipt = self.fixture(root)
            _, body, collection = self.replay_inputs(root, receipt)
            rows = list(binding.iter_collection_replay_sources(body, collection, receipt_path='sources/receipt.json'))
            self.assertEqual(rows, [
                {'path': 'sources/cargo.tgz', 'blob_sha256': binding.sha(root / 'cargo.tgz'), 'blob_size_bytes': (root / 'cargo.tgz').stat().st_size},
                {'path': 'sources/npm.tgz', 'blob_sha256': binding.sha(root / 'npm.tgz'), 'blob_size_bytes': (root / 'npm.tgz').stat().st_size},
            ])
            changed = {**collection, 'members': [{**collection['members'][0], 'original_path': 'unlisted.tgz'}]}
            with self.assertRaisesRegex(ValueError, 'differs from its receipt'):
                list(binding.iter_collection_replay_sources(body, changed, receipt_path='sources/receipt.json'))
            with self.assertRaisesRegex(ValueError, 'receipt differs'):
                list(binding.iter_collection_replay_sources(body + b' ', collection, receipt_path='sources/receipt.json'))

    def test_compact_package_mapping_uses_longest_nested_consumer(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); receipt = self.fixture(root)
            inventory = json.loads(receipt.read_bytes()); nested = dict(inventory['files'][0]); nested['name'] = 'fixture-dep'
            nested['url'] = 'https://registry.npmjs.org/fixture-dep/-/fixture-dep-1.0.0.tgz'
            nested['path'] = 'nested.tgz'; (root / nested['path']).write_bytes((root / 'npm.tgz').read_bytes())
            inventory['files'].append(nested); receipt.write_text(json.dumps(inventory))
            lock = json.loads((root / 'package-lock.json').read_bytes())
            lock['packages']['node_modules/fixture-js/node_modules/fixture-dep'] = {**lock['packages']['node_modules/fixture-js'], 'resolved': nested['url']}
            (root / 'package-lock.json').write_text(json.dumps(lock))
            source, body, collection = self.replay_inputs(root, receipt)
            mapped = binding.NpmReplaySources(root, source, body, collection, receipt_path='sources/receipt.json')
            row = mapped.resolve('node_modules/fixture-js/node_modules/fixture-dep/source.txt')
            self.assertEqual(row['member'], 'package/source.txt')
            self.assertEqual([row['consumer'] for row in mapped.consumers], ['node_modules/fixture-js', 'node_modules/fixture-js/node_modules/fixture-dep'])

    def test_compact_package_mapping_rejects_stale_or_ambiguous_authority(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); receipt = self.fixture(root); source, body, collection = self.replay_inputs(root, receipt)
            with self.assertRaisesRegex(ValueError, 'receipt differs'):
                binding.NpmReplaySources(root, source, body + b' ', collection, receipt_path='sources/receipt.json')
            bad = {**collection, 'members': collection['members'] + [{**collection['members'][0], 'path': 'blobs/' + 'a' * 64, 'sha256': 'a' * 64}]}
            with self.assertRaisesRegex(ValueError, 'collection path is ambiguous'):
                binding.NpmReplaySources(root, source, body, bad, receipt_path='sources/receipt.json')
            missing = {**collection, 'members': collection['members'][1:]}
            mapped = binding.NpmReplaySources(root, source, body, missing, receipt_path='sources/receipt.json')
            with self.assertRaisesRegex(ValueError, 'no retained locked package'):
                mapped.resolve('node_modules/fixture-js/source.txt')
            (root / 'package-lock.json').write_text('{}')
            with self.assertRaisesRegex(ValueError, 'source-material (size|hash)'):
                binding.NpmReplaySources(root, source, body, collection, receipt_path='sources/receipt.json')


if __name__ == '__main__': unittest.main()
