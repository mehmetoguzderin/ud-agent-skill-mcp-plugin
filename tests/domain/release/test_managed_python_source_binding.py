"""Original metadata fixtures; no target interpreter is ever executed."""
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import struct
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import zipfile
from contextlib import contextmanager

ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location('managed_python_source_binder', ROOT / 'scripts/release/bind-managed-python-sources.py')
BINDER = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(BINDER)
PARTS_SPEC = importlib.util.spec_from_file_location('ud_managed_test_parts', ROOT / 'scripts/release/materialize-replay-inputs.py')
PARTS = importlib.util.module_from_spec(PARTS_SPEC); PARTS_SPEC.loader.exec_module(PARTS)


class SourceParts:
    def __init__(self, bodies): self.bodies = bodies
    @contextmanager
    def open_blob(self, fingerprint, size):
        body = self.bodies.get(fingerprint)
        if body is None or len(body) != size or hashlib.sha256(body).hexdigest() != fingerprint: raise ValueError('original source blob is missing or altered')
        with io.BytesIO(body) as stream, PARTS.BlobView(stream, 0, len(body)) as view: yield view


class Recorder:
    def __init__(self): self.rows = []
    def source_blob(self, *row): self.rows.append(row)
def sha(body): return hashlib.sha256(body).hexdigest()
def tar_bytes(entries, links=()):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w:gz') as archive:
        for name, body in entries:
            entry = tarfile.TarInfo(name); entry.size = len(body); archive.addfile(entry, io.BytesIO(body))
        for name, target in links:
            entry = tarfile.TarInfo(name); entry.type = tarfile.SYMTYPE; entry.linkname = target; archive.addfile(entry)
    return output.getvalue()
def wheel_bytes(name):
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w') as archive:
        archive.writestr(name + '/__init__.py', '# exact source\n')
        archive.writestr(name + '.dist-info/licenses/LICENSE.txt', 'original ' + name + ' notice')
    return output.getvalue()
def fixture(folder):
    root = Path(folder); (root / 'runtime').mkdir(); collection = root / 'collection'; collection.mkdir(); (collection / 'blobs').mkdir(); (collection / 'notices').mkdir()
    names = ['cpython-3.14', 'cpython-3.15', 'pip', 'setuptools', 'linux-uapi', 'musl', 'musl-static', 'zstd', 'library-fixture']
    table = {}; rows = []
    for name in names:
        version = '3.14.10' if name == 'cpython-3.14' else '3.15.2' if name == 'cpython-3.15' else '1.0'
        wheel = name in ('pip', 'setuptools'); body = wheel_bytes(name) if wheel else ('source:' + name).encode(); digest = sha(body)
        url = 'https://source.example/' + name + ('-py3-none-any.whl' if wheel else '.tar.gz')
        entry = {'url': url, 'version': version, 'size': len(body), 'sha256': digest}
        if name == 'library-fixture': entry['library_names'] = ['fixture']
        if not wheel: entry['license_file'] = 'LICENSE.runtime.txt'; entry['licenses'] = ['MIT']
        table[name] = entry; (collection / 'blobs' / digest).write_bytes(body)
        rows.append({'name': name, 'version': version, 'url': url, 'sha256': digest, 'size_bytes': len(body), 'path': 'blobs/' + digest, 'acquired': True})
    commit = 'a' * 40; prefix = 'python-build-standalone-' + commit + '/'
    notice = b'original recipe license'; recipe_body = tar_bytes([(prefix + 'pythonbuild/downloads.json', json.dumps(table).encode()), (prefix + 'LICENSE.runtime.txt', notice)])
    source = {'url': 'https://codeload.github.com/astral-sh/python-build-standalone/tar.gz/' + commit, 'sha256': sha(recipe_body), 'size_bytes': len(recipe_body)}
    proof = {'repository': 'astral-sh/python-build-standalone', 'tag': '20261026', 'commit': commit, 'source': source}
    (root / 'runtime/managed-python-source.lock.json').write_text(json.dumps({'schema_version': 1, **proof, 'python_versions': {'3.14': '3.14.10', '3.15': '3.15.2'}}))
    (collection / 'build-recipe.tar.gz').write_bytes(recipe_body); (collection / 'notices' / sha(notice)).write_bytes(notice)
    rows.append({'name': 'python-build-standalone', 'version': commit, **source, 'path': 'build-recipe.tar.gz', 'acquired': True})
    report = {'schema_version': 1, 'qualification': 'frozen-managed-interpreter-runtime-source-subinventory', 'status': 'passed', 'build_source': proof, 'files': rows, 'notices': [{'source_path': prefix + 'LICENSE.runtime.txt', 'path': 'notices/' + sha(notice), 'sha256': sha(notice), 'size_bytes': len(notice)}]}
    receipt = collection / 'receipt.json'; receipt.write_text(json.dumps(report))
    platforms = {platform: {'python_download': {'version': '3.14.10', 'sha256': 'sha256:' + 'b' * 64, 'size': 20, 'url': 'https://github.com/astral-sh/python-build-standalone/releases/download/20261026/cpython-3.14.10%2B20261026-' + triple + '-install_only_stripped.tar.gz'}} for platform, triple in BINDER.PLATFORMS.items()}
    (root / 'runtime/userspace-inputs.lock.json').write_text(json.dumps({'platforms': platforms}))
    return root, receipt, report

class ManagedPythonSourceBindingTests(unittest.TestCase):
    def test_derives_runtime_sources_from_locked_recipe_instead_of_supplied_completion_list(self):
        with tempfile.TemporaryDirectory() as folder:
            root, receipt, _ = fixture(folder); result = BINDER.derive(root, receipt)
            self.assertEqual(len(result['sources']), 9); self.assertEqual(len(result['licenses']), 3)
            self.assertEqual(len(result['binary_inputs']), 6)
            self.assertTrue(result['complete_component_coverage']); self.assertFalse(result['complete_product_coverage'])
            self.assertTrue(all(row['redistribution'] == 'vendor-direct-not-redistributed' and not row['archive_inspected'] and not row['target_execution'] for row in result['binary_inputs']))

    def test_runtime_sources_and_notices_replay_from_verified_parts_without_expanded_files(self):
        with tempfile.TemporaryDirectory() as folder:
            root, receipt, report = fixture(folder); expected = BINDER.derive(root, receipt); bodies = {}
            for row in [*report['files'], *report['notices']]:
                file = receipt.parent / row['path']; bodies[row['sha256']] = file.read_bytes(); file.unlink(missing_ok=True)
            recorder = Recorder(); actual = BINDER.derive(root, receipt, source_parts=SourceParts(bodies), recorder=recorder)
            self.assertEqual(actual, expected); self.assertEqual({row[1] for row in recorder.rows}, set(bodies))
            self.assertTrue(all(not (receipt.parent / row['path']).exists() for row in report['files']))
            changed = dict(bodies); key = report['files'][0]['sha256']; changed[key] = b'bad'
            with self.assertRaisesRegex(ValueError, 'missing or altered'): BINDER.derive(root, receipt, source_parts=SourceParts(changed), recorder=Recorder())
            staged = receipt.parent / report['files'][0]['path']; staged.parent.mkdir(exist_ok=True); staged.write_bytes(b'corrupt')
            with self.assertRaises(ValueError): BINDER.derive(root, receipt, source_parts=SourceParts(bodies), recorder=Recorder())

    def test_omitted_added_corrupt_or_stale_source_and_license_inputs_cannot_claim_coverage(self):
        for change in ('omit', 'extra', 'corrupt', 'notice', 'recipe', 'platform'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as folder:
                root, receipt, report = fixture(folder)
                if change == 'omit': report['files'].pop(0)
                elif change == 'extra': report['files'].append({**report['files'][0], 'name': 'unreviewed'})
                elif change == 'corrupt': (receipt.parent / report['files'][0]['path']).write_bytes(b'changed')
                elif change == 'notice': (receipt.parent / report['notices'][0]['path']).write_bytes(b'changed')
                elif change == 'recipe': report['build_source']['commit'] = 'c' * 40
                else:
                    file = root / 'runtime/userspace-inputs.lock.json'; value = json.loads(file.read_bytes()); value['platforms'].pop('linux/x64'); file.write_text(json.dumps(value))
                receipt.write_text(json.dumps(report))
                with self.assertRaises(ValueError): BINDER.derive(root, receipt)

    def test_binary_data_inspection_checks_architecture_names_links_and_actual_notices(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); header = bytearray(64); header[:6] = b'\x7fELF\x02\x01'; struct.pack_into('<H', header, 18, 183)
            for kind in ('valid', 'wrong-arch', 'traversal', 'duplicate', 'no-notice', 'escaping-link', 'missing-link', 'linux-case-variants'):
                with self.subTest(kind=kind):
                    binary = bytes(header)
                    if kind == 'wrong-arch': wrong = bytearray(header); struct.pack_into('<H', wrong, 18, 62); binary = bytes(wrong)
                    entries = [('python/bin/python3.14', binary)]
                    if kind != 'no-notice': entries.append(('python/lib/LICENSE.txt', b'original Python notice'))
                    if kind == 'traversal': entries.append(('../escape', b'bad'))
                    if kind == 'duplicate': entries.append(entries[0])
                    if kind == 'linux-case-variants': entries.extend([('python/share/terminfo/2/2621A', b'first'), ('python/share/terminfo/2/2621a', b'second')])
                    links = [('python/bin/linked', '../../../outside')] if kind == 'escaping-link' else [('python/bin/linked', 'missing')] if kind == 'missing-link' else []
                    body = tar_bytes(entries, links); file = root / 'binary.tar.gz'; file.write_bytes(body); descriptor = {'sha256': 'sha256:' + sha(body), 'size': len(body), 'version': '3.14.10'}
                    if kind in ('valid', 'linux-case-variants'):
                        result = BINDER.inspect_binary(file, descriptor, 'linux/arm64'); self.assertTrue(result['archive_inspected']); self.assertFalse(result['target_execution']); self.assertEqual(result['executable']['architecture'], 'linux/arm64')
                        self.assertEqual(len(result['case_sensitive_name_pairs']), int(kind == 'linux-case-variants'))
                    else:
                        with self.assertRaises(ValueError): BINDER.inspect_binary(file, descriptor, 'linux/arm64')

    def test_archive_path_replacement_cannot_change_the_verified_inspection_identity(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); header = bytearray(64); header[:6] = b'\x7fELF\x02\x01'; struct.pack_into('<H', header, 18, 183)
            body = tar_bytes([('python/bin/python3.14', bytes(header)), ('python/lib/LICENSE.txt', b'notice')]); file = root / 'binary.tar.gz'; file.write_bytes(body)
            descriptor = {'sha256': 'sha256:' + sha(body), 'size': len(body), 'version': '3.14.10'}
            original = BINDER.inspector.architecture
            def replace(prefix):
                if os.name == 'nt':
                    with self.assertRaises(PermissionError) as refused: file.rename(root / 'previous.tar.gz')
                    self.assertEqual(refused.exception.winerror, 32)
                    self.assertEqual(file.read_bytes(), body)
                    return original(prefix)
                file.rename(root / 'previous.tar.gz'); file.write_bytes(body)
                return original(prefix)
            with patch.object(BINDER.inspector, 'architecture', side_effect=replace):
                if os.name == 'nt':
                    self.assertTrue(BINDER.inspect_binary(file, descriptor, 'linux/arm64')['archive_inspected'])
                    self.assertFalse((root / 'previous.tar.gz').exists())
                else:
                    with self.assertRaisesRegex(ValueError, 'changed during'):
                        BINDER.inspect_binary(file, descriptor, 'linux/arm64')

if __name__ == '__main__': unittest.main()
