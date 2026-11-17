import hashlib
import importlib.util
import io
import json
from pathlib import Path
import struct
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location('shipped_components', ROOT / 'scripts/release/collect-shipped-components.py')
shipped = importlib.util.module_from_spec(spec); spec.loader.exec_module(shipped)


class ShippedComponentTests(unittest.TestCase):
    def test_archive_backed_manifest_requires_explicit_available_target_scope(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); artifact = root / 'server.json'; artifact.write_text('{}')
            candidate = {
                'schema_version': 2,
                'qualification': 'available-target-preacceptance',
                'scope': {'kind': 'available-target-subset'},
                'source_tree_sha256': 'a' * 64, 'runtime_lock_sha256': 'b' * 64,
                'artifacts': [{'id': 'mcp-registry-record', 'path': artifact.name, 'sha256': shipped.sha(artifact), 'size': artifact.stat().st_size}],
            }
            self.assertEqual(shipped.collect(root, candidate, available_targets=True)['subjects'][0]['id'], 'mcp-registry-record')
            with self.assertRaisesRegex(ValueError, 'source/runtime-bound'): shipped.collect(root, candidate)
            with self.assertRaisesRegex(ValueError, 'immutable subset authority'):
                shipped.collect(root, {**candidate, 'scope': {'kind': 'foreign'}}, available_targets=True)
            with self.assertRaisesRegex(ValueError, 'immutable subset authority'):
                shipped.collect(root, candidate, available_targets=True, diagnostic=True)
            candidate['artifacts'][0]['sha256'] = '0' * 64
            with self.assertRaisesRegex(ValueError, 'hash'):
                shipped.collect(root, candidate, available_targets=True)

    def worker_transport(self, root, *, extra=False):
        def canonical(value): return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()
        sha = lambda value: 'sha256:' + hashlib.sha256(value).hexdigest()
        executable = bytearray(64); executable[:6] = b'\x7fELF\x02\x01'; struct.pack_into('<H', executable, 18, 183)
        layer = io.BytesIO()
        with tarfile.open(fileobj=layer, mode='w', format=tarfile.USTAR_FORMAT) as output:
            row = tarfile.TarInfo('bin/private-tool'); row.size = len(executable); output.addfile(row, io.BytesIO(executable))
        layer = layer.getvalue()
        config = canonical({'os': 'linux', 'architecture': 'arm64', 'rootfs': {'type': 'layers', 'diff_ids': [sha(layer)]}})
        manifest = canonical({'schemaVersion': 2, 'mediaType': 'application/vnd.oci.image.manifest.v1+json', 'config': {'mediaType': 'application/vnd.oci.image.config.v1+json', 'digest': sha(config), 'size': len(config)}, 'layers': [{'mediaType': 'application/vnd.oci.image.layer.v1.tar', 'digest': sha(layer), 'size': len(layer)}]})
        descriptor = {'mediaType': 'application/vnd.oci.image.manifest.v1+json', 'digest': sha(manifest), 'size': len(manifest), 'platform': {'os': 'linux', 'architecture': 'arm64'}}
        index = canonical({'schemaVersion': 2, 'mediaType': 'application/vnd.oci.image.index.v1+json', 'manifests': [descriptor]})
        files = {'oci-layout': b'{"imageLayoutVersion":"1.0.0"}', 'index.json': index, 'manifest.json': canonical([{'Config': 'blobs/sha256/' + sha(config)[7:], 'Layers': ['blobs/sha256/' + sha(layer)[7:]], 'RepoTags': []}]), **{'blobs/sha256/' + sha(body)[7:]: body for body in (config, manifest, layer)}}
        if extra: files['hidden-runtime'] = b'foreign unreferenced binary'
        file = root / 'worker.docker.tar'
        with tarfile.open(file, 'w', format=tarfile.USTAR_FORMAT) as output:
            for name, body in files.items():
                row = tarfile.TarInfo(name); row.size = len(body); output.addfile(row, io.BytesIO(body))
        artifact = {'id': 'core-linux-arm64-docker-archive-0', 'path': file.name, 'sha256': shipped.sha(file), 'size': file.stat().st_size}
        image = {'digest': sha(manifest), 'config_digest': sha(config), 'diff_ids': [sha(layer)], 'transports': [{'format': 'docker-archive', 'path': file.name, 'sha256': 'sha256:' + artifact['sha256'], 'size_bytes': artifact['size']}]}
        runtime = {'packs': {'core': {'images': {'linux/arm64': image}}}}
        return file, artifact, runtime, hashlib.sha256(executable).hexdigest()

    def test_real_per_arch_transport_members_are_reconciled_and_not_treated_as_unknown_sidecars(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); file, artifact, runtime, executable = self.worker_transport(root)
            (root / 'runtime').mkdir(); lock = root / 'runtime/runtime.lock.json'; lock.write_text(json.dumps(runtime))
            candidate = {'schema_version': 1, 'source_tree_sha256': 'a' * 64, 'runtime_lock_sha256': shipped.sha(lock), 'artifacts': [artifact]}
            result = shipped.collect(root, candidate, diagnostic=True)
            self.assertEqual(result['subjects'][0]['role'], 'worker-runtime')
            members = result['subjects'][0]['members']; self.assertEqual(len(members), 1)
            self.assertEqual((members[0]['image_path'], members[0]['sha256'], members[0]['architecture']), ('bin/private-tool', executable, 'linux-arm64'))
            self.assertFalse(any(row['code'] == 'UNCLASSIFIED_DISTRIBUTION_FORMAT' for row in result['blockers']))
            runtime['packs']['core']['images']['linux/arm64']['diff_ids'] = ['sha256:' + 'f' * 64]
            with self.assertRaisesRegex(ValueError, 'image graph differs'):
                shipped.transport_members(root, file, artifact, runtime, 'core', 'linux/arm64', 'docker-archive', 0)

    def test_worker_sidecar_extra_archive_payload_cannot_disappear_during_normalization(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); file, artifact, runtime, _ = self.worker_transport(root, extra=True)
            with self.assertRaisesRegex(ValueError, 'unreferenced archive members'):
                shipped.transport_members(root, file, artifact, runtime, 'core', 'linux/arm64', 'docker-archive', 0)

    def test_actual_archive_members_are_discovered_independently_of_supplied_components(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); file = root / 'pack.tar.gz'; body = bytearray(64); body[:6] = b'\x7fELF\x02\x01'; struct.pack_into('<H', body, 18, 183)
            with tarfile.open(file, 'w:gz') as archive:
                for name, content in [('bin/perl', body), ('share/licenses/LICENSE', b'Original upstream terms\n')]:
                    row = tarfile.TarInfo(name); row.size = len(content); archive.addfile(row, io.BytesIO(content))
            manifest = {'schema_version': 1, 'source_tree_sha256': 'a' * 64, 'runtime_lock_sha256': 'b' * 64, 'artifacts': [{'id': 'userspace-core-linux-arm64', 'path': file.name, 'sha256': shipped.sha(file), 'size': file.stat().st_size, 'complete_product_coverage': True, 'components': []}]}
            result = shipped.collect(root, manifest)
            self.assertFalse(result['complete_product_coverage'])
            self.assertEqual(result['status'], 'incomplete')
            self.assertEqual(len(result['required_distributions']), 16)
            self.assertEqual([row['path'] for row in result['subjects'][0]['members']], ['bin/perl', 'share/licenses/LICENSE']); self.assertEqual(result['subjects'][0]['members'][0]['architecture'], 'linux-arm64')
            self.assertEqual(sum(row['code'] == 'REQUIRED_DISTRIBUTION_MISSING' for row in result['blockers']), 16)
            self.assertTrue(any(row['code'] == 'SOURCE_RECIPE_AND_LICENSE_BINDING_REQUIRED' for row in result['blockers']))
            manifest['artifacts'][0]['sha256'] = '0' * 64
            with self.assertRaisesRegex(ValueError, 'hash'): shipped.collect(root, manifest)

    def test_archive_links_unicode_aliases_and_unknown_artifacts_cannot_hide_runtime_inputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); file = root / 'pack.tar.gz'
            for mode in ('escape', 'alias', 'link'):
                with tarfile.open(file, 'w:gz') as archive:
                    names = ['../outside'] if mode == 'escape' else ['Straße.txt', 'STRASSE.txt'] if mode == 'alias' else ['link']
                    for name in names:
                        row = tarfile.TarInfo(name)
                        if mode == 'link': row.type = tarfile.SYMTYPE; row.linkname = '/outside'; archive.addfile(row)
                        else: row.size = 1; archive.addfile(row, io.BytesIO(b'x'))
                with self.subTest(mode=mode), self.assertRaises(ValueError): shipped.archive_members(file)
            file.write_bytes(b'an undeclared runtime payload')
            result = shipped.collect(root, {'schema_version': 1, 'source_tree_sha256': 'a' * 64, 'runtime_lock_sha256': 'b' * 64, 'artifacts': [{'id': 'surprise-payload', 'path': file.name, 'sha256': shipped.sha(file), 'size': file.stat().st_size}]})
            self.assertTrue(any(row['code'] == 'UNCLASSIFIED_DISTRIBUTION_FORMAT' for row in result['blockers']))


if __name__ == '__main__': unittest.main()
