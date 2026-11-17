"""Opaque OCI member keys never become host extraction paths."""
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location('oci_member_materializer', ROOT / 'scripts/release/materialize-replay-inputs.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
NAME = 'var/lib/dpkg/info/libdb5.3t64:arm64.list'
BODY = b'/usr/lib/aarch64-linux-gnu/libdb-5.3.so\n'


def fixture(root):
    canonical = lambda value: json.dumps(value, sort_keys=True, separators=(',', ':')).encode()
    digest = lambda body: 'sha256:' + hashlib.sha256(body).hexdigest()
    held = io.BytesIO()
    with tarfile.open(fileobj=held, mode='w', format=tarfile.USTAR_FORMAT) as archive:
        row = tarfile.TarInfo(NAME)
        row.size = len(BODY)
        archive.addfile(row, io.BytesIO(BODY))
    layer = held.getvalue()
    config = canonical({'os': 'linux', 'architecture': 'arm64', 'rootfs': {'type': 'layers', 'diff_ids': [digest(layer)]}})
    manifest = canonical({'schemaVersion': 2, 'mediaType': 'application/vnd.oci.image.manifest.v1+json', 'config': {'mediaType': 'application/vnd.oci.image.config.v1+json', 'digest': digest(config), 'size': len(config)}, 'layers': [{'mediaType': 'application/vnd.oci.image.layer.v1.tar', 'digest': digest(layer), 'size': len(layer)}]})
    descriptor = {'mediaType': 'application/vnd.oci.image.manifest.v1+json', 'digest': digest(manifest), 'size': len(manifest), 'platform': {'os': 'linux', 'architecture': 'arm64'}}
    index = canonical({'schemaVersion': 2, 'mediaType': 'application/vnd.oci.image.index.v1+json', 'manifests': [descriptor], 'annotations': {'org.opencontainers.image.ref.name': 'test-original-export'}})
    files = {'oci-layout': b'{"imageLayoutVersion":"1.0.0"}', 'index.json': index, 'manifest.json': canonical([{'Config': 'blobs/sha256/' + digest(config)[7:], 'Layers': ['blobs/sha256/' + digest(layer)[7:]], 'RepoTags': []}]), **{'blobs/sha256/' + digest(body)[7:]: body for body in (config, manifest, layer)}}
    docker = root / 'worker.docker.tar'
    with tarfile.open(docker, 'w', format=tarfile.USTAR_FORMAT) as archive:
        for name, body in files.items():
            row = tarfile.TarInfo(name)
            row.size = len(body)
            archive.addfile(row, io.BytesIO(body))
    layout = root / 'layout'
    staged = m.shipped.worker_export.stage_image(docker, 'linux/arm64', digest(config), layout / 'blobs/sha256', strict_inventory=True)
    oci = root / 'worker.oci.tar'
    index_digest = m.shipped.worker_export.platform_archive(layout, staged['descriptor'], staged, oci)
    receipt = lambda file: {'path': file.name, 'sha256': m.shipped.sha(file), 'size': file.stat().st_size}
    image = {'digest': digest(manifest), 'config_digest': digest(config), 'diff_ids': [digest(layer)], 'engine_descriptor_digests': staged['engine_descriptor_digests'], 'transports': [{'format': 'docker-archive', 'sha256': 'sha256:' + receipt(docker)['sha256'], 'size_bytes': docker.stat().st_size}, {'format': 'oci-archive', 'sha256': 'sha256:' + receipt(oci)['sha256'], 'size_bytes': oci.stat().st_size, 'index_digest': index_digest}]}
    pack = {'index_digest': index_digest, 'platforms': {'linux/arm64': digest(manifest)}, 'images': {'linux/arm64': image}, 'index_transport': {'path': 'original/unavailable-cache.oci.tar', 'sha256': 'sha256:' + receipt(oci)['sha256'], 'size_bytes': oci.stat().st_size}}
    runtime = {'state': 'frozen', 'packs': {'core': pack}}
    (root / 'runtime').mkdir()
    lock = root / 'runtime/runtime.lock.json'
    lock.write_text(json.dumps(runtime))
    return [(identifier, {**receipt(file), 'id': identifier}) for identifier, file in [('core-oci-index', oci), ('core-linux-arm64-docker-archive-0', docker), ('core-linux-arm64-oci-archive-1', oci)]], m.shipped.sha(lock), 'layers/' + digest(layer)[7:] + '/0/' + NAME


class OciReplayMemberTests(unittest.TestCase):
    def setUp(self):
        self.environment = mock.patch.dict(os.environ, {'UD_STORAGE_LEASE': ''})
        self.environment.start(); self.addCleanup(self.environment.stop)

    def test_catalog_requires_actual_discovered_member_identity_and_safe_host_destination(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            file = root / 'cache/input'
            file.parent.mkdir()
            file.write_bytes(BODY)
            key = 'layers/' + 'a' * 64 + '/0/' + NAME
            row = {'path': 'cache/input', 'sha256': hashlib.sha256(BODY).hexdigest(), 'size_bytes': len(BODY), 'executable': False, 'retention': {'kind': 'released-artifact-member', 'artifact': 'core-oci-index', 'member': key}}
            subjects = [{'id': 'core-oci-index', 'sha256': 'b' * 64}]
            discovered = [{'id': 'core-oci-index', 'members': [{'path': key, 'sha256': row['sha256'], 'size_bytes': len(BODY)}]}]
            catalog = {'schema_version': 1, 'qualification': m.inputs.QUALIFICATION, 'source_inventory_sha256': 'c' * 64, 'subjects': subjects, 'inputs': [row], 'inventory_sha256': hashlib.sha256(m.inputs.canonical([row])).hexdigest(), 'unretained_inputs': [], 'tools': []}
            self.assertTrue(m.inputs.verify(catalog, root, 'c' * 64, subjects, require_retained=True, discovered_subjects=discovered)['verified'])
            for field, value in [('member', key + '.foreign'), ('sha256', 'f' * 64), ('path', 'cache/input:unsafe')]:
                bad = copy.deepcopy(catalog)
                if field == 'member': bad['inputs'][0]['retention']['member'] = value
                else: bad['inputs'][0][field] = value
                bad['inventory_sha256'] = hashlib.sha256(m.inputs.canonical(bad['inputs'])).hexdigest()
                with self.subTest(field=field), self.assertRaises(ValueError):
                    m.inputs.verify(bad, root, 'c' * 64, subjects, require_retained=True, discovered_subjects=discovered)

    def test_opaque_layer_colon_is_allowed_only_for_exact_known_oci_artifact_keys(self):
        key = 'layers/' + 'a' * 64 + '/0/' + NAME
        self.assertEqual(m.inputs.artifact_member('core-oci-index', key), key)
        with self.assertRaises(ValueError): m.inputs.safe(NAME)
        with self.assertRaises(ValueError): m.inputs.artifact_member('native-linux-arm64', key)
        for bad in [key.replace('/0/', '/00/'), key.replace('/0/', '/0/../'), '/'+key, key.replace('/var/', '/var\\'), key.replace('layers/', 'other/')]:
            with self.subTest(name=bad), self.assertRaises(ValueError): m.inputs.artifact_member('core-oci-index', bad)

    def test_index_docker_and_oci_transport_copy_exact_graph_member_into_safe_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifacts, runtime_hash, key = fixture(root)
            for identifier, artifact in artifacts:
                destination = root / identifier
                destination.mkdir()
                row = {'path': 'cache/package-list', 'sha256': hashlib.sha256(BODY).hexdigest(), 'size_bytes': len(BODY), 'executable': False}
                original = m.shipped.transport_members
                def bounded_transport(*args, **kwargs):
                    self.assertEqual(tempfile.gettempdir(), str(destination.parent))
                    return original(*args, **kwargs)
                previous_tempdir = tempfile.tempdir
                with mock.patch.object(m.shipped, 'transport_members', side_effect=bounded_transport):
                    m.copy_oci_members(root, root, artifact, runtime_hash, {key: [row]}, destination, available_targets=True)
                self.assertEqual(tempfile.tempdir, previous_tempdir)
                self.assertEqual((destination / row['path']).read_bytes(), BODY)
                self.assertFalse((destination / row['path']).stat().st_mode & 0o222)
                self.assertFalse((destination / 'var').exists())

    def test_materializer_entrypoint_rebuilds_missing_cache_from_private_copied_oci_subject(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifacts, runtime_hash, key = fixture(root)
            artifact = artifacts[0][1]
            runtime = root / 'runtime/runtime.lock.json'
            source = {'sha256': 'c' * 64, 'files': [{'path': 'runtime/runtime.lock.json', 'sha256': runtime_hash, 'size': runtime.stat().st_size, 'executable': False}]}
            candidate = {'schema_version': 1, 'qualification': 'available-target-preacceptance', 'source_tree_sha256': source['sha256'], 'runtime_lock_sha256': runtime_hash, 'artifacts': [artifact]}
            row = {'path': '.artifacts/missing-cache/package-list', 'sha256': hashlib.sha256(BODY).hexdigest(), 'size_bytes': len(BODY), 'executable': False, 'retention': {'kind': 'released-artifact-member', 'artifact': artifact['id'], 'member': key}}
            catalog = {'schema_version': 1, 'qualification': m.inputs.QUALIFICATION, 'source_inventory_sha256': source['sha256'], 'subjects': [{'id': artifact['id'], 'sha256': artifact['sha256']}], 'inputs': [row], 'inventory_sha256': hashlib.sha256(m.inputs.canonical([row])).hexdigest(), 'unretained_inputs': [], 'tools': []}
            report = {'source_inventory_sha256': source['sha256'], 'inspection_inputs': catalog, 'required_materials': [], 'subjects': [{'id': artifact['id'], 'bindings': [{'size_bytes': len(BODY)}]}]}
            destination = root / 'new-private-replay'
            self.assertFalse((root / row['path']).exists())
            self.assertTrue(m.materialize(root, candidate, source, report, destination)['verified'])
            self.assertEqual((destination / row['path']).read_bytes(), BODY)
            compact = root / 'compact-private-replay'
            self.assertTrue(m.materialize(root, candidate, source, report, compact, compact=True)['verified'])
            self.assertEqual((compact / row['path']).read_bytes(), BODY)
            self.assertFalse((compact / artifact['path']).exists())
            self.assertFalse((compact / 'runtime/runtime.lock.json').exists())
            bad = copy.deepcopy(report)
            bad['inspection_inputs']['inputs'][0]['retention']['member'] += '.foreign'
            bad['inspection_inputs']['inventory_sha256'] = hashlib.sha256(m.inputs.canonical(bad['inspection_inputs']['inputs'])).hexdigest()
            rejected = root / 'rejected-private-replay'
            with self.assertRaisesRegex(ValueError, 'omitted a referenced'):
                m.materialize(root, candidate, source, bad, rejected)
            self.assertFalse(rejected.exists())

    def test_wrong_runtime_layer_member_hash_and_unsafe_output_cannot_materialize(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifacts, runtime_hash, key = fixture(root)
            artifact = artifacts[0][1]
            destination = root / 'output'
            destination.mkdir()
            row = {'path': 'cache/package-list', 'sha256': hashlib.sha256(BODY).hexdigest(), 'size_bytes': len(BODY), 'executable': False}
            with self.assertRaisesRegex(ValueError, 'runtime lock differs'):
                m.copy_oci_members(root, root, artifact, '0' * 64, {key: [row]}, destination, available_targets=True)
            for foreign in [key.replace(key.split('/')[1], 'f' * 64), key + '.foreign']:
                with self.assertRaisesRegex(ValueError, 'omitted a referenced'):
                    m.copy_oci_members(root, root, artifact, runtime_hash, {foreign: [row]}, destination, available_targets=True)
            with self.assertRaisesRegex(ValueError, 'differs from actual referenced bytes'):
                m.copy_oci_members(root, root, artifact, runtime_hash, {key: [{**row, 'sha256': 'f' * 64}]}, destination, available_targets=True)
            with self.assertRaisesRegex(ValueError, 'unsafe'):
                m.copy_oci_members(root, root, artifact, runtime_hash, {key: [{**row, 'path': '../outside'}]}, destination, available_targets=True)


if __name__ == '__main__':
    unittest.main()
