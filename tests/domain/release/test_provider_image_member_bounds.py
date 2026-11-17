import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts/release' / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


shipped = load('provider_image_shipped', 'collect-shipped-components.py')
materializer = load('provider_image_materializer', 'materialize-replay-inputs.py')
IMAGE = 'runtime/providers/lima-nerdctl/darwin-arm64/guest/ubuntu.img'
BODY = b'QFI\xfb original guest image bytes'
NOTICE = b'MIT\n'


def fixture(root):
    file = root / 'provider.tar.gz'
    with tarfile.open(file, 'w:gz') as archive:
        for name, body in [(IMAGE, BODY), ('LICENSE', NOTICE)]:
            row = tarfile.TarInfo(name)
            row.size = len(body)
            archive.addfile(row, io.BytesIO(body))
    artifact = {'id': 'provider-assets-lima-nerdctl-darwin-arm64', 'path': file.name, 'sha256': shipped.sha(file), 'size': file.stat().st_size}
    image = {'key': 'image', 'path': IMAGE, 'sha256': 'sha256:' + hashlib.sha256(BODY).hexdigest(), 'size_bytes': len(BODY)}
    profile = {'lazy_assets': {'sha256': 'sha256:' + artifact['sha256'], 'size': artifact['size'], 'files': [{key: value for key, value in image.items() if key != 'key'}]}, 'provisioning': {'assets': [image]}}
    runtime = {'state': 'frozen', 'provider_receipts': {'lima-nerdctl/darwin/arm64': profile}}
    (root / 'runtime').mkdir()
    candidate = {'schema_version': 1, 'source_tree_sha256': 'a' * 64, 'artifacts': [artifact]}
    save_runtime(root, runtime, candidate)
    return file, artifact, runtime, profile, candidate


def save_runtime(root, runtime, candidate):
    file = root / 'runtime/runtime.lock.json'
    file.write_text(json.dumps(runtime))
    candidate['runtime_lock_sha256'] = shipped.sha(file)


class ProviderImageMemberBoundsTests(unittest.TestCase):
    def test_exact_outer_archive_and_member_identities_admit_only_the_pinned_large_guest(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(shipped, 'MAX_AUX_FILE', 8):
            root = Path(temporary)
            file, artifact, _, _, candidate = fixture(root)
            with self.assertRaisesRegex(ValueError, 'oversized member'):
                shipped.archive_members(file)
            result = shipped.collect(root, candidate)
            image = next(row for row in result['subjects'][0]['members'] if row['path'] == IMAGE)
            self.assertEqual(image['sha256'], hashlib.sha256(BODY).hexdigest())
            self.assertEqual(image['size_bytes'], len(BODY))
            unknown = {**artifact, 'id': 'provider-assets-unrelated-darwin-arm64'}
            self.assertEqual(shipped.provider_image_members(root, unknown, candidate['runtime_lock_sha256']), {})

    def test_missing_wrong_name_size_hash_and_archive_descriptors_reject(self):
        mutations = [
            lambda profile: profile['provisioning'].update(assets=[]),
            lambda profile: profile['provisioning']['assets'][0].update(path=IMAGE + '.foreign'),
            lambda profile: profile['lazy_assets'].update(sha256='sha256:' + 'f' * 64),
            lambda profile: profile['lazy_assets']['files'][0].update(size_bytes=len(BODY) + 1),
            lambda profile: profile['provisioning']['assets'][0].update(size_bytes=2 * 1024 ** 3 + 1),
        ]
        for mutate in mutations:
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                _, artifact, runtime, profile, candidate = fixture(root)
                mutate(profile)
                save_runtime(root, runtime, candidate)
                with self.assertRaises(ValueError):
                    shipped.provider_image_members(root, artifact, candidate['runtime_lock_sha256'])
        with tempfile.TemporaryDirectory() as temporary, patch.object(shipped, 'MAX_AUX_FILE', 8):
            root = Path(temporary)
            file, artifact, runtime, profile, candidate = fixture(root)
            for row in [profile['lazy_assets']['files'][0], profile['provisioning']['assets'][0]]:
                row['sha256'] = 'sha256:' + 'f' * 64
            save_runtime(root, runtime, candidate)
            with self.assertRaisesRegex(ValueError, 'member hash differs'):
                shipped.collect(root, candidate)
            with self.assertRaisesRegex(ValueError, 'runtime lock differs'):
                shipped.provider_image_members(root, artifact, '0' * 64)

    def test_collector_aggregate_bound_remains_in_force_for_pinned_images(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(shipped, 'MAX_AUX_FILE', 8), patch.object(shipped, 'MAX_AUX_TOTAL', len(BODY) + len(NOTICE) - 1):
            root = Path(temporary)
            _, _, _, _, candidate = fixture(root)
            with self.assertRaisesRegex(ValueError, 'archive exceeds bound'):
                shipped.collect(root, candidate)

    def test_rebuilt_outer_descriptor_cannot_omit_rename_or_resize_the_pinned_image(self):
        for mode in ['omit', 'rename', 'size']:
            with tempfile.TemporaryDirectory() as temporary, patch.object(shipped, 'MAX_AUX_FILE', 8):
                root = Path(temporary)
                file, artifact, runtime, profile, candidate = fixture(root)
                if mode == 'size':
                    for row in [profile['lazy_assets']['files'][0], profile['provisioning']['assets'][0]]:
                        row['size_bytes'] += 1
                else:
                    with tarfile.open(file, 'w:gz') as archive:
                        for name, body in ([('LICENSE', NOTICE)] if mode == 'omit' else [(IMAGE + '.foreign', BODY), ('LICENSE', NOTICE)]):
                            row = tarfile.TarInfo(name)
                            row.size = len(body)
                            archive.addfile(row, io.BytesIO(body))
                    artifact.update(sha256=shipped.sha(file), size=file.stat().st_size)
                    profile['lazy_assets'].update(sha256='sha256:' + artifact['sha256'], size=artifact['size'])
                save_runtime(root, runtime, candidate)
                with self.subTest(mode=mode), self.assertRaises(ValueError):
                    shipped.collect(root, candidate)

    def test_materializer_hashes_both_selected_and_unselected_pinned_members(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(materializer, 'MAX_MEMBER_FILE', 8):
            root = Path(temporary)
            file, artifact, _, _, candidate = fixture(root)
            pinned = shipped.provider_image_members(root, artifact, candidate['runtime_lock_sha256'])
            for selected in [IMAGE, 'LICENSE']:
                destination = root / ('image-copy' if selected == IMAGE else 'notice-copy')
                destination.mkdir()
                body = BODY if selected == IMAGE else NOTICE
                requests = {selected: [{'path': 'cache/input', 'sha256': hashlib.sha256(body).hexdigest(), 'size_bytes': len(body), 'executable': False}]}
                materializer.copy_members(file, artifact, requests, destination, provider_images=pinned)
                self.assertEqual((destination / 'cache/input').read_bytes(), body)
            bad = copy.deepcopy(pinned)
            bad[IMAGE]['sha256'] = 'f' * 64
            destination = root / 'rejected'
            destination.mkdir()
            with self.assertRaisesRegex(ValueError, 'provider image hash differs'):
                materializer.copy_members(file, artifact, {}, destination, provider_images=bad)

    def test_materializer_normal_member_and_total_bounds_are_not_relaxed(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(materializer, 'MAX_MEMBER_FILE', 8):
            root = Path(temporary)
            file, artifact, _, _, candidate = fixture(root)
            destination = root / 'cache'
            destination.mkdir()
            with self.assertRaisesRegex(ValueError, 'duplicate or oversized'):
                materializer.copy_members(file, artifact, {}, destination)
            pinned = shipped.provider_image_members(root, artifact, candidate['runtime_lock_sha256'])
            with patch.object(materializer, 'MAX_MEMBER_TOTAL', len(BODY) + len(NOTICE) - 1):
                with self.assertRaisesRegex(ValueError, 'expansion exceeds bound'):
                    materializer.copy_members(file, artifact, {}, destination, provider_images=pinned)


if __name__ == '__main__':
    unittest.main()
