import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location('worker_export', ROOT / 'scripts/runtime/export-workers.py')
exporter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(exporter)


class WorkerExportTests(unittest.TestCase):
    def fixture(self, directory, *, extra=None, attest=False):
        layer = b'independent layer bytes'
        config = exporter.canonical({'os': 'linux', 'architecture': 'arm64', 'rootfs': {'type': 'layers', 'diff_ids': [exporter.sha(layer)]}})
        config_id = exporter.sha(config)
        manifest = exporter.canonical({'schemaVersion': 2, 'mediaType': exporter.MANIFEST, 'config': {'mediaType': exporter.CONFIG, 'digest': config_id, 'size': len(config)}, 'layers': [{'mediaType': 'application/vnd.oci.image.layer.v1.tar', 'digest': exporter.sha(layer), 'size': len(layer)}]})
        image = exporter.sha(manifest)
        descriptor = {'mediaType': exporter.MANIFEST, 'digest': image, 'size': len(manifest), 'platform': {'os': 'linux', 'architecture': 'arm64'}}
        index = exporter.canonical({'schemaVersion': 2, 'mediaType': exporter.INDEX, 'manifests': [descriptor, descriptor] if attest else [descriptor]})
        files = {'oci-layout': b'{"imageLayoutVersion":"1.0.0"}', 'index.json': index,
                 'blobs/sha256/' + image[7:]: manifest, 'blobs/sha256/' + config_id[7:]: config,
                 'blobs/sha256/' + exporter.sha(layer)[7:]: layer}
        archive = directory / 'image.tar'
        with tarfile.open(archive, 'w') as target:
            for name, data in files.items():
                info = tarfile.TarInfo(name); info.size = len(data)
                target.addfile(info, io.BytesIO(data))
            if extra:
                target.addfile(extra)
        return archive, exporter.sha(index), image, config_id, layer

    def test_local_engine_index_is_bound_to_exact_config_and_layers(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive, engine, image, config, layer = self.fixture(root)
            result = exporter.stage_image(archive, 'linux/arm64', engine, root / 'blobs')
            self.assertEqual(result['descriptor']['digest'], image)
            self.assertEqual(result['config_digest'], config)
            self.assertEqual(result['diff_ids'], ['sha256:' + hashlib.sha256(layer).hexdigest()])
            self.assertEqual(result['engine_descriptor_digests'], [engine])
            with self.assertRaisesRegex(ValueError, 'engine identity'):
                exporter.stage_image(archive, 'linux/arm64', 'sha256:' + 'a' * 64, root / 'blobs2')
            with self.assertRaisesRegex(ValueError, 'platform'):
                exporter.stage_image(archive, 'linux/amd64', engine, root / 'blobs3')

    def test_per_arch_oci_transport_contains_only_selected_verified_image_closure(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive, engine, image, config, layer = self.fixture(root)
            layout = root / 'layout'
            blobs = layout / 'blobs/sha256'
            item = exporter.stage_image(archive, 'linux/arm64', engine, blobs)
            extra = b'unrelated architecture bytes'
            (blobs / exporter.sha(extra)[7:]).write_bytes(extra)
            output = root / 'one.oci.tar'
            index = exporter.platform_archive(layout, item['descriptor'], item, output)
            with tarfile.open(output) as transport:
                names = {entry.name for entry in transport}
                self.assertNotIn('blobs/sha256/' + exporter.sha(extra)[7:], names)
                self.assertEqual(exporter.sha(transport.extractfile('index.json').read()), index)
                self.assertEqual(json.load(transport.extractfile('index.json'))['manifests'], [item['descriptor']])
                for identifier in [image, config, exporter.sha(layer), engine]:
                    self.assertIn('blobs/sha256/' + identifier[7:], names)
                    self.assertEqual(exporter.sha(transport.extractfile('blobs/sha256/' + identifier[7:]).read()), identifier)
            (blobs / config[7:]).write_bytes(b'damaged config')
            with self.assertRaisesRegex(ValueError, 'damaged'):
                exporter.platform_archive(layout, item['descriptor'], item, root / 'damaged.oci.tar')

    def test_attestations_and_hostile_archive_members_are_never_admitted(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive, engine, *_ = self.fixture(root, attest=True)
            with self.assertRaisesRegex(ValueError, 'provenance=false'):
                exporter.stage_image(archive, 'linux/arm64', engine, root / 'blobs')

    def test_source_inspection_cannot_discard_unreferenced_archive_payloads(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive, engine, *_ = self.fixture(root)
            exporter.stage_image(archive, 'linux/arm64', engine, root / 'closed', strict_inventory=True)
            extra = tarfile.TarInfo('unreferenced-payload'); extra.size = 0
            archive, engine, *_ = self.fixture(root, extra=extra)
            with self.assertRaisesRegex(ValueError, 'unreferenced'):
                exporter.stage_image(archive, 'linux/arm64', engine, root / 'unclosed', strict_inventory=True)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            link = tarfile.TarInfo('escape'); link.type = tarfile.SYMTYPE; link.linkname = '/outside'
            archive, engine, *_ = self.fixture(root, extra=link)
            with self.assertRaisesRegex(ValueError, 'link'):
                exporter.stage_image(archive, 'linux/arm64', engine, root / 'blobs')


if __name__ == '__main__':
    unittest.main()
