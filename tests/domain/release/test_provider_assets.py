import gzip
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import struct
import sys
import tarfile
import tempfile
import unittest
import zipfile
from compression import zstd

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'scripts/runtime'))
spec = importlib.util.spec_from_file_location('provider_assets', ROOT / 'scripts/runtime/prepare-provider-assets.py')
assets = importlib.util.module_from_spec(spec)
spec.loader.exec_module(assets)


class ProviderAssets(unittest.TestCase):
    def test_init_normalization_preserves_upstream_layer_and_binds_new_local_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cache = root / 'cache'
            cache.mkdir()
            raw = b'independent uncompressed init bytes'
            layer = gzip.compress(raw, mtime=0)
            layer_hash = assets.sha(layer)
            config = json.dumps({'architecture': 'arm64', 'os': 'linux', 'rootfs': {'type': 'layers', 'diff_ids': [layer_hash]}}).encode()
            manifest = json.dumps({'schemaVersion': 2, 'config': {'digest': assets.sha(config), 'size': len(config), 'mediaType': 'application/vnd.oci.image.config.v1+json'}, 'layers': [{'digest': layer_hash, 'size': len(layer), 'mediaType': 'application/vnd.oci.image.layer.v1.tar+gzip'}]}).encode()
            index = json.dumps({'manifests': [{'digest': assets.sha(manifest), 'platform': {'architecture': 'arm64'}}]}).encode()
            for body in [layer, config]:
                (cache / assets.sha(body)[7:]).write_bytes(body)
            (cache / 'apple-init-manifest.json').write_bytes(manifest)
            (cache / 'apple-init-index.json').write_bytes(index)
            lock = {'apple_container': {'init_image': {'manifest_digest': assets.sha(manifest), 'config_digest': assets.sha(config), 'index_digest': assets.sha(index)}}}
            result = assets.prepare_init(lock, cache, root / 'output')
            self.assertEqual(result['diff_ids'], ['sha256:' + hashlib.sha256(raw).hexdigest()])
            self.assertNotEqual(result['digest'], assets.sha(manifest))
            self.assertTrue(result['reference'].startswith('localhost/ud-agent-skill-mcp-plugin-init@'))
            with tarfile.open(root / 'output/runtime/images/init-linux-arm64.tar') as bundle:
                self.assertEqual(bundle.extractfile('blobs/sha256/' + layer_hash[7:]).read(), layer)
                derived = bundle.extractfile('blobs/sha256/' + result['config_digest'][7:]).read()
                self.assertEqual(assets.sha(derived), result['config_digest'])
                self.assertEqual(json.loads(derived)['rootfs']['diff_ids'], result['diff_ids'])
                annotations = json.load(bundle.extractfile('index.json'))['manifests'][0]['annotations']
                self.assertEqual(set(annotations.values()), {result['reference']})
            (cache / layer_hash[7:]).write_bytes(b'corrupt')
            with self.assertRaisesRegex(ValueError, 'integrity'):
                assets.prepare_init(lock, cache, root / 'rejected')

    def test_selected_zip_members_reject_links_duplicates_and_size_excess(self):
        for kind in ['duplicate', 'symlink', 'oversized']:
            buffer = io.BytesIO()
            with zipfile.ZipFile(buffer, 'w') as bundle:
                entry = zipfile.ZipInfo('sdk.dll')
                entry.external_attr = (0o120777 if kind == 'symlink' else 0o100644) << 16
                bundle.writestr(entry, b'bytes')
                if kind == 'duplicate':
                    bundle.writestr('sdk.dll', b'different')
            with zipfile.ZipFile(io.BytesIO(buffer.getvalue())) as bundle:
                with self.assertRaisesRegex(ValueError, 'ZIP member'):
                    assets.safe_zip_member(bundle, 'sdk.dll', 4 if kind == 'oversized' else 10)

    def test_kernel_image_header_checks_architecture_and_zero_fill_extent(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for valid in [True, False]:
                body = bytearray(128)
                body[:2] = b'MZ'
                body[56:60] = b'ARMd'
                struct.pack_into('<Q', body, 16, 4096)  # Boot zero-fill exceeds file bytes.
                struct.pack_into('<I', body, 60, 64)
                body[64:70] = b'PE\0\0' + (b'\x64\xaa' if valid else b'\x64\x86')
                stream = io.BytesIO()
                with tarfile.open(fileobj=stream, mode='w') as bundle:
                    entry = tarfile.TarInfo('./frozen/vmlinux')
                    entry.size = len(body)
                    bundle.addfile(entry, io.BytesIO(body))
                archive = root / ('valid.zst' if valid else 'invalid.zst')
                archive.write_bytes(zstd.compress(stream.getvalue()))
                if valid:
                    assets.extract_kernel(archive, 'frozen/vmlinux', root / 'kernel')
                    self.assertEqual((root / 'kernel').read_bytes(), body)
                else:
                    with self.assertRaisesRegex(ValueError, 'AArch64'):
                        assets.extract_kernel(archive, 'frozen/vmlinux', root / 'rejected')


if __name__ == '__main__':
    unittest.main()
