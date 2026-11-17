import hashlib
import importlib.util
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location('ud_provider_archives_test', ROOT / 'scripts/runtime/prepare-provider-archives.py')
provider = importlib.util.module_from_spec(spec)
spec.loader.exec_module(provider)


class ProviderArchiveTests(unittest.TestCase):
    def test_each_provider_transport_has_only_its_closed_inventory_and_is_reproducible(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / 'source'
            source.mkdir()
            data = {'runtime/providers/apple-container/darwin-arm64/container': b'Apple ARM', 'runtime/providers/wslc/win32-x64/wslc.exe': b'WSL AMD', 'runtime/images/init-linux-arm64.tar': b'init OCI', 'runtime/engine-distributions.lock.json': b'{}\n'}
            files = []
            for name, content in data.items():
                file = source / name
                file.parent.mkdir(parents=True, exist_ok=True)
                file.write_bytes(content)
                files.append({'path': name, 'sha256': 'sha256:' + hashlib.sha256(content).hexdigest(), 'size_bytes': len(content)})
            (source / 'provider-receipts.json').write_text(json.dumps({'schema_version': 1, 'files': files, 'provider_receipts': {'apple-container/darwin/arm64': {}, 'wslc/win32/x64': {}}}))
            first = provider.prepare(source, root / 'one')
            second = provider.prepare(source, root / 'two')
            self.assertEqual(first['lazy_archive_assets'], second['lazy_archive_assets'])
            metadata = json.loads((source / 'provider-receipts.json').read_text())
            metadata['provider_receipts']['apple-container/darwin/arm64']['executable_sha256'] = 'sha256:' + 'a' * 64
            (source / 'provider-receipts.json').write_text(json.dumps(metadata))
            reused = provider.prepare(source, root / 'reused', root / 'one')
            self.assertEqual(first['lazy_archive_assets'], reused['lazy_archive_assets'])
            self.assertEqual(reused['provider_receipts']['apple-container/darwin/arm64']['executable_sha256'], 'sha256:' + 'a' * 64)
            for item in reused['lazy_archive_assets']:
                self.assertEqual((root / 'one' / item['path']).read_bytes(), (root / 'reused' / item['path']).read_bytes())
            for name, record in first['provider_receipts'].items():
                selected = {item['path'] for item in record['lazy_assets']['files']}
                expected = {'runtime/providers/apple-container/darwin-arm64/container', 'runtime/images/init-linux-arm64.tar'} if name.startswith('apple') else {'runtime/providers/wslc/win32-x64/wslc.exe'}
                self.assertEqual(selected, expected)
                archive = next(item for item in first['lazy_archive_assets'] if item['id'] == 'provider-assets-' + name.replace('/', '-'))
                with tarfile.open(root / 'one' / archive['path'], 'r:gz') as transport:
                    self.assertEqual({item.name for item in transport}, expected)
                    for item in transport:
                        self.assertTrue(item.isfile())
                        self.assertFalse(item.pax_headers)
                        self.assertEqual((item.uid, item.gid, item.mtime), (0, 0, 0))
                        self.assertEqual(transport.extractfile(item).read(), data[item.name])
            (source / files[0]['path']).write_bytes(b'corrupt')
            with self.assertRaisesRegex(ValueError, 'frozen receipt'):
                provider.prepare(source, root / 'corrupt')

    def test_reuse_rejects_changed_inventory_and_self_consistent_corrupt_archive(self):
        import io
        for case in ['changed-inventory', 'corrupt-content']:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                root=Path(temporary);source=root/'source';name='runtime/providers/lima-nerdctl/darwin-x64/bin/limactl';file=source/name;file.parent.mkdir(parents=True);file.write_bytes(b'good')
                record={'schema_version':1,'files':[{'path':name,'sha256':'sha256:'+hashlib.sha256(b'good').hexdigest(),'size_bytes':4}],'provider_receipts':{'lima-nerdctl/darwin/x64':{}}}
                (source/'provider-receipts.json').write_text(json.dumps(record));old=provider.prepare(source,root/'old');asset=old['lazy_archive_assets'][0]
                if case=='changed-inventory':
                    file.write_bytes(b'new!');record['files'][0]['sha256']='sha256:'+hashlib.sha256(b'new!').hexdigest();(source/'provider-receipts.json').write_text(json.dumps(record))
                else:
                    archive=root/'old'/asset['path']
                    with tarfile.open(archive,'w:gz')as bundle:
                        header=tarfile.TarInfo(name);header.size=4;header.mode=0o444;header.mtime=0;bundle.addfile(header,io.BytesIO(b'evil'))
                    fingerprint='sha256:'+hashlib.sha256(archive.read_bytes()).hexdigest();size=archive.stat().st_size
                    asset.update(sha256=fingerprint,size_bytes=size);old['provider_receipts']['lima-nerdctl/darwin/x64']['lazy_assets'].update(sha256=fingerprint,size=size)
                    (root/'old/provider-receipts.json').write_text(json.dumps(old))
                with self.assertRaisesRegex(ValueError,'unchanged|member bytes'):
                    provider.prepare(source,root/'new',root/'old')
                if case=='changed-inventory':
                    refreshed=provider.prepare(source,root/'selective',root/'old',reuse_unchanged=True)
                    self.assertNotEqual(refreshed['lazy_archive_assets'][0]['sha256'],asset['sha256'])
                    with tarfile.open(root/'selective'/refreshed['lazy_archive_assets'][0]['path'],'r:gz')as bundle:self.assertEqual(bundle.extractfile(name).read(),b'new!')
                else:
                    with self.assertRaisesRegex(ValueError,'member bytes'):provider.prepare(source,root/'selective',root/'old',reuse_unchanged=True)


if __name__ == '__main__':
    unittest.main()
