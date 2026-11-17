import importlib.util
import hashlib
import copy
import io
import json
import lzma
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location('lima_assets', ROOT / 'scripts/runtime/prepare-lima-assets.py')
lima = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lima)


def archive(file, entries):
    with tarfile.open(file, 'w:gz') as target:
        for name, data, kind in entries:
            item = tarfile.TarInfo(name)
            item.mode = 0o755
            if kind == 'link':
                item.type, item.linkname = tarfile.SYMTYPE, '../../outside'
                target.addfile(item)
            else:
                item.size = len(data)
                target.addfile(item, io.BytesIO(data))


class LimaAssetsTests(unittest.TestCase):
    def test_namespace_helpers_are_bound_to_exact_image_bytes_for_both_architectures(self):
        frozen = json.loads((ROOT / 'runtime/lima-guest.lock.json').read_text())
        expected = {'arm64': ('b55c259966772a75df59c0dd42bdebe67886b89baf403488dc3ef7e11ff7a024', 68272), 'amd64': ('763259c01dca596ed903f1dc430599a938396294723165d0b0fdfdcc15d92aea', 35544)}
        for architecture, (digest, size) in expected.items():
            helper = lima.guest_namespace_helper(frozen, architecture)
            self.assertEqual(helper, {'path': '/usr/bin/nsenter', 'sha256': 'sha256:' + digest, 'size_bytes': size, 'image_sha256': frozen['images'][architecture]['sha256']})
            for fields in ({'path': '/tmp/project-nsenter'}, {'sha256': 'corrupt'}, {'image_sha256': 'sha256:' + '0' * 64}, {'size_bytes': 0}, {'size_bytes': True}):
                changed = copy.deepcopy(frozen)
                changed['images'][architecture]['executables']['nsenter'].update(fields)
                with self.assertRaisesRegex(ValueError, 'exact frozen guest image'):
                    lima.guest_namespace_helper(changed, architecture)

    def test_locally_derived_replacements_are_source_bound_and_keep_unmodified_components(self):
        with tempfile.TemporaryDirectory()as temporary:
            root=Path(temporary);derived=root/'derived';derived.mkdir();records={}
            for architecture,machine in [('arm64',183),('amd64',62)]:
                folder=derived/architecture;folder.mkdir();selected={}
                for name in('runc','containerd','containerd-shim-runc-v2','ctr'):
                    body=bytearray(64);body[:6]=b'\x7fELF\x02\x01';body[18:20]=machine.to_bytes(2,'little');body.extend((architecture+name).encode());file=folder/name;file.write_bytes(body)
                    selected['bin/'+name]={'path':architecture+'/'+name,'sha256':hashlib.sha256(body).hexdigest(),'size_bytes':len(body)}
                records[architecture]=selected
            manifest={'schema_version':1,'qualification':'source-closed-local-provider-binary-derivation-not-upstream-signature','versions':{'runc':'1.5.2','containerd':'2.4.2'},'binaries':records,'runc_derivation':{'commit':'29dd3dc2b13b4123162e5fe132504bb4b15569f1','version':'1.5.2','status':'cross-built','binaries':{arch:items['bin/runc']for arch,items in records.items()}},'containerd_derivation':{'commit':'b7a25261e029d68978bbf290df0a62fc819b3c51','status':'cross-built','cgo':False,'binaries':{arch:{name[4:]:item for name,item in items.items()if name!='bin/runc'}for arch,items in records.items()}}}
            manifest=json.loads(json.dumps(manifest))
            file=derived/'derived-runtimes.json';file.write_text(json.dumps(manifest))
            selected,proof=lima.derived_members(derived,'arm64');self.assertEqual(set(selected),{'bin/runc','bin/containerd','bin/containerd-shim-runc-v2','bin/ctr'})
            self.assertEqual(selected['bin/runc'][0],(derived/'arm64/runc').read_bytes());self.assertEqual(proof,manifest)
            original=bytearray(64);original[:6]=b'\x7fELF\x02\x01';original[18:20]=(183).to_bytes(2,'little')
            source=root/'original.tar.gz';archive(source,[(name,bytes(original)if name.startswith('bin/')and name not in('bin/containerd-rootless.sh','bin/containerd-rootless-setuptool.sh')else b'original script/notice','')for name in lima.GUEST_FILES])
            merged=lima.guest_archive(source,root/'derived.tar.gz','arm64',derived)
            for name in('bin/runc','bin/containerd','bin/containerd-shim-runc-v2','bin/ctr'):self.assertEqual(merged[name][0],selected[name][0])
            for name in('bin/nerdctl','bin/rootlesskit','bin/rootlessctl'):self.assertEqual(merged[name][0],bytes(original))
            for field,value in [('qualification','upstream-signed'),('versions',{'runc':'obsolete','containerd':'2.4.2'}),('binaries',{'arm64':{}})]:
                changed=copy.deepcopy(manifest);changed[field]=value;file.write_text(json.dumps(changed))
                with self.subTest(field=field),self.assertRaises(ValueError):lima.derived_members(derived,'arm64')
            changed=copy.deepcopy(manifest);changed['binaries']['arm64']['bin/runc']['sha256']='0'*64;file.write_text(json.dumps(changed))
            with self.assertRaisesRegex(ValueError,'build receipt'):lima.derived_members(derived,'arm64')
            file.write_text(json.dumps(manifest));(derived/'arm64/runc').write_bytes(b'corrupt')
            with self.assertRaisesRegex(ValueError,'identity or size|digest'):lima.derived_members(derived,'arm64')

    def test_hostile_archives_never_materialize_selected_links_or_duplicate_paths(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for entries in [[('../escape', b'x', '')], [('bin/runc', b'', 'link')], [('bin/runc', b'one', ''), ('bin/runc', b'two', '')]]:
                source = root / 'input.tar.gz'
                archive(source, entries)
                with self.assertRaises(ValueError):
                    lima.read_members(source, ['bin/runc'])
            self.assertFalse((root / 'outside').exists())

    def test_closed_guest_archive_checks_each_elf_and_discards_unselected_services(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            elf = bytearray(64)
            elf[:6], elf[18:20] = b'\x7fELF\x02\x01', (183).to_bytes(2, 'little')
            binaries={'bin/nerdctl','bin/containerd','bin/containerd-shim-runc-v2','bin/runc','bin/rootlesskit','bin/rootlessctl','bin/ctr'}
            entries = [(name, bytes(elf) if name in binaries else b'upstream script or notice', '') for name in lima.GUEST_FILES]
            entries.append(('bin/buildkitd', b'not shipped', ''))
            entries.append(('bin/buildkit-cni-bridge', b'', 'link'))
            archive(root / 'full.tar.gz', entries)
            result = lima.guest_archive(root / 'full.tar.gz', root / 'minimal.tar.gz', 'arm64')
            self.assertEqual(set(result), set(lima.GUEST_FILES))
            self.assertIn('bin/ctr',result)
            with tarfile.open(root / 'minimal.tar.gz') as bundle:
                self.assertEqual(set(bundle.getnames()), set(lima.GUEST_FILES))
                self.assertTrue(all(item.isfile() for item in bundle))
            with self.assertRaisesRegex(ValueError, 'ELF architecture'):
                lima.guest_archive(root / 'full.tar.gz', root / 'wrong.tar.gz', 'amd64')
            other=bytearray(elf);other[18:20]=(62).to_bytes(2,'little')
            archive(root/'bad-ctr.tar.gz',[(name,bytes(other)if name=='bin/ctr'else data,kind)for name,data,kind in entries])
            with self.assertRaisesRegex(ValueError,'ELF architecture'):
                lima.guest_archive(root/'bad-ctr.tar.gz',root/'bad-ctr-result.tar.gz','arm64')

    def test_both_architecture_dependency_scripts_pin_packages_and_only_one_rootless_service(self):
        frozen = json.loads((ROOT / 'runtime/lima-guest.lock.json').read_text())
        for architecture in ('arm64', 'amd64'):
            with self.subTest(architecture=architecture):
                package = frozen['packages'][architecture][0]
                script = lima.dependency_script(frozen, architecture, [(package, b'independent payload')]).decode()
                self.assertIn(f'dpkg --print-architecture)" = {architecture}', script)
                self.assertIn('aW5kZXBlbmRlbnQgcGF5bG9hZA==', script)
                self.assertIn(package['sha256'][7:], script)
                self.assertIn('CONTAINERD_ROOTLESS_ROOTLESSKIT_NET=none', script)
                self.assertIn('test -u /usr/bin/newuidmap', script)
                self.assertEqual(script.count('\nExecStart='), 1)
                self.assertNotIn('apt-get', script)
                self.assertNotIn('curl ', script)
                self.assertNotIn('buildkit.service', script)
        changed = {**frozen, 'guest': {**frozen['guest'], 'network': 'host'}}
        with self.assertRaisesRegex(ValueError, 'guest policy'):
            lima.dependency_script(changed, 'arm64', [])

    def test_metadata_and_package_authentication_bind_the_complete_signed_definition(self):
        with tempfile.TemporaryDirectory() as temporary:
            cache = Path(temporary)
            signer = '1234567890ABCDEF' * 2 + '12345678'
            packages = []
            paragraphs = []
            for name in ('libsubid5', 'uidmap'):
                file = f'{name}_1.0_arm64.deb'
                body = name.encode()
                (cache / file).write_bytes(body)
                item = {'name': name, 'version': '1.0', 'filename': file, 'sha256': lima.sha(body), 'size_bytes': len(body), 'depends': 'libc6 (>= 2.38)'}
                packages.append(item)
                paragraphs.append('\n'.join(f'{key}: {value}' for key, value in {'Package': name, 'Version': '1.0', 'Architecture': 'arm64', 'SHA256': item['sha256'][7:], 'Size': len(body), 'Filename': f'pool/main/s/shadow/{file}', 'Depends': item['depends']}.items()))
            compressed = lzma.compress(('\n\n'.join(paragraphs)).encode())
            (cache / 'Packages-arm64.xz').write_bytes(compressed)
            release = f' {lima.sha(compressed)[7:]} {len(compressed)} main/binary-arm64/Packages.xz\n'.encode()
            (cache / 'InRelease').write_bytes(release)
            (cache / 'ubuntu-archive-keyring.gpg').write_bytes(b'fixture keyring')
            auth = {'release_sha256': lima.sha(release), 'keyring_sha256': lima.sha(b'fixture keyring'), 'signer_fingerprint': signer, 'indexes': {'arm64': {'sha256': lima.sha(compressed), 'size_bytes': len(compressed)}}}
            lock = {'package_authentication': auth, 'packages': {'arm64': packages}}
            status = subprocess.CompletedProcess([], 0, stdout=f'[GNUPG:] VALIDSIG {signer} timestamp\n'.encode(), stderr=b'')
            with patch.object(lima.subprocess, 'run', return_value=status) as run:
                result = lima.authenticated_packages(cache, lock, 'arm64', Path('/fixture/gpgv'))
                self.assertEqual([item['name'] for item, _ in result], ['libsubid5', 'uidmap'])
                self.assertEqual(run.call_args.kwargs['timeout'], 30)
                self.assertTrue(run.call_args.kwargs['check'])
                bad = {**lock, 'packages': {'arm64': [{**packages[0], 'version': '1.1'}, packages[1]]}}
                with self.assertRaisesRegex(ValueError, 'signed package metadata'):
                    lima.authenticated_packages(cache, bad, 'arm64', Path('/fixture/gpgv'))
            with patch.object(lima.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, stdout=b'[GNUPG:] VALIDSIG OTHER timestamp\n')):
                with self.assertRaisesRegex(ValueError, 'signer differs'):
                    lima.authenticated_packages(cache, lock, 'arm64', Path('/fixture/gpgv'))
            (cache / packages[0]['filename']).write_bytes(b'corrupt')
            with patch.object(lima.subprocess, 'run', return_value=status):
                with self.assertRaisesRegex(ValueError, 'identity or size|digest differs'):
                    lima.authenticated_packages(cache, lock, 'arm64', Path('/fixture/gpgv'))

    def test_missing_or_modified_input_never_admits_a_usable_pack(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            file = root / 'asset'
            file.write_bytes(b'original')
            self.assertEqual(lima.verified(file, lima.sha(b'original'), 8), file)
            with self.assertRaisesRegex(ValueError, 'digest differs'):
                lima.verified(file, lima.sha(b'changed!'), 8)
            with self.assertRaisesRegex(ValueError, 'identity or size'):
                lima.verified(file, lima.sha(b'original'), 7)
            with self.assertRaisesRegex(ValueError, 'explicit supported architecture'):
                lima.prepare(root, root, root / 'nested', 'arm64', file, file, {}, {})


if __name__ == '__main__':
    unittest.main()
