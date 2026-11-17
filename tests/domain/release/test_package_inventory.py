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
import zipfile

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location("package_inventory", ROOT / "scripts/release/inspect-package.py")
inspector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inspector)


class PackageInventoryTests(unittest.TestCase):
    def test_original_native_archive_extracts_one_verified_platform_without_retained_tree(self):
        source = 'a' * 64
        lock = b'{}'; runtime = hashlib.sha256(lock).hexdigest()
        support = inspector._support.expected(ROOT, inspector._paths)
        files = {row['path']: (ROOT / row['path']).read_bytes() for row in support['files']}
        executable = b'\xcf\xfa\xed\xfe' + struct.pack('<I', 0x100000c) + bytes(64)
        catalog = [{'name': 'validation_report'}, {'name': 'custom_report'}]
        recipe = {'provider': 'conda-vc-runtime', 'platform': 'darwin/arm64'}
        files.update({'SKILL-SUPPORT.json': json.dumps(support).encode(), 'runtime/runtime.lock.json': lock,
                      'contracts/ud-interfaces.json': json.dumps(catalog).encode(),
                      'runtime/pack/native/darwin-arm64/perl/vendor-runtime.json': json.dumps(recipe).encode(),
                      'lib/coordinator.mjs': b'export {};', 'bin/ud-agent': executable, 'bin/ud-agent-guard': executable,
                      'runtime/node/bin/node': executable, 'RELEASE-CANDIDATE.md': b'candidate'})
        files['BUILD-RECEIPT.json'] = json.dumps({'schema_version': 1, 'product_version': '0.1.0-beta.1', 'kind': 'native', 'platform': 'darwin-arm64', 'source_tree_sha256': source, 'runtime_lock_sha256': runtime, 'qualification': 'preacceptance_candidate'}).encode()
        modes = {name: 0o755 if name in ('bin/ud-agent','bin/ud-agent-guard','runtime/node/bin/node') else 0o644 for name in files}
        files['PACKAGE-INVENTORY.json'] = json.dumps({'schema_version': 1, 'files': [{'path': name, 'sha256': hashlib.sha256(body).hexdigest(), 'size': len(body), 'executable': bool(modes[name] & 0o111)} for name, body in files.items()]}).encode()
        modes['PACKAGE-INVENTORY.json'] = 0o644
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for extension in ('tar.gz', 'mcpb'):
                archive = root/('original.'+extension)
                if extension == 'mcpb':
                    # MCPB requires a manifest, included in its exact inventory.
                    files['manifest.json'] = b'{"version":"0.1.0-beta.1"}'; modes['manifest.json'] = 0o644
                    files['PACKAGE-INVENTORY.json'] = json.dumps({'schema_version': 1, 'files': [{'path': name, 'sha256': hashlib.sha256(body).hexdigest(), 'size': len(body), 'executable': bool(modes[name] & 0o111)} for name, body in files.items() if name != 'PACKAGE-INVENTORY.json']}).encode()
                    with zipfile.ZipFile(archive, 'w') as target:
                        for name,body in files.items():
                            item=zipfile.ZipInfo(name); item.external_attr=(0o100000 | modes[name]) << 16; target.writestr(item,body)
                else:
                    with tarfile.open(archive, 'w:gz') as target:
                        for name,body in files.items():
                            item=tarfile.TarInfo(name); item.size=len(body); item.mode=modes[name]; target.addfile(item,io.BytesIO(body))
                body=archive.read_bytes(); expected=hashlib.sha256(body).hexdigest(); output=root/('installed-'+extension)
                inspected=inspector.inspect(archive,'native','darwin-arm64',source,runtime,True,contracts=True,details=True)
                contract=inspected['contracts']
                self.assertEqual(contract['metadata']['contracts/ud-interfaces.json'],catalog)
                self.assertEqual(contract['metadata']['runtime/pack/native/darwin-arm64/perl/vendor-runtime.json'],recipe)
                self.assertEqual(contract['members']['contracts/ud-interfaces.json']['sha256'],hashlib.sha256(files['contracts/ud-interfaces.json']).hexdigest())
                self.assertTrue(contract['release_candidate']);self.assertFalse(contract['unaccepted'])
                kwargs={'archive_sha256':expected,'archive_size':len(body),'max_output_bytes':sum(map(len,files.values())),'require_candidate':True}
                result=inspector.extract_verified(archive,output,'native','darwin-arm64',source,runtime,**kwargs)
                self.assertEqual(result['qualification'],'verified-original-package-extraction'); self.assertEqual((output/'bin/ud-agent').read_bytes(),executable)
                self.assertTrue(inspected['members']['bin/ud-agent']['executable'])
                if os.name == 'nt': self.assertTrue((output/'bin/ud-agent').stat().st_mode & 0o400)
                else: self.assertTrue((output/'bin/ud-agent').stat().st_mode & 0o111)
                with self.assertRaisesRegex(ValueError,'new private destination'):inspector.extract_verified(archive,output,'native','darwin-arm64',source,runtime,**kwargs)
                with self.assertRaisesRegex(ValueError,'output budget'):inspector.extract_verified(archive,root/('small-'+extension),'native','darwin-arm64',source,runtime,**{**kwargs,'max_output_bytes':1})
                self.assertFalse((root/('small-'+extension)).exists())
                with self.assertRaisesRegex(ValueError,'exact receipt'):inspector.extract_verified(archive,root/('changed-'+extension),'native','darwin-arm64',source,runtime,**{**kwargs,'archive_sha256':'f'*64})
                self.assertFalse((root/('changed-'+extension)).exists())

    def test_source_archive_uses_frozen_unicode16_collision_and_boundary_policy(self):
        with tempfile.TemporaryDirectory()as temporary:
            filename=Path(temporary)/'source.tar.gz'
            def write(names):
                files={name:b'bytes\n'for name in names};rows=[{'path':name,'sha256':hashlib.sha256(body).hexdigest(),'size':len(body),'executable':False}for name,body in sorted(files.items())]
                fingerprint=hashlib.sha256(json.dumps(rows,ensure_ascii=False,separators=(',',':')).encode()).hexdigest();files['SOURCE-MANIFEST.json']=json.dumps({'algorithm':'sha256-json-file-inventory-v1','sha256':fingerprint,'files':rows}).encode()
                with tarfile.open(filename,'w:gz')as target:
                    for name,body in files.items():
                        item=tarfile.TarInfo(name);item.size=len(body);item.mode=0o644;target.addfile(item,io.BytesIO(body))
                return fingerprint
            for names in [('Straße.txt','STRASSE.txt'),('Σ.txt','ς.txt'),('é.txt','e\u0301.txt')]:
                fingerprint=write(names)
                with self.subTest(names=names),self.assertRaisesRegex(ValueError,'duplicate'):inspector.inspect(filename,'source','all',fingerprint,'b'*64)
            mark=chr(0x1acf);fingerprint=write(['A\u0315'+mark+'.txt','A'+mark+'\u0315.txt'])
            self.assertTrue(inspector.inspect(filename,'source','all',fingerprint,'b'*64)['verified'])
            for name in ['CON.txt','.git/config','trailing.','space ','bad\nname']:
                fingerprint=write([name])
                with self.subTest(name=name),self.assertRaisesRegex(ValueError,'unsafe'):inspector.inspect(filename,'source','all',fingerprint,'b'*64)

    def test_archive_inventory_binds_every_byte_and_build_subject(self):
        source, runtime = "a" * 64, "b" * 64
        support = inspector._support.expected(ROOT, inspector._paths)
        files = {row['path']: (ROOT / row['path']).read_bytes() for row in support['files']}
        files['SKILL-SUPPORT.json'] = json.dumps(support).encode()
        files['BUILD-RECEIPT.json'] = json.dumps({"schema_version": 1, "product_version": "0.1.0-beta.1", "kind": "skills", "platform": "all", "source_tree_sha256": source, "runtime_lock_sha256": runtime}).encode()
        inventory = {"schema_version": 1, "files": [{"path": name, "sha256": hashlib.sha256(data).hexdigest(), "size": len(data), "executable": False} for name, data in files.items()]}
        files["PACKAGE-INVENTORY.json"] = json.dumps(inventory).encode()
        with tempfile.TemporaryDirectory() as temporary:
            filename = Path(temporary) / "skills.tar.gz"

            def write(extra=None):
                with tarfile.open(filename, "w:gz") as archive:
                    for name, content in {**files, **(extra or {})}.items():
                        member = tarfile.TarInfo(name); member.size = len(content); member.mode = 0o644
                        archive.addfile(member, io.BytesIO(content))

            write()
            self.assertEqual(inspector.inspect(filename, "skills", "all", source, runtime)["files"], len(files))
            with self.assertRaisesRegex(ValueError, "subjects"):
                inspector.inspect(filename, "skills", "all", "c" * 64, runtime)
            write({"skills/ud-validate/SKILL.md": b"tampered"})
            with self.assertRaisesRegex(ValueError, "inventory"):
                inspector.inspect(filename, "skills", "all", source, runtime)
            write({"../escape": b"hostile"})
            with self.assertRaisesRegex(ValueError, "unsafe"):
                inspector.inspect(filename, "skills", "all", source, runtime)

    def test_self_consistent_archive_cannot_omit_required_skill_support(self):
        source, runtime = 'a' * 64, 'b' * 64
        support = inspector._support.expected(ROOT, inspector._paths)
        with tempfile.TemporaryDirectory() as temporary:
            file = Path(temporary) / 'skills.tar.gz'
            for mode in ('missing', 'changed', 'added'):
                files = {row['path']: (ROOT / row['path']).read_bytes() for row in support['files']}
                resource = next(name for name in files if '/references/' in name)
                if mode == 'missing': del files[resource]
                elif mode == 'changed': files[resource] += b'changed'
                else: files['skills/ud-validate/unknown.md'] = b'undeclared'
                files['SKILL-SUPPORT.json'] = json.dumps(support).encode()
                files['BUILD-RECEIPT.json'] = json.dumps({'schema_version': 1, 'product_version': '0.1.0-beta.1', 'kind': 'skills', 'platform': 'all', 'source_tree_sha256': source, 'runtime_lock_sha256': runtime}).encode()
                files['PACKAGE-INVENTORY.json'] = json.dumps({'schema_version': 1, 'files': [{'path': name, 'sha256': hashlib.sha256(body).hexdigest(), 'size': len(body), 'executable': False} for name, body in files.items()]}).encode()
                with tarfile.open(file, 'w:gz') as archive:
                    for name, body in files.items():
                        entry = tarfile.TarInfo(name); entry.size = len(body); entry.mode = 0o644; archive.addfile(entry, io.BytesIO(body))
                with self.subTest(mode=mode), self.assertRaisesRegex(ValueError, 'skill support'):
                    inspector.inspect(file, 'skills', 'all', source, runtime)

    def test_native_headers_identify_architecture_without_execution(self):
        elf = bytearray(64); elf[:6] = b"\x7fELF\x02\x01"; struct.pack_into("<H", elf, 18, 183)
        self.assertEqual(inspector.architecture(elf), "linux-arm64")
        struct.pack_into("<H", elf, 18, 62)
        self.assertEqual(inspector.architecture(elf), "linux-x64")
        mach = b"\xcf\xfa\xed\xfe" + struct.pack("<I", 0x100000C)
        self.assertEqual(inspector.architecture(mach), "darwin-arm64")
        pe = bytearray(128); pe[:2] = b"MZ"; struct.pack_into("<I", pe, 60, 64); pe[64:68] = b"PE\0\0"; struct.pack_into("<H", pe, 68, 0x8664)
        self.assertEqual(inspector.architecture(pe), "win32-x64")
        self.assertEqual(inspector.architecture(b"wrong"), "unknown")


if __name__ == "__main__":
    unittest.main()
