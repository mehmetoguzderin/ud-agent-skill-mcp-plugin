"""Data-only uv vendoring and Windows header lookup contracts."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
import struct
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[3]
SPEC=importlib.util.spec_from_file_location('prepare_windows_uv',ROOT/'scripts/runtime/prepare-windows-uv.py')
BUILDER=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(BUILDER)


class WindowsUvInputs(unittest.TestCase):
    def test_vendor_keeps_exact_bytes_and_complete_checksum_map(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);archive=root/'crate.tar.gz'
            with tarfile.open(archive,'w:gz') as stream:
                for name,data in [('tiny-1.2/src/lib.rs',b'pub fn answer()->u8{42}\n'),('tiny-1.2/Cargo.toml',b'[package]\nname="tiny"\n')]:
                    row=tarfile.TarInfo(name);row.size=len(data);row.mode=0o644;stream.addfile(row,io.BytesIO(data))
            checksum=BUILDER.digest(archive);result=BUILDER.extract_crate(archive,root/'vendor','tiny','1.2',checksum)
            self.assertEqual(result['files'],2)
            self.assertEqual((root/'vendor/src/lib.rs').read_bytes(),b'pub fn answer()->u8{42}\n')
            manifest=json.loads((root/'vendor/.cargo-checksum.json').read_text())
            self.assertEqual(manifest['package'],checksum)
            self.assertEqual(manifest['files']['src/lib.rs'],hashlib.sha256(b'pub fn answer()->u8{42}\n').hexdigest())
            self.assertEqual(set(manifest['files']),{'src/lib.rs','Cargo.toml'})

    def test_vendor_rejects_foreign_traversal_links_and_duplicate_members(self):
        for names in [[('foreign-1/a',None)],[('tiny-1.2/../escape',None)],[('tiny-1.2/a','../outside')],[('tiny-1.2/a',None),('tiny-1.2/a',None)],[('tiny-1.2/.cargo-checksum.json',None)]]:
            with self.subTest(names=names),tempfile.TemporaryDirectory() as directory:
                root=Path(directory);archive=root/'bad.tar.gz'
                with tarfile.open(archive,'w:gz') as stream:
                    for name,link in names:
                        row=tarfile.TarInfo(name)
                        if link is not None:row.type=tarfile.SYMTYPE;row.linkname=link;stream.addfile(row)
                        else:row.size=1;stream.addfile(row,io.BytesIO(b'x'))
                with self.assertRaises(ValueError):BUILDER.extract_crate(archive,root/'vendor','tiny','1.2',BUILDER.digest(archive))
                self.assertFalse((root/'escape').exists())

    def sdk(self,root):
        for name in ['crt/include','sdk/include/ucrt','sdk/include/um','sdk/include/shared','sdk/include/winrt']:(root/name).mkdir(parents=True)

    def test_overlay_preserves_original_sdk_bytes_and_models_windows_lookup(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);sdk=root/'sdk';self.sdk(sdk);file=sdk/'sdk/include/um/Windows.h';file.write_bytes(b'original-header\r\n')
            result=BUILDER.header_overlay(sdk,root/'headers.json');overlay=json.loads((root/'headers.json').read_text())
            self.assertIs(overlay['case-sensitive'],False)
            self.assertEqual(result['headers'],[{'path':'sdk/include/um/Windows.h','sha256':hashlib.sha256(b'original-header\r\n').hexdigest(),'size_bytes':17}])
            self.assertEqual(file.read_bytes(),b'original-header\r\n')
            self.assertEqual(overlay['roots'][2]['contents'][0]['external-contents'],str(file.resolve()))
            self.assertEqual(result['sha256'],BUILDER.digest(root/'headers.json'))

    def test_overlay_rejects_foreign_resolution_without_requiring_symlink_privilege(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);sdk=root/'sdk';self.sdk(sdk);header=sdk/'sdk/include/um/Windows.h';header.write_bytes(b'one');foreign=root/'foreign.h';foreign.write_bytes(b'two');original=Path.resolve
            def resolve(file,*args,**kwargs):return original(foreign)if file==header else original(file,*args,**kwargs)
            with patch.object(Path,'resolve',resolve),self.assertRaisesRegex(ValueError,'escapes'):BUILDER.header_overlay(sdk,root/'headers.json')
            self.assertFalse((root/'headers.json').exists())

    def test_overlay_rejects_distinct_case_aliases_on_case_insensitive_hosts(self):
        # Model the directory listing explicitly so this policy runs on Windows
        # as well as case-sensitive development volumes, without requiring two
        # same-directory names that Windows cannot create.
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);sdk=root/'sdk';self.sdk(sdk);upper=sdk/'fixtures/one/Windows.h';lower=sdk/'fixtures/two/windows.h'
            for file,data in [(upper,b'one'),(lower,b'two')]:file.parent.mkdir(parents=True);file.write_bytes(data)
            original=Path.iterdir;um=sdk/'sdk/include/um'
            def listing(directory):return iter([upper,lower])if directory==um else original(directory)
            with patch.object(Path,'iterdir',listing),self.assertRaisesRegex(ValueError,'ambiguous'):BUILDER.header_overlay(sdk,root/'headers.json')
            self.assertFalse((root/'headers.json').exists())

    def test_independent_vendor_replay_rejects_modified_bytes_forged_manifest_and_extras(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);sources=root/'sources';sources.mkdir();output=root/'output';(output/'vendor').mkdir(parents=True);archive=sources/'tiny.tar.gz'
            with tarfile.open(archive,'w:gz') as stream:
                row=tarfile.TarInfo('tiny-1.2/src/lib.rs');row.size=8;stream.addfile(row,io.BytesIO(b'original'))
            checksum=BUILDER.digest(archive);(sources/'receipt.json').write_text(json.dumps({'files':[{'family':'cargo','name':'tiny','version':'1.2','sha256':checksum,'size_bytes':archive.stat().st_size,'path':'tiny.tar.gz'}]}))
            vendor=output/'vendor/tiny-1.2';dependency=BUILDER.extract_crate(archive,vendor,'tiny','1.2',checksum)
            (output/'source-receipt.json').write_text(json.dumps({'dependencies':[dependency],'source_receipts':{'dependencies':BUILDER.digest(sources/'receipt.json')}}))
            result=BUILDER.verify_vendor(output,sources);self.assertEqual(result['crates'],1);self.assertEqual(result['files'],1)
            source=vendor/'src/lib.rs';source.chmod(0o644);source.write_bytes(b'modified');manifest=vendor/'.cargo-checksum.json';manifest.write_text(json.dumps({'files':{'src/lib.rs':hashlib.sha256(b'modified').hexdigest()},'package':checksum},sort_keys=True,separators=(',',':'))+'\n')
            with self.assertRaisesRegex(ValueError,'bytes changed'):BUILDER.verify_vendor(output,sources)
            source.write_bytes(b'original');manifest.write_text(json.dumps({'files':{'src/lib.rs':hashlib.sha256(b'original').hexdigest()},'package':checksum},sort_keys=True,separators=(',',':'))+'\n');(vendor/'extra').write_bytes(b'foreign')
            with self.assertRaisesRegex(ValueError,'inventory is not closed'):BUILDER.verify_vendor(output,sources)

    def test_resource_tool_aliases_are_native_arm_only_and_never_replace_foreign_paths(self):
        # Mock only link creation so this admission policy also runs on Windows
        # without requiring Developer Mode or an elevation prompt.
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);tool=root/'llvm-mt';tool.write_bytes(b'\xcf\xfa\xed\xfe'+struct.pack('<I',0x0100000c)+b'native')
            with patch.object(Path,'symlink_to') as link:
                result=BUILDER.prepare_host_tools(root,{'mt.exe':tool});self.assertEqual(result['mt.exe']['execution_architecture'],'darwin-arm64');self.assertEqual(result['mt.exe']['sha256'],BUILDER.digest(tool));link.assert_called_once_with(tool.resolve())
            for data in [b'MZwindows',b'\xcf\xfa\xed\xfe'+struct.pack('<I',0x01000007),b'\xcf\xfa\xed\xfe']:
                tool.write_bytes(data)
                with self.assertRaisesRegex(ValueError,'native macOS ARM64'):BUILDER.prepare_host_tools(root,{'mt.exe':tool})
            tool.write_bytes(b'\xcf\xfa\xed\xfe'+struct.pack('<I',0x0100000c));(root/'tools/mt.exe').write_bytes(b'foreign')
            with self.assertRaisesRegex(ValueError,'alias changed'):BUILDER.prepare_host_tools(root,{'mt.exe':tool})
            with self.assertRaisesRegex(ValueError,'Unsupported'):BUILDER.prepare_host_tools(root,{'arbitrary.exe':tool})


if __name__=='__main__':unittest.main()
