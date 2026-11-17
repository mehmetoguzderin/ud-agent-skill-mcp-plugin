import importlib.util
import hashlib
import io
import os
from pathlib import Path
import struct
import tarfile
import tempfile
import time
import unittest

ROOT=Path(__file__).resolve().parents[3]
spec=importlib.util.spec_from_file_location('verifier_inventory',ROOT/'scripts/release/prepare-verifier-runtime.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)


class VerifierNativeInventoryTests(unittest.TestCase):
    def thin(self,cpu):
        body=bytearray(32);body[:4]=b'\xcf\xfa\xed\xfe';struct.pack_into('<I',body,4,cpu);return bytes(body)

    def test_entrypoint_cpu_is_read_from_actual_thin_or_fat_headers(self):
        arm=self.thin(0x100000c);intel=self.thin(0x1000007)
        self.assertEqual(module.native_slices(arm),[('darwin-arm64',arm)])
        header=b'\xca\xfe\xba\xbe'+struct.pack('>I',2)+struct.pack('>IIIII',0x100000c,0,48,32,0)+struct.pack('>IIIII',0x1000007,0,80,32,0)
        self.assertEqual([row[0]for row in module.native_slices(header+arm+intel)],['darwin-arm64','darwin-x64'])
        for body in (arm[:8],self.thin(123),header+intel+arm,header+arm,b'\xfe\xed\xfa\xce'+bytes(32)):
            with self.subTest(body=body),self.assertRaises(ValueError):module.native_slices(body)

    def test_native_dependency_commands_require_bounded_strings_and_sizes(self):
        self.assertEqual(module.macho_dependencies(self.thin(0x100000c)),([],[]))
        body=bytearray(self.thin(0x100000c));struct.pack_into('<II',body,16,1,12);body.extend(struct.pack('<III',12,12,99))
        with self.assertRaisesRegex(ValueError,'dependency string'):module.macho_dependencies(body)

    def test_archive_identity_and_source_reads_share_one_held_descriptor(self):
        with tempfile.TemporaryDirectory()as temporary:
            root=Path(temporary);file=root/'original.tar.gz'
            with tarfile.open(file,'w:gz')as archive:
                row=tarfile.TarInfo('python/original.py');row.size=8;archive.addfile(row,io.BytesIO(b'original'))
            asset={'size':file.stat().st_size,'digest':'sha256:'+hashlib.sha256(file.read_bytes()).hexdigest()}
            if os.name=='nt':
                with module.verified_tar(file,asset)as archive:
                    with self.assertRaises(PermissionError)as refused:file.rename(root/'held-input')
                    self.assertEqual(refused.exception.winerror,32)
                    self.assertEqual(archive.extractfile('python/original.py').read(),b'original')
                self.assertFalse((root/'held-input').exists())
                file.write_bytes(b'foreign replacement')
            else:
                with self.assertRaisesRegex(ValueError,'changed during same-FD'),module.verified_tar(file,asset)as archive:
                    # Kernel ctime advances in coarse ticks; let one pass so
                    # the rename is observable on fast hosts.
                    time.sleep(0.05)
                    file.rename(root/'held-input');file.write_bytes(b'foreign replacement')
                    self.assertEqual(archive.extractfile('python/original.py').read(),b'original')
            with self.assertRaisesRegex(ValueError,'frozen publisher asset'):
                with module.verified_tar(file,asset):pass


if __name__=='__main__':unittest.main()
