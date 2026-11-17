import base64
import hashlib
import importlib.util
import io
from pathlib import Path
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location('pip_components', ROOT / 'scripts/release/bind-pip-components.py')
binding = importlib.util.module_from_spec(spec); spec.loader.exec_module(binding)


class PackagingComponentTests(unittest.TestCase):
    def test_record_must_cover_every_actual_member_and_exact_bytes(self):
        fingerprint = hashlib.sha256(b'original').hexdigest(); entries = {'pip/source.py': {'sha256':fingerprint,'size_bytes':8}, 'pip.dist-info/RECORD': {'sha256':'a'*64,'size_bytes':0}}
        digest = base64.urlsafe_b64encode(bytes.fromhex(fingerprint)).decode().rstrip('='); record = f'pip/source.py,sha256={digest},8\npip.dist-info/RECORD,,\n'.encode()
        binding.verify_record(entries,record)
        for broken in (record.replace(b',8\n',b',9\n'),record.splitlines()[0]+b'\n',record+record.splitlines()[0]+b'\n',record.replace(b'sha256=',b'md5=')):
            with self.assertRaises(ValueError):binding.verify_record(entries,broken)

    def test_original_source_notices_are_bound_to_the_held_archive(self):
        with tempfile.TemporaryDirectory()as temporary:
            root=Path(temporary);file=root/'original.tar.gz'
            with tarfile.open(file,'w:gz')as archive:
                for name,body in [('fixture/LICENSE.txt',b'Original BSD-style terms\n'),('fixture/PC/launcher.c',b'/* source and original binary notice */\n')]:
                    row=tarfile.TarInfo(name);row.size=len(body);archive.addfile(row,io.BytesIO(body))
            receipt={'path':file.name,'sha256':hashlib.sha256(file.read_bytes()).hexdigest(),'size_bytes':file.stat().st_size};source,records,bodies,notices=binding.tar_members(root,receipt,'fixture/')
            self.assertEqual(notices[0]['source_archive_sha256'],source['sha256']);self.assertEqual(bodies['PC/launcher.c'],b'/* source and original binary notice */\n');self.assertIn('LICENSE.txt',records)
            file.write_bytes(b'changed')
            with self.assertRaises(ValueError):binding.tar_members(root,receipt,'fixture/')

    def test_source_archives_cannot_substitute_links_duplicate_or_foreign_members(self):
        for mode in ('link','duplicate','foreign'):
            with self.subTest(mode=mode),tempfile.TemporaryDirectory()as temporary:
                root=Path(temporary);file=root/'source.tar'
                with tarfile.open(file,'w:')as archive:
                    for index in range(2 if mode=='duplicate'else 1):
                        row=tarfile.TarInfo('outside/LICENSE.txt'if mode=='foreign'else'fixture/LICENSE.txt')
                        if mode=='link':row.type=tarfile.SYMTYPE;row.linkname='/outside';archive.addfile(row)
                        else:row.size=1;archive.addfile(row,io.BytesIO(b'x'))
                receipt={'path':file.name,'sha256':hashlib.sha256(file.read_bytes()).hexdigest(),'size_bytes':file.stat().st_size}
                with self.assertRaises(ValueError):binding.tar_members(root,receipt,'fixture/')


if __name__ == '__main__': unittest.main()
