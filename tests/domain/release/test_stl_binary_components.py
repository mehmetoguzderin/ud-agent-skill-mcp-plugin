import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location('stl_components', ROOT / 'scripts/release/stl-binary-components.py')
stl = importlib.util.module_from_spec(spec); spec.loader.exec_module(stl)


def checksum(name, fingerprint, kind='SHA256'):
    chunks = [fingerprint[index:index + 8].upper() for index in range(0, len(fingerprint), 8)]
    return '    FileChecksum {\n      Filename: ' + name + ' (0x1)\n      ChecksumSize: 0x20\n      ChecksumKind: ' + kind + ' (0x3)\n      ChecksumBytes (\n        0000: ' + ' '.join(chunks[:4]) + ' |original source|\n        0010: ' + ' '.join(chunks[4:]) + ' |original source|\n      )\n    }'


class StlComponentTests(unittest.TestCase):
    def test_original_checksum_inventory_rejects_conflicts_missing_and_unsupported_records(self):
        original = checksum(r'D:\source\github\stl\src\actual.cpp', 'a' * 64)
        self.assertEqual(stl.checksums(original)[0]['sha256'], 'a' * 64)
        self.assertEqual(len(stl.checksums(original + '\n' + original)), 1)
        for value in ('', original.replace('ChecksumSize: 0x20', 'ChecksumSize: 0x10'), original.replace('SHA256', 'MD5'), original.replace('AAAAAAAA', 'ZZZZZZZZ'), original + '\n' + checksum(r'D:\source\github\stl\src\actual.cpp', 'b' * 64)):
            with self.subTest(value=value), self.assertRaises(ValueError): stl.checksums(value)

    def test_only_exact_stl_member_checksums_join_and_external_headers_remain_separate(self):
        rows = [{'compiler_path': r'D:\source\github\stl\src\actual.cpp', 'sha256': 'a' * 64}, {'compiler_path': r'D:\source\ExternalAPIs\SDK\windows.h', 'sha256': 'b' * 64}]
        members = {'stl/src/actual.cpp': {'member_path': 'STL-fixed/stl/src/actual.cpp', 'sha256': 'a' * 64, 'size_bytes': 14}}
        joined, external, missing = stl.join(rows, members)
        self.assertEqual(len(joined), 1); self.assertEqual(len(external), 1); self.assertFalse(external[0]['redistributed_source_bytes']); self.assertEqual(missing, [])
        for changed in ({}, {'stl/src/actual.cpp': {**members['stl/src/actual.cpp'], 'sha256': 'f' * 64}}):
            joined, external, missing = stl.join(rows, changed); self.assertEqual(joined, []); self.assertEqual(len(missing), 2)

    def test_original_source_license_is_byte_preserved_and_duplicate_members_fail(self):
        with tempfile.TemporaryDirectory() as temporary:
            archive = Path(temporary) / 'source.tar.gz'; terms = (ROOT / 'licenses/vendor/Microsoft-STL-14.51/LICENSE.txt').read_bytes()
            def make(duplicate=False):
                with tarfile.open(archive, 'w:gz') as target:
                    for name, body in [('STL-fixed/LICENSE.txt', terms), ('STL-fixed/stl/src/actual.cpp', b'original source\n')] + ([('STL-fixed/stl/src/actual.cpp', b'forged duplicate\n')] if duplicate else []):
                        member = tarfile.TarInfo(name); member.size = len(body); target.addfile(member, io.BytesIO(body))
                return {'source_root': 'STL-fixed', 'archive': {'sha256': stl.sha(archive), 'size_bytes': archive.stat().st_size}}
            contract = make(); members, source, license_record = stl.source_members(archive, contract); self.assertEqual(license_record['sha256'], hashlib.sha256(terms).hexdigest()); self.assertIn('stl/src/actual.cpp', members)
            with self.assertRaisesRegex(ValueError, 'duplicate'): stl.source_members(archive, make(True))
            contract = make(); archive.write_bytes(b'changed original archive')
            with self.assertRaisesRegex(ValueError, 'size or kind|hash or identity'): stl.source_members(archive, contract)


if __name__ == '__main__': unittest.main()
