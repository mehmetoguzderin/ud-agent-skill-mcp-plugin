"""Source equality is evidence; it is never source-duty acceptance."""
import copy
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location('windows_perl_source_checksums', ROOT / 'scripts/release/windows-perl-source-checksums.py')
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)


class WindowsPerlSourceChecksums(unittest.TestCase):
    def fixture(self):
        return {'records': [{'platform': 'win32/arm64', 'binaries': [
            {'origin': 'supplier', 'path': 'bin/perl.exe', 'runtime_compilands': [
                {'id': 1, 'object': 'startup.obj', 'contributions': [{'file_bytes': 4}],
                 'source_files': [{'path': r'C:\src\startup.c', 'algorithm': 'sha256', 'checksum': 'a' * 64},
                                  {'path': r'C:\sdk\header.h', 'algorithm': 'sha256', 'checksum': 'b' * 64}]},
                {'id': 2, 'object': 'Import:kernel32.dll', 'contributions': [{'file_bytes': 4}],
                 'source_files': [{'path': 'excluded.h', 'algorithm': 'sha256', 'checksum': 'c' * 64}]},
                {'id': 3, 'object': 'unlinked.obj', 'contributions': [],
                 'source_files': [{'path': 'unlinked.h', 'algorithm': 'sha256', 'checksum': 'd' * 64}]},
            ]}, {'origin': 'authored-reproduced-XS', 'path': 'authored.dll'}]}]}

    def test_exact_checksum_and_basename_are_both_required(self):
        expected = M.expected_sources(self.fixture(), lambda value: value)
        actual = M.match_sources(expected, [('startup.c', 'a' * 64, 'local/startup.c'),
                                            ('header.h', '0' * 64, 'local/wrong.h'),
                                            ('other.h', 'b' * 64, 'local/other.h')])
        self.assertEqual([row['name'] for row in actual], ['header.h', 'startup.c'])
        self.assertEqual(actual[0]['status'], 'no-match-in-scanned-local-includes')
        self.assertEqual(actual[1]['local_matches'], ['local/startup.c'])
        self.assertEqual(actual[1]['contributors'], [{'platform': 'win32/arm64', 'binary_path': 'bin/perl.exe', 'module_id': 1}])

    def test_invalid_checksum_is_rejected(self):
        fixture = copy.deepcopy(self.fixture())
        fixture['records'][0]['binaries'][0]['runtime_compilands'][0]['source_files'][0]['checksum'] = 'abc'
        with self.assertRaises(ValueError):
            M.expected_sources(fixture, lambda value: value)


if __name__ == '__main__':
    unittest.main()
