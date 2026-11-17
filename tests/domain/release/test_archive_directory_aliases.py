"""Directory spelling aliases must not hide real package file conflicts."""
import hashlib
import importlib.util
import json
from types import SimpleNamespace
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[3]


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts/release' / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


writer = load('archive_directory_alias_writer', 'archive-dev.py')
inspector = load('archive_directory_alias_inspector', 'inspect-package.py')


def admit(entries):
    seen = {}
    for name, directory in entries:
        writer._record_path(seen, name, directory)


class ArchiveDirectoryAliases(unittest.TestCase):
    def test_windows_archive_modes_omit_python_extension_bits_to_match_libuv(self):
        file = SimpleNamespace(stat=lambda: SimpleNamespace(st_mode=0o100755))
        with patch.object(writer, 'os', SimpleNamespace(name='nt')):
            self.assertFalse(writer.executable(file))
        with patch.object(writer, 'os', SimpleNamespace(name='posix')):
            self.assertTrue(writer.executable(file))
            self.assertFalse(writer.executable(SimpleNamespace(stat=lambda: SimpleNamespace(st_mode=0o100644))))

    def test_disjoint_directory_aliases_in_both_orders(self):
        entries = [('perl/Pod', True), ('perl/pod', True), ('perl/Pod/Usage.pm', False), ('perl/pod/perl.pod', False)]
        admit(entries)
        admit(list(reversed(entries)))

    def test_full_file_casefold_collisions_in_both_orders(self):
        for paths in [('perl/Pod/Usage.pm', 'perl/pod/usage.pm'), ('perl/Straße.pm', 'perl/STRASSE.pm')]:
            entries = [(name, False) for name in paths]
            for ordered in [entries, list(reversed(entries))]:
                with self.assertRaisesRegex(ValueError, 'Unicode16 file or directory conflict'):
                    admit(ordered)

    def test_file_directory_and_implicit_prefix_conflicts_in_both_orders(self):
        for other in [('perl/pod', True), ('perl/pod/perl.pod', False)]:
            entries = [('perl/Pod', False), other]
            for ordered in [entries, list(reversed(entries))]:
                with self.assertRaisesRegex(ValueError, 'Unicode16 file or directory conflict'):
                    admit(ordered)
        with self.assertRaises(ValueError):
            admit([('perl/../escape', False)])

    def test_zip_and_tar_preserve_exact_source_paths_and_bytes_and_pass_public_inspector(self):
        with tempfile.TemporaryDirectory(prefix='ud-archive-directory-alias-') as temporary:
            root = Path(temporary)
            source = root / 'source'
            support = inspector._support.expected(ROOT, inspector._paths)
            for row in support['files']:
                item = source / row['path']
                item.parent.mkdir(parents=True, exist_ok=True)
                item.write_bytes((ROOT / row['path']).read_bytes())
            for name, body in [('perl/Pod/Usage.pm', b'package Pod::Usage;\n'), ('perl/pod/perl.pod', b'=head1 Perl documentation\n')]:
                item = source / name
                item.parent.mkdir(parents=True, exist_ok=True)
                item.write_bytes(body)
            # Use the actual host directory spellings. The pure cases above
            # cover both aliases even on filesystems that merge their names.
            source_hash, runtime_hash = 'a' * 64, 'b' * 64
            (source / 'SKILL-SUPPORT.json').write_text(json.dumps(support))
            (source / 'BUILD-RECEIPT.json').write_text(json.dumps({'schema_version': 1, 'product_version': '0.1.0-beta.1', 'kind': 'skills', 'platform': 'all', 'source_tree_sha256': source_hash, 'runtime_lock_sha256': runtime_hash}))
            originals = {item.relative_to(source).as_posix(): item.read_bytes() for item in source.rglob('*') if item.is_file()}
            files = [{'path': name, 'sha256': hashlib.sha256(body).hexdigest(), 'size': len(body), 'executable': False} for name, body in sorted(originals.items())]
            (source / 'PACKAGE-INVENTORY.json').write_text(json.dumps({'schema_version': 1, 'files': files}))
            expected = {**originals, 'PACKAGE-INVENTORY.json': (source / 'PACKAGE-INVENTORY.json').read_bytes()}
            for fmt in ['zip', 'tar.gz']:
                target = root / ('original.' + fmt)
                writer.archive(source, target, fmt)
                if fmt == 'zip':
                    with zipfile.ZipFile(target) as archive:
                        actual = {item.filename: archive.read(item) for item in archive.infolist() if not item.is_dir()}
                else:
                    with tarfile.open(target, 'r:gz') as archive:
                        actual = {item.name: archive.extractfile(item).read() for item in archive if item.isfile()}
                self.assertEqual(actual, expected)
                self.assertEqual({name: (source / name).read_bytes() for name in expected}, expected)
                result = inspector.inspect(target, 'skills', 'all', source_hash, runtime_hash, details=True)
                self.assertTrue(result['verified'])
                self.assertEqual(set(result['members']), set(expected))


if __name__ == '__main__':
    unittest.main()
