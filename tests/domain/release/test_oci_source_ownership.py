import importlib.util
import io
from pathlib import Path
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location('oci_source_ownership', ROOT / 'scripts/release/bind-oci-package-files.py')
binding = importlib.util.module_from_spec(spec); spec.loader.exec_module(binding)


def add(filesystem, rows):
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode='w') as archive:
        for name, body in rows:
            entry = tarfile.TarInfo(name); entry.size = len(body); archive.addfile(entry, io.BytesIO(body))
    data.seek(0)
    with tarfile.open(fileobj=data, mode='r:') as archive: filesystem.add_layer(archive)


class OciSourceOwnershipTests(unittest.TestCase):
    def test_exact_actual_file_lists_and_control_members_define_ownership(self):
        with tempfile.TemporaryDirectory() as temporary:
            fs = binding.oci.Filesystem(Path(temporary) / 'opaque')
            add(fs, [('usr/bin/tool', b'actual original binary fixture'), ('var/lib/dpkg/info/example:arm64.list', b'/usr/bin/tool\n'), ('var/lib/dpkg/info/example:arm64.postinst', b'#!/bin/sh\n'), ('usr/bin/unowned', b'not in publisher ownership list')])
            package = {'name': 'example', 'version': '3.0-2', 'architecture': 'arm64'}
            owners = binding.ownership(fs, [package]); self.assertEqual(owners['usr/bin/tool'], {('example', '3.0-2', 'arm64')}); self.assertIn('var/lib/dpkg/info/example:arm64.postinst', owners); self.assertNotIn('usr/bin/unowned', owners)
            for body in [b'../outside\n', b'/usr/bin/tool\n/usr/bin/tool\n', b'/a/../usr/bin/tool\n']:
                add(fs, [('var/lib/dpkg/info/example:arm64.list', body)])
                with self.subTest(body=body), self.assertRaises(ValueError): binding.ownership(fs, [package])

    def test_missing_or_ambiguous_actual_publisher_lists_cannot_be_substituted(self):
        with tempfile.TemporaryDirectory() as temporary:
            fs = binding.oci.Filesystem(Path(temporary) / 'opaque'); package = {'name': 'example', 'version': '3.0-2', 'architecture': 'arm64'}
            with self.assertRaisesRegex(ValueError, 'absent'): binding.ownership(fs, [package])
            add(fs, [('var/lib/dpkg/info/example:arm64.list', b'/usr/bin/tool\n'), ('var/lib/dpkg/info/example.list', b'/usr/bin/tool\n')])
            with self.assertRaisesRegex(ValueError, 'ambiguous'): binding.ownership(fs, [package])

    def test_generated_mime_requires_the_actual_writer_recipe_and_exact_namespace(self):
        with tempfile.TemporaryDirectory() as temporary:
            fs = binding.oci.Filesystem(Path(temporary) / 'opaque'); package = {'name': 'shared-mime-info', 'version': '2.4-5', 'architecture': 'arm64'}
            add(fs, [('usr/share/mime/application/example.xml', b'<mime-type type="application/example"/>'), ('usr/share/mime/foreign.so', b'\x7fELFforeign'), ('usr/share/mime/mime.cache', b'\0\x01\0\x02' + bytes(40)), ('var/lib/dpkg/info/shared-mime-info.postinst', b'update-mime-database /usr/share/mime\n')])
            actual = binding.generated_ownership(fs, [package], {})
            self.assertEqual(set(actual), {'usr/share/mime/application/example.xml','usr/share/mime/mime.cache'})
            self.assertTrue(all(row['component'] == ('shared-mime-info','2.4-5','arm64') for row in actual.values()))
            add(fs, [('var/lib/dpkg/info/shared-mime-info.postinst', b'not the mime writer')]); self.assertEqual(binding.generated_ownership(fs, [package], {}), {})

    def test_generated_package_state_is_finite_text_or_a_recognized_cache_not_a_binary_waiver(self):
        with tempfile.TemporaryDirectory() as temporary:
            fs = binding.oci.Filesystem(Path(temporary) / 'opaque'); packages = [{'name': name, 'version': '1', 'architecture': 'arm64'} for name in ('dpkg','libc-bin','apt')]
            add(fs, [('var/log/dpkg.log', b'actual publisher package log\n'), ('var/log/arbitrary.log', b'unowned'), ('var/lib/dpkg/alternatives/editor', b'auto\n/usr/bin/editor\n'), ('var/lib/dpkg/alternatives/foreign', b'print("arbitrary code")'), ('etc/ld.so.cache', b'glibc-ld.so.cache1.1' + bytes(20)), ('var/log/apt/term.log', b'\x7fELF\0not text'), ('var/lib/dpkg/lock', b'')])
            owners = {'usr/sbin/ldconfig': {('libc-bin','1','arm64')}}; actual = binding.generated_ownership(fs, packages, owners)
            self.assertEqual(set(actual), {'var/log/dpkg.log','var/lib/dpkg/alternatives/editor','etc/ld.so.cache','var/lib/dpkg/lock'})
            add(fs, [('etc/ld.so.cache', b'\x7fELFunexplained executable')]); self.assertNotIn('etc/ld.so.cache', binding.generated_ownership(fs, packages, owners))


if __name__ == '__main__': unittest.main()
