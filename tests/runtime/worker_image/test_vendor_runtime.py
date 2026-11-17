import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import struct
import tarfile
import tempfile
import time
import unittest
from unittest.mock import patch
from compression.zstd import compress
import zipfile

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location('vendor_runtime', ROOT / 'workers/ud/src/ud_agent/vendor_runtime.py')
vendor = importlib.util.module_from_spec(spec); spec.loader.exec_module(vendor)


class VendorRuntimeTests(unittest.TestCase):
    def fixture(self, root, extra=None, architecture=0xAA64):
        source = root / 'source'; (source / 'bin').mkdir(parents=True)
        binary = bytearray(128); binary[:2] = b'MZ'; struct.pack_into('<I', binary, 60, 64); binary[64:68] = b'PE\0\0'; struct.pack_into('<H', binary, 68, architecture)
        (source / 'bin/perl.exe').write_bytes(binary)
        def record(body): return {'sha256': hashlib.sha256(body).hexdigest(), 'size_bytes': len(body)}
        members = [('Library/bin/vcruntime140.dll', bytes(binary)), ('info/licenses/LICENSE.TXT', b'Original vendor license\n')]
        if extra: members.append(extra)
        archive = root / 'vendor.conda'
        with zipfile.ZipFile(archive, 'w') as bundle:
            bundle.writestr('metadata.json', '{"conda_pkg_format_version":2}')
            for kind in ('pkg', 'info'):
                output = io.BytesIO()
                with tarfile.open(fileobj=output, mode='w', format=tarfile.USTAR_FORMAT) as tar:
                    for name, body in members:
                        if name.startswith('info/') != (kind == 'info'): continue
                        member = tarfile.TarInfo(name); member.size = len(body); tar.addfile(member, io.BytesIO(body))
                bundle.writestr(kind + '-fixture.tar.zst', compress(output.getvalue()))
        recipe = {'schema_version': 1, 'provider': 'conda-vc-runtime', 'platform': 'win32/arm64', 'executable': 'bin/perl.exe', 'archive': {'url': 'https://conda.anaconda.org/conda-forge/win-arm64/vc14_runtime-1-build.conda', **record(archive.read_bytes())}, 'base_files': [{'source': 'bin/perl.exe', 'path': 'bin/perl.exe', **record(binary)}], 'files': [{'source': name, 'path': 'bin/vcruntime140.dll' if name.startswith('Library/') else 'licenses/vendor/LICENSE.TXT', **record(body)} for name, body in members[:2]]}
        file = root / 'recipe.json'; file.write_text(json.dumps(recipe)); return file, archive, source

    def test_exact_vendor_bytes_and_base_executable_are_materialized_without_execution(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); recipe, archive, source = self.fixture(root); result = vendor.materialize(recipe, archive, source, root / 'private')
            self.assertEqual(len(result['files']), 3); self.assertEqual((root / 'private/bin/perl.exe').read_bytes(), (source / 'bin/perl.exe').read_bytes()); self.assertEqual((root / 'private/licenses/vendor/LICENSE.TXT').read_bytes(), b'Original vendor license\n')
            self.assertFalse(any((source / 'bin').glob('vcruntime*')))

    def test_supplier_executable_joins_retained_perl_modules(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            recipe, runtime, source = self.fixture(root)
            executable = source / 'bin/perl.exe'
            perl_bytes = executable.read_bytes()
            executable.unlink()
            module = source / 'lib/Test.pm'
            module.parent.mkdir()
            module.write_text('package Test; 1;')
            supplier = root / 'perl.tar.bz2'
            with tarfile.open(supplier, 'w:bz2') as bundle:
                file = tarfile.TarInfo('Library/bin/perl.exe')
                file.size = len(perl_bytes)
                bundle.addfile(file, io.BytesIO(perl_bytes))

            def record(body):
                return {'sha256': hashlib.sha256(body).hexdigest(), 'size_bytes': len(body)}

            data = json.loads(recipe.read_bytes())
            data['base_files'] = [{'source': 'lib/Test.pm', 'path': 'lib/Test.pm', **record(module.read_bytes())}]
            data['supplier'] = {
                'archive': {'url': 'https://conda.anaconda.org/anaconda/win-arm64/perl-5.44.0.tar.bz2', **record(supplier.read_bytes())},
                'files': [{'source': 'Library/bin/perl.exe', 'path': 'bin/perl.exe', **record(perl_bytes)}],
            }
            recipe.write_text(json.dumps(data))
            with self.assertRaisesRegex(ValueError, 'SUPPLIER_ARCHIVE_REQUIRED'):
                vendor.materialize(recipe, runtime, source, root / 'private')
            result = vendor.materialize(recipe, runtime, source, root / 'private', supplier)
            self.assertEqual(result['supplier_archive_sha256'], data['supplier']['archive']['sha256'])
            self.assertEqual((root / 'private/bin/perl.exe').read_bytes(), perl_bytes)
            self.assertEqual((root / 'private/lib/Test.pm').read_bytes(), module.read_bytes())
            self.assertFalse(executable.exists())

    def test_integrity_architecture_and_hostile_members_fail_with_owned_rollback(self):
        for mode in ('hash', 'architecture', 'escape', 'collision', 'missing'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary); extra = ('../outside', b'escape') if mode == 'escape' else ('LIBRARY/BIN/VCRUNTIME140.DLL', b'collision') if mode == 'collision' else None
                recipe, archive, source = self.fixture(root, extra, 0x8664 if mode == 'architecture' else 0xAA64)
                if mode == 'hash': archive.write_bytes(archive.read_bytes() + b'corrupt')
                if mode == 'missing': data = json.loads(recipe.read_bytes()); data['files'][0]['source'] = 'Library/bin/absent.dll'; recipe.write_text(json.dumps(data))
                with self.assertRaises(ValueError): vendor.materialize(recipe, archive, source, root / 'private')
                self.assertFalse((root / 'private').exists()); self.assertFalse((root / 'outside').exists())

    def test_verified_archive_handle_rejects_path_replacement_and_inplace_change(self):
        for mode in ('replace', 'change'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary); recipe, archive, source = self.fixture(root); original = zipfile.ZipFile
                retained = archive.read_bytes()
                refused = []
                def swapped(stream):
                    # Kernel ctime advances in coarse ticks; let one pass so a
                    # same-size rename/replace is observable on fast hosts.
                    time.sleep(0.05)
                    if mode == 'replace':
                        if os.name == 'nt':
                            with self.assertRaises(PermissionError):
                                archive.rename(root / 'original.conda')
                            refused.append(True)
                            self.assertEqual(archive.read_bytes(), retained)
                        else:
                            archive.rename(root / 'original.conda'); archive.write_bytes(b'not the admitted archive')
                    else:
                        with archive.open('ab') as destination: destination.write(b'changed')
                    return original(stream)
                with patch.object(vendor.zipfile, 'ZipFile', swapped):
                    if os.name == 'nt' and mode == 'replace':
                        result = vendor.materialize(recipe, archive, source, root / 'private')
                        self.assertEqual(refused, [True])
                        self.assertEqual(len(result['files']), 3)
                        self.assertEqual(archive.read_bytes(), retained)
                        self.assertEqual((root / 'private/licenses/vendor/LICENSE.TXT').read_bytes(), b'Original vendor license\n')
                    else:
                        with self.assertRaisesRegex(ValueError, 'ARCHIVE_CHANGED'): vendor.materialize(recipe, archive, source, root / 'private')
                        self.assertFalse((root / 'private').exists())


if __name__ == '__main__': unittest.main()
