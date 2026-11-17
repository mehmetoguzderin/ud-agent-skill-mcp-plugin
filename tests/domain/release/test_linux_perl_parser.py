import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location('linux_ppi_builder', ROOT / 'scripts/quality/prepare-linux-perl-parser.py')
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)


def archive(name, members):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w:gz') as stream:
        for path, content, kind in members:
            entry = tarfile.TarInfo(name + '/' + path)
            entry.size = len(content)
            if kind == 'link':
                entry.type = tarfile.SYMTYPE
                entry.linkname = '/outside'
                entry.size = 0
            stream.addfile(entry, io.BytesIO(content) if kind != 'link' else None)
    return output.getvalue()


class LinuxPerlParserPreparation(unittest.TestCase):
    def fixture(self, root):
        product = root / 'product'
        borrowed = ['lib/perl5/aarch64-linux/Clone.pm', 'lib/perl5/aarch64-linux/auto/Clone/Clone.so', 'lib/perl5/aarch64-linux/Params/Util.pm', 'lib/perl5/aarch64-linux/Params/Util/PP.pm', 'lib/perl5/aarch64-linux/auto/Params/Util/Util.so']
        files = []
        for name in borrowed:
            target = product / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(('independent fixture ' + name).encode())
            files.append({'path': name, 'sha256': 'sha256:' + builder.sha(target.read_bytes()), 'size': target.stat().st_size})
        cache = root / 'cache'
        cache.mkdir()
        release_names = ['Clone-0.51', 'Params-Util-1.102', 'PPI-1.291', 'Safe-Isa-1.000010', 'Task-Weaken-1.06', 'YAML-PP-v0.43.0']
        releases = {}
        for name in release_names:
            data = archive(name, [('lib/' + name + '.pm', b'package Fixture;1;', 'file'), ('t/lib/Hidden.pm', b'not an installed library', 'file')])
            fingerprint = builder.sha(data)
            (cache / (fingerprint + '.tar.gz')).write_bytes(data)
            releases[name] = {'sha256': fingerprint}
        modules = {'releases': {name: releases[name] for name in release_names[:2]}}
        runtime = root / 'runtime'
        runtime.mkdir()
        (runtime / 'native-perl-modules.lock.json').write_text(json.dumps(modules))
        receipt = {'platform': 'linux/arm64', 'probe': {'version': 'v5.44.0', 'ambient_modules': False, 'ambient_elf': False}, 'modules_sha256': builder.sha(builder.canonical(modules)), 'files': files}
        receipt_file = root / 'native.json'
        receipt_file.write_text(json.dumps(receipt))
        lock = {'schema_version': 1, 'state': 'frozen-inputs', 'parser_release': 'PPI-1.291', 'releases': releases}
        lock_file = root / 'parser.lock.json'
        lock_file.write_text(json.dumps(lock))
        return product, receipt_file, cache, lock_file, root / 'parser', lock

    def test_copies_only_verified_xs_and_pure_installed_libraries_and_binds_the_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            product, native, cache, lock_file, output, lock = self.fixture(root)
            with patch.object(builder, 'ROOT', root):
                receipt = builder.prepare(product, native, output, cache, lock_file)
                self.assertEqual(receipt['perl_version'], 'v5.44.0')
                self.assertEqual(receipt['lock_sha256'], hashlib.sha256(json.dumps(lock, sort_keys=True, separators=(',', ':')).encode()).hexdigest())
                paths = {item['path'] for item in receipt['files']}
                self.assertEqual(len(paths), 10)
                self.assertFalse(any('Hidden.pm' in name for name in paths))
                self.assertIn('lib/perl5/PPI-1.291.pm', paths)
                for item in receipt['files']:
                    self.assertEqual((output / item['path']).stat().st_size, item['size'])
                    self.assertEqual(hashlib.sha256((output / item['path']).read_bytes()).hexdigest(), item['sha256'])
                with self.assertRaisesRegex(ValueError, 'new owned directory'):
                    builder.prepare(product, native, output, cache, lock_file)

    def test_rejects_changed_xs_and_wrong_abi_without_publishing_a_partial_parser(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            product, native, cache, lock_file, output, _ = self.fixture(root)
            record = json.loads(native.read_text())
            record['platform'] = 'linux/amd64'
            native.write_text(json.dumps(record))
            with patch.object(builder, 'ROOT', root):
                with self.assertRaisesRegex(ValueError, 'ABI'):
                    builder.prepare(product, native, output, cache, lock_file)
                record['platform'] = 'linux/arm64'
                native.write_text(json.dumps(record))
                (product / record['files'][0]['path']).write_bytes(b'changed')
                with self.assertRaisesRegex(ValueError, 'missing or changed'):
                    builder.prepare(product, native, output, cache, lock_file)
            self.assertFalse(output.exists())
            self.assertFalse(list(root.glob('.linux-ppi-*')))

    def test_rejects_corrupt_cached_sources_and_link_payloads_before_publication(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            product, native, cache, lock_file, output, lock = self.fixture(root)
            fingerprint = lock['releases']['PPI-1.291']['sha256']
            selected = cache / (fingerprint + '.tar.gz')
            selected.write_bytes(b'corrupt archive')
            with patch.object(builder, 'ROOT', root):
                with self.assertRaisesRegex(ValueError, 'cache integrity'):
                    builder.prepare(product, native, output, cache, lock_file)
                data = archive('PPI-1.291', [('lib/escape.pm', b'', 'link')])
                fingerprint = builder.sha(data)
                (cache / (fingerprint + '.tar.gz')).write_bytes(data)
                lock['releases']['PPI-1.291']['sha256'] = fingerprint
                lock_file.write_text(json.dumps(lock))
                with self.assertRaisesRegex(ValueError, 'unsafe archive'):
                    builder.prepare(product, native, output, cache, lock_file)
            self.assertFalse(output.exists())


if __name__ == '__main__':
    unittest.main()
