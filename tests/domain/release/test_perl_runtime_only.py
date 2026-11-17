import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location('perl_runtime_only', ROOT / 'scripts/runtime/prepare-perl-runtime-only.py'); builder = importlib.util.module_from_spec(spec); spec.loader.exec_module(builder)


class PerlRuntimeOnlyTests(unittest.TestCase):
    def fixture(self, root):
        pack = root / 'supplier'; pack.mkdir()
        contents = {'bin/perl.exe': b'original interpreter bytes', 'bin/perl544.dll': b'original loader dependency', 'bin/perl.pdb': b'original supplier symbols', 'lib/CORE/perl.lib': b'original import library', 'lib/CORE/header.h': b'Config/ExtUtils input', 'lib/auto/example.exp': b'original linker export', 'lib/auto/real.dll': b'original precompiled XS', 'lib/Config.pm': b'original module configuration'}
        for name, body in contents.items(): file = pack / name; file.parent.mkdir(parents=True, exist_ok=True); file.write_bytes(body)
        receipt = root / 'receipt.json'; receipt.write_text(json.dumps({'schema_version': 1, 'platform': 'win32/arm64', 'executable': 'bin/perl.exe', 'native_probe': {'status': 'pending_native'}, 'files': [{'path': name, 'sha256': 'sha256:' + hashlib.sha256(body).hexdigest(), 'size': len(body)} for name, body in contents.items()]})); return pack, receipt, contents

    def test_only_proven_linker_debug_artifacts_are_removed_and_originals_remain(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); pack, receipt, original = self.fixture(root); before = receipt.read_bytes(); result = builder.prepare(pack, receipt, root / 'runtime')
            self.assertEqual(set(row['path'] for row in result['files']), set(original) - {'bin/perl.pdb', 'lib/CORE/perl.lib', 'lib/auto/example.exp'})
            self.assertEqual(result['native_probe']['status'], 'pending_native'); self.assertFalse(result['runtime_only_derivation']['compiler_provenance_resolved_by_filter']); self.assertEqual(receipt.read_bytes(), before)
            self.assertTrue(all((pack / name).read_bytes() == body for name, body in original.items())); self.assertEqual((root / 'runtime/lib/CORE/header.h').read_bytes(), original['lib/CORE/header.h'])

    def test_missing_extra_corrupt_and_unsafe_input_inventory_fail_before_copy(self):
        for mode in ('extra', 'corrupt', 'path'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary); pack, receipt, _ = self.fixture(root)
                if mode == 'extra': (pack / 'unlisted').write_bytes(b'extra')
                elif mode == 'corrupt': (pack / 'bin/perl.exe').write_bytes(b'changed')
                else:
                    value = json.loads(receipt.read_bytes()); value['files'][0]['path'] = '../outside'; receipt.write_text(json.dumps(value))
                with self.assertRaises(ValueError): builder.prepare(pack, receipt, root / 'runtime')
                self.assertFalse((root / 'runtime').exists())


if __name__ == '__main__': unittest.main()
