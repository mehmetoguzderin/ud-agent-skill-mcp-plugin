import hashlib
import importlib.util
import io
from pathlib import Path
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location('coordinator_program_inputs', ROOT / 'scripts/release/component-closure.py')
closure = importlib.util.module_from_spec(spec); spec.loader.exec_module(closure)


class Recorder:
    def __init__(self): self.references = []
    def source_member(self, file, archive_sha256, member): self.references.append((Path(file).name, archive_sha256, member))


class CoordinatorOriginalInputTests(unittest.TestCase):
    def test_sdk_source_is_joined_to_actual_original_tar_member_not_ambient_installed_metadata(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); archive = root / 'original.tgz'; body = b'export const value = 42;\n'
            with tarfile.open(archive, 'w:gz') as target:
                entry = tarfile.TarInfo('package/value.mjs'); entry.size = len(body); target.addfile(entry, io.BytesIO(body))
            original = {'path': archive.name, 'sha256': hashlib.sha256(archive.read_bytes()).hexdigest(), 'size_bytes': archive.stat().st_size}
            binding = {'family': 'npm', 'name': 'fixture', 'version': '1.0.0', 'consumers': ['node_modules/fixture'], 'source': original}
            supplied = {'path': 'node_modules/fixture/value.mjs', 'sha256': hashlib.sha256(body).hexdigest(), 'size': len(body)}
            recorder = Recorder()
            result = closure.verify_npm_program_inputs(root / 'source-receipt.json', [binding], [supplied], recorder, root)
            self.assertEqual(result, [binding]); self.assertEqual(recorder.references, [('value.mjs', original['sha256'], 'package/value.mjs')])
            # An ambient install can report a different complete digest; that
            # never substitutes for bytes in the already authenticated archive.
            changed = {**supplied, 'sha256': hashlib.sha256(b'export const value = 43;\n').hexdigest()}
            with self.assertRaisesRegex(ValueError, 'differs from its locked original npm archive'): closure.verify_npm_program_inputs(root / 'source-receipt.json', [binding], [changed])
            with self.assertRaisesRegex(ValueError, 'no exact locked npm source consumer'): closure.verify_npm_program_inputs(root / 'source-receipt.json', [binding], [{**supplied, 'path': 'node_modules/unknown/value.mjs'}])
            archive.write_bytes(b'changed original archive')
            with self.assertRaisesRegex(ValueError, 'size or kind|hash or identity'): closure.verify_npm_program_inputs(root / 'source-receipt.json', [binding], [supplied])


if __name__ == '__main__': unittest.main()
