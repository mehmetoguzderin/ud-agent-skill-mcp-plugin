"""Declared SBOM packages are metadata, never a binary source relation."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location('component_declaration_closure', ROOT / 'scripts/release/component-closure.py')
closure = importlib.util.module_from_spec(spec)
spec.loader.exec_module(closure)


class ComponentDeclarationTests(unittest.TestCase):
    def test_sbom_declarations_do_not_become_files_or_admit_an_actual_unbound_binary(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'LICENSE').write_text('Original authored fixture license\n')
            (root / '.artifacts').mkdir()
            binary = b'MZ' + bytes(128)
            fingerprint = hashlib.sha256(binary).hexdigest()
            archive = root / '.artifacts/runtime.tar.gz'
            with tarfile.open(archive, 'w:gz') as stream:
                entry = tarfile.TarInfo('bin/unknown.exe')
                entry.size = len(binary)
                stream.addfile(entry, io.BytesIO(binary))
            sbom = root / '.artifacts/sbom.json'
            # This claims the actual binary hash and an MIT label; neither is
            # an independently derived source/notice relationship.
            sbom.write_text(json.dumps({'spdxVersion': 'SPDX-2.3', 'packages': [{'SPDXID': 'SPDXRef-Unknown', 'name': 'unknown', 'versionInfo': '1', 'licenseDeclared': 'MIT', 'checksums': [{'algorithm': 'SHA256', 'checksumValue': fingerprint}]}]}))
            source = closure.source_inventory(root)
            candidate = {'schema_version': 1, 'source_tree_sha256': source['sha256'], 'runtime_lock_sha256': 'b' * 64, 'artifacts': [{'id': identifier, 'path': file.relative_to(root).as_posix(), 'sha256': closure.digest(file), 'size': file.stat().st_size} for identifier, file in [('sbom', sbom), ('userspace-core-win32-arm64', archive)]]}
            result = closure.derive(root, candidate, {'schema_version': 1, 'families': []})
            declaration = next(row for row in result['subjects'] if row['id'] == 'sbom')
            self.assertEqual(declaration['members'], 1)
            self.assertEqual(declaration['bindings'], [])
            self.assertFalse(result['complete_available_shipped_component_coverage'])
            self.assertEqual([(row['artifact'], row['path'], row['sha256']) for row in result['unresolved_shipped_members']], [('userspace-core-win32-arm64', 'bin/unknown.exe', fingerprint)])


if __name__ == '__main__':
    unittest.main()
