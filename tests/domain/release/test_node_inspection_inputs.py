import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location('node_inspection_inputs', ROOT / 'scripts/release/bind-node-sources.py')
node = importlib.util.module_from_spec(spec); spec.loader.exec_module(node)


class NodeInspectionInputTests(unittest.TestCase):
    def test_original_selected_and_comparison_only_archives_are_retained_once_by_exact_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); rows = []
            for name in ['selected-arm.tar.xz', 'comparison-x64.tar.xz']:
                body = ('original fixture ' + name).encode(); (root / name).write_bytes(body); rows.append({'path': name, 'sha256': hashlib.sha256(body).hexdigest(), 'size_bytes': len(body)})
            result = node.original_inspection_inputs(root, [{'archive': rows[0]}], {'bindings': [{'node_archive': rows[0]}, {'node_archive': rows[1]}]})
            self.assertEqual(result, sorted(rows, key=lambda row: row['sha256']))
            (root / rows[1]['path']).write_bytes(b'x' * rows[1]['size_bytes'])
            with self.assertRaisesRegex(ValueError, 'hash or identity'): node.original_inspection_inputs(root, [{'archive': rows[0]}], {'bindings': [{'node_archive': rows[1]}]})


if __name__ == '__main__': unittest.main()
