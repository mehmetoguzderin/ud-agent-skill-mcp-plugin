import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from ud_agent.contexts import resolve_snapshot_context

class ContextTests(unittest.TestCase):
    def test_hash_bound_context_and_escape_refusal(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            directory = root / 'context'; (directory / 'rules').mkdir(parents=True)
            rules = {}
            for name in ('data.json', 'deprels.json', 'edeprels.json', 'feats.json', 'tospace.json', 'udeprels.json', 'upos.json'):
                (directory / 'rules' / name).write_bytes(b'{}\n')
                rules[name] = hashlib.sha256(b'{}\n').hexdigest()
            manifest = {'rule_dir': 'rules', 'rules': rules, 'context_sha256': hashlib.sha256(json.dumps(rules, sort_keys=True, separators=(',', ':')).encode()).hexdigest()}
            (directory / 'context.json').write_text(json.dumps(manifest))
            self.assertEqual(resolve_snapshot_context(str(root), 'context/context.json', '/installed'), str(directory / 'context.json'))
            self.assertEqual(resolve_snapshot_context(str(root), '', '/installed'), '/installed')
            (directory / 'rules' / 'data.json').write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError, 'HASH_MISMATCH'):
                resolve_snapshot_context(str(root), 'context/context.json', '/installed')
            with self.assertRaisesRegex(ValueError, 'PATH_INVALID'):
                resolve_snapshot_context(str(root), '../outside', '/installed')
            manifest['rule_dir'] = '/absolute'
            (directory / 'context.json').write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError, 'PATH_INVALID'):
                resolve_snapshot_context(str(root), 'context/context.json', '/installed')

if __name__ == '__main__':
    unittest.main()
