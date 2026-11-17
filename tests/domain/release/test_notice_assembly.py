import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[3]
spec=importlib.util.spec_from_file_location('notice_assembly',ROOT/'scripts/release/assemble-notices.py');notices=importlib.util.module_from_spec(spec);spec.loader.exec_module(notices)


class NoticeAssemblyTests(unittest.TestCase):
    def test_exact_original_notice_and_source_attribution_survive_deduplication(self):
        with tempfile.TemporaryDirectory()as temporary:
            root=Path(temporary);body=b'Copyright upstream author\r\nPermission notice\n';fingerprint=hashlib.sha256(body).hexdigest();(root/'notice').write_bytes(body)
            content={'path':'notice','source_path':'source/LICENSE','sha256':fingerprint,'size_bytes':len(body)}
            receipt=root/'receipt.json';receipt.write_text(json.dumps({'schema_version':1,'status':'passed','files':[{'name':'component','version':'1.2.3','sha256':'a'*64,'notices':[content,content]}]}))
            result=notices.assemble([('source',receipt)],root/'output');self.assertEqual(len(result['files']),1);self.assertEqual(len(result['components']),2);self.assertEqual((root/'output'/result['files'][0]['path']).read_bytes(),body);self.assertEqual(result['components'][0]['archive_sha256'],'a'*64);self.assertEqual(result['qualification'],'original-upstream-notices-no-license-conclusion')
            (root/'notice').write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError,'size|hash'):notices.assemble([('source',receipt)],root/'corrupt')

    def test_incomplete_and_linked_notice_inputs_cannot_be_certified(self):
        with tempfile.TemporaryDirectory()as temporary:
            root=Path(temporary);receipt=root/'receipt.json';receipt.write_text(json.dumps({'status':'incomplete'}))
            with self.assertRaisesRegex(ValueError,'incomplete'):notices.assemble([('source',receipt)],root/'incomplete')
            (root/'actual').write_bytes(b'x');(root/'link').symlink_to(root/'actual');receipt.write_text(json.dumps({'status':'passed','files':[{'name':'component','version':'1','sha256':'a'*64,'notices':[{'path':'link','source_path':'LICENSE','sha256':hashlib.sha256(b'x').hexdigest(),'size_bytes':1}]}]}))
            with self.assertRaisesRegex(ValueError,'link'):notices.assemble([('source',receipt)],root/'linked')
