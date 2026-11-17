"""Real stdlib archives must work under the exported OCI worker environment."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[3]


class RuntimeZipEpochTests(unittest.TestCase):
    def test_worker_epoch_allows_real_python_standard_library_zip_creation(self):
        containerfile = (ROOT / 'runtime/Containerfile.core').read_text()
        match = re.search(r'\bSOURCE_DATE_EPOCH=(\d+)\b', containerfile)
        self.assertIsNotNone(match)
        script = '''import io,json,zipfile
buffer=io.BytesIO()
with zipfile.ZipFile(buffer,'w') as archive:
 archive.writestr('result.txt',b'validator output')
with zipfile.ZipFile(io.BytesIO(buffer.getvalue())) as archive:
 print(json.dumps({'bytes':archive.read('result.txt').decode(),'date':archive.getinfo('result.txt').date_time}))
'''
        result = subprocess.run([sys.executable, '-I', '-c', script], env={**os.environ, 'SOURCE_DATE_EPOCH': match[1]}, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), {'bytes': 'validator output', 'date': [1980, 1, 1, 0, 0, 0]})


if __name__ == '__main__':
    unittest.main()
