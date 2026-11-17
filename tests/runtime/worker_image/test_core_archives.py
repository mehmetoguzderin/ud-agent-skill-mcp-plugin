import hashlib
import importlib.util
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[3]
spec=importlib.util.spec_from_file_location('ud_core_archives_test',ROOT/'scripts/runtime/prepare-core-archives.py');core=importlib.util.module_from_spec(spec);spec.loader.exec_module(core)


class CoreArchiveTests(unittest.TestCase):
    def test_transports_are_exact_selected_inventory_reproducible_and_tamper_checked(self):
        with tempfile.TemporaryDirectory()as temporary:
            root=Path(temporary);source=root/'source';(source/'runtime').mkdir(parents=True)
            data={'runtime/common/main.py':b'worker','runtime/native/arm64/perl':b'ARM Perl','runtime/native/x64/perl':b'x64 Perl'}
            for name,value in data.items():file=source/name;file.parent.mkdir(parents=True,exist_ok=True);file.write_bytes(value);file.chmod(0o555)
            record=lambda name:{'path':name,'sha256':'sha256:'+hashlib.sha256(data[name]).hexdigest(),'size':len(data[name])}
            manifest={'schema_version':1,'format_revision':2,'state':'frozen','platforms':{'darwin/arm64':{'files':[record('runtime/common/main.py'),record('runtime/native/arm64/perl')]},'darwin/x64':{'files':[record('runtime/common/main.py'),record('runtime/native/x64/perl')]}}}
            (source/'runtime/userspace.lock.json').write_text(json.dumps(manifest))
            first=core.prepare(source,root/'one');second=core.prepare(source,root/'two')
            self.assertEqual(first['assets'],second['assets']);self.assertEqual(len(first['assets']),2)
            for asset in first['assets']:
                host=asset['platform'].replace('darwin-','darwin/');expected={entry['path']for entry in manifest['platforms'][host]['files']}
                with tarfile.open(root/'one'/asset['path'],'r:gz')as archive:
                    self.assertEqual({entry.name for entry in archive},expected)
                    for entry in archive:
                        self.assertTrue(entry.isfile());self.assertFalse(entry.pax_headers);self.assertEqual((entry.uid,entry.gid,entry.mtime),(0,0,0));self.assertEqual(archive.extractfile(entry).read(),data[entry.name])
            self.assertNotIn('lazy_core',json.loads((source/'runtime/userspace.lock.json').read_text())['platforms']['darwin/arm64'])
            (source/'runtime/common/main.py').chmod(0o644);(source/'runtime/common/main.py').write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError,'inventory'):core.prepare(source,root/'corrupt')


if __name__=='__main__':unittest.main()
