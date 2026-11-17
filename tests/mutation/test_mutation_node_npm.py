"""Original npm archive data admission only; target binaries are never executed."""
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('npm_mutation_context',ROOT/'scripts/quality/prepare-mutation-runtime.py')
runtime=importlib.util.module_from_spec(spec);spec.loader.exec_module(runtime)


class MutationNpmArchiveTests(unittest.TestCase):
    def archive(self, root, case=None):
        version='26.13.0';prefix='node-v'+version+'-linux-arm64/lib/node_modules/npm/';file=root/'node.tar.xz'
        records=[('package.json',json.dumps({'name':'npm','version':'11.9.0'}).encode()),('LICENSE',b'original npm fixture notice\n'),('bin/npm-cli.js',b'#!/usr/bin/env node\n// original CLI fixture\n'),('node_modules/dependency/index.js',b'export const fixture = true;\n')]
        if case=='missing':records=[row for row in records if row[0]!='bin/npm-cli.js']
        if case=='duplicate':records.append(records[-1])
        if case=='escape':records.append(('../escape',b'never written'))
        if case=='case':records.append(('license',b'collision'))
        if case=='file-parent':records.extend([('ordinary',b'one'),('ordinary/child',b'two')])
        with tarfile.open(file,'w:xz')as archive:
            for name,body in records:
                member=tarfile.TarInfo(prefix+name);member.size=len(body);member.mode=0o755 if name=='bin/npm-cli.js' else 0o644;archive.addfile(member,io.BytesIO(body))
            if case=='link':
                member=tarfile.TarInfo(prefix+'foreign');member.type=tarfile.SYMTYPE;member.linkname='/outside';archive.addfile(member)
            foreign=tarfile.TarInfo('node-v'+version+'-linux-arm64/foreign-not-selected');foreign.size=1;archive.addfile(foreign,io.BytesIO(b'x'))
        return file,{'filename':'node-v'+version+'-linux-arm64.tar.xz','sha256':runtime.digest(file)},version

    def test_exact_complete_original_npm_regular_subtree_and_license_are_retained_read_only(self):
        with tempfile.TemporaryDirectory()as temporary:
            root=Path(temporary);archive,item,version=self.archive(root);output=root/'node';output.mkdir();(output/'LICENSE').write_text('original Node license')
            chmod=Path.chmod;modes=[]
            def retain_mode(path,mode,**options):
                modes.append((path,mode));return chmod(path,mode,**options)
            with patch.object(Path,'chmod',retain_mode):
                result=runtime.copy_node_npm(archive,item,version,output)
            self.assertEqual(result['version'],'11.9.0');self.assertEqual(result['provider']['sha256'],item['sha256'])
            self.assertEqual([row['path']for row in result['files']],['lib/node_modules/npm/LICENSE','lib/node_modules/npm/bin/npm-cli.js','lib/node_modules/npm/node_modules/dependency/index.js','lib/node_modules/npm/package.json'])
            self.assertEqual((output/'lib/node_modules/npm/node_modules/dependency/index.js').read_bytes(),b'export const fixture = true;\n')
            self.assertEqual((output/'LICENSE').read_text(),'original Node license');self.assertFalse((output/'foreign-not-selected').exists())
            for row in result['files']:
                file=output/row['path'];expected=0o555 if row['executable'] else 0o444
                self.assertIn((file,expected),modes);self.assertEqual(runtime.digest(file),row['sha256'])
                self.assertEqual(file.stat().st_mode&0o777,0o444 if os.name=='nt' else expected)

    def test_damage_wrong_version_unsafe_or_incomplete_archive_is_rejected_before_writes(self):
        for case in ('digest','version','missing','duplicate','escape','case','file-parent','link'):
            with self.subTest(case=case),tempfile.TemporaryDirectory()as temporary:
                root=Path(temporary);archive,item,version=self.archive(root,case);output=root/'node';output.mkdir()
                if case=='digest':item['sha256']='f'*64
                if case=='version':version='26.12.0'
                with self.assertRaises(ValueError):runtime.copy_node_npm(archive,item,version,output)
                self.assertEqual(list(output.iterdir()),[]);self.assertFalse((root/'escape').exists())

    def test_existing_library_destination_is_never_adopted_or_rewritten(self):
        with tempfile.TemporaryDirectory()as temporary:
            root=Path(temporary);archive,item,version=self.archive(root);output=root/'node';(output/'lib').mkdir(parents=True);file=output/'lib/owned';file.write_bytes(b'preserve')
            with self.assertRaises(ValueError):runtime.copy_node_npm(archive,item,version,output)
            self.assertEqual(file.read_bytes(),b'preserve')


if __name__=='__main__':unittest.main()
