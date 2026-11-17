import base64
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[3]
spec=importlib.util.spec_from_file_location('package_sources',ROOT/'scripts/release/collect-package-sources.py');collector=importlib.util.module_from_spec(spec);spec.loader.exec_module(collector)


def roots(root,integrity):
    package={'version':'0.1.0-beta.1','resolved':'https://registry.npmjs.org/@owner/package/-/package-0.1.0-beta.1.tgz','integrity':integrity,'license':'MIT'}
    (root/'package-lock.json').write_text(json.dumps({'packages':{'node_modules/@owner/package':package,'node_modules/peer/node_modules/@owner/package':package}}))
    for name in ['Cargo.lock','scripts/quality/rust-assertion-parser/Cargo.lock']:
        target=root/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_text('version = 4\n[[package]]\nname = "local"\nversion = "0.1.0"\n')


class PackageSourceTests(unittest.TestCase):
    def test_actual_npm_pack_bytes_and_full_lock_deduplication(self):
        fixture=ROOT/'tests/fixtures/source-materials/npm-public-fixture.tgz';body=fixture.read_bytes();proof=json.loads(fixture.with_suffix('.json').read_bytes())
        self.assertEqual(hashlib.sha256(body).hexdigest(),proof['sha256'])
        integrity='sha512-'+base64.b64encode(hashlib.sha512(body).digest()).decode()
        with tempfile.TemporaryDirectory()as temporary:
            root=Path(temporary);roots(root,integrity);planned,bindings=collector.plan(root)
            self.assertEqual(len(planned),1);self.assertEqual(planned[0]['name'],'@owner/package');self.assertEqual(len(planned[0]['consumers']),2);self.assertEqual(len(bindings),3)
            output=root/'output';target=output/'blobs'/hashlib.sha256(planned[0]['url'].encode()).hexdigest();target.parent.mkdir(parents=True);target.write_bytes(body)
            result=collector.collect(root,output,False)
            self.assertEqual(result['status'],'passed');self.assertEqual(result['files'][0]['sha256'],proof['sha256']);self.assertFalse(result['target_execution'])
            target.write_bytes(b'corrupt')
            with self.assertRaisesRegex(ValueError,'SRI'):collector.collect(root,output,False)

    def test_all_cargo_locks_contribute_exact_sources_and_conflicts_fail(self):
        with tempfile.TemporaryDirectory()as temporary:
            root=Path(temporary);roots(root,'sha256-'+base64.b64encode(b'x'*32).decode())
            base='version = 4\n[[package]]\nname = "source"\nversion = "1.2.3"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\nchecksum = "'+('a'*64)+'"\n'
            (root/'Cargo.lock').write_text(base);(root/'scripts/quality/rust-assertion-parser/Cargo.lock').write_text(base)
            items,_=collector.plan(root);cargo=next(item for item in items if item['family']=='cargo');self.assertEqual(len(cargo['consumers']),2);self.assertEqual(cargo['url'],'https://static.crates.io/crates/source/source-1.2.3.crate')
            (root/'scripts/quality/rust-assertion-parser/Cargo.lock').write_text(base.replace('a'*64,'b'*64))
            with self.assertRaisesRegex(ValueError,'disagree'):collector.plan(root)

    def test_no_weak_hashes_foreign_registry_or_missing_workspaces(self):
        with tempfile.TemporaryDirectory()as temporary:
            root=Path(temporary);roots(root,'sha1-'+base64.b64encode(b'x'*20).decode())
            with self.assertRaisesRegex(ValueError,'strong integrity'):collector.plan(root)
            roots(root,'sha512-'+base64.b64encode(b'x'*64).decode());file=root/'package-lock.json';data=json.loads(file.read_bytes());data['packages']['node_modules/@owner/package']['resolved']='https://example.org/source.tgz';file.write_text(json.dumps(data))
            with self.assertRaisesRegex(ValueError,'non-registry'):collector.plan(root)
            roots(root,'sha512-'+base64.b64encode(b'x'*64).decode());(root/'Cargo.lock').unlink()
            with self.assertRaisesRegex(ValueError,'missing'):collector.plan(root)

    def test_original_license_bytes_are_preserved_without_extracting_links(self):
        with tempfile.TemporaryDirectory()as temporary:
            root=Path(temporary);archive=root/'source.tgz';license=b'Original author\nPermission is hereby granted\n'
            with tarfile.open(archive,'w:gz')as target:
                member=tarfile.TarInfo('package/LICENSE');member.size=len(license);target.addfile(member,io.BytesIO(license))
                link=tarfile.TarInfo('package/linked');link.type=tarfile.SYMTYPE;link.linkname='/unreadable';target.addfile(link)
            rows=collector.inspect_archive(archive,root);self.assertEqual(rows[0]['source_path'],'package/LICENSE');self.assertEqual((root/rows[0]['path']).read_bytes(),license);self.assertFalse((root/'package').exists())
            with tarfile.open(archive,'w:gz')as target:
                member=tarfile.TarInfo('../LICENSE');member.size=1;target.addfile(member,io.BytesIO(b'x'))
            with self.assertRaisesRegex(ValueError,'unsafe'):collector.inspect_archive(archive,root)
