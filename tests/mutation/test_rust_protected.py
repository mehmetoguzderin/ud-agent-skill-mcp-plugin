"""Independent closed-byte and build-authority policies; native proof is separate."""
import copy
import hashlib
import importlib.util
import io
import json
import stat
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('ud_rust_protected_policy', ROOT / 'scripts/quality/rust-protected.py')
runner = importlib.util.module_from_spec(spec);spec.loader.exec_module(runner)


def bundle(control, payloads=(), names=None):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w', format=tarfile.USTAR_FORMAT) as archive:
        for name, data in [('build.json', json.dumps(control).encode()), *zip(names or [f'binaries/{i}' for i in range(len(payloads))], payloads)]:
            item = tarfile.TarInfo(name);item.size = len(data);archive.addfile(item, io.BytesIO(data))
    return output.getvalue()


def elf():
    data = bytearray(64);data[:6] = b'\x7fELF\x02\x01';data[18:20] = (183).to_bytes(2, 'little');return bytes(data)


class RustProtectedTests(unittest.TestCase):
    def test_root_outcomes_bind_each_completed_artifact_and_reject_mixed_runner_errors(self):
        artifact={'id':'packages/launcher/tests/guard.rs','sha256':'a'*64}
        arguments=['--test-threads=1'];log='test independent ... ok\n'
        outcome={'status':0,'timed_out':False,'owned_descendants_cancelled':[],'uid':100001,'handoff':{'readonly_tree':True},'stderr':log}
        record={'schema_version':1,'artifact':artifact,'arguments':arguments,'outcome':outcome}
        evidence=runner.invocation_evidence(record,artifact,arguments,0,log.encode(),['independent'])
        self.assertEqual(evidence,{'artifact_id':artifact['id'],'artifact_sha256':artifact['sha256'],'expected_tests':['independent'],'status':0,'timed_out':False,'cancelled':False,'owned_descendants_cancelled':False,'cleanup_verified':True,'log':log})
        assertion={**record,'outcome':{**outcome,'status':101}}
        self.assertEqual(runner.invocation_evidence(assertion,artifact,arguments,101,log.encode(),['independent'])['status'],101)
        for changed in [{'status':125},{'status':-11},{'status':True},{'timed_out':True},{'cancelled':True},{'owned_descendants_cancelled':[{'pid':8}]},{'uid':0},{'uid':True},{'handoff':{}},{'handoff':None},{'stderr':log+'forged'}]:
            with self.subTest(changed=changed),self.assertRaises(ValueError):runner.invocation_evidence({**record,'outcome':{**outcome,**changed}},artifact,arguments,changed.get('status',0),log.encode(),['independent'])
        for changed in [{'schema_version':True},{'artifact':{**artifact,'sha256':'b'*64}},{'arguments':['filtered']},{'extra':True}]:
            with self.subTest(changed=changed),self.assertRaises(ValueError):runner.invocation_evidence({**record,**changed},artifact,arguments,0,log.encode(),['independent'])
        # A clean assertion in one artifact cannot validate another root error.
        with self.assertRaises(ValueError):runner.invocation_evidence({**record,'outcome':{**outcome,'status':125}},artifact,arguments,125,log.encode(),['independent'])
        with self.assertRaises(ValueError):runner.invocation_evidence(record,artifact,arguments,101,log.encode(),['independent'])

    def test_required_artifacts_are_discovered_independently_from_closed_sources(self):
        receipt = {'files': [{'path': name} for name in ['packages/launcher/tests/core.rs', 'packages/launcher/tests/other.rs', 'packages/launcher/tests/support/helper.rs', 'tests/unrelated.rs']]}
        self.assertEqual(runner.required_artifacts(receipt), {('packages/launcher/src/main.rs', 'product'), ('packages/launcher/src/fs_guard.rs', 'product'), ('packages/launcher/src/main.rs', 'test'), ('packages/launcher/src/fs_guard.rs', 'test'), ('packages/launcher/tests/core.rs', 'test'), ('packages/launcher/tests/other.rs', 'test')})
        with self.assertRaises(ValueError):runner.required_artifacts({'files': []})
        manifest='scripts/quality/rust-assertion-parser/Cargo.toml'
        self.assertEqual(runner.required_artifacts({'files':[{'path':'scripts/quality/rust-assertion-parser/tests/protocol.rs'}]},manifest),{('scripts/quality/rust-assertion-parser/src/main.rs','product'),('scripts/quality/rust-assertion-parser/src/main.rs','test'),('scripts/quality/rust-assertion-parser/tests/protocol.rs','test')})
        with self.assertRaises(ValueError):runner.required_artifacts(receipt,'unregistered/Cargo.toml')

    def control(self):
        raw = elf()
        artifacts = []
        for name, source, kind in [('ud-agent', 'src/main.rs', 'product'), ('ud-agent-guard', 'src/fs_guard.rs', 'product'), ('deps/independent-test', 'tests/independent.rs', 'test')]:
            artifacts.append({'path': 'target/aarch64-unknown-linux-gnu/debug/' + name, 'id': 'packages/launcher/' + source, 'kind': kind, 'sha256': hashlib.sha256(raw).hexdigest(), 'size': len(raw)})
        return {'schema_version': 1, 'status': 0, 'argv': ['cargo', 'test'], 'source_root': '/tmp/ud-mutation-jobs/closed/tree', 'artifacts': artifacts}, [raw] * 3

    def test_harvest_requires_both_products_tests_and_exact_native_bytes(self):
        control, payloads = self.control()
        actual, data = runner.decode_bundle(bundle(control, payloads))
        self.assertEqual(actual, control);self.assertEqual(data, payloads)
        failure = {**control, 'status': 101, 'artifacts': []}
        self.assertEqual(runner.decode_bundle(bundle(failure)), (failure, []))
        for kind in ('missing-product', 'missing-tests', 'foreign-arch', 'wrong-hash', 'extra-payload', 'missing-payload', 'path-escape', 'duplicate', 'boolean-status', 'unknown-field'):
            changed = copy.deepcopy(control);body = list(payloads)
            if kind == 'missing-product': del changed['artifacts'][0];del body[0]
            elif kind == 'missing-tests': changed['artifacts'] = changed['artifacts'][:2];body = body[:2]
            elif kind == 'foreign-arch': body[0] = b'\x7fELF\x02\x01' + b'x' * 58
            elif kind == 'wrong-hash': changed['artifacts'][0]['sha256'] = 'a' * 64
            elif kind == 'extra-payload': body.append(elf())
            elif kind == 'missing-payload': body.pop()
            elif kind == 'path-escape': changed['artifacts'][0]['path'] = '../coordinator'
            elif kind == 'duplicate': changed['artifacts'][1] = changed['artifacts'][0]
            elif kind == 'boolean-status': changed['status'] = True
            else: changed['extra'] = True
            with self.subTest(kind=kind), self.assertRaises(ValueError):runner.decode_bundle(bundle(changed, body))

    def test_second_workspace_bundle_cannot_inherit_launcher_authority(self):
        control,payloads=self.control();control['workspace_manifest']='scripts/quality/rust-assertion-parser/Cargo.toml'
        with self.assertRaises(ValueError):runner.decode_bundle(bundle(control,payloads))
        for index,(name,kind)in enumerate([('src/main.rs','product'),('src/main.rs','test'),('tests/protocol.rs','test')]):
            control['artifacts'][index]['id']='scripts/quality/rust-assertion-parser/'+name;control['artifacts'][index]['kind']=kind
        self.assertEqual(runner.decode_bundle(bundle(control,payloads))[0],control)

    def test_archive_special_members_duplicates_and_undeclared_names_never_extract(self):
        control, payloads = self.control()
        for names in (['binaries/0', 'binaries/0', 'binaries/2'], ['../outside', 'binaries/1', 'binaries/2']):
            with self.subTest(names=names), self.assertRaises(ValueError):runner.decode_bundle(bundle(control, payloads, names))
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode='w') as archive:
            item = tarfile.TarInfo('build.json');item.type = tarfile.SYMTYPE;item.linkname = '/coordinator';archive.addfile(item)
        with self.assertRaises(ValueError):runner.decode_bundle(output.getvalue())
        with self.assertRaises(ValueError):runner.decode_bundle(b'x' * (32 * 1024**2 + 1))

    def test_compiler_authority_rejects_unbound_source_or_build_executables(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary);original = root / 'original';work = root / 'work'
            for path in (original, work):
                (path / 'packages/launcher/src').mkdir(parents=True)
                (path / 'Cargo.toml').write_text('[workspace]\nmembers=["packages/launcher"]\n')
                (path / 'packages/launcher/Cargo.toml').write_text('[package]\nname="ud-agent-launcher"\nversion="0.1.0"\n')
                (path / 'packages/launcher/src/main.rs').write_text('fn main(){assert!(true);}\n')
            files = [{'path': p.relative_to(original).as_posix(), 'sha256': hashlib.sha256(p.read_bytes()).hexdigest()} for p in original.rglob('*') if p.is_file()]
            receipt = {'copy': str(original), 'files': files};schedule = {'inventory': []}
            ordinary = Path.lstat
            def owned(path):
                info = ordinary(path)
                return type('Owned', (), {key: (0 if key == 'st_uid' else (stat.S_IFMT(info.st_mode) | 0o644) if key == 'st_mode' else getattr(info, key)) for key in ('st_uid', 'st_mode', 'st_nlink')})()
            with patch.object(Path, 'lstat', owned):
                runner.validate_build_source(receipt, work, schedule)
                (work / 'packages/launcher/src/main.rs').write_text('fn main(){assert!(false);}\n')
                with self.assertRaises(ValueError):runner.validate_build_source(receipt, work, schedule)
                (work / 'packages/launcher/src/main.rs').write_text((original / 'packages/launcher/src/main.rs').read_text())
                malicious = {**receipt, 'files': [*files, {'path': 'packages/launcher/build.rs', 'sha256': hashlib.sha256(b'fn main(){}').hexdigest()}]}
                (work / 'packages/launcher/build.rs').write_bytes(b'fn main(){}')
                with self.assertRaises(ValueError):runner.validate_build_source(malicious, work, schedule)


if __name__ == '__main__':unittest.main()
