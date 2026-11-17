"""CONTROL and inert runtime projection proofs; generated programs remain data."""
from contextlib import contextmanager
from difflib import unified_diff
import hashlib
import importlib.abc
import importlib.metadata
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]


def load_module(name, file):
    spec = importlib.util.spec_from_file_location(name, file)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


proof = load_module('python_generation_projection_proof', ROOT / 'scripts/quality/prove-python-generation.py')
projection = load_module('python_generation_projection_data', ROOT / 'scripts/quality/python-runtime-projection.py')
candidate_driver = load_module('python_generation_candidate_driver', ROOT / 'scripts/quality/mutmut-driver.py')
candidate_operators = load_module('python_generation_candidate_operators', ROOT / 'scripts/quality/python-operators.py')
DEPENDENCIES = {'mutmut-driver.py': candidate_driver, 'python-operators.py': candidate_operators,
                'python-runtime-projection.py': projection}


def digest(content):
    return hashlib.sha256(content).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode()


def dependency_data(name):
    """Only fixture data uses same-source originals; behavior stays candidate-owned."""
    if name not in DEPENDENCIES:
        raise ValueError('unknown fixture dependency data')
    protected = ROOT.name == 'mutants'
    origin = ROOT.parent if protected else ROOT
    def read(file, maximum):
        descriptor = os.open(file, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
        with os.fdopen(descriptor, 'rb') as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > maximum or (protected and (before.st_uid != 0 or before.st_mode & 0o022)):
                raise ValueError('fixture original data is not an ordinary protected input')
            content = stream.read(maximum + 1); after = os.fstat(stream.fileno())
            if len(content) != before.st_size or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                raise ValueError('fixture original data changed during its held read')
            return content
    relative = 'scripts/quality/' + name
    selected = origin
    for part in relative.split('/'):
        selected /= part
        if selected.is_symlink():
            raise ValueError('fixture original data cannot contain links')
    content = read(selected, 1024 ** 2)
    if protected:
        receipt = json.loads(read(ROOT.parent.parent / 'snapshot.json', 64 * 1024 ** 2))
        rows = [row for row in receipt.get('files', []) if row.get('path') == relative]
        if receipt.get('qualification') != 'mutation-source-copy' or receipt.get('copy') != str(origin) or len(rows) != 1 or rows[0].get('sha256') != digest(content) or rows[0].get('size') != len(content):
            raise ValueError('fixture original data differs from its same-candidate receipt')
    return content


class CandidateDependencyLoader(importlib.abc.Loader):
    def __init__(self, candidate):
        self.candidate = candidate

    def create_module(self, spec):
        return self.candidate

    def exec_module(self, value):
        if value is not self.candidate:
            raise ValueError('fixture dependency loader returned a different module')


@contextmanager
def candidate_dependencies(source):
    """Model only the three data-fixture imports; real proof loaders remain real.

    This unit boundary does not certify copying/importing compiled source.
    Actual discovery/prove must independently use their original real loaders.
    """
    expected = {source / 'scripts/quality' / name: candidate for name, candidate in DEPENDENCIES.items()}
    original = importlib.util.spec_from_file_location
    def selected(name, file, *args, **kwargs):
        candidate = expected.get(Path(file)) if file is not None else None
        if candidate is not None:
            return importlib.util.spec_from_loader(name, CandidateDependencyLoader(candidate), origin=str(candidate.__file__))
        return original(name, file, *args, **kwargs)
    with patch.object(importlib.util, 'spec_from_file_location', selected):
        yield


class Fixture:
    def __init__(self, root, projected=True):
        self.source, self.state = root / 'source', root / 'state'
        (self.source / 'scripts/quality').mkdir(parents=True)
        (self.source / 'quality/reviews').mkdir(parents=True)
        for name in DEPENDENCIES:
            (self.source / 'scripts/quality' / name).write_bytes(dependency_data(name))
        self.original = 'def accepted(value):\n    return value > 2\n'
        (self.source / 'scripts/sample.py').write_text(self.original)
        (self.source / 'scripts/zero.py').write_text('# explicit zero-ID module\n')
        registry = {'schema_version': 1, 'version': 'empty-data-fixture', 'rows': []}
        (self.source / 'quality/python-operator-repairs.json').write_bytes(canonical(registry))
        (self.source / 'quality/reviews/python-operator-repairs-domain-review.json').write_bytes(canonical({
            'registry_sha256': digest(canonical(registry)), 'registry_version': registry['version'],
            'reviewer': 'domain_completion', 'rows': [], 'dependency_source_sha256': {},
        }))
        (self.source / 'quality/python-graph-operators.activation.json').write_bytes(canonical({'schema_version': 1, 'active': False}))
        files = [{'path': file.relative_to(self.source).as_posix(), 'sha256': digest(file.read_bytes())}
                 for file in sorted(self.source.rglob('*.py'))]
        self.receipt = {'sha256': 'a' * 64, 'files': files}
        self.subject = root / 'subject.json'
        self.subject.write_bytes(canonical(self.receipt))
        self.keys = ['scripts.sample.x_accepted__mutmut_1', 'scripts.sample.x_accepted__mutmut_2']
        full, spans = '# unchanged generated scaffold\n', {}
        for name, body in [('x_accepted__mutmut_orig', 'value > 2'),
                           ('x_accepted__mutmut_1', 'value >= 2'), ('x_accepted__mutmut_2', 'value < 2')]:
            fragment = f'def {name}(value):\n    return {body}\n'
            start = full.count('\n') + 1
            spans[name] = [start, start + 1]
            full += fragment + '\n'
        full += 'def accepted(value):\n    return x_accepted__mutmut_orig(value)\n'
        self.full, self.index = full, {'version': 1, 'spans': spans}
        operators = candidate_operators
        profile = {'version': operators.VERSION, 'mutmut': '3.8.1', 'libcst': importlib.metadata.version('libcst'),
                   'repairs': ['IfExp-word-separators', 'typed-ABI-argument-v1'], 'generation_mode': 'deterministic-sequential'}
        hashes = {item['path']: item['sha256'] for item in files}
        inventory = []
        for key, body in zip(self.keys, ['value >= 2', 'value < 2']):
            replacement = f'def accepted(value):\n    return {body}\n'
            definition = {'tool': 'mutmut', 'version': '3.8.1', 'generation_profile': profile,
                          'generation_repairs': [], 'file': 'scripts/sample.py',
                          'location': {'line': 1, 'end_line': 2, 'column': 0},
                          'original_function': self.original, 'replacement_function': replacement,
                          'diff': '\n'.join(unified_diff(self.original.splitlines(), replacement.splitlines(),
                                                       fromfile='scripts/sample.py', tofile='scripts/sample.py', lineterm=''))}
            inventory.append({'id': key, 'file': 'scripts/sample.py', 'source_sha256': hashes['scripts/sample.py'],
                              'definition': definition, 'definition_sha256': digest(canonical(definition))})
        discovery = {'scope_complete': True, 'source_tree_sha256': self.receipt['sha256'],
                     'inventory': [{key: item[key] for key in ('id', 'file', 'source_sha256')} for item in inventory]}
        self.state.mkdir()
        self.write(self.state / 'discovery.json', canonical(discovery))
        self.plan = {'scope_complete': True, 'source_tree_sha256': self.receipt['sha256'],
                     'discovery_sha256': digest(canonical(discovery)), 'generation_profile': profile,
                     'generation_repairs': [], 'inventory': inventory, 'scheduled': len(inventory)}
        self.write(self.state / 'schedule.json', canonical(self.plan))
        self.rows, self.controls = [], {}
        for item in files:
            name = item['path']
            content, index, keys = ((full, self.index, self.keys) if name == 'scripts/sample.py'
                                    else ((self.source / name).read_text(), {'version': 1, 'spans': {}}, []))
            metadata = canonical({'exit_code_by_key': dict.fromkeys(keys)})
            self.write(self.state / 'work/mutants' / name, content.encode())
            self.write(self.state / 'work/mutants' / (name + '.spans'), canonical(index))
            self.write(self.state / 'work/mutants' / (name + '.meta'), metadata)
            self.write(self.state / 'generation-metadata' / (name + '.meta'), metadata)
            self.controls[name] = (content, index['spans'])
            if projected:
                control_name = 'control/python-projection/files/' + name
                self.write(self.state / control_name, content.encode())
                self.write(self.state / (control_name + '.spans'), canonical(index))
                baseline = projection.project_source(content, index['spans'], None, name).encode()
                self.rows.append({'path': name, 'source_sha256': item['sha256'],
                                  'control': self.descriptor(control_name), 'spans': self.descriptor(control_name + '.spans'),
                                  'generation_metadata': self.descriptor('generation-metadata/' + name + '.meta'),
                                  'mutants': [{'id': key, 'name': key.rpartition('.')[2]} for key in keys],
                                  'baseline': {'sha256': digest(baseline), 'size_bytes': len(baseline)}})
        if projected:
            sdk = {'schema_version': 1, 'version': projection.VERSION,
                   'helper_sha256': hashes['scripts/quality/python-runtime-projection.py'],
                   'distribution': 'mutmut', 'distribution_version': '3.8.1',
                   'installed_path': 'python/lib/python3.14/site-packages/mutmut/mutation/trampoline.py',
                   'original_wheel': {'filename': 'mutmut-3.8.1-py3-none-any.whl', 'sha256': 'c' * 64, 'size_bytes': 1234}}
            upstream, adapter = b'# retained original trampoline fixture\n', b'# fixed SDK adapter fixture\n'
            for field, name, content in [('upstream_source', 'python-trampoline-upstream.py', upstream),
                                         ('adapter_source', 'python-trampoline-adapter.py', adapter),
                                         ('derived_source', 'python-trampoline-derived.py', upstream + adapter)]:
                self.write(self.state / ('runtime-' + name), content)
                sdk[field] = {'path': name, 'sha256': digest(content), 'size_bytes': len(content)}
            self.write(self.state / 'runtime-python-trampoline-installed.py', upstream + adapter)
            self.write(self.state / 'runtime-input-receipt.json', canonical({'python_runtime_projection': sdk,
                       'python_packages': [{'name': 'mutmut', 'version': '3.8.1', 'hash': 'sha256:' + 'c' * 64,
                                            'size': 1234, 'url': 'https://example.invalid/mutmut-3.8.1-py3-none-any.whl'}]}))
            self.manifest = {'schema_version': 1, 'version': projection.VERSION,
                             'helper_sha256': hashes['scripts/quality/python-runtime-projection.py'],
                             'source_tree_sha256': self.receipt['sha256'], 'files': self.rows}
            self.write_manifest()
            self.admit('collection', None, 100001)

    @staticmethod
    def write(file, content):
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_bytes(content)

    def descriptor(self, name):
        content = (self.state / name).read_bytes()
        return {'path': name, 'sha256': digest(content), 'size_bytes': len(content)}

    def write_manifest(self):
        self.manifest_bytes = canonical(self.manifest) + b'\n'
        self.write(self.state / 'control/python-projection/manifest.json', self.manifest_bytes)

    def admit(self, mode, key, uid):
        items = []
        active = key.rpartition('.')[2] if key is not None else None
        for row in self.rows:
            name = row['path']; selected = active if name == 'scripts/sample.py' else None
            projected = projection.project_source(*self.controls[name], selected, name).encode()
            self.write(self.state / 'work/mutants' / name, projected)
            items.append({'path': name, 'control_sha256': row['control']['sha256'],
                          'spans_sha256': row['spans']['sha256'], 'projected_sha256': digest(projected),
                          'size_bytes': len(projected), 'active_name': selected})
        witness = {'schema_version': 1, 'version': projection.VERSION, 'mode': mode, 'active_key': key,
                   'manifest_sha256': digest(self.manifest_bytes), 'files': items, 'guard_exit_code': 125,
                   'projection_sequence': uid}
        record = {'uid': uid, 'projection_sequence': uid, 'collected': True,
                  'projection': witness, 'projection_sha256': digest(canonical(witness))}
        context = {'schema_version': 1, 'version': projection.VERSION, 'uid': uid, 'projection_sequence': uid,
                   'helper_sha256': self.manifest['helper_sha256'], 'manifest_sha256': digest(self.manifest_bytes),
                   'mode': mode, 'active_key': key, 'projection_sha256': record['projection_sha256'], 'files': items}
        self.write(self.state / 'work/mutants/.ud-runtime-projection.json', canonical(context) + b'\n')
        record['projection_context'] = self.descriptor('work/mutants/.ud-runtime-projection.json')
        file = self.state / 'control/jobs' / f'{uid}.json'
        self.write(file, canonical(record))
        return file, record

    def prove(self):
        with candidate_dependencies(self.source):
            return proof.prove(self.source, self.state, self.subject)


class PythonGenerationProjectionProofTests(unittest.TestCase):
    def test_full_control_definitions_survive_inert_runtime_and_every_raw_witness_is_retained(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(Path(temporary))
            result = fixture.prove()
            expected = [{key: row[key] for key in ('id', 'file', 'source_sha256', 'definition_sha256')}
                        for row in fixture.plan['inventory']]
            self.assertEqual(result['inventory'], expected)
            actual = (fixture.state / 'work/mutants/scripts/sample.py').read_text()
            self.assertNotEqual(actual, fixture.full)
            self.assertNotIn('return value >= 2', actual)
            self.assertEqual((fixture.state / 'control/python-projection/files/scripts/sample.py').read_text(), fixture.full)
            paths = {item['path'] for item in result['raw_artifacts']}
            self.assertTrue({'control/python-projection/manifest.json', 'control/jobs/100001.json',
                             'control/python-projection/files/scripts/sample.py',
                             'control/python-projection/files/scripts/sample.py.spans',
                             'generation-metadata/scripts/sample.py.meta', 'work/mutants/scripts/sample.py',
                             'work/mutants/.ud-runtime-projection.json', 'runtime-input-receipt.json',
                             'runtime-python-trampoline-upstream.py', 'runtime-python-trampoline-adapter.py',
                             'runtime-python-trampoline-derived.py', 'runtime-python-trampoline-installed.py'} <= paths)
            zero = next(row for row in result['source_materializations'] if row['source'] == 'scripts/zero.py')
            self.assertEqual(zero['mutant_ids'], [])
            self.assertIn('control/python-projection/manifest.json', {item['path'] for item in zero['artifacts']})
            self.assertNotIn('outcomes', result)

    def test_latest_sequence_controls_runtime_bytes_without_redefining_any_inventory(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(Path(temporary))
            _, earlier = fixture.admit('active', fixture.keys[0], 100003)
            latest_file, latest = fixture.admit('active', fixture.keys[1], 100002)
            fixture.admit('active', fixture.keys[0], 100004)
            result = fixture.prove()
            self.assertEqual([item['id'] for item in result['inventory']], fixture.keys)
            self.assertIn('return value >= 2', (fixture.state / 'work/mutants/scripts/sample.py').read_text())
            self.assertNotIn('return value < 2', (fixture.state / 'work/mutants/scripts/sample.py').read_text())
            self.assertTrue({'control/jobs/100001.json', 'control/jobs/100002.json', 'control/jobs/100003.json',
                             'control/jobs/100004.json'} <= {item['path'] for item in result['raw_artifacts']})
            latest['projection_sequence'] = earlier['projection_sequence']
            fixture.write(latest_file, canonical(latest))
            with self.assertRaisesRegex(ValueError, 'witness is missing, repeated or not collected'):
                fixture.prove()

    def test_rejects_deterministically_forged_projection_even_when_witness_hashes_are_rewritten(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(Path(temporary))
            file, record = fixture.admit('collection', None, 100002)
            runtime = fixture.state / 'work/mutants/scripts/sample.py'
            wrong = runtime.read_bytes().replace(b'(125)', b'(124)')
            runtime.write_bytes(wrong)
            row = next(item for item in record['projection']['files'] if item['path'] == 'scripts/sample.py')
            row.update(projected_sha256=digest(wrong), size_bytes=len(wrong))
            record['projection_sha256'] = digest(canonical(record['projection']))
            fixture.write(file, canonical(record))
            with self.assertRaisesRegex(ValueError, 'deterministic full CONTROL replay'):
                fixture.prove()

    def test_missing_control_or_manifest_cannot_fall_back_to_projected_runtime(self):
        for change in ('control', 'manifest', 'source', 'witness'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as temporary:
                fixture = Fixture(Path(temporary))
                if change == 'control':
                    (fixture.state / 'control/python-projection/files/scripts/sample.py').unlink()
                elif change == 'manifest':
                    (fixture.state / 'control/python-projection/manifest.json').unlink()
                elif change == 'source':
                    fixture.rows[-1]['source_sha256'] = 'b' * 64; fixture.write_manifest()
                else:
                    (fixture.state / 'control/jobs/100001.json').unlink()
                with self.assertRaises((ValueError, OSError)):
                    fixture.prove()

    def test_omitted_numbered_control_function_is_rejected_despite_co_rewritten_metadata(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(Path(temporary))
            row = next(item for item in fixture.rows if item['path'] == 'scripts/sample.py')
            metadata = fixture.state / row['generation_metadata']['path']
            metadata.write_bytes(canonical({'exit_code_by_key': {fixture.keys[0]: None}}))
            row['generation_metadata'] = fixture.descriptor(row['generation_metadata']['path'])
            row['mutants'].pop(); fixture.write_manifest()
            with self.assertRaisesRegex(ValueError, 'omits or repeats a full CONTROL operator'):
                fixture.prove()

    def test_legacy_full_generated_reader_remains_unchanged_without_new_metadata(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(Path(temporary), projected=False)
            old_helper = 'scripts/quality/python-runtime-projection.py'
            (fixture.source / old_helper).unlink()
            fixture.receipt['files'] = [row for row in fixture.receipt['files'] if row['path'] != old_helper]
            fixture.subject.write_bytes(canonical(fixture.receipt))
            result = fixture.prove()
            self.assertEqual([row['id'] for row in result['inventory']], fixture.keys)
            self.assertEqual((fixture.state / 'work/mutants/scripts/sample.py').read_text(), fixture.full)
            self.assertFalse(any(row['path'].startswith('control/') for row in result['raw_artifacts']))

    def test_actual_runtime_replacement_and_linked_control_fail_closed(self):
        for change in ('runtime', 'link'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as temporary:
                fixture = Fixture(Path(temporary))
                if change == 'runtime':
                    (fixture.state / 'work/mutants/scripts/sample.py').write_text(fixture.full)
                else:
                    control = fixture.state / 'control/python-projection/files/scripts/sample.py'
                    other = Path(temporary) / 'outside.py'; other.write_bytes(control.read_bytes())
                    control.unlink(); control.symlink_to(other)
                with self.assertRaisesRegex(ValueError, 'actual runtime projection differs|cannot contain links'):
                    fixture.prove()

    def test_collected_record_with_cancelled_descendant_cannot_authorize_projection(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(Path(temporary))
            file, record = fixture.admit('collection', None, 100002)
            record['owned_descendants_cancelled'] = [{'pid': 123, 'start_ticks': 456}]
            fixture.write(file, canonical(record))
            with self.assertRaisesRegex(ValueError, 'not collected'):
                fixture.prove()

    def test_unbound_helper_unknown_activation_and_incomplete_witness_are_rejected(self):
        for change in ('helper', 'unknown-key', 'missing-module', 'witness-hash', 'sdk-wheel', 'sdk-installed', 'sdk-derived'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as temporary:
                fixture = Fixture(Path(temporary))
                file, record = fixture.admit('collection', None, 100002)
                if change == 'helper':
                    helper = fixture.source / 'scripts/quality/python-runtime-projection.py'
                    helper.write_bytes(helper.read_bytes() + b'\n# unbound helper replacement\n')
                elif change == 'unknown-key':
                    record['projection'].update(mode='active', active_key='scripts.sample.x_accepted__mutmut_999')
                elif change == 'missing-module':
                    record['projection']['files'].pop()
                elif change.startswith('sdk-'):
                    sdk_file = fixture.state / 'runtime-input-receipt.json'
                    runtime = json.loads(sdk_file.read_bytes())
                    if change == 'sdk-wheel':
                        runtime['python_runtime_projection']['original_wheel']['sha256'] = 'd' * 64
                    elif change == 'sdk-installed':
                        (fixture.state / 'runtime-python-trampoline-installed.py').write_bytes(b'# substituted installed adapter\n')
                    else:
                        replacement = b'# independently substituted derived SDK\n'
                        (fixture.state / 'runtime-python-trampoline-derived.py').write_bytes(replacement)
                        runtime['python_runtime_projection']['derived_source'].update(sha256=digest(replacement), size_bytes=len(replacement))
                        (fixture.state / 'runtime-python-trampoline-installed.py').write_bytes(replacement)
                    sdk_file.write_bytes(canonical(runtime))
                else:
                    record['projection_sha256'] = 'b' * 64
                if change != 'witness-hash':
                    record['projection_sha256'] = digest(canonical(record['projection']))
                fixture.write(file, canonical(record))
                with self.assertRaises(ValueError):
                    fixture.prove()

    def test_retained_raw_artifacts_alone_replay_all_control_modules_and_job_witnesses(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); fixture = Fixture(root)
            fixture.admit('stats', None, 100002)
            fixture.admit('active', fixture.keys[1], 100003)
            original = fixture.prove()
            retained = root / 'retained-state'; retained.mkdir()
            for row in original['raw_artifacts']:
                content = (fixture.state / row['path']).read_bytes()
                self.assertEqual((digest(content), len(content)), (row['sha256'], row['size']))
                Fixture.write(retained / row['path'], content)
            shutil.rmtree(fixture.state)
            with candidate_dependencies(fixture.source):
                replayed = proof.prove(fixture.source, retained, fixture.subject)
            self.assertEqual(replayed, original)
            paths = {row['path'] for row in replayed['raw_artifacts']}
            self.assertTrue({f'control/jobs/{uid}.json' for uid in (100001, 100002, 100003)} <= paths)
            self.assertTrue({row['control']['path'] for row in fixture.rows} <= paths)
            self.assertTrue({row['spans']['path'] for row in fixture.rows} <= paths)

    def test_context_is_exact_uid_bound_root_witness_data_and_latest_bytes_are_retained(self):
        for change in ('missing', 'older', 'conflict', 'receipt'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as temporary:
                fixture = Fixture(Path(temporary))
                context_file = fixture.state / 'work/mutants/.ud-runtime-projection.json'
                older = context_file.read_bytes()
                job_file, record = fixture.admit('active', fixture.keys[0], 100002)
                if change == 'missing':
                    context_file.unlink()
                elif change == 'older':
                    context_file.write_bytes(older)
                elif change == 'conflict':
                    context = json.loads(context_file.read_bytes())
                    context['active_key'] = fixture.keys[1]
                    context_file.write_bytes(canonical(context) + b'\n')
                    record['projection_context'] = fixture.descriptor('work/mutants/.ud-runtime-projection.json')
                    fixture.write(job_file, canonical(record))
                else:
                    record['projection_context']['sha256'] = 'b' * 64
                    fixture.write(job_file, canonical(record))
                with self.assertRaises((ValueError, OSError)):
                    fixture.prove()

    def test_dependency_loader_uses_issued_candidate_objects_and_never_executes_copied_programs(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / 'source'
            for name in DEPENDENCIES:
                file = source / 'scripts/quality' / name
                file.parent.mkdir(parents=True, exist_ok=True)
                file.write_text('raise AssertionError("copied fixture program was executed")\n')
            with candidate_dependencies(source):
                for name, candidate in DEPENDENCIES.items():
                    file = source / 'scripts/quality' / name
                    self.assertIs(proof.module('unit_candidate_dependency', file), candidate)
                    self.assertEqual(Path(candidate.__file__).resolve(), (ROOT / 'scripts/quality' / name).resolve())
                    self.assertEqual(file.read_text(), 'raise AssertionError("copied fixture program was executed")\n')


if __name__ == '__main__':
    unittest.main()
