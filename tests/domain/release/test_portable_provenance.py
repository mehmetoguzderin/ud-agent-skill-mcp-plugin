"""Independent portable artifact identities; no publisher authority is inferred."""
import base64
from hashlib import sha256
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from ud_agent.domain import release, maintenance
from ud_agent.domain._artifacts import archive, read_archive
from ud_agent.domain._release_provenance import provenance, verify_manifest_provenance
from ud_agent.errors import InvalidInput, WorkerError

RULES = ('data.json', 'deprels.json', 'edeprels.json', 'feats.json', 'tospace.json', 'udeprels.json', 'upos.json')


class PortableProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(); self.root = Path(self.temporary.name)
        self.context = self.root / 'context'; (self.context / 'rules').mkdir(parents=True)
        self.rule_bytes = {name: json.dumps({'family': name}, separators=(',', ':')).encode() for name in RULES}
        for name, data in self.rule_bytes.items(): (self.context / 'rules' / name).write_bytes(data)
        self.hashes = {name: sha256(data).hexdigest() for name, data in self.rule_bytes.items()}
        self.context_hash = sha256(json.dumps(self.hashes, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        self.manifest = {'rule_dir': 'rules', 'rules': self.hashes, 'context_sha256': self.context_hash, 'tools_commit': 'a' * 40}
        (self.context / 'context.json').write_text(json.dumps(self.manifest))
        self.files = {'a.conllu': b'# sent_id = one\n1\tHi\thi\tINTJ\t_\t_\t0\troot\t_\t_\n\n', 'LICENSE.txt': b'Copyright treebank authors. CC-BY-SA-4.0\n'}
        for name, data in self.files.items(): (self.root / name).write_bytes(data)
        self.args = {'working_tree_path': str(self.root), 'ud_context_path': str(self.context / 'context.json'), 'options': {'language_code': 'en', 'file_paths': list(self.files)}}
        self.report = {'passed': True, 'incidents': [], 'coverage': {'content': 'completed'}}

    def tearDown(self): self.temporary.cleanup()

    def test_handover_binds_exact_rule_source_and_license_bytes_without_local_paths(self):
        result = maintenance.handover_package_build({**self.args, 'output_dir_path': '/requested/output'})
        record = result['manifest']; proof = record['provenance']
        self.assertEqual(record['context'], 'urn:ud-agent:context:sha256:' + self.context_hash)
        expected = [{'path': name, 'size_bytes': len(data), 'sha256': sha256(data).hexdigest()} for name, data in sorted(self.files.items())]
        encoded = (json.dumps(expected, sort_keys=True, ensure_ascii=False, indent=2) + '\n').encode()
        self.assertEqual(proof['selected_files_sha256'], sha256(encoded).hexdigest())
        self.assertEqual(proof['context']['rules'], [{'path': name, 'size_bytes': len(self.rule_bytes[name]), 'sha256': self.hashes[name]} for name in RULES])
        self.assertEqual(proof['licenses']['files'], [next(row for row in expected if row['path'] == 'LICENSE.txt')])
        self.assertEqual(proof['licenses']['status'], 'present')
        self.assertEqual(proof['upstream_revision_declarations'][0]['commit'], 'a' * 40)
        self.assertIn('declaration', proof['upstream_revision_declarations'][0]['evidence'])
        source = next(row for row in proof['implementation']['source']['files'] if row['path'] == 'errors.py')
        original = Path(__file__).resolve().parents[3] / 'workers/ud/src/ud_agent/errors.py'
        self.assertEqual(source['sha256'], sha256(original.read_bytes()).hexdigest())
        # Frozen Unicode behavior and the userspace capability table are
        # implementation inputs, not disposable cache or ambient metadata.
        for filename in ('unicode_casefold.json', 'userspace_operations.json'):
            entry = next(row for row in proof['implementation']['source']['files'] if row['path'] == filename)
            actual = original.parent / filename
            self.assertEqual(entry['sha256'], sha256(actual.read_bytes()).hexdigest())
            self.assertEqual(entry['size_bytes'], actual.stat().st_size)
        self.assertNotIn(str(self.root), json.dumps(record))
        contents = read_archive(base64.b64decode(result['artifacts'][0]['content_base64']))
        self.assertEqual(json.loads(contents['handover-manifest.json']), record)

    def test_relocated_identical_context_produces_identical_portable_provenance(self):
        second = self.root / 'relocated'; shutil.copytree(self.context, second)
        before = provenance(self.files, self.args)
        after = provenance(self.files, {**self.args, 'ud_context_path': str(second / 'context.json')})
        self.assertEqual(before, after)
        without_license = provenance({'a.conllu': self.files['a.conllu']}, self.args)
        self.assertEqual(without_license['licenses']['status'], 'not_selected')
        self.assertEqual(without_license['licenses']['files'], [])

    def test_upstream_revision_declarations_are_portable_repository_names_not_worker_paths(self):
        self.manifest['repository_checks'] = {'source_receipts': {'docs': {'repository': 'UniversalDependencies/docs', 'commit': 'b' * 40}}}
        (self.context / 'context.json').write_text(json.dumps(self.manifest))
        proof = provenance(self.files, self.args)
        self.assertEqual(proof['upstream_revision_declarations'][1]['repository'], 'UniversalDependencies/docs')
        for repository in ['/opt/worker/docs', '../docs', {'path': '/private/docs'}, 'https://host/owner/docs', 'owner/repo\n']:
            with self.subTest(repository=repository):
                self.manifest['repository_checks']['source_receipts']['docs']['repository'] = repository
                (self.context / 'context.json').write_text(json.dumps(self.manifest))
                with self.assertRaisesRegex(InvalidInput, 'portable owner/repository'):
                    provenance(self.files, self.args)

    def test_installed_context_source_receipts_retain_nested_upstream_commit_and_archive_identities(self):
        source = {'repository': 'UniversalDependencies/docs', 'commit': 'b' * 40, 'archive_sha256': 'c' * 64}
        self.manifest['repository_checks'] = {'source_receipts': {'docs': {'source': source, 'files': {'LICENSE.txt': 'd' * 64}}}}
        (self.context / 'context.json').write_text(json.dumps(self.manifest))
        proof = provenance(self.files, self.args)
        self.assertEqual(proof['upstream_revision_declarations'][1], {**source, 'evidence': 'context-manifest declaration'})
        source['archive_sha256'] = '/opt/unchecked.tar'
        (self.context / 'context.json').write_text(json.dumps(self.manifest))
        with self.assertRaisesRegex(InvalidInput, 'archive identity'):
            provenance(self.files, self.args)

    def test_context_or_license_drift_after_planning_cannot_build_the_prior_candidate(self):
        with patch('ud_agent.domain.validation.validation_report', return_value=self.report):
            plan = release.release_plan({**self.args, 'target_release': '2.99'})
        (self.root / 'plan.json').write_text(json.dumps(plan))
        (self.context / 'rules/upos.json').write_bytes(b'changed rules')
        with self.assertRaises(WorkerError) as error:
            release.release_candidate_build({**self.args, 'release_plan_path': 'plan.json', 'output_dir_path': '/out'})
        self.assertEqual(error.exception.code, 'CONTEXT_RULE_HASH_MISMATCH')
        (self.context / 'rules/upos.json').write_bytes(self.rule_bytes['upos.json'])
        (self.root / 'LICENSE.txt').write_bytes(b'changed license')
        with self.assertRaises(WorkerError) as error:
            release.release_candidate_build({**self.args, 'release_plan_path': 'plan.json', 'output_dir_path': '/out'})
        self.assertEqual(error.exception.code, 'CONFLICT')

    def test_new_candidate_provenance_rejects_forged_license_context_and_selected_byte_identities(self):
        proof = provenance(self.files, self.args)
        record = {'context': proof['context']['identity'], 'provenance': proof}
        verify_manifest_provenance(record, self.files)
        changes = [lambda value: value['provenance'].update(selected_files_sha256='f' * 64), lambda value: value['provenance']['licenses']['files'][0].update(sha256='f' * 64), lambda value: value['provenance']['context']['rules'].append(value['provenance']['context']['rules'][0]), lambda value: value.update(context='/opt/private/context.json')]
        for change in changes:
            value = json.loads(json.dumps(record)); change(value)
            with self.subTest(change=change), self.assertRaises(InvalidInput): verify_manifest_provenance(value, self.files)
        # Historical candidate readers remain compatible; no provenance is fabricated.
        verify_manifest_provenance({'context': '/historical/context'}, self.files)

    def test_candidate_roundtrip_and_deposit_preserve_portable_manifest_and_reject_changed_validation_context(self):
        with patch('ud_agent.domain.validation.validation_report', return_value=self.report):
            plan = release.release_plan({**self.args, 'target_release': '2.99'}); (self.root / 'plan.json').write_text(json.dumps(plan))
            candidate = release.release_candidate_build({**self.args, 'release_plan_path': 'plan.json', 'output_dir_path': '/out'})
        packed = base64.b64decode(candidate['artifacts'][0]['content_base64']); (self.root / 'candidate.tar').write_bytes(packed)
        (self.root / 'deposit.json').write_text(json.dumps({'title': 'Treebank', 'license': 'CC-BY-SA-4.0'}))
        args = {**self.args, 'release_candidate_path': 'candidate.tar', 'deposit_metadata_path': 'deposit.json', 'output_dir_path': '/out'}
        with patch('ud_agent.domain.validation.validation_report', return_value=self.report):
            result = release.release_deposit_prepare(args)
        document = json.loads(base64.b64decode(result['artifacts'][0]['content_base64']))
        self.assertEqual(document['candidate_manifest'], candidate['manifest'])
        self.assertTrue(result['ready'])
        self.manifest['tools_commit'] = 'b' * 40; (self.context / 'context.json').write_text(json.dumps(self.manifest))
        with self.assertRaises(WorkerError) as error:
            release.release_deposit_prepare(args)
        self.assertEqual(error.exception.code, 'CONFLICT')
