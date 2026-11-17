"""The central replay preserves exact family scope and legacy runtime defaults."""
import hashlib
import importlib.util
import json
import io
from pathlib import Path
import shutil
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location('component_family_integration', ROOT / 'scripts/release/component-closure.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def content(value):
    return {'sha256': hashlib.sha256(value).hexdigest(), 'size_bytes': len(value)}


def binding(value):
    return {'content': content(value), 'sources': [{'form': 'independently-derived-fixture-source'}], 'notices': [{'form': 'original fixture notice'}], 'required_materials': []}


def result(bindings=(), **fields):
    return {'status': 'passed', 'generator_sha256': 'f' * 64, 'bindings': list(bindings), **fields}


class ComponentFamilyIntegrationTests(unittest.TestCase):
    def replay(self, root, families, facts, **options):
        with patch.object(m.component_duties, 'derive', return_value={}):
            return m.replay(root, {'schema_version': 1, 'families': families}, facts, **options)

    def test_locked_family_streams_original_and_reconciles_after_blob_cleanup(self):
        materializer = m.module('ud_fixture_streamed_materializer', 'materialize-replay-inputs.py')
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary); source = base/'source'; assets = base/'assets'; candidate_root = base/'candidate'
            for directory in (source, assets/'collection', candidate_root/'release'): directory.mkdir(parents=True)
            original = base/'original'; original.mkdir(); archive = original/'original.tar.gz'
            program = b'def independent_result():\n    return 17\n'; notice = b'Fixture original license terms\n'
            with tarfile.open(archive, 'w:gz') as target:
                for name, body in [('pkg/file.py', program), ('pkg/LICENSE', notice)]:
                    entry = tarfile.TarInfo(name); entry.size = len(body); target.addfile(entry, io.BytesIO(body))
            expected = {'family': 'ud', 'name': 'independent-fixture', 'version': '1', 'url': 'https://example.invalid/source.tar.gz', **content(archive.read_bytes())}
            row = {**expected, 'path': 'blobs/'+expected['sha256'], 'notice_files': m.locked.source_notices(archive)}
            (original/'blobs').mkdir(); shutil.copyfile(archive, original/row['path'])
            inventory = {'schema_version': 1, 'qualification': 'exact-locked-source-subinventory', 'status': 'passed', 'files': [row]}
            receipt = original/'receipt.json'; receipt.write_text(json.dumps(inventory)); shutil.copyfile(receipt, assets/'collection/receipt.json')
            bundle = base/'bundle'; index = materializer.materials.bundle([('fixture', receipt)], bundle, 2048, [{'sha256': row['sha256'], 'size_bytes': row['size_bytes']}])
            records = []
            for number, name in enumerate(['ud-agent-corresponding-source-index.json', *[part['path'] for part in index['parts']]]):
                shutil.copyfile(bundle/name, candidate_root/'release'/name); value = (candidate_root/'release'/name).read_bytes()
                records.append({'id': 'corresponding-source-index' if number == 0 else index['parts'][number-1]['id'], 'path': 'release/'+name, 'sha256': hashlib.sha256(value).hexdigest(), 'size': len(value)})
            (source/'runtime').mkdir(); (source/'runtime/source-materials.lock.json').write_text(json.dumps({'schema_version': 1, 'index': records[0], 'parts': records[1:]}))
            shutil.rmtree(original); shutil.rmtree(bundle)
            recipe = {'schema_version': 1, 'families': [{'kind': 'locked-source-members', 'sources': 'collection/receipt.json'}]}
            member = {'path': 'worker/file.py', 'architecture': 'data', **content(program)}
            discovery = {'subjects': [{'id': 'fixture', 'role': 'runtime', 'sha256': 'f'*64, 'size_bytes': 1, 'members': [member]}], 'blockers': []}
            facts = m.Facts(); source_inventory = {'sha256': 'a'*64, 'files': []}
            with materializer.SourceParts(source, {'artifacts': records}, candidate_root=candidate_root) as parts:
                with m.inspection.Recorder(source, assets) as recorder, patch.object(m.locked, 'plan', return_value=([expected], {})), patch.object(m.component_duties, 'derive', return_value={}):
                    reports, _ = m.replay(source, recipe, facts, assets_root=assets, wanted={(member['sha256'], member['size_bytes'])}, artifact_ids=('core-oci-index',), recorder=recorder, source_parts=parts)
                    self.assertEqual(reports[0]['status'], 'passed')
                    self.assertFalse((assets/'collection'/row['path']).exists())
                    retained = m.retained_inputs.retain_inspected_originals(source, assets, recipe, frozenset(recorder.paths), recorder)
                    self.assertEqual([(value['sha256'], value['size_bytes']) for value in retained['required_materials']], [(row['sha256'], row['size_bytes'])])
                    coverage = m.reconcile(discovery, facts, source_inventory)
                    self.assertTrue(coverage['complete_available_shipped_component_coverage'])
                    self.assertEqual(coverage['required_materials'], [{'sha256': row['sha256'], 'size_bytes': row['size_bytes']}])
                    catalog = recorder.finish(source_inventory, discovery, retained['required_materials'])
                    checked = m.inspection.verify(catalog, assets, source_inventory['sha256'], catalog['subjects'], required_materials=retained['required_materials'], discovered_subjects=discovery['subjects'], streamed_sources=recorder.streamed_sources)
                    self.assertTrue(checked['verified'])
                    altered = dict(recorder.streamed_sources); key = next(iter(altered)); altered[key] = {**altered[key], 'sha256': '0'*64}
                    with self.assertRaisesRegex(ValueError, 'streamed source observation differs'):
                        m.inspection.verify(catalog, assets, source_inventory['sha256'], catalog['subjects'], required_materials=retained['required_materials'], discovered_subjects=discovery['subjects'], streamed_sources=altered)
                # Exercise the same path through the actual closure entrypoint,
                # including final retention and inspection reconciliation.
                (source/'LICENSE').write_text('Fixture authored license\n')
                artifact = candidate_root/'release'/'core.oci'; artifact.write_bytes(b'fixture OCI subject')
                artifact_record = {'id': 'core-oci-index', 'path': 'release/core.oci', 'sha256': hashlib.sha256(artifact.read_bytes()).hexdigest(), 'size': artifact.stat().st_size}
                shipped = {'subjects': [{'id': artifact_record['id'], 'role': 'runtime', 'sha256': artifact_record['sha256'], 'size_bytes': artifact_record['size'], 'members': [member], 'colocated_preferred_sources': []}], 'blockers': []}
                candidate = {'source_tree_sha256': source_inventory['sha256'], 'runtime_lock_sha256': 'b'*64, 'artifacts': [artifact_record, *records]}
                with patch.object(m.locked, 'plan', return_value=([expected], {})), patch.object(m.component_duties, 'derive', return_value={}), patch.object(m.shipped, 'collect', return_value=shipped), patch.object(m, 'source_inventory', return_value=source_inventory):
                    report = m.derive(source, candidate, recipe, assets_root=assets, candidate_root=candidate_root, available_targets=True, source_parts=parts)
                self.assertTrue(report['complete_available_shipped_component_coverage'])
                self.assertEqual(report['inspection_inputs']['unretained_inputs'], [])
                self.assertFalse((assets/'collection'/row['path']).exists())

    def test_owned_uv_replay_receives_only_independently_admitted_source_declarations(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in ('rust.json', 'packages.json', 'providers.json'): (root / name).write_text('{}')
            recipe = {'kind': 'rust', 'rust_sources': 'rust.json', 'package_sources': 'packages.json', 'provider_sources': 'providers.json'}
            declarations = {'a' * 64: {'id': 'exact-reviewed-uv'}}
            with patch.object(m, 'proprietary_declarations', return_value=declarations), patch.object(m.rust, 'derive', return_value=result(cargo_bindings=[])) as derive, patch.object(m, 'record_package_notices'):
                self.replay(root, [recipe], m.Facts())
            self.assertIs(derive.call_args.kwargs['owned_uv_declarations'], declarations)
            with patch.object(m, 'proprietary_declarations', side_effect=ValueError('independent review is stale')), patch.object(m.rust, 'derive') as derive, self.assertRaisesRegex(ValueError, 'independent review is stale'):
                self.replay(root, [recipe], m.Facts())
            derive.assert_not_called()

    def test_fixed_family_runtime_default_and_explicit_runtime_are_forwarded_without_admitting_unknown_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); assets = root / 'assets'; runtime = root / 'runtime'
            discovery = {'subjects': []}; own = binding(b'known readable form'); unknown = content(b'MZ foreign binary')
            for selected in (None, runtime):
                facts = m.Facts()
                with patch.object(m.packaged_data, 'derive', return_value=result([own])) as packaged, patch.object(m.render_components, 'derive', return_value=result()) as render, patch.object(m.worker_metadata, 'derive', return_value=result()) as metadata:
                    reports, _ = self.replay(root, [{'kind': 'packaged-data'}, {'kind': 'native-render'}, {'kind': 'authored-worker-metadata', 'contexts': {}}], facts, assets_root=assets, runtime_root=selected, discovery=discovery)
                for call in (packaged, render, metadata):
                    self.assertEqual(call.call_args.args[2], assets if selected is None else runtime)
                self.assertEqual([row['status'] for row in reports], ['passed'] * 3)
                self.assertIn((own['content']['sha256'], own['content']['size_bytes']), facts.by_content)
                self.assertNotIn((unknown['sha256'], unknown['size_bytes']), facts.by_content)
            with self.assertRaisesRegex(ValueError, 'actual discovered subjects'):
                self.replay(root, [{'kind': 'packaged-data'}], m.Facts(), assets_root=assets)

    def python_fixture(self, root):
        (root / 'runtime/materials').mkdir(parents=True)
        (root / 'runtime/runtime.lock.json').write_text(json.dumps({'packs': {'core': {}}}))
        (root / 'runtime/materials/pip-distlib-sources.lock.json').write_text(json.dumps({'components': [{'name': 'pip', 'version': '26.2.2'}]}))
        for name in ('source.json', 'provenance.json', 'wheel-sources.json'): (root / name).write_text('{}')
        for name in ('pip-sources', 'pip-wheel'): (root / name).mkdir()
        recipe = {'kind': 'oci-python-provider', 'pack': 'core', 'platform': 'linux/arm64', 'sources': 'source.json', 'provenance': 'provenance.json'}
        original = {'sources': [{'sha256': 'a' * 64, 'size_bytes': 12}], 'notices': [{'notice': 'original pip license'}], 'members': [], 'foreign_launchers': [], 'wheel': content(b'original pip wheel'), 'static_runtime_condition': {}, 'status': 'passed', 'generator_sha256': 'e' * 64}
        provider = result(source={'sha256': 'b' * 64, 'size_bytes': 13}, provider={'manifest': 'publisher-pinned'}, component={'identity': 'CPython'}, config_digest='sha256:' + 'c' * 64, notices=[{'notice': 'CPython-specific-not-for-configs'}], metadata_materials=[], provider_source_forms=[], installed_source_forms=[], installed_script_generator={'original_pip_template': 'verified'})
        return recipe, original, provider

    def test_base_configs_preserve_self_source_comments_without_assigning_cpython_terms(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); recipe, _, provider = self.python_fixture(root)
            form = {'content': content(b'# original publisher configuration\n'), 'image_path': 'etc/example.conf', 'form': 'readable-original'}
            provider['provider_source_forms'] = [form]; facts = m.Facts()
            with patch.object(m.oci_python, 'derive', return_value=provider), patch.object(m.pip_components, 'derive') as pip:
                self.replay(root, [recipe], facts, artifact_ids=('core-oci-index',))
            row = next(iter(facts.rows.values())); notices = facts.relationships[row['notices_sha256']]
            self.assertEqual(notices[0]['sha256'], form['content']['sha256'])
            self.assertIn('no SPDX, authorship or license assignment inferred', notices[0]['scope'])
            self.assertNotIn(provider['notices'][0], notices)
            pip.assert_not_called()

    def test_installed_forms_require_exact_package_notices_and_original_pip_generator(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); recipe, original, provider = self.python_fixture(root)
            forms = [{'content': content(b'pip RECORD'), 'package': {'name': 'pip', 'version': '26.2.2'}, 'image_path': 'pip/RECORD'}, {'content': content(b'locked RECORD'), 'package': {'name': 'Some.Package', 'version': '1'}, 'image_path': 'some/RECORD'}]
            provider['installed_source_forms'] = forms
            wheel = {'package': {'name': 'some_package', 'version': '1'}, 'source': {'sha256': 'd' * 64, 'size_bytes': 14}, 'original_wheel_notices': [{'notice': 'locked wheel notice'}], 'original_source_notices': [{'notice': 'locked source notice'}]}
            wheel_recipe = {'kind': 'python-wheels', 'sources': 'wheel-sources.json'}
            pip_recipe = {'kind': 'pip-runtime', 'original_sources': 'pip-sources', 'wheel_base': 'pip-wheel'}
            facts = m.Facts()
            with patch.object(m.oci_python, 'derive', return_value=provider), patch.object(m.pip_components, 'derive', return_value=original) as pip, patch.object(m, 'wheel_facts', return_value=result([wheel], pending_declarations=[])):
                self.replay(root, [wheel_recipe, recipe, pip_recipe], facts, artifact_ids=('core-oci-index',))
            self.assertEqual(pip.call_count, 1)
            package_fact = next(row for row in facts.rows.values() if row['sha256'] == forms[1]['content']['sha256'])
            self.assertEqual(facts.relationships[package_fact['notices_sha256']], original['notices'] + wheel['original_wheel_notices'] + wheel['original_source_notices'])
            self.assertEqual(facts.relationships[package_fact['sources_sha256']][0]['original_pip_generator'], provider['installed_script_generator'])
            provider['installed_source_forms'][1]['package']['version'] = '2'
            with patch.object(m.oci_python, 'derive', return_value=provider), patch.object(m.pip_components, 'derive', return_value=original), patch.object(m, 'wheel_facts', return_value=result([wheel], pending_declarations=[])), self.assertRaisesRegex(ValueError, 'no exact original package notices'):
                self.replay(root, [wheel_recipe, recipe, pip_recipe], m.Facts(), artifact_ids=('core-oci-index',))

    def test_exact_packaged_wheel_binding_clears_only_matching_hash_and_size_pending_row(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); (root / 'sources.json').write_text('{}')
            own = binding(b'exact locked Windows ARM wheel')
            pending = [{'code': 'WINDOWS_WHEEL_COMPILER_RUNTIME_DECLARATION_REQUIRED', **own['content']}, {'code': 'WINDOWS_WHEEL_COMPILER_RUNTIME_DECLARATION_REQUIRED', 'sha256': own['content']['sha256'], 'size_bytes': own['content']['size_bytes'] + 1}, {'code': 'WINDOWS_WHEEL_COMPILER_RUNTIME_DECLARATION_REQUIRED', **content(b'unknown Windows wheel')}]
            for families in ([{'kind': 'python-wheels', 'sources': 'sources.json'}, {'kind': 'packaged-data'}], [{'kind': 'packaged-data'}, {'kind': 'python-wheels', 'sources': 'sources.json'}]):
                with patch.object(m, 'wheel_facts', return_value=result(pending_declarations=pending)), patch.object(m.packaged_data, 'derive', return_value=result([own])):
                    reports, _ = self.replay(root, families, m.Facts(), discovery={'subjects': []})
                wheel = next(row for row in reports if row['kind'] == 'python-wheels')
                self.assertEqual(wheel['handled_by_exact_packaged_data'], pending[:1])
                self.assertEqual(wheel['pending_declarations'], pending[1:])
                self.assertEqual(wheel['status'], 'incomplete')

    def test_live_original_ttc_sources_and_notices_are_forwarded_without_unrelated_font_rows(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); (root / 'runtime').mkdir()
            (root / 'runtime/runtime.lock.json').write_text(json.dumps({'packs': {'render': {}}}))
            for name in ('sources.json', 'inventory.json', 'keyring.gpg'): (root / name).write_text('{}')
            notice = root / 'notice.txt'; notice.write_text('Original supplier font license\n')
            original = {'files': [{'sha256': 'a' * 64, 'size_bytes': 13}], 'identity': 'original-font-source'}
            component = {'name': 'fonts-noto-cjk', 'version': '1', 'architecture': 'arm64'}
            ttc = {'image_path': 'usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc', 'platform': 'linux/arm64', **content(b'original TTC bytes')}
            other = {'image_path': 'usr/share/fonts/opentype/noto/Other.ttc', 'platform': 'linux/arm64', **content(b'other font bytes')}
            package = result([{'content': row, 'components': [component]} for row in (ttc, other)], components=[{'binary_component': component, 'sources': [original], 'notice': {'path': notice.name, **content(notice.read_bytes())}}])
            recipes = [{'kind': 'oci-os-packages', 'pack': 'render', 'platform': 'linux/arm64', 'inventory': 'inventory.json', 'sources': 'sources.json', 'keyring': 'keyring.gpg'}, {'kind': 'authored-worker-metadata', 'contexts': {}}]
            with patch.object(m.oci_packages, 'derive', return_value=package), patch.object(m.worker_metadata, 'derive', return_value=result()) as metadata, patch.object(m.shutil, 'which', return_value='/usr/bin/true'):
                self.replay(root, recipes, m.Facts(), artifact_ids=('render-oci-index',), discovery={'subjects': []})
            forwarded = metadata.call_args.kwargs['font_sources']
            self.assertEqual(len(forwarded), 1)
            self.assertEqual(forwarded[0]['content'], ttc)
            self.assertEqual(forwarded[0]['sources'], [original])
            self.assertEqual(forwarded[0]['notices'][0]['sha256'], content(notice.read_bytes())['sha256'])
            self.assertEqual(forwarded[0]['required_materials'], original['files'] + forwarded[0]['notices'])

    def test_retaining_inspection_materials_cannot_issue_binary_coverage_and_size_conflicts_reject(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); (root / '.artifacts').mkdir(); (root / 'LICENSE').write_text('Original authored fixture terms\n')
            payload = b'MZ' + bytes(128); archive = root / '.artifacts/runtime.tar.gz'
            with tarfile.open(archive, 'w:gz') as output:
                entry = tarfile.TarInfo('bin/unknown.exe'); entry.size = len(payload); output.addfile(entry, io.BytesIO(payload))
            original = content(b'original inspected archive')
            retention = {'status': 'passed', 'qualification': 'inspection-retention-only', 'required_materials': [original], 'joins': [{'form': 'original inspection archive'}], 'generator_sha256': 'a' * 64}
            candidate = {'schema_version': 1, 'source_tree_sha256': m.source_inventory(root)['sha256'], 'runtime_lock_sha256': 'b' * 64, 'artifacts': [{'id': 'userspace-core-win32-arm64', 'path': '.artifacts/runtime.tar.gz', 'sha256': m.digest(archive), 'size': archive.stat().st_size}]}
            with patch.object(m.retained_inputs, 'retain_inspected_originals', return_value=retention) as helper:
                report = m.derive(root, candidate, {'schema_version': 1, 'families': []}, diagnostic=True)
            self.assertIsInstance(helper.call_args.args[3], frozenset)
            self.assertEqual(report['inspection_original_retention'], retention)
            self.assertIn(original, report['required_materials'])
            self.assertFalse(report['complete_available_shipped_component_coverage'])
            self.assertEqual([row['sha256'] for row in report['unresolved_shipped_members']], [content(payload)['sha256']])
            facts = m.Facts(); facts.require_materials([original])
            self.assertEqual(facts.rows, {})
            with self.assertRaisesRegex(ValueError, 'size conflicts'):
                facts.require_materials([{**original, 'size_bytes': original['size_bytes'] + 1}])

    def test_generated_font_keeps_original_material_obligations_without_becoming_a_readable_config(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); material = content(b'original font source archive')
            generated = {'content': {'image_path': 'opt/ud-agent/render/fonts/NotoSansCJK-Regular.otf', **content(b'generated standalone font')}, 'sources': [{'form': 'exact-standalone-font-zero-derived-from-authenticated-original-collection'}], 'notices': [{'form': 'original font license'}], 'required_materials': [material]}
            member = {'path': 'fonts/generated/NotoSansCJK-Regular.otf', 'architecture': 'unknown', **generated['content']}
            discovery = {'subjects': [{'id': 'render-assets-linux-arm64', 'role': 'runtime', 'sha256': 'a' * 64, 'members': [member]}], 'blockers': []}
            recipes = [{'kind': 'authored-worker-metadata', 'contexts': {}}]; facts = m.Facts()
            with patch.object(m.worker_metadata, 'derive', return_value=result([generated])):
                self.replay(root, recipes, facts, discovery=discovery)
            self.assertEqual({row['family'] for row in facts.rows.values()}, {'generated-render-font'})
            report = m.reconcile(discovery, facts, {'sha256': 'b' * 64})
            self.assertTrue(report['complete_available_shipped_component_coverage'])
            self.assertEqual(report['required_materials'], [material])
            generated['sources'] = [{'form': 'unrecognized-compiled-output'}]
            with patch.object(m.worker_metadata, 'derive', return_value=result([generated])), self.assertRaisesRegex(ValueError, 'unknown source form'):
                self.replay(root, recipes, m.Facts(), discovery=discovery)


if __name__ == '__main__': unittest.main()
