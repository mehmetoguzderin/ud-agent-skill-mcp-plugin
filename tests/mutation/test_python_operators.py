import ast
import importlib.util
from pathlib import Path
import tempfile
import json
import unittest
from unittest.mock import patch
import libcst as cst
from mutmut.mutation.mutators import operator_if_exp
from mutmut.mutation import mutators

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('ud_python_operators_test', ROOT / 'scripts/quality/python-operators.py')
operators = importlib.util.module_from_spec(spec)
spec.loader.exec_module(operators)


class PythonOperatorTests(unittest.TestCase):
    def setUp(self):
        self.enterContext(patch.object(mutators, 'mutation_operators', [(kind, getattr(operator, '_ud_original', operator)) for kind, operator in mutators.mutation_operators]))

    def test_compact_valid_ternaries_keep_original_bytes_and_generate_valid_opposite_branches(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(cst.IfExp, 'with_changes', getattr(cst.IfExp.with_changes, '_ud_original', cst.IfExp.with_changes)):
            profile, records = operators.install(Path(temporary))
            module = cst.Module([])
            for source, condition in [("'yes'if(True)else'no'", 'True'), ("'yes' if True else 'no'", 'True'), ("'yes'if('value')else'no'", "'value'")]:
                original = cst.parse_expression(source)
                self.assertEqual(module.code_for_node(original), source)
                variants = [module.code_for_node(item) for item in operator_if_exp(original)]
                expected = [f"'yes' if ({condition}) and False else 'no'", f"'yes' if ({condition}) or True else 'no'"]
                self.assertEqual([ast.dump(ast.parse(value, mode='eval')) for value in variants], [ast.dump(ast.parse(value, mode='eval')) for value in expected])
                for value in variants:
                    compile(value, '<operator-data-only>', 'eval', dont_inherit=True, optimize=0)
                self.assertEqual(module.code_for_node(original), source)
            repaired = records()
            self.assertGreater(len(repaired), 0)
            self.assertTrue(all(item['version'] == profile['version'] and item['repair_sha256'] and item['requested_expressions'] for item in repaired))
            self.assertTrue(any('whitespace_before_else' in item['repair'] for item in repaired))

    def test_abi_and_select_argument_repairs_preserve_types_arity_and_every_original_instance(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(cst.IfExp, 'with_changes', getattr(cst.IfExp.with_changes, '_ud_original', cst.IfExp.with_changes)):
            profile, records = operators.install(Path(temporary))
            operation = next(operator for kind, operator in mutators.mutation_operators if getattr(operator, '_ud_operator_repair', False))
            module = cst.Module([])
            calls = ['libc.prctl(38, 1, 0, 0, 0)', 'library.prctl(37, ctypes.byref(selected), 0, 0, 0)', 'libc.syscall(444, 0, 0, 1)', 'select.select([descriptor], [], [], remaining)']
            for source in calls:
                node = cst.parse_expression(source)
                changed = list(operation(node))
                self.assertEqual(len(changed), len(node.args) * 2)
                rendered = [module.code_for_node(item) for item in changed]
                self.assertEqual(len(set(rendered)), len(rendered), source)
                self.assertTrue(all(len(item.args) == len(node.args) for item in changed))
                self.assertNotIn(source, rendered)
                for item in changed:
                    compile(module.code_for_node(item), '<ABI-operator-data-only>', 'eval', dont_inherit=True, optimize=0)
                    self.assertFalse(any(isinstance(arg.value, cst.Name) and arg.value.value == 'None' for arg in item.args))
                    if source.startswith('select.'):
                        self.assertTrue(all(isinstance(arg.value, cst.List) for arg in item.args[:3]))
                self.assertEqual(module.code_for_node(node), source)
            repaired = [item for item in records() if item['operator'] == 'typed-ABI-argument-v1']
            self.assertEqual(len(repaired), sum(len(cst.parse_expression(value).args) * 2 for value in calls))
            self.assertTrue(all(item['version'] == profile['version'] and item['upstream_expression'] != item['replacement_expression'] and item['repair_sha256'] for item in repaired))

    def test_every_select_repair_has_exact_descriptor_lists_timeout_and_required_arity_as_data(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(cst.IfExp, 'with_changes', getattr(cst.IfExp.with_changes, '_ud_original', cst.IfExp.with_changes)):
            operators.install(Path(temporary))
            operation = next(operator for kind, operator in mutators.mutation_operators if getattr(operator, '_ud_operator_repair', False))
            module = cst.Module([])
            variants = [module.code_for_node(item) for item in operation(cst.parse_expression('select.select([descriptor], [], [], remaining)'))]
            expected = [
                'select.select([], [], [], remaining)',
                'select.select([descriptor], [descriptor], [], remaining)',
                'select.select([descriptor], [], [descriptor], remaining)',
                'select.select([descriptor], [], [], 0)',
                'select.select([descriptor, descriptor], [], [], remaining)',
                'select.select([descriptor], [descriptor, descriptor], [], remaining)',
                'select.select([descriptor], [], [descriptor, descriptor], remaining)',
                'select.select([descriptor], [], [], 0.001)',
            ]
            self.assertEqual([ast.dump(ast.parse(value, mode='eval')) for value in variants], [ast.dump(ast.parse(value, mode='eval')) for value in expected])
            for value in variants:
                tree = ast.parse(value, mode='eval')
                self.assertEqual(len(tree.body.args), 4)
                self.assertEqual(tree.body.keywords, [])
                for group in tree.body.args[:3]:
                    self.assertIsInstance(group, ast.List)
                    self.assertTrue(all(isinstance(item, ast.Name) and item.id == 'descriptor' for item in group.elts))
                compile(tree, '<select-operator-data-only>', 'eval', dont_inherit=True, optimize=0)

    def test_typed_registry_retains_all_original_definitions_and_exact_repaired_sources(self):
        import hashlib,json
        registry=json.loads((ROOT/'quality/python-operator-repairs.json').read_text())
        review=__import__('json').loads((ROOT/'quality/reviews/python-operator-repairs-domain-review.json').read_text())
        hashes=dict(review['dependency_source_sha256'])
        for row in json.loads((ROOT/'quality/python-graph-operator-proposals.json').read_bytes())['rows']:
            hashes[row['file']]=row['source_sha256']
        graph='workers/ud/src/ud_agent/graph_backend.py';hashes[graph]=hashlib.sha256((ROOT/graph).read_bytes()).hexdigest()
        repair=operators.typed_repairs(ROOT,hashes)
        self.assertEqual(len(registry['rows']),36)
        replacements=set()
        for row in registry['rows']:
            original=row['upstream_definition']
            changed,evidence=repair(row['file'],original['replacement_function'],original,raw_id=row['id'])
            self.assertNotIn((row['file'],changed),replacements);replacements.add((row['file'],changed))
            self.assertEqual(evidence['upstream_definition'],original)
            self.assertEqual(evidence['upstream_definition_sha256'],row['upstream_definition_sha256'])
            self.assertEqual(changed,original['replacement_function'].replace(row['before'],row['after'],1))
            ast.parse(changed)
        with self.assertRaisesRegex(ValueError,'source fingerprint'):
            operators.typed_repairs(ROOT,{name:'0'*64 for name in hashes})

    def test_graph_registry_retains_every_complete_original_profile_without_executing_mutant_code(self):
        import hashlib,shutil
        registry=json.loads((ROOT/'quality/python-graph-operator-proposals.json').read_bytes())
        project=json.loads((ROOT/'quality/reviews/python-operator-repairs-domain-review.json').read_bytes())
        hashes=dict(project['dependency_source_sha256'])
        for row in registry['rows']:
            hashes[row['file']]=row['source_sha256']
        temporary=self.enterContext(tempfile.TemporaryDirectory())
        historical=Path(temporary)
        for name in ('quality/python-graph-operator-proposals.json','quality/reviews/python-graph-operators-root-review.json'):
            target=historical/name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(ROOT/name,target)
        repair=operators._graph_typed_repairs(historical,hashes)
        self.assertEqual(len(registry['rows']),126)
        programs=set()
        for row in registry['rows']:
            definition=row['upstream_definition']
            changed,evidence=repair(row['file'],definition['replacement_function'],definition)
            self.assertEqual(hashlib.sha256(changed.encode()).hexdigest(),row['proposed_function_sha256'])
            self.assertEqual(evidence['version'],'ud-graph-typed-operators-1')
            self.assertEqual(evidence['upstream_definition'],definition)
            self.assertEqual(evidence['upstream_definition_sha256'],row['upstream_definition_sha256'])
            self.assertEqual(len(changed.splitlines()),len(definition['replacement_function'].splitlines()))
            self.assertNotEqual(ast.dump(ast.parse(changed)),ast.dump(ast.parse(definition['original_function'])))
            self.assertNotIn(changed,programs);programs.add(changed)
        repair.complete({row['id']for row in registry['rows']})
        row=registry['rows'][0]
        with self.assertRaisesRegex(ValueError,'complete definition'):
            repair(row['file'],row['upstream_definition']['replacement_function'],{**row['upstream_definition'],'generation_profile':{'version':'forged'}})
        unused=operators._graph_typed_repairs(historical,hashes)
        with self.assertRaisesRegex(ValueError,'omitted'):
            unused.complete({row['id']})

    def test_retired_graph_registry_leaves_all_new_original_operators_unmodified(self):
        import hashlib
        file='workers/ud/src/ud_agent/graph_backend.py'
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'quality').mkdir();(root/'quality/python-graph-operators.activation.json').write_text('{"schema_version":1,"active":false}')
            repair=operators._graph_typed_repairs(root,{file:hashlib.sha256((ROOT/file).read_bytes()).hexdigest()})
            row=json.loads((ROOT/'quality/python-graph-operator-proposals.json').read_bytes())['rows'][0]
            self.assertIsNone(repair(file,row['upstream_definition']['replacement_function'],row['upstream_definition']))

    def test_active_revision_regenerates_every_fresh_source_bound_graph_definition(self):
        import hashlib
        file='workers/ud/src/ud_agent/graph_backend.py';selection=operators.graph_registry_selection(ROOT)
        registry=json.loads((ROOT/selection['registry']).read_bytes());repair=operators._graph_typed_repairs(ROOT,{file:hashlib.sha256((ROOT/file).read_bytes()).hexdigest()})
        ids=set()
        for row in registry['rows']:
            changed,evidence=repair(file,row['upstream_definition']['replacement_function'],row['upstream_definition'])
            self.assertEqual(hashlib.sha256(changed.encode()).hexdigest(),row['proposed_function_sha256'])
            self.assertEqual(evidence['version'],'ud-graph-typed-operators-2');ids.add(row['id'])
        self.assertEqual(len(ids),126);repair.complete(ids)


if __name__ == '__main__':
    unittest.main()
