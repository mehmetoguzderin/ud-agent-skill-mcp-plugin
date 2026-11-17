#!/usr/bin/env python3
"""Schedule exact pinned mutmut definitions before any mutant test outcomes."""
from __future__ import annotations
import argparse
import ast
import hashlib
import importlib.metadata
import importlib
import json
import math
import os
import re
import shutil
from pathlib import Path
import sys
from functools import lru_cache
from difflib import unified_diff
from types import SimpleNamespace


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False)


def write_schedule(file, header, inventory):
    """Avoid a second full-plan allocation when functions repeat many times."""
    if 'inventory' in header:
        raise ValueError('schedule header cannot supply definitions')
    with file.open('w', encoding='utf-8') as output:
        prefix = canonical(header)
        output.write(prefix[:-1] + (',' if header else '') + '"inventory":[')
        for index, item in enumerate(inventory):
            if index:
                output.write(',')
            output.write(canonical(item))
        output.write(']}\n')


def source_path(path):
    value = path.as_posix()
    if value.startswith('src/ud_agent/'):
        return 'workers/ud/src/ud_agent/' + value.removeprefix('src/ud_agent/')
    if value.startswith('scripts/'):
        return value
    raise ValueError('Unexpected scheduled Python source')


def full_suite_dispatch(mutant_ids, tests, observed, durations):
    """Separate actual statistics from deliberate complete-suite dispatch."""
    from mutmut.utils.format_utils import mangled_name_from_mutant_name
    if (not mutant_ids or len(set(mutant_ids)) != len(mutant_ids)
            or any(not isinstance(value, str) or '__mutmut_' not in value for value in mutant_ids)
            or not tests or len(set(tests)) != len(tests) or any(not isinstance(value, str) or not value for value in tests)):
        raise ValueError('full-suite dispatch requires complete unique definitions and test IDs')
    expected = set(tests)
    if set(durations) != expected or any(type(value) not in (int, float) or not math.isfinite(value) or value < 0 for value in durations.values()):
        raise ValueError('actual protected baseline durations omit or alter discovered test IDs')
    if any(not isinstance(name, str) or not name or not set(values) <= expected for name, values in observed.items()):
        raise ValueError('actual observed associations contain undeclared tests')
    complete = sorted(expected)
    functions = sorted({mangled_name_from_mutant_name(value) for value in mutant_ids})
    return {'schema_version': 1, 'strategy': 'full-discovered-original-suite-not-coverage-selection',
            'tests': complete, 'observed_associations': {name: sorted(values) for name, values in sorted(observed.items())},
            'observed_durations': dict(sorted(durations.items())),
            'function_names': functions}


@lru_cache(maxsize=4096)
def function_location(source, mutant):
    from mutmut.utils.format_utils import orig_function_and_class_names_from_key
    name, class_name = orig_function_and_class_names_from_key(mutant)
    tree = ast.parse(source)
    bodies = tree.body
    if class_name is not None:
        classes = [node for node in bodies if isinstance(node, ast.ClassDef) and node.name == class_name]
        if len(classes) != 1:
            raise ValueError('Ambiguous scheduled class identity')
        bodies = classes[0].body
    matches = [node for node in bodies if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name]
    if len(matches) != 1:
        raise ValueError('Ambiguous scheduled function identity')
    node = matches[0]
    return {'line': min([node.lineno, *(item.lineno for item in node.decorator_list)]), 'end_line': node.end_lineno, 'column': node.col_offset}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--schedule', type=Path, required=True)
    parser.add_argument('--source-receipt', type=Path, required=True)
    parser.add_argument('--outcomes', type=Path, required=True)
    parser.add_argument('--jobs', type=int, default=1)
    parser.add_argument('--inventory-only', action='store_true')
    parser.add_argument('--mutant-filter',action='append',default=[],help='explicit diagnostic glob subset; never complete acceptance')
    parser.add_argument('--source-subset',action='store_true',help='record explicit diagnostic source selection')
    args = parser.parse_args()
    if args.jobs != 1:
        raise ValueError('The complete single-active Python projection requires exactly one test job')
    if importlib.metadata.version('mutmut') != '3.8.1':
        raise ValueError('The mutation driver requires pinned mutmut3.8.1')
    root = Path.cwd().resolve(strict=True)
    # Public worker subprocess tests must resolve the same generated package as
    # in-process tests, independently of the caller's ambient PYTHONPATH.
    os.environ['PYTHONPATH']=os.pathsep.join([str(root/'mutants/src'),str(root/'mutants'),str(root/'tests/mutation')])
    receipt = json.loads(args.source_receipt.read_text())
    if receipt.get('qualification') not in ('diagnostic-only', 'mutation-source-copy', 'trusted-runner-fixture') or root == Path(receipt['source']).resolve() or (root / '.git').exists():
        raise ValueError('Mutation execution requires an isolated owned source copy')
    if os.environ.get('UD_MUTATION_OCI_GUARD') != '1':
        raise ValueError('Mutation generation and collection require the kernel-confined OCI coordinator; source copies alone are insufficient')
    hashes = {item['path']: item['sha256'] for item in receipt['files']}
    for path in [*root.joinpath('src/ud_agent').rglob('*.py'), *root.joinpath('scripts').rglob('*.py')]:
        expected = hashes.get(source_path(path.relative_to(root)))
        if path.is_symlink() or path.stat().st_nlink != 1 or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise ValueError('Python source differs from the independent source receipt')
    sys.path.insert(0, str(root / 'tests/mutation'))
    projection_path = Path(__file__).with_name('python-runtime-projection.py')
    projection_spec = importlib.util.spec_from_file_location('ud_python_runtime_projection', projection_path)
    projection = importlib.util.module_from_spec(projection_spec)
    sys.modules[projection_spec.name] = projection
    projection_spec.loader.exec_module(projection)
    import mutmut_adapter
    mutmut_adapter.install(root)
    import mutmut.mutation.trampoline as trampoline
    projection.install_guard(trampoline, context_required=True)
    import mutmut.__main__ as runner
    # Generation is deterministic and trusted; real test execution still uses
    # the bounded isolated fork server below. Sequential generation also keeps
    # the exact versioned CST repairs installed on every generated operator,
    # independent of Python3.14's platform-specific process-pool start method.
    class GenerationPool:
        def __init__(self, processes):
            if not isinstance(processes,int) or not 1 <= processes <= 16:
                raise ValueError('Mutation generation worker bound is invalid')
        def __enter__(self):
            return self
        def __exit__(self, *details):
            return False
        def imap_unordered(self, function, values):
            return map(function, values)
    runner.create_mutants.__globals__['Pool'] = GenerationPool
    collect_isolated=None
    if os.environ.get('UD_MUTATION_OCI_GUARD')=='1':
        location=Path('/opt/mutation/harness/oci-isolation.py');isolation_spec=importlib.util.spec_from_file_location('ud_mutation_isolation',location);isolation=importlib.util.module_from_spec(isolation_spec);isolation_spec.loader.exec_module(isolation)
        collect_isolated=isolation.install(runner,root,args.outcomes.parent,Path(os.environ['UD_MUTATION_PYTEST_EVIDENCE']),projection=projection)
    from mutmut.mutation.diff_apply import parse_generated_function, generated_function_names
    from mutmut.mutation.data import MutantLineSpans
    from mutmut.utils.format_utils import orig_function_and_class_names_from_key
    import libcst
    operators_path=Path(__file__).with_name('python-operators.py')
    operators_spec=importlib.util.spec_from_file_location('ud_python_operator_repairs',operators_path);operators=importlib.util.module_from_spec(operators_spec);operators_spec.loader.exec_module(operators)
    generation_profile,generation_repairs=operators.install(root/'mutants/.ud-generator-repairs')
    generation_profile['generation_mode']='deterministic-sequential'
    # The pinned upstream call discards its full-file AST. Validate every exact
    # generated function and the complete inert baseline instead, retaining all
    # full function bodies as non-executable control data. Never replace the
    # shared stdlib ast module or change operator/generation fingerprints.
    if (set(re.findall(r'\bast\.([A-Za-z_]+)', __import__('inspect').getsource(runner))) != {'parse'}
            or __import__('inspect').getsource(runner.create_mutants_for_file).count('ast.parse(f.read())') != 1):
        raise ValueError('Pinned upstream syntax-check callsite changed')
    original_writer = runner.write_all_mutants_to_file
    pending_syntax = {}
    def bounded_writer(*, out, source, filename):
        value = original_writer(out=out, source=source, filename=filename)
        mapped = projection.safe_path(Path(filename).as_posix())
        spans = {name: [span.start, span.end] for name, span in value.line_span_by_function_name.items()}
        projection.validate_control(value.code, spans, mapped)
        projection.retain_control(args.outcomes.parent, mapped, value.code, spans)
        pending_syntax.clear()
        pending_syntax.update(sha256=hashlib.sha256(value.code.encode()).hexdigest(), size=len(value.code))
        return value
    def checked_syntax(source):
        if pending_syntax != {'sha256': hashlib.sha256(source.encode()).hexdigest(), 'size': len(source)}:
            raise ValueError('Upstream syntax validation lost its exact full control binding')
        pending_syntax.clear()
        return None
    runner.write_all_mutants_to_file = bounded_writer
    runner.ast = SimpleNamespace(parse=checked_syntax)
    repair_typed=operators.typed_repairs(root,hashes)
    create = runner.create_mutants
    scheduled_data = {}
    complete_runtime = {}
    original_stats = runner.run_stats_collection
    original_collect_stats = runner.collect_or_load_stats
    def observed_full_stats(instance, tests=None):
        if tests:
            raise ValueError('incremental statistics cannot authorize complete-suite mutation dispatch')
        result = original_stats(instance, tests=None)
        if collect_isolated is not None:
            collect_isolated()
        current = runner.state()
        dispatch = full_suite_dispatch(complete_runtime['mutants'], complete_runtime['tests'],
                                      current.tests_by_mangled_function_name, current.duration_by_test)
        target = args.outcomes.parent/'full-suite-dispatch.json'
        if target.exists():
            raise ValueError('full-suite baseline evidence cannot be rebound')
        target.write_text(canonical({**dispatch, 'source_tree_sha256': receipt['source_tree_sha256']})+'\n')
        complete_tests = set(dispatch['tests'])
        for name in dispatch['function_names']:
            current.tests_by_mangled_function_name[name] = complete_tests
        complete_runtime['baseline_complete'] = True
        return result
    def collect_complete_stats(*parameters, **options):
        result = original_collect_stats(*parameters, **options)
        if complete_runtime.get('baseline_complete') is not True:
            raise ValueError('cached statistics cannot replace an actual protected full-suite baseline')
        return result
    runner.run_stats_collection = observed_full_stats
    runner.collect_or_load_stats = collect_complete_stats

    def scheduled_create(jobs):
        stats = create(jobs)
        for prefix in ['src/ud_agent','scripts']:
            for original in root.joinpath(prefix).rglob('*'):
                if original.is_file():
                    relative=original.relative_to(root)
                    expected=hashes.get(source_path(relative))
                    if expected is None:continue
                    if original.is_symlink()or hashlib.sha256(original.read_bytes()).hexdigest()!=expected:raise ValueError('supporting source differs from its independent receipt')
                    target=root/'mutants'/relative
                    if not target.exists():
                        target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(original,target)
        # mutmut sets import paths before materializing mutants/src on the
        # first run. Clear Python's cached negative path finders only after
        # that package exists, and bind imports to this generated source copy.
        generated_source = str(root / 'mutants/src')
        if generated_source not in sys.path:
            sys.path.insert(0, generated_source)
        importlib.invalidate_caches()
        if (root / 'src/ud_agent').is_dir():
            package = importlib.util.find_spec('ud_agent')
            if package is None or Path(package.origin).resolve() != root / 'mutants/src/ud_agent/__init__.py':
                raise ValueError('Python test imports are not bound to generated worker sources')
        entries, _ = runner.collect_source_file_mutation_data(mutant_names=args.mutant_filter)
        discovery = {'schema_version': 1, 'qualification': 'raw-discovery-not-acceptance',
                     'source_tree_sha256': receipt['source_tree_sha256'], 'tool': 'mutmut', 'tool_version': '3.8.1',
                     'scope_complete': not args.mutant_filter and not args.source_subset,
                     'inventory': [{'id': key, 'file': source_path(Path(metadata.path)), 'source_sha256': hashes[source_path(Path(metadata.path))]}
                                   for metadata, key, result in entries]}
        if len({item['id'] for item in discovery['inventory']}) != len(entries):
            raise ValueError('Raw Python discovery repeated a mutant identity')
        discovery_file = args.schedule.with_name('discovery.json')
        discovery_file.write_text(json.dumps(discovery, indent=2) + '\n')
        discovery_sha256 = hashlib.sha256(discovery_file.read_bytes()).hexdigest()
        inventory = []
        repairs = list({item['repair_sha256']:item for item in generation_repairs()}.values())
        repairs_by_file = {}
        for repair in repairs:
            repairs_by_file.setdefault(repair['file'], []).append(repair)
        seen = set()
        seen_definitions = {}
        generated = {}
        def functions_for(key, path):
            if generated.get('path') != path:
                spans = MutantLineSpans.load(path)
                if spans is None: raise ValueError('Generated mutant has no exact function index')
                generated.clear()
                function_location.cache_clear()
                generated.update(path=path, lines=(args.outcomes.parent / projection.CONTROL / path).read_text().splitlines(keepends=True),
                                 spans=spans.span_by_function_name, source=path.read_text(), originals={}, locations={})
            lines, spans = generated['lines'], generated['spans']
            original_name, replacement_name = generated_function_names(key)
            function_name, class_name = orig_function_and_class_names_from_key(key)
            def code(name):
                span = spans[name]
                source = ''.join(lines[span.start-1:span.end])
                normalized, count = re.subn(r'(?m)^(\s*(?:async\s+)?def\s+)' + re.escape(name) + r'(?=\()', lambda match: match.group(1)+function_name, source, count=1)
                if count != 1: raise ValueError('Generated function index is stale')
                return normalized
            if original_name not in generated['originals']:
                generated['originals'][original_name] = code(original_name)
                generated['locations'][original_name] = function_location(generated['source'], original_name)
            return generated['originals'][original_name], code(replacement_name), generated['locations'][original_name]
        for metadata, key, result in entries:
            path = Path(metadata.path)
            file = source_path(path)
            if key in seen or result is not None:
                raise ValueError('Duplicate or previously executed Python mutant')
            seen.add(key)
            original, replacement, location = functions_for(key, path)
            definition = {'tool': 'mutmut', 'version': '3.8.1', 'generation_profile': generation_profile, 'generation_repairs': [repair for repair in repairs_by_file.get(str(path), []) if repair['replacement_expression'] in replacement], 'file': file,
                'location': location, 'original_function': original,
                'replacement_function': replacement, 'diff': '\n'.join(unified_diff(original.splitlines(), replacement.splitlines(), fromfile=file, tofile=file, lineterm=''))}
            typed = repair_typed(file, replacement, definition, raw_id=key)
            if typed is not None:
                replacement, evidence = typed
                _, replacement_name = generated_function_names(key)
                lines, spans = generated['lines'], generated['spans']
                span = spans[replacement_name]
                before = ''.join(lines[span.start-1:span.end])
                change = evidence['exact_change']
                if before.count(change['before']) != 1:
                    raise ValueError('Python generated typed-operator source is ambiguous')
                after = before.replace(change['before'], change['after'], 1)
                if len(after.splitlines()) != len(before.splitlines()):
                    raise ValueError('Python typed operator invalidated generated line identities')
                lines[span.start-1:span.end] = after.splitlines(keepends=True)
                (root/'mutants'/path).write_text(''.join(lines))
                (args.outcomes.parent/projection.CONTROL/path).chmod(0o644)
                (args.outcomes.parent/projection.CONTROL/path).write_text(''.join(lines))
                (args.outcomes.parent/projection.CONTROL/path).chmod(0o444)
                definition = {**definition, 'replacement_function': replacement,
                              'diff': '\n'.join(unified_diff(original.splitlines(), replacement.splitlines(), fromfile=file, tofile=file, lineterm='')),
                              'operator_repair': evidence}
            actual_definition = (file, definition['location']['line'], hashlib.sha256(replacement.encode()).hexdigest())
            if actual_definition in seen_definitions:
                args.schedule.with_name('duplicate-definition.json').write_text(json.dumps({'qualification':'invalid-discovery', 'file':file, 'first':seen_definitions[actual_definition], 'duplicate':key, 'definition':definition}, indent=2)+'\n')
                raise ValueError('Python discovery produced a duplicate applicable operator definition: ' + key)
            seen_definitions[actual_definition] = key
            if original == replacement or not definition['diff']:
                raise ValueError('Generated mutation has no changed definition')
            inventory.append({'id': key, 'file': file, 'source_sha256': hashes[file], 'definition_ref': projection.definition_reference(path.as_posix(), definition),
                'definition_sha256': hashlib.sha256(canonical(definition).encode()).hexdigest()})
            if len(inventory) % 1000 == 0:
                args.schedule.with_suffix('.progress.json').write_text(json.dumps({'qualification':'incomplete-scheduling','scheduled_so_far':len(inventory),'discovered':len(entries),'source_tree_sha256':receipt['source_tree_sha256']})+'\n')
        if hasattr(repair_typed, 'complete'):
            repair_typed.complete({key for _,key,_ in entries})
        if not inventory:
            raise ValueError('Python mutation scheduling is empty')
        generated.clear()
        function_location.cache_clear()
        seen_definitions.clear()
        # Preserve generator metadata before timing/coverage or mutant results
        # alter it. Authority reconstruction must never infer scope from rows
        # that already contain execution outcomes.
        for metadata_file in (root/'mutants').rglob('*.meta'):
            if metadata_file.is_symlink():raise ValueError('Generated metadata cannot be a link')
            data=metadata_file.read_bytes();metadata_value=json.loads(data)
            if any(value is not None for value in metadata_value['exit_code_by_key'].values()):raise ValueError('Generation metadata already contains outcomes')
            target=args.schedule.parent/'generation-metadata'/metadata_file.relative_to(root/'mutants')
            target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(data)
        mapped_hashes = {name.replace('workers/ud/src/ud_agent/', 'src/ud_agent/', 1): fingerprint
                         for name, fingerprint in hashes.items()
                         if name.endswith('.py') and name.startswith(('workers/ud/src/ud_agent/', 'scripts/'))}
        if args.source_subset:
            mapped_hashes = {name: fingerprint for name, fingerprint in mapped_hashes.items()
                             if (root/'mutants'/Path(name+'.spans')).is_file()}
        control_manifest = projection.finalize_control(root, args.outcomes.parent, receipt['source_tree_sha256'], mapped_hashes)
        header = {'schema_version': 1, 'qualification': 'diagnostic-only',
            'source_tree_sha256': receipt['source_tree_sha256'], 'tool': 'mutmut', 'tool_version': '3.8.1',
            'discovery_sha256': discovery_sha256, 'generation_profile':generation_profile,'generation_repairs':repairs,'scope_complete':not args.mutant_filter and not args.source_subset,'mutant_filters':args.mutant_filter,'scheduled': len(inventory),
            'definition_representation': projection.DEFINITION_REPRESENTATION,
            'runtime_representation': {'version': projection.VERSION, 'manifest_path': projection.MANIFEST.as_posix(),
                'manifest_sha256': hashlib.sha256((args.outcomes.parent/projection.MANIFEST).read_bytes()).hexdigest(),
                'jobs': 1}}
        write_schedule(args.schedule, header, inventory)
        scheduled_data.update(header=header, inventory=inventory)
        complete_runtime['mutants'] = [item['id'] for item in inventory]
        print(json.dumps({'scheduled': len(inventory), 'source_tree_sha256': receipt['source_tree_sha256']}), flush=True)
        return stats

    class InventoryComplete(Exception):
        pass

    runner.create_mutants = scheduled_create
    get_runner = runner.get_mutant_runner
    def scheduled_runner(*parameters, **options):
        instance = get_runner(*parameters, **options)
        # Discover tests through the runner's isolated child, then bind their
        # identities in the trusted parent before consuming any outcomes.
        selected = instance.list_all_tests()
        if collect_isolated is not None:
            collect_isolated()
        tests = []
        for nodeid in sorted(selected.ids):
            file = nodeid.split('::', 1)[0].removeprefix('mutants/')
            if file not in hashes or not file.startswith('tests/'):
                raise ValueError('Discovered Python test is outside the independent source inventory')
            tests.append({'id': nodeid, 'source': file, 'source_sha256': hashes[file]})
        if not tests:
            raise ValueError('Python required test discovery is empty')
        complete_runtime['tests'] = [item['id'] for item in tests]
        if not scheduled_data:
            raise ValueError('test discovery occurred before complete mutation generation')
        header = {**scheduled_data['header'], 'tests': tests}
        inventory = scheduled_data['inventory']
        # Reuse the generated objects and stream rows; do not parse/dump a
        # second whole-plan string merely to append the discovered tests.
        write_schedule(args.schedule, header, inventory)
        plan = {**header, 'inventory': inventory}
        verifier = globals().get('verify_frozen_schedule')
        if verifier is not None:
            verifier(plan)
        scheduled_data.clear()
        if args.inventory_only:
            raise InventoryComplete()
        return instance
    runner.get_mutant_runner = scheduled_runner
    status = 0
    try:
        runner._run(args.mutant_filter, args.jobs)
    except InventoryComplete:
        return 0
    except SystemExit as error:
        status = error.code if isinstance(error.code, int) else 1
    finally:
        if collect_isolated is not None:collect_isolated()
        if args.schedule.exists() and not args.inventory_only:
            entries, _ = runner.collect_source_file_mutation_data(mutant_names=args.mutant_filter)
            args.outcomes.write_text(json.dumps({'schema_version': 1, 'qualification': 'diagnostic-only',
                'source_tree_sha256': receipt['source_tree_sha256'], 'outcomes': [
                    {'id': key, 'file': source_path(Path(metadata.path)), 'exit_code': code,
                     'duration_seconds': metadata.durations_by_key.get(key),
                     'type_check_error': metadata.type_check_error_by_key.get(key)} for metadata, key, code in entries]}, indent=2) + '\n')
    return status


if __name__ == '__main__':
    raise SystemExit(main())
