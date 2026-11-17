#!/usr/bin/env python3
"""Trusted OCI entrypoint for a read-only native ARM64 mutation source handoff."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sys


def schedule_identity(plan, backend, state=None):
    """Compact exact pre-outcome authority; never infer scope from results."""
    if plan.get('scope_complete') is not True:
        raise ValueError('only complete mutation schedules can be frozen')
    inventory = plan.get('inventory', plan.get('mutants'))
    if not isinstance(inventory, list) or not inventory or plan.get('scheduled', len(inventory)) != len(inventory):
        raise ValueError('mutation schedule is empty or incomplete')
    order = lambda value: value.encode('utf-16-be', errors='surrogatepass')
    mutants, ids, definitions = [], set(), set()
    reader = None
    if 'definition_representation' in plan:
        if backend != 'python' or state is None:
            raise ValueError('compact Python schedules require their actual CONTROL state')
        location = Path(__file__).with_name('python-runtime-projection.py')
        spec = importlib.util.spec_from_file_location('ud_frozen_control_definitions', location)
        helper = importlib.util.module_from_spec(spec); spec.loader.exec_module(helper)
        reader = helper.ControlDefinitionReader(state, plan)
    for item in inventory:
        if reader is not None:
            item = reader.resolve(item)
        elif 'definition_ref' in item:
            raise ValueError('compact Python definitions require their versioned representation')
        definition = item.get('definition')
        digest = hashlib.sha256(json.dumps(definition, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()
        if definition is None or digest != item.get('definition_sha256'):
            raise ValueError('mutation definition differs from its exact hash')
        identity = item['file'] + '#' + digest if backend == 'typescript' else item['id']
        key = (item['file'], digest)
        if identity in ids or key in definitions:
            raise ValueError('duplicate frozen mutation definition')
        ids.add(identity); definitions.add(key)
        mutants.append({'id': identity, 'file': item['file'], 'source_sha256': item['source_sha256'], 'definition_sha256': digest})
    tests = plan.get('tests')
    if isinstance(tests, dict):
        tests = [{'source': name, 'source_sha256': fingerprint} for name, fingerprint in tests.items()]
    elif isinstance(tests, list):
        tests = [{key: item[key] for key in ('source', 'source_sha256', 'name', 'occurrence') if key in item}
                 | ({} if 'name' in item else {'id': item['id'].removeprefix('mutants/')}) for item in tests]
    if not isinstance(tests, list) or not tests:
        raise ValueError('pre-outcome mutation test discovery is empty')
    canonical = lambda value: json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False)
    if len({canonical(item) for item in tests}) != len(tests):
        raise ValueError('pre-outcome mutation test discovery is duplicated')
    result = {'schema_version': 1, 'backend': backend, 'tool': plan['tool'], 'source_tree_sha256': plan['source_tree_sha256'],
              'mutants': sorted(mutants, key=lambda item: order(item['id'])), 'tests': sorted(tests, key=lambda item: order(canonical(item)))}
    if 'case_inventory' in plan:
        result['case_inventory'] = plan['case_inventory']
    return result


def bind_schedule(plan, backend, state=Path('/state'), frozen=Path('/input/frozen-plan.json'), runtime_file=Path('/opt/mutation/input-receipt.json')):
    if plan.get('scope_complete') is False and not frozen.exists():
        # Existing explicit diagnostic subsets may execute under the same OS
        # boundary. They cannot issue a frozen completion or satisfy a session.
        (state / 'selected-diagnostic.json').write_text(json.dumps({'schema_version': 1, 'qualification': 'selected-diagnostic', 'scope_complete': False, 'backend': backend, 'source_tree_sha256': plan['source_tree_sha256']}) + '\n')
        return None
    identity = schedule_identity(plan, backend, state)
    if frozen.exists():
        authority = json.loads(frozen.read_bytes())
        runtime_sha256 = hashlib.sha256(runtime_file.read_bytes()).hexdigest()
        if authority.get('schema_version') != 1 or authority.get('runtime_sha256') != runtime_sha256 or authority.get('plan') != identity:
            raise ValueError('regenerated mutation schedule differs from frozen source/test/SDK authority')
    target = state / 'pre-outcome-plan.json'
    if target.exists() and json.loads(target.read_bytes()) != identity:
        raise ValueError('mutation schedule changed after pre-outcome binding')
    (state / 'test-discovery.json').write_text(json.dumps({'tests': plan['tests']}, sort_keys=True, separators=(',', ':'), ensure_ascii=False) + '\n')
    target.write_text(json.dumps(identity, sort_keys=True, separators=(',', ':'), ensure_ascii=False) + '\n')
    return identity

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--snapshot',default='/input/snapshot.json');parser.add_argument('--backend',choices=['python','perl','typescript','python-static','faults','rust','catalog'],default='python');parser.add_argument('--file',action='append',default=[]);parser.add_argument('--mutant-filter',action='append',default=[]);parser.add_argument('--inventory-only',action='store_true');parser.add_argument('--diagnostic-stryker-range');args=parser.parse_args()
    if args.backend=='catalog' and (not args.inventory_only or args.file or args.mutant_filter):raise ValueError('catalog requires complete discovery-only collection')
    if args.diagnostic_stryker_range is not None and (args.backend != 'typescript' or args.file or args.mutant_filter or args.inventory_only):
        raise ValueError('diagnostic Stryker ranges are exclusive to the TypeScript backend')
    if os.geteuid()!=0:raise RuntimeError('mutation source coordinator must own its metadata')
    os.umask(0o022);state=Path('/state');state.mkdir(exist_ok=True);work=state/'work';work.mkdir(mode=0o755)
    receipt=json.loads(Path(args.snapshot).read_text());source=Path('/input/source')
    isolation_spec=importlib.util.spec_from_file_location('ud_isolation_probe','/opt/mutation/harness/oci-isolation.py')
    isolation=importlib.util.module_from_spec(isolation_spec);isolation_spec.loader.exec_module(isolation)
    proof=isolation.prove_isolation(state,Path('/opt/mutation/harness/oci-mutation.py'))
    proof.update(source_tree_sha256=receipt['source_tree_sha256'],runtime_input_sha256=hashlib.sha256(Path('/opt/mutation/input-receipt.json').read_bytes()).hexdigest())
    (state/'isolation-proof.json').write_text(json.dumps(proof,indent=2)+'\n')
    exec_spec=importlib.util.spec_from_file_location('ud_exec_probe','/opt/mutation/harness/oci-exec.py')
    exec_boundary=importlib.util.module_from_spec(exec_spec);exec_spec.loader.exec_module(exec_boundary)
    exec_proof=exec_boundary.prove_execution(state,Path(sys.executable),Path('/opt/mutation/harness/oci-mutation.py'))
    exec_proof.update(source_tree_sha256=receipt['source_tree_sha256'],runtime_input_sha256=proof['runtime_input_sha256'])
    (state/'exec-isolation-proof.json').write_text(json.dumps(exec_proof,indent=2)+'\n')
    for item in receipt['files']:
        file=source/item['path']
        if file.is_symlink()or not file.is_file()or hashlib.sha256(file.read_bytes()).hexdigest()!=item['sha256']:raise RuntimeError('immutable mutation input differs from its source receipt')
        target=work/item['path'];target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(file,target);target.chmod(0o755 if item['executable']else 0o644)
    (work/'node_modules').symlink_to('/opt/mutation/node_modules')
    os.environ['SOURCE_DATE_EPOCH']='315532800'
    os.environ.update(UD_MUTATION_OCI_GUARD='1',UD_AGENT_PYTHON=sys.executable,UD_RELEASE_PYTHON=sys.executable,PYTHONDONTWRITEBYTECODE='1')
    if args.backend=='catalog':
        backend_spec=importlib.util.spec_from_file_location('ud_catalog_collection_jobs','/opt/mutation/harness/oci-secondary.py')
        backend=importlib.util.module_from_spec(backend_spec);backend_spec.loader.exec_module(backend)
        runtime=json.loads(Path('/opt/mutation/input-receipt.json').read_bytes())
        outcome,content=backend.Jobs(work,state,receipt,exec_boundary.execute,runtime).run('acceptance-collect',timeout=540)
        if outcome['status']!=0 or outcome['timed_out'] or content is None:raise ValueError('complete protected original catalog collection failed')
        (state/'catalog.json').write_bytes(content)
        raise SystemExit(0)
    if args.backend=='rust':
        if args.mutant_filter:raise ValueError('Rust backend rejects opaque source filters')
        backend_spec=importlib.util.spec_from_file_location('ud_owned_rust_backend','/opt/mutation/harness/rust-protected.py')
        backend=importlib.util.module_from_spec(backend_spec);backend_spec.loader.exec_module(backend)
        raise SystemExit(backend.run(work,state,receipt,args.file,inventory_only=args.inventory_only,verify_schedule=lambda plan:bind_schedule(plan,args.backend)))
    if args.backend in ('python-static','faults'):
        if args.file or args.mutant_filter:raise ValueError('secondary backends require complete independently discovered scope')
        backend_spec=importlib.util.spec_from_file_location('ud_owned_secondary_backend','/opt/mutation/harness/oci-secondary.py')
        backend=importlib.util.module_from_spec(backend_spec);backend_spec.loader.exec_module(backend)
        raise SystemExit(backend.run(work,state,receipt,args.backend,inventory_only=args.inventory_only,verify_schedule=lambda plan:bind_schedule(plan,args.backend)))
    if args.backend=='typescript':
        if args.file or args.mutant_filter:raise ValueError('Stryker backend requires its complete independently discovered scope')
        backend_spec=importlib.util.spec_from_file_location('ud_owned_stryker_backend','/opt/mutation/harness/oci-stryker.py')
        backend=importlib.util.module_from_spec(backend_spec);backend_spec.loader.exec_module(backend)
        raise SystemExit(backend.run(work,state,receipt,diagnostic_range=args.diagnostic_stryker_range,inventory_only=args.inventory_only,verify_schedule=lambda plan:bind_schedule(plan,args.backend)))
    if args.backend=='perl':
        if args.file or args.mutant_filter:raise ValueError('Perl backend requires its complete independently discovered scope')
        backend_spec=importlib.util.spec_from_file_location('ud_owned_perl_backend',work/'scripts/quality/perl-mutation.py')
        backend=importlib.util.module_from_spec(backend_spec);backend_spec.loader.exec_module(backend)
        private_parser=Path('/opt/mutation/perl-parser');perl='/opt/mutation/bin/perl'
        plan,_=backend.schedule(work,private_parser,perl,state/'perl-generation' if args.inventory_only else None)
        (state/'perl-schedule.json').write_text(json.dumps(plan,indent=2)+'\n')
        bind_schedule(plan,args.backend)
        if args.inventory_only:raise SystemExit(0)
        report=backend.run(work,private_parser,perl,sys.executable,state/'perl-full.json',verify_schedule=lambda plan:bind_schedule(plan,args.backend))
        guards_spec=importlib.util.spec_from_file_location('ud_owned_guard_projection',work/'scripts/quality/perl-guard-mutation.py')
        guards=importlib.util.module_from_spec(guards_spec);guards_spec.loader.exec_module(guards)
        projection=guards.project_protected((work/guards.BRIDGE).read_bytes(),(work/guards.TEST).read_bytes(),report)
        (state/'perl-guard-fixture.json').write_text(json.dumps(projection,indent=2)+'\n')
        raise SystemExit(0 if all(item['status']=='Killed'for item in report['outcomes'])else 1)
    (work/'src').mkdir();shutil.copytree(work/'workers/ud/src/ud_agent',work/'src/ud_agent')
    project=work/'pyproject.toml';text=project.read_text();selected=[file.replace('workers/ud/src/ud_agent/','src/ud_agent/',1)for file in args.file]or['src/ud_agent','scripts']
    supporting=['.github','packaging','skills','runtime','release','contracts','quality','licenses','LICENSE','NOTICE','README.md','Cargo.toml','Cargo.lock','package.json','package-lock.json','workers']
    text=text.replace('source_paths = ["workers/ud/src/ud_agent"]','source_paths = '+json.dumps(selected)+'\nalso_copy = '+json.dumps(supporting))
    import re
    text=re.sub(r'pytest_add_cli_args_test_selection = \[[^\n]*\]','pytest_add_cli_args_test_selection = ["tests"]',text);project.write_text(text)
    receipt.update(source='/input/source',copy=str(work),qualification='mutation-source-copy');bound=state/'snapshot.json';bound.write_text(json.dumps(receipt,indent=2)+'\n')
    os.environ['SOURCE_DATE_EPOCH'] = '315532800'
    os.environ.update(PYTEST_PLUGINS='pytest_evidence',UD_MUTATION_OCI_GUARD='1',UD_MUTATION_PYTEST_EVIDENCE=str(state/'pytest-events.jsonl'),UD_AGENT_PYTHON=sys.executable,UD_RELEASE_PYTHON=sys.executable,PYTEST_DISABLE_PLUGIN_AUTOLOAD='1')
    os.chdir(work);sys.path.insert(0,'/opt/mutation/harness');sys.argv=['mutmut-driver.py','--source-receipt',str(bound),'--schedule',str(state/'schedule.json'),'--outcomes',str(state/'outcomes.json'),*(['--source-subset']if args.file else[]),*(['--inventory-only']if args.inventory_only else[]),*[argument for value in args.mutant_filter for argument in['--mutant-filter',value]]]
    import runpy
    runpy.run_path('/opt/mutation/harness/mutmut-driver.py',run_name='__main__',init_globals={'verify_frozen_schedule':lambda plan:bind_schedule(plan,args.backend)})
if __name__=='__main__':main()
