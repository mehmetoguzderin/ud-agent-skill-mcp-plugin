#!/usr/bin/env python3
"""Run independently scheduled cargo-mutants operators in isolated source copies.

The pinned discoverer occasionally proposes Default::default() for a capability
type without Default. Repair that invalid operator to a type-correct error
return before scheduling, and parenthesize bare integer casts before a proposed
less-than comparison. Compilation errors still never count as test kills.
"""
from __future__ import annotations
import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from difflib import unified_diff
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import threading
import unicodedata

VERSION='cargo-mutants-27.1.0+ud-literal-1'
TARGETS=('aarch64-apple-darwin','x86_64-apple-darwin','aarch64-unknown-linux-gnu','x86_64-unknown-linux-gnu','aarch64-pc-windows-msvc','x86_64-pc-windows-msvc')

def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False)

def fingerprint(data):
    return hashlib.sha256(data).hexdigest()

def issue_cfg_generation(source_sha256,sdk_sha256,compiler_sha256,run):
    """Execute only the original compiler's data-only target fact query."""
    records=[]
    for target in TARGETS:
        for mode in ('normal','test'):
            command=['/opt/mutation/rust/bin/rustc','--print','cfg','--target',target]+(['--test']if mode=='test'else[])
            outcome=run(command)
            if outcome.returncode!=0 or outcome.stderr or not isinstance(outcome.stdout,str)or not outcome.stdout.endswith('\n')or len(outcome.stdout.encode())>1024**2:
                raise ValueError('Original Rust compiler target fact generation failed')
            row={'target':target,'mode':mode,'command':command,'status':0,'stderr':'','stdout':outcome.stdout,'stdout_sha256':fingerprint(outcome.stdout.encode())}
            row['generation_sha256']=fingerprint(canonical(row).encode());records.append(row)
    return {'schema_version':1,'source_tree_sha256':source_sha256,'sdk_receipt_sha256':sdk_sha256,'compiler_sha256':compiler_sha256,'records':records}

def normalize_definition(item,manifest,workspaces):
    selected=workspaces[manifest];original=dict(item);file=item['file']
    prefix=Path(manifest).parent.as_posix()
    normalized=file if prefix=='.'else prefix+'/'+file
    if not normalized.startswith(selected['cwd']+'/src/')or any(part in('','.','..')for part in normalized.split('/'))or item.get('package')!=selected['package']or not item['name'].startswith(file+':'):
        raise ValueError('Rust upstream definition escapes its explicit workspace')
    return {**item,'file':normalized,'name':normalized+item['name'][len(file):],'diff':item['diff'].replace('--- '+file+'\n','--- '+normalized+'\n',1),'workspace_manifest':manifest,'upstream_definition':original}

def offsets(data,span):
    lines=data.splitlines(keepends=True)
    def position(value):
        line,column=value['line'],value['column']
        if not 1<=line<=len(lines) or not 1<=column<=len(lines[line-1])+1:
            raise ValueError('Rust operator has an invalid byte span')
        return sum(map(len,lines[:line-1]))+column-1
    start,end=position(span['start']),position(span['end'])
    if start>=end:
        raise ValueError('Rust operator has an empty or reversed span')
    data[start:end].decode('utf-8')
    return start,end

def definition(item,data):
    """Bind a repaired operator to the discoverer's full original definition."""
    result=dict(item)
    original=item['replacement']
    replacement=original
    repair=None
    returns=item.get('function',{}).get('return_type','') if item.get('function') else ''
    if item.get('genre')=='FnValue' and 'Default::default()' in original:
        if re.search(r'\b(?:Result)\s*<',returns):
            replacement='Err(std::io::Error::other("mutation error return").into())'
        elif re.fullmatch(r'->\s*(?:std::)?io::Error',returns.strip()):
            replacement='std::io::Error::other("mutation error return")'
    start,end=offsets(data,item['span'])
    if replacement!=original:
        repair='ud-type-correct-return-1'
    if item.get('genre')=='BinaryOperator' and original=='<':
        operator=re.search(r': replace (>=?) with < in ',item['name'])
        if operator:
            if data[start:end]!=operator[1].encode():
                raise ValueError('Rust cast comparison operator differs from its source span')
            line_start=data.rfind(b'\n',0,start)+1
            prefix=data[line_start:start]
            cast=re.search(rb'(?P<cast>[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*(?:\(\))?)*[ \t]+as[ \t]+(?:[ui](?:8|16|32|64|128)|[ui]size))[ \t]*$',prefix)
            # Only this simple operand idiom is recognized; do not infer a
            # boundary across unary operators, comments or arbitrary Rust syntax.
            if cast and (cast.start()==0 or re.search(rb'(?:\bif|\bwhile|\breturn|&&|\|\||[({=,;])[ \t]*$',prefix[:cast.start()])):
                start=line_start+cast.start()
                replacement='('+cast['cast'].decode()+')'+prefix[cast.end('cast'):].decode()+original
                result['span']={'start':{'line':item['span']['start']['line'],'column':cast.start()+1},'end':dict(item['span']['end'])}
                repair='ud-parenthesized-cast-comparison-1'
    if repair:
        result['operator_repair']={'version':repair,'original_definition':item}
        result['replacement']=replacement
        result['name']=item['name']+' ['+repair+']'
        mutated=data[:start]+replacement.encode()+data[end:]
        result['diff']=''.join(unified_diff(data.decode().splitlines(True),mutated.decode().splitlines(True),fromfile=item['file'],tofile=result['name']))
    return result

def assertion_evidence(log, item=None, source=None, phase=None):
    if item is not None or phase is not None:
        payload=json.dumps({'root':str(source),'item':item,'log':log,**({'phase':phase}if phase is not None else{})})
        checked=subprocess.run(['node',str(source/'scripts/quality/rust-assertions.mjs')],input=payload,capture_output=True,text=True,timeout=30)
        if checked.returncode:
            raise ValueError('Strict Rust assertion grader failed: '+checked.stderr[-2000:])
        return json.loads(checked.stdout)
    failures=[]
    for match in re.finditer(r"^thread '([^']+)'(?: \([^\n]*\))? panicked at ([^\n]+):\n([^\n]+)(?:\n|$)",log,re.M):
        message=match[3]
        failures.append({'test':match[1],'location':match[2],'message':message,'kind':'assertion' if re.match(r'assertion(?: `[^\n]+` failed| failed:)',message) else 'runtime'})
    count=sum(int(item)for item in re.findall(r'test result: FAILED\. \d+ passed; ([1-9]\d*) failed; 0 ignored',log))
    return {'failures':failures,'valid':bool(failures)and count==len(failures)and all(item['kind']=='assertion'for item in failures)}

def baseline_evidence(log):
    rows=re.findall(r'test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored',log)
    return bool(rows)and sum(int(item[0])for item in rows)>0 and all(item[1:] == ('0','0')for item in rows)

def copy_source(receipt,target):
    target.mkdir(parents=True)
    original=Path(receipt['copy'])
    seen=set()
    for item in receipt['files']:
        name=item['path']
        if not isinstance(name,str)or not name or name.startswith('/')or any(character in name for character in '\\\0:')or any(part in('','.','..')for part in name.split('/'))or unicodedata.normalize('NFC',name)!=name or name.casefold()in seen or type(item['executable'])is not bool:
            raise ValueError('Rust source copy has an escaping, colliding or invalid path')
        seen.add(name.casefold())
        source=original/item['path'];destination=target/item['path']
        for parent in source.parents:
            if parent==original:break
            if parent.is_symlink()or not parent.is_dir():raise ValueError('Rust source copy contains an aliased parent')
        if source.is_symlink()or not source.is_file()or source.stat().st_nlink!=1 or source.stat().st_size>128*1024**2:
            raise ValueError('Rust source receipt is stale, oversized or aliases another tree')
        data=source.read_bytes()
        if fingerprint(data)!=item['sha256']:
            raise ValueError('Rust source receipt is stale or aliases another tree')
        destination.parent.mkdir(parents=True,exist_ok=True);destination.write_bytes(data);destination.chmod(0o755 if item['executable']else 0o644)

def main(verify_schedule=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--snapshot',type=Path,required=True)
    parser.add_argument('--cargo-mutants',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--jobs',type=int,default=2)
    parser.add_argument('--file',action='append',default=[])
    parser.add_argument('--shard-index',type=int,default=0)
    parser.add_argument('--shard-count',type=int,default=1)
    parser.add_argument('--timeout',type=float,default=120)
    parser.add_argument('--inventory-only',action='store_true')
    args=parser.parse_args()
    if os.name != 'posix' or not hasattr(os, 'geteuid') or os.geteuid() != 0 or not Path('/opt/mutation/input-receipt.json').is_file() or os.environ.get('UD_MUTATION_OCI_GUARD') != '1':
        raise ValueError('Rust mutation execution requires the protected native ARM OCI backend; host execution is forbidden')
    if args.cargo_mutants != Path('/opt/mutation/rust/bin/cargo-mutants'):
        raise ValueError('Rust discovery requires the immutable image-bound discoverer')
    adapter_spec=importlib.util.spec_from_file_location('ud_rust_discovery_identity','/opt/mutation/harness/rust-test-runtime.py')
    identity=importlib.util.module_from_spec(adapter_spec);adapter_spec.loader.exec_module(identity)
    toolchain=identity.read_json('/opt/mutation/rust-input-receipt.json')
    sdk_bytes=Path('/opt/mutation/rust-input-receipt.json').read_bytes()
    image_inputs=identity.read_json('/opt/mutation/input-receipt.json')
    if image_inputs.get('rust',{}).get('sha256')!=fingerprint(sdk_bytes)or image_inputs['rust'].get('size_bytes')!=len(sdk_bytes):
        raise ValueError('Rust SDK differs from the frozen image authority')
    discoverer=next(item for item in toolchain['files']if item['path']=='bin/cargo-mutants')
    if identity.file_hash(args.cargo_mutants,executable=True,immutable=True)!=(discoverer['sha256'],discoverer['size']):
        raise ValueError('Rust discovery binary differs from its frozen receipt')
    receipt=json.loads(args.snapshot.read_text());source=Path(receipt['copy']).resolve(strict=True)
    if receipt.get('qualification')not in('diagnostic-only','mutation-source-copy')or source==Path(receipt['source']).resolve()or(source/'.git').exists():
        raise ValueError('Rust execution requires an independent source snapshot')
    if not 1<=args.jobs<=16 or not 0<=args.shard_index<args.shard_count or not 1<=args.shard_count<=1024 or args.timeout<=0:
        raise ValueError('Invalid Rust shard or execution bounds')
    output=args.output.resolve();output.mkdir(mode=0o700)
    env={'PATH':'/opt/mutation/rust/bin:/opt/mutation/node/bin:/opt/mutation/python/bin:/usr/bin:/bin','LANG':'C.UTF-8','CARGO_NET_OFFLINE':'true','CARGO_HOME':'/state/rust-discovery-home'}
    hashes={item['path']:item['sha256']for item in receipt['files']}
    manifests=list(identity.WORKSPACES)
    for file in args.file:
        if file not in hashes or not file.endswith('.rs')or not any(file.startswith(row['cwd']+'/src/')for row in identity.WORKSPACES.values()):
            raise ValueError('Requested Rust subset is not source-bound to a declared workspace')
    if args.file:manifests=[name for name in manifests if any(file.startswith(identity.WORKSPACES[name]['cwd']+'/')for file in args.file)]
    inventory=[];seen=set();discovered=[]
    for manifest in manifests:
        selected=identity.workspace(manifest);label=selected['id']
        discover=[str(args.cargo_mutants),'mutants','--manifest-path',str(source/manifest),'--workspace','--no-config','--skip-calls-defaults','false','--list','--json','--diff']
        prefix=Path(manifest).parent.as_posix()
        for file in args.file:
            if file.startswith(selected['cwd']+'/'):discover.extend(['--file',file if prefix=='.'else str(Path(file).relative_to(prefix))])
        with(output/('discovery-'+label+'.json')).open('xb')as target,(output/('discovery-'+label+'.log')).open('xb')as log:
            subprocess.run(discover,cwd=source,env=env,stdout=target,stderr=log,check=True,timeout=120)
        raw=json.loads((output/('discovery-'+label+'.json')).read_text())
        if not isinstance(raw,list)or not raw:raise ValueError('Rust workspace discovery scheduled no operators')
        for original in raw:
            item=normalize_definition(original,manifest,identity.WORKSPACES);file=item['file'];data=(source/file).read_bytes()
            if file not in hashes or fingerprint(data)!=hashes[file]:raise ValueError('Rust discovery source does not match its receipt')
            repaired=definition(item,data);bound={'tool':'cargo-mutants','version':'27.1.0',**repaired};digest=fingerprint(canonical(bound).encode())
            if digest in seen:raise ValueError('Duplicate Rust operator definition')
            seen.add(digest);discovered.append(item)
            inventory.append({'id':repaired['name'],'file':file,'source_sha256':hashes[file],'definition_sha256':digest,'definition':bound,'mutant':repaired,'workspace_manifest':manifest})
    (output/'discovery.json').write_text(json.dumps(discovered,indent=2)+'\n')
    if not inventory:
        raise ValueError('Rust discovery scheduled no operators')
    compilers=[item for item in toolchain['files']if item['path']=='bin/rustc']
    if len(compilers)!=1 or identity.file_hash(Path('/opt/mutation/rust/bin/rustc'),executable=True,immutable=True)!=(compilers[0]['sha256'],compilers[0]['size']):
        raise ValueError('Rust cfg generation requires the immutable frozen compiler')
    generation=issue_cfg_generation(receipt['source_tree_sha256'],fingerprint(sdk_bytes),compilers[0]['sha256'],lambda command:subprocess.run(command,cwd='/state',env=env,capture_output=True,text=True,timeout=30))
    generation_bytes=(json.dumps(generation,indent=2)+'\n').encode();(output/'target-cfg-generation.json').write_bytes(generation_bytes);(output/'target-cfg-generation.json').chmod(0o600)
    (output/'rust-sdk-receipt.json').write_bytes(sdk_bytes);(output/'rust-sdk-receipt.json').chmod(0o600)
    cfg_request={'root':str(source),'source_tree_sha256':receipt['source_tree_sha256'],'inventory':inventory,'generation':generation}
    cfg_checked=subprocess.run(['node',str(source/'scripts/quality/rust-applicability-cli.mjs')],input=json.dumps(cfg_request),capture_output=True,text=True,env=env,timeout=300)
    if cfg_checked.returncode or cfg_checked.stderr:raise ValueError('Rust source/target applicability generation failed: '+cfg_checked.stderr[-4000:])
    applicability=json.loads(cfg_checked.stdout)
    if len(applicability.get('inventory',[]))!=len(inventory):raise ValueError('Rust applicability omitted scheduled definitions')
    applicability_bytes=(json.dumps(applicability,indent=2)+'\n').encode();(output/'applicability.json').write_bytes(applicability_bytes);(output/'applicability.json').chmod(0o600)
    schedule={'schema_version':1,'qualification':'diagnostic-only','tool':VERSION,'source_tree_sha256':receipt['source_tree_sha256'],'scope_complete':not args.file,'scheduled':len(inventory),'inventory':inventory,'shard_count':args.shard_count,'shard_index':args.shard_index}
    schedule['current_target']=identity.TARGET
    schedule['applicability']={'path':'applicability.json','sha256':fingerprint(applicability_bytes),'generation_path':'target-cfg-generation.json','generation_sha256':fingerprint(generation_bytes),'sdk_receipt_path':'rust-sdk-receipt.json','sdk_receipt_sha256':fingerprint(sdk_bytes)}
    (output/'schedule.json').write_text(json.dumps(schedule,indent=2)+'\n')
    applicability_rows={row['id']:row for row in applicability['inventory']}
    if set(applicability_rows)!={row['id']for row in inventory}:raise ValueError('Rust applicability substituted scheduled identities')
    chosen=[item for index,item in enumerate(inventory)if index%args.shard_count==args.shard_index]
    print(json.dumps({'scheduled':len(inventory),'this_shard':len(chosen),'source_tree_sha256':receipt['source_tree_sha256']}),flush=True)
    # Reviewed boundary assertions are normal cfg(test) includes in the source,
    # so independent Cargo discovery sees the exact same immutable test set.
    schedule['trusted_test_augmentations']=[]
    (output/'schedule.json').write_text(json.dumps(schedule,indent=2)+'\n')
    workers=[]
    # Separate target trees make CARGO_BIN_EXE_* integration tests use the
    # current mutated helper rather than an external baseline executable.
    for index in range(args.jobs):
        work=output/('work-'+str(index));copy_source(receipt,work)
        workers.append(work)
    protected_spec=importlib.util.spec_from_file_location('ud_owned_rust_executor','/opt/mutation/harness/rust-protected.py')
    protected_module=importlib.util.module_from_spec(protected_spec);protected_spec.loader.exec_module(protected_module)
    protected=protected_module.ProtectedRust(receipt,output,schedule)
    execute_phase=protected.execute
    def commands(manifest):
        base=['cargo','test','--workspace','--manifest-path',manifest,'--locked','--offline']
        return [*base,'--no-run'],[*base,'--','--test-threads=1'],[*base,'--','--list','--format','terse']
    baseline=[]
    for index,work in enumerate(workers):
        builds={};listing_logs=[]
        # Discover all required workspace cases before consuming any baseline
        # test result. Every clone must reproduce the same exact inventories.
        for manifest in manifests:
            label=identity.workspace(manifest)['id'];compile_command,test_command,list_command=commands(manifest)
            phase=execute_phase(compile_command,work,env,output/f'baseline-{index}-{label}-build.log',300);phase['phase']='Build'
            if phase['process_status']!='Success':raise ValueError('Rust baseline compilation failed')
            listing=execute_phase(list_command,work,env,output/f'baseline-{index}-{label}-listing.log',300)
            if listing['process_status']!='Success':raise ValueError('Rust required test discovery failed')
            builds[manifest]=phase;listing_logs.append((output/f'baseline-{index}-{label}-listing.log').read_bytes())
        if index==0:
            schedule['workspace_manifests']=manifests
            schedule['tests']=[{'id':'rust:'+artifact+'#'+fingerprint(canonical([name,0]).encode())[:24],'source':artifact,'source_sha256':hashes[artifact],'name':name,'occurrence':0,'runner':'rust'}for artifact,names in protected.inventories.items()for name in names]
            if not schedule['tests']:raise ValueError('Rust required test discovery is empty')
            (output/'tests.log').write_bytes(b''.join(listing_logs));(output/'schedule.json').write_text(json.dumps(schedule,indent=2)+'\n')
            if verify_schedule is not None:verify_schedule(schedule)
            if args.inventory_only:return 0
        phases=[];baseline_logs=[]
        for manifest in manifests:
            label=identity.workspace(manifest)['id'];_,test_command,_=commands(manifest)
            test=execute_phase(test_command,work,env,output/f'baseline-{index}-{label}-test.log',300);test['phase']='Test'
            log=(output/f'baseline-{index}-{label}-test.log').read_text();complete=assertion_evidence(log,source=source,phase=test)
            if test['process_status']!='Success'or test.get('artifacts_complete')is not True or complete.get('artifacts_complete')is not True or not baseline_evidence(log):raise ValueError('Rust baseline has failed, ignored, empty or missing test outcomes')
            phases.extend([builds[manifest],test]);baseline_logs.append(log)
        (output/f'baseline-{index}-test.log').write_text(''.join(baseline_logs))
        baseline.append({'scenario':'Baseline','summary':'Success','log_path':f'baseline-{index}-test.log','phase_results':phases})
    queue=list(enumerate(chosen));mutex=threading.Lock();outcomes=[]
    def worker(index):
        work=workers[index]
        while True:
            with mutex:
                if not queue:return
                ordinal,item=queue.pop(0)
            mutant=item['mutant'];file=work/mutant['file'];original=file.read_bytes();production=original;start,end=offsets(production,mutant['span']);changed=production[:start]+mutant['replacement'].encode()+production[end:]
            if fingerprint(production)!=item['source_sha256']or changed==original:
                raise ValueError('Rust execution does not match its scheduled source replacement')
            applicability_row=applicability_rows[item['id']]
            if identity.TARGET not in applicability_row['applicable_targets']:
                outcome={'scenario':{'Mutant':mutant},'summary':'PendingNativeTarget','definition_sha256':item['definition_sha256'],'source_sha256':item['source_sha256'],'phase_results':[],'applicability':{'proof_sha256':schedule['applicability']['sha256'],'generation_sha256':schedule['applicability']['generation_sha256'],'row':applicability_row}}
                with mutex:
                    outcomes.append(outcome)
                    with(output/'outcomes.jsonl').open('a')as target:target.write(json.dumps(outcome)+'\n')
                    print(json.dumps({'completed':len(outcomes),'scheduled_this_shard':len(chosen),'summary':outcome['summary'],'id':item['id']}),flush=True)
                continue
            prefix=f'mutant-{ordinal:06d}';phases=[];summary='RuntimeError';evidence=None;compile_command,test_command,list_command=commands(item['workspace_manifest'])
            try:
                file.write_bytes(changed)
                phase=execute_phase(compile_command,work,env,output/(prefix+'-build.log'),args.timeout);phase['phase']='Build';phases.append(phase)
                if phase['process_status']=='Timeout':summary='Timeout'
                elif phase['process_status']!='Success':summary='Unviable'
                else:
                    listing=execute_phase(list_command,work,env,output/(prefix+'-listing.log'),args.timeout)
                    if listing['process_status']!='Success':raise ValueError('Rust mutation changed or omitted required tests')
                    phase=execute_phase(test_command,work,env,output/(prefix+'-test.log'),args.timeout);phase['phase']='Test';phases.append(phase)
                    log=(output/(prefix+'-test.log')).read_text();evidence=assertion_evidence(log,item,source,phase=phase)
                    if phase['process_status']=='Timeout':summary='Timeout'
                    elif phase.get('artifacts_complete')is not True or evidence.get('artifacts_complete')is not True:summary='RunnerError'
                    elif phase['process_status']=='Success':summary='MissedMutant'if baseline_evidence(log)else'RunnerError'
                    else:summary='CaughtMutant'if evidence['valid']else'RuntimeError'
            finally:
                file.write_bytes(original)
                if file.read_bytes()!=original:
                    raise ValueError('Owned Rust shard source restoration failed')
            outcome={'scenario':{'Mutant':mutant},'summary':summary,'definition_sha256':item['definition_sha256'],'source_sha256':item['source_sha256'],'log_path':prefix+'-test.log'if len(phases)>1 else prefix+'-build.log','phase_results':phases,'assertion_evidence':evidence}
            with mutex:
                outcomes.append(outcome)
                with(output/'outcomes.jsonl').open('a')as target:target.write(json.dumps(outcome)+'\n')
                print(json.dumps({'completed':len(outcomes),'scheduled_this_shard':len(chosen),'summary':summary,'id':item['id']}),flush=True)
    with ThreadPoolExecutor(max_workers=args.jobs)as pool:
        list(pool.map(worker,range(args.jobs)))
    report={'tool':VERSION,'total_mutants':len(inventory),'shard_count':args.shard_count,'shard_index':args.shard_index,'outcomes':[baseline[0],*outcomes],'source_tree_sha256':receipt['source_tree_sha256'],'end_time':datetime.now(timezone.utc).isoformat()}
    (output/'outcomes.json').write_text(json.dumps(report,indent=2)+'\n')
    return 0 if len(outcomes)==len(chosen)and all(item['summary']in('CaughtMutant','PendingNativeTarget')for item in outcomes)else 2

if __name__=='__main__':
    raise SystemExit(main())
