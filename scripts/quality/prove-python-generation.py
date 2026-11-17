"""Reconstruct every mutmut definition from its actual full generated file/index.

Projection witnesses bind deterministic runtime bytes, not equivalence of
inactive private function-body introspection. Full CONTROL remains retained.
"""
import argparse
from difflib import unified_diff
import hashlib
import importlib.metadata
import importlib.util
import inspect
import json
import os
from pathlib import Path
import re
import stat
import sys


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':'))


_ARTIFACTS = {}
_STATE = None

def data(file, maximum=1024**3, artifact=False):
    def named_identity(info):
        # Windows path stat exposes birthtime as ctime, while fstat exposes
        # native ChangeTime. Bind shared fields here and held ChangeTime below.
        return info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_size, info.st_mtime_ns
    def identity(info):
        return (*named_identity(info), info.st_ctime_ns)
    def ordinary(info):
        return stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= maximum and not getattr(info, 'st_file_attributes', 0) & 0x400
    named = os.lstat(file)
    if not ordinary(named):
        raise ValueError('bounded ordinary generation input required')
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NONBLOCK', 0)
    descriptor = os.open(file, flags)
    with os.fdopen(descriptor, 'rb') as stream:
        before = os.fstat(stream.fileno())
        if named_identity(before) != named_identity(named):
            raise ValueError('actual generation artifact changed before read')
        content = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
        current = os.lstat(file)
        if len(content) != before.st_size or identity(before) != identity(after) or not ordinary(current) or named_identity(before) != named_identity(current):
            raise ValueError('actual generation artifact changed during read')
        # Reopen the current name so all held/native timestamps are compared
        # using the same API, without accepting a substituted symlink fallback.
        check = os.open(file, flags)
        try:
            current = os.lstat(file)
            if not ordinary(current) or named_identity(before) != named_identity(current) or identity(before) != identity(os.fstat(check)) or identity(before) != identity(os.fstat(stream.fileno())):
                raise ValueError('actual generation artifact changed during read')
        finally:
            os.close(check)
    if artifact:
        name=file.relative_to(_STATE).as_posix();record={'path':name,'sha256':hashlib.sha256(content).hexdigest(),'size':len(content)}
        if name in _ARTIFACTS and _ARTIFACTS[name]!=record:raise ValueError('actual generation artifact changed between proof reads')
        _ARTIFACTS[name]=record
    return content

def load(file, maximum=1024**3, artifact=False):
    return json.loads(data(file,maximum,artifact))


def module(name, file):
    spec=importlib.util.spec_from_file_location(name,file)
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value)
    return value


def projection_inputs(source, state, receipt, source_files):
    """Check runtime bytes separately; only full CONTROL defines inventory."""
    directory=state/'control/python-projection';manifest_file=directory/'manifest.json'
    if not manifest_file.exists():
        if directory.exists()or directory.is_symlink():
            raise ValueError('runtime projection CONTROL manifest is missing')
        return None
    hashes={item['path']:item['sha256']for item in receipt['files']}
    def read(file,maximum=1024**3):
        current=state
        for part in file.relative_to(state).parts:
            current/=part
            if current.is_symlink():raise ValueError('runtime projection evidence cannot contain links')
        return data(file,maximum,True)
    def checked(record,expected):
        if not isinstance(record,dict)or set(record)!={'path','sha256','size_bytes'}or record['path']!=expected or type(record['size_bytes'])is not int or not 0<=record['size_bytes']<=1024**3 or not re.fullmatch('[0-9a-f]{64}',record.get('sha256','')):
            raise ValueError('runtime projection CONTROL descriptor is invalid')
        content=read(state/expected)
        if len(content)!=record['size_bytes']or hashlib.sha256(content).hexdigest()!=record['sha256']:
            raise ValueError('runtime projection CONTROL bytes differ')
        return content
    manifest_bytes=read(manifest_file,64*1024**2);manifest=json.loads(manifest_bytes)
    helper_name='scripts/quality/python-runtime-projection.py';helper_file=source/helper_name
    helper_bytes=data(helper_file)
    if hashes.get(helper_name)!=hashlib.sha256(helper_bytes).hexdigest():
        raise ValueError('runtime projection helper differs from protected source')
    helper=module('ud_generation_projection',helper_file)
    if not isinstance(manifest,dict)or set(manifest)!={'schema_version','version','helper_sha256','source_tree_sha256','files'}or manifest.get('schema_version')!=1 or manifest.get('version')!=helper.VERSION or manifest.get('helper_sha256')!=hashes[helper_name]or manifest.get('source_tree_sha256')!=receipt['sha256']or not isinstance(manifest.get('files'),list):
        raise ValueError('runtime projection manifest differs from its source authority')
    runtime_file=state/'runtime-input-receipt.json';runtime=json.loads(read(runtime_file,64*1024**2));sdk=runtime.get('python_runtime_projection')
    if not isinstance(sdk,dict)or sdk.get('schema_version')!=1 or sdk.get('version')!=helper.VERSION or sdk.get('helper_sha256')!=hashes[helper_name]or sdk.get('distribution')!='mutmut'or sdk.get('distribution_version')!='3.8.1'or sdk.get('installed_path')!='python/lib/python3.14/site-packages/mutmut/mutation/trampoline.py':
        raise ValueError('runtime projection SDK differs from its fixed helper/distribution')
    originals=[item for item in runtime.get('python_packages',[])if item.get('name')=='mutmut'and item.get('version')=='3.8.1']
    if len(originals)!=1 or sdk.get('original_wheel')!={'filename':originals[0].get('url','').rsplit('/',1)[-1],'sha256':originals[0].get('hash','').removeprefix('sha256:'),'size_bytes':originals[0].get('size')}:
        raise ValueError('runtime projection SDK differs from its exact locked original wheel')
    sdk_artifacts=[runtime_file.relative_to(state).as_posix()];sdk_sources={}
    for field,name in [('upstream_source','python-trampoline-upstream.py'),('adapter_source','python-trampoline-adapter.py'),('derived_source','python-trampoline-derived.py')]:
        record=sdk.get(field)
        if not isinstance(record,dict)or set(record)!={'path','sha256','size_bytes'}or record.get('path')!=name or type(record.get('size_bytes'))is not int or not 1<=record['size_bytes']<=1024**2:
            raise ValueError('runtime projection SDK source descriptor is invalid')
        actual_file=state/('runtime-'+name);content=read(actual_file,1024**2)
        if len(content)!=record['size_bytes']or hashlib.sha256(content).hexdigest()!=record.get('sha256'):
            raise ValueError('runtime projection SDK source bytes differ from its receipt')
        sdk_sources[field]=content;sdk_artifacts.append(actual_file.relative_to(state).as_posix())
    installed_file=state/'runtime-python-trampoline-installed.py';installed=read(installed_file,1024**2)
    if sdk_sources['derived_source']!=sdk_sources['upstream_source']+sdk_sources['adapter_source']or installed!=sdk_sources['derived_source']:
        raise ValueError('runtime projection installed SDK is not exact upstream plus fixed adapter')
    sdk_artifacts.append(installed_file.relative_to(state).as_posix())
    from mutmut.mutation.diff_apply import generated_function_names
    mapped={('src/ud_agent/'+name.removeprefix('workers/ud/src/ud_agent/')if name.startswith('workers/ud/src/ud_agent/')else name):name for name in source_files}
    rows={};baselines={};artifacts={};all_keys=set()
    for row in manifest['files']:
        if not isinstance(row,dict)or set(row)!={'path','source_sha256','control','spans','generation_metadata','mutants','baseline'}or row.get('path')not in mapped or row['path']in rows or row.get('source_sha256')!=hashes[mapped[row['path']]]:
            raise ValueError('runtime projection manifest repeats, omits or changes source identity')
        name=row['path'];control_name='control/python-projection/files/'+name
        content=checked(row['control'],control_name).decode('utf-8')
        index=json.loads(checked(row['spans'],control_name+'.spans'))
        metadata=json.loads(checked(row['generation_metadata'],'generation-metadata/'+name+'.meta'))
        if index.get('version')!=1 or not isinstance(index.get('spans'),dict)or not isinstance(metadata.get('exit_code_by_key'),dict)or any(value is not None for value in metadata['exit_code_by_key'].values()):
            raise ValueError('runtime projection CONTROL index or pristine metadata is invalid')
        mutants=[{'id':key,'name':generated_function_names(key)[1]}for key in metadata['exit_code_by_key']]
        if not isinstance(row['mutants'],list)or sorted(row['mutants'],key=canonical)!=sorted(mutants,key=canonical):
            raise ValueError('runtime projection manifest differs from every original mutant key')
        numbered={name for name in index['spans']if re.fullmatch(r'.+__mutmut_[0-9]+',name)and int(name.rpartition('__mutmut_')[2])>0}
        if numbered!={item['name']for item in mutants}or any(generated_function_names(item['id'])[0]not in index['spans']for item in mutants)or all_keys.intersection(metadata['exit_code_by_key']):
            raise ValueError('runtime projection metadata omits or repeats a full CONTROL operator')
        all_keys.update(metadata['exit_code_by_key'])
        baseline=helper.project_source(content,index['spans'],None,name).encode('utf-8')
        if row['baseline']!={'sha256':hashlib.sha256(baseline).hexdigest(),'size_bytes':len(baseline)}:
            raise ValueError('runtime projection baseline differs from full CONTROL replay')
        rows[name]=row;baselines[name]=row['baseline']
        artifacts[name]=[manifest_file.relative_to(state).as_posix(),control_name,control_name+'.spans','generation-metadata/'+name+'.meta',*sdk_artifacts]
        del content,index,metadata,baseline
    if set(rows)!=set(mapped):raise ValueError('runtime projection manifest omits selected Python modules')
    manifest_sha=hashlib.sha256(manifest_bytes).hexdigest();witnesses=[];sequences=set()
    selected={item['id']:(name,item['name'])for name,row in rows.items()for item in row['mutants']}
    for file in sorted((state/'control/jobs').glob('*.json')):
        if file.name.endswith('.exec.json'):continue
        record=json.loads(read(file,64*1024**2));witness=record.get('projection');sequence=record.get('projection_sequence')
        if not isinstance(witness,dict)or type(sequence)is not int or not 100000<sequence<2**31 or sequence!=record.get('uid')or sequence in sequences or record.get('collected')is not True or ('owned_descendants_cancelled'in record and record['owned_descendants_cancelled']!=[]):
            raise ValueError('runtime projection job witness is missing, repeated or not collected')
        if record.get('projection_sha256')!=hashlib.sha256(canonical(witness).encode()).hexdigest():
            raise ValueError('runtime projection job witness fingerprint differs')
        if set(witness)!={'schema_version','version','mode','active_key','manifest_sha256','files','guard_exit_code','projection_sequence'}or witness.get('schema_version')!=1 or witness.get('version')!=helper.VERSION or witness.get('manifest_sha256')!=manifest_sha or witness.get('guard_exit_code')!=125 or witness.get('projection_sequence')!=sequence or witness.get('mode')not in {'collection','baseline','stats','forced-fail','active'}or not isinstance(witness.get('files'),list):
            raise ValueError('runtime projection job witness contract differs')
        key=witness['active_key']
        if witness['mode']=='active':
            if not isinstance(key,str)or key not in selected:raise ValueError('runtime projection selects an unknown original mutant')
        elif key is not None:raise ValueError('baseline runtime projection carries an active mutant')
        seen=set()
        for item in witness['files']:
            if not isinstance(item,dict)or set(item)!={'path','control_sha256','spans_sha256','projected_sha256','size_bytes','active_name'}or item.get('path')not in rows or item['path']in seen:
                raise ValueError('runtime projection job omits or repeats a module')
            name=item['path'];seen.add(name);row=rows[name]
            active=selected[key][1]if key is not None and selected[key][0]==name else None
            expected=baselines[name]
            if active is not None:
                content=checked(row['control'],row['control']['path']).decode('utf-8')
                index=json.loads(checked(row['spans'],row['spans']['path']))
                projected=helper.project_source(content,index['spans'],active,name).encode('utf-8')
                expected={'sha256':hashlib.sha256(projected).hexdigest(),'size_bytes':len(projected)}
                del content,index,projected
            if item!={'path':name,'control_sha256':row['control']['sha256'],'spans_sha256':row['spans']['sha256'],'projected_sha256':expected['sha256'],'size_bytes':expected['size_bytes'],'active_name':active}:
                raise ValueError('runtime projection job differs from deterministic full CONTROL replay')
        if seen!=set(rows):raise ValueError('runtime projection job omits selected Python modules')
        context={'schema_version':1,'version':helper.VERSION,'uid':sequence,'projection_sequence':sequence,
                 'helper_sha256':hashes[helper_name],'manifest_sha256':manifest_sha,'mode':witness['mode'],
                 'active_key':key,'projection_sha256':record['projection_sha256'],'files':witness['files']}
        context_bytes=(canonical(context)+'\n').encode('utf-8')
        if record.get('projection_context')!={'path':'work/mutants/.ud-runtime-projection.json','sha256':hashlib.sha256(context_bytes).hexdigest(),'size_bytes':len(context_bytes)}:
            raise ValueError('runtime projection context differs from its root-issued job witness')
        sequences.add(sequence);witnesses.append((sequence,file,witness,context_bytes))
    if not witnesses:raise ValueError('runtime projection has no admitted job witness')
    _,latest_file,latest,latest_context=max(witnesses,key=lambda item:item[0])
    context_file=state/'work/mutants/.ud-runtime-projection.json'
    if read(context_file,64*1024**2)!=latest_context:
        raise ValueError('actual runtime context differs from its latest root-issued job')
    for item in latest['files']:
        name=item['path'];runtime_file=state/'work/mutants'/name;actual=read(runtime_file)
        if len(actual)!=item['size_bytes']or hashlib.sha256(actual).hexdigest()!=item['projected_sha256']:
            raise ValueError('actual runtime projection differs from its latest admitted job')
        artifacts[name].extend([latest_file.relative_to(state).as_posix(),runtime_file.relative_to(state).as_posix(),context_file.relative_to(state).as_posix()])
    return {'generated':directory/'files','artifacts':artifacts,'manifest_sha256':manifest_sha,'version':helper.VERSION}


def prove(source, state, source_receipt):
    global _STATE
    _STATE=state;_ARTIFACTS.clear()
    if importlib.metadata.version('mutmut') != '3.8.1':
        raise ValueError('the exact pinned mutmut reader is required')
    from mutmut.mutation.diff_apply import generated_function_names
    from mutmut.utils.format_utils import orig_function_and_class_names_from_key
    receipt=load(source_receipt,64*1024**2);hashes={item['path']:item['sha256']for item in receipt['files']}
    plan=load(state/'schedule.json',artifact=True);discovery=load(state/'discovery.json',64*1024**2,artifact=True)
    if plan.get('scope_complete')is not True or discovery.get('scope_complete')is not True or plan.get('source_tree_sha256')!=receipt['sha256']or discovery.get('source_tree_sha256')!=receipt['sha256']or plan.get('discovery_sha256')!=hashlib.sha256((state/'discovery.json').read_bytes()).hexdigest():
        raise ValueError('complete independently discovered source identity required')
    driver=module('ud_generation_driver',source/'scripts/quality/mutmut-driver.py')
    operators=module('ud_generation_operators',source/'scripts/quality/python-operators.py')
    profile=plan['generation_profile']
    if profile!={'version':operators.VERSION,'mutmut':'3.8.1','libcst':importlib.metadata.version('libcst'),'repairs':['IfExp-word-separators','typed-ABI-argument-v1'],'generation_mode':'deterministic-sequential'}:
        raise ValueError('generation profile differs from its actual pinned operator source')
    generated=state/'work/mutants';artifacts=['schedule.json','discovery.json'];repairs=[]
    dispatch=state/'full-suite-dispatch.json'
    if dispatch.exists()or dispatch.is_symlink():
        data(dispatch,64*1024**2,True);artifacts.append('full-suite-dispatch.json')
    for file in sorted((generated/'.ud-generator-repairs').glob('*.jsonl')):
        artifacts.append(file.relative_to(state).as_posix())
        for line in data(file,64*1024**2,True).decode().splitlines():
            item=json.loads(line);claimed=item['repair_sha256'];unsigned={key:value for key,value in item.items()if key!='repair_sha256'}
            if hashlib.sha256(json.dumps(unsigned,sort_keys=True,separators=(',',':')).encode()).hexdigest()!=claimed:
                raise ValueError('actual generator repair fingerprint differs')
            repairs.append(item)
    repairs=list({item['repair_sha256']:item for item in repairs}.values())
    if repairs!=plan['generation_repairs']:
        raise ValueError('scheduled repairs differ from actual materialized repairs')
    by_file={}
    for item in repairs:by_file.setdefault(item['file'],[]).append(item)
    typed=operators.typed_repairs(source,hashes)
    typed_raw_ids='raw_id'in inspect.signature(typed).parameters
    registry=load(source/'quality/python-operator-repairs.json',16*1024**2)
    typed_rows={item['id']:item for item in registry['rows']}
    selected_graph=operators.graph_registry_selection(source)
    graph_registry=source/selected_graph['registry']if selected_graph is not None else None
    if graph_registry is not None and graph_registry.exists():
        for item in load(graph_registry,64*1024**2)['rows']:
            if item['id']in typed_rows:raise ValueError('typed registries repeat an original operator identity')
            typed_rows[item['id']]=item
    planned={item['id']:item for item in plan['inventory']}
    if len(planned)!=len(plan['inventory'])or len(planned)!=plan['scheduled']:
        raise ValueError('scheduled mutation IDs are duplicate or incomplete')
    discovered={item['id']:item for item in discovery['inventory']}
    if len(discovered)!=len(discovery['inventory'])or set(discovered)!=set(planned):
        raise ValueError('schedule omits actual independently discovered IDs')
    inventory=[];materializations=[];seen=set();definitions=set()
    source_files=sorted(name for name in hashes if(name.startswith('workers/ud/src/ud_agent/')or name.startswith('scripts/'))and name.endswith('.py'))
    projection=projection_inputs(source,state,receipt,source_files)
    if projection is not None:generated=projection['generated']
    representation=plan.get('definition_representation')
    if representation is not None:
        runtime=plan.get('runtime_representation')
        if representation!='mutmut-control-spans-v1'or projection is None or plan.get('schema_version')!=1 or plan.get('tool')!='mutmut'or plan.get('tool_version')!='3.8.1'or not isinstance(runtime,dict)or runtime.get('manifest_path')!='control/python-projection/manifest.json'or runtime.get('manifest_sha256')!=projection['manifest_sha256']or runtime.get('version')!=projection['version']:
            raise ValueError('compact Python definitions require their exact full CONTROL manifest')
    for file in source_files:
        original_file=source/file
        if original_file.is_symlink()or hashlib.sha256(original_file.read_bytes()).hexdigest()!=hashes[file]:
            raise ValueError('source changed before generation reconstruction')
        mapped='src/ud_agent/'+file.removeprefix('workers/ud/src/ud_agent/')if file.startswith('workers/ud/src/ud_agent/')else file
        data_file=generated/mapped;index_file=Path(str(data_file)+'.spans');meta_file=Path(str(data_file)+'.meta')
        index=load(index_file,64*1024**2,True)
        if index.get('version')!=1:
            raise ValueError('unsupported actual generated function index')
        # A pristine generation metadata copy is preferred for later executions;
        # the initial failed-baseline run also has no per-mutant outcomes.
        pristine=state/'generation-metadata'/Path(mapped+'.meta')
        if pristine.exists():meta_file=pristine
        meta=load(meta_file,64*1024**2,True)
        if any(value is not None for value in meta['exit_code_by_key'].values()):
            raise ValueError('generation metadata contains outcomes instead of its pre-execution snapshot')
        lines=data(data_file,1024**3,True).decode().splitlines(keepends=True);spans=index['spans'];ids=[]
        file_artifacts=[path.relative_to(state).as_posix()for path in[data_file,index_file,meta_file]]
        if projection is not None:file_artifacts=list(dict.fromkeys([*file_artifacts,*projection['artifacts'][mapped]]))
        artifacts.extend(file_artifacts)
        original_text=original_file.read_text()
        def function(name,actual_name):
            start,end=spans[name]
            if not 1<=start<=end<=len(lines):raise ValueError('generated span exceeds actual file')
            text=''.join(lines[start-1:end])
            changed,count=re.subn(r'(?m)^(\s*(?:async\s+)?def\s+)'+re.escape(name)+r'(?=\()',lambda match:match.group(1)+actual_name,text,count=1)
            if count!=1:raise ValueError('actual generated function identity differs')
            return changed
        for key in meta['exit_code_by_key']:
            if key in seen or key not in discovered or discovered[key]['file']!=file or discovered[key]['source_sha256']!=hashes[file]:
                raise ValueError('actual generated ID is duplicated, omitted or unbound')
            seen.add(key);ids.append(key)
            original_name,replacement_name=generated_function_names(key);actual_name,_=orig_function_and_class_names_from_key(key)
            original=function(original_name,actual_name);replacement=function(replacement_name,actual_name)
            raw=typed_rows[key]['upstream_definition']['replacement_function']if key in typed_rows else replacement
            definition={'tool':'mutmut','version':'3.8.1','generation_profile':profile,'generation_repairs':[item for item in by_file.get(mapped,[])if item['replacement_expression']in raw],'file':file,
                        'location':driver.function_location(original_text,key.partition('__mutmut_')[0]+'__mutmut_orig'),'original_function':original,'replacement_function':raw,
                        'diff':'\n'.join(unified_diff(original.splitlines(),raw.splitlines(),fromfile=file,tofile=file,lineterm=''))}
            repaired=typed(file,raw,definition,raw_id=key)if typed_raw_ids else typed(file,raw,definition)
            if repaired is not None:
                changed,evidence=repaired
                if changed!=replacement:raise ValueError('typed repair differs from actual generated program')
                definition={**definition,'replacement_function':changed,'diff':'\n'.join(unified_diff(original.splitlines(),changed.splitlines(),fromfile=file,tofile=file,lineterm='')),'operator_repair':evidence}
            digest=hashlib.sha256(canonical(definition).encode()).hexdigest();selected=planned[key]
            if representation is None:
                matches='definition_ref'not in selected and selected.get('definition')==definition
            else:
                reference={'kind':'mutmut-control-spans-v1','module':mapped,'location':definition['location'],'generation_repairs':definition['generation_repairs']}
                if 'operator_repair'in definition:reference['operator_repair']=definition['operator_repair']
                matches=set(selected)=={'id','file','source_sha256','definition_sha256','definition_ref'}and selected['definition_ref']==reference
            if selected['file']!=file or selected['source_sha256']!=hashes[file]or selected['definition_sha256']!=digest or not matches:
                raise ValueError('provided schedule differs from independently reconstructed generated program: '+key)
            identity=(file,digest)
            if identity in definitions:raise ValueError('actual generation repeats an applicable definition')
            definitions.add(identity);inventory.append({'id':key,'file':file,'source_sha256':hashes[file],'definition_sha256':digest})
        materializations.append({'source':file,'source_sha256':hashes[file],'mutant_ids':sorted(ids,key=lambda value:value.encode('utf-16-be',errors='surrogatepass')),'artifacts':[_ARTIFACTS[name]for name in file_artifacts]})
    if seen!=set(discovered):raise ValueError('actual full per-source generation inventory is incomplete')
    typed.complete(seen)
    inventory.sort(key=lambda item:item['id'].encode('utf-16-be',errors='surrogatepass'))
    return{'schema_version':1,'qualification':'reconstructed-actual-generated-definitions-no-outcomes','source_tree_sha256':receipt['sha256'],'inventory':inventory,
           'inventory_sha256':hashlib.sha256(canonical(inventory).encode()).hexdigest(),'source_materializations':materializations,'raw_artifacts':[_ARTIFACTS[name]for name in sorted(set(artifacts)|set(_ARTIFACTS))]}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--source-root',type=Path,required=True);parser.add_argument('--state',type=Path,required=True);parser.add_argument('--source-receipt',type=Path,required=True);parser.add_argument('--output',type=Path,required=True);args=parser.parse_args()
    result=prove(args.source_root.resolve(strict=True),args.state.resolve(strict=True),args.source_receipt.resolve(strict=True))
    with args.output.open('x')as target:json.dump(result,target,ensure_ascii=False,separators=(',',':'));target.write('\n')
    print(json.dumps({'mutants':len(result['inventory']),'sources':len(result['source_materializations'])}))
