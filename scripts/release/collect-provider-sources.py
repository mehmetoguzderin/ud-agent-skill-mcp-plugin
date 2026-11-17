#!/usr/bin/env python3
"""Collect pinned provider/bootstrap repositories and resolved Swift dependencies."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import tarfile

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('ud_acquire',Path(__file__).with_name('collect-debian-sources.py'));acquisition=importlib.util.module_from_spec(spec);spec.loader.exec_module(acquisition)
spec=importlib.util.spec_from_file_location('ud_package_sources',Path(__file__).with_name('collect-package-sources.py'));packages=importlib.util.module_from_spec(spec);spec.loader.exec_module(packages)


def collect(root,output):
    output.mkdir(parents=True,exist_ok=True);bindings={};metadata=[];sources={};queue=[];frozen={}
    mapping=root/'runtime/materials/provider-source-mappings.lock.json'
    if mapping.exists():
        if mapping.is_symlink():raise ValueError('provider source mapping is linked')
        document=json.loads(mapping.read_bytes())
        if document.get('schema_version')!=1 or document.get('qualification')!='frozen-provider-bootstrap-source-commits':raise ValueError('provider source mapping has an invalid authority format')
        for row in document['sources']:
            identity=row['name']+'@'+row['version']
            if identity in frozen:raise ValueError('provider source mapping has duplicate identities')
            frozen[identity]=row
        bindings['runtime/materials/provider-source-mappings.lock.json']=acquisition.digest(mapping)
        for row in document['release_metadata']:
            url=row['url'];expected='metadata/'+hashlib.sha256(url.encode()).hexdigest()
            if row['path']!=expected or not re.fullmatch(r'https://api\.github\.com/repos/(?:apple/containerization|astral-sh/uv)/git/(?:ref/tags/[A-Za-z0-9._-]+|tags/[a-f0-9]{40})',url):raise ValueError('frozen provider release metadata has an unsafe authority')
            acquisition.acquire(url,output/expected,row['size_bytes'],row['sha256'],maximum=2*1024**2);metadata.append(row)
    def read(name):
        file=root/name;bindings[name]=acquisition.digest(file);return json.loads(file.read_bytes())
    def source(repository,commit,origin):
        if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+',repository)or not re.fullmatch('[0-9a-f]{40}',commit):raise ValueError('provider source lacks a confined immutable Git identity')
        identity=repository+'@'+commit
        if identity not in sources:sources[identity]={'family':'provider-source','name':repository,'version':commit,'origins':[origin]};queue.append((repository,commit))
        elif origin not in sources[identity]['origins']:sources[identity]['origins'].append(origin)
    def tag(repository,version):
        if frozen:
            candidates=[row for row in frozen.values()if row['name']==repository and any(origin.endswith(version)for origin in row['origins'])]
            if len(candidates)!=1:raise ValueError('provider release has no unique frozen source commit')
            return candidates[0]['version']
        url='https://api.github.com/repos/'+repository+'/git/ref/tags/'+version;file=output/'metadata'/hashlib.sha256(url.encode()).hexdigest();acquisition.acquire(url,file,maximum=2*1024**2);metadata.append({'path':file.relative_to(output).as_posix(),'url':url,'sha256':acquisition.digest(file),'size_bytes':file.stat().st_size});value=json.loads(file.read_bytes())['object']
        for _ in range(4):
            if value.get('type')=='commit':return value['sha']
            if value.get('type')!='tag'or not re.fullmatch('[0-9a-f]{40}',value.get('sha','')):raise ValueError('provider tag has an invalid immutable object')
            url='https://api.github.com/repos/'+repository+'/git/tags/'+value['sha'];file=output/'metadata'/hashlib.sha256(url.encode()).hexdigest();acquisition.acquire(url,file,maximum=2*1024**2);metadata.append({'path':file.relative_to(output).as_posix(),'url':url,'sha256':acquisition.digest(file),'size_bytes':file.stat().st_size});value=json.loads(file.read_bytes())['object']
        raise ValueError('provider tag resolution exceeds its bound')
    providers = read('runtime/provider-assets.lock.json')
    source('apple/container', providers['apple_container']['source_commit'], 'Apple Container' + providers['apple_container']['version'])
    wsl = providers['wslc']
    source('microsoft/WSL', wsl['source_commit'], 'WSL' + wsl['version'])
    if wsl.get('maintained_source_commit'):
        source('microsoft/WSL', wsl['maintained_source_commit'], 'WSL' + wsl['version'])
    version=providers['apple_container']['init_image']['version'];source('apple/containerization',tag('apple/containerization',version),'pinned offline init image'+version)
    lima=read('runtime/lima-inputs.lock.json');source('lima-vm/lima',lima['sources']['lima']['commit'],'Lima2.3.0')
    binary_sources=root/'runtime/materials/provider-binary-sources.lock.json'
    if binary_sources.exists():
        selected=read('runtime/materials/provider-binary-sources.lock.json')
        if selected.get('schema_version')!=1 or selected.get('qualification')!='exact-upstream-binary-release-source-identities':raise ValueError('provider binary source lock is malformed')
        for row in selected['sources']:
            identity=row['repository']+'@'+row['commit'];expected=frozen.get(identity)
            if frozen and(expected is None or expected['sha256']!=row['archive_sha256']or expected['size_bytes']!=row['archive_size_bytes']or expected['url']!=row['url']):raise ValueError('provider binary source differs from frozen source archive identity')
            source(row['repository'],row['commit'],row['provider']+' '+row['role'])
    inputs=read('runtime/userspace-inputs.lock.json');versions={re.search(r'/releases/download/([^/]+)/',row['uv_archive']['url'])[1]for row in inputs['platforms'].values()}
    if len(versions)!=1:raise ValueError('platform uv bootstrap releases disagree')
    version=next(iter(versions));source('astral-sh/uv',tag('astral-sh/uv',version),'uv bootstrap'+version)
    index=0;locks=[]
    while index<len(queue):
        if len(queue)>256:raise ValueError('resolved provider source closure exceeds bound')
        repository,commit=queue[index];index+=1;identity=repository+'@'+commit;target=output/'sources'/hashlib.sha256(identity.encode()).hexdigest();url='https://codeload.github.com/'+repository+'/tar.gz/'+commit;expected=frozen.get(identity)
        if frozen and expected is None:raise ValueError('provider dependency is absent from the frozen source closure')
        if expected is not None and expected['url']!=url:raise ValueError('provider source URL differs from its frozen mapping')
        acquisition.acquire(url,target,expected.get('size_bytes')if expected else None,expected.get('sha256')if expected else None,maximum=512*1024**2)
        record=sources[identity];record.update(url=url,path=target.relative_to(output).as_posix(),sha256=acquisition.digest(target),size_bytes=target.stat().st_size,acquired=True,notices=packages.inspect_archive(target,output));resolved=[]
        with tarfile.open(target,'r:gz')as archive:
            for member in archive:
                if not member.isfile()or member.name.rsplit('/',1)[-1]not in('Package.resolved','Cargo.lock'):continue
                if not 0<member.size<=8*1024**2:raise ValueError('provider dependency lock exceeds bound')
                body=archive.extractfile(member).read(member.size+1)
                if len(body)!=member.size:raise ValueError('provider dependency lock is truncated')
                if repository=='astral-sh/uv'and member.name.count('/')==1 and member.name.endswith('/Cargo.lock'):
                    file=output/'locks/uv.Cargo.lock';file.parent.mkdir(exist_ok=True);file.write_bytes(body);locks.append({'path':file.relative_to(output).as_posix(),'sha256':hashlib.sha256(body).hexdigest(),'size_bytes':len(body)});continue
                if not member.name.endswith('/Package.resolved'):continue
                data=json.loads(body);pins=data.get('pins',data.get('object',{}).get('pins'))
                if not isinstance(pins,list):raise ValueError('Swift resolved dependency list is malformed')
                for pin in pins:
                    location=pin.get('location',pin.get('repositoryURL',''));match=re.fullmatch(r'https://github.com/([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+?)(?:\.git)?',location);revision=pin.get('state',{}).get('revision')
                    if not match or not isinstance(revision,str)or not re.fullmatch('[0-9a-f]{40}',revision):raise ValueError('Swift dependency is not pinned to an exact supported Git commit')
                    source(match[1],revision,identity+':'+member.name);resolved.append({'repository':match[1],'commit':revision,'lock_path':member.name,'lock_sha256':hashlib.sha256(body).hexdigest()})
        record['resolved_swift_sources']=resolved
    if any(acquisition.digest(root/name)!=expected for name,expected in bindings.items()):raise ValueError('provider source input locks changed')
    if frozen and set(sources)!=set(frozen):raise ValueError('provider source closure omits a frozen resolved dependency')
    records=[sources[key]for key in sorted(sources)];report={'schema_version':1,'qualification':'pinned-source-and-notices','status':'passed','target_execution':False,'scope':'Exact provider/uv main repositories and all recursive Swift Package.resolved commits; compiler/system libraries and other lock ecosystems require separate closure receipts.','locks':bindings,'files':records,'notices':metadata+locks}
    (output/'receipt.json').write_text(json.dumps(report,indent=2)+'\n');return report


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--root',type=Path,default=ROOT);parser.add_argument('--output',type=Path,required=True);args=parser.parse_args();report=collect(args.root,args.output);print(json.dumps({'status':report['status'],'source_repositories':len(report['files'])}))
