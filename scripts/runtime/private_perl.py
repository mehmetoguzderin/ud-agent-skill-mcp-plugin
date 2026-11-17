"""Stage the same source/module Perl contract into both OCI architectures."""
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('ud_private_perl_paths',ROOT/'workers/ud/src/ud_agent/unicode_paths.py');paths=importlib.util.module_from_spec(spec);spec.loader.exec_module(paths)


def canonical_hash(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()


def stage(root:Path,destination:Path,platforms=None):
    if destination.exists():raise ValueError('private Perl staging must be new')
    source=json.loads((root/'runtime/native-perl-source.lock.json').read_text())
    modules=json.loads((root/'runtime/native-perl-modules.lock.json').read_text())
    interset=json.loads((root/'runtime/perl-deps.lock.json').read_text())['interset']
    result={'source_sha256':canonical_hash(source),'modules_sha256':canonical_hash(modules),'interset_commit':interset['commit'],'platforms':{}}
    selected=platforms or ['linux/arm64','linux/amd64']
    if not selected or len(set(selected))!=len(selected)or any(value not in ['linux/arm64','linux/amd64']for value in selected):raise ValueError('private Perl platform selection is invalid')
    for architecture,slug in [('arm64','arm64'),('amd64','x64')]:
        if 'linux/'+architecture not in selected:continue
        base=root/'.artifacts/native-perl'/('linux-'+slug+'-source')
        receipt=json.loads(base.with_name(base.name+'-receipt.json').read_text())
        if any(receipt.get(name)!=result[name]for name in ['source_sha256','modules_sha256','interset_commit'])or receipt.get('probe',{}).get('status')!='passed'or receipt['probe'].get('ambient_modules')is not False or receipt['probe'].get('ambient_elf')is not False or receipt['probe'].get('version')!='v5.44.0' or not receipt.get('loader'):
            raise ValueError('private OCI Perl does not satisfy the shared source/module/ELF contract')
        target=destination/architecture;seen=set();keys=set();directories=set()
        for item in receipt['files']:
            name=item['path']
            paths.validate_path(name);key=paths.path_key(name)
            if key in keys:
                raise ValueError('private OCI Perl inventory has an unsafe or duplicate path')
            keys.add(key);seen.add(name);file=base/name
            if file.is_symlink()or base.is_symlink()or base.resolve()not in file.resolve(strict=True).parents or not file.is_file()or file.stat().st_size!=item['size']or'sha256:'+hashlib.sha256(file.read_bytes()).hexdigest()!=item['sha256']:
                raise ValueError('private OCI Perl inventory is damaged')
            output=target/name;output.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(file,output);output.chmod(0o555 if file.stat().st_mode&0o111 else 0o444)
            parent=Path(name).parent
            while parent!=Path('.'):directories.add(parent.as_posix());parent=parent.parent
        executable=receipt['executable'];loader=receipt['loader']
        if executable not in seen or loader.get('executable')not in seen or not receipt['library_dirs']or any(name not in directories for name in[*receipt['library_dirs'],*loader['library_dirs']]):raise ValueError('private OCI Perl closure is incomplete')
        runtime={'schema_version':1,'executable':executable,'library_dirs':receipt['library_dirs'],'loader':loader}
        (target/'runtime.json').write_text(json.dumps(runtime,sort_keys=True,indent=2)+'\n')
        (target/'source-receipt.json').write_text(json.dumps(receipt,sort_keys=True,indent=2)+'\n')
        result['platforms']['linux/'+architecture]={'files':len(seen),'receipt_sha256':canonical_hash(receipt),'runtime':runtime}
    return result
