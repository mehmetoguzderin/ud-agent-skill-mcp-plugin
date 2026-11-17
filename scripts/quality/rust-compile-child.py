#!/opt/mutation/python/bin/python3
"""Fixed Cargo compilation inside a fresh UID; export only closed native ELFs."""
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tarfile

TARGET = 'aarch64-unknown-linux-gnu'
MAX_BUNDLE = 32 * 1024**2
spec = importlib.util.spec_from_file_location('ud_compile_workspace_contract', Path(__file__).with_name('rust-test-runtime.py'))
contract = importlib.util.module_from_spec(spec);spec.loader.exec_module(contract)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def confined():
    if sys.platform != 'linux' or os.geteuid() < 100001:
        raise ValueError('Rust compilation requires a fresh protected UID')
    fields = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
    if fields['NoNewPrivs'].strip() != '1' or any(fields[name].strip() != '0000000000000000' for name in ('CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb')):
        raise ValueError('Rust compiler retained privilege acquisition or capabilities')


def artifacts(log, root, target, manifest='Cargo.toml'):
    selected=contract.workspace(manifest)
    values = [];seen = set()
    for line in log.splitlines():
        try: row = json.loads(line)
        except ValueError: continue
        if row.get('reason') != 'compiler-artifact' or not row.get('executable'):continue
        if row['target']['kind'] == ['custom-build']:continue
        executable = Path(row['executable']);source = Path(row['target']['src_path'])
        if not executable.is_relative_to(target / TARGET / 'debug') or not source.is_relative_to(root / selected['cwd']):
            raise ValueError('Rust compiler emitted an executable outside its declared package')
        name = executable.relative_to(target).as_posix();identity = source.relative_to(root).as_posix()
        if name in seen: raise ValueError('Rust compiler emitted duplicate executable records')
        seen.add(name);info = executable.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022 or info.st_size > MAX_BUNDLE:
            raise ValueError('Rust compiled ELF is not an ordinary owned bounded file')
        data = executable.read_bytes()
        if data[:6] != b'\x7fELF\x02\x01' or int.from_bytes(data[18:20], 'little') != 183:
            raise ValueError('Rust compiler emitted a foreign native architecture')
        kind = 'test' if row['profile']['test'] else 'product'
        if kind == 'product' and row['target']['name'] not in selected['products']:
            raise ValueError('Rust compiler emitted an undeclared product')
        values.append(({'path': 'target/' + name, 'id': identity, 'kind': kind, 'sha256': hashlib.sha256(data).hexdigest(), 'size': len(data)}, data))
    if {row['id'] for row, _ in values if row['kind'] == 'product'} != {selected['cwd']+'/'+name for name in selected['products'].values()} or not any(row['kind'] == 'test' for row, _ in values):
        raise ValueError('Rust compiler omitted required products or tests')
    return values


def main():
    confined()
    if len(sys.argv) != 4:raise ValueError('Rust compiler needs one immutable request, result, and source root')
    request_file,result,root = map(Path,sys.argv[1:]);info=request_file.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o222 or info.st_size > 4096:raise ValueError('Rust compile request is not immutable coordinator data')
    request=json.loads(request_file.read_bytes())
    if not isinstance(request,dict)or set(request)!={'schema_version','target','workspace_manifest'}or request['schema_version']!=1 or request['target']!=TARGET:raise ValueError('Rust compiler received an undeclared command')
    manifest=request['workspace_manifest'];selected=contract.workspace(manifest)
    if root != Path.cwd() or root.name != 'tree' or not root.is_relative_to('/tmp/ud-mutation-jobs') or root.stat().st_uid != 0 or root.stat().st_mode & 0o222:raise ValueError('Rust compilation source is not an immutable job tree')
    cache=Path(os.environ['TMPDIR']);target=cache/'cargo-target';home=cache/'cargo-home';home.mkdir()
    environment={'PATH':'/opt/mutation/rust/bin:/opt/mutation/python/bin:/usr/bin:/bin','LANG':'C.UTF-8','HOME':str(cache),'TMPDIR':str(cache),'CARGO_HOME':str(home),'CARGO_TARGET_DIR':str(target),'CARGO_NET_OFFLINE':'true','CARGO_BUILD_JOBS':'2','CARGO_INCREMENTAL':'0','CARGO_PROFILE_DEV_DEBUG':'0','CARGO_PROFILE_TEST_DEBUG':'0','SOURCE_DATE_EPOCH':'315532800','RUSTC':'/opt/mutation/rust/bin/rustc','RUSTC_WRAPPER':'/opt/mutation/harness/rust-test-runtime.py','UD_MUTATION_RUST_SOURCE_ROOT':str(root),'UD_MUTATION_RUST_WORKSPACE':manifest}
    command=['/opt/mutation/rust/bin/cargo','test','--workspace','--manifest-path',str(root/manifest),'--locked','--offline','--target',TARGET,'--no-run','--message-format=json','--config','source.crates-io.replace-with="verified-vendor"','--config','source.verified-vendor.directory="/opt/mutation/rust/vendor"']
    completed=subprocess.run(command,cwd=root,env=environment,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
    log=completed.stdout
    if len(log)>16*1024**2:raise ValueError('Rust compiler log exceeded its bound')
    sys.stdout.buffer.write(log);sys.stdout.flush()
    compiled=artifacts(log,root,target,manifest) if completed.returncode==0 else []
    control={'schema_version':1,'status':completed.returncode,'argv':command,'source_root':str(root),'artifacts':[row for row,_ in compiled],'workspace_manifest':manifest}
    total=sum(len(data)for _,data in compiled)
    if total>MAX_BUNDLE-2*1024**2:raise ValueError('Rust compiled closure exceeds the bounded export contract')
    with tarfile.open(result,'w',format=tarfile.USTAR_FORMAT)as archive:
        for name,data in [('build.json',canonical(control)),*[(f'binaries/{index}',data)for index,(_,data)in enumerate(compiled)]]:
            member=tarfile.TarInfo(name);member.size=len(data);member.mode=0o444;member.mtime=315532800;archive.addfile(member,io.BytesIO(data))
    return 0


if __name__=='__main__':
    try:raise SystemExit(main())
    except Exception as error:
        sys.stderr.write('RUST_COMPILE_BOUNDARY_ERROR: '+str(error)+'\n');raise SystemExit(125)
