#!/usr/bin/env python3
"""Close locally derived provider binaries before including them in guest assets."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('ud_runc_builder',Path(__file__).with_name('build-lima-runc.py'));builder=importlib.util.module_from_spec(spec);spec.loader.exec_module(builder)


def prepare(runc,containerd,inputs,output):
    if output.exists():raise ValueError('derived runtime export must be new')
    receipt_runc=json.loads((runc/'receipt.json').read_bytes());receipt_containerd=json.loads((containerd/'receipt.json').read_bytes());source_inputs=json.loads((inputs/'input-receipt.json').read_bytes())
    if receipt_runc.get('qualification')!='locally-derived-same-source-runc-crossbuild-not-upstream-signature'or receipt_runc.get('status')!='cross-built'or receipt_runc.get('commit')!=builder.RUNC_COMMIT or receipt_runc.get('inputs_receipt_sha256')!=builder.digest(inputs/'input-receipt.json')or receipt_runc.get('builder_sha256')!=builder.digest(Path(__file__).with_name('build-lima-runc.py')):raise ValueError('runc derivation is stale or lacks exact source/tool binding')
    if receipt_containerd.get('qualification')!='locally-derived-same-source-containerd-crossbuild-not-upstream-signature'or receipt_containerd.get('status')!='cross-built'or receipt_containerd.get('cgo')is not False or receipt_containerd.get('version')!='2.4.2'or receipt_containerd.get('toolchain_receipt_sha256')!=builder.digest(runc/'receipt.json')or receipt_containerd.get('builder_sha256')!=builder.digest(Path(__file__).with_name('build-lima-containerd.py')):raise ValueError('containerd derivation is stale or lacks exact source/tool binding')
    for item in source_inputs['files']:
        if builder.digest(inputs/item['path'])!=item['sha256']:raise ValueError('derived runtime source/tool artifact has changed')
    output.mkdir(parents=True);binaries={}
    for architecture in('arm64','amd64'):
        records={};items=[('runc',runc,receipt_runc['binaries'][architecture])]+[(name,containerd,receipt_containerd['binaries'][architecture][name])for name in('containerd','containerd-shim-runc-v2','ctr')]
        for name,source,item in items:
            file=source/item['path']
            if file.is_symlink()or not file.is_file()or file.stat().st_size!=item['size_bytes']or builder.digest(file)!=item['sha256']:raise ValueError('derived runtime bytes differ from their exact build receipt')
            builder.elf(file.read_bytes(),architecture);target=output/architecture/name;target.parent.mkdir(exist_ok=True);shutil.copyfile(file,target);target.chmod(0o555)
            records['bin/'+name]={'path':target.relative_to(output).as_posix(),'sha256':item['sha256'],'size_bytes':item['size_bytes']}
        binaries[architecture]=records
    receipt={'schema_version':1,'qualification':'source-closed-local-provider-binary-derivation-not-upstream-signature','versions':{'runc':'1.5.2','containerd':'2.4.2'},'binaries':binaries,'source_inputs':source_inputs,'runc_derivation':receipt_runc,'containerd_derivation':receipt_containerd,'runtime_capability_acceptance':'pending-fresh-actual-arm64-provider; amd64-user-deferred','exporter_sha256':builder.digest(Path(__file__))}
    (output/'derived-runtimes.json').write_text(json.dumps(receipt,sort_keys=True,indent=2)+'\n');return receipt


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--runc',type=Path,required=True);parser.add_argument('--containerd',type=Path,required=True);parser.add_argument('--inputs',type=Path,required=True);parser.add_argument('--output',type=Path,required=True);args=parser.parse_args();print(json.dumps({'platforms':list(prepare(args.runc.resolve(),args.containerd.resolve(),args.inputs.resolve(),args.output.resolve())['binaries'])}))
