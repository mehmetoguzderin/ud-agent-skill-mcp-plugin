#!/usr/bin/env python3
"""Collect exact OS source/notice identities from a verified, unexecuted OCI graph."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import tempfile

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('ud_opaque_oci',ROOT/'scripts/runtime/oci_filesystem.py');oci=importlib.util.module_from_spec(spec);spec.loader.exec_module(oci)
spec=importlib.util.spec_from_file_location('ud_sources',Path(__file__).with_name('source_materials.py'));materials=importlib.util.module_from_spec(spec);spec.loader.exec_module(materials)


def collect(root,pack,platform,output,single=False):
    inputs=[Path(__file__),ROOT/'scripts/runtime/oci_filesystem.py',Path(__file__).with_name('source_materials.py')];fingerprints={str(file):hashlib.sha256(file.read_bytes()).hexdigest()for file in inputs}
    if output.exists():raise ValueError('new OCI source metadata output required')
    if platform not in('linux/arm64','linux/amd64'):raise ValueError('unsupported OCI source architecture')
    output.mkdir(parents=True);(output/'INCOMPLETE').write_text('No complete OCI source metadata receipt.\n')
    packages={};common={};snapshots={}
    def inspect_layer(filesystem,layer,index):
        try:status=filesystem.resolve('var/lib/dpkg/status')[1].read_bytes()
        except ValueError:return
        fingerprint=materials.sha(status)
        records=[row for row in materials.control_records(status)if row.get('Status')=='install ok installed']
        manifest=''.join(row['Package']+'\t'+row['Version']+'\n'for row in records).encode();architecture=platform.split('/')[1]
        target=output/'status'/fingerprint;target.parent.mkdir(exist_ok=True)
        if not target.exists():target.write_bytes(status);target.chmod(0o444)
        snapshots.setdefault(fingerprint,{'path':target.relative_to(output).as_posix(),'sha256':fingerprint,'size_bytes':len(status),'layer_digest':layer['digest'],'layer_index':index})
        for package in materials.installed_packages(status,manifest,architecture):
            identity=package['name']+'@'+package['version']+':'+package['architecture'];name,file=filesystem.resolve(package['notice_guest_path']);body=file.read_bytes()
            if not body or len(body)>8*1024**2:raise ValueError('OCI OS notice is empty or oversized')
            digest=materials.sha(body);target=output/'copyright'/digest;target.parent.mkdir(exist_ok=True)
            if not target.exists():target.write_bytes(body);target.chmod(0o444)
            notice={'path':target.relative_to(output).as_posix(),'sha256':digest,'size_bytes':len(body),'resolved_image_path':name,'layer_digest':layer['digest'],'layer_index':index}
            if identity not in packages:packages[identity]={**package,'notice':notice,'notices':[notice]}
            elif all(row['sha256']!=digest for row in packages[identity]['notices']):packages[identity]['notices'].append(notice)
        for logical,(kind,file)in sorted(filesystem.inventory.items()):
            if not logical.startswith('usr/share/common-licenses/')or'/'in logical.removeprefix('usr/share/common-licenses/')or kind=='dir':continue
            name,data=filesystem.resolve(logical);body=data.read_bytes()
            if not body or len(body)>8*1024**2:raise ValueError('OCI common license is empty or oversized')
            digest=materials.sha(body);target=output/'common-licenses'/digest;target.parent.mkdir(exist_ok=True)
            if not target.exists():target.write_bytes(body);target.chmod(0o444)
            common[logical+'@'+digest]={'logical_path':logical,'path':target.relative_to(output).as_posix(),'sha256':digest,'size_bytes':len(body),'resolved_image_path':name,'layer_digest':layer['digest'],'layer_index':index}
    with tempfile.TemporaryDirectory(prefix='ud-oci-source-',dir=output)as temporary:
        filesystem=oci.verified_filesystem(root,pack,platform,Path(temporary)/'opaque',single,inspect_layer)
        keyring=filesystem.resolve('usr/share/keyrings/debian-archive-keyring.gpg')[1].read_bytes();(output/'archive-keyring.gpg').write_bytes(keyring)
    if not packages or not snapshots:raise ValueError('OCI graph has no installed package source metadata')
    if any(hashlib.sha256(Path(name).read_bytes()).hexdigest()!=value for name,value in fingerprints.items()):raise ValueError('source metadata collector changed during inspection')
    report={'schema_version':1,'qualification':'oci-bound-publisher-package-and-notice-inventory','status':'passed','target_execution':False,'emulation':False,'platform':platform,'oci_index_digest':pack['index_digest'],'oci_image_digest':pack['platforms'][platform],'image_transport':pack['index_transport'],'package_scope':'every distinct installed dpkg status in every redistributed OCI layer','packages':list(packages.values()),'common_licenses':list(common.values()),'archive_keyring':{'path':'archive-keyring.gpg','sha256':materials.sha(keyring),'size_bytes':len(keyring)},'status_files':list(snapshots.values()),'collector_sha256':fingerprints[str(Path(__file__))],'helper_sha256':{str(Path(name).relative_to(ROOT)):value for name,value in fingerprints.items()if Path(name)!=Path(__file__)}}
    (output/'receipt.json').write_text(json.dumps(report,indent=2)+'\n');(output/'INCOMPLETE').unlink();return report


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--root',type=Path,required=True);parser.add_argument('--lock',type=Path,required=True);parser.add_argument('--pack',choices=['core','render'],required=True);parser.add_argument('--platform',choices=['linux/arm64','linux/amd64'],required=True);parser.add_argument('--output',type=Path,required=True);parser.add_argument('--diagnostic-single-platform',action='store_true');args=parser.parse_args();pack=json.loads(args.lock.read_bytes())['packs'][args.pack];report=collect(args.root.resolve(),pack,args.platform,args.output.resolve(),args.diagnostic_single_platform);print(json.dumps({'status':report['status'],'packages':len(report['packages']),'common_licenses':len(report['common_licenses']),'target_execution':False}))
