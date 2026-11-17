#!/usr/bin/env python3
"""Verify the developer-signed kernel source, Kata build sources and actual config."""
import argparse
import gzip
import hashlib
import importlib.util
import json
import lzma
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
from urllib.request import urlopen

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('ud_source_acquisition',Path(__file__).with_name('collect-debian-sources.py'));acquisition=importlib.util.module_from_spec(spec);spec.loader.exec_module(acquisition)
MAINTAINERS=['647F28654894E3BD457199BE38DBBDC86092693E','E27E5D8A3403A2EF66873BBCDEA66FF797772CDC']


def payload(url,target,maximum):
    acquisition.acquire(url,target,maximum=maximum);return target.read_bytes()


def collect(assets,output):
    output.mkdir(parents=True,exist_ok=True);lock=json.loads((ROOT/'runtime/provider-assets.lock.json').read_bytes());definition=lock['apple_container']['kernel'];match=re.fullmatch(r'opt/kata/share/kata-containers/vmlinux-(\d+\.\d+\.\d+)-[0-9]+-debug',definition['member'])
    if match is None:raise ValueError('kernel source release is not explicit in its asset contract')
    version=match[1];provider=json.loads((assets/'provider-receipts.json').read_bytes())['provider_receipts']['apple-container/darwin/arm64'];kernel=assets/provider['kernel']['path']
    if 'sha256:'+acquisition.digest(kernel)!=provider['kernel']['sha256']:raise ValueError('kernel bytes differ from the verified provider receipt')
    blob=kernel.read_bytes();positions=[item.start()for item in re.finditer(b'IKCFG_ST',blob)if blob[item.end():item.end()+3]==b'\x1f\x8b\x08']
    if len(positions)!=1:raise ValueError('kernel has no unique embedded build configuration')
    start=positions[0];end=blob.index(b'IKCFG_ED',start+8);config=gzip.decompress(blob[start+8:end])
    if not config or len(config)>16*1024**2:raise ValueError('kernel configuration exceeds its bound')
    (output/'kernel.config').write_bytes(config)
    banners=[item[0].decode('utf-8')for item in re.finditer(rb'Linux version '+re.escape(version.encode())+rb' [^\0\n]{1,1024}',blob)]
    if not banners:raise ValueError('kernel version banner disagrees with its source release')
    base='https://cdn.kernel.org/pub/linux/kernel/v'+version.split('.')[0]+'.x/';name='linux-'+version+'.tar.xz'
    sums=payload(base+'sha256sums.asc',output/'kernel-sha256sums.asc',2*1024**2);first=sums.index(b'\n\n')+2;last=sums.index(b'\n-----BEGIN PGP SIGNATURE-----');rows=[line.split()for line in sums[first:last].decode().splitlines()if line.split()[-1:]==[name]]
    if len(rows)!=1 or not re.fullmatch('[0-9a-f]{64}',rows[0][0]):raise ValueError('official mirror checksum listing lacks the kernel source')
    archive=output/name;acquisition.acquire(base+name,archive,sha256=rows[0][0],maximum=512*1024**2)
    signature=output/('linux-'+version+'.tar.sign');payload(base+signature.name,signature,1024*1024)
    home=output/'gpg';home.mkdir(mode=0o700,exist_ok=True);rings=[];key_receipts=[]
    for fingerprint in MAINTAINERS:
        # keys.openpgp.org may deliberately omit unverified user IDs. GnuPG
        # refuses to use that incomplete certificate even when its fingerprint
        # is correct. The keyserver is only a source of bytes: the exact primary
        # fingerprint independently pinned from kernel.org remains the authority.
        key=output/(fingerprint+'.full.asc');key_url='https://keyserver.ubuntu.com/pks/lookup?op=get&search=0x'+fingerprint
        payload(key_url,key,2*1024**2);ring=output/(fingerprint+'.full.gpg')
        subprocess.run(['gpg','--homedir',str(home),'--batch','--yes','--dearmor','--output',str(ring),str(key)],capture_output=True,check=True,timeout=30);rings.append(ring)
        shown=subprocess.run(['gpg','--homedir',str(home),'--batch','--with-colons','--show-keys',str(ring)],capture_output=True,check=True,timeout=30).stdout.decode()
        primary=re.findall(r'^pub:[^\n]*\nfpr:[^\n]*:([A-F0-9]{40}):$',shown,re.MULTILINE)
        if primary!=[fingerprint]:raise ValueError('kernel key certificate differs from the exact trusted primary fingerprint')
        key_receipts.append({'path':key.name,'url':key_url,'sha256':acquisition.digest(key),'size_bytes':key.stat().st_size,'primary_fingerprint':fingerprint})
    keyring=output/'kernel-keyring.gpg';keyring.write_bytes(b''.join(file.read_bytes()for file in rings))
    plain=output/'kernel-source.tar';count=0
    try:
        with lzma.open(archive,'rb')as source,plain.open('wb')as target:
            while chunk:=source.read(1024**2):
                count+=len(chunk)
                if count>4*1024**3:raise ValueError('kernel source expansion exceeds bound')
                target.write(chunk)
        result=subprocess.run(['gpgv','--status-fd','1','--keyring',str(keyring.resolve()),str(signature.resolve()),str(plain.resolve())],capture_output=True,timeout=180)
        valid=[line.split()for line in result.stdout.decode().splitlines()if line.startswith('[GNUPG:] VALIDSIG ')]
        if result.returncode or len(valid)!=1 or not any(fingerprint in valid[0]for fingerprint in MAINTAINERS):raise ValueError('kernel developer signature verification failed: '+result.stderr.decode(errors='replace')[:4096])
        plain_sha=acquisition.digest(plain)
    finally:plain.unlink(missing_ok=True)
    tag_url='https://api.github.com/repos/kata-containers/kata-containers/git/ref/tags/4.3.1';tag=json.loads(payload(tag_url,output/'kata-tag.json',2*1024**2))['object']
    for _ in range(4):
        if tag['type']=='commit':break
        if tag['type']!='tag'or not re.fullmatch('[0-9a-f]{40}',tag['sha'])or not tag['url'].startswith('https://api.github.com/repos/kata-containers/kata-containers/git/tags/'):raise ValueError('Kata release tag escapes its source repository')
        tag=json.loads(payload(tag['url'],output/(tag['sha']+'.json'),2*1024**2))['object']
    if tag['type']!='commit'or not re.fullmatch('[0-9a-f]{40}',tag['sha']):raise ValueError('Kata source tag did not resolve to an exact commit')
    kata=output/'kata-source.tar.gz';url='https://codeload.github.com/kata-containers/kata-containers/tar.gz/'+tag['sha'];acquisition.acquire(url,kata,maximum=128*1024**2)
    with tarfile.open(kata,'r:gz')as source:
        versions=[item for item in source if item.name.endswith('/versions.yaml')and item.isfile()and item.size<=1024*1024]
        if len(versions)!=1:raise ValueError('Kata source has no unique dependency version contract')
        source_versions=source.extractfile(versions[0]).read()
    if version.encode()not in source_versions:raise ValueError('Kata release source does not declare the selected kernel version')
    report={'schema_version':1,'qualification':'pinned-apple-kernel-corresponding-source-inputs','status':'passed','target_execution':False,'kernel_sha256':provider['kernel']['sha256'],'kernel_version':max(banners,key=len),'kernel_banners':banners,'kernel_source':{'path':name,'url':base+name,'sha256':acquisition.digest(archive),'size_bytes':archive.stat().st_size,'uncompressed_tar_sha256':plain_sha,'developer_signature':{'path':signature.name,'sha256':acquisition.digest(signature),'status':result.stdout.decode()},'trusted_maintainer_fingerprints':MAINTAINERS,'key_certificates':key_receipts,'fingerprint_source':'https://www.kernel.org/signature.html'},'kernel_config':{'path':'kernel.config','sha256':hashlib.sha256(config).hexdigest(),'size_bytes':len(config)},'kata_source':{'repository':'kata-containers/kata-containers','version':'4.3.1','commit':tag['sha'],'path':kata.name,'url':url,'sha256':acquisition.digest(kata),'size_bytes':kata.stat().st_size},'collector_sha256':acquisition.digest(Path(__file__))}
    (output/'receipt.json').write_text(json.dumps(report,indent=2)+'\n');return report


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--assets',type=Path,required=True);parser.add_argument('--output',type=Path,required=True);args=parser.parse_args();report=collect(args.assets.resolve(),args.output.resolve());print(json.dumps({'status':report['status'],'kernel_source_bytes':report['kernel_source']['size_bytes'],'kata_commit':report['kata_source']['commit']}))
