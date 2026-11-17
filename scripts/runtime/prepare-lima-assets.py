#!/usr/bin/env python3
"""Build receipt-bound, offline Lima profiles without executing guest binaries.

The cloud image, package indexes and archives must already be in the input
cache. This builder never downloads, installs host software, or starts a VM.
"""
from __future__ import annotations
import argparse
import base64
import gzip
import hashlib
import io
import json
import lzma
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tarfile

ROOT = Path(__file__).resolve().parents[2]
GUEST_FILES = ('bin/nerdctl', 'bin/containerd', 'bin/containerd-shim-runc-v2',
               'bin/runc', 'bin/rootlesskit', 'bin/rootlessctl', 'bin/ctr',
               'bin/containerd-rootless.sh', 'bin/containerd-rootless-setuptool.sh',
               'share/doc/nerdctl-full/README.md', 'share/doc/nerdctl-full/SHA256SUMS')


def sha(data):
    return 'sha256:' + hashlib.sha256(data).hexdigest()


def verified(file, expected, size=None):
    if file.is_symlink() or not file.is_file() or size is not None and file.stat().st_size != size:
        raise ValueError('Lima input file identity or size differs: ' + file.name)
    with file.open('rb') as source:
        if 'sha256:' + hashlib.file_digest(source, 'sha256').hexdigest() != expected:
            raise ValueError('Lima input digest differs: ' + file.name)
    return file


def safe_name(name):
    name = name.removeprefix('./')
    parts = PurePosixPath(name).parts
    if not name or name.startswith('/') or '\\' in name or ':' in name or any(p in ('', '.', '..') for p in parts) or len(name.encode()) > 240:
        raise ValueError('unsafe Lima archive path')
    return name


def read_members(archive, selected=None):
    found = {}
    seen = set()
    total = 0
    with tarfile.open(archive, 'r:gz') as bundle:
        for index, item in enumerate(bundle):
            if index > 10000:
                raise ValueError('Lima archive entry bound exceeded')
            name = safe_name(item.name)
            if name in seen:
                raise ValueError('duplicate Lima archive member')
            seen.add(name)
            if item.isdir():
                continue
            # This documentation-only upstream link is omitted. Runtime and
            # source inventories contain ordinary files, never link entries.
            if name == 'share/doc/lima/templates' and item.issym() and item.linkname == '../../lima/templates':
                continue
            if selected is not None and name not in selected:
                continue
            if not item.isfile() or not 0 <= item.size <= 256 * 1024**2:
                raise ValueError('linked, duplicate or oversized Lima archive member')
            total += item.size
            if total > 2 * 1024**3:
                raise ValueError('Lima archive expansion exceeds bound')
            body = bundle.extractfile(item).read(item.size + 1)
            if len(body) != item.size:
                raise ValueError('truncated Lima archive member')
            found[name] = (body, 0o555 if item.mode & 0o111 else 0o444)
    if selected is not None and set(found) != set(selected):
        raise ValueError('Lima archive lacks required guest files')
    return found


def derived_members(root, architecture):
    root=Path(root)
    if root.is_symlink()or not root.is_dir():raise ValueError('derived runtime export must be an ordinary directory')
    manifest_file=root/'derived-runtimes.json'
    if manifest_file.is_symlink()or not manifest_file.is_file()or not 0<manifest_file.stat().st_size<=8*1024**2:raise ValueError('derived runtime manifest is not bounded ordinary data')
    manifest=json.loads(manifest_file.read_bytes())
    if manifest.get('schema_version')!=1 or manifest.get('qualification')!='source-closed-local-provider-binary-derivation-not-upstream-signature'or manifest.get('versions')!={'runc':'1.5.2','containerd':'2.4.2'}or manifest.get('containerd_derivation',{}).get('cgo')is not False:
        raise ValueError('derived runtime export has no complete supported source contract')
    expected={'bin/runc','bin/containerd','bin/containerd-shim-runc-v2','bin/ctr'}
    records=manifest.get('binaries',{}).get(architecture)
    if not isinstance(records,dict)or set(records)!=expected:raise ValueError('derived runtime binary inventory is incomplete')
    runc=manifest.get('runc_derivation',{});containerd=manifest.get('containerd_derivation',{})
    if runc.get('commit')!='29dd3dc2b13b4123162e5fe132504bb4b15569f1'or runc.get('version')!='1.5.2'or runc.get('status')!='cross-built'or containerd.get('commit')!='b7a25261e029d68978bbf290df0a62fc819b3c51'or containerd.get('status')!='cross-built':raise ValueError('derived runtime source versions are unbound')
    result={}
    for name,item in records.items():
        built=runc.get('binaries',{}).get(architecture,{})if name=='bin/runc'else containerd.get('binaries',{}).get(architecture,{}).get(name[4:],{})
        if any(item.get(field)!=built.get(field)for field in('sha256','size_bytes')):raise ValueError('derived runtime differs from its source-bound build receipt')
        if item.get('path')!=architecture+'/'+name[4:] or not re.fullmatch('[0-9a-f]{64}',item.get('sha256',''))or type(item.get('size_bytes'))is not int or not 0<item['size_bytes']<=128*1024**2:
            raise ValueError('derived runtime identity or path is unsafe')
        file=root/item['path']
        if file.parent.is_symlink()or not file.parent.is_dir():raise ValueError('derived runtime directory is not ordinary')
        body=verified(file,'sha256:'+item['sha256'],item['size_bytes']).read_bytes()
        if body[:6]!=b'\x7fELF\x02\x01'or int.from_bytes(body[18:20],'little')!=({'arm64':183,'amd64':62}[architecture]):raise ValueError('derived runtime ELF architecture differs')
        result[name]=(body,0o555)
    return result,manifest


def guest_archive(source, target, architecture, derived=None):
    members = read_members(source, GUEST_FILES)
    if derived is not None:
        replacements,_=derived if isinstance(derived,tuple)else derived_members(derived,architecture);members.update(replacements)
    expected = 183 if architecture == 'arm64' else 62
    for name in ('bin/nerdctl', 'bin/containerd', 'bin/containerd-shim-runc-v2', 'bin/runc', 'bin/rootlesskit', 'bin/rootlessctl', 'bin/ctr'):
        body = members[name][0]
        if body[:6] != b'\x7fELF\x02\x01' or int.from_bytes(body[18:20], 'little') != expected:
            raise ValueError('Lima guest ELF architecture differs')
    with target.open('xb') as raw, gzip.GzipFile(filename='', fileobj=raw, mode='wb', mtime=0) as compressed, tarfile.open(fileobj=compressed, mode='w|', format=tarfile.USTAR_FORMAT) as bundle:
        for name, (body, mode) in sorted(members.items()):
            header = tarfile.TarInfo(name)
            header.mode, header.size = mode, len(body)
            bundle.addfile(header, io.BytesIO(body))
    return members


def guest_namespace_helper(lock, architecture):
    image = lock['images'][architecture]
    helper = image.get('executables', {}).get('nsenter', {})
    if helper.get('path') != '/usr/bin/nsenter' or not re.fullmatch(r'sha256:[a-f0-9]{64}', helper.get('sha256', '')) or helper.get('image_sha256') != image['sha256'] or type(helper.get('size_bytes')) is not int or not 1 <= helper['size_bytes'] <= 1024 * 1024:
        raise ValueError('Lima namespace helper must be bound to the exact frozen guest image')
    return helper


def package_records(body):
    records = {}
    for paragraph in body.decode('utf8').split('\n\n'):
        fields = {}
        key = None
        for line in paragraph.splitlines():
            if line.startswith(' ') and key:
                fields[key] += '\n' + line
            elif ': ' in line:
                key, value = line.split(': ', 1)
                fields[key] = value
        if fields.get('Package') in ('libsubid5', 'uidmap'):
            if fields['Package'] in records:
                raise ValueError('duplicate selected Ubuntu package')
            records[fields['Package']] = fields
    return records


def authenticated_packages(cache, lock, architecture, gpgv):
    auth = lock['package_authentication']
    release = verified(cache / 'InRelease', auth['release_sha256'])
    keyring = verified(cache / 'ubuntu-archive-keyring.gpg', auth['keyring_sha256'])
    status = subprocess.run([str(gpgv), '--status-fd', '1', '--keyring', str(keyring.resolve()), str(release.resolve())], capture_output=True, timeout=30, check=True)
    if ('[GNUPG:] VALIDSIG ' + auth['signer_fingerprint'] + ' ').encode() not in status.stdout:
        raise ValueError('Ubuntu package metadata signer differs')
    record = auth['indexes'][architecture]
    index = verified(cache / f'Packages-{architecture}.xz', record['sha256'], record['size_bytes'])
    expected = re.escape(record['sha256'][7:]) + r' +' + str(record['size_bytes']) + r' main/binary-' + architecture + r'/Packages.xz'
    if not re.search(r'^ ' + expected + r'$', release.read_text(), re.M):
        raise ValueError('Ubuntu package index is not bound to the signed release')
    decoded = lzma.decompress(index.read_bytes(), memlimit=128 * 1024**2)
    if len(decoded) > 32 * 1024**2:
        raise ValueError('Ubuntu package index expansion exceeds bound')
    packages = package_records(decoded)
    selected = []
    for item in lock['packages'][architecture]:
        metadata = packages.get(item['name'], {})
        if any(metadata.get(key) != value for key, value in {'Version': item['version'], 'Architecture': architecture, 'SHA256': item['sha256'][7:], 'Size': str(item['size_bytes']), 'Filename': 'pool/main/s/shadow/' + item['filename'], 'Depends': item['depends']}.items()):
            raise ValueError('Ubuntu dependency differs from signed package metadata')
        selected.append((item, verified(cache / item['filename'], item['sha256'], item['size_bytes']).read_bytes()))
    if {item['name'] for item, _ in selected} != {'libsubid5', 'uidmap'}:
        raise ValueError('incomplete Ubuntu uidmap dependency closure')
    return selected


def dependency_script(lock, architecture, packages):
    guest = lock['guest']
    if guest != {'user': 'udagent', 'uid': 1001, 'home': '/home/udagent', 'network': 'none', 'services': ['containerd.service']}:
        raise ValueError('Lima guest policy differs')
    lines = ['#!/bin/bash', 'set -euo pipefail', 'umask 077', 'test "$(id -u)" = 0', f'test "$(dpkg --print-architecture)" = {architecture}', 'test "$(id -u udagent)" = 1001']
    for name, version in sorted(lock['images'][architecture]['installed_dependencies'].items()):
        if not re.fullmatch('[a-z0-9+-]+', name) or not re.fullmatch('[0-9A-Za-z:~.+-]+', version):
            raise ValueError('invalid pinned Ubuntu dependency')
        lines.append(f'test "$(dpkg-query -W -f=\'${{Version}}\' {name})" = \'{version}\'')
    lines += ['work=$(mktemp -d /var/tmp/ud-agent-offline.XXXXXX)', 'trap \'rm -rf -- "$work"\' EXIT']
    for item, body in packages:
        name = item['filename']
        if not re.fullmatch('[a-z0-9_.+-]+', name):
            raise ValueError('invalid Ubuntu dependency filename')
        lines += [f'base64 -d >"$work/{name}" <<\'UD_AGENT_PACKAGE\'', base64.b64encode(body).decode(), 'UD_AGENT_PACKAGE', f'printf \'%s  %s\\n\' \'{item["sha256"][7:]}\' "$work/{name}" | sha256sum -c -']
    lines += ['DEBIAN_FRONTEND=noninteractive dpkg --install "$work/"*.deb', 'command -v newuidmap', 'command -v newgidmap', 'test -u /usr/bin/newuidmap', 'test -u /usr/bin/newgidmap', 'grep -Eq "^udagent:[0-9]+:([6-9][0-9]{4}|[1-9][0-9]{5,})$" /etc/subuid', 'grep -Eq "^udagent:[0-9]+:([6-9][0-9]{4}|[1-9][0-9]{5,})$" /etc/subgid', 'install -d -m 0700 -o 1001 -g "$(id -g udagent)" /home/udagent/.config /home/udagent/.config/systemd /home/udagent/.config/systemd/user', "cat >/home/udagent/.config/systemd/user/containerd.service <<'UD_AGENT_UNIT'", '[Unit]', 'Description=UD Agent private rootless containerd', 'Requires=dbus.socket', '[Service]', 'Environment=PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin', 'Environment=CONTAINERD_ROOTLESS_ROOTLESSKIT_NET=none', 'Environment=CONTAINERD_ROOTLESS_ROOTLESSKIT_PORT_DRIVER=none', 'ExecStart=/usr/local/bin/containerd-rootless.sh', 'ExecReload=/bin/kill -s HUP $MAINPID', 'Restart=on-failure', 'RestartSec=2', 'StartLimitBurst=3', 'StartLimitIntervalSec=60', 'Delegate=yes', 'TasksMax=4096', 'LimitNOFILE=1048576', 'KillMode=mixed', '[Install]', 'WantedBy=default.target', 'UD_AGENT_UNIT', 'chown 1001:"$(id -g udagent)" /home/udagent/.config/systemd/user/containerd.service', 'loginctl enable-linger udagent']
    return ('\n'.join(lines) + '\n').encode()


def prepare(inputs, ubuntu, output, architecture, image, gpgv, engine_lock, guest_lock, derived_runtime=None):
    if architecture not in ('arm64', 'amd64') or output.exists() or output.is_relative_to(inputs) or output.is_relative_to(ubuntu):
        raise ValueError('Lima output must be a new directory and an explicit supported architecture')
    if engine_lock.get('schema_version') != 1 or guest_lock.get('schema_version') != 1 or guest_lock.get('state') != 'frozen':
        raise ValueError('Lima input contracts must be frozen')
    platform_arch = 'arm64' if architecture == 'arm64' else 'x64'
    suffix = 'arm64' if architecture == 'arm64' else 'x86_64'
    engine_record = next(x for x in engine_lock['assets'] if x['name'] == f'lima-2.3.0-Darwin-{suffix}.tar.gz')
    nerdctl_record = next(x for x in engine_lock['assets'] if x['name'] == f'nerdctl-full-2.4.2-linux-{architecture}.tar.gz')
    engine = verified(inputs / engine_record['name'], 'sha256:' + engine_record['sha256'], engine_record['size'])
    nerdctl = verified(inputs / nerdctl_record['name'], 'sha256:' + nerdctl_record['sha256'], nerdctl_record['size'])
    image_record = guest_lock['images'][architecture]
    namespace_helper = guest_namespace_helper(guest_lock, architecture)
    verified(image, image_record['sha256'], image_record['size_bytes'])
    verified(ubuntu / f'image-{architecture}.manifest', image_record['manifest']['sha256'], image_record['manifest']['size_bytes'])
    packages = authenticated_packages(ubuntu, guest_lock, architecture, gpgv)
    output.mkdir(parents=True, mode=0o700)
    (output / 'INCOMPLETE').write_text('Lima provider preparation has not completed.\n')
    relative = Path(f'runtime/providers/lima-nerdctl/darwin-{platform_arch}')
    prefix = output / relative
    prefix.mkdir(parents=True)
    engine_members = read_members(engine)
    executable = engine_members.get('bin/limactl', (b'', 0))[0]
    if executable[:4] != b'\xcf\xfa\xed\xfe' or int.from_bytes(executable[4:8], 'little') != (0x0100000c if architecture == 'arm64' else 0x01000007):
        raise ValueError('Lima host Mach-O architecture differs')
    for name, (body, mode) in engine_members.items():
        target = prefix / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(body)
        target.chmod(mode)
    guest_dir = prefix / 'guest'
    guest_dir.mkdir()
    shutil.copyfile(image, guest_dir / 'ubuntu.img')
    derived = guest_dir / 'containerd.tar.gz'
    payload=derived_members(derived_runtime,architecture)if derived_runtime is not None else None
    members = guest_archive(nerdctl, derived, architecture, payload)
    derivation=payload[1]if payload is not None else None
    if derivation is not None:
        (guest_dir/'DERIVED-RUNTIMES.json').write_text(json.dumps(derivation,sort_keys=True,indent=2)+'\n')
    script = dependency_script(guest_lock, architecture, packages)
    (guest_dir / 'dependencies.sh').write_bytes(script)
    assets = [{'key': name, 'path': str(relative / 'guest' / filename), 'sha256': sha((guest_dir / filename).read_bytes()) if name != 'image' else image_record['sha256'], 'size_bytes': (guest_dir / filename).stat().st_size} for name, filename in [('image', 'ubuntu.img'), ('containerd', 'containerd.tar.gz'), ('dependencies', 'dependencies.sh')]]
    asset = {item['key']: item for item in assets}
    template = {'minimumLimaVersion': '2.3.0', 'arch': 'aarch64' if architecture == 'arm64' else 'x86_64', 'vmType': 'vz', 'cpus': 2, 'memory': '4GiB', 'disk': '16GiB', 'video': {'display': 'default'}, 'mounts': [], 'images': [{'location': '{{asset:image}}', 'digest': asset['image']['sha256']}], 'user': {'name': 'udagent', 'uid': 1001, 'home': '/home/udagent', 'shell': '/bin/bash'}, 'containerd': {'user': True, 'system': False, 'archives': [{'location': '{{asset:containerd}}', 'arch': 'aarch64' if architecture == 'arm64' else 'x86_64', 'digest': asset['containerd']['sha256']}]}, 'ssh': {'loadDotSSHPubKeys': False, 'forwardAgent': False}, 'vmOpts': {'vz': {'rosetta': {'enabled': False, 'binfmt': False}}}, 'portForwards': [{'guestIPMustBeZero': False, 'proto': 'any', 'guestPortRange': [1, 65535], 'ignore': True}], 'provision': [{'mode': 'dependency', 'skipDefaultDependencyResolution': True, 'file': {'url': '{{asset:dependencies}}', 'digest': asset['dependencies']['sha256']}}, {'mode': 'user', 'script': 'set -eu\nexport XDG_RUNTIME_DIR=/run/user/1001\nsystemctl --user daemon-reload\nsystemctl --user enable --now dbus.socket containerd.service\n'}]}
    template_file = prefix / 'template.yaml'
    template_file.write_text(json.dumps(template, sort_keys=True, indent=2) + '\n')
    record = {'schema_version': 1, 'executable_sha256': sha((prefix / 'bin/limactl').read_bytes()), 'instance': 'ud-agent', 'nerdctl': '/usr/local/bin/nerdctl', 'nerdctl_sha256': sha(members['bin/nerdctl'][0]), 'containerd': '/usr/local/bin/containerd', 'containerd_sha256': sha(members['bin/containerd'][0]), 'ctr': '/usr/local/bin/ctr', 'ctr_sha256': sha(members['bin/ctr'][0]), 'nsenter': namespace_helper['path'], 'nsenter_sha256': namespace_helper['sha256'], 'address': '/run/user/1001/containerd/containerd.sock', 'guest_uid': 1001, 'guest_home': '/home/udagent', 'architecture': architecture, 'provisioning': {'template_path': str(relative / 'template.yaml'), 'template_sha256': sha(template_file.read_bytes()), 'offline_ready': True, 'assets': assets, 'generated_config': {'networks_sha256': 'sha256:6a81404a3a74190814c937e03610ff8cab1a0063b3bd153b642ee533db2f88ec'}}}
    files = [{'path': str(file.relative_to(output)), 'sha256': verified_hash(file), 'size_bytes': file.stat().st_size} for file in sorted(prefix.rglob('*')) if file.is_file()]
    receipt = {'schema_version': 1, 'provider_receipts': {f'lima-nerdctl/darwin/{platform_arch}': record}, 'files': files, 'provenance': {'inputs': engine_lock, 'guest': guest_lock, 'package_signature_verified': True, 'builder_sha256': verified_hash(Path(__file__)), 'gpgv_sha256': verified_hash(gpgv), 'execution': 'not-executed', 'guest_binaries_executed': False}}
    if derivation is not None:receipt['provenance']['derived_runtimes']={'path':str(relative/'guest/DERIVED-RUNTIMES.json'),'sha256':verified_hash(guest_dir/'DERIVED-RUNTIMES.json'),'qualification':derivation['qualification']}
    (output / 'provider-receipts.json').write_text(json.dumps(receipt, sort_keys=True, indent=2) + '\n')
    (output / 'INCOMPLETE').unlink()
    return receipt


def verified_hash(file):
    with file.open('rb') as source:
        return 'sha256:' + hashlib.file_digest(source, 'sha256').hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inputs', type=Path, required=True)
    parser.add_argument('--ubuntu', type=Path, required=True)
    parser.add_argument('--image', type=Path, required=True)
    parser.add_argument('--architecture', choices=['arm64', 'amd64'], required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--gpgv', type=Path, default=shutil.which('gpgv'))
    parser.add_argument('--derived-runtime',type=Path,help='verified source-closed local runc/containerd export')
    args = parser.parse_args()
    if not args.gpgv or not args.gpgv.is_file():
        parser.error('gpgv is required to verify the pinned Ubuntu metadata signature')
    result = prepare(args.inputs.resolve(), args.ubuntu.resolve(), args.output.resolve(), args.architecture, args.image.resolve(), args.gpgv.resolve(), json.loads((ROOT / 'runtime/lima-inputs.lock.json').read_text()), json.loads((ROOT / 'runtime/lima-guest.lock.json').read_text()),args.derived_runtime.resolve()if args.derived_runtime else None)
    print(json.dumps({'providers': list(result['provider_receipts']), 'files': len(result['files']), 'execution': 'not-executed'}))


if __name__ == '__main__':
    main()
