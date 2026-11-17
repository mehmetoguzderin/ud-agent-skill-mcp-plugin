#!/usr/bin/env python3
"""Join every redistributed OS layer file to exact package/source/notice records.

Reads verified OCI blobs as opaque data, including superseded lower-layer bytes.
Package ownership/version is a publisher metadata relationship, not a claim of a
reproduced upstream build. Missing ownership never becomes a source exception.
"""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
import lzma
from pathlib import Path
import re
import struct
import tempfile
from xml.etree import ElementTree

ROOT = Path(__file__).resolve().parents[2]
def module(name, file):
    spec = importlib.util.spec_from_file_location(name, file); value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value); return value
oci = module('ud_os_filesystem', ROOT / 'scripts/runtime/oci_filesystem.py')
binary = module('ud_os_source_bindings', Path(__file__).with_name('bind-binary-sources.py'))


def sha(file):
    with file.open('rb') as stream: return hashlib.file_digest(stream, 'sha256').hexdigest()


def ownership(filesystem, packages):
    """Independently derive file owners from the actual layer package lists."""
    result = {}
    for package in packages:
        name = package['name']; arch = package['architecture']; found = []
        for filename in (f'var/lib/dpkg/info/{name}:{arch}.list', f'var/lib/dpkg/info/{name}.list'):
            try: _, file = filesystem.resolve(filename)
            except ValueError: continue
            if file.stat().st_size > 16 * 1024 ** 2: raise ValueError('OS package file list exceeds bound')
            found.append((filename, file))
        if len(found) != 1: raise ValueError('actual OS package file ownership list is absent or ambiguous: ' + name)
        filename, file = found[0]; logical = file.read_text(encoding='utf-8').splitlines()
        if len(logical) > 200000 or len(logical) != len(set(logical)): raise ValueError('OS package ownership list is duplicate or oversized')
        for item in logical:
            if item in ('/.', '/'): continue
            if not item.startswith('/'): raise ValueError('OS package ownership path is not root-relative')
            relative = oci.safe_name(item[1:])
            try: resolved, _ = filesystem.resolve(relative)
            except ValueError: continue # Directory, alternative, or removed conffile.
            for key in (relative, resolved): result.setdefault(key, set()).add((package['name'], package['version'], package['architecture']))
        # dpkg-owned control scripts and generated lists are not themselves
        # listed in package data.tar; bind their exact package identity too.
        stem = filename.removesuffix('.list')
        for suffix in ('list', 'md5sums', 'conffiles', 'preinst', 'postinst', 'prerm', 'postrm', 'triggers', 'shlibs', 'symbols', 'config', 'templates'):
            result.setdefault(stem + '.' + suffix, set()).add((package['name'], package['version'], package['architecture']))
    return result


def generated_ownership(filesystem, packages, owners):
    """Finite publisher-generated state recipes, never an unowned-file fallback."""
    installed = {row['name']: (row['name'], row['version'], row['architecture']) for row in packages}; result = {}; mime = False
    if 'shared-mime-info' in installed:
        for path in ('var/lib/dpkg/info/shared-mime-info.postinst', 'var/lib/dpkg/info/shared-mime-info:' + installed['shared-mime-info'][2] + '.postinst'):
            try: _, file = filesystem.resolve(path)
            except ValueError: continue
            body = file.read_bytes()
            if len(body) <= 1024**2 and b'update-mime-database' in body and b'/usr/share/mime' in body: mime = True
    def writer(package, executable):
        return package in installed and any(path.endswith('/' + executable) and any(row[0] == package for row in values) for path, values in owners.items())
    categories = {'application','audio','chemical','font','image','inode','message','model','multipart','text','video','x-content','x-epoc'}
    mime_files = {'aliases','subclasses','magic','mime.cache','types','treemagic','generic-icons','icons','version','XMLnamespaces','globs','globs2'}
    for name, (kind, file) in filesystem.inventory.items():
        if kind != 'file' or name in owners: continue
        package = None; recipe = None; magic = None
        relative = name.removeprefix('usr/share/mime/'); parts = relative.split('/')
        if mime and name.startswith('usr/share/mime/') and (relative in mime_files or len(parts) == 2 and parts[0] in categories and parts[1].endswith('.xml')):
            package = 'shared-mime-info'; recipe = 'actual-installed-shared-mime-info-postinst-update-mime-database'
        elif name == 'etc/ld.so.cache' and 'libc-bin' in installed and any('libc-bin' in {row[0] for row in owners.get(path, ())} for path in ('usr/sbin/ldconfig','sbin/ldconfig')):
            package = 'libc-bin'; recipe = 'actual-installed-libc-bin-ldconfig-generated-cache'
        elif name == 'var/cache/ldconfig/aux-cache' and writer('libc-bin', 'ldconfig'):
            package = 'libc-bin'; recipe = 'actual-installed-libc-bin-ldconfig-aux-cache'; magic = b'glibc-ld.so.auxcache-2.0'
        elif re.fullmatch(r'var/cache/fontconfig/[a-f0-9]{32}-le64\.cache-9', name) and writer('fontconfig', 'fc-cache'):
            package = 'fontconfig'; recipe = 'actual-installed-fontconfig-fc-cache'; magic = b'\x04\xfc\x02\xfc\x09\0\0\0'
        elif name == 'var/cache/fontconfig/CACHEDIR.TAG' and writer('fontconfig', 'fc-cache'):
            package = 'fontconfig'; recipe = 'fontconfig-cache-directory-tag-text-state'
        elif name == 'var/log/fontconfig.log' and writer('fontconfig', 'fc-cache'):
            package = 'fontconfig'; recipe = 'fontconfig-generated-text-state'
        elif name == 'var/lib/systemd/catalog/database' and writer('systemd', 'journalctl'):
            package = 'systemd'; recipe = 'actual-installed-systemd-journal-catalog'; magic = b'RHHHKSLP'
        elif name == 'usr/share/glib-2.0/schemas/gschemas.compiled' and writer('libglib2.0-0t64', 'glib-compile-schemas'):
            package = 'libglib2.0-0t64'; recipe = 'actual-installed-glib-compiled-schemas'; magic = b'GVariant'
        elif re.fullmatch(r'usr/share/icons/(?:Adwaita|hicolor)/icon-theme.cache', name) and writer('gtk-update-icon-cache', 'gtk-update-icon-cache'):
            package = 'gtk-update-icon-cache'; recipe = 'actual-installed-gtk-icon-cache'; magic = b'\0\x01\0\0'
        elif re.fullmatch(r'usr/lib/(?:aarch64|x86_64)-linux-gnu/gdk-pixbuf-2.0/2.10.0/loaders.cache', name) and writer('libgdk-pixbuf-2.0-0', 'gdk-pixbuf-query-loaders'):
            package = 'libgdk-pixbuf-2.0-0'; recipe = 'gdk-pixbuf-generated-loaders-text-state'
        elif re.fullmatch(r'usr/lib/(?:aarch64|x86_64)-linux-gnu/gtk-3.0/3.0.0/immodules.cache', name) and writer('libgtk-3-0t64', 'gtk-query-immodules-3.0'):
            package = 'libgtk-3-0t64'; recipe = 'gtk-generated-input-modules-text-state'
        elif re.fullmatch(r'usr/lib/(?:aarch64|x86_64)-linux-gnu/gio/modules/giomodule.cache', name) and writer('libglib2.0-0t64', 'gio-querymodules'):
            package = 'libglib2.0-0t64'; recipe = 'glib-generated-module-text-state'
        elif name in ('etc/passwd','etc/passwd-','etc/group','etc/group-') and writer('base-passwd', 'update-passwd'):
            package = 'base-passwd'; recipe = 'base-passwd-generated-account-text-state'
        elif name in ('etc/shadow','etc/shadow-','etc/gshadow','etc/gshadow-') and writer('passwd', 'pwconv'):
            package = 'passwd'; recipe = 'shadow-generated-account-text-state'
        elif name in ('etc/shells','var/lib/shells.state') and writer('debianutils', 'update-shells'):
            package = 'debianutils'; recipe = 'debianutils-generated-shells-text-state'
        elif name in ('etc/pam.d/common-account','etc/pam.d/common-auth','etc/pam.d/common-password','etc/pam.d/common-session','etc/pam.d/common-session-noninteractive','var/lib/pam/account','var/lib/pam/auth','var/lib/pam/password','var/lib/pam/seen','var/lib/pam/session','var/lib/pam/session-noninteractive') and writer('libpam-runtime', 'pam-auth-update'):
            package = 'libpam-runtime'; recipe = 'pam-auth-update-generated-text-state'
        elif name in ('etc/machine-id','var/lib/dbus/machine-id') and writer('dbus-bin', 'dbus-uuidgen'):
            package = 'dbus-bin'; recipe = 'dbus-generated-machine-identity-text-state'
        elif name == 'etc/ca-certificates.conf' and writer('ca-certificates', 'update-ca-certificates'):
            package = 'ca-certificates'; recipe = 'ca-certificates-generated-selection-text-state'
        elif re.fullmatch(r'var/lib/systemd/deb-systemd-helper-enabled/(?:apt-daily-upgrade|apt-daily|dpkg-db-backup|fstrim)\.timer\.dsh-also', name) and writer('init-system-helpers', 'deb-systemd-helper'):
            package = 'init-system-helpers'; recipe = 'deb-systemd-helper-generated-timer-text-state'
        elif name == 'var/log/apt/eipp.log.xz' and writer('apt', 'apt-get'):
            package = 'apt'; recipe = 'apt-generated-compressed-eipp-text-state'
        elif re.fullmatch(r'var/lib/apt/lists/deb\.debian\.org_(?:debian-security_dists_trixie-security|debian_dists_trixie(?:-updates)?)_InRelease', name) and writer('apt', 'apt-get'):
            package = 'apt'; recipe = 'apt-retained-publisher-release-text-state'
        elif name in ('var/lib/dpkg/status','var/lib/dpkg/status-old','var/lib/dpkg/available','var/lib/dpkg/arch','var/lib/dpkg/arch-native','var/lib/dpkg/cmethopt','var/lib/dpkg/diversions','var/lib/dpkg/diversions-old','var/lib/dpkg/statoverride','var/lib/dpkg/statoverride-old','var/lib/dpkg/triggers/File','var/lib/dpkg/triggers/ldconfig','var/lib/dpkg/triggers/libc-upgrade','var/lib/dpkg/triggers/update-ca-certificates','var/lib/dpkg/triggers/update-ca-certificates-fresh','var/log/dpkg.log','var/log/alternatives.log') or name.startswith('var/lib/dpkg/alternatives/'):
            package = 'dpkg'; recipe = 'dpkg-package-database-or-alternatives-text-state'
        elif name in ('var/log/apt/history.log','var/log/apt/term.log','var/lib/apt/extended_states'):
            package = 'apt'; recipe = 'apt-generated-text-state'
        elif name in ('var/cache/debconf/config.dat','var/cache/debconf/config.dat-old','var/cache/debconf/templates.dat','var/cache/debconf/templates.dat-old','var/cache/debconf/passwords.dat'):
            package = 'debconf'; recipe = 'debconf-generated-text-state'
        elif name in ('var/lib/dpkg/lock','var/lib/dpkg/lock-frontend','var/lib/apt/lists/lock','var/cache/apt/archives/lock') and file.stat().st_size == 0:
            package = 'dpkg' if name.startswith('var/lib/dpkg/') else 'apt'; recipe = 'empty-package-manager-lock-state'
        if package not in installed: continue
        if recipe == 'actual-installed-shared-mime-info-postinst-update-mime-database':
            if file.stat().st_size > 16 * 1024**2: raise ValueError('generated MIME state exceeds bound')
            body = file.read_bytes()
            signatures = {'magic': b'MIME-Magic\0\n', 'treemagic': b'MIME-TreeMagic\0\n', 'mime.cache': b'\0\x01\0\x02'}
            if relative in signatures:
                if not body.startswith(signatures[relative]): continue
            else:
                if b'\0' in body or body.startswith((b'\x7fELF', b'MZ')): continue
                try: body.decode('utf-8')
                except UnicodeDecodeError: continue
                if relative.endswith('.xml'):
                    if b'<!DOCTYPE' in body.upper(): continue
                    try: xml = ElementTree.fromstring(body)
                    except ElementTree.ParseError: continue
                    if xml.tag not in ('mime-type', '{http://www.freedesktop.org/standards/shared-mime-info}mime-type'): continue
        if recipe == 'actual-installed-libc-bin-ldconfig-generated-cache':
            with file.open('rb') as stream: magic = stream.read(32)
            if not magic.startswith((b'glibc-ld.so.cache', b'ld.so-1.7.0')): continue
        elif magic is not None:
            with file.open('rb') as stream: prefix = stream.read(len(magic))
            if prefix != magic: continue
            if recipe == 'actual-installed-fontconfig-fc-cache':
                with file.open('rb') as stream: header = stream.read(16)
                if len(header) != 16 or struct.unpack_from('<Q', header, 8)[0] != file.stat().st_size: continue
        if recipe.endswith('text-state'):
            if file.stat().st_size > 16 * 1024**2: raise ValueError('generated package-manager text state exceeds bound')
            body = file.read_bytes()
            if recipe == 'apt-generated-compressed-eipp-text-state':
                try:
                    decompressor = lzma.LZMADecompressor(); body = decompressor.decompress(body, max_length=16 * 1024**2 + 1)
                except lzma.LZMAError: continue
                if len(body) > 16 * 1024**2 or not decompressor.eof or decompressor.unused_data: continue
            if b'\0' in body or body.startswith((b'\x7fELF', b'MZ')): continue
            try: body.decode('utf-8')
            except UnicodeDecodeError: continue
            if name.startswith('var/lib/dpkg/alternatives/') and body.splitlines()[:1] not in ([b'auto'], [b'manual']): continue
            if recipe == 'dbus-generated-machine-identity-text-state' and not re.fullmatch(rb'[a-f0-9]{32}\n', body): continue
            if recipe == 'apt-retained-publisher-release-text-state' and not (body.startswith(b'-----BEGIN PGP SIGNED MESSAGE-----\n') and b'\nOrigin: Debian\n' in body and b'\n-----BEGIN PGP SIGNATURE-----\n' in body): continue
            if recipe == 'fontconfig-cache-directory-tag-text-state' and not body.startswith(b'Signature: 8a477f597d28d172789f06886806bc55\n'): continue
        result[name] = {'component': installed[package], 'recipe': recipe}
    return result


def derive(runtime_root, pack, platform, inventory_file, sources_file, *, keyring, gpgv, single=False, source_parts=None, recorder=None):
    proof = binary.derive(inventory_file, sources_file, keyring=keyring, gpgv=gpgv, source_parts=source_parts, recorder=recorder)
    inventory = json.loads(inventory_file.read_bytes()); components = {}
    for row in proof['bindings']:
        identity = tuple(row['binary_component'][key] for key in ('name', 'version', 'architecture')); components[identity] = row
    status_hashes = {row['sha256'] for row in inventory['status_files']}; file_rows = []; unresolved = []; pending = []
    def observe(name, file, serial, layer, index): pending.append((name, file, serial, layer, index))
    def layer_done(filesystem, layer, index):
        try: _, status = filesystem.resolve('var/lib/dpkg/status')
        except ValueError:
            if pending: raise ValueError('redistributed OS layer files have no actual package database')
            return
        if sha(status) not in status_hashes: raise ValueError('actual current OS package database differs from the source-bound publisher inventory')
        if inventory.get('archive_keyring'):
            _, actual_keyring = filesystem.resolve('usr/share/keyrings/debian-archive-keyring.gpg')
            if sha(actual_keyring) != inventory['archive_keyring']['sha256'] or sha(keyring) != inventory['archive_keyring']['sha256']: raise ValueError('source publisher keyring differs from the actual pinned OCI image')
        raw = status.read_bytes(); records = [row for row in binary.materials.control_records(raw) if row.get('Status') == 'install ok installed']
        manifest = ''.join(row['Package'] + '\t' + row['Version'] + '\n' for row in records).encode(); packages = binary.materials.installed_packages(raw, manifest, platform.split('/')[1]); owners = ownership(filesystem, packages); generated = generated_ownership(filesystem, packages, owners)
        for package in packages:
            identity = tuple(package[key] for key in ('name', 'version', 'architecture'))
            if identity not in components: raise ValueError('actual OS package has no authenticated source/notice component')
            _, notice = filesystem.resolve(package['notice_guest_path']); originals = next(row for row in inventory['packages'] if all(row[key] == package[key] for key in ('name', 'version', 'architecture')))
            if sha(notice) not in {row['sha256'] for row in originals.get('notices', [originals['notice']])}: raise ValueError('actual OS notice differs from the source-bound original')
        for name, file, serial, origin, origin_index in pending:
            content = {'image_path': name, 'path': 'layers/' + origin['digest'][7:] + '/' + str(serial) + '/' + name, 'sha256': sha(file), 'size_bytes': file.stat().st_size, 'platform': platform, 'layer_digest': origin['digest'], 'layer_index': origin_index}
            identities = sorted(owners.get(name, ()))
            recipe = None
            if not identities and name in generated: identities = [generated[name]['component']]; recipe = generated[name]['recipe']
            if identities: file_rows.append({'content': content, 'components': [dict(zip(('name', 'version', 'architecture'), identity)) for identity in identities], **({'generated_state_recipe': recipe} if recipe else {})})
            else: unresolved.append(content)
        pending.clear()
    with tempfile.TemporaryDirectory(prefix='ud-os-source-layer-') as temporary:
        oci.verified_filesystem(runtime_root, pack, platform, Path(temporary) / 'opaque', single, layer_done, observe)
    return {'schema_version': 1, 'qualification': 'actual-oci-layer-package-file-source-license-bindings', 'status': 'passed', 'target_execution': False, 'emulation': False, 'image_digest': pack['images'][platform]['digest'], 'platform': platform, 'bindings': file_rows, 'components': list(components.values()), 'package_source_binding': proof, 'unowned_layer_files': unresolved, 'source_binding_sha256': hashlib.sha256(json.dumps(proof, sort_keys=True, separators=(',', ':')).encode()).hexdigest(), 'generator_sha256': sha(Path(__file__)), 'generator_inputs': [{'path': str(file.relative_to(ROOT)), 'sha256': sha(file)} for file in (Path(__file__), Path(binary.__file__), ROOT / 'scripts/runtime/oci_filesystem.py', Path(binary.materials.__file__))], 'relationship': 'Exact OCI bytes plus actual publisher dpkg ownership/source/version and original notice; not a reproduced binary build.'}


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__); p.add_argument('--runtime-root', type=Path, required=True); p.add_argument('--lock', type=Path, required=True); p.add_argument('--pack', choices=['core', 'render'], required=True); p.add_argument('--platform', choices=['linux/arm64', 'linux/amd64'], required=True); p.add_argument('--inventory', type=Path, required=True); p.add_argument('--sources', type=Path, required=True); p.add_argument('--keyring', type=Path, required=True); p.add_argument('--gpgv', type=Path, required=True); p.add_argument('--diagnostic-single-platform', action='store_true'); p.add_argument('--output', type=Path, required=True); a = p.parse_args()
    if a.output.exists(): raise ValueError('new OS source binding output required')
    result = derive(a.runtime_root.resolve(), json.loads(a.lock.read_bytes())['packs'][a.pack], a.platform, a.inventory, a.sources, keyring=a.keyring.resolve(), gpgv=a.gpgv.resolve(), single=a.diagnostic_single_platform)
    a.output.write_text(json.dumps(result, indent=2) + '\n'); print(json.dumps({'bound_files': len(result['bindings']), 'unowned_files': len(result['unowned_layer_files']), 'target_execution': False}))
