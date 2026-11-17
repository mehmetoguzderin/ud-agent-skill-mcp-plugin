"""Materialize fixed replay input references into a new private ordinary tree.

Consumes authenticated catalog data, verified source parts and actual candidate
archives. No network, installers, archive extraction paths or private SDK copies.
"""
from __future__ import annotations
import argparse
import base64
import bisect
import errno
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from contextlib import contextmanager
from contextvars import ContextVar

ROOT = Path(__file__).resolve().parents[2]
def module(name, file):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).parent / file); value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value); return value
inputs = module('ud_materialize_inputs', 'replay-inspection-inputs.py')
materials = module('ud_materialize_sources', 'source-bundle.py')
inspector = module('ud_materialize_paths', 'inspect-package.py')
shipped = module('ud_materialize_shipped', 'collect-shipped-components.py')
MAX_MEMBER_FILE = 512 * 1024 ** 2
MAX_MEMBER_TOTAL = 8 * 1024 ** 3
MAX_REPLAY_BYTES = 4_000_000_000
MAX_OWNED_BYTES = 40_000_000_000
FREE_RESERVE_BYTES = 10_000_000_000
STORAGE = ContextVar('replay_storage', default=None)


def remove_private_tree(root):
    """Remove only a caller-created disposable tree, including sealed files."""
    root = Path(root)
    def readonly(function, name, error):
        file = Path(name)
        if os.name != 'nt' or function is not os.unlink or not isinstance(error, PermissionError): raise error
        file.relative_to(root)
        current = file
        while current != root.parent:
            info = current.lstat()
            if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400: raise error
            current = current.parent
        info = file.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_mode & 0o222: raise error
        authority = module('ud_replay_windows_cleanup', '../quality/windows-storage-acl.py').WindowsStorage()
        authority.unlink_readonly(str(file), (info.st_dev, info.st_ino))
    shutil.rmtree(root, onexc=readonly)


def storage_owner(root):
    owner = root.resolve()
    for current in [owner, *owner.parents]:
        if current.name == '.artifacts': owner = current.parent
    return owner


def existing_parent(file):
    while not file.exists():
        if file == file.parent: raise ValueError('inspection storage has no existing parent')
        file = file.parent
    return file


def check_free_space(root, destination, additional):
    if type(additional) is not int or additional < 0: raise ValueError('inspection storage has no finite byte plan')
    if min(shutil.disk_usage(existing_parent(root)).free, shutil.disk_usage(existing_parent(destination)).free) - additional < FREE_RESERVE_BYTES:
        raise ValueError('inspection storage would consume the 10 GiB free reserve')


def streamed_os_source_paths(root, subjects, catalog):
    """Find OS-family originals that their binder reads from source parts."""
    recipe_file = root / 'runtime/materials/component-source-replay.json'
    if not recipe_file.is_file(): return set()
    recipe = json.loads(recipe_file.read_bytes()); families = recipe.get('families', [])
    if recipe.get('schema_version') != 1 or not isinstance(families, list): raise ValueError('inspection source family recipe is invalid')
    identifiers = {row['id'] for row in subjects}; rows = catalog['inputs']; by_path = {row['path']: row for row in rows}
    selected = set()
    for item in families:
        if item.get('kind') != 'oci-os-packages' or item.get('pack') + '-oci-index' not in identifiers: continue
        name = inputs.safe(item['sources']); shared = [family for family in families if family.get('sources') == name]
        if any(family.get('kind') != 'oci-os-packages' or family.get('pack') + '-oci-index' not in identifiers for family in shared): continue
        receipt = by_path.get(name)
        if not receipt or receipt.get('retention', {}).get('kind') != 'retained-json-metadata': continue
        body = base64.b64decode(receipt['retention']['base64'], validate=True)
        if len(body) > 8 * 1024 ** 2 or len(body) != receipt['size_bytes'] or hashlib.sha256(body).hexdigest() != receipt['sha256']: raise ValueError('inspection OS source receipt differs')
        collection = json.loads(body)
        if collection.get('qualification') != 'publisher-authenticated-exact-corresponding-source-closure' or collection.get('status') != 'passed': raise ValueError('inspection OS source collection is incomplete')
        metadata = {inputs.safe(row['path']) for row in collection['metadata']}
        parent = Path(name).parent
        for original in collection['files']:
            relative = inputs.safe(original['path'])
            if relative in metadata: continue # Signature/index tools need real paths.
            path = inputs.safe((parent / relative).as_posix()); row = by_path.get(path)
            if row and row['retention'].get('kind') == 'corresponding-source-blob' and row.get('executable') is False and row['sha256'] == original['sha256'] and row['size_bytes'] == original['size_bytes']:
                selected.add(path)
    return selected


def streamed_provider_source_paths(root, subjects, catalog):
    """Defer only source blobs consumed directly by the provider binder.

    Its signed index metadata and other families' inputs still need ordinary
    files. A matching verified collection row is required for every omission.
    """
    recipe_file = root / 'runtime/materials/component-source-replay.json'
    if not recipe_file.is_file(): return set()
    recipe = json.loads(recipe_file.read_bytes()); families = recipe.get('families', [])
    if recipe.get('schema_version') != 1 or not isinstance(families, list): raise ValueError('inspection source family recipe is invalid')
    if not any(item.get('kind') == 'provider-runtime' for item in families): return set()
    identifiers = {row['id'] for row in subjects}
    if not any(name.startswith('provider-assets-') for name in identifiers): return set()
    by_path = {row['path']: row for row in catalog['inputs']}; selected = set()

    def collection(name, qualification):
        receipt = by_path.get(name)
        if not receipt or receipt.get('retention', {}).get('kind') != 'retained-json-metadata': return None
        body = base64.b64decode(receipt['retention']['base64'], validate=True)
        if len(body) > 8 * 1024 ** 2 or len(body) != receipt['size_bytes'] or hashlib.sha256(body).hexdigest() != receipt['sha256']: raise ValueError('inspection provider source receipt differs')
        value = json.loads(body)
        if value.get('status') != 'passed' or value.get('qualification') != qualification: raise ValueError('inspection provider source collection is incomplete')
        return value

    def select(name, originals):
        parent = Path(name).parent
        for original in originals:
            relative = inputs.safe(original['path']); path = inputs.safe((parent / relative).as_posix()); row = by_path.get(path)
            if row and row.get('retention', {}).get('kind') == 'corresponding-source-blob' and row.get('executable') is False and row['sha256'] == original['sha256'] and row['size_bytes'] == original.get('size_bytes', original.get('size')):
                selected.add(path)

    base = '.artifacts/source-materials-data/'
    name = base + 'provider-sources-binary-v2/receipt.json'
    data = collection(name, 'pinned-source-and-notices')
    if data is not None:
        # The separate Rust family still reads uv's source archive from disk.
        select(name, [row for row in data['files'] if row.get('name') != 'astral-sh/uv'])
    if any(name.startswith('provider-assets-lima-nerdctl-') for name in identifiers):
        name = base + 'ubuntu-sources-historical/receipt.json'
        data = collection(name, 'publisher-authenticated-exact-corresponding-source-closure')
        if data is not None:
            metadata = {inputs.safe(row['path']) for row in data['metadata']}
            select(name, [row for row in data['files'] if inputs.safe(row['path']) not in metadata])
        for folder in ('lima-host-go', 'derived-lima-go'):
            name = base + folder + '/receipt.json'
            data = collection(name, 'binary-bound-go-module-source-inventory')
            if data is not None:
                originals = [*data['main_sources'], *(row['archive'] for row in data['modules']), *data['standard_libraries'], *data.get('derived_runtime_sources', [])]
                select(name, originals)
    return selected


def streamed_node_source_paths(root, subjects, catalog):
    """Defer the fixed Node/Linux producer inputs to its private family stage."""
    recipe_file = root / 'runtime/materials/component-source-replay.json'
    lock_file = root / 'runtime/materials/node-linux-rust.lock.json'
    if not recipe_file.is_file() or not lock_file.is_file(): return set()
    recipe = json.loads(recipe_file.read_bytes()); families = recipe.get('families', [])
    if recipe.get('schema_version') != 1 or not isinstance(families, list): raise ValueError('inspection source family recipe is invalid')
    if not any(row.get('kind') == 'node' for row in families): return set()
    identifiers = {row['id'] for row in subjects}
    if not any(name == 'npm' or re.fullmatch(r'(?:native|mcpb)-linux-(?:arm64|amd64)', name) for name in identifiers): return set()
    lock = json.loads(lock_file.read_bytes())
    if lock.get('schema_version') != 1 or lock.get('qualification') != 'exact-red-hat-node-linux-rust-source-provenance-input-lock': raise ValueError('inspection Node producer source lock differs')
    originals = [lock[key] for key in ('source_rpm', 'redhat_key', 'upstream_signature')]
    originals.extend({'path': '.artifacts/source-materials-data/redhat-rust-1.88-node-linux/extracted/' + row['name'], 'sha256': row['sha256'], 'size_bytes': row['size_bytes']} for row in lock['source_rpm_members'])
    rows = {row['path']: row for row in catalog['inputs']}; selected = set()
    for original in originals:
        name = inputs.safe(original['path']); row = rows.get(name)
        if row and row.get('retention', {}).get('kind') == 'corresponding-source-blob' and row.get('executable') is False and row['sha256'] == original['sha256'] and row['size_bytes'] == original['size_bytes']:
            selected.add(name)
    return selected


def streamed_managed_source_paths(root, subjects, catalog):
    """Select managed-Python originals consumed by the streamed binders."""
    recipe_file = root / 'runtime/materials/component-source-replay.json'
    if not recipe_file.is_file(): return set()
    recipe = json.loads(recipe_file.read_bytes()); families = recipe.get('families', [])
    if recipe.get('schema_version') != 1 or not isinstance(families, list): raise ValueError('inspection source family recipe is invalid')
    identifiers = {row['id'] for row in subjects}; rows = {row['path']: row for row in catalog['inputs']}; selected = set()
    source_names = {item['sources'] for item in families if item.get('kind') in ('runtime-source-members', 'oci-python-provider', 'managed-python') and 'sources' in item}
    for name in source_names:
        name = inputs.safe(name); shared = [item for item in families if item.get('sources') == name]
        if any(item.get('kind') not in ('runtime-source-members', 'oci-python-provider', 'managed-python') for item in shared): continue
        # No binder consumes the collection if its corresponding worker or
        # managed-Python family was not selected by the candidate.
        active = any(item.get('kind') == 'managed-python' or item.get('kind') == 'runtime-source-members' and any(identifier.endswith('-oci-index') or re.match(r'^(?:core|render)-linux-', identifier) for identifier in identifiers) or item.get('kind') == 'oci-python-provider' and item.get('pack', '') + '-oci-index' in identifiers for item in shared)
        if not active: continue
        receipt = rows.get(name)
        if not receipt or receipt.get('retention', {}).get('kind') != 'retained-json-metadata': continue
        body = base64.b64decode(receipt['retention']['base64'], validate=True)
        if len(body) > 8 * 1024 ** 2 or len(body) != receipt['size_bytes'] or hashlib.sha256(body).hexdigest() != receipt['sha256']: raise ValueError('inspection managed source receipt differs')
        data = json.loads(body)
        if data.get('status') != 'passed' or data.get('qualification') != 'frozen-managed-interpreter-runtime-source-subinventory': raise ValueError('inspection managed source collection is incomplete')
        parent = Path(name).parent; keep = set()
        # The separate pip/distlib binder still consumes this wheel by path.
        pip_families = [item for item in families if item.get('kind') == 'pip-runtime' and item.get('wheel_base') == parent.as_posix()]
        if pip_families:
            lock = json.loads((root / 'runtime/materials/pip-distlib-sources.lock.json').read_bytes())
            keep.add(inputs.safe(lock['wheel']['path']))
        for original in [*data['files'], *data.get('notices', [])]:
            relative = inputs.safe(original['path'])
            if relative in keep: continue
            path = inputs.safe((parent / relative).as_posix()); row = rows.get(path)
            sha = original['sha256'].removeprefix('sha256:'); size = original.get('size_bytes', original.get('size'))
            if row and row.get('retention', {}).get('kind') == 'corresponding-source-blob' and row.get('executable') is False and row['sha256'] == sha and row['size_bytes'] == size:
                selected.add(path)
    return selected


def streamed_source_paths(root, subjects, catalog):
    return streamed_os_source_paths(root, subjects, catalog) | streamed_provider_source_paths(root, subjects, catalog) | streamed_node_source_paths(root, subjects, catalog) | streamed_managed_source_paths(root, subjects, catalog)


def deferred_perl_families(root, subjects, catalog):
    """Select recipe-owned Perl packs for one-at-a-time materialization.
    """
    recipe_file = root / 'runtime/materials/component-source-replay.json'
    if not recipe_file.is_file(): return {}
    recipe = json.loads(recipe_file.read_bytes()); families = recipe.get('families', [])
    if recipe.get('schema_version') != 1 or not isinstance(families, list): raise ValueError('inspection source family recipe is invalid')
    identifiers = {row['id'] for row in subjects}; result = {}
    for family in families:
        if family.get('kind') != 'private-perl' or family.get('platform') not in ('darwin/arm64', 'linux/arm64', 'win32/arm64'): continue
        pack = inputs.safe(family['pack']); packs = [pack]
        if 'runtime_only' in family:
            selection = family['runtime_only']
            if not isinstance(selection, dict) or set(selection) != {'input_pack', 'input_receipt'}: raise ValueError('inspection Perl runtime-only recipe is invalid')
            packs.append(inputs.safe(selection['input_pack']))
        if len(set(packs)) != len(packs) or any(left.startswith(right + '/') or right.startswith(left + '/') for left in packs for right in packs if left != right): raise ValueError('inspection Perl family packs overlap')
        if any(other is not family and (other.get('pack') in packs or isinstance(other.get('runtime_only'), dict) and other['runtime_only'].get('input_pack') in packs) for other in families): continue
        rows = [row for row in catalog['inputs'] if any(row['path'].startswith(item + '/') for item in packs)]
        if not rows or any(not any(row['path'].startswith(item + '/') for row in rows) for item in packs): continue
        def supported(row):
            ref = row.get('retention', {}); kind = ref.get('kind')
            return kind in ('corresponding-source-blob', 'corresponding-source-member') or kind == 'released-artifact-member' and ref.get('artifact') in identifiers and not inputs.oci_artifact(ref['artifact'])
        # Never defer a partial directory, because a later binder may inspect
        # its full tree before reading any particular file.
        if not all(supported(row) for row in rows): continue
        if pack in result: raise ValueError('inspection Perl family pack is duplicated')
        result[pack] = rows
    return result


def compact_perl_families(root, subjects, compact, required_materials):
    """Derive one-at-a-time Perl inputs from recipe and retained pack receipts.

    This is an in-memory projection, not a stored per-read catalog. Original
    file identities come from the pack receipts; candidate archive bytes and
    the supplier source archive are checked again while each family runs.
    """
    recipe = json.loads((root / 'runtime/materials/component-source-replay.json').read_bytes())
    if recipe.get('schema_version') != 1 or not isinstance(recipe.get('families'), list): raise ValueError('inspection source family recipe is invalid')
    metadata = {}
    for row in compact.get('metadata', []):
        name = inputs.safe(row['path']); reference = row.get('retention', {})
        if name in metadata or reference.get('kind') != 'retained-json-metadata' or set(reference) != {'kind', 'base64'}: raise ValueError('inspection compact metadata is duplicate or invalid')
        body = base64.b64decode(reference['base64'], validate=True)
        if len(body) > 8 * 1024 ** 2 or len(body) != row.get('size_bytes') or hashlib.sha256(body).hexdigest() != row.get('sha256'): raise ValueError('inspection compact metadata differs')
        metadata[name] = json.loads(body)
    identifiers = {row['id'] for row in subjects}; originals = {row['sha256']: row['size_bytes'] for row in required_materials}; result = {}
    profiles = {'darwin/arm64': ('native-macos-arm64', 'darwin-arm64'), 'linux/arm64': ('native-linux-arm64', 'linux-arm64'), 'win32/arm64': ('native-windows-arm64', 'win32-arm64')}
    for family in recipe['families']:
        if family.get('kind') != 'private-perl' or family.get('platform') not in profiles: continue
        identifier, archive_platform = profiles[family['platform']]
        if identifier not in identifiers: continue
        pack = inputs.safe(family['pack']); name = inputs.safe(family['receipt']); receipt = metadata.get(name)
        if not isinstance(receipt, dict) or not isinstance(receipt.get('files'), list) or not receipt['files']: raise ValueError('inspection compact Perl receipt is missing')
        def indexed(value):
            selected = {}
            for row in value.get('files', []):
                path = inputs.safe(row.get('path')); sha = row.get('sha256', '').removeprefix('sha256:'); size = row.get('size')
                if path in selected or not re.fullmatch('[a-f0-9]{64}', sha) or type(size) is not int or size < 0: raise ValueError('inspection compact Perl receipt has invalid file identities')
                selected[path] = (sha, size)
            return selected
        output = indexed(receipt); rows = []
        def append(directory, path, identity, reference):
            sha, size = identity
            rows.append({'path':directory + '/' + path, 'sha256':sha, 'size_bytes':size, 'executable':None, 'retention':reference})
        def released(path): return {'kind':'released-artifact-member', 'artifact':identifier, 'member':'runtime/pack/native/' + archive_platform + '/perl/' + path}
        for path, identity in output.items(): append(pack, path, identity, released(path))
        if 'runtime_only' in family:
            selection = family['runtime_only']
            if family['platform'] != 'win32/arm64' or not isinstance(selection, dict) or set(selection) != {'input_pack', 'input_receipt'}: raise ValueError('inspection compact Perl runtime-only recipe is invalid')
            input_pack = inputs.safe(selection['input_pack']); original = metadata.get(inputs.safe(selection['input_receipt']))
            if not isinstance(original, dict) or not isinstance(original.get('files'), list) or not original['files']: raise ValueError('inspection compact Perl supplier receipt is missing')
            locked = json.loads((root / 'runtime/windows-perl-distributions.lock.json').read_bytes())['platforms']['arm64']['perl']
            supplier = locked['sha256'].removeprefix('sha256:')
            if originals.get(supplier) != locked['size_bytes']: raise ValueError('inspection compact Perl supplier source is missing')
            for path, identity in indexed(original).items():
                if path in output:
                    if output[path] != identity: raise ValueError('inspection compact Perl filtered input differs')
                    reference = released(path)
                else:
                    if Path(path).suffix.lower() not in ('.pdb', '.lib', '.exp'): raise ValueError('inspection compact Perl filtered input is unexplained')
                    reference = {'kind':'corresponding-source-member', 'blob_sha256':supplier, 'member':'Library/' + path}
                append(input_pack, path, identity, reference)
        if pack in result: raise ValueError('inspection compact Perl family is duplicated')
        result[pack] = rows
    return result


def replay_storage_bytes(source, subjects, report, *, compact=False, streamed_paths=(), family_staging_bytes=0):
    """Exact output union, needed original blobs and one sequential OCI workspace."""
    outputs = {}
    # Compact replay reads the candidate's already verified source and subject
    # archives in place. Only paths actually observed by the closure are new.
    omitted = frozenset(streamed_paths)
    rows = [row for row in report['inspection_inputs']['inputs'] if row['path'] not in omitted] if compact else [*source['files'], *subjects, *report['inspection_inputs']['inputs']]
    for row in rows:
        name = inputs.safe(row['path']); size = row.get('size_bytes', row.get('size'))
        if type(size) is not int or not 0 <= size <= MAX_REPLAY_BYTES: raise ValueError('inspection storage input has no finite byte inventory')
        if name in outputs and outputs[name] != size: raise ValueError('inspection storage output paths have conflicting sizes')
        outputs[name] = size
    sizes = {}; blobs = {}
    for row in report['required_materials']:
        size = row['size_bytes']
        if type(size) is not int or not 0 <= size <= MAX_REPLAY_BYTES or row['sha256'] in sizes: raise ValueError('inspection original byte inventory is duplicate or invalid')
        sizes[row['sha256']] = size
    for row in report['inspection_inputs']['inputs']:
        if compact and row['path'] in omitted: continue
        ref = row['retention']; kind = ref['kind']
        fingerprint = row['sha256'] if kind == 'corresponding-source-blob' else ref.get('blob_sha256') if kind == 'corresponding-source-member' else None
        if fingerprint is not None:
            if fingerprint not in sizes: raise ValueError('inspection original has no finite byte inventory')
            blobs[fingerprint] = sizes[fingerprint]
    oci = []
    inspections = {row['id']: row for row in report.get('subjects', [])}
    for subject in subjects:
        if not inputs.oci_artifact(subject['id']): continue
        row = inspections.get(subject['id'])
        if row is None or not isinstance(row.get('bindings'), list): raise ValueError('inspection OCI workspace has no finite byte inventory')
        sizes = [binding['size_bytes'] for binding in row['bindings']]
        if any(type(size) is not int or size < 0 for size in sizes): raise ValueError('inspection OCI binding size is invalid')
        workspace = sum(sizes)
        if not subject['id'].endswith('-oci-index'):
            size = subject.get('size')
            if type(size) is not int or not 0 <= size <= MAX_REPLAY_BYTES: raise ValueError('inspection OCI transport has no finite byte inventory')
            # transport_members temporarily holds a normalized archive and its
            # extracted blobs in addition to opaque member files. The export
            # reader allows at most 50,000 archive entries; 64 MiB covers their
            # headers/padding and the generated single-image index metadata.
            workspace += 2 * size + 64 * 1024 ** 2
        oci.append(workspace)
    # Compact replay reads the verified source parts in place and never writes
    # an additional whole source blob. Legacy replay still holds all blobs.
    blob_bytes = 0 if compact else sum(blobs.values())
    # Node's signed-source verifier uses a private, temporary family stage for
    # path-based signature tools. It runs after OCI materialization, so budget
    # the larger workspace rather than incorrectly retaining both at once.
    node_inputs = 0
    if compact and any(name.startswith('.artifacts/source-materials-data/redhat-rust-1.88-node-linux/') for name in omitted):
        prefixes = ('.artifacts/node/', '.artifacts/source-materials-data/redhat-rust-1.88-node-linux/', '.artifacts/source-materials-data/rust-runtime-sources-node-v4/')
        node_inputs = sum(row['size_bytes'] for row in report['inspection_inputs']['inputs'] if row['path'].startswith(prefixes))
    if type(family_staging_bytes) is not int or family_staging_bytes < 0: raise ValueError('inspection family staging size is invalid')
    planned = sum(outputs.values()) + blob_bytes + max([node_inputs, family_staging_bytes, *oci], default=0) + 128 * 1024 ** 2
    if planned > MAX_REPLAY_BYTES: raise ValueError('inspection storage exceeds the 4 GB replay budget')
    return planned


def private_json(file):
    info = file.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 16384: raise ValueError('inspection storage owner record is not private')
    descriptor = os.open(file, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_BINARY', 0))
    with os.fdopen(descriptor, 'rb') as stream:
        held = os.fstat(descriptor)
        if not stat.S_ISREG(held.st_mode) or held.st_nlink != 1 or held.st_size > 16384: raise ValueError('inspection storage owner record is not private')
        if os.name == 'nt':
            import msvcrt
            authority = module('ud_replay_windows_storage', '../quality/windows-storage-acl.py').WindowsStorage()
            authority.inspect_handle(msvcrt.get_osfhandle(descriptor), str(file), 'file', True)
        elif held.st_mode & 0o077 or held.st_uid != os.getuid():
            raise ValueError('inspection storage owner record is not private')
        body = stream.read(16385)
        if len(body) != held.st_size: raise ValueError('inspection storage owner record changed')
        materials.verify_held_path(stream, file, materials.file_state(held))
        return json.loads(body)


def require_live_process(pid):
    if type(pid) is not int or not 0 < pid <= 0xffffffff: raise ValueError('inspection storage owner PID is invalid')
    if os.name != 'nt':
        os.kill(pid, 0)
        return
    # Python's Windows kill(pid, 0) sends CTRL_C_EVENT; it is not a query.
    import ctypes
    from ctypes import wintypes
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel.WaitForSingleObject.restype = wintypes.DWORD
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
    handle = kernel.OpenProcess(0x100000, False, pid)
    if not handle: raise ctypes.WinError(ctypes.get_last_error())
    try:
        if kernel.WaitForSingleObject(handle, 0) != 258: raise ValueError('inspection storage owner process is not live')
    finally: kernel.CloseHandle(handle)


def owned_storage_bytes(directory, limit):
    pending = [directory] if directory.exists() else []; total = 0
    while pending:
        file = pending.pop(); info = file.lstat()
        if stat.S_ISDIR(info.st_mode): pending.extend(file.iterdir())
        else: total += info.st_size
        if total > limit: raise ValueError('inspection owned storage would exceed 40 GB')
    return total


def admit_storage(root, destination, planned):
    owner = storage_owner(root); check_free_space(owner, destination, planned)
    token = os.environ.get('UD_STORAGE_LEASE')
    if token:
        try:
            identity = json.loads(base64.urlsafe_b64decode(token + '=' * (-len(token) % 4)))
            lock = owner / '.artifacts/.storage-reservation'
            if Path(identity['lock']) != lock or Path(identity['root']) != owner or lock.resolve() != lock: raise ValueError('foreign storage lease root')
            record = private_json(lock / 'reservation.json')
            if record['schema_version'] != 1 or any(record[key] != identity[key] for key in ('id', 'root', 'lock', 'directory', 'pid')) or type(record['plannedBytes']) is not int or not planned <= record['plannedBytes'] <= MAX_REPLAY_BYTES or type(record['pid']) is not int or record['pid'] <= 0: raise ValueError('storage lease byte plan or identity differs')
            directory = Path(record['directory'])
            compact_id = base64.urlsafe_b64encode(bytes.fromhex(record['id'].replace('-', ''))).rstrip(b'=').decode('ascii')
            names = ('ud-storage-' + record['id'], 'ud-' + compact_id)
            if directory not in (Path(record['parent']) / name for name in names): raise ValueError('storage lease directory differs')
            if directory.resolve() != directory:
                if os.name != 'nt': raise ValueError('storage lease directory differs')
                # Node may retain TEMP's 8.3 spelling. The held native check
                # admits only its long spelling of the same ordinary target.
                authority = module('ud_replay_windows_lease', '../quality/windows-storage-acl.py').WindowsStorage()
                authority.inspect(str(directory), 'directory')
                directory = directory.resolve()
            marker = private_json(directory / '.ud-storage-owner.json')
            if marker['id'] != record['id'] or marker['lock'] != str(lock): raise ValueError('storage lease marker differs')
            require_live_process(record['pid'])
        except (KeyError, TypeError, ValueError, OSError) as error:
            raise ValueError('inspection inherited storage lease is invalid') from error
    else:
        if (owner / '.artifacts/.storage-reservation').exists(): raise ValueError('inspection storage already has an active or interrupted reservation')
        if owned_storage_bytes(owner, MAX_OWNED_BYTES - planned) + planned > MAX_OWNED_BYTES: raise ValueError('inspection owned storage would exceed 40 GB')
    return owner


def put(destination, row, stream):
    name = inputs.safe(row['path']); target = destination / name
    expected = row['size_bytes']
    if type(expected) is not int or not 0 <= expected <= 8 * 1024 ** 3: raise ValueError('inspection output size is invalid')
    check_free_space(STORAGE.get() or ROOT, destination, expected)
    for parent in target.parents:
        if parent == destination.parent: break
        if parent.exists() and (parent.is_symlink() or not parent.is_dir()): raise ValueError('inspection output parent is not an ordinary directory')
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fingerprint = hashlib.sha256(); size = 0
    existing = target.exists() or target.is_symlink(); held = None; output = None
    try:
        if existing:
            held, _ = inputs.opened(destination, row)
            before = os.fstat(held.fileno())
        else: output = target.open('xb')
        while chunk := stream.read(min(1024 ** 2, expected - size + 1)):
            size += len(chunk)
            if size > expected: raise ValueError('materialized inspection input exceeds its receipt')
            if output is not None: output.write(chunk)
            fingerprint.update(chunk)
        if output is not None: output.flush(); os.fsync(output.fileno())
        if size != expected or fingerprint.hexdigest() != row['sha256']: raise ValueError('materialized inspection input differs from actual referenced bytes')
        if held is not None:
            materials.verify_held_path(held, target, materials.file_state(before))
        else: target.chmod(0o555 if row.get('executable', False) else 0o444)
        info = os.fstat((held if held is not None else output).fileno())
        return info.st_dev, info.st_ino
    finally:
        if output is not None: output.close()
        if held is not None: held.close()


def put_private_blob(destination, row, blob):
    """Reuse an already verified private replay blob without copying it again.

    The blob is created in the same disposable replay workspace, never linked
    directly to a candidate or an external build input. The regular-file and
    content checks still run for each destination. A full copy remains the
    conservative reservation and is used when links are not available.
    """
    name = inputs.safe(row['path']); target = destination / name
    # Windows READONLY belongs to the inode. Keep separate owned copies so
    # cleanup can clear that flag without changing a retained hardlink's mode.
    if os.name == 'nt':
        stream, _ = inputs.opened(blob.parent, {**row, 'path': blob.name})
        with stream: put(destination, row, stream)
        return
    if row.get('executable') is not False or target.exists() or target.is_symlink():
        with blob.open('rb') as stream: put(destination, row, stream)
        return
    check_free_space(STORAGE.get() or ROOT, destination, 0)
    for parent in target.parents:
        if parent == destination.parent: break
        if parent.exists() and (parent.is_symlink() or not parent.is_dir()): raise ValueError('inspection output parent is not an ordinary directory')
    # Before creating an alias, prove that the private blob has the expected
    # bytes and metadata. Verify the actual destination after the link too.
    stream, _ = inputs.opened(blob.parent, {**row, 'path': blob.name})
    stream.close()
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        os.link(blob, target, follow_symlinks=False)
    except OSError as error:
        if error.errno not in (errno.EXDEV, errno.EPERM, errno.ENOTSUP, errno.EOPNOTSUPP, errno.EMLINK): raise
        with blob.open('rb') as body: put(destination, row, body)
        return
    try:
        stream, _ = inputs.opened(destination, row)
        stream.close()
    except BaseException:
        target.unlink(missing_ok=True)
        raise


def require_unchanged(root, row, expected):
    """Confirm an in-place compact input remains the same ordinary file."""
    file = root
    for part in inputs.safe(row['path']).split('/'):
        file /= part
        if file.is_symlink(): raise ValueError('compact replay input path changed to a link')
    descriptor = os.open(file, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_BINARY', 0))
    with os.fdopen(descriptor, 'rb') as stream:
        try: materials.verify_held_path(stream, file, expected)
        except (OSError, ValueError) as error: raise ValueError('compact replay input changed during inspection') from error


class Parts:
    def __init__(self, root, rows): self.root = root; self.rows = iter(rows); self.current = None; self.identity = None; self.hash = hashlib.sha256(); self.size = 0
    def read(self, size):
        result = bytearray()
        while len(result) < size:
            if self.current is None:
                row = next(self.rows, None)
                if row is None: break
                self.current, self.identity, _ = materials.opened(self.root, row)
            chunk = self.current.read(size - len(result))
            if chunk:
                result.extend(chunk); self.hash.update(chunk); self.size += len(chunk)
            else:
                info = os.fstat(self.current.fileno())
                if self.identity != (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns): raise ValueError('source part changed while materializing inspection inputs')
                self.current.close(); self.current = None
        return bytes(result)
    def close(self):
        if self.current is not None: self.current.close(); self.current = None


class SeekableParts(io.RawIOBase):
    """Read verified source shards as one seekable stream without copying them."""
    def __init__(self, root, rows, expected_hash, expected_size):
        super().__init__()
        self.parts = []; self.offsets = []; self.size = 0; self.position = 0
        whole = hashlib.sha256()
        try:
            for row in rows:
                name = inputs.safe(row.get('path')); size = row.get('size'); fingerprint = row.get('sha256')
                if type(size) is not int or size <= 0 or not isinstance(fingerprint, str) or not re.fullmatch('[0-9a-f]{64}', fingerprint): raise ValueError('inspection source part receipt is invalid')
                file = root
                for part in name.split('/'):
                    file /= part
                    if file.is_symlink(): raise ValueError('inspection source part contains a link')
                fd = os.open(file, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0)); stream = os.fdopen(fd, 'rb')
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode) or info.st_size != size:
                    stream.close(); raise ValueError('inspection source part size or kind differs')
                identity = (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
                self.offsets.append(self.size); self.parts.append((stream, identity))
                self.size += size; part_hash = hashlib.sha256()
                while chunk := stream.read(1024 * 1024): whole.update(chunk); part_hash.update(chunk)
                self._unchanged(stream, identity)
                if part_hash.hexdigest() != fingerprint: raise ValueError('inspection source part differs from its identity')
            if not self.parts or self.size != expected_size or whole.hexdigest() != expected_hash:
                raise ValueError('inspection source stream is incomplete or differs')
        except BaseException:
            self.close(); raise

    @staticmethod
    def _unchanged(stream, identity):
        info = os.fstat(stream.fileno())
        if identity != (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns):
            raise ValueError('source part changed while inspecting source inputs')

    def verify_unchanged(self):
        for stream, identity in self.parts: self._unchanged(stream, identity)

    def readable(self): return True
    def seekable(self): return True
    def tell(self): return self.position
    def seek(self, offset, whence=io.SEEK_SET):
        position = offset if whence == io.SEEK_SET else self.position + offset if whence == io.SEEK_CUR else self.size + offset if whence == io.SEEK_END else -1
        if position < 0: raise ValueError('invalid source stream offset')
        self.position = position; return position
    def read(self, size=-1):
        if size is None or size < 0: size = max(0, self.size - self.position)
        size = min(size, max(0, self.size - self.position)); result = bytearray()
        while len(result) < size:
            part = bisect.bisect_right(self.offsets, self.position) - 1
            stream, _ = self.parts[part]
            stream.seek(self.position - self.offsets[part])
            chunk = stream.read(min(size - len(result), self.parts[part][1][2] - (self.position - self.offsets[part])))
            if not chunk: raise ValueError('inspection source part is truncated')
            result.extend(chunk); self.position += len(chunk)
        return bytes(result)
    def close(self):
        if not self.closed:
            for stream, _ in self.parts: stream.close()
        super().close()


class BlobView(io.RawIOBase):
    """A bounded seekable view of one archive member in verified source parts."""
    def __init__(self, parts, offset, size):
        super().__init__(); self.parts = parts; self.offset = offset; self.size = size; self.position = 0
    def readable(self): return True
    def seekable(self): return True
    def tell(self): return self.position
    def seek(self, offset, whence=io.SEEK_SET):
        position = offset if whence == io.SEEK_SET else self.position + offset if whence == io.SEEK_CUR else self.size + offset if whence == io.SEEK_END else -1
        if position < 0: raise ValueError('invalid source blob offset')
        self.position = position; return position
    def read(self, size=-1):
        if size is None or size < 0: size = max(0, self.size - self.position)
        size = min(size, max(0, self.size - self.position))
        self.parts.seek(self.offset + self.position); result = self.parts.read(size)
        self.position += len(result); return result


def source_part_index(root, candidate, candidate_root):
    """Resolve candidate-bound source shards and their authenticated index."""
    lock = json.loads((root / 'runtime/source-materials.lock.json').read_bytes())
    def released(row, identifier):
        found = [value for value in candidate['artifacts'] if value['id'] == identifier]
        if len(found) != 1 or any(found[0][key] != row[key] for key in ('sha256', 'size')) or Path(found[0]['path']).name != Path(row['path']).name: raise ValueError('inspection source sidecar differs from frozen artifact identity')
        return {**row, 'path': inputs.safe(found[0]['path'])}
    lock = {'index': released(lock['index'], 'corresponding-source-index'), 'parts': [released(row, row['id']) for row in lock['parts']]}
    stream, _, _ = materials.opened(candidate_root, lock['index'])
    try: index = json.load(stream)
    finally: stream.close()
    if len(lock['parts']) != len(index['parts']) or any(any(row[key] != expected[key] for key in ('id', 'sha256', 'size')) for row, expected in zip(lock['parts'], index['parts'])): raise ValueError('inspection source part order differs from its index')
    return lock['parts'], index


class SourceParts:
    """Verified, seekable access to the existing corresponding-source manifest."""
    def __init__(self, root, candidate, *, candidate_root=None):
        candidate_root = root if candidate_root is None else candidate_root
        rows, index = source_part_index(root, candidate, candidate_root)
        self.parts = SeekableParts(candidate_root, rows, index['stream_sha256'], index['stream_size_bytes'])
        self.blobs = {}; self.manifest = None; self.verified_blobs = set()
        try:
            entries = {}
            with tarfile.open(fileobj=self.parts, mode='r:') as archive:
                for entry in archive:
                    name = inputs.safe(entry.name)
                    if name in entries or len(entries) >= 100000 or not entry.isfile() or entry.pax_headers or entry.size > 8 * 1024 ** 3: raise ValueError('inspection source stream is not closed ordinary source material')
                    entries[name] = (entry.offset_data, entry.size)
                    if name == 'MATERIALS.json':
                        if entry.size > 32 * 1024 ** 2: raise ValueError('inspection source manifest exceeds bound')
                        with archive.extractfile(entry) as source: body = source.read()
                        if hashlib.sha256(body).hexdigest() != index['manifest_sha256']: raise ValueError('inspection source manifest differs')
                        self.manifest = json.loads(body)
            if not isinstance(self.manifest, dict) or not isinstance(self.manifest.get('files'), list) or not isinstance(self.manifest.get('collections'), list): raise ValueError('inspection source manifest is missing or invalid')
            expected = {'MATERIALS.json'}
            for row in self.manifest['files']:
                fingerprint, size = row.get('sha256'), row.get('size_bytes')
                if not isinstance(fingerprint, str) or not re.fullmatch('[0-9a-f]{64}', fingerprint) or type(size) is not int or size < 0 or row.get('path') != 'blobs/' + fingerprint or fingerprint in self.blobs: raise ValueError('inspection source manifest blob is invalid or duplicate')
                location = entries.get(row['path'])
                if location is None or location[1] != size: raise ValueError('inspection source manifest blob is missing or differs')
                self.blobs[fingerprint] = location; expected.add(row['path'])
            for row in self.manifest['collections']:
                name = inputs.safe(row.get('receipt_path')); size = row.get('receipt_size_bytes'); fingerprint = row.get('receipt_sha256')
                location = entries.get(name)
                if name in expected or not isinstance(fingerprint, str) or not re.fullmatch('[0-9a-f]{64}', fingerprint) or type(size) is not int or size < 0 or location is None or location[1] != size: raise ValueError('inspection source collection receipt is invalid')
                with BlobView(self.parts, *location) as body:
                    digest = hashlib.sha256()
                    while chunk := body.read(1024 * 1024): digest.update(chunk)
                    if digest.hexdigest() != fingerprint: raise ValueError('inspection source collection receipt differs')
                expected.add(name)
            if set(entries) != expected: raise ValueError('inspection source stream has unlisted or missing materials')
            self.parts.verify_unchanged()
        except BaseException:
            self.parts.close(); raise

    @contextmanager
    def open_blob(self, fingerprint, size):
        location = self.blobs.get(fingerprint)
        if location is None or location[1] != size: raise ValueError('inspection source blob is missing or differs')
        with BlobView(self.parts, *location) as blob:
            self.parts.verify_unchanged()
            if fingerprint not in self.verified_blobs:
                digest = hashlib.sha256()
                while chunk := blob.read(1024 * 1024): digest.update(chunk)
                if digest.hexdigest() != fingerprint: raise ValueError('inspection source blob differs from its identity')
                self.parts.verify_unchanged(); self.verified_blobs.add(fingerprint)
            blob.seek(0)
            try: yield blob
            finally: self.parts.verify_unchanged()

    def __enter__(self): return self
    def __exit__(self, *_): self.parts.close()


def stream_original_blobs(root, candidate, required, consume, *, candidate_root=None):
    """Consume requested exact source blobs without writing an extra copy."""
    found = set()
    with SourceParts(root, candidate, candidate_root=candidate_root) as source:
        for fingerprint, size in required.items():
            with source.open_blob(fingerprint, size) as blob: consume(fingerprint, blob)
            found.add(fingerprint)
    return found


def original_blobs(root, candidate, required, destination, *, candidate_root=None, consume=None):
    candidate_root = root if candidate_root is None else candidate_root
    rows, index = source_part_index(root, candidate, candidate_root)
    needed = dict(required); found = {}; seen = set(); reader = Parts(candidate_root, rows)
    try:
        with tarfile.open(fileobj=reader, mode='r|') as archive:
            for entry in archive:
                name = inputs.safe(entry.name)
                if name in seen or len(seen) >= 100000 or not entry.isfile() or entry.pax_headers or entry.size > 8 * 1024 ** 3: raise ValueError('inspection source stream is not closed ordinary source material')
                seen.add(name)
                if name == 'MATERIALS.json':
                    if entry.size > 32 * 1024 ** 2: raise ValueError('inspection source manifest exceeds bound')
                    with archive.extractfile(entry) as source: body = source.read()
                    if hashlib.sha256(body).hexdigest() != index['manifest_sha256']: raise ValueError('inspection source manifest differs')
                elif name.startswith('blobs/') and name[6:] in needed:
                    fingerprint = name[6:]
                    row = {'path': fingerprint, 'sha256': fingerprint, 'size_bytes': needed[fingerprint]}
                    if entry.size != row['size_bytes']: raise ValueError('inspection source blob size differs')
                    with archive.extractfile(entry) as source: created = put(destination, row, source)
                    found[fingerprint] = destination / fingerprint
                    if consume is not None:
                        try: consume(fingerprint, found[fingerprint])
                        finally:
                            file = found[fingerprint]
                            current = file.lstat()
                            if not stat.S_ISREG(current.st_mode) or (current.st_dev, current.st_ino) != created:
                                raise ValueError('private source blob identity changed during consumption')
                            if os.name == 'nt':
                                authority = module('ud_replay_windows_blob_cleanup', '../quality/windows-storage-acl.py').WindowsStorage()
                                authority.unlink_readonly(str(file), created)
                            else: file.unlink(missing_ok=True)
        while reader.read(1024 ** 2): pass
        if reader.hash.hexdigest() != index['stream_sha256'] or reader.size != index['stream_size_bytes'] or set(found) != set(needed): raise ValueError('inspection source stream is incomplete or differs')
    finally: reader.close()
    return found


def copy_members(file, source_receipt, requests, destination, *, npm=False, source_archive=False, provider_images=None, stream=None):
    """Only stream selected ordinary member bytes; never extract archive paths."""
    own_stream = stream is None
    if own_stream: stream, identity, _ = materials.opened(file.parent, {**source_receipt, 'path': file.name})
    found = set(); seen = set(); total = 0
    provider_images = {} if provider_images is None else provider_images
    found_images = set()
    def member(name, size, body, executable):
        nonlocal total
        name = inspector._paths.validate_path(name); key = name if source_archive else inspector._paths.path_key(name)
        pinned = provider_images.get(name)
        if key in seen or len(seen) >= 200000 or not 0 <= size <= (shipped.MAX_PROVIDER_IMAGE if pinned else MAX_MEMBER_FILE): raise ValueError('inspection member archive is duplicate or oversized')
        if pinned and size != pinned['size_bytes']: raise ValueError('inspection provider image size differs')
        seen.add(key); total += size
        if total > MAX_MEMBER_TOTAL: raise ValueError('inspection member archive expansion exceeds bound')
        if pinned:
            fingerprint = hashlib.sha256(); actual_size = 0
            while chunk := body.read(1024 ** 2):
                fingerprint.update(chunk); actual_size += len(chunk)
            if actual_size != size or fingerprint.hexdigest() != pinned['sha256']: raise ValueError('inspection provider image hash differs')
            found_images.add(name)
        selected = name.removeprefix('package/') if npm else name
        if selected in requests:
            for row in requests[selected]:
                body.seek(0) if hasattr(body, 'seek') else None
                # Compact family inputs derive mode from the exact verified
                # archive member; legacy catalog rows keep their recorded mode.
                selected_row = {**row, 'executable': executable} if row.get('executable') is None else row
                put(destination, selected_row, body)
                if row.get('executable') is None: row['executable'] = executable
            found.add(selected)
    try:
        if zipfile.is_zipfile(stream):
            stream.seek(0)
            with zipfile.ZipFile(stream) as archive:
                for entry in archive.infolist():
                    if entry.is_dir(): continue
                    if (entry.external_attr >> 16) & 0o170000 not in (0, 0o100000): raise ValueError('inspection source member is linked or special')
                    with archive.open(entry) as body: member(entry.filename, entry.file_size, body, bool((entry.external_attr >> 16) & 0o111))
        else:
            stream.seek(0)
            with tarfile.open(fileobj=stream, mode='r:*') as archive:
                for entry in archive:
                    if entry.isdir(): continue
                    # Original source archives may retain opaque upstream links;
                    # they cannot satisfy an ordinary-file input request.
                    if not entry.isfile():
                        if entry.name in requests: raise ValueError('inspection source member is not ordinary')
                        continue
                    with archive.extractfile(entry) as body: member(entry.name.removeprefix('./'), entry.size, body, bool(entry.mode & 0o111))
        if own_stream:
            info = os.fstat(stream.fileno())
            if identity != (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns): raise ValueError('inspection archive changed or omitted a referenced member')
        if found != set(requests) or found_images != set(provider_images): raise ValueError('inspection archive changed or omitted a referenced member')
    finally:
        if own_stream: stream.close()


def copy_oci_members(artifact_root, runtime_root, artifact, runtime_sha256, requests, destination, *, available_targets=False):
    """Copy exact graph-observed bytes through opaque files, never image paths."""
    if not inputs.oci_artifact(artifact['id']): raise ValueError('inspection OCI artifact identity is unsupported')
    for name in requests: inputs.artifact_member(artifact['id'], name)
    raw = (runtime_root / 'runtime/runtime.lock.json').read_bytes()
    if len(raw) > 32 * 1024 ** 2 or hashlib.sha256(raw).hexdigest() != runtime_sha256: raise ValueError('inspection OCI runtime lock differs')
    runtime = json.loads(raw)
    if runtime.get('state') != 'frozen': raise ValueError('inspection OCI runtime is not frozen')
    found = set()
    def observe(name, opaque):
        if name in requests:
            for row in requests[name]:
                with opaque.open('rb') as body: put(destination, row, body)
            found.add(name)
    if artifact['id'].endswith('-oci-index'):
        pack = runtime['packs'][artifact['id'].removesuffix('-oci-index')]
        descriptor = pack['index_transport']
        if descriptor['sha256'] != 'sha256:' + artifact['sha256'] or descriptor['size_bytes'] != artifact['size']: raise ValueError('inspection OCI index differs from its frozen descriptor')
        # Only the contained physical archive path is projected. Its hash,
        # complete graph, platforms, config and layer identities stay frozen.
        projection = {**pack, 'index_transport': {**descriptor, 'path': inputs.safe(artifact['path'])}}
        for number, platform in enumerate(sorted(pack['images'])):
            with tempfile.TemporaryDirectory(prefix='ud-inspection-oci-members-', dir=destination.parent) as temporary:
                def file_observer(name, opaque, serial, layer, index):
                    observe('layers/' + layer['digest'][7:] + '/' + str(serial) + '/' + name, opaque)
                shipped.oci.verified_filesystem(artifact_root, projection, platform, Path(temporary) / str(number), available_targets, file_observer=file_observer)
    else:
        match = __import__('re').fullmatch(r'(core|render)-linux-(arm64|amd64)-(oci-archive|docker-archive)-([0-9]+)', artifact['id'])
        # transport_members uses Python's default temporary directory. Keep its
        # bounded sequential OCI workspace beside this replay instead of an
        # unrelated, unmonitored system temp directory.
        previous_tempdir = tempfile.tempdir
        try:
            tempfile.tempdir = str(destination.parent)
            shipped.transport_members(artifact_root, artifact_root / inputs.safe(artifact['path']), artifact, runtime, match[1], 'linux/' + match[2], match[3], int(match[4]), member_observer=observe)
        finally: tempfile.tempdir = previous_tempdir
    if found != set(requests): raise ValueError('inspection OCI graph omitted a referenced ordinary member')


@contextmanager
def staged_perl_family(root, candidate, candidate_root, assets_root, pack, rows, source_parts, required_materials, recorder, *, input_pack=None):
    """Materialize one declared Perl pack, then retain observations and remove it."""
    pack = inputs.safe(pack); packs = [pack] + ([inputs.safe(input_pack)] if input_pack is not None else []); assets_root = Path(assets_root)
    if len(set(packs)) != len(packs) or any(left.startswith(right + '/') or right.startswith(left + '/') for left in packs for right in packs if left != right): raise ValueError('inspection Perl family packs overlap')
    targets = []
    for name in packs:
        target = assets_root
        for part in name.split('/'):
            target /= part
            if target.is_symlink(): raise ValueError('inspection Perl family path contains a link')
        if target.exists(): raise ValueError('inspection Perl family stage is not new')
        targets.append(target)
    if not rows or any(not any(row['path'].startswith(name + '/') for name in packs) for row in rows): raise ValueError('inspection Perl family has foreign inputs')
    subjects = {row['id']: row for row in candidate['artifacts'] if row['id'] not in ('component-source-coverage', 'publisher-authority', 'checksum-manifest')}
    originals = {row['sha256']: row['size_bytes'] for row in required_materials}; groups = {}; source_groups = {}
    if len(originals) != len(required_materials): raise ValueError('inspection Perl source materials are duplicated')
    was_active = recorder.active
    try:
        # Materialization reads are not family observations. Only actual
        # binder reads may be checkpointed for the final reconciliation.
        recorder.active = False
        for row in rows:
            reference = row['retention']; kind = reference['kind']
            if kind == 'corresponding-source-blob':
                if reference != {'kind': kind, 'member': 'blobs/' + row['sha256']} or originals.get(row['sha256']) != row['size_bytes']: raise ValueError('inspection Perl original is not a selected source blob')
                with source_parts.open_blob(row['sha256'], row['size_bytes']) as blob: put(assets_root, row, blob)
            elif kind == 'corresponding-source-member':
                if set(reference) != {'kind', 'blob_sha256', 'member'} or reference['blob_sha256'] not in originals: raise ValueError('inspection Perl member has no selected source blob')
                member = inputs.safe(reference['member'])
                source_groups.setdefault(reference['blob_sha256'], {}).setdefault(member, []).append(row)
            elif kind == 'released-artifact-member':
                if set(reference) != {'kind', 'artifact', 'member'}: raise ValueError('inspection Perl artifact member is malformed')
                identifier = reference['artifact']; member = inputs.artifact_member(identifier, reference['member'])
                if identifier not in subjects or inputs.oci_artifact(identifier): raise ValueError('inspection Perl artifact member has no supported subject')
                groups.setdefault(identifier, {}).setdefault(member, []).append(row)
            else: raise ValueError('inspection Perl family input is unsupported')
        for fingerprint, requests in source_groups.items():
            with source_parts.open_blob(fingerprint, originals[fingerprint]) as blob:
                copy_members(None, {'sha256':fingerprint, 'size_bytes':originals[fingerprint]}, requests, assets_root, source_archive=True, stream=blob)
        for identifier, requests in groups.items():
            artifact = subjects[identifier]
            pinned = shipped.provider_image_members(root, artifact, candidate.get('runtime_lock_sha256'))
            copy_members(Path(candidate_root) / inputs.safe(artifact['path']), artifact, requests, assets_root, npm=identifier == 'npm', provider_images=pinned)
        if any(not target.is_dir() or target.is_symlink() for target in targets): raise ValueError('inspection Perl family stage was not created')
        recorder.active = was_active
        yield
        # Verify and retain the consumed identities before removing the pack.
        # These observations are in memory only, never a second input catalog.
        for row in rows:
            if row['path'] in recorder.paths:
                expected = {key: value for key, value in row.items() if key != 'executable' or value is not None}
                recorder.checkpoint(assets_root / row['path'], expected=expected)
    finally:
        recorder.active = was_active
        for target in reversed(targets):
            if target.exists() or target.is_symlink():
                if target.is_symlink() or not target.is_dir(): raise ValueError('inspection Perl family stage changed during cleanup')
                remove_private_tree(target)


def materialize(root, candidate, source, report, destination, *, candidate_root=None, compact=False, stream_source=False):
    """The signed report is authority only after real referenced bytes verify."""
    candidate_root = root if candidate_root is None else candidate_root
    catalog = report.get('inspection_inputs', {}); rows = catalog.get('inputs')
    if catalog.get('schema_version') != 1 or catalog.get('qualification') != inputs.QUALIFICATION or catalog.get('source_inventory_sha256') != source['sha256'] or report.get('source_inventory_sha256') != source['sha256'] or not isinstance(rows, list) or len(rows) > inputs.MAX_FILES or catalog.get('inventory_sha256') != hashlib.sha256(inputs.canonical(rows)).hexdigest(): raise ValueError('inspection materialization catalog is invalid or foreign')
    if catalog.get('unretained_inputs') != [] or any(row.get('retention', {}).get('kind') == 'unretained-local-input' for row in rows): raise ValueError('unretained inspection inputs cannot be materialized or admitted')
    subjects = [row for row in candidate['artifacts'] if row['id'] not in ('component-source-coverage', 'publisher-authority', 'checksum-manifest')]
    if catalog.get('subjects') != [{'id': row['id'], 'sha256': row['sha256']} for row in subjects]: raise ValueError('inspection materialization subjects differ')
    if destination.exists() or destination.is_symlink(): raise ValueError('inspection materialization requires a new private tree')
    names = [inputs.safe(row['path']) for row in rows]
    if names != sorted(set(names)): raise ValueError('inspection materialization input paths collide')
    if len({inspector._paths.path_key(name) for name in names}) != len(names): raise ValueError('inspection materialization paths collide under frozen Unicode policy')
    families = deferred_perl_families(root, subjects, catalog) if compact and stream_source else {}
    omitted = streamed_source_paths(root, subjects, catalog) if compact and stream_source else set()
    omitted.update(row['path'] for family in families.values() for row in family)
    family_bytes = max((sum(row['size_bytes'] for row in family) for family in families.values()), default=0)
    planned = replay_storage_bytes(source, subjects, report, compact=compact, streamed_paths=omitted, family_staging_bytes=family_bytes)
    rows = [row for row in rows if row['path'] not in omitted]
    owner = admit_storage(root, destination, planned)
    destination.mkdir(mode=0o700); blob_root = None
    storage_context = STORAGE.set(owner)
    try:
        if not compact: blob_root = Path(tempfile.mkdtemp(prefix='ud-inspection-source-blobs-', dir=destination.parent))
        held = []
        for row in source['files']:
            stream, identity, _ = materials.opened(root, row)
            try:
                if not compact: put(destination, {**row, 'size_bytes': row['size']}, stream)
                else: held.append((root, row, identity))
            finally: stream.close()
        by_artifact = {row['id']: row for row in subjects}
        for row in subjects:
            stream, identity, _ = materials.opened(candidate_root, row)
            try:
                if not compact: put(destination, {**row, 'size_bytes': row['size']}, stream)
                else: held.append((candidate_root, row, identity))
            finally: stream.close()
        material_sizes = {row['sha256']: row['size_bytes'] for row in report['required_materials']}
        needed = {}
        for row in rows:
            reference = row['retention']; kind = reference['kind']
            fingerprint = row['sha256'] if kind == 'corresponding-source-blob' else reference.get('blob_sha256') if kind == 'corresponding-source-member' else None
            if fingerprint is not None:
                if fingerprint not in material_sizes: raise ValueError('inspection reference has no required original source blob')
                needed[fingerprint] = material_sizes[fingerprint]
        blobs = original_blobs(root, candidate, needed, blob_root, candidate_root=candidate_root) if needed and not compact else {}
        groups = {}; direct_blobs = {}; metadata_size = 0
        for row in rows:
            if set(row) != {'path', 'sha256', 'size_bytes', 'executable', 'retention'} or type(row['executable']) is not bool: raise ValueError('inspection materialization receipt is not closed')
            reference = row['retention']; kind = reference['kind']
            if kind == 'retained-json-metadata':
                body = base64.b64decode(reference['base64'], validate=True); metadata_size += len(body)
                if len(body) > 8 * 1024 ** 2 or metadata_size > inputs.MAX_METADATA: raise ValueError('inspection materialization metadata exceeds bound')
                json.loads(body); put(destination, row, io.BytesIO(body))
            elif kind == 'corresponding-source-blob':
                if compact: direct_blobs.setdefault(row['sha256'], []).append(row)
                else: put_private_blob(destination, row, blobs[row['sha256']])
            elif kind == 'released-artifact':
                origin = by_artifact.get(reference['artifact'])
                if origin is None or origin['sha256'] != row['sha256'] or origin['size'] != row['size_bytes']: raise ValueError('inspection artifact reference differs')
                stream, _, _ = materials.opened(candidate_root, origin)
                try: put(destination, row, stream)
                finally: stream.close()
            elif kind in ('private-locked-cpython-input', 'private-locked-windows-perl-input'):
                if reference != inputs.private_vendor_reference(row, reference.get('role')):
                    raise ValueError('unrecognized private vendor verification input')
                stream, _ = inputs.opened(root, row)
                try: put(destination, row, stream)
                finally: stream.close()
            elif kind in ('corresponding-source-member', 'released-artifact-member'):
                key = (kind, reference.get('blob_sha256') if kind == 'corresponding-source-member' else reference.get('artifact'))
                member = inputs.safe(reference['member']) if kind == 'corresponding-source-member' else inputs.artifact_member(reference.get('artifact'), reference['member'])
                groups.setdefault(key, {}).setdefault(member, []).append(row)
            else: raise ValueError('unsupported inspection materialization reference')
        if compact and needed:
            def consume_original(identity, blob):
                for row in direct_blobs.get(identity, []):
                    blob.seek(0); put(destination, row, blob)
                requests = groups.pop(('corresponding-source-member', identity), None)
                if requests:
                    blob.seek(0)
                    copy_members(None, {'sha256': identity, 'size_bytes': material_sizes[identity]}, requests, destination, source_archive=True, stream=blob)
            blobs = stream_original_blobs(root, candidate, needed, consume_original, candidate_root=candidate_root)
        for (kind, identity), requests in groups.items():
            if kind == 'corresponding-source-member':
                copy_members(blobs[identity], {'sha256': identity, 'size_bytes': material_sizes[identity]}, requests, destination, source_archive=True)
            else:
                origin = by_artifact.get(identity)
                if origin is None: raise ValueError('inspection member has no actual released artifact')
                if inputs.oci_artifact(identity):
                    # The subject was already hash-copied and made read-only
                    # inside this private tree before graph-based inspection.
                    artifact_root, runtime_root = (candidate_root, root) if compact else (destination, destination)
                    copy_oci_members(artifact_root, runtime_root, origin, candidate.get('runtime_lock_sha256'), requests, destination, available_targets=candidate.get('qualification') == 'available-target-preacceptance')
                else:
                    pinned = shipped.provider_image_members(root, origin, candidate.get('runtime_lock_sha256'))
                    copy_members(candidate_root / origin['path'], origin, requests, destination, npm=identity == 'npm', provider_images=pinned)
        if compact:
            for base, row, identity in held: require_unchanged(base, row, identity)
        return {'verified': True, 'inputs': len(rows), 'deferred_streamed_sources': len(omitted), 'deferred_families': len(families), 'source_blobs': len(blobs), 'artifacts': len(subjects), 'storage_plan_bytes': planned}
    except BaseException:
        remove_private_tree(destination); raise
    finally:
        try:
            if blob_root is not None: remove_private_tree(blob_root)
        finally: STORAGE.reset(storage_context)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for flag in ('root', 'candidate', 'source', 'report', 'output'): parser.add_argument('--' + flag, type=Path, required=True)
    parser.add_argument('--candidate-root', type=Path)
    parser.add_argument('--compact', action='store_true')
    parser.add_argument('--stream-source', action='store_true')
    parser.add_argument('--plan', action='store_true')
    args = parser.parse_args()
    root = args.root.resolve(); candidate = json.loads(args.candidate.read_bytes()); source = json.loads(args.source.read_bytes()); report = json.loads(args.report.read_bytes())
    if args.stream_source and not args.compact: raise ValueError('streamed source replay requires compact inputs')
    subjects = [row for row in candidate['artifacts'] if row['id'] not in ('component-source-coverage', 'publisher-authority', 'checksum-manifest')]
    catalog = report.get('inspection_inputs', {}); rows = catalog.get('inputs')
    if not isinstance(rows, list) or catalog.get('source_inventory_sha256') != source['sha256'] or catalog.get('inventory_sha256') != hashlib.sha256(inputs.canonical(rows)).hexdigest() or catalog.get('subjects') != [{'id': row['id'], 'sha256': row['sha256']} for row in subjects] or catalog.get('unretained_inputs') != []: raise ValueError('inspection materialization catalog is invalid or foreign')
    families = deferred_perl_families(root, subjects, catalog) if args.compact and args.stream_source else {}
    omitted = streamed_source_paths(root, subjects, catalog) if args.compact and args.stream_source else set()
    omitted.update(row['path'] for family in families.values() for row in family)
    family_bytes = max((sum(row['size_bytes'] for row in family) for family in families.values()), default=0)
    planned = replay_storage_bytes(source, subjects, report, compact=args.compact, streamed_paths=omitted, family_staging_bytes=family_bytes)
    if args.plan:
        print(json.dumps({'storage_plan_bytes': planned, 'deferred_streamed_sources': len(omitted)})); raise SystemExit(0)
    if not os.environ.get('UD_STORAGE_LEASE'):
        node = shutil.which('node')
        if not node: raise ValueError('standalone replay requires the supported Node coordinator for bounded storage reservation')
        # The existing Node lifecycle owns the reservation until this exact
        # candidate script exits. Existing CLI output paths remain unchanged.
        command = [node, str(ROOT / 'scripts/quality/storage-lifecycle.mjs'), '--run', str(storage_owner(root)), str(planned), 'release', '--', sys.executable, '-I', '-S', '-B', str(Path(__file__).resolve()), *sys.argv[1:]]
        raise SystemExit(subprocess.run(command, check=False).returncode)
    print(json.dumps(materialize(root, candidate, source, report, args.output.resolve(), candidate_root=args.candidate_root.resolve() if args.candidate_root else None, compact=args.compact, stream_source=args.stream_source)))
