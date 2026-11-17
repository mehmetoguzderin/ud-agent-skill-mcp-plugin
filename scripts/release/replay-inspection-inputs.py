"""Retain the exact data inputs consumed by fixed component-source replay.

This is an inspection catalog, not a source/license waiver or a reconstruction
language. Metadata bytes are retained; source blobs and shipped members name
their existing distribution subjects. Anything else stays explicitly unretained.
"""
from __future__ import annotations
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys

MAX_FILES = 100000
MAX_METADATA = 32 * 1024 ** 2
QUALIFICATION = 'observed-component-replay-inputs-no-unretained-input-waiver'
COMPACT_QUALIFICATION = 'compact-family-replay-inputs-no-unretained-input-waiver'


def audit_executable(executable, arguments):
    if executable is not None: return os.fsdecode(executable)
    # Windows subprocess audits the command line with executable=None. Its
    # list2cmdline output quotes an application path containing whitespace.
    # Retain only an unambiguous first token; never mistake argv for a path.
    if isinstance(arguments, (list, tuple)) and arguments: return os.fsdecode(arguments[0])
    if isinstance(arguments, str):
        matched = re.match(r'^(?:"([^"\r\n]+)"|([^\s"]+))(?:\s|$)', arguments)
        if matched: return matched.group(1) or matched.group(2)
    raise ValueError('inspection subprocess has no unambiguous executable')


def canonical(value): return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()


def safe(name):
    if not isinstance(name, str) or not name or name.startswith('/') or '\\' in name or ':' in name or '\0' in name or any(part in ('', '.', '..') for part in name.split('/')):
        raise ValueError('inspection input path is unsafe')
    return name


def private_vendor_reference(row, role):
    fingerprint = row['sha256']
    path = safe(row['path'])
    if not re.fullmatch('[a-f0-9]{64}', fingerprint):
        raise ValueError('private vendor inspection input digest is invalid')
    if role == 'cpython-donor-layer':
        pattern = r'\.artifacts/source-materials-data/core-image-provenance-v1/layers/' + fingerprint
        maximum = 1024 ** 3
    elif role == 'cpython-pip-generator':
        pattern = r'\.artifacts/source-materials-data/python-runtime-sources/blobs/' + fingerprint
        maximum = 8 * 1024 ** 2
    elif role in ('windows-perl-supplier-archive', 'windows-perl-vc-archive'):
        pattern = (r'\.artifacts/native-perl/cache/windows/perl-[a-z0-9_.-]+(?:\.conda|\.tar\.bz2)'
                   if role == 'windows-perl-supplier-archive'
                   else r'\.artifacts/native-perl/cache/windows/vc14_runtime-[a-z0-9_.-]+\.conda')
        maximum = 128 * 1024 ** 2
    elif role == 'windows-perl-build-input-member':
        pattern = r'\.artifacts/native-perl/[a-z0-9_-]+/(?:bin|lib)/.+\.(?:dll|exe|lib|pdb|exp)'
        maximum = 32 * 1024 ** 2
    else:
        raise ValueError('unknown private vendor inspection input role')
    windows_member = role == 'windows-perl-build-input-member'
    if (not re.fullmatch(pattern, path, re.IGNORECASE if windows_member else 0)
            or type(row['size_bytes']) is not int or not 0 < row['size_bytes'] <= maximum
            or (row['executable'] and not windows_member)):
        raise ValueError('private vendor inspection input is outside its locked role')
    kind = 'private-locked-cpython-input' if role.startswith('cpython-') else 'private-locked-windows-perl-input'
    return {'kind': kind, 'role': role}


def oci_artifact(identifier):
    return isinstance(identifier, str) and re.fullmatch(r'(?:core|render)-(?:oci-index|linux-(?:arm64|amd64)-(?:oci-archive|docker-archive)-[0-9]+)', identifier) is not None


def artifact_member(identifier, name):
    """OCI layer locators are opaque keys, never host output paths."""
    if not oci_artifact(identifier):
        return safe(name)
    if not isinstance(name, str) or not re.fullmatch(r'layers/[a-f0-9]{64}/(?:0|[1-9][0-9]*)/.+', name) or '\\' in name or '\0' in name or any(part in ('', '.', '..') for part in name.split('/')):
        raise ValueError('inspection OCI member locator is unsafe')
    return name


def opened(root, row):
    file = root
    for part in safe(row['path']).split('/'):
        file /= part
        if file.is_symlink(): raise ValueError('inspection input contains a link')
    descriptor = os.open(file, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
    if not stat.S_ISREG(os.fstat(descriptor).st_mode):
        os.close(descriptor); raise ValueError('inspection input is not an ordinary file')
    stream = os.fdopen(descriptor, 'rb')
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size > 8 * 1024 ** 3: raise ValueError('inspection input is special or oversized')
        fingerprint = hashlib.file_digest(stream, 'sha256').hexdigest(); after = os.fstat(descriptor)
        identity = lambda info: (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        if identity(before) != identity(after): raise ValueError('inspection input changed during verification')
        if 'sha256' in row and (row['sha256'] != fingerprint or row['size_bytes'] != before.st_size): raise ValueError('inspection input differs from its retained identity')
        executable = bool(before.st_mode & 0o111)
        if 'executable' in row:
            if type(row['executable']) is not bool: raise ValueError('inspection input executable mode differs')
            if os.name == 'nt':
                # Windows cannot retain POSIX executable bits. Keep the
                # archive's metadata only alongside its verified byte identity.
                if 'sha256' not in row: raise ValueError('inspection executable metadata lacks retained byte identity')
                executable = row['executable']
            elif executable != row['executable']: raise ValueError('inspection input executable mode differs')
        stream.seek(0)
        return stream, {'path': row['path'], 'sha256': fingerprint, 'size_bytes': before.st_size, 'executable': executable}
    except BaseException:
        stream.close(); raise


class _FamilyObservations:
    """Ephemeral identities captured by this recorder before family cleanup.

    This is not serialized as new authority. Original archives and candidate
    members remain independently verified by their existing binders.
    """
    def __init__(self, recorder):
        self.recorder = recorder
        self.root = recorder.assets_root
        self.rows = {}
        self.metadata_bytes = 0


class Recorder:
    """Observe Python reads plus explicit fixed-backend input receipts.

    Subprocess tool identities are separate, nonredistributed prerequisites.
    Backend-reported files supplement reads performed inside Node/esbuild.
    No observation grants a right to redistribute the observed bytes.
    """
    def __init__(self, source_root, assets_root):
        self.assets_alias = Path(os.path.abspath(assets_root))
        self.source_root = Path(source_root).resolve(); self.assets_root = Path(assets_root).resolve()
        self.verified_subject_files = {}
        self.paths = set(); self.existing_paths = set(); self.tools = {}; self.active = False
        self.references = {}; self.reference_contents = {}
        self.streamed_sources = {}
        self.private_vendor_inputs = {}
        self.observations = _FamilyObservations(self)

    def private_vendor_input(self, file, role, expected):
        """Record a fixed, independently authenticated input without redistributing it."""
        name = self._asset_name(file)
        self.note(file)
        stream, row = opened(self.assets_root, {**expected, 'path': name})
        stream.close()
        selection = (row, private_vendor_reference(row, role))
        if name in self.private_vendor_inputs and self.private_vendor_inputs[name] != selection:
            raise ValueError('private vendor inspection input changed between reads')
        self.private_vendor_inputs[name] = selection

    def _asset_name(self, file):
        file = Path(os.path.abspath(file))
        try: name = file.relative_to(self.assets_alias).as_posix()
        except ValueError:
            try: name = file.relative_to(self.assets_root).as_posix()
            except ValueError: raise ValueError('inspection observation is outside its input root') from None
        return safe(name)

    def checkpoint(self, file, expected=None):
        """Capture one actually observed input before its private family is removed.

        Expected identities, when supplied by a fixed family receipt, are
        checked against the same opened bytes. JSON needed by final retention
        is bounded and held only in memory, not written as another catalog.
        """
        name = self._asset_name(file)
        if name not in self.paths: raise ValueError('inspection checkpoint was not observed by the family')
        expected = {} if expected is None else dict(expected)
        if 'path' in expected and expected['path'] != name: raise ValueError('inspection checkpoint receipt path differs')
        if 'sha256' in expected:
            expected['sha256'] = expected['sha256'].removeprefix('sha256:')
            if 'size_bytes' not in expected and 'size' in expected: expected['size_bytes'] = expected['size']
            if 'size_bytes' not in expected: raise ValueError('inspection checkpoint receipt lacks a size')
        stream, row = opened(self.assets_root, {**expected, 'path': name})
        try:
            if name in self.reference_contents and self.reference_contents[name] != row: raise ValueError('inspection source member changed before family cleanup')
            if name in self.streamed_sources and self.streamed_sources[name] != row: raise ValueError('streamed source differs before family cleanup')
            previous = self.observations.rows.get(name)
            if previous is not None:
                if previous['row'] != row: raise ValueError('inspection input changed between family checkpoints')
                return row
            body = None
            if name.endswith('.json') and row['size_bytes'] <= 8 * 1024 ** 2 and self.observations.metadata_bytes + row['size_bytes'] <= MAX_METADATA:
                body = stream.read(row['size_bytes'] + 1)
                if len(body) != row['size_bytes'] or hashlib.sha256(body).hexdigest() != row['sha256']:
                    raise ValueError('inspection metadata changed during family checkpoint')
                self.observations.metadata_bytes += len(body)
            self.observations.rows[name] = {'row': row, 'body': body}
            return row
        finally: stream.close()

    def observed_bytes(self, file):
        """Return captured bounded JSON only when this family observed it."""
        name = self._asset_name(file); captured = self.observations.rows.get(name)
        if captured is None or captured['body'] is None: raise ValueError('inspection metadata was not captured before cleanup')
        if len(captured['body']) != captured['row']['size_bytes'] or hashlib.sha256(captured['body']).hexdigest() != captured['row']['sha256']: raise ValueError('inspection captured metadata differs')
        return captured['body']

    def observed_receipt(self, file, expected=None):
        """Check a cleaned input against its independent family receipt."""
        name = self._asset_name(file); captured = self.observations.rows.get(name)
        if captured is None: raise ValueError('inspection input was not captured before cleanup')
        row = captured['row']
        if expected is not None:
            fingerprint = expected.get('sha256', '').removeprefix('sha256:')
            size = expected.get('size_bytes', expected.get('size'))
            if fingerprint != row['sha256'] or size != row['size_bytes'] or 'executable' in expected and expected['executable'] != row['executable']: raise ValueError('inspection observation differs from its family receipt')
        return dict(row)

    def note(self, file):
        file = Path(os.path.abspath(file))
        try: name = file.relative_to(self.assets_alias).as_posix()
        except ValueError:
            try: name = file.relative_to(self.assets_root).as_posix()
            except ValueError:
                # Controlled private build overlays may refer back to the
                # actual input tree. Observe those real bytes too. An alias
                # already inside the input root keeps its original name and
                # remains subject to opened()'s ordinary-path/link checks.
                try: name = file.resolve().relative_to(self.assets_root).as_posix()
                except (ValueError, OSError, RuntimeError): return
        if len(self.paths) >= MAX_FILES and name not in self.paths: raise ValueError('inspection input count exceeds bound')
        self.paths.add(safe(name))
        try:
            info = file.lstat()
            if stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode): self.existing_paths.add(name)
        except FileNotFoundError: pass

    def separately_verified(self, file, sha256, size_bytes):
        """Only exact source/runtime/archive files have separate byte authority."""
        record = {'sha256': sha256.removeprefix('sha256:'), 'size_bytes': size_bytes}
        for name in (Path(os.path.abspath(file)), Path(file).resolve()):
            self.verified_subject_files[name] = record

    def source_blob(self, file, sha256, size_bytes):
        """Remember an original blob verified directly in immutable source parts."""
        self.note(file)
        name = Path(os.path.abspath(file)).relative_to(self.assets_alias).as_posix()
        if not re.fullmatch('[a-f0-9]{64}', sha256) or type(size_bytes) is not int or size_bytes < 0: raise ValueError('streamed source identity is invalid')
        row = {'path': safe(name), 'sha256': sha256, 'size_bytes': size_bytes, 'executable': False}
        if name in self.streamed_sources and self.streamed_sources[name] != row: raise ValueError('streamed source identity changed')
        self.streamed_sources[name] = row

    def audit(self, event, args):
        if not self.active: return
        if event == 'open' and isinstance(args[0], (str, bytes, os.PathLike)):
            # O_RDWR is a read; write-only outputs are not replay inputs.
            if args[2] & (os.O_WRONLY | os.O_RDWR) != os.O_WRONLY: self.note(os.fsdecode(args[0]))
        elif event == 'subprocess.Popen':
            executable = audit_executable(args[0], args[1]); selected = shutil.which(executable)
            if args[0] is None and not selected: raise ValueError('inspection subprocess executable is unresolved or ambiguous')
            if selected: self.tools[Path(selected).resolve().as_posix()] = Path(executable).name

    def source_member(self, file, archive_sha256, member):
        self.note(file)
        name = Path(os.path.abspath(file)).relative_to(self.assets_alias).as_posix()
        reference = {'kind': 'corresponding-source-member', 'blob_sha256': archive_sha256, 'member': safe(member)}
        try:
            stream, content = opened(self.assets_root, {'path': name}); stream.close()
        except FileNotFoundError:
            # The caller still verifies the actual archive member before this
            # join; only an exact pre-cleanup file observation may stand in
            # for the removed temporary member path.
            content = self.observed_receipt(file)
        if name in self.reference_contents and self.reference_contents[name] != content: raise ValueError('inspection source member bytes changed between original origins')
        self.reference_contents[name] = content
        # Notice caches deduplicate identical original bytes from several
        # archives. Preserve those independently verified alternatives and
        # select deterministically among the actually required source blobs.
        self.references.setdefault(name, {})[canonical(reference)] = reference

    def __enter__(self):
        sys.addaudithook(self.audit); self.active = True; return self

    def __exit__(self, *_): self.active = False

    def _inputs(self, source, discovery, required_materials, artifacts_input=(), *, strict_missing=False):
        self.active = False
        protected = {row['path']: row for row in source['files']}
        for row in source['files']:
            try: name = (self.source_root / row['path']).relative_to(self.assets_root).as_posix()
            except ValueError: continue
            protected[name] = row
        originals = {(row['sha256'], row['size_bytes']) for row in required_materials}
        artifacts = {}; members = {}
        for subject in discovery['subjects']:
            artifacts[(subject['sha256'], subject['size_bytes'])] = subject['id']
            for row in subject['members']:
                if 'sha256' in row: members.setdefault((row['sha256'], row['size_bytes']), {'artifact': subject['id'], 'member': row['path']})
        retained_bytes = 0
        artifact_paths = {row['path'] for row in artifacts_input}
        for name in sorted(self.paths):
            file = self.assets_root / name
            captured = self.observations.rows.get(name)
            if not file.exists() and name not in self.streamed_sources and captured is None:
                if strict_missing and name in self.existing_paths: raise ValueError('observed family input disappeared without a checkpoint: ' + name)
                continue # A failed optional lookup consumed no bytes.
            if not file.is_symlink() and file.is_dir(): continue # Directory FDs contain no input-file bytes.
            if not file.exists() and not file.is_symlink():
                row = captured['row'] if captured is not None else self.streamed_sources[name]
                if name in self.streamed_sources and self.streamed_sources[name] != row: raise ValueError('streamed source differs from family observation')
                stream = io.BytesIO(captured['body'] if captured is not None and captured['body'] is not None else b'')
            else:
                stream, row = opened(self.assets_root, captured['row'] if captured is not None and os.name == 'nt' else {'path': name})
                if name in self.streamed_sources and self.streamed_sources[name] != row: raise ValueError('streamed source differs from its staged file')
                if captured is not None and captured['row'] != row: raise ValueError('inspection input changed after family checkpoint')
            try:
                verified = self.verified_subject_files.get(file) or self.verified_subject_files.get(file.resolve())
                if verified is not None:
                    if any(row[key] != verified[key] for key in ('sha256', 'size_bytes')): raise ValueError('separately inventoried replay subject changed')
                    continue
                # Candidate archive paths change from assembly staging to the
                # final release directory. Their exact signed descriptors are
                # copied separately, not stored as incidental cache paths.
                if name in artifact_paths: continue
                if protected.get(name, {}).get('sha256') == row['sha256']: continue
                key = row['sha256'], row['size_bytes']
                references = [value for _, value in sorted(self.references.get(name, {}).items()) if any(fingerprint == value['blob_sha256'] for fingerprint, _ in originals)]
                if name in self.private_vendor_inputs:
                    original, retention = self.private_vendor_inputs[name]
                    if original != row: raise ValueError('private vendor inspection input changed after verification')
                elif references:
                    if self.reference_contents[name] != row: raise ValueError('inspection source member changed after original-byte verification')
                    retention = references[0]
                elif key in originals: retention = {'kind': 'corresponding-source-blob', 'member': 'blobs/' + row['sha256']}
                elif key in artifacts: retention = {'kind': 'released-artifact', 'artifact': artifacts[key]}
                elif key in members: retention = {'kind': 'released-artifact-member', **members[key]}
                elif name.endswith('.json') and row['size_bytes'] <= 8 * 1024 ** 2:
                    body = stream.read()
                    if len(body) != row['size_bytes'] or hashlib.sha256(body).hexdigest() != row['sha256']:
                        retention = {'kind': 'unretained-local-input', 'reason': 'Inspection metadata was not captured before its family was removed.'}
                    elif retained_bytes + len(body) <= MAX_METADATA:
                        json.loads(body)
                        retained_bytes += len(body)
                        retention = {'kind': 'retained-json-metadata', 'base64': base64.b64encode(body).decode('ascii')}
                    else:
                        retention = {'kind': 'unretained-local-input', 'reason': 'Inspection metadata exceeds the retained report bound and needs a separately closed retained sidecar.'}
                else:
                    retention = {'kind': 'unretained-local-input', 'reason': 'No verified source-part or released-member reference; redistribution authority is not inferred.'}
                yield {**row, 'retention': retention}
            finally: stream.close()

    def _tools(self):
        tools = []
        for name, executable_name in sorted(self.tools.items()):
            file = Path(name)
            with file.open('rb') as stream: fingerprint = hashlib.file_digest(stream, 'sha256').hexdigest()
            tools.append({'name': executable_name, 'sha256': fingerprint, 'size_bytes': file.stat().st_size, 'distribution': 'nonredistributed-inspection-tool-prerequisite'})
        tools.sort(key=lambda row: (row['name'], row['sha256']))
        return tools

    def finish(self, source, discovery, required_materials, artifacts_input=()):
        inputs = list(self._inputs(source, discovery, required_materials, artifacts_input))
        tools = self._tools()
        return {'schema_version': 1, 'qualification': QUALIFICATION, 'source_inventory_sha256': source['sha256'], 'subjects': [{'id': row['id'], 'sha256': row['sha256']} for row in discovery['subjects']], 'inputs': inputs, 'tools': tools, 'unretained_inputs': [row['path'] for row in inputs if row['retention']['kind'] == 'unretained-local-input'], 'inventory_sha256': hashlib.sha256(canonical(inputs)).hexdigest()}

    def finish_compact(self, source, discovery, required_materials, artifacts_input=()):
        """Stream a canonical input digest, retaining only bounded JSON receipts.

        The digest binds each actual verified input, but no per-read catalog is
        generated or stored. Missing previously observed files require a real
        pre-cleanup checkpoint. Family recipes remain responsible for selecting
        and independently verifying the original bytes in a later replay.
        """
        subjects = [{'id': row['id'], 'sha256': row['sha256']} for row in discovery['subjects']]
        source_blobs = {(row['sha256'], row['size_bytes']) for row in required_materials}
        artifacts = {row['id']: row['sha256'] for row in subjects}
        members = {(subject['id'], row['path']): (row['sha256'], row['size_bytes']) for subject in discovery['subjects'] for row in subject['members'] if 'sha256' in row}
        digest = hashlib.sha256(b'['); unresolved = hashlib.sha256(b'[')
        count = 0; unretained = 0; metadata = []; retained_size = 0
        for row in self._inputs(source, discovery, required_materials, artifacts_input, strict_missing=True):
            missing, length = _verify_input(row, self.assets_root, source_blobs, artifacts, members, self.streamed_sources, self.observations)
            retained_size += length
            if retained_size > MAX_METADATA: raise ValueError('retained inspection metadata exceeds bound')
            if count: digest.update(b',')
            digest.update(canonical(row)); count += 1
            if row['retention']['kind'] == 'retained-json-metadata': metadata.append(row)
            if missing:
                if unretained: unresolved.update(b',')
                unresolved.update(canonical(row['path'])); unretained += 1
        digest.update(b']'); unresolved.update(b']')
        return {'schema_version': 2, 'qualification': COMPACT_QUALIFICATION, 'source_inventory_sha256': source['sha256'], 'subjects': subjects, 'input_count': count, 'inventory_sha256': digest.hexdigest(), 'metadata': metadata, 'tools': self._tools(), 'unretained_count': unretained, 'unretained_sha256': unresolved.hexdigest()}


def _verify_input(row, assets_root, source_blobs, artifacts, members, streamed_sources, observations):
    if set(row) != {'path', 'sha256', 'size_bytes', 'executable', 'retention'} or type(row['executable']) is not bool: raise ValueError('inspection input receipt is not closed')
    file = assets_root / row['path']; captured = observations.rows.get(row['path']) if observations is not None else None
    if not file.exists() and not file.is_symlink() and captured is not None:
        actual = captured['row']
        if any(actual.get(key) != row[key] for key in ('path', 'sha256', 'size_bytes', 'executable')): raise ValueError('inspection family observation differs')
        stream = io.BytesIO(captured['body'] if captured['body'] is not None else b'')
    elif not file.exists() and not file.is_symlink() and row['path'] in streamed_sources:
        actual = streamed_sources[row['path']]
        if any(actual.get(key) != row[key] for key in ('path', 'sha256', 'size_bytes', 'executable')) or row['retention'].get('kind') != 'corresponding-source-blob': raise ValueError('streamed source observation differs')
        stream = io.BytesIO()
    else: stream, actual = opened(assets_root, row)
    try:
        retention = row['retention']; kind = retention.get('kind'); retained_size = 0
        if kind == 'retained-json-metadata':
            body = base64.b64decode(retention['base64'], validate=True)
            if set(retention) != {'kind', 'base64'} or len(body) > 8 * 1024 ** 2 or stream.read() != body: raise ValueError('retained inspection metadata differs')
            json.loads(body); retained_size = len(body)
        elif kind == 'corresponding-source-blob':
            if retention != {'kind': kind, 'member': 'blobs/' + actual['sha256']} or (actual['sha256'], actual['size_bytes']) not in source_blobs: raise ValueError('inspection source reference is not a selected original source blob')
        elif kind == 'released-artifact':
            if set(retention) != {'kind', 'artifact'} or artifacts.get(retention['artifact']) != actual['sha256']: raise ValueError('inspection artifact reference differs from the released subject')
        elif kind == 'released-artifact-member':
            if set(retention) != {'kind', 'artifact', 'member'} or members.get((retention['artifact'], retention['member'])) != (actual['sha256'], actual['size_bytes']): raise ValueError('inspection artifact member reference differs from actual archive bytes')
            artifact_member(retention['artifact'], retention['member'])
        elif kind == 'corresponding-source-member':
            if set(retention) != {'kind', 'blob_sha256', 'member'} or not any(fingerprint == retention['blob_sha256'] for fingerprint, _ in source_blobs): raise ValueError('inspection member has no selected original source archive')
            safe(retention['member'])
            if captured is not None and not file.exists() and (canonical(retention) not in observations.recorder.references.get(row['path'], {}) or observations.recorder.reference_contents.get(row['path']) != actual): raise ValueError('inspection family source member was not verified against its original archive')
        elif kind in ('private-locked-cpython-input', 'private-locked-windows-perl-input'):
            if retention != private_vendor_reference(actual, retention.get('role')):
                raise ValueError('private vendor inspection receipt is invalid')
            if observations is not None and observations.recorder.private_vendor_inputs.get(row['path']) != (actual, retention):
                raise ValueError('private vendor inspection input was not authenticated by the replay')
        elif kind != 'unretained-local-input': raise ValueError('inspection input retention kind is unsupported')
        return kind == 'unretained-local-input', retained_size
    finally: stream.close()


def verify(catalog, assets_root, source, subjects, *, require_retained=True, required_materials=(), discovered_subjects=(), streamed_sources=None, observations=None):
    """Reopen real bytes; retained metadata is evidence, not a presence boolean."""
    if not isinstance(catalog, dict) or set(catalog) != {'schema_version', 'qualification', 'source_inventory_sha256', 'subjects', 'inputs', 'tools', 'unretained_inputs', 'inventory_sha256'} or catalog['schema_version'] != 1 or catalog['qualification'] != QUALIFICATION or catalog['source_inventory_sha256'] != source or catalog['subjects'] != subjects:
        raise ValueError('component replay inspection catalog has a foreign subject')
    rows = catalog['inputs']
    if not isinstance(rows, list) or len(rows) > MAX_FILES or catalog['inventory_sha256'] != hashlib.sha256(canonical(rows)).hexdigest(): raise ValueError('inspection input inventory differs')
    names = [safe(row['path']) for row in rows]
    if names != sorted(set(names)): raise ValueError('inspection input paths duplicate or differ from canonical order')
    source_blobs = {(row['sha256'], row['size_bytes']) for row in required_materials}
    artifacts = {row['id']: row['sha256'] for row in subjects}
    members = {(subject['id'], row['path']): (row['sha256'], row['size_bytes']) for subject in discovered_subjects for row in subject['members'] if 'sha256' in row}
    if observations is not None and (not isinstance(observations, _FamilyObservations) or observations.root != Path(assets_root).resolve()): raise ValueError('inspection family observations have a foreign input root')
    unretained = []; retained_size = 0; streamed_sources = {} if streamed_sources is None else streamed_sources
    for row in rows:
        missing, length = _verify_input(row, assets_root, source_blobs, artifacts, members, streamed_sources, observations)
        retained_size += length
        if retained_size > MAX_METADATA: raise ValueError('retained inspection metadata exceeds bound')
        if missing: unretained.append(row['path'])
    if unretained != catalog['unretained_inputs']: raise ValueError('inspection input unresolved list differs')
    if require_retained and unretained: raise ValueError('Unretained component replay inspection inputs: ' + ', '.join(unretained[:8]))
    for tool in catalog['tools']:
        if set(tool) != {'name', 'sha256', 'size_bytes', 'distribution'} or tool['distribution'] != 'nonredistributed-inspection-tool-prerequisite' or Path(tool['name']).name != tool['name']: raise ValueError('inspection tool prerequisite is malformed')
        name = shutil.which(tool['name'])
        if name is None: raise ValueError('required nonredistributed inspection tool is absent: ' + tool['name'])
        with Path(name).resolve().open('rb') as stream: fingerprint = hashlib.file_digest(stream, 'sha256').hexdigest()
        if fingerprint != tool['sha256'] or Path(name).stat().st_size != tool['size_bytes']: raise ValueError('required nonredistributed inspection tool differs: ' + tool['name'])
    return {'verified': True, 'inputs': len(rows), 'unretained': len(unretained)}


def verify_compact(report, assets_root, source, discovery, *, recorder, required_materials=(), artifacts_input=(), require_retained=True):
    """Recompute a compact report from real family observations and receipts."""
    if not isinstance(recorder, Recorder) or recorder.assets_root != Path(assets_root).resolve(): raise ValueError('inspection compact replay has a foreign recorder')
    actual = recorder.finish_compact(source, discovery, required_materials, artifacts_input)
    if not isinstance(report, dict) or canonical(actual) != canonical(report): raise ValueError('inspection compact replay differs from verified family observations')
    if require_retained and actual['unretained_count']: raise ValueError('Unretained component replay inspection inputs remain')
    # The legacy tool verifier also checks exact executable identities. No
    # input rows are serialized or reconstructed for this check.
    tools = {'schema_version': 1, 'qualification': QUALIFICATION, 'source_inventory_sha256': source['sha256'], 'subjects': actual['subjects'], 'inputs': [], 'tools': actual['tools'], 'unretained_inputs': [], 'inventory_sha256': hashlib.sha256(canonical([])).hexdigest()}
    verify(tools, Path(assets_root), source['sha256'], actual['subjects'])
    return {'verified': True, 'inputs': actual['input_count'], 'unretained': actual['unretained_count']}
