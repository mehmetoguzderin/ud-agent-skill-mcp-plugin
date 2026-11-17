#!/usr/bin/env python3
"""Reconcile complete lock-derived npm/Cargo source and original-notice recipes."""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path, PurePosixPath
import tarfile


def module(name, file):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(file)); value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value); return value
packages = module('ud_package_recipe_sources', 'collect-package-sources.py')
materials = module('ud_package_recipe_materials', 'source-bundle.py')


def sha(file):
    with file.open('rb') as source: return hashlib.file_digest(source, 'sha256').hexdigest()


def archive_notices(file):
    records = []; seen = set(); total = 0
    with tarfile.open(file, 'r:*') as archive:
        for member in archive:
            name = member.name.removeprefix('./').rstrip('/')
            if not name or name.startswith('/') or '\\' in name or any(part in ('', '.', '..') for part in name.split('/')) or name in seen or len(seen) >= 200000: raise ValueError('package source archive path is unsafe or duplicate')
            seen.add(name); total += member.size
            if member.size > 512 * 1024 ** 2 or total > 4 * 1024 ** 3: raise ValueError('package source archive exceeds bounds')
            if member.isfile() and packages.NOTICE.fullmatch(name.rsplit('/', 1)[-1]):
                if member.size > 8 * 1024 ** 2: raise ValueError('package notice exceeds bound')
                body = archive.extractfile(member).read(member.size + 1)
                if len(body) != member.size: raise ValueError('package notice is truncated')
                records.append({'source_path': name, 'sha256': hashlib.sha256(body).hexdigest(), 'size_bytes': len(body)})
    return records


def npm_input_identities(expected, inputs):
    """Derive npm scope from actual compiler/bundle member paths, not a list of packages."""
    identities = set()
    for content in inputs:
        name = materials.safe(content['path'])
        choices = [(consumer, item) for item in expected if item['family'] == 'npm' for consumer in item['consumers'] if name.startswith(consumer + '/')]
        if not choices: raise ValueError('actual npm program input has no original locked package: ' + name)
        _, item = max(choices, key=lambda value: len(value[0]))
        identities.add((item['family'], item['name'], item['version']))
    return identities


def iter_collection_replay_sources(receipt_bytes, collection, *, receipt_path):
    """Yield selected manifest members at their receipt-relative input paths.

    The collection must come from the independently verified source manifest;
    this checks that every selected path also appears in the original receipt.
    The caller verifies the bytes via SourceParts before staging or reading them.
    """
    receipt_path = materials.safe(receipt_path)
    if not isinstance(receipt_bytes, bytes) or len(receipt_bytes) > 8 * 1024 ** 2 or not isinstance(collection, dict):
        raise ValueError('bounded original source collection receipt required')
    if (collection.get('receipt_sha256') != hashlib.sha256(receipt_bytes).hexdigest()
            or collection.get('receipt_size_bytes') != len(receipt_bytes)
            or not isinstance(collection.get('members'), list) or len(collection['members']) > 100000):
        raise ValueError('receipt differs from the verified source collection')
    try: inventory = json.loads(receipt_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError) as error: raise ValueError('source collection receipt is not valid JSON') from error
    if not isinstance(inventory, dict) or inventory.get('qualification') != collection.get('qualification'):
        raise ValueError('source collection qualification differs')
    selected = {}
    for row in materials.selected(inventory):
        name = materials.safe(row.get('path')); fingerprint = row.get('sha256'); size = row.get('size_bytes', row.get('size'))
        if not isinstance(fingerprint, str) or not materials.SHA.fullmatch(fingerprint) or type(size) is not int or not 0 <= size <= 8 * 1024 ** 3:
            raise ValueError('source collection input identity is invalid')
        identity = (fingerprint, size)
        if name in selected and selected[name] != identity: raise ValueError('source collection receipt path is ambiguous')
        selected[name] = identity
    observed = {}
    for item in collection['members']:
        if not isinstance(item, dict): raise ValueError('source collection member is malformed')
        name = materials.safe(item.get('original_path')); fingerprint = item.get('sha256'); size = item.get('size_bytes')
        if (not isinstance(fingerprint, str) or not materials.SHA.fullmatch(fingerprint)
                or type(size) is not int or size < 0 or item.get('path') != 'blobs/' + fingerprint
                or selected.get(name) != (fingerprint, size)):
            raise ValueError('source collection member differs from its receipt')
        if name in observed:
            if observed[name] != (fingerprint, size): raise ValueError('source collection member path is ambiguous')
            continue
        observed[name] = (fingerprint, size)
    for name, (fingerprint, size) in sorted(observed.items()):
        yield {'path': materials.safe(str(PurePosixPath(receipt_path).parent / name)), 'blob_sha256': fingerprint, 'blob_size_bytes': size}


class NpmReplaySources:
    """Resolve locked package members from a verified source collection in memory.

    The caller must authenticate the original source blob and its lock SRI and
    each tar member, including rejecting duplicate member names. These outputs
    are unverified mappings, not evidence that archive bytes were checked.
    This index is transient; it is not a serialized inspection-input catalog.
    """
    def __init__(self, root, source_inventory, receipt_bytes, collection, *, receipt_path):
        root = Path(root)
        receipt_path = materials.safe(receipt_path)
        if not isinstance(receipt_bytes, bytes) or len(receipt_bytes) > 8 * 1024 ** 2:
            raise ValueError('bounded original package receipt bytes are required')
        if (not isinstance(collection, dict) or collection.get('id') != 'package-sources'
                or collection.get('qualification') != 'complete-locked-npm-cargo-source-and-notice-subinventory'
                or collection.get('receipt_sha256') != hashlib.sha256(receipt_bytes).hexdigest()
                or collection.get('receipt_size_bytes') != len(receipt_bytes)
                or not isinstance(collection.get('members'), list)):
            raise ValueError('package receipt differs from the verified source collection')
        try:
            inventory = json.loads(receipt_bytes)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError('package receipt is not valid JSON') from error
        if (not isinstance(inventory, dict) or inventory.get('schema_version') != 1
                or inventory.get('qualification') != collection['qualification'] or inventory.get('status') != 'passed'
                or not isinstance(inventory.get('files'), list)):
            raise ValueError('complete package source inventory required')

        if not isinstance(source_inventory, dict) or not isinstance(source_inventory.get('files'), list):
            raise ValueError('protected source inventory is required')
        protected = {}
        for row in source_inventory['files']:
            if not isinstance(row, dict) or not isinstance(row.get('path'), str) or row['path'] in protected:
                raise ValueError('protected source inventory is invalid or duplicated')
            protected[row['path']] = row
        lock_names = ['package-lock.json', 'Cargo.lock', 'scripts/quality/rust-assertion-parser/Cargo.lock']
        def check_locks():
            result = {}
            for name in lock_names:
                item = protected.get(name)
                if not item or type(item.get('size')) is not int or item['size'] < 0:
                    raise ValueError('package source lock is outside protected source: ' + name)
                stream, _, actual = materials.opened(root, {'path': name, 'sha256': item.get('sha256'), 'size_bytes': item.get('size')})
                stream.close(); result[str((root / name).resolve())] = actual['sha256']
            return result
        hashes = check_locks()
        expected, observed = packages.plan(root)
        if observed != hashes or check_locks() != hashes:
            raise ValueError('package source locks changed during replay mapping')

        members = {}
        for item in collection['members']:
            if not isinstance(item, dict): raise ValueError('package collection member is malformed')
            name = materials.safe(item.get('original_path'))
            fingerprint, size = item.get('sha256'), item.get('size_bytes')
            if (not isinstance(fingerprint, str) or not materials.SHA.fullmatch(fingerprint)
                    or type(size) is not int or not 0 <= size <= 8 * 1024 ** 3
                    or item.get('path') != 'blobs/' + fingerprint):
                raise ValueError('package collection member identity is invalid')
            identity = (fingerprint, size)
            if name in members and members[name] != identity: raise ValueError('package collection path is ambiguous')
            members[name] = identity

        actual = {}
        for row in inventory['files']:
            if not isinstance(row, dict): raise ValueError('package source row is malformed')
            identity = (row.get('family'), row.get('name'), row.get('version'))
            if identity in actual: raise ValueError('source package identity duplicated')
            actual[identity] = row
        locked = {(row['family'], row['name'], row['version']): row for row in expected}
        consumers, notices = {}, {}
        for identity, item in locked.items():
            row = actual.get(identity)
            if row is None: raise ValueError('lock-required source archive omitted: ' + str(identity))
            if row.get('url') != item['url']: raise ValueError('package source publisher differs from its lock')
            original = materials.safe(row.get('path')); fingerprint, size = row.get('sha256'), row.get('size_bytes')
            if (not isinstance(fingerprint, str) or not materials.SHA.fullmatch(fingerprint)
                    or type(size) is not int or not 0 <= size <= 8 * 1024 ** 3):
                raise ValueError('package source archive identity is invalid')
            retained = members.get(original)
            if retained is None: continue  # This locked package was not selected for the shipped candidate.
            if retained != (fingerprint, size): raise ValueError('package source archive differs from its collection')
            if item['family'] == 'cargo' and fingerprint != item['sha256']: raise ValueError('Cargo source checksum differs from exact lock')
            base = {'blob_sha256': fingerprint, 'blob_size_bytes': size}
            if item['family'] == 'npm':
                if not item['integrities']: raise ValueError('npm source lacks lock integrity')
                for raw in item['consumers']:
                    consumer = materials.safe(raw)
                    if not consumer.startswith('node_modules/') or consumer in consumers:
                        raise ValueError('locked npm consumer is ambiguous or invalid')
                    consumers[consumer] = {'consumer': consumer, 'name': item['name'], 'version': item['version'], **base, 'integrities': item['integrities']}
            for notice in row.get('notices', []):
                if not isinstance(notice, dict): raise ValueError('package original notice is malformed')
                relative = materials.safe(notice.get('path')); member = materials.safe(notice.get('source_path'))
                name = materials.safe(str(PurePosixPath(receipt_path).parent / relative))
                sha256, length = notice.get('sha256'), notice.get('size_bytes')
                if not isinstance(sha256, str) or not materials.SHA.fullmatch(sha256) or type(length) is not int or not 0 <= length <= 8 * 1024 ** 2:
                    raise ValueError('package original notice identity is invalid')
                candidate = {'path': name, **base, 'member': member, 'sha256': sha256, 'size_bytes': length,
                             'integrities': item.get('integrities', [])}
                if name in notices:
                    previous = notices[name][0]
                    if (previous['sha256'], previous['size_bytes']) != (sha256, length): raise ValueError('package original notice path is ambiguous')
                    if candidate not in notices[name]: notices[name].append(candidate)
                else:
                    notices[name] = [candidate]
        self.consumers = tuple(consumers[name] for name in sorted(consumers))
        self.notices = tuple(candidate for name in sorted(notices) for candidate in sorted(
            notices[name], key=lambda row: (row['blob_sha256'], row['member'], repr(row['integrities']))))
        self._consumers = consumers

    def resolve(self, path):
        name = materials.safe(path)
        choices = [consumer for consumer in self._consumers if name.startswith(consumer + '/')]
        if not choices: raise ValueError('actual npm program input has no retained locked package: ' + name)
        consumer = max(choices, key=len)
        row = self._consumers[consumer]
        return {'path': name, 'blob_sha256': row['blob_sha256'], 'blob_size_bytes': row['blob_size_bytes'],
                'member': materials.safe('package/' + name[len(consumer) + 1:]), 'integrities': row['integrities']}


def derive_npm_inputs(root, source_file, inputs, additional_cargo=()):
    expected, _ = packages.plan(root, additional_cargo)
    return derive(root, source_file, additional_cargo, required_identities=npm_input_identities(expected, inputs))


def cargo_consumer_identity(root, file):
    file = Path(file).resolve(); root = root.resolve()
    return file.relative_to(root).as_posix() if file.is_relative_to(root) else 'original-lock-sha256:' + sha(file)


def derive(root, source_file, additional_cargo=(), *, required_identities=None, required_cargo_consumers=None):
    expected, locks = packages.plan(root, additional_cargo); inventory = json.loads(source_file.read_bytes())
    if required_identities is not None and required_cargo_consumers is not None: raise ValueError('ambiguous package source selection')
    if required_cargo_consumers is not None:
        consumers = {str(Path(file).resolve()) for file in required_cargo_consumers}
        if not consumers <= locks.keys(): raise ValueError('selected Cargo consumer is not an original source lock')
        required_identities = {(item['family'], item['name'], item['version']) for item in expected if item['family'] == 'cargo' and consumers.intersection(item['consumers'])}
    if required_identities is not None and not set(required_identities) <= {(item['family'], item['name'], item['version']) for item in expected}: raise ValueError('selected package is outside the original source locks')
    if inventory.get('schema_version') != 1 or inventory.get('qualification') != 'complete-locked-npm-cargo-source-and-notice-subinventory' or inventory.get('status') != 'passed': raise ValueError('complete package source inventory required')
    actual = {}
    for row in inventory['files']:
        identity = row['family'], row['name'], row['version']
        if identity in actual: raise ValueError('source package identity duplicated')
        actual[identity] = row
    bindings = []
    for item in expected:
        identity = item['family'], item['name'], item['version']; row = actual.get(identity)
        if row is None: raise ValueError('lock-required source archive omitted: ' + str(identity))
        if row.get('url') != item['url']: raise ValueError('package source publisher differs from its lock')
        # All original lock/receipt metadata remains authoritative. Only
        # archives used by the independently derived shipped consumer scope
        # become replay byte inputs; developer-only packages are not shipped.
        if required_identities is not None and identity not in required_identities: continue
        stream, _, record = materials.opened(source_file.parent, row)
        try:
            if item['family'] == 'cargo':
                if row['sha256'] != item['sha256']: raise ValueError('Cargo source checksum differs from exact lock')
            else:
                if not item['integrities']: raise ValueError('npm package lacks strong integrity')
                for integrity in item['integrities']:
                    stream.seek(0)
                    if hashlib.file_digest(stream, integrity['algorithm']).hexdigest() != integrity['hex']: raise ValueError('npm source archive differs from exact lock integrity')
        finally: stream.close()
        original_notices = []
        observed_notices = archive_notices(source_file.parent / row['path'])
        if observed_notices != [{key: notice[key] for key in ('source_path', 'sha256', 'size_bytes')} for notice in row.get('notices', [])]: raise ValueError('package original notice inventory is omitted or changed')
        for notice in row.get('notices', []):
            stream, _, content = materials.opened(source_file.parent, notice); stream.close(); original_notices.append({**content, 'source_path': notice['source_path']})
        # The original distribution archive also retains upstream metadata and
        # all embedded notices. This does not infer a new SPDX conclusion.
        consumers = [cargo_consumer_identity(root, file) for file in item['consumers']] if item['family'] == 'cargo' else item['consumers']
        bindings.append({'family': item['family'], 'name': item['name'], 'version': item['version'], 'consumers': consumers, 'source': record, 'license_declared': item.get('license_declared', row.get('license_declared')), 'notices': original_notices})
    if any(packages.acquisition.digest(Path(file)) != fingerprint for file, fingerprint in locks.items()): raise ValueError('dependency locks changed during source binding')
    return {'schema_version': 1, 'qualification': 'derived-npm-cargo-source-recipe-license-bindings', 'status': 'passed', 'complete_component_coverage': True, 'complete_product_coverage': False, 'target_execution': False, 'bindings': bindings, 'source_collections': [{'sha256': sha(source_file), 'size_bytes': source_file.stat().st_size}], 'build_recipes': [{'path': str(Path(file).relative_to(root)) if Path(file).is_relative_to(root) else str(file), 'sha256': fingerprint, 'size_bytes': Path(file).stat().st_size} for file, fingerprint in locks.items()], 'generator_sha256': sha(Path(__file__)), 'scope': 'All original lock entries are reconciled; opened source bytes are restricted to the actual program inputs or original Cargo consumers selected by the fixed replay adapter.' if required_identities is not None else 'All actual current lock entries, including build-time dependencies. Distribution archives are retained exactly; prebuilt development-tool tarballs are not asserted to be their upstream corresponding source.'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('--root', type=Path, required=True); parser.add_argument('--sources', type=Path, required=True); parser.add_argument('--cargo-lock', action='append', type=Path, default=[]); parser.add_argument('--output', type=Path, required=True); args = parser.parse_args()
    if args.output.exists(): raise ValueError('new package source binding output required')
    result = derive(args.root.resolve(), args.sources, args.cargo_lock); args.output.write_text(json.dumps(result, indent=2) + '\n'); print(json.dumps({'status': result['status'], 'components': len(result['bindings'])}))
