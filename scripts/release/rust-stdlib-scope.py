"""Derive conservative normal/build std dependencies for the six shipped targets.

All feature branches are retained. Unknown target predicates retain edges too;
only predicates proven false on every supported target and dev-only edges are
excluded. This module reads Cargo metadata as data and runs no build scripts.
"""
from __future__ import annotations
import hashlib
import os
import stat
import io
import json
import posixpath
import re
import tarfile
import tomllib

TARGETS = {
    'aarch64-apple-darwin': {'target_arch': 'aarch64', 'target_os': 'macos', 'target_env': '', 'target_vendor': 'apple', 'target_family': 'unix'},
    'x86_64-apple-darwin': {'target_arch': 'x86_64', 'target_os': 'macos', 'target_env': '', 'target_vendor': 'apple', 'target_family': 'unix'},
    'aarch64-unknown-linux-gnu': {'target_arch': 'aarch64', 'target_os': 'linux', 'target_env': 'gnu', 'target_vendor': 'unknown', 'target_family': 'unix'},
    'x86_64-unknown-linux-gnu': {'target_arch': 'x86_64', 'target_os': 'linux', 'target_env': 'gnu', 'target_vendor': 'unknown', 'target_family': 'unix'},
    'aarch64-pc-windows-msvc': {'target_arch': 'aarch64', 'target_os': 'windows', 'target_env': 'msvc', 'target_vendor': 'pc', 'target_family': 'windows'},
    'x86_64-pc-windows-msvc': {'target_arch': 'x86_64', 'target_os': 'windows', 'target_env': 'msvc', 'target_vendor': 'pc', 'target_family': 'windows'},
}
OPEN_WINDOWS_TARGETS = {
    f'{architecture}-pc-windows-gnullvm': {'target_arch': architecture, 'target_os': 'windows', 'target_env': 'gnu', 'target_abi': 'llvm', 'target_vendor': 'pc', 'target_family': 'windows'}
    for architecture in ('aarch64', 'x86_64')
}


def cfg(expression, profile):
    tokens = re.findall(r'"(?:[^"\\]|\\.)*"|[A-Za-z_][A-Za-z_0-9]*|[(),=]|\S', expression); index = 0
    def value():
        nonlocal index
        if index >= len(tokens): raise ValueError('truncated Rust Cargo target predicate')
        name = tokens[index]; index += 1
        if not re.fullmatch('[A-Za-z_][A-Za-z_0-9]*', name): raise ValueError('unsupported Rust Cargo target predicate syntax')
        if index < len(tokens) and tokens[index] == '(':
            index += 1; values = []
            while index < len(tokens) and tokens[index] != ')':
                values.append(value())
                if index < len(tokens) and tokens[index] == ',': index += 1
                elif index >= len(tokens) or tokens[index] != ')': raise ValueError('invalid Rust Cargo target predicate separator')
            if index >= len(tokens): raise ValueError('unclosed Rust Cargo target predicate')
            index += 1
            if name == 'cfg' and len(values) == 1: return values[0]
            if name == 'not' and len(values) == 1: return None if values[0] is None else not values[0]
            if name == 'all': return False if False in values else None if None in values else True
            if name == 'any': return True if True in values else None if None in values else False
            return None
        if index < len(tokens) and tokens[index] == '=':
            index += 1
            if index >= len(tokens) or not tokens[index].startswith('"'): raise ValueError('invalid Rust Cargo target predicate value')
            expected = json.loads(tokens[index]); index += 1
            values = {**profile, 'target_pointer_width': '64', 'target_endian': 'little'}
            return values[name] == expected if name in values else None
        if name in ('unix', 'windows'): return profile['target_family'] == name
        return None
    result = value()
    if index != len(tokens): raise ValueError('trailing Rust Cargo target predicate tokens')
    return result


def applies(condition, target, profile):
    return cfg(condition, profile) is not False if condition.startswith('cfg(') else condition == target


def metadata(archive, expected_sha256=None):
    result = {}
    descriptor = os.open(archive, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
    with os.fdopen(descriptor, 'rb') as stream:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size > 512 * 1024**2: raise ValueError('original Rust metadata source is special or oversized')
        if expected_sha256 is not None and hashlib.file_digest(stream, 'sha256').hexdigest() != expected_sha256: raise ValueError('original Rust std crate differs from signed dependency checksum')
        stream.seek(0)
        with tarfile.open(fileobj=stream, mode='r:*') as source:
            for entry in source:
                if entry.name.endswith(('/Cargo.toml', '/Cargo.lock')):
                    if entry.name in result or not entry.isfile() or entry.size > 4 * 1024 ** 2: raise ValueError('Rust source manifest is duplicate, special or oversized')
                    with source.extractfile(entry) as body: raw = body.read(entry.size + 1)
                    if len(raw) != entry.size: raise ValueError('Rust source manifest is truncated')
                    result[entry.name] = (tomllib.loads(raw.decode()), hashlib.sha256(raw).hexdigest())
        after = os.fstat(descriptor)
        if any(getattr(before, field) != getattr(after, field) for field in ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')): raise ValueError('original Rust metadata bytes changed during same-FD inspection')
    return result


def derive(archive, original_crates, *, extra_targets=None):
    targets = {**TARGETS, **(extra_targets or {})}
    sources = metadata(archive); locks = [name for name in sources if name.endswith('/rust/library/Cargo.lock')]
    if len(locks) != 1: raise ValueError('unique actual Rust std source lock required')
    base = locks[0].removesuffix('Cargo.lock'); lock = sources[locks[0]][0]; packages = {(row['name'], row['version']): row for row in lock['package']}
    if len(packages) != len(lock['package']): raise ValueError('Rust std lock package identity is duplicated')
    manifests = {}; external = {}
    for key, package in packages.items():
        if 'source' in package:
            external[key] = package
    local = {}
    for file, (manifest, fingerprint) in sources.items():
        if not file.startswith(base) or not file.endswith('/Cargo.toml') or 'package' not in manifest: continue
        package = manifest['package']; name = package.get('name'); matches = [key for key in packages if key[0] == name and 'source' not in packages[key]]
        if len(matches) == 1: local[file] = matches[0]; manifests[matches[0]] = (file, manifest, fingerprint, sources)
    roots = [key for key in packages if key[0] == 'std' and key in manifests]
    if len(roots) != 1: raise ValueError('original Rust std library manifest is missing or ambiguous')
    reached = set(); pending = list(roots); reasons = []
    while pending:
        key = pending.pop()
        if key in reached: continue
        if key in external and key not in manifests:
            if key not in original_crates: raise ValueError('original Rust std crate metadata is absent: ' + '@'.join(key))
            source = metadata(original_crates[key], external[key]['checksum']); candidates = [name for name in source if name.count('/') == 1 and name.endswith('/Cargo.toml')]
            if len(candidates) != 1: raise ValueError('original Rust std crate root manifest is ambiguous')
            file = candidates[0]; manifests[key] = (file, source[file][0], source[file][1], source)
        reached.add(key); file, manifest, fingerprint, source = manifests[key]
        groups = [(None, 'dependencies', manifest.get('dependencies', {})), (None, 'build-dependencies', manifest.get('build-dependencies', {})), (None, 'dev-dependencies', manifest.get('dev-dependencies', {}))]
        for condition, section in manifest.get('target', {}).items():
            for kind in ('dependencies', 'build-dependencies', 'dev-dependencies'): groups.append((condition, kind, section.get(kind, {})))
        for condition, kind, dependencies in groups:
            supported = list(targets) if condition is None else [target for target, profile in targets.items() if applies(condition, target, profile)]
            for alias, definition in dependencies.items():
                definition = {'version': definition} if isinstance(definition, str) else definition
                if not isinstance(definition, dict): raise ValueError('unsupported original Rust std dependency definition')
                name = definition.get('package', alias); edge = {'consumer': {'name': key[0], 'version': key[1]}, 'dependency': name, 'kind': kind, 'condition': condition, 'source_manifest': file, 'manifest_sha256': fingerprint}
                if kind == 'dev-dependencies' or not supported:
                    reasons.append({**edge, 'reason': 'dev-only-edge' if kind == 'dev-dependencies' else 'foreign-target-only-edge'}); continue
                path = definition.get('path')
                if path and key not in external:
                    target_file = posixpath.normpath(posixpath.join(posixpath.dirname(file), path, 'Cargo.toml'))
                    choices = [local[target_file]] if target_file in local else []
                else:
                    allowed = packages[key].get('dependencies', []); choices = [other for other in packages if other[0] == name and any(value == name or value.startswith(name + ' ' + other[1]) for value in allowed)]
                if not choices and definition.get('optional') is True:
                    reasons.append({**edge, 'reason': 'optional-edge-absent-from-original-resolved-std-lock'}); continue
                if len(choices) != 1 or choices[0] not in manifests and choices[0] not in external: raise ValueError('supported Rust std dependency has no unique exact original source: ' + key[0] + ' -> ' + name)
                pending.append(choices[0])
    selected = sorted(key for key in reached if key in external)
    reason = 'unreachable-from-std-normal-or-build-dependencies-for-frozen-targets' if extra_targets else 'unreachable-from-std-normal-or-build-dependencies-for-six-targets'
    return {'targets': list(targets), 'feature_policy': 'conservative-union-of-all-normal-and-build-feature-branches; unknown-cfg-retains-edge', 'selected_registry_packages': [{'name': key[0], 'version': key[1], 'sha256': external[key]['checksum']} for key in selected], 'unselected_registry_packages': [{'name': key[0], 'version': key[1], 'sha256': external[key]['checksum'], 'reason': reason} for key in sorted(set(external) - set(selected))], 'excluded_edges': reasons}
