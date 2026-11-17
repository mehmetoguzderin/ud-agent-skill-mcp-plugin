#!/usr/bin/env python3
"""Build native OCI workers offline with exact per-architecture transports."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import platform as host_platform
import subprocess
import uuid

ROOT = Path(__file__).resolve().parents[2]


def run(command, *, log=None, timeout=900):
    result = subprocess.run(command, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout, check=False)
    if log is not None:
        log.write_bytes(result.stdout)
    if result.returncode:
        raise RuntimeError('worker build command failed: ' + ' '.join(command[:3]) + '\n' + result.stdout.decode(errors='replace')[-4000:])
    return result.stdout


def load(name):
    spec = importlib.util.spec_from_file_location('ud_worker_build_' + name.replace('-', '_'), ROOT / 'scripts/runtime' / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def build(output, download=False):
    if output.exists() or output.is_symlink():
        raise ValueError('worker build output must be new')
    host = os.environ.get('DOCKER_HOST')
    if host and not host.startswith('unix:///'):
        raise ValueError('worker build supports only a local Unix Docker endpoint')
    if not host:
        context = json.loads(run(['docker', 'context', 'inspect']))
        if len(context) != 1 or not context[0].get('Endpoints', {}).get('docker', {}).get('Host', '').startswith('unix:///'):
            raise ValueError('worker build requires a verified local Docker endpoint')
    info = json.loads(run(['docker', 'info', '--format', '{{json .}}']))
    architecture = {'aarch64': 'arm64', 'arm64': 'arm64', 'x86_64': 'amd64', 'amd64': 'amd64'}.get(info.get('Architecture'))
    if info.get('OSType') != 'linux' or architecture is None:
        raise ValueError('worker build requires an available native Linux OCI provider')
    host_architecture = {'aarch64': 'arm64', 'arm64': 'arm64', 'x86_64': 'amd64', 'AMD64': 'amd64'}.get(host_platform.machine())
    if host_architecture != architecture:
        raise ValueError('foreign-architecture worker execution is deferred; use a native builder for that architecture')
    platform = 'linux/' + architecture
    base = re.search(r'^FROM\s+(\S+)', (ROOT / 'runtime/Containerfile.core').read_text(), re.M).group(1)
    inspected = subprocess.run(['docker', 'image', 'inspect', base], cwd=ROOT, capture_output=True, check=False)
    if inspected.returncode:
        if not download:
            raise ValueError('pinned base image is unavailable offline; acquire it explicitly with --download')
        run(['docker', 'image', 'pull', '--platform', platform, base], timeout=600)
    output.mkdir(parents=True, mode=0o700)
    (output / 'INCOMPLETE').write_text('Native worker build has not completed.\n')
    owner = uuid.uuid4().hex
    tags = {name: 'localhost/ud-agent-' + name + '-candidate:' + owner + '-' + architecture for name in ('core', 'render')}
    core = load('prepare-core-build')
    render = load('prepare-render-build')
    exporter = load('export-workers')
    core_context, render_context = output / 'core-context', output / 'render-context'
    private_perl = ROOT / '.artifacts/native-perl' / ('linux-' + {'amd64': 'x64', 'arm64': 'arm64'}[architecture] + '-source')
    if download and not private_perl.with_name(private_perl.name + '-receipt.json').exists():
        # The private Perl closure is built from its locked public sources in
        # the pinned builder image; no release-pipeline pack is required.
        run(['python3', str(ROOT / 'scripts/runtime/build-linux-perl.py'), '--platform', platform, '--download', '--output', str(private_perl)], log=output / 'private-perl-build.log', timeout=7800)
    core.prepare(ROOT, ROOT / '.artifacts/wheels', core_context, download, [platform])
    if download:
        run(['python3', str(ROOT / 'scripts/runtime/fetch_perl_inputs.py'), '--render', '--download'], log=output / 'render-inputs.log', timeout=1800)
    render.prepare(ROOT, render_context)
    for name, context in [('core', core_context), ('render', render_context)]:
        command = ['docker', 'build', '--platform', platform, '--pull=false', '--network', 'none', '--provenance=false', '--tag', tags[name], '--file', str(context / 'Containerfile')]
        if name == 'core':
            command += ['--build-arg', 'INPUT_MANIFEST_PATH=' + core.content_addressed_manifest(core_context)]
        if name == 'render':
            command += ['--build-arg', 'CORE_IMAGE=' + tags['core']]
        # BuildKit reuses a transferred context by its directory name and
        # skips members whose size/mode/mtime match. Context mtimes are
        # normalized, so a same-size rebuilt file (such as private Perl
        # scripts) from another checkout's 'core-context' could be served
        # stale. A build-unique context name prevents that reuse.
        unique = output / ('.' + name + '-context-' + owner)
        unique.symlink_to(context.name, target_is_directory=True)
        try:
            command.append(str(unique))
            run(command, log=output / (name + '-build.log'), timeout=1800)
        finally:
            unique.unlink()
    receipt = exporter.export(ROOT, output / 'transports', {name: {platform: tag} for name, tag in tags.items()}, [platform])
    verifier = load('verify-worker-contents')
    content_evidence = {name: verifier.verify(ROOT / pack['index_transport']['path'], pack['images'][platform]['digest'], core_context, name == 'render') for name, pack in receipt['packs'].items()}
    if any(value.get('status') != 'passed' for value in content_evidence.values()):
        raise ValueError('built worker contents did not match their source context')
    (output / 'content-evidence.json').write_text(json.dumps(content_evidence, sort_keys=True, indent=2) + '\n')
    result = {'schema_version': 1, 'qualification': 'native-build-unaccepted', 'platform': platform, 'provider': 'local-docker', 'emulated': False, 'tags': tags, 'transports': str(output / 'transports/worker-receipt.json'), 'packs': {name: value['index_digest'] for name, value in receipt['packs'].items()}, 'deferred_platforms': sorted({'linux/arm64', 'linux/amd64'} - {platform}), 'limitations': ['Worker build/content evidence is separate from runtime-provider acceptance and final frozen release certification.']}
    (output / 'build-receipt.json').write_text(json.dumps(result, sort_keys=True, indent=2) + '\n')
    (output / 'INCOMPLETE').unlink()
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--download', action='store_true', help='explicitly acquire missing pinned build inputs; no publication')
    args = parser.parse_args()
    print(json.dumps(build(args.output.resolve(), args.download)))


if __name__ == '__main__':
    main()
