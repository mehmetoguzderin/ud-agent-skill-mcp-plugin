"""Reconstruct the finite authored worker receipts without executing image code."""
from __future__ import annotations
import hashlib
import importlib.util
import json
from pathlib import Path, PurePosixPath
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
CORE_NAMES = {'opt/ud-agent/input-manifest.json': 'input-manifest.json', 'opt/ud-agent/context/context.json': 'context/context.json', 'opt/ud-agent/perl/runtime.json': 'perl/{arch}/runtime.json', 'opt/ud-agent/perl/source-receipt.json': 'perl/{arch}/source-receipt.json', 'tmp/ud-agent-requirements.txt': 'requirements.txt'}


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, file)
    value = importlib.util.module_from_spec(spec)
    previous = sys.dont_write_bytecode
    try:
        sys.dont_write_bytecode = True
        spec.loader.exec_module(value)
    finally:
        sys.dont_write_bytecode = previous
    return value


shipped = load('worker_metadata_shipped', Path(__file__).with_name('collect-shipped-components.py'))


def digest(file):
    with file.open('rb') as stream: return hashlib.file_digest(stream, 'sha256').hexdigest()


def original_directory(root, name):
    shipped.inspector._paths.validate_path(name)
    value = root
    for part in name.split('/'):
        value /= part
        if value.is_symlink(): raise ValueError('worker metadata original context contains a link')
    if not value.is_dir(): raise ValueError('worker metadata original context is missing')
    return value


def reconstructed_core(source_root, assets_root, context, platform):
    """Use the candidate-owned original producer against explicit immutable inputs."""
    original_file = context / 'input-manifest.json'
    if original_file.is_symlink() or not original_file.is_file() or original_file.stat().st_size > 8 * 1024 ** 2: raise ValueError('worker input manifest is absent or oversized')
    original = json.loads(original_file.read_bytes())
    selected = original.get('build_platforms')
    if selected is not None and (not isinstance(selected, list) or platform not in selected or len(selected) != len(set(selected)) or not set(selected) <= {'linux/arm64', 'linux/amd64'}): raise ValueError('worker metadata build platform differs')
    core = load('worker_metadata_original_core', source_root / 'scripts/runtime/prepare-core-build.py')
    with tempfile.TemporaryDirectory(prefix='ud-worker-metadata-core-') as temporary:
        private = Path(temporary)
        overlay = private / 'source'
        overlay.mkdir()
        for name in ['workers', 'runtime', 'licenses', 'LICENSE', 'NOTICE', 'uv.lock']:
            target = source_root / name
            if not target.exists() or target.is_symlink(): raise ValueError('worker metadata source input is absent or linked')
            (overlay / name).symlink_to(target, target_is_directory=target.is_dir())
        (overlay / '.artifacts').symlink_to(assets_root / '.artifacts', target_is_directory=True)
        rebuilt = private / 'context'
        previous = sys.dont_write_bytecode
        try:
            sys.dont_write_bytecode = True
            expected = core.prepare(overlay, context / 'wheels', rebuilt, False, selected)
        finally:
            sys.dont_write_bytecode = previous
        if expected != original or (rebuilt / 'input-manifest.json').read_bytes() != original_file.read_bytes(): raise ValueError('worker input manifest does not reconstruct from exact source and original inputs')
        return {name: (rebuilt / relative.format(arch=platform.split('/')[1])).read_bytes() for name, relative in CORE_NAMES.items()}


def render_form(filesystem, generator, font_derivations=None):
    """The original manifest's fixed inventory algorithm over opaque image files."""
    available = {}
    selected = set()
    for name, (kind, _) in filesystem.inventory.items():
        if name.startswith('usr/share/fonts/') and kind == 'file':
            base = PurePosixPath(name).name
            if base in available: raise ValueError('worker render font basename is ambiguous')
            available[base] = name
    fonts = [available[name] for name in generator.FONT_NAMES if name in available]
    if len(fonts) != len(generator.FONT_NAMES) or 'NotoSansCJK-Regular.ttc' not in available: raise ValueError('worker render font selection is incomplete')
    _, collection = filesystem.resolve(available['NotoSansCJK-Regular.ttc'])
    generated_name = 'opt/ud-agent/render/fonts/NotoSansCJK-Regular.otf'
    _, generated = filesystem.resolve(generated_name)
    if generator.standalone_font(collection.read_bytes()) != generated.read_bytes(): raise ValueError('worker render generated font differs from its original collection')
    if font_derivations is not None:
        font_derivations.append({'input': {'image_path': available['NotoSansCJK-Regular.ttc'], 'sha256': digest(collection), 'size_bytes': collection.stat().st_size}, 'content': {'image_path': generated_name, 'sha256': digest(generated), 'size_bytes': generated.stat().st_size}})
    fonts.append(generated_name)
    if sum(filesystem.resolve(name)[1].stat().st_size for name in fonts) > 64 * 1024 ** 2: raise ValueError('worker render selected fonts exceed bound')
    selected.update(fonts)
    for prefix in ['usr/lib/chromium', 'usr/share/fonts', 'usr/share/fontconfig/conf.avail', 'etc/fonts/fonts.conf', 'opt/ud-agent/render/dependency-lock.json']:
        if prefix not in filesystem.inventory: raise ValueError('worker render asset prefix is absent')
        for name, (kind, _) in filesystem.inventory.items():
            if name == prefix or name.startswith(prefix + '/'):
                if kind == 'file': selected.add(name)
                elif kind == 'link':
                    resolved, file = filesystem.resolve(name, allow_directory=True)
                    if file is not None: selected.add(resolved)
    executable = 'usr/lib/chromium/chromium'
    filesystem.resolve(executable)
    selected.add(executable)
    if not 1 <= len(selected) <= 10000: raise ValueError('worker render file selection exceeds bound')
    files = []
    total = 0
    for name in sorted(selected, key=lambda value: PurePosixPath(value).parts):
        _, file = filesystem.resolve(name)
        size = file.stat().st_size
        total += size
        if size > 512 * 1024 ** 2 or total > 2 * 1024 ** 3: raise ValueError('worker render closure exceeds bound')
        files.append({'path': '/' + name, 'sha256': digest(file), 'size_bytes': size})
    return (json.dumps({'schema_version': 1, 'executable': '/' + executable, 'files': files, 'fonts': ['/' + name for name in fonts]}, sort_keys=True, indent=2) + '\n').encode()


def generated_font_bindings(derivations, font_sources, platform, image_digest, recipes, wanted):
    """Inherit only the authenticated source/notice facts of the exact TTC
    whose bytes were used by render_form's standalone-font replay above."""
    bindings = []
    for derivation in derivations:
        content = derivation['content']
        if (content['sha256'], content['size_bytes']) not in wanted: continue
        original = derivation['input']
        origins = [row for row in font_sources if row['content'].get('platform') == platform and all(row['content'].get(key) == original[key] for key in ('image_path', 'sha256', 'size_bytes'))]
        if not origins or any(not row.get('sources') or not row.get('notices') or not row.get('required_materials') for row in origins): raise ValueError('generated render font lacks the exact original TTC source and notice binding')
        bindings.append({'content': content, 'sources': [*[source for row in origins for source in row['sources']], {'form': 'exact-standalone-font-zero-derived-from-authenticated-original-collection', 'input': {**original, 'platform': platform}, 'image_digest': image_digest, 'source_generators': recipes}], 'notices': [notice for row in origins for notice in row['notices']], 'required_materials': [material for row in origins for material in row['required_materials']]})
    return bindings


def derive(source_root, assets_root, runtime_root, discovery, wanted, recorder=None, *, contexts, font_sources=()):
    raw = (runtime_root / 'runtime/runtime.lock.json').read_bytes()
    if hashlib.sha256(raw).hexdigest() != digest(source_root / 'runtime/runtime.lock.json'): raise ValueError('worker metadata runtime differs from its source')
    runtime = json.loads(raw)
    if runtime.get('state') != 'frozen' or not isinstance(contexts, dict) or not set(contexts) <= {'linux/arm64', 'linux/amd64'}: raise ValueError('worker metadata requires frozen explicit platform contexts')
    observed = {(row.get('platform'), row.get('image_path'), row.get('sha256'), row.get('size_bytes')) for subject in discovery['subjects'] for row in subject['members'] if row.get('image_path')}
    notices = [{'path': name, 'sha256': digest(source_root / name), 'size_bytes': (source_root / name).stat().st_size} for name in ['LICENSE', 'NOTICE']]
    recipes = [{'path': name, 'sha256': digest(source_root / name)} for name in ['scripts/runtime/prepare-core-build.py', 'scripts/runtime/private_perl.py', 'scripts/runtime/render_manifest.py', 'runtime/Containerfile.core', 'runtime/Containerfile.render']]
    generator = load('worker_metadata_original_render', source_root / 'scripts/runtime/render_manifest.py')
    bindings = []
    for platform, context_name in sorted(contexts.items()):
        if platform not in runtime['packs']['core']['images']: continue
        context = original_directory(assets_root, context_name)
        contents = reconstructed_core(source_root, assets_root, context, platform)
        for name, body in contents.items():
            content = {'sha256': hashlib.sha256(body).hexdigest(), 'size_bytes': len(body)}
            if (content['sha256'], content['size_bytes']) not in wanted: continue
            if (platform, name, content['sha256'], content['size_bytes']) not in observed: raise ValueError('reconstructed worker metadata differs from actual image member')
            bindings.append({'content': content, 'sources': [{'form': 'exact-authored-readable-build-metadata', 'image_path': name, 'platform': platform, 'source_generators': recipes, 'original_context_manifest_sha256': digest(context / 'input-manifest.json')}], 'notices': notices, 'required_materials': []})
        pack = runtime['packs']['render']
        if platform not in pack['images']: continue
        font_derivations = []
        with tempfile.TemporaryDirectory(prefix='ud-worker-metadata-render-') as temporary:
            filesystem = shipped.oci.verified_filesystem(runtime_root, pack, platform, Path(temporary) / 'opaque', len(pack['images']) == 1)
            body = render_form(filesystem, generator, font_derivations)
        bindings.extend(generated_font_bindings(font_derivations, font_sources, platform, pack['images'][platform]['digest'], recipes, wanted))
        content = {'sha256': hashlib.sha256(body).hexdigest(), 'size_bytes': len(body)}
        if (content['sha256'], content['size_bytes']) in wanted:
            if (platform, 'opt/ud-agent/render/manifest.json', content['sha256'], content['size_bytes']) not in observed: raise ValueError('reconstructed worker render manifest differs from actual image member')
            bindings.append({'content': content, 'sources': [{'form': 'exact-authored-readable-render-inventory', 'platform': platform, 'image_digest': pack['images'][platform]['digest'], 'source_generators': recipes}], 'notices': notices, 'required_materials': []})
    return {'schema_version': 1, 'qualification': 'fixed-authored-worker-metadata-reconstruction-no-target-execution', 'status': 'passed', 'target_execution': False, 'bindings': bindings, 'generator_sha256': digest(Path(__file__))}
