"""Keep complete mutmut control data while compiling one active body per run.

This is private test instrumentation. Inactive bodies/closures/code introspection
are deliberately unavailable; their exact definitions remain in control data.
No generated source is executed by this module.
"""
from __future__ import annotations

import ast
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import tokenize
from difflib import unified_diff

VERSION = 'ud-python-inert-projection-1'
GUARD_NAME = '_ud_inert_mutation_exit_125_6a7fb94c30e84119'
MANIFEST = Path('control/python-projection/manifest.json')
CONTROL = Path('control/python-projection/files')
BASELINES = Path('control/python-projection/baselines')
CONTEXT = '.ud-runtime-projection.json'
DEFINITION_REPRESENTATION = 'mutmut-control-spans-v1'
_REAL_EXIT = os._exit
_REAL_GETEUID = getattr(os, 'geteuid', None)
_RUNTIME_CACHE = {}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def _runtime_uid():
    if _REAL_GETEUID is None:
        raise RuntimeError('runtime projection requires the native Linux OCI identity API')
    return _REAL_GETEUID()


def safe_path(value):
    if (not isinstance(value, str) or '\\' in value or ':' in value
            or any(part in ('', '.', '..') for part in value.split('/'))
            or not value.endswith('.py') or not value.startswith(('src/ud_agent/', 'scripts/'))):
        raise ValueError('projection module path is outside fixed Python source roots')
    return value


def _numbered(name):
    prefix, separator, suffix = name.rpartition('__mutmut_')
    return bool(separator and prefix and suffix.isascii() and suffix.isdigit() and int(suffix) > 0)


def _tokens(source):
    try:
        yield from tokenize.generate_tokens(io.StringIO(source).readline)
    except tokenize.TokenError as error:
        raise SyntaxError('invalid control token stream: ' + str(error)) from error


def _spans(source, spans):
    if not isinstance(spans, dict):
        raise ValueError('projection requires an exact function span mapping')
    lines = source.splitlines(keepends=True)
    entries = []
    for name, bounds in spans.items():
        if (not isinstance(name, str) or not name.isidentifier()
                or not (name.endswith('__mutmut_orig') or _numbered(name))
                or not isinstance(bounds, (list, tuple)) or len(bounds) != 2
                or any(type(value) is not int for value in bounds)):
            raise ValueError('projection function index is malformed')
        start, end = bounds
        if not 1 <= start <= end <= len(lines):
            raise ValueError('projection function span exceeds control bytes')
        entries.append((start, end, name))
    entries.sort()
    previous = 0
    for start, end, name in entries:
        if start <= previous:
            raise ValueError('projection function spans overlap')
        previous = end
    # The index and metadata must not be able to co-omit a real emitted
    # function. Tokenization streams raw control text without constructing its
    # enormous full-module AST, and ignores apparent defs inside string data.
    declared = {}
    expect_name = False
    for token in _tokens(source):
        if token.type == tokenize.NAME and token.string == GUARD_NAME:
            raise ValueError('control source collides with the private SDK guard namespace')
        if expect_name:
            expect_name = False
            if token.type != tokenize.NAME:
                raise ValueError('control function declaration is malformed')
            if token.string.endswith('__mutmut_orig') or _numbered(token.string):
                if token.string in declared:
                    raise ValueError('control repeats a generated function definition')
                declared[token.string] = token.start[0]
        if token.type == tokenize.NAME and token.string == 'def':
            expect_name = True
    if set(declared) != set(spans):
        raise ValueError('function index omits or invents an emitted control function')
    for name, line in declared.items():
        start, end = spans[name]
        if not start <= line <= end:
            raise ValueError('function index points at a different emitted declaration')
    return lines, entries


def _function(text, name, filename):
    definition = re.search(r'(?m)^([ \t]*)(?:async[ \t]+)?def[ \t]+' + re.escape(name) + r'(?=[(\[ \t])', text)
    if definition is None:
        raise ValueError('projection span has no exact function definition')
    # Never dedent source: that also rewrites continuation lines *inside* a
    # string literal. A synthetic class provides the existing method indent
    # while retaining every source token, literal and byte unchanged.
    offset = 1 if definition.group(1) else 0
    parsed = 'class _ud_projection_parse_context:\n' + text if offset else text
    tree = ast.parse(parsed, filename=filename)
    bodies = tree.body
    if offset:
        if len(bodies) != 1 or not isinstance(bodies[0], ast.ClassDef):
            raise ValueError('projection method escaped its parse context')
        bodies = bodies[0].body
    if len(bodies) != 1 or not isinstance(bodies[0], (ast.FunctionDef, ast.AsyncFunctionDef)) or bodies[0].name != name:
        raise ValueError('projection span does not contain its exact indexed function')
    node = bodies[0]
    if any(not isinstance(item, ast.Name) or item.id not in ('staticmethod', 'classmethod') for item in node.decorator_list) or len(node.decorator_list) > 1:
        raise ValueError('indexed generated function has an unsupported upstream decorator')
    return parsed, node, offset


def _generator(node):
    pending = list(node.body)
    while pending:
        item = pending.pop()
        if isinstance(item, (ast.Yield, ast.YieldFrom)):
            return True
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        pending.extend(ast.iter_child_nodes(item))
    return False


def _header(node):
    return (type(node).__name__, node.name, ast.dump(node.args),
            ast.dump(node.returns) if node.returns else None,
            tuple(ast.dump(item) for item in node.decorator_list),
            tuple(ast.dump(item) for item in getattr(node, 'type_params', ())),
            node.type_comment)


def _stub(text, name, filename):
    parsed, node, offset = _function(text, name, filename)
    original_lines = text.splitlines(keepends=True)
    doc = node.body[0] if isinstance(node.body[0], ast.Expr) and isinstance(node.body[0].value, ast.Constant) and isinstance(node.body[0].value.value, str) else None
    if doc is not None and len(node.body) == 1:
        line, column, delimiter = doc.end_lineno - offset, doc.end_col_offset, '; '
    else:
        first = node.body[1] if doc is not None else node.body[0]
        line, column, delimiter = first.lineno - offset, first.col_offset, ''
    # AST columns count UTF-8 bytes, while Python slices count characters.
    column = len(original_lines[line - 1].encode('utf-8')[:column].decode('utf-8'))
    prefix = ''.join(original_lines[:line - 1]) + original_lines[line - 1][:column]
    guard = delimiter + GUARD_NAME + '(125)'
    if _generator(node):
        guard += '; (yield None) if False else None'
    remaining_lines = text.count('\n') - prefix.count('\n')
    newline = '\r\n' if '\r\n' in text else '\n'
    result = prefix + guard + newline * remaining_lines
    if result.count('\n') != text.count('\n'):
        raise ValueError('inactive projection changed source line identities')
    _, projected, _ = _function(result, name, filename)
    if (_header(projected) != _header(node) or ast.get_docstring(projected, clean=False) != ast.get_docstring(node, clean=False)
            or _generator(projected) != _generator(node)):
        raise ValueError('inactive projection changed a function header or protocol flag')
    return result


def project_source(source, spans, active_name=None, filename='<mutmut-control>'):
    """Derive exact runtime bytes as data; never execute or import the result."""
    if not isinstance(source, str):
        raise ValueError('control source must be text')
    lines, entries = _spans(source, spans)
    numbered = {name for _, _, name in entries if _numbered(name)}
    if active_name is not None and active_name not in numbered:
        raise ValueError('active generated function is not in the full control inventory')
    result, position = [], 0
    for start, end, name in entries:
        result.extend(lines[position:start - 1])
        text = ''.join(lines[start - 1:end])
        # Validate indexed originals too, but retain their exact bytes.
        _function(text, name, filename)
        result.append(_stub(text, name, filename) if _numbered(name) and name != active_name else text)
        position = end
    result.extend(lines[position:])
    return ''.join(result)


def validate_control(source, spans, filename='<mutmut-control>'):
    """Validate every complete function and the full baseline, without exec."""
    lines, entries = _spans(source, spans)
    for start, end, name in entries:
        text, node, _ = _function(''.join(lines[start - 1:end]), name, filename)
        # Full bytecode compilation catches restrictions that ast.parse alone
        # accepts. The code object is discarded and never executed.
        compile(text, filename, 'exec', dont_inherit=True, optimize=0)
    baseline = project_source(source, spans, None, filename)
    compile(baseline, filename, 'exec', dont_inherit=True, optimize=0)
    return {'version': VERSION, 'functions': len(entries),
            'numbered_functions': sum(_numbered(name) for _, _, name in entries),
            'control_sha256': digest(source.encode()),
            'baseline_sha256': digest(baseline.encode()), 'baseline_size_bytes': len(baseline.encode())}


def install_guard(trampoline, context_required=False):
    """Bind the captured real exit before any generated application executes."""
    previous = trampoline.wrap_in_trampoline
    real_exit = _REAL_EXIT
    def wrapper(*args, **kwargs):
        decorate = previous(*args, **kwargs)
        def bind(function):
            if context_required:
                try:
                    module = _bind_runtime_context(function, trampoline)
                    mutants = args[0] if args else kwargs['mutants_dict']
                    for candidate in [function, *mutants.values()]:
                        candidate.__module__ = module
                except BaseException:
                    real_exit(125)
            globals_ = function.__globals__
            if GUARD_NAME in globals_ and globals_[GUARD_NAME] is not real_exit:
                raise RuntimeError('application replaced the private inactive-body guard')
            globals_[GUARD_NAME] = real_exit
            return decorate(function)
        return bind
    trampoline.wrap_in_trampoline = wrapper


def _bind_runtime_context(function, trampoline):
    """Every interpreter binds the same issued context, including python -I."""
    file = Path(function.__code__.co_filename)
    if not file.is_absolute():
        raise ValueError('generated module has no absolute runtime source identity')
    file = file.resolve(strict=True)
    roots = [parent for parent in file.parents if parent.name == 'mutants']
    if len(roots) != 1:
        raise ValueError('generated module is outside its issued runtime namespace')
    runtime = roots[0]
    context_file = runtime / CONTEXT
    context_info, module_info = context_file.lstat(), file.lstat()
    def identity(info):
        return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_nlink,
                info.st_size, info.st_mtime_ns, info.st_ctime_ns)
    cache_key = (_runtime_uid(), str(runtime), identity(context_info), str(file), identity(module_info))
    if cache_key in _RUNTIME_CACHE:
        return _RUNTIME_CACHE[cache_key]
    parents = list(file.parents)
    for parent in [runtime, *parents[:parents.index(runtime)]]:
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('runtime namespace is writable by a test identity')
    context_bytes = _ordinary(context_file, 64 * 1024 ** 2, True)
    context = json.loads(context_bytes)
    uid = _runtime_uid()
    if (context.get('schema_version') != 1 or context.get('version') != VERSION
            or type(context.get('uid')) is not int or uid == 0 or context['uid'] != uid
            or context.get('projection_sequence') != uid
            or context.get('helper_sha256') != digest(Path(__file__).read_bytes())):
        raise ValueError('runtime context belongs to another helper or test identity')
    mapped = safe_path(file.relative_to(runtime).as_posix())
    rows = [row for row in context['files'] if row['path'] == mapped]
    if len(rows) != 1:
        raise ValueError('runtime module is absent from the issued projection')
    content = _ordinary(file, owner=True)
    if len(content) != rows[0]['size_bytes'] or digest(content) != rows[0]['projected_sha256']:
        raise ValueError('runtime module differs from its exact issued projection')
    mode, key = context['mode'], context['active_key']
    if mode not in ('collection', 'baseline', 'stats', 'forced-fail', 'active') or (mode == 'active') != isinstance(key, str):
        raise ValueError('runtime context has an invalid activation')
    if mode != 'active' and key is not None:
        raise ValueError('non-mutant runtime context supplied an activation')
    tag = (uid, digest(context_bytes))
    if getattr(trampoline, '_ud_projection_context', None) != tag:
        expected = {'collection': 'list_all_tests', 'baseline': '', 'stats': 'stats', 'forced-fail': 'fail', 'active': key}[mode]
        allowed = {'collection': ('', 'mutant_generation', 'list_all_tests'), 'baseline': ('',),
                   'stats': ('stats',), 'forced-fail': ('fail',), 'active': (key,)}[mode]
        current = os.environ.get('MUTANT_UNDER_TEST')
        if current is None:
            # A new interpreter has no process-local fallback. Only restore the
            # root-issued key; never derive an activation from application data.
            trampoline.set_mutant_under_test(expected)
        elif current not in allowed:
            raise ValueError('explicit activation conflicts with issued projection')
        if mode == 'stats':
            _initialize_stats_config(runtime.parent)
        _latch_activation(mode, key)
        trampoline._ud_projection_context = tag
    from mutmut.utils.format_utils import get_mutant_name
    canonical_module = get_mutant_name(Path(mapped), 'x_bound__mutmut_orig').rsplit('.', 1)[0]
    _RUNTIME_CACHE[cache_key] = canonical_module
    return canonical_module


def _initialize_stats_config(work):
    """A fresh exec reads the same actual upstream config as the root runner."""
    from mutmut import configuration
    if configuration._config is not None:
        return
    for path, directory in ((work, True), (work / 'pyproject.toml', False)):
        info = path.lstat()
        ordinary = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
        if not ordinary or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('stats configuration is not protected root-owned input')
    _ordinary(work / 'pyproject.toml', 64 * 1024 ** 2)
    from mutmut.utils.file_utils import change_cwd
    # Config resolves mutation paths relative to cwd. The UID-owned job remains
    # the caller's cwd after this one actual pinned configuration load.
    with change_cwd(work):
        configuration.config()


def _latch_activation(mode, active_key):
    from mutmut.mutation import trampoline
    getter = trampoline.get_mutant_under_test
    allowed = {'collection': frozenset(('', 'mutant_generation', 'list_all_tests')),
               'baseline': frozenset(('',)), 'stats': frozenset(('stats',)),
               'forced-fail': frozenset(('fail',)), 'active': frozenset((active_key,))}[mode]
    if getter() not in allowed:
        raise ValueError('trusted runner activation differs from admitted runtime projection')
    real_exit = _REAL_EXIT
    def checked():
        current = getter()
        if current not in allowed:
            real_exit(125)
        return current
    trampoline.get_mutant_under_test = checked


def _ordinary(file, maximum=1024 ** 3, owner=False):
    selected = Path(file).lstat()
    if not stat.S_ISREG(selected.st_mode):
        raise ValueError('projection input is not an ordinary file')
    fd = os.open(file, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_CLOEXEC', 0))
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        if ((selected.st_dev, selected.st_ino) != (before.st_dev, before.st_ino)
                or not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > maximum or (owner and (before.st_uid != 0 or before.st_mode & 0o222))):
            raise ValueError('projection input is not bounded ordinary root-owned data')
        data = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
        if len(data) != before.st_size or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise ValueError('projection input changed during read')
    return data


def definition_reference(mapped, definition):
    reference = {'kind': DEFINITION_REPRESENTATION, 'module': safe_path(mapped),
                 'location': definition['location'], 'generation_repairs': definition['generation_repairs']}
    if 'operator_repair' in definition:
        reference['operator_repair'] = definition['operator_repair']
    return reference


class ControlDefinitionReader:
    """Resolve one compact definition as data, retaining at most one module."""
    def __init__(self, state, plan):
        self.state, self.plan = Path(state), plan
        if plan.get('definition_representation') != DEFINITION_REPRESENTATION:
            raise ValueError('unsupported compact Python definition representation')
        runtime = plan.get('runtime_representation', {})
        if runtime.get('version') != VERSION or runtime.get('manifest_path') != MANIFEST.as_posix():
            raise ValueError('compact Python definition has no fixed CONTROL manifest')
        content = _ordinary(self.state / MANIFEST, 64 * 1024 ** 2)
        if digest(content) != runtime.get('manifest_sha256'):
            raise ValueError('compact Python CONTROL manifest changed')
        manifest = json.loads(content)
        if (manifest.get('schema_version') != 1 or manifest.get('version') != VERSION
                or manifest.get('source_tree_sha256') != plan.get('source_tree_sha256')
                or manifest.get('helper_sha256') != digest(Path(__file__).read_bytes())
                or not isinstance(manifest.get('files'), list)):
            raise ValueError('compact Python CONTROL manifest differs from its source/helper')
        self.rows, self.ids = {}, {}
        for row in manifest['files']:
            name = safe_path(row['path'])
            if name in self.rows:
                raise ValueError('compact Python CONTROL repeats a module')
            for field, expected in [('control', CONTROL / name), ('spans', CONTROL / (name + '.spans'))]:
                record = row.get(field)
                if (not isinstance(record, dict) or set(record) != {'path', 'sha256', 'size_bytes'}
                        or record['path'] != expected.as_posix() or not re.fullmatch('[a-f0-9]{64}', record.get('sha256', ''))
                        or type(record.get('size_bytes')) is not int or not 0 <= record['size_bytes'] <= 1024 ** 3):
                    raise ValueError('compact Python CONTROL descriptor is invalid')
            self.rows[name] = row
            for item in row['mutants']:
                if item['id'] in self.ids:
                    raise ValueError('compact Python CONTROL repeats a raw identity')
                self.ids[item['id']] = (name, item['name'])
        self.module = None
        self.lines = self.spans = None

    def resolve(self, item):
        from mutmut.mutation.diff_apply import generated_function_names
        from mutmut.utils.format_utils import orig_function_and_class_names_from_key
        if not isinstance(item, dict) or 'definition' in item or set(item) != {'id', 'file', 'source_sha256', 'definition_sha256', 'definition_ref'}:
            raise ValueError('compact Python definition is mixed or malformed')
        reference = item['definition_ref']
        if (not isinstance(reference, dict) or set(reference) not in (
                {'kind', 'module', 'location', 'generation_repairs'},
                {'kind', 'module', 'location', 'generation_repairs', 'operator_repair'})
                or reference.get('kind') != DEFINITION_REPRESENTATION):
            raise ValueError('compact Python definition reference is invalid')
        mapped = safe_path(reference['module'])
        expected_file = mapped.replace('src/ud_agent/', 'workers/ud/src/ud_agent/', 1) if mapped.startswith('src/ud_agent/') else mapped
        row = self.rows.get(mapped)
        if row is None or item['file'] != expected_file or item['source_sha256'] != row['source_sha256']:
            raise ValueError('compact Python definition has a different source identity')
        original_name, replacement_name = generated_function_names(item['id'])
        if self.ids.get(item['id']) != (mapped, replacement_name):
            raise ValueError('compact Python definition is not an exact raw CONTROL identity')
        if self.module != mapped:
            values = []
            for field in ('control', 'spans'):
                record = row[field]
                parent = self.state
                for part in Path(record['path']).parts[:-1]:
                    parent /= part
                    if parent.is_symlink():
                        raise ValueError('compact Python CONTROL cannot traverse links')
                content = _ordinary(self.state / record['path'])
                if len(content) != record['size_bytes'] or digest(content) != record['sha256']:
                    raise ValueError('compact Python CONTROL/index bytes changed')
                values.append(content)
            index = json.loads(values[1])
            if index.get('version') != 1 or not isinstance(index.get('spans'), dict):
                raise ValueError('compact Python CONTROL index is invalid')
            self.lines, self.spans = values[0].decode().splitlines(keepends=True), index['spans']
            self.module = mapped
        actual_name, _ = orig_function_and_class_names_from_key(item['id'])
        def function(name):
            bounds = self.spans.get(name)
            if not isinstance(bounds, list) or len(bounds) != 2 or any(type(value) is not int for value in bounds) or not 1 <= bounds[0] <= bounds[1] <= len(self.lines):
                raise ValueError('compact Python definition span is invalid')
            text = ''.join(self.lines[bounds[0] - 1:bounds[1]])
            changed, count = re.subn(r'(?m)^(\s*(?:async\s+)?def\s+)' + re.escape(name) + r'(?=\()', lambda match: match.group(1) + actual_name, text, count=1)
            if count != 1:
                raise ValueError('compact Python definition has a different function declaration')
            return changed
        original, replacement = function(original_name), function(replacement_name)
        definition = {'tool': 'mutmut', 'version': '3.8.1', 'generation_profile': self.plan['generation_profile'],
                      'generation_repairs': reference['generation_repairs'], 'file': item['file'],
                      'location': reference['location'], 'original_function': original, 'replacement_function': replacement,
                      'diff': '\n'.join(unified_diff(original.splitlines(), replacement.splitlines(), fromfile=item['file'], tofile=item['file'], lineterm=''))}
        if 'operator_repair' in reference:
            evidence = reference['operator_repair']
            upstream = evidence['upstream_definition']
            change = evidence['exact_change']
            if (digest(canonical(upstream).encode()) != evidence['upstream_definition_sha256']
                    or any(upstream[field] != definition[field] for field in ('tool', 'version', 'generation_profile', 'generation_repairs', 'file', 'location', 'original_function'))
                    or upstream['original_function'] != original or upstream['replacement_function'].count(change['before']) != 1
                    or upstream['replacement_function'].replace(change['before'], change['after'], 1) != replacement):
                raise ValueError('compact Python typed repair differs from retained CONTROL')
            definition['operator_repair'] = evidence
        if digest(canonical(definition).encode()) != item['definition_sha256']:
            raise ValueError('compact Python canonical full definition hash differs')
        return {key: value for key, value in item.items() if key != 'definition_ref'} | {'definition': definition}


def _write(file, data, mode=0o444):
    file.parent.mkdir(parents=True, exist_ok=True)
    temporary = file.with_name(file.name + '.projection-' + str(os.getpid()))
    with temporary.open('xb') as stream:
        stream.write(data)
    temporary.chmod(mode)
    os.replace(temporary, file)


def retain_control(state, mapped, source, spans, index_bytes=None):
    """Keep the complete corrected source and original upstream span index."""
    safe_path(mapped)
    data = source.encode()
    index = index_bytes if index_bytes is not None else (json.dumps({'version': 1, 'spans': spans}) + '\n').encode()
    _write(state / CONTROL / mapped, data)
    _write(state / CONTROL / (mapped + '.spans'), index)
    return data, index


def finalize_control(work, state, source_tree_sha256, source_hashes):
    """Finalize complete control authority before any runtime test collection."""
    from mutmut.mutation.diff_apply import generated_function_names
    rows = []
    for mapped, source_sha256 in sorted(source_hashes.items()):
        safe_path(mapped)
        generated = work / 'mutants' / mapped
        index_bytes = _ordinary(Path(str(generated) + '.spans'))
        index = json.loads(index_bytes)
        if index.get('version') != 1:
            raise ValueError('unsupported upstream generated index')
        source_bytes = _ordinary(generated)
        validation = validate_control(source_bytes.decode(), index['spans'], mapped)
        control_bytes, index_bytes = retain_control(state, mapped, source_bytes.decode(), index['spans'], index_bytes)
        metadata_path = Path('generation-metadata') / (mapped + '.meta')
        metadata_bytes = _ordinary(state / metadata_path)
        metadata = json.loads(metadata_bytes)
        if any(code is not None for code in metadata['exit_code_by_key'].values()):
            raise ValueError('control metadata contains prior outcomes')
        mutants = []
        for key in sorted(metadata['exit_code_by_key']):
            original, name = generated_function_names(key)
            if original not in index['spans'] or name not in index['spans'] or not _numbered(name):
                raise ValueError('control metadata omits an exact generated function')
            mutants.append({'id': key, 'name': name})
        if {item['name'] for item in mutants} != {name for name in index['spans'] if _numbered(name)}:
            raise ValueError('control metadata does not cover the full generated operator union')
        baseline = project_source(source_bytes.decode(), index['spans'], None, mapped).encode()
        _write(state / BASELINES / mapped, baseline)
        _write(generated, baseline)
        rows.append({'path': mapped, 'source_sha256': source_sha256,
                     'control': {'path': (CONTROL / mapped).as_posix(), 'sha256': digest(control_bytes), 'size_bytes': len(control_bytes)},
                     'spans': {'path': (CONTROL / (mapped + '.spans')).as_posix(), 'sha256': digest(index_bytes), 'size_bytes': len(index_bytes)},
                     'generation_metadata': {'path': metadata_path.as_posix(), 'sha256': digest(metadata_bytes), 'size_bytes': len(metadata_bytes)},
                     'mutants': mutants, 'baseline': {'sha256': digest(baseline), 'size_bytes': len(baseline)}})
    manifest = {'schema_version': 1, 'version': VERSION, 'helper_sha256': digest(Path(__file__).read_bytes()),
                'source_tree_sha256': source_tree_sha256, 'files': rows}
    _write(state / MANIFEST, (canonical(manifest) + '\n').encode())
    return manifest


def prepare_runtime(work, state, mode, active_key=None):
    """Materialize one serial test invocation; caller owns quiescence/locking."""
    if os.geteuid() != 0 or mode not in ('collection', 'baseline', 'stats', 'forced-fail', 'active') or (mode == 'active') != isinstance(active_key, str):
        raise ValueError('projection requires root admission and an exact runtime mode/key')
    if mode != 'active' and active_key is not None:
        raise ValueError('non-mutant projection cannot supply an active key')
    manifest_bytes = _ordinary(state / MANIFEST, 64 * 1024 ** 2, True)
    manifest = json.loads(manifest_bytes)
    if manifest.get('schema_version') != 1 or manifest.get('version') != VERSION or manifest.get('helper_sha256') != digest(Path(__file__).read_bytes()):
        raise ValueError('runtime projection helper/control authority differs')
    active_rows = [(row['path'], item['name']) for row in manifest['files'] for item in row['mutants'] if item['id'] == active_key]
    if mode == 'active' and len(active_rows) != 1:
        raise ValueError('runtime requested an unknown or ambiguous mutation activation')
    active = dict(active_rows)
    witness = []
    for row in manifest['files']:
        mapped = safe_path(row['path'])
        for key, expected in [('control', CONTROL / mapped), ('spans', CONTROL / (mapped + '.spans'))]:
            receipt = row[key]
            if receipt['path'] != expected.as_posix():
                raise ValueError('control receipt points outside its fixed path')
        source = _ordinary(state / row['control']['path'], owner=True)
        index = _ordinary(state / row['spans']['path'], 64 * 1024 ** 2, True)
        for content, receipt in [(source, row['control']), (index, row['spans'])]:
            if len(content) != receipt['size_bytes'] or digest(content) != receipt['sha256']:
                raise ValueError('runtime control bytes differ from admitted metadata')
        name = active.get(mapped)
        if name is None:
            projected = _ordinary(state / BASELINES / mapped, owner=True)
            if digest(projected) != row['baseline']['sha256'] or len(projected) != row['baseline']['size_bytes']:
                raise ValueError('runtime baseline projection changed')
        else:
            projected = project_source(source.decode(), json.loads(index)['spans'], name, mapped).encode()
            compile(projected, mapped, 'exec', dont_inherit=True, optimize=0)
        _write(work / 'mutants' / mapped, projected)
        witness.append({'path': mapped, 'control_sha256': row['control']['sha256'], 'spans_sha256': row['spans']['sha256'],
                        'projected_sha256': digest(projected), 'size_bytes': len(projected), 'active_name': name})
    _latch_activation(mode, active_key)
    return {'schema_version': 1, 'version': VERSION, 'mode': mode, 'active_key': active_key,
            'manifest_sha256': digest(manifest_bytes), 'files': witness, 'guard_exit_code': 125}


def issue_runtime_context(work, state, uid, witness):
    """Issue immutable exec-child authority inside the existing runtime tree."""
    if os.geteuid() != 0 or type(uid) is not int or not 100000 <= uid < 2 ** 31:
        raise ValueError('runtime context requires the fresh admitted UID')
    if witness.get('schema_version') != 1 or witness.get('version') != VERSION or witness.get('projection_sequence') != uid:
        raise ValueError('runtime witness and issued test identity differ')
    manifest = _ordinary(state / MANIFEST, 64 * 1024 ** 2, True)
    if digest(manifest) != witness['manifest_sha256']:
        raise ValueError('runtime manifest changed before context issuance')
    declared = json.loads(manifest)
    if {row['path'] for row in declared['files']} != {row['path'] for row in witness['files']} or len(declared['files']) != len(witness['files']):
        raise ValueError('runtime witness omits a control module')
    for row in witness['files']:
        content = _ordinary(work / 'mutants' / safe_path(row['path']), owner=True)
        if len(content) != row['size_bytes'] or digest(content) != row['projected_sha256']:
            raise ValueError('runtime bytes changed before context issuance')
    context = {'schema_version': 1, 'version': VERSION, 'uid': uid, 'projection_sequence': uid,
               'helper_sha256': digest(Path(__file__).read_bytes()), 'manifest_sha256': witness['manifest_sha256'],
               'mode': witness['mode'], 'active_key': witness['active_key'],
               'projection_sha256': digest(canonical(witness).encode()), 'files': witness['files']}
    data = (canonical(context) + '\n').encode()
    file = work / 'mutants' / CONTEXT
    info = file.parent.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise ValueError('runtime context namespace is not owned and immutable to tests')
    _write(file, data)
    return {'path': file.relative_to(state).as_posix(), 'sha256': digest(data), 'size_bytes': len(data)}
