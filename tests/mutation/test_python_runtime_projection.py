"""Original data-only projection contracts; emitted programs never run on host."""
import ast
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import types
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / 'scripts/quality/python-runtime-projection.py'
spec = importlib.util.spec_from_file_location('ud_projection_original_tests', HELPER)
projection = importlib.util.module_from_spec(spec)
spec.loader.exec_module(projection)


def index(source):
    result = {}
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and '__mutmut_' in node.name:
            result[node.name] = [min([node.lineno, *[item.lineno for item in node.decorator_list]]), node.end_lineno]
    return result


def functions(source):
    return {node.name: node for node in ast.walk(ast.parse(source))
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}


def codes(source):
    # Compilation is data-only. Never execute or import this code object.
    pending = [compile(source, 'authored-projection-fixture', 'exec', dont_inherit=True, optimize=0)]
    result = {}
    while pending:
        code = pending.pop()
        result[code.co_name] = code
        pending.extend(value for value in code.co_consts if isinstance(value, types.CodeType))
    return result


class PythonRuntimeProjectionTests(unittest.TestCase):
    def test_data_only_helper_import_does_not_require_the_linux_identity_api(self):
        with mock.patch.object(projection.os, 'geteuid', None, create=True):
            other_spec = importlib.util.spec_from_file_location('ud_original_projection_without_unix_identity', HELPER)
            other = importlib.util.module_from_spec(other_spec)
            other_spec.loader.exec_module(other)
        self.assertEqual(other.project_source('value = 1\n', {}), 'value = 1\n')
        with self.assertRaisesRegex(RuntimeError, 'native Linux OCI identity API'):
            other._runtime_uid()

    def test_full_control_and_active_body_are_exact_and_inactive_header_docstring_and_lines_survive(self):
        source = '''# authored control data
def wrapper(value):
    return value
def x_f__mutmut_orig(value=3):
    """public doc"""
    return value + 1
def x_f__mutmut_1(value=3):
    """public doc"""
    return value - 1
def x_f__mutmut_2(value=3):
    """public doc"""
    return value * 1
dispatch = {'_mutmut_orig': x_f__mutmut_orig, 'one': x_f__mutmut_1, 'two': x_f__mutmut_2}
'''
        spans = index(source)
        actual = projection.project_source(source, spans, 'x_f__mutmut_2', 'scripts/authored.py')
        lines, projected = source.splitlines(keepends=True), actual.splitlines(keepends=True)
        self.assertEqual(len(projected), len(lines))
        start, end = spans['x_f__mutmut_1']
        self.assertEqual(projected[:start - 1] + projected[end:], lines[:start - 1] + lines[end:])
        original, rewritten = functions(source), functions(actual)
        self.assertEqual(ast.dump(rewritten['x_f__mutmut_2']), ast.dump(original['x_f__mutmut_2']))
        inactive = rewritten['x_f__mutmut_1']
        self.assertEqual(inactive.name, 'x_f__mutmut_1')
        self.assertEqual(ast.get_docstring(inactive), 'public doc')
        self.assertEqual(ast.dump(inactive.args), ast.dump(original['x_f__mutmut_1'].args))
        self.assertEqual(inactive.body[1].value.func.id, projection.GUARD_NAME)
        self.assertEqual(inactive.body[1].value.args[0].value, 125)
        self.assertEqual(projection.validate_control(source, spans)['numbered_functions'], 2)

    def test_defaults_annotations_unicode_and_descriptor_headers_are_not_evaluated_or_rewritten(self):
        source = '''class Container:
    @classmethod
    def xǁContainerǁmethod__mutmut_orig(cls, /, value: unknown_type = side_effect(), *, flag=True) -> 'Result':
        """保持 documentation"""
        return value + 1
    @classmethod
    def xǁContainerǁmethod__mutmut_1(cls, /, value: unknown_type = side_effect(), *, flag=True) -> 'Result':
        """保持 documentation"""
        return value - 1
    @staticmethod
    def xǁContainerǁother__mutmut_orig(value): return value + 1
    @staticmethod
    def xǁContainerǁother__mutmut_1(value): return value - 1
'''
        actual = projection.project_source(source, index(source))
        for name, node in functions(source).items():
            target = functions(actual)[name]
            self.assertEqual(projection._header(node), projection._header(target))
            self.assertEqual(ast.get_docstring(node), ast.get_docstring(target))
        self.assertIn("value: unknown_type = side_effect()", actual)
        self.assertIn("@classmethod\n    def xǁContainerǁmethod__mutmut_1", actual)
        compile(actual, 'descriptor-data-only', 'exec', dont_inherit=True, optimize=0)

    def test_async_generator_coroutine_and_sync_generator_flags_are_preserved_without_running_programs(self):
        source = '''def x_g__mutmut_orig():
    yield 1
def x_g__mutmut_1():
    yield 2
async def x_a__mutmut_orig():
    yield 1
async def x_a__mutmut_1():
    yield 2
async def x_c__mutmut_orig():
    return 1
async def x_c__mutmut_1():
    return 2
def x_nested__mutmut_orig():
    def inner(): yield 1
    return inner
def x_nested__mutmut_1():
    def inner(): yield 2
    return inner
'''
        actual = projection.project_source(source, index(source))
        before, after = codes(source), codes(actual)
        for name in ('x_g__mutmut_1', 'x_a__mutmut_1', 'x_c__mutmut_1', 'x_nested__mutmut_1'):
            self.assertEqual(after[name].co_flags & (0x20 | 0x80 | 0x200), before[name].co_flags & (0x20 | 0x80 | 0x200))
        self.assertIn('(yield None) if False else None', actual)

    def test_same_line_body_and_docstring_only_body_keep_line_count(self):
        source = 'def x_f__mutmut_orig(): return 1\ndef x_f__mutmut_1(): """doc"""; return 2\ndef x_f__mutmut_2(): """only doc"""\n'
        actual = projection.project_source(source, index(source))
        self.assertEqual(actual.count('\n'), source.count('\n'))
        self.assertIn('def x_f__mutmut_1(): """doc"""; '+projection.GUARD_NAME+'(125)', actual)
        self.assertIn('def x_f__mutmut_2(): """only doc"""; '+projection.GUARD_NAME+'(125)', actual)
        compile(actual, 'single-line-data-only', 'exec', dont_inherit=True, optimize=0)

    def test_method_multiline_literals_keep_column_zero_continuations_and_unicode_bytes(self):
        source = '''class Container:
    def xǁContainerǁmethod__mutmut_orig(self, value="""默认值
column zero 默认
    """):
        """文档
column zero 文档
        """
        return """结果
column zero 结果
        """
    def xǁContainerǁmethod__mutmut_1(self, value="""默认值
column zero 默认
    """):
        """文档
column zero 文档
        """
        return """变化
column zero 变化
        """
    def xǁContainerǁmethod__mutmut_2(self, value="""默认值
column zero 默认
    """):
        """文档
column zero 文档
        """
        return "active"
'''
        spans = index(source)
        actual = projection.project_source(source, spans, 'xǁContainerǁmethod__mutmut_2')
        original, rewritten = functions(source), functions(actual)
        for name in original:
            self.assertEqual(projection._header(original[name]), projection._header(rewritten[name]))
            self.assertEqual(ast.get_docstring(original[name], clean=False), ast.get_docstring(rewritten[name], clean=False))
        for name in ('xǁContainerǁmethod__mutmut_orig', 'xǁContainerǁmethod__mutmut_2'):
            start, end = spans[name]
            self.assertEqual(actual.splitlines(keepends=True)[start-1:end], source.splitlines(keepends=True)[start-1:end])
        self.assertEqual(actual.count('\n'), source.count('\n'))
        self.assertEqual(projection.validate_control(source, spans)['functions'], 3)

    def test_bad_index_unknown_active_real_namespace_collision_and_invalid_functions_reject(self):
        source = 'def x_f__mutmut_orig(): return 1\ndef x_f__mutmut_1(): return 2\n'
        for spans in ({'x_f__mutmut_1': [0, 2]}, {'x_f__mutmut_1': [1, 2]}, {'x_f__mutmut_orig': [1, 1], 'x_f__mutmut_1': [1, 2]}):
            with self.assertRaises(ValueError):
                projection.project_source(source, spans)
        with self.assertRaises(ValueError):
            projection.project_source(source, index(source), 'x_f__mutmut_999')
        with self.assertRaises(ValueError):
            projection.project_source(projection.GUARD_NAME+' = lambda code: None\n'+source, {})
        with self.assertRaises(SyntaxError):
            projection.validate_control('def x_f__mutmut_1():\n    return (\n', {'x_f__mutmut_1': [1, 2]})
        with self.assertRaises(ValueError):
            projection.project_source('@custom\ndef x_f__mutmut_1(): return 2\n', {'x_f__mutmut_1': [1, 2]})
        with self.assertRaises(ValueError):
            projection.project_source(source, {'x_f__mutmut_orig': [1, 1]})

    def test_guard_literals_comments_and_original_declaration_are_data_not_identifiers(self):
        source = 'NOTICE = '+repr(projection.GUARD_NAME)+'\n# '+projection.GUARD_NAME+'\ndef x_f__mutmut_orig(): return 1\ndef x_f__mutmut_1(): return 2\n'
        actual = projection.project_source(source, index(source))
        self.assertIn('NOTICE = '+repr(projection.GUARD_NAME), actual)
        # An authored original declaration is stable input. Reading this
        # module's instrumented runtime copy would include SDK stub calls and
        # correctly collide with the reserved namespace.
        declaration = 'GUARD_NAME = '+repr(projection.GUARD_NAME)+'\n'
        self.assertEqual(projection.project_source(declaration, {}), declaration)

    def test_captured_original_exit_survives_ordinary_os_monkeypatch_in_original_helper_child(self):
        program = '''import importlib.util,os,sys,types
spec=importlib.util.spec_from_file_location('original_projection_guard',sys.argv[1]);p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)
sdk=types.SimpleNamespace(wrap_in_trampoline=lambda *args,**kwargs:lambda original:original)
p.install_guard(sdk)
def original_helper_fixture(): pass
bound=sdk.wrap_in_trampoline({})(original_helper_fixture)
os._exit=lambda code:None
try:
 bound.__globals__[p.GUARD_NAME](125)
except BaseException:
 raise SystemExit(7)
raise SystemExit(8)
'''
        result = subprocess.run([sys.executable, '-I', '-B', '-c', program, str(HELPER)], capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 125, result.stderr.decode())

    def test_different_activation_cannot_silently_reach_an_inactive_body(self):
        program = '''import importlib.util,os,sys,types
spec=importlib.util.spec_from_file_location('original_projection_activation',sys.argv[1]);p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)
package=types.ModuleType('mutmut');mutation=types.ModuleType('mutmut.mutation');sdk=types.ModuleType('mutmut.mutation.trampoline')
current=['scripts.example.x_f__mutmut_1'];sdk.get_mutant_under_test=lambda:current[0]
package.mutation=mutation;mutation.trampoline=sdk
sys.modules.update({'mutmut':package,'mutmut.mutation':mutation,'mutmut.mutation.trampoline':sdk})
p._latch_activation('active',current[0])
assert sdk.get_mutant_under_test()=='scripts.example.x_f__mutmut_1'
current[0]='scripts.example.x_f__mutmut_2'
try:
 sdk.get_mutant_under_test()
except BaseException:
 raise SystemExit(7)
raise SystemExit(8)
'''
        result = subprocess.run([sys.executable, '-I', '-B', '-c', program, str(HELPER)], capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 125, result.stderr.decode())


if __name__ == '__main__':
    unittest.main()
