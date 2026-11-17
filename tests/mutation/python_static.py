"""Generate and run module/class-scope Python mutants in an isolated snapshot.

mutmut mutates callable bodies but not import-time expressions. This script
accounts for both sets; it never edits the original working tree.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
import os
from pathlib import Path
import py_compile
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from typing import Any


class Collector(ast.NodeVisitor):
    def __init__(self) -> None:
        self.nodes: list[ast.Constant] = []

    def _body(self, body: list[ast.stmt]) -> None:
        for index, statement in enumerate(body):
            if index == 0 and isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Constant) and isinstance(statement.value.value, str):
                continue
            self.visit(statement)

    def visit_Module(self, node: ast.Module) -> None:
        self._body(node.body)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        for item in [*node.decorator_list, *node.bases, *[k.value for k in node.keywords]]:
            self.visit(item)
        self._body(node.body)

    def visit_FunctionDef(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        for item in [*node.decorator_list, *node.args.defaults, *[x for x in node.args.kw_defaults if x is not None]]:
            self.visit(item)
        # mutmut covers code inside function bodies.

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Constant(self, node: ast.Constant) -> None:
        if replacement(node.value) is not None:
            self.nodes.append(node)


def replacement(value: Any) -> str | None:
    if isinstance(value, bool):
        return "False" if value else "True"
    if value is None:
        return "True"
    if isinstance(value, int):
        return "1" if value == 0 else "0"
    if isinstance(value, float):
        return "1.0" if value == 0 else "0.0"
    if isinstance(value, str):
        return repr("__MUTATED__" if value == "" else "")
    if isinstance(value, bytes):
        return repr(b"__MUTATED__" if value == b"" else b"")
    return None


def source_files(root: Path) -> list[Path]:
    return sorted([*root.glob("workers/ud/src/ud_agent/**/*.py"), *root.glob("scripts/**/*.py")])


def enumerate_mutants(root: Path) -> list[dict[str, Any]]:
    result = []
    for path in source_files(root):
        content = path.read_bytes()
        tree = ast.parse(content, filename=str(path))
        collector = Collector()
        collector.visit(tree)
        lines = content.splitlines(keepends=True)
        relative = path.relative_to(root).as_posix()
        source_hash = hashlib.sha256(content).hexdigest()
        for node in collector.nodes:
            if node.end_lineno != node.lineno:
                # Multiline constants are still included; splice using byte offsets.
                pass
            replacement_text = replacement(node.value)
            assert replacement_text is not None and node.end_lineno is not None and node.end_col_offset is not None
            start = sum(map(len, lines[:node.lineno - 1])) + node.col_offset
            end = sum(map(len, lines[:node.end_lineno - 1])) + node.end_col_offset
            original = content[start:end]
            ident = f"{relative}:{node.lineno}:{node.col_offset}:{hashlib.sha256(original + b'->' + replacement_text.encode()).hexdigest()[:16]}"
            definition = {"tool": "python-static", "version": "1.0.0", "operator": "module_constant_literal", "start": start, "end": end, "original_hex": original.hex(), "replacement": replacement_text}
            definition_hash = hashlib.sha256(json.dumps(definition, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
            result.append({"id": ident, "file": relative, "source_sha256": source_hash, "definition": definition, "definition_sha256": definition_hash,
                           "line": node.lineno, "column": node.col_offset, "start": start, "end": end,
                           "replacement": replacement_text})
    return result


def _junit(path: Path, source_hashes=None, source_root=None) -> tuple[int, int, int, int]:
    root = ET.parse(path).getroot()
    tests = root.findall(".//testcase")
    failures = [failure for test in tests for failure in test.findall("failure")]
    def assertion(test):
        try:
            entries=test.findall('./properties/property')
            def one(name):
                values=[entry.get('value') for entry in entries if entry.get('name')==name]
                if len(values)!=1:raise ValueError('missing or duplicate origin')
                return values[0]
            origin=json.loads(one('ud-assertion-origin'))
            if one('ud-failure-kind')!='assertion' or not one('ud-exception-type') or origin['contract']!='python-test-source-origin-v2' or origin['test_id']!=one('ud-test-id') or origin['test_source']!=one('ud-source') or origin['test_source_sha256']!=one('ud-source-sha256'):return False
            for name,digest,line in [('source','source_sha256','line'),('test_source','test_source_sha256','test_line')]:
                source=origin[name]
                if not isinstance(source,str) or not source.startswith('tests/') or not source.endswith('.py') or any(value in source for value in ('\\','\0',':')) or any(part in ('','.','..') for part in source.split('/')) or not source_hashes or source_hashes.get(source)!=origin[digest] or type(origin[line])is not int or origin[line]<1:return False
                if source_root is None:return False
                file=Path(source_root)/source
                if file.is_symlink() or not file.is_file() or file.stat().st_size>4*1024**2:return False
                content=file.read_bytes()
                if hashlib.sha256(content).hexdigest()!=origin[digest] or origin[line]>len(content.splitlines()):return False
            return True
        except (ValueError,TypeError,KeyError):return False
    assertions = sum(assertion(test) for test in tests for _ in test.findall('failure'))
    errors = sum(bool(test.findall("error")) for test in tests) + len(failures) - assertions
    return len(tests), assertions, errors, sum(bool(test.findall("skipped")) for test in tests)


def run(root: Path, output: Path, python: str, timeout: int, limit: int | None, inventory_only: bool = False, *, execute=None) -> int:
    original_root = os.environ.get("UD_MUTATION_ORIGINAL_ROOT")
    if not original_root or root.resolve() == Path(original_root).resolve():
        raise ValueError("static mutants require an isolated source snapshot")
    root = root.resolve(strict=True)
    if (root / ".git").exists() or (root / ".git").is_symlink():
        raise ValueError("static mutants cannot execute in a live source checkout")
    if not inventory_only and execute is None:
        raise ValueError('static mutant execution requires the protected OCI coordinator')
    cases = enumerate_mutants(root)
    report: dict[str, Any] = {"schema_version": 1, "tool": "python-static", "complete": False,
                              "scheduled": len(cases), "inventory": cases, "outcomes": []}
    output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    if inventory_only:
        report["inventory_only"] = True
        output.write_text(json.dumps(report, indent=2), encoding="utf-8")
        return 0
    env = {**os.environ, "PYTHONPATH": str(root / "workers/ud/src"), "PYTHONDONTWRITEBYTECODE": "1", "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1"}
    # This runner owns a separate disposable fixture and its strict JUnit
    # evidence. An outer mutmut session's plugin is outside that fixture and
    # must not redirect or poison nested test discovery.
    for name in ("PYTEST_PLUGINS", "PYTEST_ADDOPTS", "UD_MUTATION_PYTEST_EVIDENCE", "MUTANT_UNDER_TEST"):
        env.pop(name, None)
    source_hashes={file.relative_to(root).as_posix():hashlib.sha256(file.read_bytes()).hexdigest() for file in (root/'tests').rglob('*.py') if file.is_file() and not file.is_symlink()}
    selected = cases if limit is None else cases[:limit]
    for index, case in enumerate(selected):
        path = root / case["file"]
        current = root
        for component in Path(case["file"]).parts:
            current = current / component
            if current.is_symlink():
                raise ValueError("static mutation source cannot alias another source tree")
        if not path.is_file() or path.stat().st_nlink != 1:
            raise ValueError("static mutation source must be an independent ordinary copy")
        original = path.read_bytes()
        record = {key: case[key] for key in ("id", "file", "source_sha256", "definition", "definition_sha256", "line", "column")}
        if hashlib.sha256(original).hexdigest() != case["source_sha256"]:
            record.update(status="Error", reason="source changed after enumeration")
        else:
            mutated = original[:case["start"]] + case["replacement"].encode() + original[case["end"]:]
            try:
                path.write_bytes(mutated)
                with tempfile.TemporaryDirectory(prefix="ud-agent-static-mutant-") as temp:
                    junit = Path(temp) / "junit.xml"
                    try:
                        py_compile.compile(str(path), doraise=True, cfile=str(Path(temp) / "test.pyc"))
                    except py_compile.PyCompileError as exc:
                        record.update(status="CompileError", reason=str(exc))
                    else:
                        try:
                            completed = (execute or subprocess.run)([python, "-m", "pytest", "tests", "-q", "--junitxml", str(junit)], cwd=root, env=env, capture_output=True, text=True, timeout=timeout, check=False)
                        except subprocess.TimeoutExpired:
                            record.update(status="Timeout", reason="test deadline exceeded")
                        else:
                            try:
                                total, failures, errors, skipped = _junit(junit,source_hashes,root)
                            except (OSError, ET.ParseError):
                                record.update(status="RunnerError", reason="missing or malformed pytest JUnit report")
                            else:
                                if not total or errors or skipped or completed.returncode not in (0, 1):
                                    record.update(status="RunnerError", reason=f"pytest exit={completed.returncode}, tests={total}, errors={errors}, skipped={skipped}")
                                elif completed.returncode == 1 and failures:
                                    record.update(status="Killed", tests=total, failures=failures)
                                elif completed.returncode == 0 and not failures:
                                    record.update(status="Survived", tests=total)
                                else:
                                    record.update(status="RunnerError", reason="pytest status and JUnit results disagree")
            finally:
                path.write_bytes(original)
        report["outcomes"].append(record)
        output.write_text(json.dumps(report, indent=2), encoding="utf-8")
        if index % 25 == 0:
            print(f"python-static: {index + 1}/{len(selected)} ({record['status']})", flush=True)
    report["complete"] = limit is None and len(selected) == len(cases)
    output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return 0 if report["complete"] and all(item["status"] == "Killed" for item in report["outcomes"]) else 1


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--python", default=sys.executable)
    parser.add_argument("--timeout", type=int, default=120)
    parser.add_argument("--limit", type=int)
    parser.add_argument("--inventory-only", action="store_true")
    args = parser.parse_args()
    if args.timeout < 1 or (args.limit is not None and args.limit < 1):
        parser.error("timeout and limit must be positive")
    if not args.inventory_only:
        parser.error("mutant execution requires the protected OCI coordinator; use mutation-gate.mjs --backend python")
    return run(args.root, args.output, args.python, args.timeout, args.limit, args.inventory_only)


if __name__ == "__main__":
    raise SystemExit(main())
