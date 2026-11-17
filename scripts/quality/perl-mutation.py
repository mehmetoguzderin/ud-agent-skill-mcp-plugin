#!/usr/bin/env python3
"""Schedule and execute PPI-token-based mutations across all owned Perl sources."""
from __future__ import annotations

import argparse
import ast
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def source_receipt(root):
    node = shutil.which("node")
    if not node:
        raise ValueError("the locked developer Node runtime is required for source inventory")
    module = (root / "scripts/release/candidate.mjs").resolve(strict=True).as_uri()
    script = 'import { sourceReceipt } from ' + json.dumps(module) + '; process.stdout.write(JSON.stringify(sourceReceipt(process.argv[1])));'
    return json.loads(subprocess.check_output([node, "--input-type=module", "-e", script, str(root)], timeout=60))


def verify_parser(root, parser_root, perl):
    lock = json.loads((root / "quality/perl-parser.lock.json").read_text())
    receipt = json.loads((parser_root / "parser-receipt.json").read_text())
    if receipt.get("lock_sha256") != sha(canonical(lock)) or receipt.get("parser_release") != lock.get("parser_release") or not receipt.get("files"):
        raise ValueError("private Perl parser differs from its frozen lock")
    expected = {}
    for item in receipt["files"]:
        name = item["path"]
        if name in expected or name.startswith("/") or ".." in name.split("/") or "\\" in name:
            raise ValueError("private Perl parser inventory is invalid")
        path = parser_root / name
        if path.is_symlink() or not path.is_file() or path.stat().st_size != item["size"] or sha(path.read_bytes()) != item["sha256"]:
            raise ValueError("private Perl parser file differs from its receipt")
        expected[name] = item["sha256"]
    actual = {path.relative_to(parser_root).as_posix() for path in parser_root.rglob("*") if path.is_file() and path.name != "parser-receipt.json"}
    if actual != set(expected):
        raise ValueError("private Perl parser contains unlisted files")
    version = subprocess.check_output([perl, "-e", "print $^V"], text=True)
    if version != receipt["perl_version"]:
        raise ValueError("private Perl parser was built for a different interpreter ABI")
    return receipt


def tokens(root, file, parser_root, perl):
    env = {key: value for key, value in os.environ.items() if key not in ("PERL5LIB", "PERL5OPT", "PERL_MM_OPT", "PERL_MB_OPT")}
    env["UD_PERL_PARSER_LIB"] = str(parser_root / "lib/perl5")
    result = subprocess.run([perl, str(root / "scripts/quality/perl_tokens.pl"), str(root / file)], env=env, capture_output=True, timeout=30)
    if result.returncode or result.stderr:
        raise ValueError("private Perl parser did not complete: " + result.stderr.decode("utf-8", "replace")[:1000])
    data = json.loads(result.stdout)
    source = (root / file).read_bytes()
    if data.get("schema_version") != 1 or data.get("parser_version") != "1.291" or data.get("source_sha256") != sha(source):
        raise ValueError("Perl token stream is not bound to the frozen source")
    return data


def regex_parts(content, operators):
    """Locate an already PPI-parsed match body without reparsing its grammar.

    PPI has established the token boundary. The final delimiter is immediately
    followed by modifiers; paired delimiters and escaped inner delimiters stay
    byte-for-byte intact. Unknown spellings are incomplete, never silent skips.
    """
    match = re.match(r"(?:m\s*)?([^A-Za-z0-9_\s])", content)
    if not match or match[1] not in operators.get("regex_delimiters", {}):
        return None
    closing = operators["regex_delimiters"][match[1]]
    end = content.rfind(closing)
    if end < match.end() or not re.fullmatch(r"[A-Za-z]*", content[end + 1:]):
        return None
    return content[:match.end()], content[match.end():end], content[end:]


def regex_anchors(body, extended=False):
    """Identify zero-width anchors outside escapes, quoted text and classes."""
    result=[];index=0;in_class=False;class_first=False;quoted=False
    while index<len(body):
        char=body[index]
        if char=='\\' and index+1<len(body):
            escaped=body[index+1]
            if in_class:class_first=False
            if quoted:
                if escaped=='E':quoted=False
            elif escaped=='Q'and not in_class:quoted=True
            elif not in_class and escaped in ('A','z','Z'):
                result.append((index,index+2,'start'if escaped=='A'else'end'))
            index+=2;continue
        if quoted:index+=1;continue
        if in_class:
            if char=='['and index+1<len(body)and body[index+1]in(':','.','='):
                end=body.find(body[index+1]+']',index+2)
                if end<0:raise ValueError('PPI regex character class is incomplete')
                index=end+2;class_first=False;continue
            if char==']'and not class_first:in_class=False
            elif not(char=='^'and class_first):class_first=False
            index+=1;continue
        if char=='[':in_class=True;class_first=True;index+=1;continue
        if extended and char=='#':
            end=body.find('\n',index);index=len(body)if end<0 else end+1;continue
        if body.startswith('(?#',index):
            end=body.find(')',index+3)
            if end<0:raise ValueError('PPI regex comment is incomplete')
            index=end+1;continue
        if char=='^':result.append((index,index+1,'start'))
        elif char=='$'and(index+1==len(body)or not re.match(r'[A-Za-z0-9_{]',body[index+1])):
            result.append((index,index+1,'end'))
        index+=1
    return result


def inventory(source, file, parsed, operators, coverage=None):
    if parsed.get("source_sha256") != sha(source):
        raise ValueError("Perl token stream source mismatch")
    result, identities, cursor = [], set(), 0

    def add(token, replacement, operator):
        original = token["content"]
        if replacement == original:
            return
        definition = {"tool": "ppi-perl", "version": "1.0.0", "operator": operator, "start": token["start"], "end": token["end"], "original": original, "replacement": replacement}
        fingerprint = sha(canonical(definition))
        identity = f"{file}#{token['start']}:{operator}"
        if identity in identities:
            raise ValueError("duplicate Perl mutation identity")
        identities.add(identity)
        result.append({"id": identity, "file": file, "source_sha256": sha(source), "definition_sha256": fingerprint, "definition": definition})

    for token in parsed["tokens"]:
        raw = token["content"].encode("utf-8")
        if token["start"] != cursor or source[cursor:token["end"]] != raw:
            raise ValueError("Perl tokens do not exactly cover source bytes")
        cursor = token["end"]
        kind, content = token["class"], token["content"]
        before=len(result);classification='outside-selected-family';reason='PPI syntax or identifier outside declared mutation families'
        if kind == "PPI::Token::Operator" and content in operators["operator_replacements"]:
            add(token, operators["operator_replacements"][content], "operator_" + content)
        elif kind == "PPI::Token::Operator" and content=='?':
            for operator,replacement in operators.get('ternary_replacements',{}).items():add(token,replacement,operator)
        elif kind == "PPI::Token::Operator":
            if content in operators.get('structural_operators',{}):classification='structural';reason=operators['structural_operators'][content]
            else:classification='unimplemented';reason='Live operator has no declared mutation or structural rule'
        elif kind == "PPI::Token::Word" and content in operators["keyword_replacements"]:
            add(token, operators["keyword_replacements"][content], "keyword_" + content)
        elif kind == "PPI::Token::Number" and re.fullmatch(r"\d+", content):
            if re.search(rb"\bexit\s*$", source[max(0, token["start"] - 32):token["start"]]) and content in ("0", "1"):
                add(token, "1" if content == "0" else "0", "exit_status_flip")
            else:
                for difference in operators["integer_boundaries"]:
                    replacement = int(content) + difference
                    if replacement >= 0:
                        add(token, str(replacement), "integer_boundary_" + str(difference))
        elif kind.startswith('PPI::Token::Number'):
            classification='unimplemented';reason='Numeric spelling is outside the declared decimal integer family'
        elif kind in ("PPI::Token::Quote::Single", "PPI::Token::Quote::Double") and len(content) >= 2 and content[0] == content[-1] and content[0] in ("'", '"'):
            if re.search(rb"\b(?:no|use)\s+warnings\s*$", source[max(0, token["start"] - 64):token["start"]]):
                add(token, content[0] + ("uninitialized" if content[1:-1] != "uninitialized" else "io") + content[-1], "warning_category")
            else:
                add(token, content[0] + ("mutated" if len(content) == 2 else "") + content[-1], "string_value")
        elif kind == "PPI::Token::Regexp::Match":
            parts=regex_parts(content,operators)
            if parts is None:
                classification='unimplemented';reason='PPI match delimiter has no declared mutation rule'
            elif re.search(r'\(\?(?:\??\{|[A-Za-z-]*[xX])',parts[1]):
                classification='unimplemented';reason='Embedded code or inline extended-mode semantics require explicit regex support'
            else:
                prefix,body,suffix=parts;anchors=regex_anchors(body,'x'in suffix[1:])
                for direction in('start','end'):
                    selected=[(start,end)for start,end,kind in anchors if kind==direction]
                    for number,(start,end)in enumerate(selected):
                        operator='regex_remove_'+direction+'_anchor'+(''if number==0 else'_'+str(number))
                        add(token,prefix+body[:start]+body[end:]+suffix,operator)
                add(token,prefix+'(?:)'+suffix,'regex_match_any')
        elif 'Regexp'in kind or kind in('PPI::Token::Quote::Single','PPI::Token::Quote::Double'):
            classification='unimplemented';reason='Selected literal family has an unsupported PPI spelling'
        if len(result)>before:classification='scheduled';reason='Declared applicable token mutations are materialized'
        if coverage is not None:coverage.append({'start':token['start'],'end':token['end'],'class':kind,'content':content,'classification':classification,'reason':reason,'mutant_ids':[item['id']for item in result[before:]]})
    if cursor != len(source):
        raise ValueError("Perl token inventory is incomplete")
    return result


def discover_sources(root):
    result = []
    for directory in ("packages", "workers", "scripts"):
        for path in sorted((root / directory).rglob("*")):
            if path.suffix in (".pl", ".pm") and "__pycache__" not in path.parts:
                if path.is_symlink() or not path.is_file():
                    raise ValueError("owned Perl source is not an ordinary file")
                result.append(path.relative_to(root).as_posix())
    return result


def classify(result):
    output = (result.stdout.decode("utf-8", "replace") + "\n" + result.stderr.decode("utf-8", "replace")).replace('\r\n', '\n')
    count = re.search(r"(?m)^Ran (\d+) tests? in ", output)
    if not count or int(count.group(1)) < 1 or re.search(r"\b(?:skipped|expected failures|unexpected successes)=", output):
        return "RunnerError", []
    if result.returncode == 0 and re.search(r"(?m)^OK\s*$", output):
        return "Survived", []
    failed = re.search(r"(?m)^FAILED \(failures=(\d+)\)\s*$", output)
    assertions = re.findall(r"(?m)^AssertionError(?::.*)?$", output)
    if result.returncode == 1 and failed and len(assertions) == int(failed.group(1)) and not re.search(r"(?m)^ERROR:", output) and "UD_COMPONENT_UNEXPECTED_EXIT:" not in output and "self.assertEqual(result.stderr, b'')" not in output:
        return "Killed", re.findall(r"(?m)^FAIL: (.+)$", output)
    return "RuntimeError", []


def test_cases(root, tests):
    """Independently freeze the closed, directly declared unittest methods."""
    result = {"bridge": [], "tool": []}
    for name, fingerprint in sorted(tests.items()):
        raw = (root / name).read_bytes()
        if sha(raw) != fingerprint:
            raise ValueError("Perl test source changed during independent discovery")
        tree = ast.parse(raw)
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == "load_tests":
                raise ValueError("dynamic Perl unittest collection requires an explicit discovery contract")
            if not isinstance(node, ast.ClassDef):
                continue
            methods = [method for method in node.body if isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef)) and method.name.startswith("test")]
            if not methods:
                continue
            if node.decorator_list or len(node.bases) != 1 or ast.unparse(node.bases[0]) != "unittest.TestCase" or any(method.decorator_list or isinstance(method, ast.AsyncFunctionDef) for method in methods):
                raise ValueError("Perl unittest class is outside the closed discovery contract")
            suite = "bridge" if name.startswith("tests/domain/perl/") else "tool"
            result[suite].extend({"id": f"{Path(name).stem}.{node.name}.{method.name}", "source": name, "source_sha256": fingerprint} for method in methods)
    for rows in result.values():
        rows.sort(key=lambda item: item["id"])
        if not rows or len({item["id"] for item in rows}) != len(rows):
            raise ValueError("independent Perl test collection is empty or duplicated")
    return result


def typed_classification(result, expected, root=None, source_inventory=None):
    value = getattr(result, "unittest_evidence", None)
    if not isinstance(value, dict) or value.get("schema_version") != 1 or value.get("contract") != "python-test-source-origin-v2" or value.get("expected") != expected or not isinstance(value.get("cases"), list) or value.get("tests_run") != len(expected) or len(value["cases"]) != len(expected):
        return "RunnerError", []
    hashes = {item['path']: item['sha256'] for item in source_inventory or []}
    def valid_site(name, fingerprint, line):
        if (root is None or not isinstance(name, str) or not name.startswith('tests/') or not name.endswith('.py')
                or '\\' in name or ':' in name or any(part in ('', '.', '..') for part in name.split('/'))
                or hashes.get(name) != fingerprint or type(line) is not int or line < 1):
            return False
        file = Path(root) / name
        try:
            if file.is_symlink() or not file.is_file() or file.stat().st_size > 4 * 1024 ** 2:
                return False
            content = file.read_bytes()
            return sha(content) == fingerprint and line <= len(content.splitlines())
        except OSError:
            return False
    failed = []
    for case, wanted in zip(value["cases"], expected):
        if not isinstance(case, dict) or any(case.get(key) != wanted[key] for key in wanted) or case.get("completed") is not True or not isinstance(case.get("events"), list) or not case["events"]:
            return "RunnerError", []
        for event in case["events"]:
            if not isinstance(event, dict) or event.get("kind") not in ("success", "failure"):
                return "RuntimeError", []
            if event["kind"] == "failure":
                origin = event.get("assertion_origin")
                if (event.get("assertion") is not True or not isinstance(event.get("exception_type"), str)
                        or not isinstance(origin, dict) or origin.get('contract') != 'python-test-source-origin-v2'
                        or origin.get('test_id') != wanted['id'] or origin.get('test_source') != wanted['source']
                        or origin.get('test_source_sha256') != wanted['source_sha256']
                        or not valid_site(origin.get('source'), origin.get('source_sha256'), origin.get('line'))
                        or not valid_site(origin.get('test_source'), origin.get('test_source_sha256'), origin.get('test_line'))):
                    return "RuntimeError", []
                failed.append(case["id"])
    status, _ = classify(result)
    if failed:
        return ("Killed", sorted(set(failed))) if status == "Killed" and result.returncode == 1 and value.get("successful") is False else ("RuntimeError", [])
    return ("Survived", []) if status == "Survived" and value.get("successful") is True else ("RuntimeError", [])


def schedule(root, parser_root, perl, materializations=None):
    parser = verify_parser(root, parser_root, perl)
    operators_data = (root / "quality/perl-operators.json").read_bytes()
    operators = json.loads(operators_data)
    sources = discover_sources(root)
    scheduled = []
    source_data = {}
    parsed_sources = {}
    operator_coverage = {}
    for file in sources:
        source_data[file] = (root / file).read_bytes()
        parsed_sources[file] = tokens(root, file, parser_root, perl)
        operator_coverage[file] = []
        scheduled.extend(inventory(source_data[file], file, parsed_sources[file], operators, operator_coverage[file]))
    if not scheduled:
        raise ValueError("Perl scheduling generated no applicable mutations")
    tests = {path.relative_to(root).as_posix(): sha(path.read_bytes()) for directory in ("tests/domain/perl", "tests/mutation") for path in sorted((root / directory).glob("test_*.py")) if directory == "tests/domain/perl" or path.name.startswith("test_perl_")}
    frozen = source_receipt(root)
    report = {"schema_version": 1, "tool": "ppi-perl", "tool_version": "1.0.0", "source_tree_sha256": frozen["sha256"], "source_inventory": frozen["files"], "parser_release": parser["parser_release"], "operator_sha256": sha(operators_data), "scope_complete": all(row['classification']!='unimplemented'for rows in operator_coverage.values()for row in rows), "operator_coverage":operator_coverage,"sources": {file: sha(data) for file, data in source_data.items()}, "tests": tests, "case_inventory": test_cases(root, tests), "scheduled": len(scheduled), "inventory": scheduled, "outcomes": [], "baseline": {}}
    if materializations is not None:
        materializations = Path(materializations)
        materializations.mkdir(mode=0o700)
        rows = []
        for file in sources:
            name = "tokens/" + file + ".json"
            target = materializations / name
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            raw = canonical(parsed_sources[file]) + b"\n"
            with target.open("xb") as stream:
                stream.write(raw)
            rows.append({"source": file, "source_sha256": sha(source_data[file]),
                         "mutant_ids": sorted(item["id"] for item in scheduled if item["file"] == file),
                         "tokens": {"path": name, "sha256": sha(raw), "size": len(raw)}})
        manifest = {"schema_version": 1, "qualification": "complete-ppi-token-materialization-no-outcomes",
                    "source_tree_sha256": frozen["sha256"], "parser_release": parser["parser_release"],
                    "operator_sha256": sha(operators_data), "operator_coverage":operator_coverage,"sources": rows}
        with (materializations / "manifest.json").open("x") as stream:
            json.dump(manifest, stream, sort_keys=True)
            stream.write("\n")
    return report, source_data


def run(root, parser_root, perl, python, output, timeout=120, verify_schedule=None):
    if os.environ.get('UD_MUTATION_OCI_GUARD') != '1' or os.geteuid() != 0:
        raise ValueError('complete Perl mutation execution requires the protected OCI coordinator')
    boundary_path = Path('/opt/mutation/harness/oci-exec.py')
    boundary_spec = importlib.util.spec_from_file_location('ud_perl_execution_boundary', boundary_path)
    boundary = importlib.util.module_from_spec(boundary_spec)
    boundary_spec.loader.exec_module(boundary)
    def execute(command, env, limit, structured=False):
        result = boundary.execute(command, state=output.parent, environment=env, timeout=limit,
                                  **({"result": {"basename": "unittest-result.json", "max_bytes": 16 * 1024 * 1024}} if structured else {}))
        if result['timed_out']:
            raise subprocess.TimeoutExpired(command, limit)
        completed = subprocess.CompletedProcess(command, result['status'], result['stdout'].encode(), result['stderr'].encode())
        if structured:
            try:
                completed.unittest_evidence = json.loads(result.get("result_bytes") or b"null")
            except (ValueError, UnicodeError):
                completed.unittest_evidence = None
        return completed
    report, source_data = schedule(root, parser_root, perl, output.parent / 'perl-generation')
    scheduled = report["inventory"]
    output.write_text(json.dumps(report, indent=2) + "\n")
    if report['scope_complete']is not True:
        raise ValueError('Perl source has unimplemented live token semantics; incomplete schedule retained without mutant execution')
    if verify_schedule is not None:
        verify_schedule(report)
    with tempfile.TemporaryDirectory(prefix="ud-perl-full-") as temporary:
        Path(temporary).chmod(0o755)
        work = Path(temporary) / report["source_tree_sha256"]
        ignore = shutil.ignore_patterns(".git", "node_modules", ".venv", ".artifacts", "target", "dist", "reports", "mutants", "__pycache__", "*.pyc")
        shutil.copytree(root, work, ignore=ignore, symlinks=False)
        if source_receipt(work)["sha256"] != report["source_tree_sha256"] or source_receipt(root)["sha256"] != report["source_tree_sha256"]:
            raise ValueError("source changed while the isolated Perl mutation snapshot was captured")
        (Path(temporary) / "snapshot-receipt.json").write_text(json.dumps({"source_sha256": report["source_tree_sha256"], "origin": str(root), "copy": str(work), "writes": "copy-only"}) + "\n")
        env = {key: value for key, value in os.environ.items() if key not in ("PERL5LIB", "PERL5OPT", "PYTHONPATH", "PYTHONHOME") and not re.search("TOKEN|PASSWORD|SECRET|CREDENTIAL|API_KEY", key, re.I)}
        env.update({"UD_AGENT_PERL": perl, "UD_PERL_PARSER_LIB": str(parser_root / "lib/perl5"), "UD_PERL_PARSER_ROOT": str(parser_root), "PYTHONDONTWRITEBYTECODE": "1", "PYTHONPATH": str(work / 'workers/ud/src')})
        commands = {
            name: [python, str(work / "scripts/quality/perl-test-evidence.py"), "--root", str(work), "--suite", name, "--output", "{result}"]
            for name in ("bridge", "tool")
        }
        for name, command in commands.items():
            result = execute(command, env, timeout, structured=True)
            report["baseline"][name] = {"status": result.returncode, "passed": typed_classification(result, report["case_inventory"][name], work, report['source_inventory'])[0] == "Survived", "unittest": result.unittest_evidence}
        if not all(item["passed"] for item in report["baseline"].values()):
            raise ValueError("complete Perl mutation baseline did not pass")
        previous = None
        for item in scheduled:
            file = item["file"]
            if previous is not None:
                (work / previous).write_bytes(source_data[previous])
            source = source_data[file]
            definition = item["definition"]
            (work / file).write_bytes(source[:definition["start"]] + definition["replacement"].encode() + source[definition["end"]:])
            previous = file
            try:
                compile_env = {**env, "UD_PERL_PARSER_LIB": str(parser_root / "lib/perl5")}
                compiled = execute([perl, "-c", str(work / file)], compile_env, timeout)
                if compiled.returncode:
                    status, tests = "CompileError", []
                    evidence = {"phase": "compile", "stdout": compiled.stdout.decode("utf-8", "replace"), "stderr": compiled.stderr.decode("utf-8", "replace")}
                else:
                    name = "tool" if file.startswith("scripts/") else "bridge"
                    executed = execute(commands[name], env, timeout, structured=True)
                    status, tests = typed_classification(executed, report["case_inventory"][name], work, report['source_inventory'])
                    evidence = {"phase": "test", "status": executed.returncode, "stdout": executed.stdout.decode("utf-8", "replace"), "stderr": executed.stderr.decode("utf-8", "replace"), "unittest": executed.unittest_evidence}
            except subprocess.TimeoutExpired:
                status, tests = "Timeout", []
                evidence = {"phase": "timeout", "limit_seconds": timeout}
            report["outcomes"].append({"id": item["id"], "file": file, "definition_sha256": item["definition_sha256"], "status": status, "failure_kind": "assertion" if status == "Killed" else None, "tests": tests, "evidence": evidence})
            if len(report["outcomes"]) % 25 == 0:
                output.write_text(json.dumps(report, indent=2) + "\n")
        report["complete"] = True
        output.write_text(json.dumps(report, indent=2) + "\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--parser-root", type=Path, required=True)
    parser.add_argument("--perl", required=True)
    parser.add_argument("--python", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--inventory-only", action="store_true")
    args = parser.parse_args()
    if args.inventory_only:
        report, _ = schedule(args.root.resolve(), args.parser_root.resolve(), str(Path(args.perl).resolve()))
        args.output.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps({"scheduled": report["scheduled"], "sources": len(report["sources"])}))
        return 0
    report = run(args.root.resolve(), args.parser_root.resolve(), str(Path(args.perl).resolve()), args.python, args.output)
    print(json.dumps({"scheduled": report["scheduled"], "outcomes": len(report["outcomes"]), "killed": sum(item["status"] == "Killed" for item in report["outcomes"])}))
    return 0 if all(item["status"] == "Killed" for item in report["outcomes"]) else 1


if __name__ == "__main__":
    sys.exit(main())
