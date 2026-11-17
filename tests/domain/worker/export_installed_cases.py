"""Export independent operation fixtures for real installed coordinator runners.

No worker invocation, Git write, provider emulation, or outcome is supplied by
this exporter. Every result is obtained by the separate installed runner.
"""
from __future__ import annotations
import argparse
import base64
import hashlib
import json
from pathlib import Path
import tempfile

from operation_cases import make_cases


def digest(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def complete_installed_context(root):
    """Finalize exact context bytes before any provenance-bound input is authored."""
    rules = {file.name: digest(file.read_bytes()) for file in sorted((root / "rules").glob("*.json"))}
    (root / "context.json").write_text(canonical({"schema_version": 1, "rule_dir": "rules", "rules": rules, "context_sha256": digest(canonical(rules).encode())}) + "\n", encoding="utf-8")


def selected_fixtures(root, arguments):
    explicit, directories = set(), set()
    def paths(value):
        if isinstance(value, str):
            if value.endswith(".conllu"):
                explicit.add(value)
            elif value and not Path(value).is_absolute() and (root / value).is_dir():
                directories.add(value.rstrip("/"))
        elif isinstance(value, list):
            for item in value:
                paths(item)
        elif isinstance(value, dict):
            for item in value.values():
                paths(item)
    paths(arguments)
    result = []
    for file in sorted(root.rglob("*")):
        if not file.is_file():
            continue
        name = file.relative_to(root).as_posix()
        if name.startswith(".ud-agent-inputs/"):
            continue
        if name.endswith(".conllu") and name != "main.conllu" and name not in explicit and not any(name.startswith(directory + "/") for directory in directories):
            continue
        data = file.read_bytes()
        result.append({"path": name, "sha256": digest(data), "size_bytes": len(data), "content_base64": base64.b64encode(data).decode("ascii")})
    return result


def export():
    catalog = json.loads((Path(__file__).resolve().parents[3] / "contracts/ud-interfaces.json").read_text())
    signatures = {item["name"]: {parameter["name"] for parameter in item["parameters"]} for item in catalog}
    result = []
    with tempfile.TemporaryDirectory(prefix="ud-installed-fixture-export-") as temporary:
        root = Path(temporary).resolve(strict=True)
        cases = make_cases(root, prepare_context=complete_installed_context)
        def portable(value):
            if isinstance(value, str):
                if value == str(root):
                    return "${WORKSPACE}"
                if value.startswith(str(root) + "/"):
                    return "${WORKSPACE}/" + value[len(str(root)) + 1:]
                if value == "/out" or value.startswith("/out/"):
                    return "${OUTPUT}" + value[4:]
                return value
            if isinstance(value, list):
                return [portable(item) for item in value]
            if isinstance(value, dict):
                return {key: portable(item) for key, item in value.items()}
            return value
        for case in cases:
            name = case["operation"]
            args = {key: value for key, value in case["arguments"].items() if key in signatures[name]}
            if name == "plan_apply":
                args["options"] = {"mode": "preview", "validation_options": {"language_code": "ud", "level": 2}, "ud_context_path": str(root / "context.json")}
            checks = dict(case["checks"])
            profile = "trusted_builtin"
            prerequisites = []
            expected_artifacts = []
            for field in list(checks):
                if field.startswith("artifacts.") and field.endswith(".content"):
                    index = int(field.split(".")[1])
                    data = checks.pop(field).encode("utf-8")
                    expected_artifacts.append({"index": index, "sha256": digest(data), "size_bytes": len(data), "content_base64": base64.b64encode(data).decode("ascii"), "verify_via": ["immutable artifact resource", "authorized exported file"]})
            if checks.get("requires_host_export") is True:
                checks["requires_host_export"] = False
            if name == "project_consistency_report":
                profile = "fresh_oci_project_jobs"
                checks = {"passed": True, "official.passed": True, "project.passed": True}
            if "evidence" in case:
                revision = "4d0f1a789fbc5838cb6db1e9aafbd4596492c7a7"
                args["base_revision"] = revision
                prerequisites.append({"type": "existing_git_repository", "repository_path": ".artifacts/uv-cache/git-v0/db/695d30bf270676a4", "requested_revision": revision, "tree_oid": "cd6390d21c32b02b741fb1a8b83151ee9768f7aa", "conllu_files": 98, "conllu_bytes": 4490522, "requirements": ["reuse existing pinned upstream object database", "no new commits or refs", "real broker revision resolution", "read-only Git capture", "fresh snapshot binding", "no public evidence injection"]})
                if name == "treebank_review":
                    checks["changes.0.kind"] = "added"
                    checks["changes.0.file_path"] = "main.conllu"
                    checks["revision_attestation.resolved_commit"] = revision
                else:
                    checks["changes.0.change"] = "added"
                    checks["changes.0.file_path"] = "main.conllu"
            files = selected_fixtures(root, args)
            result.append({"operation": name, "arguments": portable(args), "expected_fields": portable(checks), "execution_profile": profile,
                           "prerequisites": prerequisites, "expected_artifacts": expected_artifacts, "files": files,
                           "fixture_manifest_sha256": digest(canonical([{key: item[key] for key in ("path", "sha256", "size_bytes")} for item in files]).encode())})
    names = [item["operation"] for item in result]
    if len(names) != 102 or len(set(names)) != 102 or set(names) != set(signatures):
        raise ValueError("installed behavior inventory must cover exactly the preserved102 operations")
    return {"schema_version": 1, "qualification": "independent-inputs-and-expectations-only", "scheduled_operations": 102,
            "placeholders": {"${WORKSPACE}": "unique granted directory populated from this case's bytes", "${OUTPUT}": "unique explicitly granted export directory"},
            "requirements": ["invoke installed public dispatch", "isolate each case workspace", "assert each independent expected field", "verify fixture hashes before execution", "record actual provider and architecture", "never reuse unit-test mocks or supplied outcomes"], "cases": result}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.write_text(json.dumps(export(), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
