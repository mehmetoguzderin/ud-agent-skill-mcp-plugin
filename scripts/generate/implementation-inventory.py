#!/usr/bin/env python3
"""Bind retained requirements to actual implementation and original test files."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
AUTHORITY = "contracts/implementation-requirements.json"
TARGET = "contracts/implementation-inventory.json"
EXCLUDED = {"__pycache__", "target", "node_modules", ".venv", ".pytest_cache"}


def evidence(name: str) -> list[dict]:
    if not isinstance(name, str) or not name or any(part in {"", ".", ".."} for part in name.split("/")) or any(char in name for char in "\\:\0"):
        raise ValueError("unsafe requirement evidence path")
    selected = ROOT
    for part in name.split("/"):
        selected /= part
        if selected.is_symlink():
            raise ValueError("symbolic link in requirement evidence: " + name)
    if selected.is_dir():
        files = []
        for child in sorted(selected.iterdir()):
            if child.name not in EXCLUDED and not child.name.endswith(".pyc"):
                files.extend(evidence(child.relative_to(ROOT).as_posix()))
        if not files:
            raise ValueError("empty requirement evidence directory: " + name)
        return files
    if not selected.is_file():
        raise ValueError("required implementation/test evidence is absent: " + name)
    data = selected.read_bytes()
    return [{"path": name, "sha256": hashlib.sha256(data).hexdigest(), "size_bytes": len(data)}]


def inventory() -> dict:
    specification = json.loads((ROOT / AUTHORITY).read_text(encoding="utf-8"))
    acceptance = json.loads((ROOT / "quality/requirements.json").read_text(encoding="utf-8"))
    requirements = specification.get("requirements")
    if specification.get("schema_version") != 1 or not isinstance(requirements, list) or not requirements:
        raise ValueError("retained requirements are empty or invalid")
    required_suites = acceptance.get("required_suites")
    if not isinstance(required_suites, list) or not required_suites or len(set(required_suites)) != len(required_suites):
        raise ValueError("acceptance suite authority is invalid")
    profiles = {"exhaustive": required_suites}
    bounded = acceptance.get("mutation_profiles", {}).get("bounded")
    if bounded is not None:
        if not isinstance(bounded, dict) or bounded.get("policy") != "bounded-reviewed-v1" or bounded.get("suite") != "mutation-bounded" or bounded.get("scheduled") != 18 or bounded.get("exhaustive") is not False:
            raise ValueError("bounded acceptance suite authority is invalid")
        if "signing_profile" in bounded and bounded["signing_profile"] != "publisher-beta":
            raise ValueError("bounded signing profile is invalid")
        legacy_signing = {"signing-macos", "signing-windows"} if bounded.get("signing_profile") == "publisher-beta" else set()
        profiles["bounded"] = [name for name in required_suites if not name.startswith("mutation-") and name not in legacy_signing] + [bounded["suite"]]
    default_profile = acceptance.get("default_test_mutation_profile", "exhaustive")
    if default_profile not in profiles:
        raise ValueError("default acceptance profile is not declared")
    declared_suites = list(dict.fromkeys(suite for suites in profiles.values() for suite in suites))
    ids, covered, rows = set(), set(), []
    fields = {"id", "requirement", "authorities", "implementation", "tests", "required_suites"}
    for row in requirements:
        if not isinstance(row, dict) or set(row) != fields or not isinstance(row["id"], str) or not row["id"] or row["id"] in ids or not isinstance(row["requirement"], str) or not row["requirement"]:
            raise ValueError("invalid or duplicate retained requirement")
        ids.add(row["id"])
        bound = {"id": row["id"], "requirement": row["requirement"]}
        for key in ("authorities", "implementation", "tests"):
            paths = row[key]
            if not isinstance(paths, list) or not paths or len(set(paths)) != len(paths):
                raise ValueError("empty or duplicate requirement linkage: " + row["id"])
            files = {item["path"]: item for name in paths for item in evidence(name)}
            bound[key] = [files[name] for name in sorted(files)]
        suites = row["required_suites"]
        if not isinstance(suites, list) or not suites or len(set(suites)) != len(suites) or not set(suites) <= set(declared_suites):
            raise ValueError("invalid requirement suite linkage: " + row["id"])
        covered.update(suites)
        bound["required_suites"] = suites
        bound["required_suites_by_profile"] = {name: [suite for suite in selected if suite in suites] for name, selected in profiles.items()}
        rows.append(bound)
    if covered != set(declared_suites):
        raise ValueError("required acceptance suites lack implementation/test linkage: " + ", ".join(sorted(set(declared_suites) - covered)))
    return {
        "schema_version": 1,
        "qualification": "requirements-implementation-test-linkage-not-execution-or-release-certification",
        "authority": evidence(AUTHORITY)[0],
        "acceptance_authority": evidence("quality/requirements.json")[0],
        "required_suites": required_suites,
        "default_test_mutation_profile": default_profile,
        "default_required_suites": profiles[default_profile],
        "required_suites_by_profile": profiles,
        "required_suite_union": declared_suites,
        "required_artifacts": acceptance["required_artifacts"],
        "policy": "Every retained requirement names existing source and original test bytes. The legacy required_suites field retains exhaustive compatibility; default_required_suites and required_suites_by_profile identify the selected policy without relabelling legacy mutation suites as the default. This inventory records no pass, kill, native execution, publisher authority or release certification. Acceptance must independently discover and execute the selected profile's complete inventories against one frozen source snapshot.",
        "requirements": rows,
    }


def main() -> None:
    if sys.argv[1:] not in ([], ["--check"]):
        raise SystemExit("Usage: implementation-inventory.py [--check]")
    value = inventory()
    body = json.dumps(value, indent=2, ensure_ascii=False) + "\n"
    target = ROOT / TARGET
    if sys.argv[1:] == ["--check"]:
        if not target.is_file() or target.read_text(encoding="utf-8") != body:
            raise SystemExit("Requirements implementation inventory is stale.")
    else:
        target.write_text(body, encoding="utf-8")
    print(f"Linked {len(value['requirements'])} retained requirements; default {value['default_test_mutation_profile']} has {len(value['default_required_suites'])} suites, legacy exhaustive has {len(value['required_suites'])}; execution remains separately required.")


if __name__ == "__main__":
    main()
