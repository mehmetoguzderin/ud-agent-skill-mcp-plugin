#!/usr/bin/env python3
"""Export shared schemas and dispatch bindings from the canonical JSON catalog."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CHECK = False

def write(path: Path, value: str) -> None:
    if CHECK:
        if not path.is_file() or path.read_text(encoding="utf-8") != value:
            raise ValueError(f"generated file is stale: {path.relative_to(ROOT)}")
    else:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value, encoding="utf-8")


def inventory() -> list[dict]:
    records = json.loads((ROOT / "contracts/ud-interfaces.json").read_text(encoding="utf-8"))
    if not isinstance(records, list) or len(records) != 102:
        raise ValueError("canonical catalog must contain exactly IDs 001–102")
    names = set()
    fields = {"id", "name", "original_signature", "upstream_provenance", "handler", "runtime_pack", "output_schema", "access", "parameters"}
    for index, item in enumerate(records, 1):
        if not isinstance(item, dict) or set(item) != fields or item["id"] != f"{index:03}":
            raise ValueError("invalid canonical operation identity or fields")
        name = item["name"]
        if not isinstance(name, str) or not re.fullmatch(r"[a-z_]+", name) or name in names:
            raise ValueError("invalid or duplicate canonical operation name")
        names.add(name)
        signature = re.fullmatch(re.escape(name) + r"\(([^()]*)\)", item["original_signature"])
        parameters = item["parameters"]
        if not signature or not isinstance(parameters, list) or not all(
            isinstance(value, dict) and set(value) == {"name", "required"}
            and isinstance(value["name"], str) and re.fullmatch(r"[a-z_]+", value["name"])
            and type(value["required"]) is bool for value in parameters
        ):
            raise ValueError("invalid canonical signature or parameters: " + name)
        parameter_names = [value["name"] for value in parameters]
        if len(set(parameter_names)) != len(parameter_names) or parameter_names != [value.strip() for value in signature[1].split(",") if value.strip()]:
            raise ValueError("canonical signature/parameter mismatch: " + name)
        if not isinstance(item["handler"], str) or not re.fullmatch(r"ud_agent\.domain\.[a-z_]+:" + re.escape(name), item["handler"]):
            raise ValueError("invalid canonical handler: " + name)
        if item["runtime_pack"] not in {"core", "render"} or item["upstream_provenance"] not in set("DPCOXN") or item["output_schema"] != f"contracts/schema/results/{name}.schema.json":
            raise ValueError("invalid canonical runtime/provenance/result: " + name)
        access = item["access"]
        if not isinstance(access, dict) or set(access) != {"writes_workspace", "writes_outputs", "executes_project_code"} or not all(type(value) is bool for value in access.values()):
            raise ValueError("invalid canonical access: " + name)
    return records


def main() -> None:
    catalog = inventory()
    input_shapes = json.loads((ROOT / "contracts/input-shapes.json").read_text(encoding="utf-8"))
    if input_shapes.get("schema_version") != 1 or set(input_shapes.get("operations", {})) != {item["name"] for item in catalog}:
        raise ValueError("input contracts must cover exactly the canonical operations")
    text = json.dumps(catalog, indent=2, ensure_ascii=False) + "\n"
    # JSON is authored authority; the YAML mirror and dispatch/schema bindings are derived.
    write(ROOT / "contracts/ud-interfaces.yaml", text)
    write(ROOT / "workers/ud/src/ud_agent/userspace_operations.json",
        json.dumps([item["name"] for item in catalog if item["id"] != "050"], indent=2) + "\n",
    )
    reference = {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "file_path": {"type": "string", "minLength": 1},
            "sent_id": {"type": "string", "minLength": 1},
            "ordinal": {"type": "integer", "minimum": 0},
            "fingerprint": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
        },
        "required": ["file_path"],
        "anyOf": [
            {"properties": {"sent_id": {}}, "required": ["sent_id"]},
            {"properties": {"ordinal": {}, "fingerprint": {}}, "required": ["ordinal", "fingerprint"]},
        ],
    }
    token_ref = {
        "type": "object", "additionalProperties": False,
        "properties": {"tree_ref": reference, "token_id": {"type": "string", "pattern": "^[1-9][0-9]*$"}},
        "required": ["tree_ref", "token_id"],
    }
    array_names = {
        "columns", "dimensions", "fix_ids", "selected_action_ids", "token_ids",
        "new_sent_ids", "file_paths", "input_paths", "source_file_paths", "target_file_paths",
        "peer_file_paths", "related_repository_paths", "peer_treebank_paths", "affected_treebank_paths",
        "source_annotation_paths", "source_tokenization_paths", "source_segmentation_paths",
        "gold_file_paths", "prediction_file_paths",
    }
    object_names = {
        "options", "edit_options", "read_options", "matching_options", "token_patch", "metadata_patch",
        "multiword_token_patch", "empty_node_data", "empty_node_patch", "annotation_map", "token_data",
        "attachment_spec", "removal_spec", "multiword_token_patch", "lexeme_filter",
        "paradigm_filter", "relation_filter", "features", "misc_entries",
    }
    array_objects = {"tree_refs", "edit_batch", "repository_specs", "edit_operations", "edge_operations", "incoming_edges", "enhanced_edges"}

    def parameter(name: str) -> dict:
        if name == "tree_ref":
            return reference
        if name == "token_ref":
            return token_ref
        if name == "tree_refs":
            return {"type": "array", "items": reference, "minItems": 1}
        if name == "annotation_map":
            attrs = {"anyOf": [{"type": "string"}, {"type": "object"}, {"type": "array"}, {"type": "null"}]}
            edge = {"type": "object", "additionalProperties": False,
                    "properties": {"head_id": {"type": "string", "minLength": 1}, "deprel": {"type": "string", "minLength": 1}},
                    "required": ["head_id", "deprel"]}
            fields = {field: {"type": "string"} for field in ("form", "lemma", "upos", "xpos", "head", "deprel")}
            fields.update(feats=attrs, misc=attrs, deps={"type": "array", "items": edge})
            row_types = []
            for kind in ("word", "empty", "multiword"):
                properties = {"id": {"type": "string", "minLength": 1}, "kind": {"const": kind}}
                required = ["id", "kind"]
                if kind == "word":
                    properties.update(fields)
                    required += list(fields)
                elif kind == "empty":
                    properties.update({field: value for field, value in fields.items() if field not in ("head", "deprel")})
                    properties["after_word_id"] = {"type": "string", "minLength": 1}
                    required += [field for field in fields if field not in ("head", "deprel")] + ["after_word_id"]
                else:
                    properties.update(form={"type": "string"}, misc=attrs,
                                      components={"type": "array", "minItems": 2, "uniqueItems": True, "items": {"type": "string", "minLength": 1}})
                    required += ["form", "misc", "components"]
                row_types.append({"type": "object", "additionalProperties": False, "properties": properties, "required": required})
            legacy_target = {"type": "object", "additionalProperties": False,
                             "properties": {"sent_id": {"type": "string"}, "conllu": {"type": "string"}},
                             "required": ["sent_id", "conllu"]}
            typed_target = {"type": "object", "additionalProperties": False,
                            "properties": {"sent_id": {"type": "string", "minLength": 1}, "text": {"type": "string"},
                                           "comments": {"type": "array", "items": {"type": "string", "pattern": "^#"}},
                                           "rows": {"type": "array", "minItems": 1, "items": {"oneOf": row_types}}},
                            "required": ["sent_id", "text", "comments", "rows"]}
            return {
                "type": "object", "additionalProperties": False,
                "properties": {
                    "id_mapping": {"type": "object", "additionalProperties": {"type": "array", "items": {"type": "string"}}},
                    "created": {"type": "array", "items": {"type": "string"}},
                    "sentences": {"type": "array", "items": {"oneOf": [legacy_target, typed_target]}},
                    "decisions": {"type": "object", "additionalProperties": False,
                        "properties": {item: {"const": "explicit"} for item in ("basic", "enhanced", "surface", "metadata")}},
                    "unresolved": {"type": "array", "items": {"type": "string"}},
                },
            }
        if name == "replacement_words":
            return {"type": "array", "minItems": 2, "items": {"anyOf": [{"type": "string"}, {"type": "object"}]}}
        if name == "merged_word":
            return {"anyOf": [{"type": "string"}, {"type": "object"}]}
        if name in array_names or name.endswith("_paths"):
            return {"type": "array", "items": {"type": "string"}}
        if name in array_objects:
            return {"type": "array", "items": {"type": "object"}}
        if name == "split_boundaries":
            return {"type": "array", "items": {"type": "string"}, "minItems": 1}
        if name in object_names:
            return {"type": "object"}
        if name == "seed":
            return {"type": "integer"}
        if name in {"feature_values", "attribute_values"}:
            return {"type": "array", "items": {"type": "string"}}
        if name == "insertion_point":
            return {"anyOf": [{"type": "object"}, {"type": "string"}, {"type": "integer"}]}
        return {"type": "string"}

    schema_dir = ROOT / "contracts/schema/operations"
    def input_refs(value):
        if isinstance(value, list): return [input_refs(item) for item in value]
        if isinstance(value, dict): return {key: (item.replace("#/definitions/", "#/$defs/") if key == "$ref" else input_refs(item)) for key, item in value.items()}
        return value
    def prune_definitions(schema):
        """Keep the exact transitive contract without repeating unrelated types."""
        definitions = schema.get("$defs", {})
        selected, pending = {}, []
        def references(value):
            if isinstance(value, list):
                for item in value: references(item)
            elif isinstance(value, dict):
                reference = value.get("$ref")
                if isinstance(reference, str) and reference.startswith("#/$defs/"):
                    pending.append(reference.removeprefix("#/$defs/"))
                for key, item in value.items():
                    if key != "$defs": references(item)
        references(schema)
        while pending:
            name = pending.pop()
            if name in selected: continue
            if name not in definitions: raise ValueError(f"undefined contract reference: {name}")
            selected[name] = definitions[name]
            references(definitions[name])
        return {**schema, "$defs": {name: selected[name] for name in sorted(selected)}}
    environment = json.loads((ROOT / "contracts/environment.json").read_text(encoding="utf-8"))
    environment_result = {"type": "object", "required": ["requested_tools", "platform", "working_tree_changes", "status", "ready"], "properties": {
        "requested_tools": {"type": "array", "items": {"type": "string"}}, "platform": {"type": "object", "required": ["os", "arch"], "properties": {"os": {"type": "string"}, "arch": {"type": "string"}}},
        "working_tree_changes": {"type": "array", "items": {"type": "string"}}, "status": {"type": "string"}, "ready": {"type": "boolean"},
        "runtime": {"type": "object", "properties": {"engine": {"enum": ["apple-container", "wslc", "lima-nerdctl", "podman", "docker-rootless", "docker", "userspace"]}, "executable": {"type": ["string", "null"]}, "isolation_model": {"type": "string"}, "rootless_verified": {"type": ["boolean", "null"]}, "worker_uid_verified": {"type": "boolean"}, "verification": {"type": "string"}, "selection_reason": {"type": "string"}, "available_operations": {"type": "array", "items": {"type": "string"}}}},
        "missing": {"type": "array", "items": {"type": "string"}}, "host_prerequisites": {"type": "array", "items": {"type": "string"}}, "actions": {"type": "array", "items": {"type": "string"}}, "dry_run": {"type": "boolean"}, "reason": {"type": "string"}, "mode": {"enum": ["ensure", "repair", "update", "resume"]}, "network": {"enum": ["bootstrap_only", "offline"]}}}
    for operation in catalog:
        inputs = operation["parameters"]
        schema = {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "title": operation["name"],
            "type": "object",
            "additionalProperties": False,
            "$defs": input_refs(input_shapes["definitions"]),
            "properties": input_refs(input_shapes["operations"][operation["name"]]),
            "required": [item["name"] for item in inputs if item["required"]],
        }
        write(schema_dir / f'{operation["name"]}.input.schema.json', json.dumps(prune_definitions(schema), indent=2, ensure_ascii=False) + "\n")

    environment_properties = {
        "working_tree_path": {"type": "string", "minLength": 1},
        "required_tools": {"type": "array", "minItems": 1, "uniqueItems": True, "items": {"type": "string", "minLength": 1}},
        "engine": {"enum": ["auto", "apple-container", "wslc", "lima-nerdctl", "podman", "docker-rootless", "docker", "userspace"]},
        "offline": {"type": "boolean"},
        "mode": {"enum": ["ensure", "repair", "update", "resume"]},
        "network": {"enum": ["bootstrap_only", "offline"]},
        "dry_run": {"type": "boolean"},
        "continuation_token": {"type": "string", "minLength": 1},
        "target_release": {"type": "string", "minLength": 1},
    }
    for operation in json.loads((ROOT / "contracts/environment.json").read_text(encoding="utf-8")):
        schema = {
            "$schema": "https://json-schema.org/draft/2020-12/schema", "title": operation["name"],
            "type": "object", "additionalProperties": False,
            "properties": {p["name"]: environment_properties[p["name"]] for p in operation["parameters"]},
        }
        write(schema_dir / f'{operation["name"]}.input.schema.json', json.dumps(schema, indent=2) + "\n")

    shapes = json.loads((ROOT / "contracts/result-shapes.json").read_text(encoding="utf-8"))
    if shapes["schema_version"] != 1 or set(shapes["operations"]) != {item["name"] for item in catalog}:
        raise ValueError("result contracts must cover exactly all 102 domain operations")
    def refs(value):
        if isinstance(value, list): return [refs(item) for item in value]
        if isinstance(value, dict): return {key: (item.replace("#/definitions/", "#/$defs/") if key == "$ref" else refs(item)) for key, item in value.items()}
        return value
    def public_result(value):
        if isinstance(value, list): return [public_result(item) for item in value]
        if not isinstance(value, dict): return value
        result = {key: public_result(item) for key, item in value.items()}
        for name in ("requires_host_export", "requires_broker_export"):
            if isinstance(result.get("properties"), dict) and result["properties"].get(name) == {"const": True}:
                result["properties"][name] = {"type": "boolean"}
        return result
    resource = {"type": "object", "required": ["uri", "mime_type", "size_bytes", "sha256", "retention"], "properties": {"uri": {"type": "string", "pattern": "^ud://"}, "mime_type": {"type": "string"}, "size_bytes": {"type": "integer", "minimum": 0}, "sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"}, "retention": {"type": "object", "required": ["expires_at"], "properties": {"expires_at": {"type": "string"}}}}}
    definitions = public_result(refs(shapes["definitions"]))
    definitions["artifact"]["anyOf"].append({"allOf": [resource, {"type": "object", "required": ["relative_path"], "properties": {"relative_path": {"type": "string"}}}]})
    for operation in [*catalog, *environment]:
        schema = {"$schema": "https://json-schema.org/draft/2020-12/schema", "title": operation["name"] + " result", "type": "object",
            "required": ["schema_version", "operation", "operation_id", "execution", "scope", "inputs", "provenance", "result", "diagnostics", "artifacts", "coverage", "limitations"],
            "properties": {"schema_version": {"const": "1"}, "operation": {"const": operation["name"]}, "operation_id": {"const": operation["id"]},
                "execution": {"type": "object", "required": ["status", "elapsed_ms"], "properties": {"status": {"enum": ["completed", "rejected", "incomplete"]}, "elapsed_ms": {"type": "integer", "minimum": 0}}},
                "scope": {"type": "object"}, "inputs": {"type": "object"}, "provenance": {"type": "object", "required": ["product_version"], "properties": {"product_version": {"const": "0.1.0-beta.1"}}},
                "result": {"type": "object"}, "diagnostics": {"type": "array"}, "artifacts": {"type": "array", "items": resource}, "coverage": {"type": "object"}, "limitations": {"type": "array", "items": {"type": "string"}}},
            "$defs": definitions,
            "allOf": [{"if": {"properties": {"execution": {"type": "object", "properties": {"status": {"const": "completed"}}, "required": ["status"]}}, "required": ["execution"]}, "then": {"properties": {"result": {"anyOf": [public_result(refs(shapes["operations"].get(operation["name"], environment_result))), {"type": "object", "required": ["status", "report_resource", "summary"], "properties": {"status": {"const": "resource"}, "report_resource": resource, "summary": {"type": "object"}}}], "allOf": [{"if": {"type": "object", "required": [name], "properties": {name: {"const": False}}}, "then": {"type": "object", "required": ["exports", "export_transaction"], "properties": {"exports": {"type": "array", "minItems": 1, "items": {"type": "object", "required": ["path", "sha256", "size_bytes"], "properties": {"path": {"type": "string"}, "sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"}, "size_bytes": {"type": "integer", "minimum": 0}}}}, "export_transaction": {"type": "object", "required": ["status"], "properties": {"status": {"const": "completed"}}}}}} for name in ("requires_host_export", "requires_broker_export")]}}}}]}
        write(ROOT / operation.get("output_schema", f'contracts/schema/results/{operation["name"]}.schema.json'), json.dumps(prune_definitions(schema), ensure_ascii=False, indent=2) + "\n")
    handlers = {item["name"]: item["handler"].removeprefix("ud_agent.domain.").split(":") for item in catalog}
    write(ROOT / "workers/ud/src/ud_agent/generated_catalog.py", '"""Generated from contracts/ud-interfaces.json; run scripts/generate/contracts.py."""\nHANDLERS = ' + repr(handlers) + '\n')
    union = " | ".join(json.dumps(item["name"]) for item in catalog)
    metadata = [{key: item[key] for key in ("id", "name", "runtime_pack", "handler", "output_schema", "access")} for item in catalog]
    write(ROOT / "packages/coordinator/src/generated-contracts.ts", '// Generated from contracts/ud-interfaces.json and shared contracts.\nexport type DomainOperationName = ' + union + ';\nexport const domainMetadata = ' + json.dumps(metadata, ensure_ascii=False, indent=2) + ' as const;\n')


if __name__ == "__main__":
    if sys.argv[1:] not in ([], ["--check"]): raise SystemExit("Usage: contracts.py [--check]")
    CHECK = sys.argv[1:] == ["--check"]
    main()
