"""Source-bound MLX-VLM 0.7.11 transport interoperability patches. MIT.

The installed private runtime remains byte-identical. XML parameter decoding and
Messages metadata projection are patched in memory; native generation and
templates remain owned by MLX-VLM. Importing never imports MLX or loads models.
"""
import hashlib
import importlib.metadata
import importlib.util
import inspect
import json
from pathlib import Path
import sys

EXPECTED = {
    "streaming": "4d88b210cb966c166f06ebe7459dbc09c4e24480e678ef287bb917cd390cb0c5",
    "parser": "28584fbef4c44d80753fbd1dbcda00cfd4248f0d99c40deb85b02b9b110c0bc1",
}
EXPECTED_MESSAGES = "6e9ec4ac974db64608d96ef7fb6b12ece5eeaa9dbfdae3538659807b5264f4e9"
EXPECTED_GENERATION = "7d19bafb1fcd8d0427572920d545130deabd024c3483f240bdcb0cf7b2ddcd1a"


def observe_model_load(generation, version, identity_function):
    """Observe the objects returned by the pinned native loader, without replacing it."""
    if version != "0.7.11":
        raise RuntimeError("MLX_LOAD_OBSERVER_VERSION_UNVERIFIED")
    source = Path(inspect.getsourcefile(generation))
    if hashlib.sha256(source.read_bytes()).hexdigest() != EXPECTED_GENERATION:
        raise RuntimeError("MLX_LOAD_OBSERVER_SOURCE_UNVERIFIED")
    original = generation.load_model_resources
    observation = {}

    def loaded(model_path, adapter_path):
        observation.clear()
        if adapter_path:
            raise RuntimeError("EXACT_MODEL_ADAPTER_UNSUPPORTED")
        model, processor, config = original(model_path, adapter_path)
        observation.update(identity_function(model_path, model, processor, original))
        return model, processor, config

    generation.load_model_resources = loaded
    return observation


def decoder_module():
    source = Path(__file__).with_name("minicpm_server.py")
    spec = importlib.util.spec_from_file_location("ud_local_xml_decoder", source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def patch_modules(streaming, parser, version):
    """Fail closed on an unknown source; safe to exercise with inert modules."""
    if version != "0.7.11":
        raise RuntimeError("MLX_XML_PATCH_VERSION_UNVERIFIED")
    sources = {"streaming": Path(inspect.getsourcefile(streaming)),
               "parser": Path(inspect.getsourcefile(parser))}
    hashes = {name: hashlib.sha256(file.read_bytes()).hexdigest()
              for name, file in sources.items()}
    if hashes != EXPECTED:
        raise RuntimeError("MLX_XML_PATCH_SOURCE_UNVERIFIED")
    decoder = decoder_module()
    original_get = parser._get_arguments_config
    original_convert = parser._convert_param_value

    def get_arguments(name, tools):
        properties = original_get(name, tools)
        root = next((tool["function"].get("parameters", {}) for tool in (tools or [])
                     if tool.get("function", {}).get("name") == name), {})
        # Resolve only type information used by this decoder, retaining native
        # handling of scalar schemas and other parser behavior.
        result = {}
        for key, schema in properties.items():
            if isinstance(schema, dict) and any(item in schema for item in ("$ref", "anyOf", "oneOf", "allOf")):
                result[key] = {**schema, "type": sorted(decoder.schema_types(schema, root))}
            else:
                result[key] = schema
        return result

    def convert(value, name, properties):
        schema = properties.get(name, {})
        if isinstance(schema, dict) and isinstance(schema.get("type"), list):
            return decoder.parameter_value(value, {"type": schema["type"]})
        return original_convert(value, name, properties)

    def string_parameter(schema, string_types):
        kind = schema.get("type") if isinstance(schema, dict) else None
        # Do not stream an ambiguous union's argument prefix. Its exact value
        # will be emitted once the parameter is closed and strictly decoded.
        return isinstance(kind, str) and kind in string_types

    text = inspect.getsource(streaming._xml_call)
    old = 'properties.get(key, {}).get(\n                "type"\n            ) in module._string_types'
    if text.count(old) != 1:
        raise RuntimeError("MLX_XML_PATCH_EXPRESSION_UNVERIFIED")
    text = text.replace(old, '_ud_string_parameter(properties.get(key, {}), module._string_types)')
    namespace = {**streaming.__dict__, "_ud_string_parameter": string_parameter}
    exec(compile(text, "<ud-local-mlx-xml-schema-patch>", "exec"), namespace)
    streaming._xml_call = namespace["_xml_call"]
    parser._get_arguments_config = get_arguments
    parser._convert_param_value = convert
    return {"patch": "ud-local-mlx-xml-schema-v1", "runtime": "mlx-vlm",
            "version": version, "sources": [{"path": str(sources[name]), "sha256": hashes[name]}
                                             for name in sorted(sources)],
            "installed_files_changed": False, "semantic_argument_repairs": False}


def patch_messages_module(native, version):
    """Keep native generation/token counting; project unsupported wire metadata."""
    if version != "0.7.11":
        raise RuntimeError("MLX_MESSAGES_PATCH_VERSION_UNVERIFIED")
    source = Path(inspect.getsourcefile(native))
    source_hash = hashlib.sha256(source.read_bytes()).hexdigest()
    if source_hash != EXPECTED_MESSAGES:
        raise RuntimeError("MLX_MESSAGES_PATCH_SOURCE_UNVERIFIED")
    helper = Path(__file__).with_name("messages_protocol.py")
    spec = importlib.util.spec_from_file_location("ud_local_messages_protocol", helper)
    protocol = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(protocol)
    original = native._anthropic_messages_to_internal

    def messages_to_internal(request):
        projected, _evidence = protocol.normalize_messages_request(
            request.model_dump(mode="python", exclude_none=True))
        return original(type(request).model_validate(projected))

    native._anthropic_messages_to_internal = messages_to_internal
    return {"patch": "ud-local-mlx-messages-v1", "runtime": "mlx-vlm", "version": version,
            "sources": [{"path": str(source), "sha256": source_hash},
                        {"path": str(helper), "sha256": hashlib.sha256(helper.read_bytes()).hexdigest()}],
            "installed_files_changed": False, "semantic_argument_repairs": False,
            "context_edit": "only-exact-keep-all-noop", "deferred_tools": "native-result-reference-only",
            "definition_placement": "local-chat-template-tool-section"}


def main():
    from mlx_vlm.tools import streaming
    from mlx_vlm.tools.parsers import qwen3_coder
    receipt = patch_modules(streaming, qwen3_coder, importlib.metadata.version("mlx-vlm"))
    print(json.dumps({"event": "runtime_patch", **receipt}), flush=True)
    from mlx_vlm.server import anthropic
    receipt = patch_messages_module(anthropic, importlib.metadata.version("mlx-vlm"))
    print(json.dumps({"event": "runtime_patch", **receipt}), flush=True)
    import mlx.core as mx
    from mlx.utils import tree_flatten
    from mlx_vlm.server import generation
    spec = importlib.util.spec_from_file_location("ud_runtime_identity", Path(__file__).with_name("runtime_identity.py"))
    identity = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(identity)
    observed = observe_model_load(generation, importlib.metadata.version("mlx-vlm"),
                                  lambda directory, model, processor, loader:
                                  identity.mlx_identity(directory, model, processor, mx, tree_flatten, loader))
    app_module = importlib.import_module("mlx_vlm.server.app")
    from fastapi import Request, HTTPException
    # FastAPI resolves this annotation in module globals.
    globals()["Request"] = Request

    async def runtime_identity(request: Request):
        app_module._require_management_api_key(request)
        current = app_module._server_runtime_snapshot()
        if not observed or current.get("loaded_model") != observed.get("model"):
            raise HTTPException(status_code=503, detail="LOADED_RUNTIME_IDENTITY_UNAVAILABLE")
        return observed

    app_module.app.add_api_route("/local-eval/runtime-identity", runtime_identity, methods=["GET"])
    from mlx_vlm.server import main as native_main
    native_main()


if __name__ == "__main__":
    main()
