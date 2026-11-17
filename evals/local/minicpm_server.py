"""Bounded, single-model MiniCPM NF4 Chat transport. Importing never loads weights.

Uses the exact artifact's published AutoProcessor/AutoModelForImageTextToText
recipe and XML tool grammar in chat_template.jinja. No agent loop or tool repair.
SPDX-License-Identifier: MIT
"""
import argparse
import base64
import copy
import io
import json
import hashlib
import importlib.util
import math
import os
import stat
import queue
import random
import re
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ARTIFACT = "openbmb/MiniCPM-V-4.7-1B-int4"
MAX_CONTEXT = 32768
MAX_OUTPUT = 512
MAX_BYTES = 16 * 1024 * 1024
LOCK_GRACE_SECONDS = 5
SAMPLING = {"temperature": 0.7, "top_p": 0.95, "top_k": 100,
            "min_p": 0.0, "repetition_penalty": 1.03,
            "presence_penalty": 0, "enable_thinking": False,
            "top_n_sigma": 0, "p_less": False, "typical_p": 1,
            "frequency_penalty": None, "repetition_context_size": None,
            "presence_context_size": None, "frequency_context_size": None}
NEUTRAL = {"presence_penalty": (None, 0), "frequency_penalty": (None, 0),
           "top_n_sigma": (0,), "p_less": (False,),
           "repetition_context_size": (None,), "presence_context_size": (None,),
           "frequency_context_size": (None,)}
GENERATION_FIELDS = ("temperature", "top_p", "top_k", "min_p",
                     "repetition_penalty", "typical_p")


def strict_json(value):
    def invalid_constant(_value):
        raise ValueError("NONFINITE_JSON")
    def finite_float(raw):
        value = float(raw)
        if not math.isfinite(value):
            raise ValueError("NONFINITE_JSON")
        return value
    return json.loads(value, parse_constant=invalid_constant, parse_float=finite_float)


def integer(value):
    return isinstance(value, int) and not isinstance(value, bool)


def validate_request(body, model, *, count_only=False):
    if not isinstance(body, dict) or body.get("model") not in (model, ARTIFACT):
        raise ValueError("MODEL_NOT_ADMITTED")
    allowed = {"model", "messages", "tools", "tool_choice", "seed", "stream",
               "stream_options", "max_tokens", "max_completion_tokens", "n",
               "context_management", "chat_template_kwargs", *SAMPLING}
    if set(body) - allowed:
        raise ValueError("REQUEST_FIELD_UNSUPPORTED:" + ",".join(sorted(set(body) - allowed)))
    if body.get("context_management", []) != [] or body.get("n", 1) != 1:
        raise ValueError("REQUEST_MULTIGENERATION_UNSUPPORTED")
    if body.get("enable_thinking", False) is not False or body.get("chat_template_kwargs", {}) not in ({}, {"enable_thinking": False}):
        raise ValueError("THINKING_DISABLED")
    if body.get("tool_choice", "auto") not in (None, "auto"):
        raise ValueError("TOOL_CHOICE_UNSUPPORTED")
    if not isinstance(body.get("stream", False), bool):
        raise ValueError("STREAM_INVALID")
    if body.get("stream_options", {}) not in ({}, {"include_usage": True}, {"include_usage": False}):
        raise ValueError("STREAM_OPTIONS_UNSUPPORTED")
    for name, allowed_values in NEUTRAL.items():
        value = body.get(name, SAMPLING[name])
        if value not in allowed_values:
            raise ValueError("SAMPLER_UNSUPPORTED:" + name)
    effective = {**SAMPLING, **{name: body[name] for name in SAMPLING if name in body}}
    for name in GENERATION_FIELDS:
        value = effective[name]
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not float("-inf") < value < float("inf"):
            raise ValueError("SAMPLER_INVALID:" + name)
    if not 0 < effective["temperature"] <= 2 or not 0 < effective["top_p"] <= 1 or not 0 <= effective["min_p"] <= 1 or not 0 < effective["typical_p"] <= 1 or effective["repetition_penalty"] <= 0 or not integer(effective["top_k"]) or effective["top_k"] < 0:
        raise ValueError("SAMPLER_INVALID")
    seed = body.get("seed", 17)
    if not integer(seed) or not 0 <= seed <= 0xffffffff:
        raise ValueError("SEED_INVALID")
    limits = [body[name] for name in ("max_tokens", "max_completion_tokens") if name in body]
    ceiling = 2**31 - 1 if count_only else MAX_OUTPUT
    if any(not integer(value) or not 1 <= value <= ceiling for value in limits) or len(set(limits)) > 1:
        raise ValueError("OUTPUT_LIMIT_INVALID")
    maximum = limits[0] if limits else MAX_OUTPUT
    messages = body.get("messages")
    if not isinstance(messages, list) or not messages:
        raise ValueError("MESSAGES_REQUIRED")
    tools = body.get("tools", [])
    if not isinstance(tools, list) or len(tools) > 256:
        raise ValueError("TOOLS_INVALID")
    names = set()
    for tool in tools:
        if not isinstance(tool, dict) or tool.get("type") != "function" or not isinstance(tool.get("function"), dict):
            raise ValueError("TOOL_SCHEMA_UNSUPPORTED")
        function = tool["function"]
        name = function.get("name")
        if not isinstance(name, str) or not re.fullmatch(r"[\w.:-]+", name) or name in names or not isinstance(function.get("parameters", {}), dict):
            raise ValueError("TOOL_SCHEMA_INVALID")
        names.add(name)
    return effective, seed, maximum


def normalize_messages(messages):
    """Transport normalization only; every external image is supplied as bytes."""
    result = copy.deepcopy(messages)
    images = 0
    for message in result:
        if not isinstance(message, dict) or message.get("role") not in ("system", "user", "assistant", "tool"):
            raise ValueError("MESSAGE_ROLE_UNSUPPORTED")
        content = message.get("content")
        if isinstance(content, list):
            normalized = []
            for part in content:
                if not isinstance(part, dict):
                    raise ValueError("CONTENT_INVALID")
                if part.get("type") == "text" and isinstance(part.get("text"), str):
                    normalized.append({"type": "text", "text": part["text"]})
                elif part.get("type") == "image_url" and message["role"] == "user":
                    url = part.get("image_url", {}).get("url")
                    if not isinstance(url, str) or not re.match(r"^data:image/(?:png|jpeg|webp);base64,", url):
                        raise ValueError("INLINE_IMAGE_REQUIRED")
                    raw = base64.b64decode(url.split(",", 1)[1], validate=True)
                    if len(raw) > 8 * 1024 * 1024:
                        raise ValueError("IMAGE_TOO_LARGE")
                    from PIL import Image
                    image = Image.open(io.BytesIO(raw))
                    if image.width * image.height > 16_000_000:
                        raise ValueError("IMAGE_TOO_LARGE")
                    image.load()
                    normalized.append({"type": "image", "image": image.convert("RGB")})
                    images += 1
                else:
                    raise ValueError("CONTENT_TYPE_UNSUPPORTED")
            message["content"] = normalized
        elif content is None and message["role"] == "assistant" and isinstance(message.get("tool_calls"), list):
            message["content"] = ""
        elif not isinstance(content, str):
            raise ValueError("CONTENT_INVALID")
        if "tool_calls" in message:
            if message["role"] != "assistant" or not isinstance(message["tool_calls"], list):
                raise ValueError("TOOL_HISTORY_INVALID")
            for call in message["tool_calls"]:
                if not isinstance(call, dict) or call.get("type") != "function" or not isinstance(call.get("function"), dict):
                    raise ValueError("TOOL_HISTORY_INVALID")
                function = call["function"]
                if isinstance(function.get("arguments"), str):
                    function["arguments"] = strict_json(function["arguments"])
                if not isinstance(function.get("arguments"), dict):
                    raise ValueError("TOOL_ARGUMENTS_INVALID")
    if images > 4:
        raise ValueError("IMAGE_COUNT_EXCEEDED")
    return result


def schema_types(schema, root=None, depth=0):
    """Resolve decoding types without changing the declared schema or argument."""
    universe = {"string", "integer", "number", "boolean", "object", "array", "null"}
    if schema is True:
        return universe
    if schema is False:
        return set()
    if not isinstance(schema, dict) or depth > 16:
        raise ValueError("TOOL_PARAMETER_SCHEMA_UNSUPPORTED")
    root = schema if root is None else root
    if "$ref" in schema:
        reference = schema["$ref"]
        if not isinstance(reference, str) or not reference.startswith("#/"):
            raise ValueError("TOOL_PARAMETER_SCHEMA_UNSUPPORTED")
        resolved = root
        try:
            for key in reference[2:].split("/"):
                resolved = resolved[key.replace("~1", "/").replace("~0", "~")]
        except (KeyError, TypeError):
            raise ValueError("TOOL_PARAMETER_SCHEMA_UNSUPPORTED") from None
        inherited = schema_types(resolved, root, depth + 1)
        siblings = {key: value for key, value in schema.items() if key != "$ref"}
        return inherited & schema_types(siblings, root, depth + 1) if any(key in siblings for key in ("type", "anyOf", "oneOf", "allOf")) else inherited
    kind = schema.get("type")
    if isinstance(kind, str):
        kinds = {kind}
    elif isinstance(kind, list) and kind and all(isinstance(item, str) for item in kind):
        kinds = set(kind)
    elif kind is None:
        kinds = None
    else:
        raise ValueError("TOOL_PARAMETER_SCHEMA_UNSUPPORTED")
    values = schema.get("enum", [schema["const"]] if "const" in schema else None)
    if values is not None:
        if not isinstance(values, list) or not values:
            raise ValueError("TOOL_PARAMETER_SCHEMA_UNSUPPORTED")
        inferred = {name for name in universe if any(value_kind_matches(value, name) for value in values)}
        kinds = inferred if kinds is None else kinds & inferred
    for composition in ("anyOf", "oneOf", "allOf"):
        if composition in schema:
            branches = schema[composition]
            if not isinstance(branches, list) or not branches:
                raise ValueError("TOOL_PARAMETER_SCHEMA_UNSUPPORTED")
            alternatives = [schema_types(branch, root, depth + 1) for branch in branches]
            combined = set.intersection(*alternatives) if composition == "allOf" else set.union(*alternatives)
            kinds = combined if kinds is None else kinds & combined
    # Constraint-only branches such as {required:[...]} do not constrain JSON
    # types. They must not erase an enclosing type:object during projection.
    kinds = universe if kinds is None else kinds
    if kinds - universe:
        raise ValueError("TOOL_PARAMETER_TYPE_UNSUPPORTED")
    return kinds


def value_kind_matches(value, kind):
    return {"integer": integer(value) or isinstance(value, float) and value.is_integer(), "number": isinstance(value, (int, float)) and not isinstance(value, bool),
            "boolean": isinstance(value, bool), "object": isinstance(value, dict),
            "array": isinstance(value, list), "null": value is None,
            "string": isinstance(value, str)}[kind]


def parameter_value(raw, schema, root=None):
    """Decode XML values, including nullable/composed/local-reference schemas.

    Scalar strings preserve every byte. For a union, a valid JSON value matching
    a non-string alternative is decoded; otherwise a permitted string stays raw.
    No coercion, missing-field insertion or partial JSON repair is performed.
    """
    value = raw.removeprefix("\n").removesuffix("\n")
    kinds = schema_types(schema, root)
    if kinds == {"string"}:
        return value
    try:
        decoded = strict_json(value)
    except (ValueError, TypeError):
        if "string" in kinds:
            return value
        raise ValueError("TOOL_PARAMETER_TYPE_MISMATCH") from None
    if any(value_kind_matches(decoded, kind) for kind in kinds - {"string"}):
        return decoded
    if "string" in kinds:
        return value
    raise ValueError("TOOL_PARAMETER_TYPE_MISMATCH")


class GenerationEvidence:
    """Immutable raw generations outside agent roots; nothing is printed to logs."""
    def __init__(self, directory):
        if os.name != "posix":
            raise ValueError("PRIVATE_GENERATION_PLATFORM_UNSUPPORTED")
        selected = Path(directory)
        if not selected.is_absolute() or selected.is_symlink():
            raise ValueError("PRIVATE_GENERATION_EVIDENCE_REQUIRED")
        selected.mkdir(parents=True, exist_ok=True, mode=0o700)
        info = selected.stat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ValueError("PRIVATE_GENERATION_EVIDENCE_REQUIRED")
        self.directory = selected.resolve(strict=True)

    def write(self, identifier, value):
        filename = self.directory / (identifier + ".json")
        payload = (json.dumps(value, ensure_ascii=False, allow_nan=False) + "\n").encode()
        descriptor = os.open(filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        return {"id": identifier, "sha256": hashlib.sha256(payload).hexdigest()}


def parse_output(text, tools, lenient=False):
    """Parse the format printed by this artifact's chat template.

    Strict (default) rejects undeclared names, unknown, missing or mistyped
    parameters. ``lenient`` mirrors the serving parsers for this XML format
    (vLLM qwen3_coder, llama.cpp): the syntax must still be complete and
    unambiguous, but names and parameters are passed through as written --
    an undeclared parameter or a value that does not convert stays a raw
    string, and required keys are not checked -- so the host or tool server
    reports its own specific error. Nothing is inserted or repaired.
    """
    if "<tool_call>" not in text:
        if any(marker in text for marker in ("<tool_call", "</tool_call", "<function=", "<parameter=")):
            raise ValueError("TOOL_ARGUMENTS_INCOMPLETE")
        return {"role": "assistant", "content": text}
    prefix, remaining = text.split("<tool_call>", 1)
    remaining = "<tool_call>" + remaining
    functions = {tool["function"]["name"]: tool["function"] for tool in tools}
    calls = []
    while remaining.strip():
        match = re.match(r"\s*<tool_call>\s*<function=([^>\s]+)>\n?([\s\S]*?)</function>\s*</tool_call>", remaining)
        if not match:
            raise ValueError("TOOL_ARGUMENTS_INCOMPLETE")
        name, parameters = match.group(1, 2)
        if name not in functions and not lenient:
            raise ValueError("TOOL_NAME_UNDECLARED")
        schema = functions.get(name, {}).get("parameters", {})
        properties = schema.get("properties", {})
        arguments = {}
        while parameters.strip():
            parameter = re.match(r"\s*<parameter=([^>\s]+)>([\s\S]*?)</parameter>", parameters)
            if not parameter or parameter[1] in arguments or (parameter[1] not in properties and not lenient):
                raise ValueError("TOOL_ARGUMENTS_INVALID")
            if parameter[1] not in properties:
                arguments[parameter[1]] = parameter[2].removeprefix("\n").removesuffix("\n")
            elif lenient:
                try:
                    arguments[parameter[1]] = parameter_value(parameter[2], properties[parameter[1]], schema)
                except ValueError:
                    arguments[parameter[1]] = parameter[2].removeprefix("\n").removesuffix("\n")
            else:
                arguments[parameter[1]] = parameter_value(parameter[2], properties[parameter[1]], schema)
            parameters = parameters[parameter.end():]
            # A repeated closing tag right after a closed parameter is a stray
            # token, not new content; serving parsers for this XML format (vLLM,
            # llama.cpp qwen3-coder) locate parameters by tag and ignore it too.
            parameters = re.sub(r"^(?:\s*</parameter>)+", "", parameters)
        if not lenient and any(key not in arguments for key in schema.get("required", [])):
            raise ValueError("TOOL_ARGUMENTS_MISSING")
        calls.append({"id": "call_" + uuid.uuid4().hex, "type": "function", "function": {
            "name": name, "arguments": json.dumps(arguments, ensure_ascii=False, separators=(",", ":"))}})
        remaining = remaining[match.end():]
    return {"role": "assistant", "content": prefix or None, "tool_calls": calls}


def openapi():
    properties = {name: {"default": value} for name, value in SAMPLING.items()}
    properties.update({name: {} for name in ("model", "messages", "tools", "tool_choice", "seed", "stream", "stream_options", "max_tokens", "max_completion_tokens", "context_management")})
    request = {"requestBody": {"content": {"application/json": {"schema": {
        "type": "object", "required": ["model", "messages"], "properties": properties}}}}}
    return {"openapi": "3.1.0", "info": {"title": "Bounded exact MiniCPM local transport", "version": "1"},
            "paths": {"/v1/chat/completions": {"post": request}, "/chat/input_tokens": {"post": request}}}


def select_device(torch, requested=None):
    """Exact NF4 weights on the best local device: MPS (macOS), CUDA, then CPU.

    The artifact is never converted; bitsandbytes provides NF4 kernels for each.
    """
    requested = requested or os.environ.get("UD_EVAL_DEVICE") or "auto"
    available = {"mps": bool(getattr(torch.backends, "mps", None) and torch.backends.mps.is_available()),
                 "cuda": bool(torch.cuda.is_available()), "cpu": True}
    if requested == "auto":
        return next(name for name in ("mps", "cuda", "cpu") if available[name])
    if requested not in available or not available[requested]:
        raise ValueError("DEVICE_UNAVAILABLE:" + str(requested))
    return requested


def avx512_repack_supported(module):
    """Shapes bitsandbytes' CPU NF4 repack can reshape: out % 32 == 0 and in % blocksize == 0."""
    state = getattr(getattr(module, "weight", None), "quant_state", None)
    blocksize = getattr(state, "blocksize", 64) or 64
    return getattr(module, "out_features", 0) % 32 == 0 and getattr(module, "in_features", 0) % blocksize == 0


class Backend:
    def __init__(self, directory, evidence_directory=None, device=None, generation_seconds=90):
        self.evidence = GenerationEvidence(evidence_directory) if evidence_directory is not None else None
        import torch
        from transformers import AutoModelForImageTextToText, AutoProcessor
        self.directory = str(Path(directory).resolve(strict=True))
        config = strict_json((Path(self.directory) / "config.json").read_text())
        quantization = config.get("quantization_config", {})
        if config.get("model_type") != "minicpmv4_7" or quantization.get("bnb_4bit_quant_type") != "nf4" or quantization.get("load_in_4bit") is not True:
            raise ValueError("EXACT_NF4_ARTIFACT_REQUIRED")
        self.processor = AutoProcessor.from_pretrained(self.directory, local_files_only=True)
        self.device = select_device(torch, device)
        self.generation_seconds = generation_seconds
        self.model = AutoModelForImageTextToText.from_pretrained(
            self.directory, local_files_only=True, device_map=self.device, torch_dtype="auto").eval()
        if self.device == "cpu":
            # bitsandbytes' AVX512-BF16 NF4 repacking needs out_features divisible by 32 and in_features
            # divisible by the quantization block size (the vision MLP's fc2 has in_features 4304 = 67.25 x 64);
            # other layers keep the generic exact NF4 kernel. Weights are never converted.
            for module in self.model.modules():
                if getattr(module, "support_avx512bf16_for_cpu", False) and not avx512_repack_supported(module):
                    module.support_avx512bf16_for_cpu = False
        self.torch = torch
        self.lock = threading.Lock()
        spec = importlib.util.spec_from_file_location("ud_runtime_identity", Path(__file__).with_name("runtime_identity.py"))
        identity_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(identity_module)
        self.runtime_identity = identity_module.minicpm_identity(self.directory, self.model, self.processor, self.device)

    def prepare(self, body, *, count_only=False):
        effective, seed, maximum = validate_request(body, self.directory, count_only=count_only)
        messages = normalize_messages(body["messages"])
        inputs = self.processor.apply_chat_template(
            messages, tools=body.get("tools"), tokenize=True, add_generation_prompt=True,
            return_dict=True, return_tensors="pt", downsample_mode="16x",
            max_slice_nums=36, enable_thinking=False)
        count = int(inputs["input_ids"].shape[-1])
        if not count_only and count + maximum > MAX_CONTEXT:
            raise ValueError("CONTEXT_ENVELOPE_EXCEEDED")
        return inputs, count, maximum, effective, seed

    def generate(self, body, prepared, cancelled, streamer=None):
        from transformers import StoppingCriteria, StoppingCriteriaList
        inputs, count, maximum, effective, seed = prepared
        deadline = time.monotonic() + getattr(self, "generation_seconds", 90)
        started_ns = time.time_ns()

        class BoundedStop(StoppingCriteria):
            def __call__(self, input_ids, scores, **kwargs):
                return cancelled.is_set() or time.monotonic() >= deadline

        random.seed(seed)
        self.torch.manual_seed(seed)
        if getattr(self, "device", "mps") == "mps":
            self.torch.mps.manual_seed(seed)
        import numpy
        numpy.random.seed(seed)
        with self.torch.inference_mode():
            result = self.model.generate(
                **inputs.to(self.model.device), downsample_mode="16x", max_new_tokens=maximum,
                do_sample=True, **{name: effective[name] for name in GENERATION_FIELDS},
                num_return_sequences=1, stopping_criteria=StoppingCriteriaList([BoundedStop()]),
                **({"streamer": streamer} if streamer is not None else {}))
        generated = result[0, count:]
        output_tokens = int(generated.shape[-1])
        token_ids = [int(token) for token in generated.tolist()]
        if len(token_ids) != output_tokens or output_tokens > maximum:
            raise ValueError("GENERATED_TOKEN_SHAPE_INVALID")
        text = self.processor.tokenizer.decode(generated, skip_special_tokens=True, clean_up_tokenization_spaces=False)
        eos = self.model.generation_config.eos_token_id
        ended = bool(output_tokens and token_ids[-1] in (eos if isinstance(eos, list) else [eos]))
        termination = "cancelled" if cancelled.is_set() else "deadline" if time.monotonic() >= deadline else "eos" if ended else "length" if output_tokens >= maximum else "stopped"
        observation = {"schema_version": 1, "model": self.directory, "seed": seed,
                       "started_at_ns": started_ns, "recorded_at_ns": time.time_ns(),
                       "request_sha256": hashlib.sha256(json.dumps(body, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest(),
                       "prompt_tokens": count, "completion_tokens": output_tokens,
                       "maximum_tokens": maximum, "termination": termination,
                       "token_ids": token_ids, "text": text, "parser_status": "not_attempted"}
        identifier = uuid.uuid4().hex
        evidence = getattr(self, "evidence", None)
        try:
            if termination in ("cancelled", "deadline"):
                raise ValueError("GENERATION_CANCELLED")
            message = parse_output(text, body.get("tools", []), lenient=getattr(self, "tool_parser", "strict") == "lenient")
            observation["parser_status"] = "accepted"
            finish = "length" if termination == "length" else "tool_calls" if message.get("tool_calls") else "stop"
            if finish == "length" and message.get("tool_calls"):
                raise ValueError("TOOL_OUTPUT_TRUNCATED")
        except Exception as error:
            if observation["parser_status"] == "not_attempted" and termination not in ("cancelled", "deadline"):
                observation["parser_status"] = "rejected"
            observation["dispatch_eligible"] = False
            observation["failure"] = type(error).__name__ + ":" + str(error)[:500]
            if evidence is not None:
                evidence.write(identifier, observation)
            # A complete generation containing invalid tool syntax is still an
            # assistant turn. Preserve its exact decoded text and measured usage
            # so the native harness can apply its own bounded format recovery.
            # Never publish an unparsed call, guess arguments, or hide a runtime
            # failure behind prose. The private token receipt must already exist.
            if (isinstance(error, ValueError) and evidence is not None and
                    str(error) in {"TOOL_ARGUMENTS_INCOMPLETE", "TOOL_NAME_UNDECLARED",
                                   "TOOL_ARGUMENTS_INVALID", "TOOL_ARGUMENTS_MISSING",
                                   "TOOL_PARAMETER_TYPE_MISMATCH", "TOOL_OUTPUT_TRUNCATED"} and
                    termination not in ("cancelled", "deadline")):
                message = {"role": "assistant", "content": text}
                finish = "length" if termination == "length" else "stop"
            else:
                raise
        else:
            observation["dispatch_eligible"] = True
            if evidence is not None:
                evidence.write(identifier, observation)
        return {"id": "chatcmpl_" + uuid.uuid4().hex, "object": "chat.completion", "created": int(time.time()),
                "model": self.directory, "choices": [{"index": 0, "message": message, "finish_reason": finish}],
                "usage": {"prompt_tokens": count, "completion_tokens": output_tokens, "total_tokens": count + output_tokens}}


def handler_for(backend):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, pattern, *args):
            # Do not write prompts, credentials or image bytes to server logs.
            print(json.dumps({"event": "http", "method": self.command, "route": self.path.split("?")[0], "status": str(args[1]) if len(args) > 1 else "unknown"}), flush=True)

        def json(self, status, body):
            payload = json.dumps(body, ensure_ascii=False, allow_nan=False).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def do_GET(self):
            if self.path == "/health":
                self.json(200, {"status": "ok", "artifact": ARTIFACT, "model": backend.directory,
                                "runtime_identity": backend.runtime_identity})
            elif self.path == "/local-eval/runtime-identity":
                self.json(200, backend.runtime_identity)
            elif self.path in ("/models", "/v1/models"):
                self.json(200, {"object": "list", "data": [{"id": backend.directory, "object": "model"}]})
            elif self.path == "/openapi.json":
                self.json(200, openapi())
            else:
                self.close_connection = True
                self.json(404, {"error": {"message": "ROUTE_UNSUPPORTED"}})

        def sse(self, value):
            data = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
            self.wfile.write(("data: " + data + "\n\n").encode())
            self.wfile.flush()

        def stream(self, body, prepared, cancelled):
            from transformers import TextIteratorStreamer
            streamer = TextIteratorStreamer(backend.processor.tokenizer, skip_prompt=True,
                                            skip_special_tokens=True, clean_up_tokenization_spaces=False, timeout=0.25)
            result = queue.Queue()

            def generate():
                try:
                    result.put((True, backend.generate(body, prepared, cancelled, streamer)))
                except Exception as error:
                    result.put((False, error))
                    streamer.end()

            worker = threading.Thread(target=generate, daemon=True)
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Connection", "close")
            self.end_headers()
            self.close_connection = True
            worker.start()
            identifier = "chatcmpl_" + uuid.uuid4().hex
            base = {"id": identifier, "object": "chat.completion.chunk", "created": int(time.time()), "model": backend.directory}
            text, emitted, holding = "", 0, False
            try:
                self.sse({**base, "choices": [{"index": 0, "delta": {"role": "assistant"}, "finish_reason": None}]})
                until = time.monotonic() + 90
                while True:
                    if time.monotonic() > until:
                        raise ValueError("GENERATION_TIMEOUT")
                    try:
                        fragment = next(streamer)
                    except queue.Empty:
                        if not worker.is_alive():
                            break
                        continue
                    except StopIteration:
                        break
                    text += fragment
                    # Hold potential XML until strict parsing; never expose tool syntax as prose.
                    if not holding:
                        safe = text.find("<", emitted)
                        holding = safe >= 0
                        end = safe if holding else len(text)
                        if end > emitted:
                            self.sse({**base, "choices": [{"index": 0, "delta": {"content": text[emitted:end]}, "finish_reason": None}]})
                            emitted = end
                worker.join(timeout=max(0, until - time.monotonic()))
                if worker.is_alive():
                    raise ValueError("GENERATION_TIMEOUT")
                ok, response = result.get_nowait()
                if not ok:
                    raise response
                choice = response["choices"][0]
                content = choice["message"].get("content") or ""
                if not content.startswith(text[:emitted]):
                    raise ValueError("STREAM_CONTENT_MISMATCH")
                if len(content) > emitted:
                    self.sse({**base, "choices": [{"index": 0, "delta": {"content": content[emitted:]}, "finish_reason": None}]})
                for index, call in enumerate(choice["message"].get("tool_calls", [])):
                    self.sse({**base, "choices": [{"index": 0, "delta": {"tool_calls": [{"index": index, **call}]}, "finish_reason": None}]})
                self.sse({**base, "choices": [{"index": 0, "delta": {}, "finish_reason": choice["finish_reason"]}]})
                self.sse({**base, "choices": [], "usage": response["usage"]})
                self.sse("[DONE]")
            finally:
                cancelled.set()
                # The campaign owns the process group for a blocked MPS kernel; no new
                # request may enter this backend while the generation worker survives.
                worker.join(timeout=1)
                if worker.is_alive():
                    raise RuntimeError("GENERATION_WORKER_UNRELEASED")

        def do_POST(self):
            if self.path not in ("/chat/completions", "/v1/chat/completions", "/chat/input_tokens", "/v1/chat/input_tokens"):
                self.close_connection = True
                self.json(404, {"error": {"message": "ROUTE_UNSUPPORTED"}})
                return
            # A keep-alive client may send its next request before the previous
            # handler thread has released the lock after writing its response, so
            # wait a short grace period; a real concurrent generation still gets 409.
            if not backend.lock.acquire(timeout=LOCK_GRACE_SECONDS):
                # Never leave an unread body on a kept-alive connection.
                self.close_connection = True
                self.json(409, {"error": {"message": "SINGLE_GENERATION_ACTIVE"}})
                return
            cancelled = threading.Event()
            release = True
            try:
                self.connection.settimeout(95)
                size = int(self.headers.get("Content-Length", "0"))
                if self.headers.get("Transfer-Encoding") or not 0 < size <= MAX_BYTES:
                    raise ValueError("REQUEST_SIZE_INVALID")
                raw = self.rfile.read(size)
                if len(raw) != size:
                    raise ValueError("REQUEST_TRUNCATED")
                body = strict_json(raw)
                prepared = backend.prepare(body, count_only=self.path.endswith("input_tokens"))
                if self.path.endswith("input_tokens"):
                    self.json(200, {"input_tokens": prepared[1], "trusted": True})
                elif body.get("stream"):
                    self.stream(body, prepared, cancelled)
                else:
                    self.json(200, backend.generate(body, prepared, cancelled))
            except (BrokenPipeError, ConnectionResetError):
                cancelled.set()
            except Exception as error:
                cancelled.set()
                if str(error) == "GENERATION_WORKER_UNRELEASED":
                    release = False
                if not self.close_connection:
                    self.json(422, {"error": {"type": "local_model_rejection", "message": str(error)[:500]}})
                else:
                    print(json.dumps({"event": "request_failed", "reason": type(error).__name__ + ":" + str(error)[:500]}), flush=True)
            finally:
                if release:
                    backend.lock.release()
    return Handler


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", required=True)
    parser.add_argument("--host", default="127.0.0.1", choices=["127.0.0.1"])
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--evidence-directory", required=True)
    parser.add_argument("--device", default="auto", choices=["auto", "mps", "cuda", "cpu"])
    parser.add_argument("--generation-seconds", default=90, type=int,
                        help="Per-request generation bound; CPU hosts need more than the 90-second default.")
    parser.add_argument("--tool-parser", default="strict", choices=["strict", "lenient"],
                        help="lenient passes names/parameters through like vLLM's qwen3_coder parser; syntax stays strict.")
    args = parser.parse_args()
    if not Path(args.model).is_absolute() or not 1 <= args.port <= 65535:
        parser.error("An absolute exact-artifact directory and valid loopback port are required.")
    if not 1 <= args.generation_seconds <= 3600:
        parser.error("--generation-seconds must be between 1 and 3600.")
    backend = Backend(args.model, args.evidence_directory, device=args.device, generation_seconds=args.generation_seconds)
    backend.tool_parser = args.tool_parser
    server = ThreadingHTTPServer((args.host, args.port), handler_for(backend))
    server.daemon_threads = True
    server.serve_forever(poll_interval=0.1)


if __name__ == "__main__":
    main()
