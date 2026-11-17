"""Loop-compatible local server for the registry's MLX artifacts (LFM3, Bonsai). MIT.

Diagnostic only. It serves the exact registry artifacts with the pinned MLX-VLM
0.7.11 runtime (Apple-silicon GPU by default, which is what these artifacts target),
so the focused improvement loop can run the same groups, seeds and harnesses as
MiniCPM (`loop-run --model-id lfm3|bonsai`). Prompts are rendered and preprocessed
by the repository's native-pipeline helper (runtime.tokenize_chat). Tool calls are
parsed by the same XML parser as the MiniCPM loop server: both artifacts' chat
templates print <tool_call><function=...><parameter=...> blocks.

On Linux, MLX has only a CPU backend: it links the reference BLAS, has no native
bfloat16 arithmetic and no optimized quantized prefill kernel. --cpu-throughput
(opt-in; set UD_MLX_CPU_BLAS to an OpenBLAS with the CBLAS ABI) makes calls with many activation rows use a cached
bfloat16 dequantization of the same quantized weights, multiplied in float32, and
unquantized parameters are upcast to float32 (exact values; MLX's CPU backend has
no native bfloat16 arithmetic); single-token decoding keeps the native quantized kernel. This is
a throughput patch, not a model change, and it is recorded in the runtime identity.
"""
import argparse
import hashlib
import importlib.metadata
import importlib.util
import json
import os
import random
import sys
import threading
import time
import uuid
from http.server import ThreadingHTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent
ARTIFACTS = {"lfm3_vl": "LiquidAI/LFM3-VL-2B-MLX-5bit", "prism_hadamard_qwen35": "prism-ml/Ternary-Bonsai-2-2B-mlx-2bit"}
# Registry sampling (evals/local/registry.mjs); fields the loop does not send keep these values.
SAMPLING = {
    "lfm3_vl": {"temperature": 0.1, "top_p": 1.0, "top_k": 50, "repetition_penalty": 1.1},
    "prism_hadamard_qwen35": {"temperature": 0.7, "top_p": 0.8, "top_k": 20, "min_p": 0.0, "repetition_penalty": 1.0,
                              "presence_penalty": 1.5, "presence_context_size": 64},
}
MAX_CONTEXT = 32768
MAX_OUTPUT = 512


def _module(name, file):
    spec = importlib.util.spec_from_file_location(name, file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


base = _module("ud_loop_minicpm_server", HERE / "minicpm_server.py")
runtime = _module("ud_loop_runtime", HERE / "runtime.py")


def install_prefill_dequantization(mx, min_rows=16):
    """Route many-row quantized matmuls through a cached float32 dequantization."""
    native = mx.quantized_matmul
    cache = {}
    stats = {"dequantized_weights": 0, "dequantized_calls": 0, "native_calls": 0}

    def patched(x, w, scales, biases=None, transpose=True, group_size=64, bits=4, mode="affine", **kwargs):
        rows = 1
        for size in x.shape[:-1]:
            rows *= size
        if rows < min_rows or not transpose or mode != "affine" or biases is None or kwargs:
            stats["native_calls"] += 1
            return native(x, w, scales, biases, transpose=transpose, group_size=group_size, bits=bits, mode=mode, **kwargs)
        key = (id(w), group_size, bits)
        entry = cache.get(key)
        if entry is None or entry[0] is not w:
            dense = mx.dequantize(w, scales, biases, group_size=group_size, bits=bits).astype(mx.bfloat16)
            mx.eval(dense)
            entry = (w, dense)
            cache[key] = entry
            stats["dequantized_weights"] += 1
        stats["dequantized_calls"] += 1
        return mx.matmul(x.astype(mx.float32), entry[1].astype(mx.float32).T).astype(x.dtype)

    mx.quantized_matmul = patched
    return stats


class Backend:
    """MLX streams are thread-local, so one owned worker thread loads and runs everything."""
    def __init__(self, directory, evidence_directory, generation_seconds=300, prefill_dequantized=False, device="auto"):
        from concurrent.futures import ThreadPoolExecutor
        self.worker = ThreadPoolExecutor(max_workers=1, thread_name_prefix="mlx")
        self.worker.submit(self._load, directory, evidence_directory, generation_seconds, prefill_dequantized, device).result()

    def prepare(self, body, *, count_only=False):
        return self.worker.submit(self._prepare, body, count_only=count_only).result()

    def generate(self, body, prepared, cancelled, streamer=None):
        return self.worker.submit(self._generate, body, prepared, cancelled).result()

    def _load(self, directory, evidence_directory, generation_seconds, prefill_dequantized, device):
        import mlx.core as mx
        if importlib.metadata.version("mlx-vlm") != "0.7.11":
            raise RuntimeError("MLX_VLM_0_7_11_REQUIRED")
        gpu = mx.is_available(mx.gpu) if hasattr(mx, "is_available") else mx.default_device() == mx.gpu
        if device == "gpu" and not gpu:
            raise ValueError("DEVICE_UNAVAILABLE:gpu")
        self.device = "gpu" if device in ("auto", "gpu") and gpu else "cpu"
        mx.set_default_device(mx.gpu if self.device == "gpu" else mx.cpu)
        if prefill_dequantized:
            mx.set_cache_limit(512 * 1024 * 1024)
        self.mx = mx
        self.evidence = base.GenerationEvidence(evidence_directory)
        self.directory = str(Path(directory).resolve(strict=True))
        config = json.loads((Path(self.directory) / "config.json").read_text())
        self.model_type = config.get("model_type")
        if self.model_type not in ARTIFACTS:
            raise ValueError("REGISTRY_MLX_ARTIFACT_REQUIRED")
        self.artifact = ARTIFACTS[self.model_type]
        self.sampling = SAMPLING[self.model_type]
        self.generation_seconds = generation_seconds
        self.prefill_stats = install_prefill_dequantization(mx) if prefill_dequantized else None
        if self.model_type == "prism_hadamard_qwen35":
            sys.path.insert(0, str(Path(self.directory) / "runtime"))
            from vision_artifact import load_vl_model
            self.model, self.processor, _ = load_vl_model(self.directory)
        else:
            from mlx_vlm.utils import load
            self.model, self.processor = load(self.directory)
        if prefill_dequantized:
            # MLX's CPU backend has no native bfloat16 arithmetic, so bfloat16 activations
            # run about 7x slower. Upcast the unquantized parameters (norms, convolutions,
            # quantization scales and biases, vision tower) to float32: exact values, float32 compute.
            from mlx.utils import tree_map
            self.model.update(tree_map(lambda a: a.astype(mx.float32) if a.dtype in (mx.bfloat16, mx.float16) else a,
                                       self.model.parameters()))
        self.lock = threading.Lock()
        self.runtime_identity = {
            "runtime": "mlx-vlm", "version": "0.7.11", "mlx": importlib.metadata.version("mlx"),
            "device": self.device, "artifact": self.artifact, "model_type": self.model_type,
            "quantization": config.get("quantization"),
            "cpu_throughput": {"prefill": "cached-bfloat16-dequantized-same-weights-float32-matmul",
                               "activations": "float32-upcast"} if prefill_dequantized else None,
            "blas_preload": os.environ.get("LD_PRELOAD", ""),
            "qualification": "diagnostic-not-registry-qualification"}

    def _prepare(self, body, *, count_only=False):
        if not isinstance(body, dict) or body.get("model") not in (self.directory, self.artifact):
            raise ValueError("MODEL_NOT_ADMITTED")
        allowed = {"model", "messages", "tools", "tool_choice", "seed", "stream", "max_tokens", "max_completion_tokens",
                   "temperature", "top_p", "top_k", "min_p", "repetition_penalty"}
        if set(body) - allowed:
            raise ValueError("REQUEST_FIELD_UNSUPPORTED:" + ",".join(sorted(set(body) - allowed)))
        if body.get("tool_choice", "auto") not in (None, "auto") or body.get("stream", False):
            raise ValueError("REQUEST_MODE_UNSUPPORTED")
        effective = {**self.sampling, **{k: body[k] for k in ("temperature", "top_p", "top_k", "min_p", "repetition_penalty") if k in body}}
        seed = body.get("seed", 17)
        limits = [body[k] for k in ("max_tokens", "max_completion_tokens") if k in body]
        maximum = limits[0] if limits else MAX_OUTPUT
        if not count_only and not 1 <= maximum <= MAX_OUTPUT:
            raise ValueError("OUTPUT_LIMIT_INVALID")
        request = {"messages": body["messages"], **({"tools": body["tools"]} if body.get("tools") else {})}
        inputs, _, _, prompt = runtime.tokenize_chat(request, self.directory, return_prepared=True)
        ids = inputs["input_ids"]
        count = int(ids.shape[-1])
        if not count_only and count + maximum > MAX_CONTEXT:
            raise ValueError("CONTEXT_ENVELOPE_EXCEEDED")
        return (inputs, prompt), count, maximum, effective, seed

    def _generate(self, body, prepared, cancelled):
        from mlx_vlm.generate.dispatch import stream_generate
        mx = self.mx
        (inputs, prompt), count, maximum, effective, seed = prepared
        arrays = {}
        for key, value in inputs.items():
            if value is None:
                continue
            name = "mask" if key == "attention_mask" else key
            arrays[name] = value if isinstance(value, mx.array) else mx.array(value)
        random.seed(seed)
        mx.random.seed(seed)
        deadline = time.monotonic() + self.generation_seconds
        started_ns = time.time_ns()
        text, tokens, termination = "", [], "stopped"
        for response in stream_generate(self.model, self.processor, prompt, max_tokens=maximum, **effective, **arrays):
            text += response.text
            if response.token is not None:
                tokens.append(int(response.token))
            if response.finish_reason:
                termination = "eos" if response.finish_reason == "stop" else "length" if response.finish_reason == "length" else response.finish_reason
            if cancelled.is_set():
                termination = "cancelled"
                break
            if time.monotonic() >= deadline:
                termination = "deadline"
                break
        if termination == "stopped" and len(tokens) >= maximum:
            termination = "length"
        observation = {"schema_version": 1, "model": self.directory, "artifact": self.artifact, "seed": seed,
                       "started_at_ns": started_ns, "recorded_at_ns": time.time_ns(),
                       "request_sha256": hashlib.sha256(json.dumps(body, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
                       "prompt_tokens": count, "completion_tokens": len(tokens), "maximum_tokens": maximum,
                       "termination": termination, "token_ids": tokens, "text": text, "parser_status": "not_attempted",
                       "prefill": dict(self.prefill_stats) if self.prefill_stats is not None else None}
        identifier = uuid.uuid4().hex
        try:
            if termination in ("cancelled", "deadline"):
                raise ValueError("GENERATION_CANCELLED")
            message = base.parse_output(text, body.get("tools", []), lenient=getattr(self, "tool_parser", "strict") == "lenient")
            observation["parser_status"] = "accepted"
            finish = "length" if termination == "length" else "tool_calls" if message.get("tool_calls") else "stop"
            if finish == "length" and message.get("tool_calls"):
                raise ValueError("TOOL_OUTPUT_TRUNCATED")
        except ValueError as error:
            observation["parser_status"] = "rejected" if termination not in ("cancelled", "deadline") else "not_attempted"
            observation["dispatch_eligible"] = False
            observation["failure"] = type(error).__name__ + ":" + str(error)[:500]
            self.evidence.write(identifier, observation)
            if termination in ("cancelled", "deadline"):
                raise
            message = {"role": "assistant", "content": text}
            finish = "length" if termination == "length" else "stop"
        else:
            observation["dispatch_eligible"] = True
            self.evidence.write(identifier, observation)
        return {"id": "chatcmpl_" + uuid.uuid4().hex, "object": "chat.completion", "created": int(time.time()),
                "model": self.directory, "choices": [{"index": 0, "message": message, "finish_reason": finish}],
                "usage": {"prompt_tokens": count, "completion_tokens": len(tokens), "total_tokens": count + len(tokens)}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", required=True)
    parser.add_argument("--host", default="127.0.0.1", choices=["127.0.0.1"])
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--evidence-directory", required=True)
    parser.add_argument("--device", default="auto", choices=["auto", "gpu", "cpu", "mps"], help="mps is accepted as the loop's name for the Apple GPU.")
    parser.add_argument("--generation-seconds", default=300, type=int)
    parser.add_argument("--tool-parser", default="strict", choices=["strict", "lenient"])
    parser.add_argument("--cpu-throughput", action="store_true",
                        help="Linux CPU only: cached dequantized prefill and float32 activations (same weights).")
    args = parser.parse_args()
    blas = os.environ.get("UD_MLX_CPU_BLAS")
    if blas and os.environ.get("LD_PRELOAD") != blas:
        # MLX's Linux CPU wheel links the reference BLAS; an OpenBLAS with the standard CBLAS ABI
        # (UD_MLX_CPU_BLAS) is preloaded for this server process only.
        if not Path(blas).is_absolute() or not Path(blas).is_file():
            parser.error("UD_MLX_CPU_BLAS must name an existing absolute shared library.")
        os.execve(sys.executable, [sys.executable, *sys.argv], {**os.environ, "LD_PRELOAD": blas})
    if not Path(args.model).is_absolute() or not 1 <= args.port <= 65535 or not 1 <= args.generation_seconds <= 3600:
        parser.error("An absolute artifact directory, a valid port and 1..3600 generation seconds are required.")
    backend = Backend(args.model, args.evidence_directory, args.generation_seconds,
                      prefill_dequantized=args.cpu_throughput or os.environ.get("UD_MLX_CPU_THROUGHPUT") == "1",
                      device="gpu" if args.device == "mps" else args.device)
    backend.tool_parser = args.tool_parser
    base.ARTIFACT = backend.artifact
    server = ThreadingHTTPServer((args.host, args.port), base.handler_for(backend))
    server.daemon_threads = True
    server.serve_forever(poll_interval=0.1)


if __name__ == "__main__":
    main()
