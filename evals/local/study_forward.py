"""Bounded, text-only mechanistic forwards on exact local artifacts. MIT.

JSONL worker: importing is inert. Each input is one charged forward pass. Native
fused attention remains in use; only the native prefix's final query row is summarized. No
sampling, agent loop, hidden answers or full attention tensors are produced.
"""
import argparse
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import sys
import time

ARTIFACTS = {
    "openbmb/MiniCPM-V-4.7-1B-int4": "minicpm",
    "LiquidAI/LFM3-VL-2B-MLX-5bit": "lfm3",
    "prism-ml/Ternary-Bonsai-2-2B-mlx-2bit": "bonsai",
}
ORDINARY_FORWARD_INPUT_LIMIT = 16384


def local_module(name):
    spec = importlib.util.spec_from_file_location("ud_forward_" + name, Path(__file__).with_name(name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def validate_probe(value):
    if not isinstance(value, dict) or not isinstance(value.get("request"), dict):
        raise ValueError("FORWARD_REQUEST_REQUIRED")
    messages = value["request"].get("messages")
    if not isinstance(messages, list) or any(not isinstance(message.get("content"), (str, type(None))) and
       not (isinstance(message.get("content"), list) and all(part.get("type") == "text" for part in message["content"]))
       for message in messages):
        raise ValueError("FORWARD_TEXT_ONLY")
    spans = value.get("spans", [])
    if not isinstance(spans, list) or len(spans) > 32 or any(not isinstance(span, dict) or not isinstance(span.get("name"), str) or
       not isinstance(span.get("start"), int) or not isinstance(span.get("end"), int) or not 0 <= span["start"] < span["end"] for span in spans):
        raise ValueError("FORWARD_SPANS_INVALID")
    texts = value.get("span_texts", [])
    if not isinstance(texts, list) or len(texts) + len(spans) > 32 or any(not isinstance(span, dict) or not isinstance(span.get("name"), str) or
       not isinstance(span.get("text"), str) or not 0 < len(span["text"].encode()) <= 128 * 1024 for span in texts):
        raise ValueError("FORWARD_SPAN_TEXTS_INVALID")
    continuation = value.get("continuation", "")
    if not isinstance(continuation, str) or len(continuation.encode()) > 8192:
        raise ValueError("FORWARD_CONTINUATION_INVALID")
    candidates = value.get("candidate_token_ids", [])
    if not isinstance(candidates, list) or len(candidates) > 64 or any(type(item) is not int or item < 0 for item in candidates):
        raise ValueError("FORWARD_CANDIDATES_INVALID")
    intervention = value.get("intervention")
    if intervention is not None and (not isinstance(intervention, dict) or intervention.get("kind") != "zero_operator_last_position" or
                                     type(intervention.get("layer")) is not int or intervention["layer"] < 0 or value.get("instrument", False) is not True):
        raise ValueError("FORWARD_INTERVENTION_INVALID")
    return value


def resolve_spans(tokenizer, token_ids, value):
    """Exact token subsequences only; boundary merges/duplicates stay unknown."""
    resolved = list(value.get("spans", []))
    observations = [{**span, "status": "resolved", "method": "explicit-token-range"} for span in resolved]
    for span in value.get("span_texts", []):
        needle = tokenizer.encode(span["text"], add_special_tokens=False)
        positions = [index for index, token in enumerate(token_ids) if needle and token == needle[0] and token_ids[index:index + len(needle)] == needle]
        observation = {"name": span["name"], "method": "exact-native-token-subsequence",
                       "text_sha256": hashlib.sha256(span["text"].encode()).hexdigest(),
                       "matched_occurrences": len(positions), "status": "resolved" if len(positions) == 1 else "unmatched" if not positions else "ambiguous"}
        if len(positions) == 1:
            selected = {"name": span["name"], "start": positions[0], "end": positions[0] + len(needle)}
            resolved.append(selected); observation.update(selected)
        observations.append(observation)
    return resolved, observations


def scoring_metadata(prompt_tokens, continuation):
    """Causal index t predicts token t+1, including the first continuation."""
    appended = continuation[:-1]
    total = prompt_tokens + len(appended)
    return {"continuation_token_ids": continuation, "input_appended_token_ids": appended,
            "prediction_positions": list(range(prompt_tokens - 1, total)) if continuation else [],
            "next_logits_position": prompt_tokens - 1, "attention_query_position": prompt_tokens - 1,
            "operator_observation_position": prompt_tokens - 1,
            "distribution": "base-model logits before sampler penalties or temperature",
            "sampled_tokens": 0}


def bounded_forward_tokens(prompt_tokens, continuation_tokens):
    """S2/S3 study forwards reserve ordinary input, including forced targets.

    This does not change the model server's separate S4 extended envelope.
    Check after tokenization and before any model forward or embedding lookup.
    """
    total = prompt_tokens + max(0, continuation_tokens - 1)
    if total > ORDINARY_FORWARD_INPUT_LIMIT:
        raise ValueError("FORWARD_CONTEXT_LIMIT")
    return total


def prefix_position(prompt_tokens, input_start, input_length):
    position = prompt_tokens - 1 - input_start
    if not 0 <= position < input_length:
        raise ValueError("FORWARD_PREFIX_POSITION_OUTSIDE_INPUT")
    return position


def attention_key_layout(total_tokens, key_tokens, query_tokens, cache=None):
    """Return physical-to-temporal key identity, or explicit unavailable.

    Pinned RotatingKVCache's multi-query _update_concat sets _idx to the full
    returned key length. Single-query in-place updates can expose a ring.
    Retained-prefix or unrecognized layouts cannot use one contiguous offset.
    """
    if not 0 < key_tokens <= total_tokens:
        return None
    order = list(range(key_tokens))
    if type(cache).__name__ == "RotatingKVCache":
        if getattr(cache, "keep", None) != 0 or getattr(cache, "offset", None) != total_tokens:
            return None
        index = getattr(cache, "_idx", None)
        if index == key_tokens:
            pass  # Native concatenation (or an unrotated full buffer).
        elif query_tokens == 1 and type(index) is int and 0 <= index < key_tokens and total_tokens >= key_tokens:
            order = order[index:] + order[:index]
        else:
            return None
    offset = total_tokens - key_tokens
    physical_positions = [0] * key_tokens
    for rank, physical in enumerate(order):
        physical_positions[physical] = offset + rank
    return {"temporal_order": order, "physical_positions": physical_positions, "key_offset": offset}


def attention_mask_query(mask_shape, query_position, query_tokens):
    if len(mask_shape) < 2:
        return None
    if mask_shape[-2] == 1:
        return 0
    if mask_shape[-2] == query_tokens and 0 <= query_position < query_tokens:
        return query_position
    raise ValueError("FORWARD_ATTENTION_MASK_QUERY_UNVERIFIED")


def attention_summary(rows, spans, key_offset=0):
    """Pure small-array reducer, also exercised without any model dependency."""
    if not rows or any(not row or any(not math.isfinite(value) or value < 0 for value in row) for row in rows):
        raise ValueError("ATTENTION_ROW_INVALID")
    size = len(rows[0])
    if any(len(row) != size or abs(sum(row) - 1) > 0.005 for row in rows):
        raise ValueError("ATTENTION_ROW_INVALID")
    result = []
    for span in spans:
        if key_offset == 0 and span["end"] > size:
            raise ValueError("FORWARD_SPAN_OUTSIDE_CONTEXT")
        start, end = max(0, span["start"] - key_offset), min(size, span["end"] - key_offset)
        covered = max(0, end - start)
        masses = [sum(row[start:end]) if covered else 0 for row in rows]
        result.append({"name": span["name"], "start": span["start"], "end": span["end"],
                       "covered_key_tokens": covered, "key_window_status": "complete" if covered == span["end"] - span["start"] else "partial" if covered else "outside",
                       "mass_by_head": masses, "mean_mass": sum(masses) / len(masses),
                       "mean_mass_per_token": sum(masses) / len(masses) / (span["end"] - span["start"])})
    entropy = [-sum(value * math.log(value) for value in row if value) for row in rows]
    return {"key_tokens": size, "key_offset": key_offset, "heads": len(rows), "query_rows": 1, "spans": result, "entropy_by_head": entropy}


class TorchForward:
    def __init__(self, directory):
        module = local_module("minicpm_server")
        self.backend = module.Backend(directory)
        self.torch = self.backend.torch
        self.model = self.backend.model
        self.layers = self.model.model.language_model.layers
        self.tokenizer = self.backend.processor.tokenizer
        if any(getattr(layer.self_attn.config, "_attn_implementation", None) in (None, "eager", "paged|eager")
               for layer in self.layers if hasattr(layer, "self_attn")):
            raise ValueError("FORWARD_NATIVE_FUSED_ATTENTION_REQUIRED")

    def run(self, value):
        torch = self.torch
        inputs, count, _, _, _ = self.backend.prepare(value["request"])
        prefix_ids = inputs["input_ids"].tolist()[0]
        spans, span_observations = resolve_spans(self.tokenizer, prefix_ids, value)
        suffix = self.tokenizer.encode(value.get("continuation", ""), add_special_tokens=False)
        if len(suffix) > 64:
            raise ValueError("FORWARD_CONTINUATION_TOKEN_LIMIT")
        bounded_forward_tokens(count, len(suffix))
        if suffix:
            inputs["input_ids"] = torch.cat([inputs["input_ids"], torch.tensor([suffix[:-1]], dtype=inputs["input_ids"].dtype)], dim=1)
            if "attention_mask" in inputs:
                inputs["attention_mask"] = torch.ones_like(inputs["input_ids"])
            if "mm_token_type_ids" in inputs:
                inputs["mm_token_type_ids"] = torch.zeros_like(inputs["input_ids"])
        total = int(inputs["input_ids"].shape[-1])
        query_position = prefix_position(count, 0, total)
        if any(span["end"] > count for span in value.get("spans", [])):
            raise ValueError("FORWARD_SPAN_OUTSIDE_CONTEXT")
        if value.get("intervention", {}).get("layer") not in (None, *[index for index, layer in enumerate(self.layers) if getattr(layer, "linear_attn", None) is not None]):
            raise ValueError("FORWARD_INTERVENTION_LAYER_UNSUPPORTED")
        attention, hybrid, handles = [], [], []
        implementation = None
        if value.get("instrument"):
            from transformers.models.qwen3_5 import modeling_qwen3_5 as architecture
            interface = architecture.ALL_ATTENTION_FUNCTIONS
            original_get = interface.get_interface

            def get_interface(name, default):
                native = original_get(name, default)
                def observed(module, queries, keys, values, mask, **kwargs):
                    if hasattr(module, "layer_idx"):
                        with torch.no_grad():
                            selected_position = prefix_position(count, 0, queries.shape[-2])
                            q = queries[:, :, selected_position:selected_position + 1, :].float()
                            k = keys.float().repeat_interleave(queries.shape[1] // keys.shape[1], dim=1)
                            scores = torch.matmul(q, k.transpose(-2, -1)) * kwargs.get("scaling", module.scaling)
                            if mask is not None:
                                row = attention_mask_query(mask.shape, selected_position, queries.shape[-2])
                                selected = mask[..., row:row + 1, :keys.shape[-2]] if row is not None else mask[..., :keys.shape[-2]]
                                scores = scores.masked_fill(~selected, float("-inf")) if selected.dtype == torch.bool else scores + selected
                            # SDPA can express causality without an explicit mask.
                            allowed = torch.arange(keys.shape[-2], device=queries.device) <= query_position
                            scores = scores.masked_fill(~allowed, float("-inf"))
                            rows = torch.softmax(scores, dim=-1)[0, :, 0, :].cpu().tolist()
                            attention.append({"layer": module.layer_idx, "query_position": query_position, **attention_summary(rows, spans)})
                    return native(module, queries, keys, values, mask, **kwargs)
                return observed

            interface.get_interface = get_interface
            implementation = (interface, original_get)
            intervention = value.get("intervention", {})
            for index, layer in enumerate(self.layers):
                operator = getattr(layer, "linear_attn", None)
                if operator is None:
                    continue
                def hook(module, arguments, output, index=index):
                    selected = output[:, query_position:query_position + 1, :].float()
                    hybrid.append({"layer": index, "operator": "linear_attention", "observation": "operator_output",
                                   "position": query_position,
                                   "last_position_l2": float(torch.linalg.vector_norm(selected).item())})
                    if intervention.get("layer") == index:
                        result = output.clone(); result[:, query_position:query_position + 1, :] = 0
                        return result
                handles.append(operator.register_forward_hook(hook))
        try:
            with torch.inference_mode():
                result = self.model(**inputs.to(self.model.device), use_cache=True, logits_to_keep=max(1, len(suffix)), downsample_mode="16x")
                logits = result.logits[0].float()
                log_probs = torch.log_softmax(logits, dim=-1)
                vector = logits[0].cpu().tolist()
                selected = [float(log_probs[index, token].item()) for index, token in enumerate(suffix)] if suffix else []
                candidates = [{"token_id": token, "log_probability": float(log_probs[0, token].item())}
                              for token in value.get("candidate_token_ids", [])]
                cache = result.past_key_values
                cache_states = []
                for index, layer in enumerate(getattr(cache, "layers", [])):
                    for name in ("recurrent_states", "conv_states"):
                        state = getattr(layer, name, None)
                        states = state if isinstance(state, (list, tuple)) else [state]
                        for slot, item in enumerate(states):
                            if torch.is_tensor(item):
                                cache_states.append({"layer": index, "state": name, "slot": slot, "shape": list(item.shape),
                                                     "l2": float(torch.linalg.vector_norm(item.float()).item())})
            observation = self.result(vector, selected, candidates, attention, hybrid, count, total, cache_states)
            observation["prefix_token_ids_sha256"] = hashlib.sha256(json.dumps(prefix_ids, separators=(",", ":")).encode()).hexdigest()
            observation["span_observations"] = span_observations
            observation["teacher_forcing"] = scoring_metadata(count, suffix)
            observation["intervention_position"] = query_position if value.get("intervention") else None
            return observation
        finally:
            for handle in handles:
                handle.remove()
            if implementation:
                implementation[0].get_interface = implementation[1]

    @staticmethod
    def result(vector, selected, candidates, attention, hybrid, count, total, cache_states=None):
        return {"status": "observed", "input_tokens": count, "forward_tokens": total, "generated_tokens": 0,
                "next_logits_position": count - 1, "attention_query_position": count - 1, "operator_observation_position": count - 1,
                "cache_states_position": total - 1,
                "next_logits": vector, "continuation_log_probabilities": selected,
                "candidate_log_probabilities": candidates, "attention": attention, "hybrid": hybrid,
                "cache_states": cache_states or [], "full_attention_tensors_materialized": False,
                "full_attention_tensor_observation_scope": "instrumentation; native fused kernel internals are not introspected"}


class MlxForward:
    def __init__(self, directory, artifact):
        import mlx.core as mx
        from mlx_vlm.utils import load
        import importlib.metadata
        if importlib.metadata.version("mlx-vlm") != "0.7.11":
            raise ValueError("FORWARD_RUNTIME_UNVERIFIED")
        self.mx = mx
        self.model, self.processor = load(Path(directory).resolve(strict=True), lazy=False)
        self.directory, self.artifact = directory, artifact
        self.runtime = local_module("runtime")

    def run(self, value):
        mx = self.mx
        inputs, _, processor, prompt = self.runtime.tokenize_chat(value["request"], self.directory, return_prepared=True)
        if any(key not in ("input_ids", "attention_mask") for key in inputs):
            raise ValueError("FORWARD_PROCESSOR_FIELDS_UNVERIFIED")
        ids = inputs["input_ids"]
        count = int(ids.shape[-1])
        prefix_ids = ids.tolist()[0]
        spans, span_observations = resolve_spans(processor.tokenizer, prefix_ids, value)
        suffix = processor.tokenizer.encode(value.get("continuation", ""), add_special_tokens=False)
        if len(suffix) > 64:
            raise ValueError("FORWARD_CONTINUATION_TOKEN_LIMIT")
        bounded_forward_tokens(count, len(suffix))
        if any(span["end"] > count for span in value.get("spans", [])):
            raise ValueError("FORWARD_SPAN_OUTSIDE_CONTEXT")
        if suffix:
            ids = mx.concatenate([ids, mx.array([suffix[:-1]], dtype=ids.dtype)], axis=1)
        total = int(ids.shape[-1]); mx.set_default_device(mx.gpu)
        language = self.model.language_model
        if hasattr(language, "_position_ids"):
            language._position_ids = None; language._rope_deltas = None
        layers = language.layers
        if value.get("intervention", {}).get("layer") not in (None, *[index for index, layer in enumerate(layers) if getattr(layer, "linear_attn", None) is not None or getattr(layer, "conv", None) is not None]):
            raise ValueError("FORWARD_INTERVENTION_LAYER_UNSUPPORTED")
        import importlib
        module = importlib.import_module(type(layers[0]).__module__)
        attention, hybrid, originals = [], [], []
        capture_enabled = False
        query_position = count - 1
        capture_start = 0
        if value.get("instrument"):
            native_attention = module.scaled_dot_product_attention
            attention_layers = [(index, getattr(layer, "layer_type", "full_attention")) for index, layer in enumerate(layers) if getattr(layer, "self_attn", None) is not None]
            def observed(queries, keys, values, **kwargs):
                if not capture_enabled:
                    return native_attention(queries, keys, values, **kwargs)
                layer, kind = attention_layers[len(attention)]
                layout = attention_key_layout(total, keys.shape[-2], queries.shape[-2], kwargs.get("cache"))
                if layout is None:
                    attention.append({"layer": layer, "layer_type": kind, "status": "unavailable", "reason": "ATTENTION_KEY_LAYOUT_UNVERIFIED", "query_position": query_position})
                    return native_attention(queries, keys, values, **kwargs)
                selected_position = prefix_position(count, capture_start, queries.shape[-2])
                q = queries[:, :, selected_position:selected_position + 1, :].astype(mx.float32)
                k = mx.repeat(keys.astype(mx.float32), queries.shape[1] // keys.shape[1], axis=1)
                scores = (q @ k.swapaxes(-2, -1)) * kwargs["scale"]
                mask = kwargs.get("mask")
                if isinstance(mask, str) and mask != "causal":
                    attention.append({"layer": layer, "layer_type": kind, "status": "unavailable", "reason": "ATTENTION_MASK_SEMANTICS_UNVERIFIED", "query_position": query_position})
                    return native_attention(queries, keys, values, **kwargs)
                if mask is not None and not isinstance(mask, str):
                    row = attention_mask_query(mask.shape, selected_position, queries.shape[-2])
                    selected = mask[..., row:row + 1, :keys.shape[-2]] if row is not None else mask[..., :keys.shape[-2]]
                    scores = mx.where(selected, scores, -float("inf")) if selected.dtype == mx.bool_ else scores + selected
                allowed = mx.array(layout["physical_positions"]) <= query_position
                scores = mx.where(allowed, scores, -float("inf"))
                rows = mx.softmax(scores, axis=-1)[0, :, 0, :]
                rows = rows[:, mx.array(layout["temporal_order"])]
                mx.eval(rows)
                attention.append({"layer": layer, "layer_type": kind, "query_position": query_position,
                                  **attention_summary(rows.tolist(), spans, layout["key_offset"])})
                return native_attention(queries, keys, values, **kwargs)
            module.scaled_dot_product_attention = observed
            originals.append((module, "scaled_dot_product_attention", native_attention))
            operators = {}
            for index, layer in enumerate(layers):
                for name in ("linear_attn", "conv"):
                    operator = getattr(layer, name, None)
                    if operator is not None:
                        operators[id(operator)] = (index, name)
            intervention = value.get("intervention", {})
            for cls in {type(operator) for layer in layers for operator in [getattr(layer, "linear_attn", None), getattr(layer, "conv", None)] if operator is not None}:
                native = cls.__call__
                def observed_operator(instance, *args, _native=native, **kwargs):
                    out = _native(instance, *args, **kwargs)
                    if capture_enabled and id(instance) in operators:
                        index, name = operators[id(instance)]
                        selected_position = prefix_position(count, capture_start, out.shape[1])
                        norm = mx.sqrt(mx.sum(out[:, selected_position:selected_position + 1, :].astype(mx.float32) ** 2)); mx.eval(norm)
                        hybrid.append({"layer": index, "operator": name, "observation": "operator_output", "position": query_position, "last_position_l2": float(norm.item())})
                        if intervention.get("layer") == index:
                            out = out.at[:, selected_position:selected_position + 1, :].multiply(0)
                    return out
                cls.__call__ = observed_operator
                originals.append((cls, "__call__", native))
        try:
            # Text-only execution uses the exact native text stack, then projects
            # only required positions: never allocate vocabulary x full-context.
            features = self.model.get_input_embeddings(ids)
            cache = language.make_cache()
            from mlx_vlm.generate.common import DEFAULT_PREFILL_STEP_SIZE, _chunked_prefill_enabled
            def hidden_forward(start, end):
                if self.artifact.endswith("Bonsai-2-2B-mlx-2bit"):
                    metadata = {**features.to_dict(), "inputs_embeds": features.inputs_embeds[:, start:end]}
                    return language(ids[:, start:end], cache=cache, **metadata, return_hidden=True, skip_logits=True).hidden_states[-1]
                positions = features.position_ids[..., start:end] if features.position_ids is not None else None
                return language.model(ids[:, start:end], cache=cache, input_embeddings=features.inputs_embeds[:, start:end], position_ids=positions)
            prefill_end = total - max(1, len(suffix))
            chunked = _chunked_prefill_enabled(self.model, input_ids=ids, inputs_embeds=features.inputs_embeds, prompt_cache=cache,
                                               prefill_kwargs={key: item for key, item in features.to_dict().items() if key != "inputs_embeds" and item is not None})
            start = 0
            if chunked:
                while start < prefill_end:
                    end = min(start + DEFAULT_PREFILL_STEP_SIZE, prefill_end)
                    hidden_forward(start, end)
                    mx.eval([entry.state for entry in cache]); mx.clear_cache()
                    start = end
            capture_start = start
            capture_enabled = True
            hidden = hidden_forward(start, total)
            selected_hidden = hidden[:, -max(1, len(suffix)):, :]
            tied = language.args.tie_word_embeddings if hasattr(language, "args") else language.config.tie_word_embeddings
            logits = language.model.embed_tokens.as_linear(selected_hidden) if tied else language.lm_head(selected_hidden)
            logits = logits[0].astype(mx.float32)
            log_probs = logits - mx.logsumexp(logits, axis=-1, keepdims=True)
            mx.eval(logits, log_probs)
            selected = [float(log_probs[index, token].item()) for index, token in enumerate(suffix)] if suffix else []
            candidates = [{"token_id": token, "log_probability": float(log_probs[0, token].item())} for token in value.get("candidate_token_ids", [])]
            result = TorchForward.result(logits[0].tolist(), selected, candidates, attention, hybrid, count, total)
            result["prefix_token_ids_sha256"] = hashlib.sha256(json.dumps(prefix_ids, separators=(",", ":")).encode()).hexdigest()
            result["prompt_sha256"] = hashlib.sha256(prompt.encode()).hexdigest()
            result["execution_path"] = {"native_chunked_prefill": chunked, "prefill_step_size": DEFAULT_PREFILL_STEP_SIZE if chunked else None,
                                        "teacher_forced_tail_positions": max(1, len(suffix)), "logits_projected_positions": max(1, len(suffix))}
            result["span_observations"] = span_observations
            result["teacher_forcing"] = scoring_metadata(count, suffix)
            result["intervention_position"] = query_position if value.get("intervention") else None
            states = []
            for index, entry in enumerate(cache):
                if getattr(layers[index], "linear_attn", None) is None and getattr(layers[index], "conv", None) is None:
                    continue
                state = getattr(entry, "state", None)
                if isinstance(state, (list, tuple)):
                    for slot, item in enumerate(state):
                        if hasattr(item, "shape"):
                            norm = mx.sqrt(mx.sum(item.astype(mx.float32) ** 2)); mx.eval(norm)
                            states.append({"layer": index, "operator": "linear_attention" if getattr(layers[index], "linear_attn", None) is not None else "conv",
                                           "slot": slot, "shape": list(item.shape), "l2": float(norm.item())})
            result["cache_states"] = states
            result["cache_states_observation"] = "fresh native cache; recurrent/conv state slots where exposed"
            return result
        finally:
            for owner, name, original in reversed(originals):
                setattr(owner, name, original)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", required=True)
    parser.add_argument("--artifact", required=True, choices=sorted(ARTIFACTS))
    parser.add_argument("--opt-in", action="store_true")
    parser.add_argument("--maximum-forwards", type=int, default=24, choices=range(1, 25))
    args = parser.parse_args()
    if not args.opt_in or any(os.environ.get(name) not in (None, "", "0", "false") for name in ("CI", "GITHUB_ACTIONS", "GITLAB_CI", "BUILD_BUILDID", "JENKINS_URL")):
        parser.error("Explicit --opt-in outside CI is required.")
    directory = Path(args.model)
    if not directory.is_absolute() or not directory.is_dir():
        parser.error("An exact local model directory is required.")
    backend = TorchForward(str(directory)) if ARTIFACTS[args.artifact] == "minicpm" else MlxForward(str(directory), args.artifact)
    print(json.dumps({"event": "ready", "artifact": args.artifact, "maximum_forwards": args.maximum_forwards}), flush=True)
    used = 0
    for line in sys.stdin:
        started = time.monotonic()
        try:
            if len(line.encode()) > 4 * 1024 * 1024:
                raise ValueError("FORWARD_REQUEST_TOO_LARGE")
            value = validate_probe(json.loads(line))
            if used >= args.maximum_forwards:
                raise ValueError("FORWARD_BUDGET_EXCEEDED")
            used += 1
            result = backend.run(value)
            result.update({"forward_ordinal": used, "elapsed_ms": round(1000 * (time.monotonic() - started)), "artifact": args.artifact})
            result["instrumented"] = value.get("instrument", False)
            result["intervention"] = value.get("intervention")
            result["intervention_scope"] = "native-prefix-end operator contribution; not skill-specific" if value.get("intervention") else None
            print(json.dumps(result, allow_nan=False), flush=True)
        except Exception as error:
            print(json.dumps({"status": "blocked", "reason": type(error).__name__ + ":" + str(error)[:500], "forward_ordinal": used}), flush=True)


if __name__ == "__main__":
    main()
