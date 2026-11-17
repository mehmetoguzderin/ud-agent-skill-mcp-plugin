"""MIT. Opt-in interpretability for the QSLM loop: why does a tool-call decision go wrong?

Two objectives share one decision position (the token after ``<function=``, or
after ``<parameter=command>`` for the shell tool):
  * skill-call (negative scenarios and the default): first token of a valid tool
    name against the first token of a skill name used as a function;
  * uptake (positive scenarios): the reference first action (load the skill)
    against the first actions the model actually took in failing episodes, each
    scored as a whole continuation sequence (sum of token log-probabilities).

At the decision position this script measures
  * attention from that position to labeled prompt spans in every full-attention
    layer and head (the hybrid model's linear-attention layers have no attention map);
  * input x gradient and integrated-gradients attribution of the margin
    logsumexp(first token of a valid tool) - logsumexp(first token of a skill name)
    with respect to the prompt token embeddings, aggregated per span;
  * optionally, the same margin for candidate rewordings of product text (forward only).

It loads the exact NF4 artifact on CPU (gradients flow through the frozen 4-bit
layers to the input embeddings; no weights are converted or trained). Outputs are
written only to --output. Never imported by tests; never run by default.
"""
import argparse
import json
import math
import re
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))


def log(message):
    print(f"[interpret {time.strftime('%H:%M:%S')}] {message}", file=sys.stderr, flush=True)


def load(model_dir, dtype="float32"):
    import torch
    from transformers import AutoModelForImageTextToText, AutoProcessor
    processor = AutoProcessor.from_pretrained(model_dir, local_files_only=True)
    model = AutoModelForImageTextToText.from_pretrained(model_dir, local_files_only=True, device_map="cpu", torch_dtype="auto", attn_implementation="eager").eval()
    for module in model.modules():
        if getattr(module, "support_avx512bf16_for_cpu", False) and getattr(module, "out_features", 0) % 32:
            module.support_avx512bf16_for_cpu = False
    # The vision tower is never used for text prompts; drop it before densifying.
    if getattr(model.model, "vision_tower", None) is not None:
        model.model.vision_tower = None
        model.model.merger = None
    dequantize(torch, model, getattr(torch, dtype))
    # bf16 CPU kernels reorder reductions between runs; the hybrid linear-attention
    # layers amplify that into logit-margin noise of several nats. float32 keeps
    # candidate scores reproducible (about 4.5 GB for the dense text model).
    torch.nn.Module.to(model, getattr(torch, dtype))  # all layers are dense now
    # Recompute activations in backward: bounded memory for 3k+ token prompts on CPU.
    model.gradient_checkpointing_enable(gradient_checkpointing_kwargs={"use_reentrant": False})
    for parameter in model.parameters():
        parameter.requires_grad_(False)
    torch.set_grad_enabled(False)
    return torch, processor, model


def dequantize(torch, model, dtype=None):
    """Replace NF4 layers by dense layers holding the identical dequantized NF4 values.

    bitsandbytes' CPU gemv_4bit has no autograd kernel, so backpropagation through
    4-bit layers would silently drop gradient paths. The dense copy keeps the exact
    quantized weights (no training, no reloading of other precisions).
    """
    import bitsandbytes as bnb
    dtype = dtype or torch.bfloat16
    replaced = 0
    for name, module in list(model.named_modules()):
        for child_name, child in list(module.named_children()):
            if isinstance(child, bnb.nn.Linear4bit):
                weight = bnb.functional.dequantize_4bit(child.weight.data, child.weight.quant_state).to(dtype)
                dense = torch.nn.Linear(child.in_features, child.out_features, bias=child.bias is not None, dtype=dtype)
                dense.weight.data.copy_(weight)
                if child.bias is not None:
                    dense.bias.data.copy_(child.bias.data.to(dtype))
                setattr(module, child_name, dense)
                replaced += 1
    log(f"dequantized {replaced} NF4 layers to {dtype}")
    return replaced


def render(processor, body):
    from minicpm_server import normalize_messages
    messages = normalize_messages(body["messages"])
    text = processor.apply_chat_template(messages, tools=body.get("tools"), tokenize=False, add_generation_prompt=True, enable_thinking=False)
    return text if isinstance(text, str) else text[0]


def spans_for(text, case, body):
    """Character spans of prompt parts; later, more specific spans win."""
    spans = []

    def add(label, start, end):
        if 0 <= start < end:
            spans.append((label, start, end))

    system = body["messages"][0]["content"]
    s0 = text.find(system[:60])
    if s0 >= 0:
        add("system_rules", s0, s0 + len(system))
        skills_at = text.find("Available skills:", s0)
        if skills_at >= 0:
            end = skills_at
            for skill in case["skills"]:
                line = f"- {skill['name']}: {skill['description']}"
                at = text.find(line, s0)
                if at >= 0:
                    add(f"skill:{skill['name']}", at, at + len(line))
                    end = max(end, at + len(line))
            add("skill_catalog", skills_at, end)
            spans.sort(key=lambda item: item[0].startswith("skill:"))
        for marker, label in (("Call activate_skill", "loader_rule"), ("Skills are instruction files", "loader_rule"), ("Deferred tools", "deferred_list"), ("Folder structure", "folder_structure")):
            at = text.find(marker, s0)
            if at >= 0:
                stop = text.find("\n\n", at)
                add(label, at, (stop if stop > 0 else s0 + len(system)) if label != "loader_rule" else text.find("\n", at) if text.find("\n", at) > 0 else s0 + len(system))
    for message in body["messages"][2:]:
        # Teacher-forced history: a loaded skill (tool result) is its own span.
        if message["role"] == "tool" and message.get("content"):
            at = text.find(message["content"][:200])
            add("loaded_skill", at, at + len(message["content"]))
    user = body["messages"][1]["content"]
    u0 = text.rfind(user)
    add("user_task", u0, u0 + len(user))
    tools_open, tools_close = text.find("<tools>"), text.find("</tools>")
    if tools_open >= 0 and tools_close > tools_open:
        add("tool_definitions", tools_open, tools_close + len("</tools>"))
        names = [tool["function"]["name"] for tool in body.get("tools", [])]
        starts = sorted((text.find(f'"name": "{name}"', tools_open), name) for name in names)
        starts = [(at, name) for at, name in starts if at >= 0]
        for index, (at, name) in enumerate(starts):
            line_start = text.rfind("\n", tools_open, at) + 1
            stop = starts[index + 1][0] if index + 1 < len(starts) else tools_close
            stop = text.rfind("\n", line_start, stop) if text.rfind("\n", line_start, stop) > line_start else stop
            add(f"tool:{name}", line_start, stop)
    return spans


def label_tokens(offsets, spans, prompt_chars):
    labels = []
    for start, _end in offsets:
        label = "assistant_prefix" if start >= prompt_chars else "template"
        best = None
        for name, s, e in spans:
            if s <= start < e and (best is None or (e - s) < (best[2] - best[1])):
                best = (name, s, e)
        labels.append(best[0] if best else label)
    return labels


def case_name(item):
    """harness/scenario, plus a stage suffix for teacher-forced later decisions."""
    return item.get("label") or f'{item["harness"]}/{item["scenario_id"]}'


def group_of(label):
    return label.split(":")[0] if ":" in label else label


def first_tokens(tokenizer, full_ids, full_text, valid, invalid):
    """First generated token of each candidate name at the decision position.

    The decoder emits the call prefix (``<function=``) and then the name as a
    separate continuation, so each name is tokenized on its own rather than
    merged with the prefix text. Tokens shared by a valid and a skill name are
    excluded from the margin.
    """
    first = {}
    for name in valid + invalid:
        ids = tokenizer(name, add_special_tokens=False)["input_ids"]
        if ids:
            first[name] = ids[0]
    shared = {first[n] for n in valid if n in first} & {first[n] for n in invalid if n in first}
    valid_first = {n: t for n, t in first.items() if n in valid and t not in shared}
    invalid_first = {n: t for n, t in first.items() if n in invalid and t not in shared}
    return len(full_ids), valid_first, invalid_first, sorted(n for n in first if first[n] in shared)


def margin_from_logits(torch, logits, valid_ids, invalid_ids):
    log_probs = torch.log_softmax(logits.float(), dim=-1)
    valid = torch.logsumexp(log_probs[sorted(set(valid_ids))], dim=0)
    invalid = torch.logsumexp(log_probs[sorted(set(invalid_ids))], dim=0)
    return valid - invalid, valid, invalid


def continuation_ids(tokenizer, sequences):
    """Each continuation is tokenized on its own, as the decoder emits it after the prefix."""
    return [tokenizer(text, add_special_tokens=False)["input_ids"] for text in sequences]


def token_logprobs(torch, model, prefix_ids, ids):
    """Per-token log-probabilities of one continuation (where a reference action loses mass)."""
    with torch.no_grad():
        logits = model(input_ids=torch.tensor([prefix_ids + ids]), use_cache=False, logits_to_keep=len(ids) + 1).logits[0, :-1]
    return torch.log_softmax(logits.float(), dim=-1)[torch.arange(len(ids)), torch.tensor(ids)].tolist()


def cached_sequence_logprobs(torch, model, prefix_ids, continuations):
    """Forward-only scoring that encodes the shared prefix once and reuses its cache per continuation.

    The prefix's last logits score each continuation's first token; a deep copy of the
    (attention + linear-attention state) cache scores the rest. Equal to the uncached
    forward up to float32 rounding (verified on the G1 shell case: identical to 4 decimals, 3x faster).
    """
    import copy
    with torch.no_grad():
        out = model(input_ids=torch.tensor([prefix_ids]), use_cache=True, logits_to_keep=1)
        first = torch.log_softmax(out.logits[0, -1].float(), dim=-1)
        values = []
        for ids in continuations:
            total = float(first[ids[0]])
            if len(ids) > 1:
                cache = copy.deepcopy(out.past_key_values)
                logits = model(input_ids=torch.tensor([ids[:-1]]), past_key_values=cache, use_cache=True,
                               cache_position=torch.arange(len(prefix_ids), len(prefix_ids) + len(ids) - 1)).logits[0]
                total += float(torch.log_softmax(logits.float(), dim=-1)[torch.arange(len(ids) - 1), torch.tensor(ids[1:])].sum())
                del cache, logits
            values.append(total)
    del out
    return values


def sequence_logprobs(torch, model, prefix_ids, continuations, prefix_embeds=None, grad=False):
    """Sum of continuation-token log-probabilities after the prefix, one forward per continuation.

    With ``grad`` the gradient of each log-probability w.r.t. ``prefix_embeds`` is
    returned too (continuation embeddings are held fixed: only the prompt is attributed).
    """
    embed = model.get_input_embeddings()
    values, grads = [], []
    for ids in continuations:
        full = torch.tensor([prefix_ids + ids])
        if prefix_embeds is None:
            with torch.no_grad():
                logits = model(input_ids=full, use_cache=False, logits_to_keep=len(ids) + 1).logits[0, :-1]
            value = torch.log_softmax(logits.float(), dim=-1)[torch.arange(len(ids)), torch.tensor(ids)].sum()
            values.append(float(value)); continue
        point = prefix_embeds.detach().requires_grad_(True)
        tail = embed(torch.tensor([ids])).detach().to(point.dtype)
        model.train()  # checkpointing is active only in training mode; every dropout rate is zero
        with torch.enable_grad():
            logits = model(input_ids=full, inputs_embeds=torch.cat([point, tail], dim=1), use_cache=False, logits_to_keep=len(ids) + 1).logits[0, :-1]
            value = torch.log_softmax(logits.float(), dim=-1)[torch.arange(len(ids)), torch.tensor(ids)].sum()
            (gradient,) = torch.autograd.grad(value, point) if grad else (None,)
        model.eval()
        values.append(float(value)); grads.append(gradient.float() if gradient is not None else None)
        del logits, value
    return values, grads


def sequence_margin_value(valid_values, invalid_values):
    return math.log(sum(math.exp(v) for v in valid_values)) - math.log(sum(math.exp(v) for v in invalid_values))


def sequence_margin_gradient(torch, model, prefix_ids, prefix_embeds, valid, invalid):
    """d margin / d embeddings, with margin = logsumexp(valid) - logsumexp(invalid) over sequences."""
    values, grads = sequence_logprobs(torch, model, prefix_ids, valid + invalid, prefix_embeds, grad=True)
    v, i = values[:len(valid)], values[len(valid):]
    wv = torch.softmax(torch.tensor(v), 0).tolist(); wi = torch.softmax(torch.tensor(i), 0).tolist()
    total = sum(w * g for w, g in zip(wv, grads[:len(valid)])) - sum(w * g for w, g in zip(wi, grads[len(valid):]))
    return sequence_margin_value(v, i), total


def analyze_case(torch, processor, model, case, steps, max_gradient_tokens=3000):
    if case.get("objective", "").startswith("uptake"):
        return analyze_uptake_case(torch, processor, model, case, steps, max_gradient_tokens)
    tokenizer = processor.tokenizer
    body = case["body"]
    prompt = render(processor, body)
    full_text = prompt + case["prefix"]
    encoded = tokenizer(full_text, add_special_tokens=False, return_offsets_mapping=True)
    ids, offsets = encoded["input_ids"], encoded["offset_mapping"]
    reference = processor.apply_chat_template(__import__("minicpm_server").normalize_messages(body["messages"]), tools=body.get("tools"), tokenize=True, add_generation_prompt=True, return_dict=True, return_tensors="pt", enable_thinking=False)["input_ids"][0].tolist()
    template_match = ids[:len(reference)] == reference
    position, valid_first, invalid_first, shared_names = first_tokens(tokenizer, ids, full_text, case["valid"], case["invalid"])
    if not valid_first or not invalid_first:
        raise ValueError(f"no distinguishing first tokens for {case['harness']}/{case['scenario_id']}")
    ids, offsets = ids[:position], offsets[:position]
    valid_merged, invalid_merged = shared_names, []
    spans = spans_for(prompt, case, body)
    labels = label_tokens(offsets, spans, len(prompt))
    input_ids = torch.tensor([ids])
    log(f"{case['harness']}/{case['scenario_id']}: {len(ids)} tokens, template_match={template_match}")
    # 1) attention from the decision position, full-attention layers only.
    with torch.no_grad():
        out = model(input_ids=input_ids, output_attentions=True, use_cache=False, logits_to_keep=1)
    logits = out.logits[0, -1]
    margin, valid_lp, invalid_lp = margin_from_logits(torch, logits, list(valid_first.values()), list(invalid_first.values()))
    log_probs = torch.log_softmax(logits.float(), dim=-1)
    top = torch.topk(log_probs, 8)
    attention_layers = [index for index, value in enumerate(out.attentions) if value is not None] if out.attentions else []
    full_layers = [i for i, kind in enumerate(model.config.text_config.layer_types) if kind == "full_attention"]
    rows = [value[0, :, -1, :].float() for value in out.attentions if value is not None]
    groups = sorted({group_of(label) for label in labels})
    fine = sorted({label for label in labels})
    attention = {}
    for name in fine:
        mask = torch.tensor([label == name for label in labels])
        attention[name] = [[float(row[head][mask].sum()) for head in range(row.shape[0])] for row in rows]
    attention_group = {}
    for name in groups:
        mask = torch.tensor([group_of(label) == name for label in labels])
        attention_group[name] = [[float(row[head][mask].sum()) for head in range(row.shape[0])] for row in rows]
    del out
    if len(ids) > max_gradient_tokens:
        # Backprop through a longer prompt exceeds the CPU memory bound; keep attention only.
        log(f"  {len(ids)} tokens > --max-gradient-tokens {max_gradient_tokens}: attention only, no gradients")
        return {
            "harness": case["harness"], "scenario_id": case["scenario_id"], "prefix_source": case["prefix_source"], "tokens": len(ids), "template_match": template_match,
            "decision": {"margin": float(margin), "valid_logprob": float(valid_lp), "skill_logprob": float(invalid_lp), "embedding_path_margin": None,
                         "valid_first_tokens": {name: tokenizer.decode([token]) for name, token in valid_first.items()},
                         "skill_first_tokens": {name: tokenizer.decode([token]) for name, token in invalid_first.items()},
                         "shared_first_token_names": valid_merged, "decision_position": position,
                         "top_next_tokens": [{"token": tokenizer.decode([int(t)]), "logprob": float(v)} for v, t in zip(top.values, top.indices)]},
            "full_attention_layers": full_layers, "attention_rows": len(rows), "attention": attention, "attention_group": attention_group,
            "span_tokens": {name: sum(1 for label in labels if label == name) for name in fine},
            "ig": {}, "ig_group": {}, "input_x_grad_group": {}, "grad_norm_group": {}, "ig_completeness": None, "top_tokens": [],
            "gradients_skipped": f"{len(ids)} tokens > {max_gradient_tokens}",
        }
    # 2) gradients w.r.t. input embeddings (input x gradient, integrated gradients from a zero baseline).
    embed = model.get_input_embeddings()
    base = embed(input_ids).detach().float()
    total = torch.zeros_like(base)
    gradient_at_input = None
    alphas = [(k + 1) / steps for k in range(steps)]
    for alpha in alphas:
        point = (base * alpha).to(embed.weight.dtype).requires_grad_(True)
        model.train()  # checkpointing is active only in training mode; every dropout rate is zero
        with torch.enable_grad():
            result = model(input_ids=input_ids, inputs_embeds=point, use_cache=False, logits_to_keep=1)
            value, _, _ = margin_from_logits(torch, result.logits[0, -1], list(valid_first.values()), list(invalid_first.values()))
            (grad,) = torch.autograd.grad(value, point)
        model.eval()
        grad = grad.float()
        total += grad
        if alpha == 1.0:
            gradient_at_input = grad
            embed_margin = float(value)
        del result, grad, point
        log(f"  IG step alpha={alpha:.3f} margin={float(value):.3f}")
    integrated = (base * total / steps).sum(-1)[0]
    input_x_grad = (base * gradient_at_input).sum(-1)[0]
    grad_norm = gradient_at_input.norm(dim=-1)[0]

    def aggregate(vector, key):
        return {name: float(vector[torch.tensor([key(label) == name for label in labels])].sum()) for name in sorted({key(label) for label in labels})}

    token_rows = []
    for index in torch.topk(integrated.abs(), min(30, len(ids))).indices.tolist():
        token_rows.append({"index": index, "token": tokenizer.decode([ids[index]]), "span": labels[index], "ig": float(integrated[index]), "input_x_grad": float(input_x_grad[index])})
    return {
        "harness": case["harness"], "scenario_id": case["scenario_id"], "prefix_source": case["prefix_source"], "tokens": len(ids), "template_match": template_match,
        "decision": {"margin": float(margin), "valid_logprob": float(valid_lp), "skill_logprob": float(invalid_lp), "embedding_path_margin": embed_margin,
                     "valid_first_tokens": {name: tokenizer.decode([token]) for name, token in valid_first.items()},
                     "skill_first_tokens": {name: tokenizer.decode([token]) for name, token in invalid_first.items()},
                     "shared_first_token_names": valid_merged, "decision_position": position,
                     "top_next_tokens": [{"token": tokenizer.decode([int(t)]), "logprob": float(v)} for v, t in zip(top.values, top.indices)]},
        "full_attention_layers": full_layers, "attention_rows": len(rows), "attention": attention, "attention_group": attention_group,
        "span_tokens": {name: sum(1 for label in labels if label == name) for name in fine},
        "ig": aggregate(integrated, lambda label: label), "ig_group": aggregate(integrated, group_of),
        "input_x_grad_group": aggregate(input_x_grad, group_of), "grad_norm_group": aggregate(grad_norm, group_of),
        "ig_completeness": {"sum": float(integrated.sum()), "margin_minus_baseline_hint": "zero-embedding baseline; sum approximates margin(x) - margin(0)"},
        "top_tokens": token_rows,
    }


def attention_from_last(torch, model, input_ids, labels):
    with torch.no_grad():
        out = model(input_ids=input_ids, output_attentions=True, use_cache=False, logits_to_keep=1)
    logits = out.logits[0, -1]
    rows = [value[0, :, -1, :].float() for value in out.attentions if value is not None]
    attention, attention_group = {}, {}
    for name in sorted(set(labels)):
        mask = torch.tensor([label == name for label in labels])
        attention[name] = [[float(row[head][mask].sum()) for head in range(row.shape[0])] for row in rows]
    for name in sorted({group_of(label) for label in labels}):
        mask = torch.tensor([group_of(label) == name for label in labels])
        attention_group[name] = [[float(row[head][mask].sum()) for head in range(row.shape[0])] for row in rows]
    del out
    return logits, rows, attention, attention_group


def analyze_uptake_case(torch, processor, model, case, steps, max_gradient_tokens):
    """Reference action (load the skill) against the model's observed first actions, as sequences."""
    tokenizer = processor.tokenizer
    body = case["body"]
    prompt = render(processor, body)
    encoded = tokenizer(prompt, add_special_tokens=False, return_offsets_mapping=True)
    prompt_ids, offsets = encoded["input_ids"], encoded["offset_mapping"]
    prefix_extra = tokenizer(case["prefix"], add_special_tokens=False, return_offsets_mapping=True)
    ids = prompt_ids + prefix_extra["input_ids"]
    offsets = offsets + [(len(prompt) + a, len(prompt) + b) for a, b in prefix_extra["offset_mapping"]]
    reference = processor.apply_chat_template(__import__("minicpm_server").normalize_messages(body["messages"]), tools=body.get("tools"), tokenize=True, add_generation_prompt=True, return_dict=True, return_tensors="pt", enable_thinking=False)["input_ids"][0].tolist()
    template_match = prompt_ids == reference
    labels = label_tokens(offsets, spans_for(prompt, case, body), len(prompt))
    valid, invalid = continuation_ids(tokenizer, case["valid_sequences"]), continuation_ids(tokenizer, case["invalid_sequences"])
    log(f"{case['harness']}/{case['scenario_id']} (uptake): {len(ids)} tokens, {len(valid)} reference vs {len(invalid)} observed sequences")
    input_ids = torch.tensor([ids])
    logits, rows, attention, attention_group = attention_from_last(torch, model, input_ids, labels)
    log_probs = torch.log_softmax(logits.float(), dim=-1)
    top = torch.topk(log_probs, 8)
    values = cached_sequence_logprobs(torch, model, ids, valid + invalid)
    margin = sequence_margin_value(values[:len(valid)], values[len(valid):])
    full_layers = [i for i, kind in enumerate(model.config.text_config.layer_types) if kind == "full_attention"]
    fine = sorted(set(labels))
    reference_tokens = [[{"token": tokenizer.decode([t]), "logprob": lp} for t, lp in zip(seq, token_logprobs(torch, model, ids, seq))] for seq in valid]
    result = {
        "harness": case["harness"], "scenario_id": case["scenario_id"], "label": case_name(case), "objective": case["objective"], "prefix_source": case["prefix_source"], "tokens": len(ids), "template_match": template_match,
        "decision": {"margin": float(margin), "valid_logprob": math.log(sum(math.exp(v) for v in values[:len(valid)])), "skill_logprob": math.log(sum(math.exp(v) for v in values[len(valid):])),
                     "sequences": [{"text": text, "kind": kind, "logprob": value, "tokens": len(seq)} for (text, kind, seq), value in zip([(t, "reference", q) for t, q in zip(case["valid_sequences"], valid)] + [(t, "observed", q) for t, q in zip(case["invalid_sequences"], invalid)], values)],
                     "reference_tokens": reference_tokens, "embedding_path_margin": None, "decision_position": len(ids),
                     "top_next_tokens": [{"token": tokenizer.decode([int(t)]), "logprob": float(v)} for v, t in zip(top.values, top.indices)]},
        "full_attention_layers": full_layers, "attention_rows": len(rows), "attention": attention, "attention_group": attention_group,
        "span_tokens": {name: sum(1 for label in labels if label == name) for name in fine},
        "ig": {}, "ig_group": {}, "input_x_grad_group": {}, "grad_norm_group": {}, "ig_completeness": None, "top_tokens": [],
    }
    if len(ids) > max_gradient_tokens:
        log(f"  {len(ids)} tokens > --max-gradient-tokens {max_gradient_tokens}: attention only, no gradients")
        result["gradients_skipped"] = f"{len(ids)} tokens > {max_gradient_tokens}"
        return result
    embed = model.get_input_embeddings()
    base = embed(input_ids).detach().float()
    total, gradient_at_input = torch.zeros_like(base), None
    for alpha in [(k + 1) / steps for k in range(steps)]:
        value, grad = sequence_margin_gradient(torch, model, ids, (base * alpha).to(embed.weight.dtype), valid, invalid)
        total += grad
        if alpha == 1.0:
            gradient_at_input, result["decision"]["embedding_path_margin"] = grad, value
        log(f"  IG step alpha={alpha:.3f} margin={value:.3f}")
    integrated = (base * total / steps).sum(-1)[0]
    input_x_grad = (base * gradient_at_input).sum(-1)[0]
    grad_norm = gradient_at_input.norm(dim=-1)[0]

    def aggregate(vector, key):
        return {name: float(vector[torch.tensor([key(label) == name for label in labels])].sum()) for name in sorted({key(label) for label in labels})}
    result.update({
        "ig": aggregate(integrated, lambda label: label), "ig_group": aggregate(integrated, group_of),
        "input_x_grad_group": aggregate(input_x_grad, group_of), "grad_norm_group": aggregate(grad_norm, group_of),
        "ig_completeness": {"sum": float(integrated.sum()), "margin_minus_baseline_hint": "zero-embedding baseline; sum approximates margin(x) - margin(0)"},
        "top_tokens": [{"index": index, "token": tokenizer.decode([ids[index]]), "span": labels[index], "ig": float(integrated[index]), "input_x_grad": float(input_x_grad[index])}
                       for index in torch.topk(integrated.abs(), min(30, len(ids))).indices.tolist()],
    })
    return result


def candidate_margin(torch, processor, model, case, replace):
    body = json.loads(json.dumps(case["body"]))
    def apply(value):
        for old, new in replace:
            value = value.replace(old, new)
        return value
    for message in body["messages"]:
        message["content"] = apply(message["content"])
    for tool in body.get("tools", []):
        tool["function"]["description"] = apply(tool["function"]["description"])
    tokenizer = processor.tokenizer
    if case.get("objective", "").startswith("uptake"):
        ids = tokenizer(render(processor, body), add_special_tokens=False)["input_ids"] + tokenizer(case["prefix"], add_special_tokens=False)["input_ids"]
        valid, invalid = continuation_ids(tokenizer, case["valid_sequences"]), continuation_ids(tokenizer, case["invalid_sequences"])
        values = cached_sequence_logprobs(torch, model, ids, valid + invalid)
        return float(sequence_margin_value(values[:len(valid)], values[len(valid):]))
    full_text = render(processor, body) + case["prefix"]
    ids = tokenizer(full_text, add_special_tokens=False)["input_ids"]
    position, valid_first, invalid_first, _ = first_tokens(tokenizer, ids, full_text, case["valid"], case["invalid"])
    ids = ids[:position]
    with torch.no_grad():
        logits = model(input_ids=torch.tensor([ids]), use_cache=False, logits_to_keep=1).logits[0, -1]
    margin, _, _ = margin_from_logits(torch, logits, list(valid_first.values()), list(invalid_first.values()))
    return float(margin)


def figures(results, output):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import numpy as np
    paths = []
    focus = ["loaded_skill", "skill_catalog", "skill", "loader_rule", "tool_definitions", "tool", "user_task", "system_rules", "assistant_prefix", "deferred_list", "folder_structure", "template"]
    # Layer x head mass on the skill catalog (incl. skill lines) for every case.
    fig, axes = plt.subplots(1, len(results), figsize=(3.2 * len(results), 3.6), squeeze=False)
    for axis, result in zip(axes[0], results):
        mass = np.array(result["attention_group"].get("skill_catalog", [[0]])) + np.array(result["attention_group"].get("skill", [[0]]))
        image = axis.imshow(mass, cmap="magma", vmin=0, vmax=max(0.05, float(mass.max())), aspect="auto")
        axis.set_yticks(range(len(result["full_attention_layers"])), [f"L{layer}" for layer in result["full_attention_layers"]], fontsize=7)
        axis.set_xticks(range(mass.shape[1]), [f"h{h}" for h in range(mass.shape[1])], fontsize=7)
        axis.set_title(f'{case_name(result)}\nmargin {result["decision"]["margin"]:.2f}', fontsize=8)
        fig.colorbar(image, ax=axis, fraction=0.046)
    fig.suptitle("Attention mass from the decision position to the skill catalog (layer x head)", fontsize=9)
    fig.tight_layout(); path = output / "interpret-attention-skill-catalog-layer-head.png"; fig.savefig(path, dpi=130); plt.close(fig); paths.append(path.name)
    # Span x case: attention (mean over heads/layers) vs IG attribution.
    names = [name for name in focus if any(name in r["attention_group"] for r in results)]
    attn = np.array([[np.mean(r["attention_group"].get(name, [[0]])) for r in results] for name in names])
    ig = np.array([[r["ig_group"].get(name, 0.0) for r in results] for name in names])
    fig, axes = plt.subplots(1, 2, figsize=(4 + 1.4 * len(results), 0.45 * len(names) + 2.2))
    for axis, data, title, cmap in ((axes[0], attn, "attention mass (mean head)", "viridis"), (axes[1], ig, "integrated gradients (+ favours the reference action)", "coolwarm")):
        limit = float(np.abs(data).max()) or 1.0
        image = axis.imshow(data, cmap=cmap, aspect="auto", **({"vmin": -limit, "vmax": limit} if cmap == "coolwarm" else {"vmin": 0}))
        axis.set_yticks(range(len(names)), names, fontsize=8)
        axis.set_xticks(range(len(results)), [case_name(r) for r in results], rotation=45, ha="right", fontsize=7)
        for i in range(data.shape[0]):
            for j in range(data.shape[1]):
                axis.text(j, i, f"{data[i, j]:.2f}", ha="center", va="center", fontsize=6, color="white" if abs(data[i, j]) > limit * 0.6 else "black")
        axis.set_title(title, fontsize=9); fig.colorbar(image, ax=axis, fraction=0.046)
    fig.tight_layout(); path = output / "interpret-span-attribution.png"; fig.savefig(path, dpi=130); plt.close(fig); paths.append(path.name)
    # Per-skill and per-tool fine attribution for each case.
    fig, axes = plt.subplots(len(results), 1, figsize=(9, 2.2 * len(results)), squeeze=False)
    for axis, result in zip(axes[:, 0], results):
        fine = [name for name in result["ig"] if name.startswith(("skill:", "tool:"))]
        values = [result["ig"][name] for name in fine]
        axis.bar(range(len(fine)), values, color=["#c0392b" if v < 0 else "#2e86c1" for v in values])
        axis.set_xticks(range(len(fine)), fine, rotation=60, ha="right", fontsize=6)
        axis.axhline(0, color="black", linewidth=0.5)
        wrong = "the observed alternative actions" if result.get("objective", "").startswith("uptake") else "a skill-name call"
        axis.set_title(f'{case_name(result)}: IG per skill line / tool definition (negative pushes toward {wrong})', fontsize=8)
    fig.tight_layout(); path = output / "interpret-fine-ig.png"; fig.savefig(path, dpi=130); plt.close(fig); paths.append(path.name)
    return paths


def candidate_figure(ranking, output):
    """Candidate x case margin heatmap, relative to the first listed candidate's margins when it is the baseline."""
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import numpy as np
    cases = list(ranking[0]["margins"])
    data = np.array([[item["margins"][case] for case in cases] for item in ranking])
    label_room = 0.07 * max(len(case) for case in cases)  # rotated case labels need height of their own
    fig, axis = plt.subplots(figsize=(2 + 1.1 * len(cases), 1 + 0.32 * len(ranking) + label_room))
    limit = float(np.abs(data).max()) or 1.0
    image = axis.imshow(data, cmap="coolwarm", vmin=-limit, vmax=limit, aspect="auto")
    axis.set_yticks(range(len(ranking)), [item["id"] for item in ranking], fontsize=7)
    axis.set_xticks(range(len(cases)), cases, rotation=45, ha="right", fontsize=7)
    for i in range(data.shape[0]):
        for j in range(data.shape[1]):
            axis.text(j, i, f"{data[i, j]:.1f}", ha="center", va="center", fontsize=6)
    axis.set_title("Candidate wording x case: decision margin (nats; + favours the reference)", fontsize=8)
    fig.colorbar(image, ax=axis, fraction=0.046); fig.tight_layout()
    path = output / "interpret-candidates.png"; fig.savefig(path, dpi=130); plt.close(fig)
    return path.name


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", required=True)
    parser.add_argument("--cases", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--candidates")
    parser.add_argument("--steps", type=int, default=6)
    parser.add_argument("--max-gradient-tokens", type=int, default=3000,
                        help="attention only above this prompt length (backprop memory bound on CPU)")
    parser.add_argument("--dtype", choices=["float32", "bfloat16"], default="float32",
                        help="dense compute precision; bfloat16 halves memory but adds run-to-run margin noise")
    parser.add_argument("--only", default="", help="comma list of harness/scenario to analyze")
    parser.add_argument("--case-only", action="store_true", help="analyze and cache the selected cases, then exit")
    parser.add_argument("--cached-only", action="store_true", help="use cached case analyses; compute none")
    args = parser.parse_args()
    output = Path(args.output).resolve(); output.mkdir(parents=True, exist_ok=True)
    data = json.loads(Path(args.cases).read_text())
    cases = [case for case in data["cases"] if not args.only or f'{case["harness"]}/{case["scenario_id"]}' in args.only.split(",")]
    torch, processor, model = load(args.model, args.dtype)
    torch.manual_seed(0)
    # Each case is cached so a bounded process per case (see loop.mjs) keeps peak memory flat.
    cache = output / "cases"; cache.mkdir(exist_ok=True)
    results = []
    for case in cases:
        stem = case["label"].replace("/", "-").replace("@", "-") if case.get("label") else f'{case["harness"]}-{case["scenario_id"]}'
        file = cache / f'{stem}-{case.get("objective", "skill-call")}-steps{max(1, args.steps)}.json'
        if file.exists():
            results.append(json.loads(file.read_text())); continue
        if args.cached_only:
            continue
        results.append(analyze_case(torch, processor, model, case, max(1, args.steps), args.max_gradient_tokens))
        file.write_text(json.dumps(results[-1]) + "\n")
    if args.case_only:
        print(json.dumps({"cached": [case_name(r) for r in results]}))
        return
    summary = {"schema_version": 1, "qualification": "diagnostic-interpretability-not-qualification", "steps": args.steps, "cases": results, "figures": figures(results, output) if results else []}
    if args.candidates:
        candidates = json.loads(Path(args.candidates).read_text())
        ranking = []
        for candidate in candidates:
            margins = {case_name(case): candidate_margin(torch, processor, model, case, candidate.get("replace", [])) for case in cases}
            ranking.append({"id": candidate["id"], "note": candidate.get("note", ""), "margins": margins, "mean_margin": sum(margins.values()) / len(margins), "min_margin": min(margins.values())})
            log(f"candidate {candidate['id']}: mean {ranking[-1]['mean_margin']:.3f} min {ranking[-1]['min_margin']:.3f}")
        ranking.sort(key=lambda item: (-item["mean_margin"], -item["min_margin"]))
        summary["candidates"] = ranking
        summary["figures"].append(candidate_figure(ranking, output))
    (output / "interpret-summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    lines = ["# Tool-call decision interpretability", "", "Margin: skill-call objective = valid tool - skill name (first token); uptake objective = reference action - observed actions (sequence log-probabilities).", "",
             "| Case | Objective | Prefix | Tokens | Margin | Top next tokens |", "|---|---|---|---:|---:|---|"]
    for r in results:
        lines.append(f'| {case_name(r)} | {r.get("objective", "skill-call")} | {r["prefix_source"]} | {r["tokens"]} | {r["decision"]["margin"]:.2f} | ' + ", ".join(f'`{t["token"]}` {math.exp(t["logprob"]):.2f}' for t in r["decision"]["top_next_tokens"][:4]) + " |")
    for r in results:
        for item in r["decision"].get("sequences", []):
            lines.append(f'- {case_name(r)} {item["kind"]} `{item["text"].strip()[:70]}`: {item["logprob"]:.2f}')
        for tokens in r["decision"].get("reference_tokens", []):
            lines.append(f'  - reference per token: ' + " ".join(f'`{t["token"]!r}` {t["logprob"]:.2f}' for t in tokens))
    lines += ["", "IG per span (positive favours the reference action):", ""]
    for r in results:
        lines.append(f'- {case_name(r)}: ' + ", ".join(f"{k} {v:+.2f}" for k, v in sorted(r["ig_group"].items(), key=lambda item: item[1])))
    if args.candidates:
        lines += ["", "| Candidate | Mean margin | Min margin | Note |", "|---|---:|---:|---|"] + [f'| {c["id"]} | {c["mean_margin"]:.3f} | {c["min_margin"]:.3f} | {c["note"]} |' for c in summary["candidates"]]
    (output / "interpret-summary.md").write_text("\n".join(lines) + "\n")
    print(json.dumps({"output": str(output), "figures": summary["figures"], "cases": [{"case": case_name(r), "margin": r["decision"]["margin"]} for r in results], "best_candidate": summary.get("candidates", [{}])[0].get("id")}))


if __name__ == "__main__":
    main()
