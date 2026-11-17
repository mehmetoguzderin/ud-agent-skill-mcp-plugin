"""Deterministic Messages-to-local-runtime protocol projection. MIT.

Only a native client tool_result can activate a declared deferred definition.
This module performs no search, inference, tool dispatch or argument repair.
"""
import copy
import json


def normalize_messages_request(body):
    request = copy.deepcopy(body)
    thinking = request.get("thinking")
    thinking_override = False
    if request.get("enable_thinking") is True:
        raise ValueError("THINKING_DISABLED")
    if thinking not in (None, {}, {"type": "disabled"}):
        if (request.get("enable_thinking") is not False or not isinstance(thinking, dict) or
                thinking.get("type") not in ("adaptive", "enabled") or
                set(thinking) - {"type", "budget_tokens", "display"}):
            raise ValueError("THINKING_OR_COMPACTION_UNSUPPORTED")
        # The frozen publisher sampler is authoritative on every protocol.
        # Native MLX also prioritizes explicit enable_thinking over this hint.
        request["thinking"] = {"type": "disabled"}
        thinking_override = True
    context = request.pop("context_management", None)
    if context not in (None, [], {}, {"edits": []},
                        {"edits": [{"type": "clear_thinking_20251015", "keep": "all"}]}):
        raise ValueError("MESSAGES_CONTEXT_EDIT_UNSUPPORTED")
    tools = request.get("tools", [])
    if tools is None:
        tools = []
    if not isinstance(tools, list):
        raise ValueError("MESSAGES_TOOL_TYPE_UNSUPPORTED")
    definitions = {}
    for tool in tools:
        if (not isinstance(tool, dict) or tool.get("type") not in (None, "custom") or
                not isinstance(tool.get("name"), str) or not tool["name"] or
                not isinstance(tool.get("input_schema"), dict)):
            raise ValueError("MESSAGES_TOOL_TYPE_UNSUPPORTED")
        if tool["name"] in definitions:
            raise ValueError("MESSAGES_TOOL_NAME_DUPLICATE")
        if "defer_loading" in tool and not isinstance(tool["defer_loading"], bool):
            raise ValueError("MESSAGES_DEFER_LOADING_INVALID")
        if tool.get("defer_loading") and "cache_control" in tool:
            raise ValueError("MESSAGES_DEFERRED_CACHE_CONTROL_UNSUPPORTED")
        if "allowed_callers" in tool and tool["allowed_callers"] != ["direct"]:
            raise ValueError("MESSAGES_TOOL_CALLER_UNSUPPORTED")
        definitions[tool["name"]] = tool
    messages = request.get("messages")
    if not isinstance(messages, list):
        raise ValueError("MESSAGES_REQUIRED")
    # The pinned native MLX Messages endpoint accepts harness-internal system
    # turns: leading ones join system; later ones retain their position as user
    # turns. Apply that same published-runtime projection on translated routes.
    system_parts, conversation, system_turns = [], False, 0
    normalized = []
    for message in messages:
        if isinstance(message, dict) and message.get("role") == "system":
            system_turns += 1
            if conversation:
                normalized.append({**message, "role": "user"})
                continue
            content = message.get("content")
            if isinstance(content, str):
                system_parts.append(content)
            elif isinstance(content, list) and all(isinstance(part, dict) and part.get("type") == "text" and isinstance(part.get("text"), str) for part in content):
                system_parts.append("\n".join(part["text"] for part in content).strip())
            else:
                raise ValueError("MESSAGES_SYSTEM_CONTENT_UNSUPPORTED")
        else:
            conversation = True
            normalized.append(message)
    if system_parts:
        existing = request.get("system")
        if isinstance(existing, str):
            system_parts.insert(0, existing)
        elif isinstance(existing, list) and all(isinstance(part, dict) and part.get("type") == "text" and isinstance(part.get("text"), str) for part in existing):
            system_parts.insert(0, "\n".join(part["text"] for part in existing).strip())
        elif existing is not None:
            raise ValueError("MESSAGES_SYSTEM_CONTENT_UNSUPPORTED")
        request["system"] = "\n".join(system_parts)
    messages = request["messages"] = normalized
    known, resolved, activated, references = {}, set(), set(), []
    for message in messages:
        if not isinstance(message, dict) or message.get("role") not in ("user", "assistant"):
            raise ValueError("MESSAGES_ROLE_UNSUPPORTED")
        content = message.get("content")
        if isinstance(content, str):
            continue
        if not isinstance(content, list):
            raise ValueError("MESSAGES_CONTENT_UNSUPPORTED")
        for block in content:
            if not isinstance(block, dict):
                raise ValueError("MESSAGES_CONTENT_UNSUPPORTED")
            if block.get("type") == "tool_use" and message["role"] == "assistant":
                identity = block.get("id")
                name = block.get("name")
                if (not isinstance(identity, str) or not identity or identity in known or
                        not isinstance(name, str) or not name or not isinstance(block.get("input"), dict)):
                    raise ValueError("TOOL_HISTORY_INVALID")
                if name in definitions and definitions[name].get("defer_loading") and name not in activated:
                    raise ValueError("MESSAGES_TOOL_HISTORY_UNLOADED")
                known[identity] = name
            elif block.get("type") == "tool_result" and message["role"] == "user":
                if block.get("tool_use_id") not in known or block["tool_use_id"] in resolved:
                    raise ValueError("ORPHAN_TOOL_RESULT_UNSUPPORTED")
                resolved.add(block["tool_use_id"])
                parts = block.get("content")
                if isinstance(parts, str) or parts is None:
                    continue
                if not isinstance(parts, list):
                    raise ValueError("TOOL_RESULT_CONTENT_UNSUPPORTED")
                for index, part in enumerate(parts):
                    if not isinstance(part, dict):
                        raise ValueError("TOOL_RESULT_CONTENT_UNSUPPORTED")
                    if part.get("type") == "tool_reference":
                        name = part.get("tool_name")
                        if (set(part) - {"type", "tool_name", "cache_control"} or
                                not isinstance(name, str) or name not in definitions):
                            raise ValueError("MESSAGES_TOOL_REFERENCE_UNDECLARED")
                        activated.add(name)
                        references.append({"tool_use_id": block["tool_use_id"], "tool_name": name})
                        # The local Chat templates have no reference block. Keep
                        # its identity at the native result position as JSON;
                        # its exact declared schema enters the callable catalog.
                        parts[index] = {"type": "text", "text": json.dumps(
                            {"type": "tool_reference", "tool_name": name},
                            ensure_ascii=False, separators=(",", ":"))}
                    elif part.get("type") != "text" or not isinstance(part.get("text"), str):
                        raise ValueError("TOOL_RESULT_CONTENT_UNSUPPORTED")
                # MLX's native list conversion strips surrounding whitespace.
                # A plain string follows its byte-preserving path instead.
                block["content"] = "\n".join(part["text"] for part in parts)
            elif block.get("type") == "tool_reference":
                raise ValueError("MESSAGES_TOOL_REFERENCE_OUTSIDE_RESULT")
            elif block.get("type") in ("thinking", "redacted_thinking"):
                # Keep-all cannot silently discard pre-existing reasoning that
                # these non-thinking local templates cannot represent.
                raise ValueError("MESSAGES_THINKING_HISTORY_UNSUPPORTED")
    selected = []
    for tool in tools:
        if not tool.get("defer_loading") or tool["name"] in activated:
            selected.append({key: value for key, value in tool.items()
                             if key not in ("defer_loading", "allowed_callers")})
    request["tools"] = selected
    choice = request.get("tool_choice")
    if isinstance(choice, dict) and choice.get("type") == "tool" and choice.get("name") not in {tool["name"] for tool in selected}:
        raise ValueError("MESSAGES_TOOL_CHOICE_UNLOADED")
    return request, {"context_edit": "keep-all-noop" if context else "none",
                     "thinking_override": thinking_override,
                     "activated_references": references,
                     "active_tool_names": [tool["name"] for tool in selected],
                     "deferred_tool_names": [tool["name"] for tool in tools if tool.get("defer_loading") and tool["name"] not in activated],
                     "definition_placement": "local-chat-template-tool-section",
                     "reference_placement": "original-tool-result-as-exact-name-json",
                     "system_turns_projected": system_turns,
                     "search_or_tool_selection": False, "argument_repair": False}
