"""Loopback protocol translation using pinned LiteLLM pure transformations.

No agent loop, generation retry, network provider discovery or argument repair.
The outer gateway owns budgets; this process forwards one backend request only.
SPDX-License-Identifier: MIT
"""
import argparse
import copy
import importlib.util
import importlib.metadata
import json
import os
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from functools import lru_cache

VERSION = '1.109.0'
MAX_BYTES = 16 * 1024 * 1024
SAMPLERS = ('temperature', 'top_p', 'top_k', 'repetition_penalty', 'presence_penalty',
            'frequency_penalty', 'min_p', 'top_n_sigma', 'p_less', 'typical_p',
            'repetition_context_size', 'presence_context_size', 'frequency_context_size',
            'enable_thinking', 'seed')


def redact(value):
    if isinstance(value, dict):
        return {key: '[REDACTED]' if re.fullmatch(r'(?:authorization|proxy-authorization|cookie|set-cookie|api[-_]?key|access[-_]?token|refresh[-_]?token|password|secret)', key, re.I) else redact(child) for key, child in value.items()}
    if isinstance(value, list):
        return [redact(child) for child in value]
    if isinstance(value, str):
        return re.sub(r'Bearer\s+[A-Za-z0-9._~+/-]+={0,2}', 'Bearer [REDACTED]', value, flags=re.I)
    return value


def libraries():
    if importlib.metadata.version('litellm') != VERSION:
        raise ValueError('TRANSLATION_RUNTIME_UNVERIFIED')
    if importlib.metadata.version('llguidance') != '1.9.1':
        raise ValueError('CUSTOM_GRAMMAR_RUNTIME_UNVERIFIED')
    # Import uses the packaged model map; never fetch a remote pricing manifest.
    os.environ['LITELLM_LOCAL_MODEL_COST_MAP'] = 'True'
    os.environ['DO_NOT_TRACK'] = '1'
    import litellm
    litellm.telemetry = False
    litellm.drop_params = False
    from litellm.responses.litellm_completion_transformation.transformation import LiteLLMCompletionResponsesConfig
    from litellm.google_genai.adapters.transformation import GoogleGenAIAdapter
    from litellm.llms.anthropic.messages.adapters.transformation import AnthropicAdapter
    from litellm.types.utils import ModelResponse
    return LiteLLMCompletionResponsesConfig, GoogleGenAIAdapter, ModelResponse, AnthropicAdapter


def object_arguments(value):
    if isinstance(value, str):
        value = json.loads(value)
    if not isinstance(value, dict):
        raise ValueError('TOOL_ARGUMENTS_INVALID')


def has_custom_responses(body):
    return any(isinstance(tool, dict) and tool.get('type') == 'custom' for tool in body.get('tools', [])) or isinstance(body.get('input'), list) and any(isinstance(item, dict) and item.get('type') in ('custom_tool_call', 'custom_tool_call_output') for item in body['input'])


def needs_responses_translation(body):
    return has_custom_responses(body) or any(isinstance(tool, dict) and tool.get('type') == 'namespace' for tool in body.get('tools', [])) or isinstance(body.get('input'), list) and any(isinstance(item, dict) and 'namespace' in item for item in body['input'])


def namespace_declarations(body):
    """Validate before LiteLLM can drop unknown members or guess bare names.

    The alias and description separator are literal LiteLLM 1.109.0 encodings.
    All cross-namespace/top-level collisions fail; no fallback renaming occurs.
    """
    def valid_name(value):
        return isinstance(value, str) and re.fullmatch(r'[A-Za-z0-9_-]{1,64}', value) is not None
    tools = body.get('tools', [])
    if not isinstance(tools, list) or len(tools) > 1024:
        raise ValueError('SERVER_TOOL_TYPE_UNSUPPORTED')
    rows, namespaces, aliases, identities = [], set(), set(), set()
    def add(tool, namespace=None, description=''):
        if not isinstance(tool, dict) or tool.get('type') not in ('function', 'custom'):
            raise ValueError('SERVER_TOOL_TYPE_UNSUPPORTED')
        fields = {'type', 'name', 'description', 'defer_loading', 'allowed_callers'} | ({'parameters', 'strict'} if tool['type'] == 'function' else {'format'})
        if set(tool) - fields:
            raise ValueError('RESPONSES_TOOL_FIELDS_UNSUPPORTED')
        if not valid_name(tool.get('name')) or 'description' in tool and not isinstance(tool['description'], str) or 'parameters' in tool and not isinstance(tool['parameters'], dict) or 'strict' in tool and not isinstance(tool['strict'], bool) or 'format' in tool and not isinstance(tool['format'], dict) or 'defer_loading' in tool and not isinstance(tool['defer_loading'], bool) or 'allowed_callers' in tool and (not isinstance(tool['allowed_callers'], list) or any(not isinstance(value, str) for value in tool['allowed_callers'])):
            raise ValueError('RESPONSES_TOOL_IDENTITY_INVALID')
        alias = namespace + '__' + tool['name'] if namespace is not None else tool['name']
        if not valid_name(alias):
            raise ValueError('RESPONSES_QUALIFIED_NAME_UNSUPPORTED')
        identity = (namespace, tool['name'])
        if alias in aliases or identity in identities:
            raise ValueError('RESPONSES_NAMESPACE_COLLISION')
        aliases.add(alias); identities.add(identity)
        rows.append({'alias': alias, 'namespace': namespace, 'name': tool['name'], 'type': tool['type'], 'tool': tool, 'description': description})
        if len(rows) > 1024:
            raise ValueError('SERVER_TOOL_TYPE_UNSUPPORTED')
    for tool in tools:
        if not isinstance(tool, dict):
            raise ValueError('SERVER_TOOL_TYPE_UNSUPPORTED')
        if tool.get('type') != 'namespace':
            add(tool); continue
        if set(tool) - {'type', 'name', 'description', 'tools'}:
            raise ValueError('RESPONSES_NAMESPACE_FIELDS_UNSUPPORTED')
        if not valid_name(tool.get('name')) or 'description' in tool and not isinstance(tool['description'], str) or not isinstance(tool.get('tools'), list) or not 0 < len(tool['tools']) <= 1024:
            raise ValueError('RESPONSES_NAMESPACE_INVALID')
        if tool['name'] in namespaces:
            raise ValueError('RESPONSES_NAMESPACE_COLLISION')
        namespaces.add(tool['name'])
        for member in tool['tools']:
            add(member, tool['name'], tool.get('description', ''))
    return rows


def encode_namespace_responses(body):
    request = copy.deepcopy(body)
    rows = namespace_declarations(request)
    active = any(row['namespace'] is not None for row in rows)
    by_identity = {(row['namespace'], row['name']): row for row in rows}
    ledger = {row['alias']: {key: row[key] for key in ('namespace', 'name', 'type')} for row in rows} if active else {}
    def encode_identity(item):
        namespace = item.get('namespace')
        if 'namespace' in item and (not isinstance(namespace, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,64}', namespace)):
            raise ValueError('RESPONSES_NAMESPACE_IDENTITY_INVALID')
        if active or 'namespace' in item:
            row = by_identity.get((namespace, item.get('name')))
            expected = 'custom' if item.get('type') in ('custom', 'custom_tool_call') else 'function'
            if row is None or row['type'] != expected:
                raise ValueError('RESPONSES_NAMESPACE_IDENTITY_INVALID')
            item['name'] = row['alias']; item.pop('namespace', None)
    if active:
        flattened = []
        for row in rows:
            tool = copy.deepcopy(row['tool']); tool['name'] = row['alias']
            if row['namespace'] is not None and row['description']:
                tool['description'] = row['description'] + ('\n\n' + tool['description'] if tool.get('description') else '')
            flattened.append(tool)
        request['tools'] = flattened
    for item in request.get('input', []) if isinstance(request.get('input'), list) else []:
        if not isinstance(item, dict):
            continue
        if item.get('type') in ('function_call', 'custom_tool_call'):
            if active and set(item) - {'type', 'id', 'call_id', 'name', 'namespace', 'arguments', 'input', 'status', 'provider_specific_fields'}:
                raise ValueError('RESPONSES_NAMESPACE_HISTORY_FIELDS_UNSUPPORTED')
            encode_identity(item)
        elif 'namespace' in item:
            raise ValueError('RESPONSES_NAMESPACE_IDENTITY_INVALID')
    if isinstance(request.get('tool_choice'), dict) and (active or 'namespace' in request['tool_choice']):
        choice = request['tool_choice']
        if choice.get('type') not in ('function', 'custom') or set(choice) - {'type', 'name', 'namespace'}:
            raise ValueError('RESPONSES_NAMESPACE_CHOICE_UNSUPPORTED')
        encode_identity(choice)
    return request, ledger


def decode_namespace_calls(response, ledger):
    result = copy.deepcopy(response)
    for item in result.get('output', []):
        if item.get('type') not in ('function_call', 'custom_tool_call'):
            continue
        if 'namespace' in item:
            raise ValueError('RESPONSES_NAMESPACE_IDENTITY_INVALID')
        if not ledger:
            continue
        row = ledger.get(item.get('name'))
        if row is None or item['type'] != ('custom_tool_call' if row['type'] == 'custom' else 'function_call'):
            raise ValueError('RESPONSES_NAMESPACE_IDENTITY_INVALID')
        item['name'] = row['name']
        if row['namespace'] is not None:
            item['namespace'] = row['namespace']
    return result


def preserve_responses_payload(transformed, encoded):
    """Keep exact schemas and call bytes instead of publisher schema defaults.

    This is representation conversion only. No field is inferred or repaired.
    """
    tools = encoded.get('tools', [])
    received = transformed.get('tools', [])
    if not isinstance(received, list) or len(received) != len(tools) or any(target.get('type') != 'function' or target.get('function', {}).get('name') != source['name'] for source, target in zip(tools, received)):
        raise ValueError('RESPONSES_LIBRARY_TOOL_PAYLOAD_CHANGED')
    if 'tools' in encoded:
        transformed['tools'] = [{'type': 'function', 'function': {key: copy.deepcopy(value) for key, value in tool.items() if key not in ('type', 'defer_loading', 'allowed_callers')}, **{key: copy.deepcopy(tool[key]) for key in ('defer_loading', 'allowed_callers') if key in tool}} for tool in tools]
    source = [item for item in encoded.get('input', []) if isinstance(item, dict) and item.get('type') == 'function_call'] if isinstance(encoded.get('input'), list) else []
    target = [call for message in transformed.get('messages', []) for call in message.get('tool_calls', [])]
    if len(source) != len(target) or any(call.get('id') != item['call_id'] or call.get('function', {}).get('name') != item['name'] or call.get('function', {}).get('arguments') != item['arguments'] for item, call in zip(source, target)):
        raise ValueError('RESPONSES_LIBRARY_TOOL_HISTORY_CHANGED')


@lru_cache(maxsize=32)
def grammar_matcher(serialized):
    specification = json.loads(serialized)
    if specification.get('type') == 'text' and set(specification) == {'type'}:
        return None
    if set(specification) != {'type', 'syntax', 'definition'} or specification.get('type') != 'grammar' or specification.get('syntax') not in ('lark', 'regex') or not isinstance(specification.get('definition'), str) or not 0 < len(specification['definition'].encode()) <= 128 * 1024:
        raise ValueError('CUSTOM_TOOL_FORMAT_UNSUPPORTED')
    if importlib.metadata.version('llguidance') != '1.9.1':
        raise ValueError('CUSTOM_GRAMMAR_RUNTIME_UNVERIFIED')
    from llguidance import LLMatcher, LLTokenizer, TokenizerWrapper
    class Bytes:
        eos_token_id = 256
        bos_token_id = None
        tokens = [bytes([value]) for value in range(256)] + [b'<eos>']
        special_token_ids = [256]
        def __call__(self, value):
            return list(value if isinstance(value, bytes) else value.encode('utf8'))
    tokenizer = LLTokenizer(TokenizerWrapper(Bytes()), slices=[])
    grammar = (LLMatcher.grammar_from_lark if specification['syntax'] == 'lark' else LLMatcher.grammar_from_regex)(specification['definition'])
    matcher = LLMatcher(tokenizer, grammar, log_level=0)
    if matcher.is_error():
        raise ValueError('CUSTOM_TOOL_GRAMMAR_UNSUPPORTED:' + matcher.get_error())
    return matcher


def custom_specifications(body):
    selected, names = {}, set()
    for tool in body.get('tools', []):
        if not isinstance(tool, dict) or not isinstance(tool.get('name'), str) or not tool['name'] or tool['name'] in names:
            raise ValueError('RESPONSES_TOOL_IDENTITY_INVALID')
        names.add(tool['name'])
        if tool.get('type') == 'custom':
            if not isinstance(tool.get('description', ''), str):
                raise ValueError('CUSTOM_TOOL_DESCRIPTION_INVALID')
            specification = tool.get('format', {'type': 'text'})
            if not isinstance(specification, dict):
                raise ValueError('CUSTOM_TOOL_FORMAT_UNSUPPORTED')
            grammar_matcher(json.dumps(specification, sort_keys=True))
            selected[tool['name']] = specification
    return selected


def encode_custom_responses(body):
    """Reversible wire encoding. Never supply, trim or repair a tool argument."""
    request = copy.deepcopy(body)
    custom = custom_specifications(request)
    for index, tool in enumerate(request.get('tools', [])):
        if tool.get('type') != 'custom':
            continue
        specification = custom[tool['name']]
        parameter_description = 'Exact raw input for this custom tool.'
        if specification['type'] == 'grammar':
            parameter_description += '\nNative grammar (' + specification['syntax'] + '):\n' + specification['definition']
        request['tools'][index] = {'type': 'function', 'name': tool['name'], 'description': tool.get('description', ''),
            'parameters': {'type': 'object', 'properties': {'input': {'type': 'string', 'description': parameter_description}}, 'required': ['input'], 'additionalProperties': False},
            **{key: tool[key] for key in ('defer_loading', 'allowed_callers') if key in tool}}
    if isinstance(request.get('input'), list):
        custom_calls = set()
        for index, item in enumerate(request['input']):
            if not isinstance(item, dict):
                continue
            if item.get('type') == 'custom_tool_call':
                if item.get('name') not in custom or not isinstance(item.get('input'), str) or not isinstance(item.get('call_id'), str):
                    raise ValueError('CUSTOM_TOOL_HISTORY_INVALID')
                custom_calls.add(item['call_id'])
                encoded = {key: value for key, value in item.items() if key != 'input'}
                encoded.update(type='function_call', arguments=json.dumps({'input': item['input']}, ensure_ascii=False, separators=(',', ':')))
                request['input'][index] = encoded
            elif item.get('type') == 'custom_tool_call_output':
                if item.get('call_id') not in custom_calls:
                    raise ValueError('ORPHAN_TOOL_RESULT_UNSUPPORTED')
                request['input'][index] = {**item, 'type': 'function_call_output'}
    if isinstance(request.get('tool_choice'), dict) and request['tool_choice'].get('type') == 'custom':
        if request['tool_choice'].get('name') not in custom:
            raise ValueError('CUSTOM_TOOL_CHOICE_INVALID')
        request['tool_choice'] = {**request['tool_choice'], 'type': 'function'}
    return request, custom


def decode_custom_calls(response, custom):
    def pairs(entries):
        result = {}
        for key, value in entries:
            if key in result:
                raise ValueError('CUSTOM_TOOL_ARGUMENTS_INVALID')
            result[key] = value
        return result
    def invalid_constant(_value):
        raise ValueError('CUSTOM_TOOL_ARGUMENTS_INVALID')
    result = copy.deepcopy(response)
    for index, item in enumerate(result.get('output', [])):
        if item.get('type') != 'function_call' or item.get('name') not in custom:
            continue
        try:
            arguments = json.loads(item['arguments'], object_pairs_hook=pairs, parse_constant=invalid_constant)
        except (KeyError, TypeError, ValueError) as error:
            raise ValueError('CUSTOM_TOOL_ARGUMENTS_INVALID') from error
        if not isinstance(arguments, dict) or set(arguments) != {'input'} or not isinstance(arguments['input'], str):
            raise ValueError('CUSTOM_TOOL_ARGUMENTS_INVALID')
        raw = arguments['input']
        matcher = grammar_matcher(json.dumps(custom[item['name']], sort_keys=True))
        if matcher is not None:
            check = matcher.deep_copy()
            if not check.consume_tokens(list(raw.encode('utf8'))) or not check.is_accepting():
                raise ValueError('CUSTOM_TOOL_GRAMMAR_REJECTED')
        decoded = {key: value for key, value in item.items() if key != 'arguments'}
        decoded.update(type='custom_tool_call', input=raw, id='ctc_' + item['call_id'])
        result['output'][index] = decoded
    return result


def validate_responses(body):
    if body.get('previous_response_id') or body.get('context_management', []) != [] or body.get('background', False):
        raise ValueError('STATEFUL_OR_COMPACTED_RESPONSES_UNSUPPORTED')
    if body.get('truncation') not in (None, 'disabled'):
        raise ValueError('TRUNCATION_UNSUPPORTED')
    if body.get('reasoning') not in (None, {}, {'effort': 'none'}, {'effort': 'minimal'}):
        raise ValueError('THINKING_DISABLED')
    for tool in body.get('tools', []):
        if not isinstance(tool, dict) or tool.get('type') != 'function' or not isinstance(tool.get('name'), str) or not isinstance(tool.get('parameters', {}), dict):
            raise ValueError('RESPONSES_TOOL_TYPE_UNSUPPORTED')
    items = body.get('input')
    if isinstance(items, str):
        return
    if not isinstance(items, list):
        raise ValueError('RESPONSES_INPUT_UNSUPPORTED')
    calls = set()
    for item in items:
        if not isinstance(item, dict):
            raise ValueError('RESPONSES_INPUT_UNSUPPORTED')
        kind = item.get('type', 'message')
        if kind == 'function_call':
            if not isinstance(item.get('call_id'), str) or not item['call_id'] or item['call_id'] in calls or not isinstance(item.get('name'), str):
                raise ValueError('TOOL_HISTORY_INVALID')
            object_arguments(item.get('arguments')); calls.add(item['call_id'])
        elif kind == 'function_call_output':
            if item.get('call_id') not in calls:
                raise ValueError('ORPHAN_TOOL_RESULT_UNSUPPORTED')
        elif kind == 'message':
            if item.get('role') not in ('system', 'developer', 'user', 'assistant'):
                raise ValueError('RESPONSES_ROLE_UNSUPPORTED')
            content = item.get('content')
            if isinstance(content, list):
                for part in content:
                    if not isinstance(part, dict) or part.get('type') not in ('input_text', 'output_text', 'input_image'):
                        raise ValueError('RESPONSES_CONTENT_UNSUPPORTED')
                    if part['type'] == 'input_image' and not str(part.get('image_url', '')).startswith('data:image/'):
                        raise ValueError('INLINE_IMAGE_REQUIRED')
            elif not isinstance(content, str):
                raise ValueError('RESPONSES_CONTENT_UNSUPPORTED')
        else:
            raise ValueError('RESPONSES_INPUT_UNSUPPORTED')


def validate_gemini(body):
    if not isinstance(body.get('contents'), list):
        raise ValueError('GEMINI_CONTENTS_UNSUPPORTED')
    config = body.get('generationConfig', {})
    if not isinstance(config, dict) or config.get('candidateCount', 1) != 1:
        raise ValueError('MULTIGENERATION_UNSUPPORTED')
    if config.get('thinkingConfig') not in (None, {}, {'thinkingBudget': 0}):
        raise ValueError('THINKING_DISABLED')
    pending, all_ids, calls, results = {}, set(), [], []
    for content_index, content in enumerate(body['contents']):
        if not isinstance(content, dict) or content.get('role', 'user') not in ('user', 'model') or not isinstance(content.get('parts'), list):
            raise ValueError('GEMINI_CONTENTS_UNSUPPORTED')
        current_calls = []
        for part_index, part in enumerate(content['parts']):
            if not isinstance(part, dict):
                raise ValueError('GEMINI_PART_UNSUPPORTED')
            kinds = set(part) - {'thoughtSignature'}
            if len(kinds) != 1:
                raise ValueError('GEMINI_PART_UNSUPPORTED')
            kind = next(iter(kinds))
            if kind == 'text' and isinstance(part[kind], str):
                continue
            if kind == 'inlineData' and isinstance(part[kind], dict) and part[kind].get('mimeType') in ('image/png', 'image/jpeg', 'image/webp'):
                continue
            if kind == 'functionCall' and content.get('role') == 'model':
                call = part[kind]; name = call.get('name') if isinstance(call, dict) else None
                if not isinstance(name, str) or not name:
                    raise ValueError('GEMINI_FUNCTION_NAME_INVALID')
                identity = call.get('id')
                if identity is not None and (not isinstance(identity, str) or not identity or len(identity) > 256):
                    raise ValueError('GEMINI_CALL_ID_INVALID')
                identity = identity or f'ud_eval_gemini_{content_index}_{part_index}'
                if identity in all_ids:
                    raise ValueError('GEMINI_DUPLICATE_CALL_ID')
                object_arguments(call.get('args')); all_ids.add(identity)
                row = {'id': identity, 'name': name, 'args': call['args'], 'explicit_id': 'id' in call}
                current_calls.append(row); calls.append(row)
            elif kind == 'functionResponse' and content.get('role', 'user') == 'user':
                result = part[kind]
                if not isinstance(result, dict) or 'response' not in result:
                    raise ValueError('ORPHAN_TOOL_RESULT_UNSUPPORTED')
                matches = [row for row in pending.values() if row['name'] == result.get('name') and (result.get('id') is None or row['id'] == result['id'])]
                if len(matches) != 1:
                    raise ValueError('GEMINI_AMBIGUOUS_PARALLEL_CALL_UNSUPPORTED' if len(matches) > 1 else 'ORPHAN_TOOL_RESULT_UNSUPPORTED')
                row = matches[0]; pending.pop(row['id']); results.append({'id': row['id'], 'name': row['name'], 'response': result['response']})
            else:
                raise ValueError('GEMINI_PART_UNSUPPORTED')
        if current_calls:
            for name in {row['name'] for row in current_calls}:
                same_name = [row for row in current_calls if row['name'] == name]
                if len(same_name) > 1 and not all(row['explicit_id'] for row in same_name):
                    raise ValueError('GEMINI_AMBIGUOUS_PARALLEL_CALL_UNSUPPORTED')
            if pending:
                raise ValueError('GEMINI_UNRESOLVED_TOOL_HISTORY')
            pending = {row['id']: row for row in current_calls}
    for tool in body.get('tools', []):
        if not isinstance(tool, dict) or set(tool) != {'functionDeclarations'} or not isinstance(tool['functionDeclarations'], list):
            raise ValueError('GEMINI_TOOL_TYPE_UNSUPPORTED')
    return calls, results


def restore_gemini_request_ids(transformed, ledger):
    """Pinned LiteLLM loses IDs. Restore only after exact payload/order checks."""
    calls, results = ledger
    translated_calls = [call for message in transformed.get('messages', []) for call in message.get('tool_calls', [])]
    translated_results = [message for message in transformed.get('messages', []) if message.get('role') == 'tool']
    if len(calls) != len(translated_calls) or len(results) != len(translated_results):
        raise ValueError('GEMINI_LIBRARY_TOOL_PAYLOAD_CHANGED')
    for source, target in zip(calls, translated_calls):
        function = target.get('function', {})
        if function.get('name') != source['name'] or json.loads(function.get('arguments', 'null')) != source['args']:
            raise ValueError('GEMINI_LIBRARY_TOOL_PAYLOAD_CHANGED')
        target['id'] = source['id']
    for source, target in zip(results, translated_results):
        if not isinstance(target.get('content'), str) or json.loads(target['content']) != source['response']:
            raise ValueError('GEMINI_LIBRARY_TOOL_PAYLOAD_CHANGED')
        target['tool_call_id'] = source['id']


def restore_gemini_response_ids(result, response):
    calls = response['choices'][0].get('message', {}).get('tool_calls', [])
    converted = [part['functionCall'] for candidate in result.get('candidates', []) for part in candidate.get('content', {}).get('parts', []) if 'functionCall' in part]
    if len(calls) != len(converted):
        raise ValueError('GEMINI_LIBRARY_TOOL_PAYLOAD_CHANGED')
    seen = set()
    for source, target in zip(calls, converted):
        identity, function = source.get('id'), source.get('function', {})
        if not isinstance(identity, str) or not identity or identity in seen or len(identity) > 256:
            raise ValueError('GEMINI_CALL_ID_INVALID')
        seen.add(identity)
        if function.get('name') != target.get('name') or json.loads(function.get('arguments', 'null')) != target.get('args'):
            raise ValueError('GEMINI_LIBRARY_TOOL_PAYLOAD_CHANGED')
        target['id'] = identity


@lru_cache(maxsize=1)
def messages_protocol():
    source = Path(__file__).with_name('messages_protocol.py')
    spec = importlib.util.spec_from_file_location('ud_local_messages_protocol', source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def normalize_messages(body):
    return messages_protocol().normalize_messages_request(body)


def validate_messages(body):
    body, _projection = normalize_messages(body)
    if not isinstance(body.get('messages'), list):
        raise ValueError('MESSAGES_REQUIRED')
    for tool in body.get('tools', []):
        if not isinstance(tool, dict) or tool.get('type') not in (None, 'custom') or not isinstance(tool.get('name'), str) or len(tool['name']) > 64 or not isinstance(tool.get('input_schema'), dict):
            raise ValueError('MESSAGES_TOOL_TYPE_UNSUPPORTED')
    known = set()
    for message in body['messages']:
        if not isinstance(message, dict) or message.get('role') not in ('user', 'assistant'):
            raise ValueError('MESSAGES_ROLE_UNSUPPORTED')
        content = message.get('content')
        if isinstance(content, str):
            continue
        if not isinstance(content, list):
            raise ValueError('MESSAGES_CONTENT_UNSUPPORTED')
        for block in content:
            if not isinstance(block, dict):
                raise ValueError('MESSAGES_CONTENT_UNSUPPORTED')
            kind = block.get('type')
            if kind == 'text' and isinstance(block.get('text'), str):
                continue
            if kind == 'tool_use' and message['role'] == 'assistant':
                if not isinstance(block.get('id'), str) or block['id'] in known or not isinstance(block.get('name'), str):
                    raise ValueError('TOOL_HISTORY_INVALID')
                object_arguments(block.get('input')); known.add(block['id'])
            elif kind == 'tool_result' and message['role'] == 'user':
                if block.get('tool_use_id') not in known:
                    raise ValueError('ORPHAN_TOOL_RESULT_UNSUPPORTED')
                parts = block.get('content')
                if not isinstance(parts, str) and (not isinstance(parts, list) or any(not isinstance(part, dict) or part.get('type') != 'text' or not isinstance(part.get('text'), str) for part in parts)):
                    raise ValueError('TOOL_RESULT_CONTENT_UNSUPPORTED')
            elif kind == 'image' and message['role'] == 'user':
                source = block.get('source', {})
                if source.get('type') != 'base64' or source.get('media_type') not in ('image/png', 'image/jpeg', 'image/webp') or not isinstance(source.get('data'), str):
                    raise ValueError('INLINE_IMAGE_REQUIRED')
            else:
                raise ValueError('MESSAGES_CONTENT_UNSUPPORTED')
    return body


def to_chat(protocol, body, model, adapters=None):
    adapters = adapters or libraries()
    response_adapter, gemini_adapter, _ = adapters[:3]
    request = copy.deepcopy(body)
    if protocol == 'responses':
        request, _namespaces = encode_namespace_responses(request)
        request, _custom = encode_custom_responses(request)
        validate_responses(request)
        options = {key: value for key, value in request.items() if key not in ('input', 'model')}
        transformed = response_adapter.transform_responses_api_request_to_chat_completion_request(
            model=model, input=request['input'], responses_api_request=options,
            custom_llm_provider='openai', stream=False, drop_params=False)
        preserve_responses_payload(transformed, request)
        transformed.pop('custom_llm_provider', None)
        # These are transport-only response lifecycle fields; no stored history.
        transformed.pop('metadata', None)
        transformed.pop('parallel_tool_calls', None)
        transformed.pop('reasoning_effort', None)
    elif protocol == 'gemini':
        ledger = validate_gemini(request)
        config = request.get('generationConfig', {})
        transformed = gemini_adapter().translate_generate_content_to_completion(
            model=model, contents=request['contents'], config=config,
            **{key: request[key] for key in ('systemInstruction', 'tools', 'toolConfig') if key in request})
        restore_gemini_request_ids(transformed, ledger)
        # The publisher adapter intentionally omits topK and provider extensions.
        # Preserve their exact numeric/boolean values as backend sampler fields.
        for source, target in (('topK', 'top_k'), ('topP', 'top_p'), ('presencePenalty', 'presence_penalty'), ('frequencyPenalty', 'frequency_penalty')):
            if source in config:
                transformed[target] = config[source]
        request = {**request, **config}
    elif protocol == 'messages':
        request = validate_messages(request)
        # The library mutates its input dictionary. Preserve the native request
        # for evidence and require that no tool name was rewritten.
        translated, names = adapters[3]().translate_completion_input_params_with_tool_mapping(
            copy.deepcopy(request), custom_llm_provider='openai', drop_params=False)
        if names or translated is None:
            raise ValueError('MESSAGES_TOOL_REWRITING_UNSUPPORTED')
        transformed = dict(translated)
        # The publisher adapter derives user/cache-routing fields from native
        # metadata. They never enter the native MLX prompt or sampling policy.
        for key in ('metadata', 'user', 'prompt_cache_key'):
            transformed.pop(key, None)
        transformed.pop('thinking', None)
        if transformed.get('reasoning_effort') not in (None, 'none'):
            raise ValueError('THINKING_DISABLED')
        transformed.pop('reasoning_effort', None)
    else:
        raise ValueError('TRANSLATED_PROTOCOL_UNSUPPORTED')
    for key in SAMPLERS:
        if key in request:
            transformed[key] = request[key]
    transformed.update(model=model, stream=False, context_management=[])
    if transformed.get('enable_thinking', False) is not False:
        raise ValueError('THINKING_DISABLED')
    # No model SDK is called: the returned bytes are the sole backend request.
    return json.loads(json.dumps(transformed, allow_nan=False))


def from_chat(protocol, body, response, model, adapters=None):
    adapters = adapters or libraries()
    response_adapter, gemini_adapter, model_response = adapters[:3]
    if response.get('model') != model or len(response.get('choices', [])) != 1:
        raise ValueError('BACKEND_MODEL_ATTRIBUTION_UNVERIFIED')
    usage = response.get('usage', {})
    if any(not isinstance(usage.get(key), int) or isinstance(usage[key], bool) or usage[key] < 0 for key in ('prompt_tokens', 'completion_tokens')):
        raise ValueError('BACKEND_TOKEN_ACCOUNTING_UNVERIFIED')
    if protocol == 'responses':
        encoded, namespaces = encode_namespace_responses(body)
        encoded, custom = encode_custom_responses(encoded)
        result = response_adapter.transform_chat_completion_response_to_responses_api_response(
            request_input=encoded['input'], responses_api_request={key: value for key, value in encoded.items() if key not in ('input', 'model')}, chat_completion_response=response)
        native = result.model_dump(mode='json', exclude_none=True)
        backend_calls = response['choices'][0].get('message', {}).get('tool_calls', [])
        native_calls = [item for item in native.get('output', []) if item.get('type') == 'function_call']
        if len(backend_calls) != len(native_calls) or any(call.get('type') != 'function' or not isinstance(call.get('id'), str) or not call['id'] or not isinstance(call.get('function', {}).get('arguments'), str) or item.get('call_id') != call['id'] or item.get('name') != call.get('function', {}).get('name') or item.get('arguments') != call['function']['arguments'] for call, item in zip(backend_calls, native_calls)):
            raise ValueError('RESPONSES_LIBRARY_TOOL_OUTPUT_CHANGED')
        decoded = decode_namespace_calls(decode_custom_calls(native, custom), namespaces)
        decoded['tools'] = body.get('tools', [])
        if 'tool_choice' in body:
            decoded['tool_choice'] = body['tool_choice']
        return decoded
    if protocol == 'messages':
        result = adapters[3]().translate_completion_output_params(model_response(**response))
        if result is None:
            raise ValueError('MESSAGES_RESPONSE_UNSUPPORTED')
        return result.model_dump(mode='json', exclude_none=True) if hasattr(result, 'model_dump') else dict(result)
    result = gemini_adapter().translate_completion_to_generate_content(model_response(**response))
    restore_gemini_response_ids(result, response)
    result['modelVersion'] = response['model']
    return result


def stream_events(protocol, response):
    """Frame a complete translated response; never release partial tool calls."""
    if protocol == 'gemini':
        return [response]
    if protocol == 'messages':
        events = [{'type': 'message_start', 'message': {**response, 'content': [], 'stop_reason': None, 'stop_sequence': None, 'usage': {**response['usage'], 'output_tokens': 0}}}]
        for index, block in enumerate(response.get('content', [])):
            if block.get('type') == 'tool_use':
                start, delta = {**block, 'input': {}}, {'type': 'input_json_delta', 'partial_json': json.dumps(block['input'], separators=(',', ':'))}
            elif block.get('type') == 'text':
                start, delta = {**block, 'text': ''}, {'type': 'text_delta', 'text': block['text']}
            else:
                raise ValueError('MESSAGES_OUTPUT_TYPE_UNSUPPORTED')
            events.extend([{'type': 'content_block_start', 'index': index, 'content_block': start}, {'type': 'content_block_delta', 'index': index, 'delta': delta}, {'type': 'content_block_stop', 'index': index}])
        events.extend([{'type': 'message_delta', 'delta': {'stop_reason': response['stop_reason'], 'stop_sequence': response.get('stop_sequence')}, 'usage': {'output_tokens': response['usage']['output_tokens']}}, {'type': 'message_stop'}])
        return events
    if response.get('status') != 'completed':
        return [{'type': 'response.incomplete', 'response': response}]
    initial = {**response, 'status': 'in_progress', 'output': []}
    events = [{'type': 'response.created', 'response': initial}, {'type': 'response.in_progress', 'response': initial}]
    for index, item in enumerate(response.get('output', [])):
        if item.get('type') in ('function_call', 'custom_tool_call'):
            custom = item['type'] == 'custom_tool_call'
            field, event = ('input', 'custom_tool_call_input') if custom else ('arguments', 'function_call_arguments')
            events.extend([
                {'type': 'response.output_item.added', 'output_index': index, 'item': {**item, field: '', 'status': 'in_progress'}},
                {'type': 'response.' + event + '.delta', 'output_index': index, 'item_id': item['id'], 'delta': item[field]},
                {'type': 'response.' + event + '.done', 'output_index': index, 'item_id': item['id'], field: item[field]},
            ])
        elif item.get('type') == 'message':
            events.append({'type': 'response.output_item.added', 'output_index': index, 'item': {**item, 'content': [], 'status': 'in_progress'}})
            for part_index, part in enumerate(item.get('content', [])):
                if part.get('type') != 'output_text':
                    raise ValueError('RESPONSES_OUTPUT_PART_UNSUPPORTED')
                base = {'output_index': index, 'content_index': part_index, 'item_id': item['id']}
                events.extend([
                    {'type': 'response.content_part.added', **base, 'part': {**part, 'text': ''}},
                    {'type': 'response.output_text.delta', **base, 'delta': part['text']},
                    {'type': 'response.output_text.done', **base, 'text': part['text']},
                    {'type': 'response.content_part.done', **base, 'part': part},
                ])
        else:
            raise ValueError('RESPONSES_OUTPUT_TYPE_UNSUPPORTED')
        events.append({'type': 'response.output_item.done', 'output_index': index, 'item': item})
    events.append({'type': 'response.completed', 'response': response})
    for ordinal, event in enumerate(events):
        event['sequence_number'] = ordinal
    return events


def protocol_for(route):
    if route == '/v1/responses':
        return 'responses'
    if re.fullmatch(r'/v1(?:beta)?/models/.+:(?:generateContent|streamGenerateContent)', route):
        return 'gemini'
    return {'/v1/chat/completions': 'chat', '/v1/messages': 'messages'}.get(route)


def handler_for(config, adapters):
    backend = urllib.parse.urlparse(config['upstream'])
    if backend.scheme != 'http' or backend.hostname != '127.0.0.1' or backend.username or backend.query or backend.fragment:
        raise ValueError('LOOPBACK_BACKEND_REQUIRED')
    traffic = Path(config['traffic'])
    lock = threading.Lock()
    def record(event):
        with lock:
            with traffic.open('a') as output:
                output.write(json.dumps(redact({'at': time.time(), **event}), allow_nan=False) + '\n')

    class Handler(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'
        def log_message(self, *_args):
            pass
        def send_json(self, code, body):
            encoded = json.dumps(body, allow_nan=False).encode()
            self.send_response(code); self.send_header('content-type', 'application/json'); self.send_header('content-length', str(len(encoded))); self.end_headers(); self.wfile.write(encoded)
        def do_GET(self):
            if self.path == '/health':
                self.send_json(200, {'status': 'ok', 'litellm': VERSION, 'llguidance': '1.9.1', 'model': config['model']})
            else:
                self.send_json(404, {'error': 'ROUTE_UNSUPPORTED'})
        def do_POST(self):
            request_id = self.headers.get('x-ud-eval-request-id') or uuid.uuid4().hex
            try:
                size = int(self.headers.get('content-length', '0'))
                if not 0 < size <= MAX_BYTES:
                    raise ValueError('TRAFFIC_SIZE_EXCEEDED')
                body = json.loads(self.rfile.read(size))
                route = urllib.parse.urlsplit(self.path).path
                if route == '/local-eval/transform':
                    self.send_json(200, {'body': to_chat(body['protocol'], body['body'], config['model'], adapters)})
                    return
                protocol = protocol_for(route)
                if protocol is None:
                    raise ValueError('ROUTE_UNSUPPORTED')
                translated = protocol not in config['native_protocols'] or protocol == 'responses' and needs_responses_translation(body)
                if protocol != 'gemini' and body.get('model') != config['model']:
                    raise ValueError('MODEL_NOT_ADMITTED')
                if protocol == 'gemini' and urllib.parse.unquote(route.split('/models/', 1)[1].rsplit(':', 1)[0]) not in (config['artifact'], config['model']):
                    raise ValueError('MODEL_NOT_ADMITTED')
                outgoing = to_chat(protocol, body, config['model'], adapters) if translated else body
                backend_route = '/v1/chat/completions' if translated else route
                record({'type': 'translation_request', 'id': request_id, 'protocol': protocol, 'translated': translated, 'native': body, 'backend': outgoing,
                        **({'protocol_projection': normalize_messages(body)[1]} if protocol == 'messages' else {})})
                request = urllib.request.Request(config['upstream'] + backend_route, json.dumps(outgoing, allow_nan=False).encode(), {'content-type': 'application/json'}, method='POST')
                with urllib.request.urlopen(request, timeout=90) as response:
                    content_type = response.headers.get('content-type', 'application/json')
                    if not translated and 'text/event-stream' in content_type:
                        self.send_response(200); self.send_header('content-type', content_type); self.send_header('connection', 'close'); self.end_headers()
                        chunks, total = [], 0
                        while True:
                            chunk = response.read1(65536)
                            if not chunk: break
                            total += len(chunk)
                            if total > MAX_BYTES: raise ValueError('TRAFFIC_SIZE_EXCEEDED')
                            chunks.append(chunk); self.wfile.write(chunk); self.wfile.flush()
                        record({'type': 'translation_response', 'id': request_id, 'protocol': protocol, 'translated': False, 'backend_sse': b''.join(chunks).decode()})
                        self.close_connection = True
                        return
                    data = response.read(MAX_BYTES + 1)
                if len(data) > MAX_BYTES:
                    raise ValueError('TRAFFIC_SIZE_EXCEEDED')
                original = json.loads(data)
                record({'type': 'translation_backend_response', 'id': request_id, 'protocol': 'chat' if translated else protocol, 'status': 200, 'streaming': False, 'body': original})
                result = from_chat(protocol, body, original, config['model'], adapters) if translated else original
                record({'type': 'translation_response', 'id': request_id, 'protocol': protocol, 'translated': translated, 'backend': original, 'native': result})
                streaming = body.get('stream', False) or protocol == 'gemini' and route.endswith(':streamGenerateContent')
                if translated and streaming:
                    encoded = ''.join(('event: ' + event['type'] + '\n' if protocol == 'messages' else '') + 'data: ' + json.dumps(event, allow_nan=False) + '\n\n' for event in stream_events(protocol, result)).encode()
                    self.send_response(200); self.send_header('content-type', 'text/event-stream'); self.send_header('content-length', str(len(encoded))); self.end_headers(); self.wfile.write(encoded)
                else:
                    self.send_json(200, result)
            except (BrokenPipeError, ConnectionResetError):
                self.close_connection = True
            except urllib.error.HTTPError as error:
                raw = error.read(MAX_BYTES + 1)
                if len(raw) > MAX_BYTES:
                    raw = b'BACKEND_ERROR_BODY_EXCEEDED'
                record({'type': 'translation_backend_error', 'id': request_id, 'backend_status': error.code, 'body': raw.decode('utf8', errors='replace')})
                self.send_json(error.code, {'error': {'type': 'local_backend_error', 'message': redact(raw.decode('utf8', errors='replace'))}})
            except Exception as error:
                record({'type': 'translation_rejection', 'id': request_id, 'reason': str(error)[:2000]})
                self.send_json(400, {'error': {'type': 'local_translation_error', 'message': str(error)[:2000]}})
    return Handler


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', required=True)
    parser.add_argument('--port', required=True, type=int)
    args = parser.parse_args()
    config = json.loads(Path(args.config).read_text())
    server = ThreadingHTTPServer(('127.0.0.1', args.port), handler_for(config, libraries()))
    server.daemon_threads = True
    server.serve_forever(poll_interval=0.1)


if __name__ == '__main__':
    main()
