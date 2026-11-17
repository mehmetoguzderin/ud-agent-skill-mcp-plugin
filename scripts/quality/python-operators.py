"""Versioned repairs for syntactically invalid upstream Python mutations."""
import hashlib
import inspect
import json
import os
import re
from pathlib import Path
import importlib.metadata

VERSION = 'ud-python-operators-2'


def install(directory):
    import libcst as cst
    from libcst._nodes.expression import ExpressionPosition
    original = cst.IfExp.with_changes
    if getattr(original, '_ud_operator_repair', False):
        raise ValueError('Python operator repairs were installed more than once')
    module = cst.Module([])
    def record(value):
        frame = inspect.currentframe()
        while frame:
            if frame.f_code.co_name == 'create_file_mutants' and isinstance(frame.f_locals.get('path'), Path):
                value['file'] = frame.f_locals['path'].as_posix()
                break
            frame = frame.f_back
        value.setdefault('file', None)
        encoded = json.dumps(value, sort_keys=True, separators=(',', ':')).encode()
        value['repair_sha256'] = hashlib.sha256(encoded).hexdigest()
        directory.mkdir(parents=True, exist_ok=True)
        with (directory / (str(os.getpid()) + '.jsonl')).open('a') as target:
            target.write(json.dumps(value) + '\n')
    def valid_words(node, **changes):
        proposed = {name: changes.get(name, getattr(node, name)) for name in ('body', 'test', 'orelse')}
        rules = [('whitespace_before_if', 'body', ExpressionPosition.LEFT), ('whitespace_after_if', 'test', ExpressionPosition.RIGHT), ('whitespace_before_else', 'test', ExpressionPosition.LEFT), ('whitespace_after_else', 'orelse', ExpressionPosition.RIGHT)]
        repairs = {}
        for whitespace, expression, side in rules:
            before = changes.get(whitespace, getattr(node, whitespace))
            if before.empty and not proposed[expression]._safe_to_use_with_word_operator(side):
                repairs[whitespace] = ' '
                changes[whitespace] = cst.SimpleWhitespace(' ')
        result = original(node, **changes)
        if repairs:
            record({'version': VERSION, 'operator': 'IfExp-word-separators',
                      'original_expression': module.code_for_node(node),
                      'requested_expressions': {name: module.code_for_node(value) for name, value in proposed.items()},
                      'repair': repairs, 'replacement_expression': module.code_for_node(result)})
        return result
    valid_words._ud_original = original
    valid_words._ud_operator_repair = True
    cst.IfExp.with_changes = valid_words
    from mutmut.mutation import mutators
    argument_operator = mutators.operator_arg_removal
    def abi_arguments(node):
        function = module.code_for_node(node.func)
        abi = function in ('libc.prctl', 'library.prctl', 'libc.syscall', 'library.syscall')
        select = function == 'select.select'
        if not abi and not select:
            yield from argument_operator(node)
            return
        if any(arg.star or arg.keyword for arg in node.args):
            raise ValueError('Known ABI operator has an unsupported variadic/keyword framing')
        if abi and function.endswith('.prctl') and len(node.args) != 5:
            raise ValueError('prctl operator requires all five ABI argument words')
        if select and len(node.args) != 4:
            raise ValueError('select operator contract requires its complete four-argument form')
        if select and (not isinstance(node.args[0].value, cst.List) or not node.args[0].value.elements or any(not isinstance(element, cst.Element) for element in node.args[0].value.elements)):
            raise ValueError('select operator requires explicit verified existing read descriptors')
        for mode in ('none', 'remove'):
            if mode == 'remove' and len(node.args) <= 1:
                continue
            for index, arg in enumerate(node.args):
                if mode == 'none' and isinstance(arg.value, cst.Name) and arg.value.value == 'None':
                    continue
                requested_args = [*node.args[:index], *node.args[index + 1:]] if mode == 'remove' else [*node.args[:index], arg.with_changes(value=cst.Name('None')), *node.args[index + 1:]]
                proposed = list(node.args)
                if select:
                    if index == 3:
                        value = cst.Integer('0') if mode == 'none' else cst.Float('0.001')
                    elif isinstance(arg.value, cst.List):
                        if not arg.value.elements:
                            value = cst.List([*node.args[0].value.elements] * (1 if mode == 'none' else 2))
                        else:
                            value = cst.List([]) if mode == 'none' else arg.value.with_changes(elements=[*arg.value.elements, node.args[0].value.elements[0]])
                    else:
                        raise ValueError('select operator requires explicitly typed descriptor lists')
                    proposed[index] = arg.with_changes(value=value)
                elif index != 0 and isinstance(arg.value, cst.Integer):
                    value = arg.value.evaluated_value + 2 + index * 2 + (mode == 'remove')
                    proposed[index] = arg.with_changes(value=cst.Integer(str(value)))
                else:
                    # Keep pointer/size expressions intact and mutate a typed
                    # flags word, never delete C varargs or pass None into a
                    # pointer constructor. Preserve the syscall/prctl command:
                    # another command can require a different pointer width.
                    # All owned calls end in integer flags.
                    if not isinstance(node.args[-1].value, cst.Integer):
                        raise ValueError('ABI operator has no known integer flags contract')
                    value = node.args[-1].value.evaluated_value + 2 + index * 2 + (mode == 'remove')
                    proposed[-1] = node.args[-1].with_changes(value=cst.Integer(str(value)))
                result = node.with_changes(args=proposed)
                record({'version': VERSION, 'operator': 'typed-ABI-argument-v1', 'callee': function, 'argument_index': index, 'upstream_mode': mode,
                        'original_expression': module.code_for_node(node), 'upstream_expression': module.code_for_node(node.with_changes(args=requested_args)),
                        'replacement_expression': module.code_for_node(result), 'arity': len(node.args)})
                yield result
    abi_arguments._ud_original = argument_operator
    abi_arguments._ud_operator_repair = True
    for index, (kind, operator) in enumerate(mutators.mutation_operators):
        if operator is argument_operator:
            mutators.mutation_operators[index] = (kind, abi_arguments)
    profile = {'version': VERSION, 'mutmut': importlib.metadata.version('mutmut'), 'libcst': importlib.metadata.version('libcst'), 'repairs': ['IfExp-word-separators', 'typed-ABI-argument-v1']}
    def records():
        result = []
        for file in sorted(directory.glob('*.jsonl')):
            result.extend(json.loads(line) for line in file.read_text().splitlines() if line)
        return result
    return profile, records


def _project_review_packets(root, registry, review):
    """Keep the original Domain review and the six Root approvals distinct."""
    if 'format_revision' not in review:
        if review.get('reviewer') != 'domain_completion':
            raise ValueError('Python typed-operator independent reviewer is invalid')
        return {row['id']: row for row in review['rows']}, {}
    if review.get('format_revision') != 2 or review.get('reviewer') != 'source-bound-review-packets':
        raise ValueError('Python typed-operator review format is unsupported')
    packets = review.get('packets')
    if not isinstance(packets, list) or len(packets) != 2 or {item.get('reviewer') for item in packets} != {'domain_completion', 'root'}:
        raise ValueError('Python typed-operator exact review packets are incomplete')
    rows = {row['id']: row for row in registry['rows']}
    approved, origins = {}, {}
    for descriptor in packets:
        name = descriptor.get('path')
        if (set(descriptor) != {'path', 'sha256', 'size_bytes', 'reviewer'} or not isinstance(name, str)
                or not name.startswith('quality/reviews/') or '\\' in name or ':' in name
                or any(part in ('', '.', '..') for part in name.split('/'))):
            raise ValueError('Python typed-operator review packet path is invalid')
        file = root / name
        if file.is_symlink() or not file.is_file() or not 0 < file.stat().st_size <= 4 * 1024 ** 2:
            raise ValueError('Python typed-operator review packet is not bounded original data')
        content = file.read_bytes()
        if len(content) != descriptor['size_bytes'] or hashlib.sha256(content).hexdigest() != descriptor['sha256']:
            raise ValueError('Python typed-operator review packet bytes changed')
        packet = json.loads(content)
        if packet.get('reviewer') != descriptor['reviewer']:
            raise ValueError('Python typed-operator packet reviewer differs')
        if descriptor['reviewer'] == 'domain_completion':
            decisions = packet['rows']
            selected_ids = {row['id'] for row in decisions}
            base = {**registry, 'rows': [row for row in registry['rows'] if row['id'] in selected_ids]}
            original_bytes = (json.dumps(base, sort_keys=True, indent=2, ensure_ascii=False) + '\n').encode()
            if packet.get('registry_version') != registry['version'] or hashlib.sha256(original_bytes).hexdigest() != packet.get('registry_sha256'):
                raise ValueError('Python original Domain registry projection changed')
            for name, fingerprint in packet.get('dependency_source_sha256', {}).items():
                if review.get('dependency_source_sha256', {}).get(name) != fingerprint:
                    raise ValueError('Python original Domain dependency review changed')
        else:
            if (packet.get('schema_version') != 1 or packet.get('qualification') != 'independent-exact-source-typed-ABI-retarget-review-not-mutation-outcomes'
                    or packet.get('approved_for_registry_activation') is not True or not isinstance(packet.get('author'), str)
                    or not packet['author'] or packet['author'] == packet.get('reviewer')):
                raise ValueError('Python Root typed-operator packet is not an independent approval')
            decisions = []
            for item in packet['reviews']:
                row = rows.get(item['id'])
                if (row is None or item.get('decision') != 'approve-typed-regeneration-only'
                        or item.get('type_contract') != row['type_contract']):
                    raise ValueError('Python Root typed-operator exact decision differs')
                decisions.append({'id': item['id'], 'decision': 'valid_operator', 'source_sha256': item['source_sha256'],
                                  'upstream_definition_sha256': item['upstream_definition_sha256'],
                                  'before': row['before'], 'after': row['after'], 'repaired_function_sha256': item['proposed_function_sha256']})
        for item in decisions:
            if item['id'] in approved or item['id'] not in rows:
                raise ValueError('Python typed-operator review packets overlap or add unknown identities')
            approved[item['id']] = item
            origins[item['id']] = descriptor
    return approved, origins


def _project_typed_repairs(root, source_hashes):
    """Retain each invalid original definition and regenerate a typed operator."""
    file = root / 'quality/python-operator-repairs.json'
    if not file.is_file():
        return lambda *args: None
    registry = json.loads(file.read_text())
    if registry.get('schema_version') != 1 or not isinstance(registry.get('rows'), list):
        raise ValueError('Python typed-operator registry is invalid')
    review_file = root / 'quality/reviews/python-operator-repairs-domain-review.json'
    review = json.loads(review_file.read_text())
    registry_sha256 = hashlib.sha256(file.read_bytes()).hexdigest()
    review_sha256 = hashlib.sha256(review_file.read_bytes()).hexdigest()
    if review.get('registry_sha256') != registry_sha256 or review.get('registry_version') != registry['version']:
        raise ValueError('Python typed-operator independent review is stale')
    for name, fingerprint in review.get('dependency_source_sha256', {}).items():
        if source_hashes.get(name) != fingerprint:
            raise ValueError('Python typed-operator dependency source fingerprint is stale')
    reviewed, review_origins = _project_review_packets(root, registry, review)
    if len(reviewed) != len(registry['rows']):
        raise ValueError('Python typed-operator independent inventory is incomplete')
    by_replacement = {}
    applied = set()
    for row in registry['rows']:
        if source_hashes.get(row['file']) != row['source_sha256']:
            raise ValueError('Python typed-operator source fingerprint is stale')
        original = json.dumps(row['upstream_definition'], sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()
        if hashlib.sha256(original).hexdigest() != row['upstream_definition_sha256']:
            raise ValueError('Python original operator definition fingerprint is invalid')
        old = row['upstream_definition']['replacement_function']
        if hashlib.sha256(old.encode()).hexdigest() != row['replacement_function_sha256'] or old.count(row['before']) != 1 or row['before'] == row['after']:
            raise ValueError('Python typed-operator exact replacement is invalid')
        key = (row['file'], row['replacement_function_sha256'])
        if any(item['id'] == row['id'] for item in by_replacement.get(key, [])):
            raise ValueError('Duplicate Python original operator identity')
        changed = old.replace(row['before'], row['after'], 1)
        approved = reviewed.get(row['id'])
        if not approved or approved['decision'] != 'valid_operator' or approved['source_sha256'] != row['source_sha256'] or approved['upstream_definition_sha256'] != row['upstream_definition_sha256'] or approved['before'] != row['before'] or approved['after'] != row['after'] or approved['repaired_function_sha256'] != hashlib.sha256(changed.encode()).hexdigest():
            raise ValueError('Python exact typed operator differs from its independent review')
        by_replacement.setdefault(key, []).append(row)
    def repair(file, replacement, definition, raw_id=None):
        candidates = by_replacement.get((file, hashlib.sha256(replacement.encode()).hexdigest()), [])
        if raw_id is not None:
            candidates = [row for row in candidates if row['id'] == raw_id]
        if not candidates:
            return None
        if len(candidates) != 1:
            raise ValueError('Python identical original operators require an exact raw identity')
        row = candidates[0]
        upstream = {key: value for key, value in definition.items() if key not in ('generation_profile', 'generation_repairs')}
        if upstream != row['upstream_definition']:
            raise ValueError('Python original operator differs from the typed contract')
        changed = replacement.replace(row['before'], row['after'], 1)
        if changed == replacement or len(changed.splitlines()) != len(replacement.splitlines()):
            raise ValueError('Python typed-operator repair changed source framing')
        # Parse the new code before scheduling; compile/runtime errors cannot be
        # used as kills, nor can an invalid typed operator enter execution.
        import ast
        ast.parse(changed)
        applied.add(row['id'])
        review_identity = {'path': 'quality/reviews/python-operator-repairs-domain-review.json', 'sha256': review_sha256}
        if row['id'] in review_origins:
            review_identity.update(reviewer=review_origins[row['id']]['reviewer'], packet=review_origins[row['id']])
        return changed, {'version': registry['version'], 'registry_sha256': registry_sha256, 'review': review_identity, 'type_contract': row['type_contract'],
                         'upstream_definition': definition,
                         'upstream_definition_sha256': hashlib.sha256(json.dumps(definition, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest(),
                         'exact_change': {'before': row['before'], 'after': row['after']}}
    def complete(requested):
        expected = {row['id'] for row in registry['rows'] if row['id'] in requested}
        if expected != applied:
            raise ValueError('Python typed operator scheduling omitted a reviewed original definition')
    repair.complete = complete
    return repair


def graph_registry_selection(root):
    """Keep historical readers while binding each activated revision to bytes."""
    selected = {'registry': 'quality/python-graph-operator-proposals.json', 'review': 'quality/reviews/python-graph-operators-root-review.json', 'proposal_version': 'ud-graph-typed-operators-proposal-1', 'operator_version': 'ud-graph-typed-operators-1'}
    activation = root / 'quality/python-graph-operators.activation.json'
    if activation.exists():
        state = json.loads(activation.read_bytes())
        if state.get('schema_version') != 1 or type(state.get('active')) is not bool:
            raise ValueError('Graph operator activation contract is invalid')
        if state['active'] is False:
            # Original operators are still generated. Nothing is excluded or
            # accepted while their new exact source definitions await review.
            return None
        if state.get('format_revision') == 2:
            if state.get('operator_version') != 'ud-graph-typed-operators-2':
                raise ValueError('Graph operator revision is unsupported')
            selected.update(proposal_version='ud-graph-typed-operators-proposal-2', operator_version=state['operator_version'])
            for key in ('registry', 'review'):
                receipt = state.get(key)
                if not isinstance(receipt, dict) or set(receipt) != {'path', 'sha256'} or not isinstance(receipt['path'], str) or not receipt['path'].startswith('quality/') or '\\' in receipt['path'] or ':' in receipt['path'] or any(part in ('', '.', '..') for part in receipt['path'].split('/')) or not re.fullmatch('[a-f0-9]{64}', receipt.get('sha256', '')):
                    raise ValueError('Graph activation receipt is invalid')
                file = root / receipt['path']
                if file.is_symlink() or not file.is_file() or hashlib.sha256(file.read_bytes()).hexdigest() != receipt['sha256']:
                    raise ValueError('Graph activated registry or review bytes changed')
                selected[key] = receipt['path']
        elif 'format_revision' in state or 'registry' in state or 'review' in state:
            raise ValueError('Graph activation format is unsupported')
    return selected


def _graph_typed_repairs(root, source_hashes):
    """Admit only the complete, independently reviewed graph proposal bytes."""
    selected_registry = graph_registry_selection(root)
    if selected_registry is None:
        return lambda *args: None
    file = root / selected_registry['registry']
    if not file.is_file():
        return lambda *args: None
    registry = json.loads(file.read_bytes())
    review_file = root / selected_registry['review']
    review = json.loads(review_file.read_bytes())
    registry_sha = hashlib.sha256(file.read_bytes()).hexdigest()
    review_sha = hashlib.sha256(review_file.read_bytes()).hexdigest()
    expected_proposal = {'path': selected_registry['registry'], 'sha256': registry_sha,
                         'version': registry.get('proposal_version')}
    if registry.get('proposal_version') != selected_registry['proposal_version'] or review.get('proposal') != expected_proposal or review.get('reviewer') != 'independent root agent /root' or not isinstance(registry.get('rows'), list):
        raise ValueError('Graph typed-operator independent review is missing or stale')
    approved = {item['id']: item for item in review['reviews']}
    if len(approved) != len(registry['rows']) or len(approved) != len(review['reviews']):
        raise ValueError('Graph typed-operator review inventory is incomplete or duplicated')
    by_replacement, programs, applied = {}, set(), set()
    for row in registry['rows']:
        definition = row['upstream_definition']
        fingerprint = hashlib.sha256(json.dumps(definition, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()
        original = definition['replacement_function']
        selected = approved.get(row['id'])
        if source_hashes.get(row['file']) != row['source_sha256'] or fingerprint != row['upstream_definition_sha256'] or hashlib.sha256(original.encode()).hexdigest() != row['replacement_function_sha256'] or original.count(row['before']) != 1 or row['before'] == row['after']:
            raise ValueError('Graph original operator identity or exact replacement differs')
        changed = original.replace(row['before'], row['after'], 1)
        changed_sha = hashlib.sha256(changed.encode()).hexdigest()
        if not selected or selected.get('decision') != 'approve-typed-regeneration-only' or selected.get('source_sha256') != row['source_sha256'] or selected.get('upstream_definition_sha256') != fingerprint or selected.get('proposed_function_sha256') != changed_sha or selected.get('type_contract') != row['type_contract'] or row.get('proposed_function_sha256') != changed_sha or changed_sha in programs:
            raise ValueError('Graph typed operator differs from its exact independent review')
        key = (row['file'], row['replacement_function_sha256'])
        if key in by_replacement:
            raise ValueError('Duplicate graph original operator definition')
        programs.add(changed_sha); by_replacement[key] = row
    def repair(file, replacement, definition, raw_id=None):
        row = by_replacement.get((file, hashlib.sha256(replacement.encode()).hexdigest()))
        if row is None or raw_id is not None and row['id'] != raw_id:
            return None
        if definition != row['upstream_definition']:
            raise ValueError('Graph original complete definition or generator profile changed')
        changed = replacement.replace(row['before'], row['after'], 1)
        if len(changed.splitlines()) != len(replacement.splitlines()):
            raise ValueError('Graph operator regeneration changed source framing')
        import ast
        ast.parse(changed)
        applied.add(row['id'])
        return changed, {'version': selected_registry['operator_version'], 'registry_sha256': registry_sha,
                         'review': {'path': selected_registry['review'], 'sha256': review_sha},
                         'type_contract': row['type_contract'], 'upstream_definition': definition,
                         'upstream_definition_sha256': row['upstream_definition_sha256'],
                         'exact_change': {'before': row['before'], 'after': row['after']}}
    def complete(requested):
        expected = {row['id'] for row in registry['rows'] if row['id'] in requested}
        if expected != applied:
            raise ValueError('Graph scheduling omitted a reviewed original operator')
    repair.complete = complete
    return repair


def typed_repairs(root, source_hashes):
    repairs = [_project_typed_repairs(root, source_hashes), _graph_typed_repairs(root, source_hashes)]
    def repair(file, replacement, definition, raw_id=None):
        values = [selected(file, replacement, definition, raw_id) for selected in repairs]
        values = [value for value in values if value is not None]
        if len(values) > 1:
            raise ValueError('Multiple typed registries claim one original operator')
        return values[0] if values else None
    def complete(requested):
        for selected in repairs:
            if hasattr(selected, 'complete'):
                selected.complete(requested)
    repair.complete = complete
    return repair
