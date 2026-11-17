/** Installed operation discovery without worker admission or workspace effects. MIT. */
import { createHash } from 'node:crypto';
import { loadContracts, loadInputSchema, loadOutputSchema, type Contract } from './catalog.js';
import { toolDescription } from './tool-descriptions.js';

const digest = (value: unknown): string => createHash('sha256').update(JSON.stringify(value)).digest('hex');
function summary(contract: Contract) {
  return { id: contract.id, name: contract.name, purpose: toolDescription(contract.name), runtime_pack: contract.runtime_pack,
    access: contract.access ?? null };
}
export function discoverOperations(root: string, query?: string) {
  const { domain, environment } = loadContracts(root);
  const terms = (query ?? '').toLowerCase().trim().split(/\s+/).filter(Boolean);
  const operations = [...domain, ...environment].map(summary).filter(operation => {
    const text = `${operation.id} ${operation.name} ${operation.name.replaceAll('_', ' ')} ${operation.purpose}`.toLowerCase();
    return terms.every(term => text.includes(term));
  });
  return { schema_version: 1, kind: 'installed-operation-catalog', query: query ?? null, count: operations.length, operations };
}
/** RFC 6901 pointers only, without URI fragments or inherited/prototype keys.
 * References stay explicit: inspect the indicated /$defs/... pointer next. */
export function schemaFragment(schema: unknown, pointer: string): unknown {
  if (typeof pointer !== 'string' || Buffer.byteLength(pointer) > 2048 || pointer !== '' && !pointer.startsWith('/') || pointer.includes('#') || /~(?![01])/.test(pointer)) throw new Error('Invalid input-schema JSON pointer.');
  let selected = schema;
  for (const token of pointer === '' ? [] : pointer.slice(1).split('/').map(part => part.replaceAll('~1', '/').replaceAll('~0', '~'))) {
    if (Array.isArray(selected) && (!/^(?:0|[1-9]\d*)$/.test(token) || !Number.isSafeInteger(Number(token)) || Number(token) >= selected.length)) throw new Error('Input-schema pointer does not select an array element.');
    if (['__proto__', 'prototype', 'constructor'].includes(token) || !selected || typeof selected !== 'object' || !Object.hasOwn(selected, token)) throw new Error('Input-schema pointer does not select an own schema field.');
    selected = (selected as Record<string, unknown>)[token];
  }
  return selected;
}
const escapePointer = (value: string): string => value.replaceAll('~', '~0').replaceAll('/', '~1');
function object(value: unknown): Record<string, unknown> | undefined { return value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : undefined; }
function outline(value: unknown, pointer: string): Record<string, unknown> {
  const node = object(value); if (!node) return { pointer, value };
  const result: Record<string, unknown> = { pointer };
  for (const key of ['type', '$ref', 'const', 'default', 'minimum', 'maximum', 'minLength', 'maxLength', 'minItems', 'maxItems', 'pattern', 'additionalProperties']) {
    const item = node[key]; if (item !== undefined && (item === null || typeof item !== 'object' || Array.isArray(item) && item.every(value => typeof value === 'string'))) result[key] = item;
  }
  if (Array.isArray(node.enum)) { result.enum = node.enum.slice(0, 12); if (node.enum.length > 12) result.enum_count = node.enum.length; }
  if (node.required) result.required = node.required;
  for (const key of ['anyOf', 'oneOf', 'allOf']) if (Array.isArray(node[key])) result[key] = (node[key] as unknown[]).map((branch, index) => {
    const item = object(branch), base = `${pointer}/${key}/${index}`;
    const discriminants = Object.fromEntries(Object.entries(object(item?.properties) ?? {}).flatMap(([name, property]) => {
      const details = object(property); return details && ('const' in details || 'enum' in details) ? [[name, 'const' in details ? details.const : details.enum]] : [];
    }));
    return { pointer: base, ...(item?.type === undefined ? {} : { type: item.type }), ...(item?.$ref ? { $ref: item.$ref } : {}), ...(Object.keys(discriminants).length ? { discriminants } : {}), ...(item?.required ? { required: item.required } : {}) };
  });
  const properties = object(node.properties);
  if (properties) result.properties = Object.fromEntries(Object.entries(properties).map(([name, property]) => [name, outlineField(property, `${pointer}/properties/${escapePointer(name)}`)]));
  if (node.items !== undefined) result.items = outlineField(node.items, `${pointer}/items`);
  if (object(node.$defs)) result.definitions = { pointer: `${pointer}/$defs`, names: Object.keys(node.$defs as Record<string, unknown>) };
  return result;
}
function outlineField(value: unknown, pointer: string): Record<string, unknown> {
  const node = object(value), result = outline(node ? Object.fromEntries(Object.entries(node).filter(([key]) => key !== 'properties' && key !== '$defs')) : value, pointer);
  if (object(node?.properties)) result.property_names = Object.keys(node!.properties as Record<string, unknown>);
  return result;
}
export function describeOperation(root: string, name: string, pointer?: string) {
  const { domain, environment } = loadContracts(root);
  const contract = [...domain, ...environment].find(operation => operation.name === name);
  if (!contract) throw new Error(`Unknown tool: ${name}`);
  const input = loadInputSchema(root, name), output = loadOutputSchema(root, name);
  const common = { schema_version: 1, kind: 'installed-operation-description', ...summary(contract), original_signature: contract.original_signature,
    input_schema_sha256: digest(input), output_schema_sha256: digest(output),
    invocation: { command: 'ud-agent', arguments: ['call', contract.name, '--input', 'REQUEST_JSON_FILE', '--allow-root', 'AUTHORIZED_WORKSPACE'] },
    guidance: 'Supply schema-required values from the authorized workspace and user request. Discovery performs no setup or operation.' };
  if (pointer !== undefined) {
    const fragment = schemaFragment(input, pointer);
    return { ...common, document: 'input', pointer, fragment, fragment_sha256: digest(fragment) };
  }
  return { ...common, input_schema: input, output_schema: output };
}
/** Operations with a dedicated CLI command, shown first so a shell agent copies a runnable line. */
export const CLI_SHORTHANDS: Readonly<Record<string, string>> = Object.freeze({
  validation_report: 'ud-agent validate --working-tree "$PWD" --lang LANGUAGE_CODE (checks every .conllu file in that folder; e.g. --lang en)',
  check_ud_environment: 'ud-agent check --working-tree "$PWD"',
  setup_ud_environment: 'ud-agent setup --working-tree "$PWD"',
});

export function formatOperationDescription(description: ReturnType<typeof describeOperation>): string {
  const pointer = 'fragment' in description ? description.pointer : '', schema = 'fragment' in description ? description.fragment : description.input_schema;
  return `${description.name} (${description.id}): ${description.purpose}\n${CLI_SHORTHANDS[description.name] ? `Run: ${CLI_SHORTHANDS[description.name]}\n` : ''}Access: ${JSON.stringify(description.access)}\n` +
    `Input projection (discovery only; not the complete schema): ${JSON.stringify(outline(schema, pointer))}\n` +
    `Inspect a fragment: ud-agent describe ${description.name} --path '/JSON_POINTER' --json\n` +
    `JSON pointers select input-schema fields. Replace '/JSON_POINTER' with a literal pointer; single-quote '/$defs/NAME' when resolving a local #/$defs/NAME reference to prevent shell expansion. No automatic reference expansion.\n` +
    `Input schema: ${description.input_schema_sha256}; output schema: ${description.output_schema_sha256}. --json without --path returns both complete schemas.\n` +
    (object('input_schema' in description ? description.input_schema.properties : undefined)?.ud_context_path ? 'ud_context_path may be an empty string to use the selected pinned runtime context, or an explicitly granted context path.\n' : '') +
    `Call: ud-agent call ${description.name} --input REQUEST_JSON_FILE --allow-root AUTHORIZED_WORKSPACE\n${description.guidance}\n`;
}
