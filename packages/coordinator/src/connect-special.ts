/** Native configuration adapters for Cordis profile patches and OpenClaw MCP. */
import { applyEdits, modify, parse as parseJson, printParseErrorCode } from 'jsonc-parser';
import type { ParseError } from 'jsonc-parser';
import { isMap, isSeq, parseDocument } from 'yaml';

export type SpecialFormat = 'deepseek' | 'openclaw';
type Entry = { command: string; args: string[]; type?: string };
export type SpecialHost = { file: string; format: SpecialFormat; key: string; skills: string; user: boolean };

export function specialHostProfile(host: string): SpecialHost | undefined {
  if (host === 'deepseek') return { file: '.dsh/profiles/web/cordis.patch.yml', format: 'deepseek', key: 'mcp-ud', skills: '.dsh/skills', user: true };
  if (host === 'openclaw') return { file: '.openclaw/openclaw.json', format: 'openclaw', key: 'mcp.servers', skills: '.openclaw/skills', user: true };
  return undefined;
}

function object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Host configuration must contain an object.');
  return value as Record<string, unknown>;
}

export function configureSpecialHost(text: string, format: SpecialFormat, entry?: Entry): { current: unknown; next: string } {
  if (format === 'openclaw') {
    const errors: ParseError[] = [];
    const value = object(parseJson(text || '{}', errors, { allowTrailingComma: true }));
    if (errors.length) throw new Error(`OpenClaw JSON configuration is invalid: ${printParseErrorCode(errors[0]!.error)}`);
    const mcp = value.mcp === undefined ? {} : object(value.mcp);
    const servers = mcp.servers === undefined ? {} : object(mcp.servers);
    return { current: servers.ud, next: applyEdits(text || '{}', modify(text || '{}', ['mcp', 'servers', 'ud'], entry, { formattingOptions: { insertSpaces: true, tabSize: 2 } })) + (text.endsWith('\n') ? '' : '\n') };
  }
  const document = parseDocument(text || '[]', { uniqueKeys: true });
  // Cordis uses !!js scalar bindings. Keep these as syntax-only YAML nodes;
  // never evaluate them, and reject every other parser warning or error.
  if (document.errors.length || document.warnings.some(warning => warning.code !== 'TAG_RESOLVE_FAILED')) throw new Error('DeepSeek profile patch YAML is invalid or ambiguous.');
  if (!isSeq(document.contents)) throw new Error('DeepSeek profile patch must be a YAML operation list.');
  const matches: { operation: number; row: number; current: Record<string, unknown> }[] = [];
  for (const [operation, node] of document.contents.items.entries()) {
    if (!isMap(node)) throw new Error('DeepSeek profile patch contains a non-object operation.');
    const inserted = node.get('insert', true);
    if (inserted === undefined) continue;
    if (!isSeq(inserted)) throw new Error('DeepSeek insert operation must contain a list.');
    for (const [row, item] of inserted.items.entries()) {
      if (!isMap(item)) throw new Error('DeepSeek inserted plugin must be an object.');
      const value = object(item.toJSON());
      const config = value.config === undefined ? {} : object(value.config);
      if (value.id === 'mcp-ud' || (value.name === '@deepseek-ai/dsh-mcp-client' && config.serverName === 'ud')) {
        if (value.id !== 'mcp-ud' || value.name !== '@deepseek-ai/dsh-mcp-client' || config.serverName !== 'ud' || config.transport !== 'stdio') throw new Error('DeepSeek ud registration belongs to a different plugin or transport.');
        const current = { ...config }; delete current.serverName; delete current.transport;
        matches.push({ operation, row, current });
      }
    }
  }
  if (matches.length > 1) throw new Error('DeepSeek profile contains duplicate ud registrations.');
  const selected = matches[0];
  if (selected) {
    const path = [selected.operation, 'insert', selected.row];
    if (entry) document.setIn(path, { id: 'mcp-ud', name: '@deepseek-ai/dsh-mcp-client', config: { serverName: 'ud', transport: 'stdio', ...entry } });
    else {
      document.deleteIn(path);
      const parent = document.getIn([selected.operation, 'insert'], true);
      const operation = document.contents.items[selected.operation];
      if (isSeq(parent) && parent.items.length === 0 && isMap(operation) && operation.items.length === 1) document.deleteIn([selected.operation]);
    }
  } else if (entry) document.add({ insert: [{ id: 'mcp-ud', name: '@deepseek-ai/dsh-mcp-client', config: { serverName: 'ud', transport: 'stdio', ...entry } }] });
  return { current: selected?.current, next: String(document) };
}
