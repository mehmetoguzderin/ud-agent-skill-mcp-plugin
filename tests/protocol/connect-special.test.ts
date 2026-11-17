import { describe, expect, it } from 'vitest';
import { parseDocument } from 'yaml';
import { configureSpecialHost, specialHostProfile } from '../../packages/coordinator/src/connect-special.js';

const entry = { command: '/installed/ud-agent', args: ['mcp', '--allow-root', '/selected/treebank'] };
describe('native special host connection formats', () => {
  it('preserves OpenClaw unrelated configuration and merges only mcp.servers.ud', () => {
    const input = '{\n // retained\n "gateway": {"port": 18789}, "mcp": {"servers": {"other": {"command":"other"}}}\n}\n';
    const result = configureSpecialHost(input, 'openclaw', entry);
    expect(result.current).toBeUndefined(); expect(result.next).toContain('// retained');
    expect(configureSpecialHost(result.next, 'openclaw', entry).current).toEqual(entry);
    expect(configureSpecialHost(result.next, 'openclaw').next).toContain('"other"');
    expect(configureSpecialHost(result.next, 'openclaw').next).not.toContain('"ud"');
    expect(() => configureSpecialHost('{"mcp": []}', 'openclaw', entry)).toThrow('object');
  });
  it('writes an executable Cordis insertion, preserves sibling rows and removes only owned row', () => {
    const input = '# retained profile\n- insert:\n    - id: sibling\n      name: other-plugin\n      config:\n        cwd: !!js process.cwd()\n';
    const result = configureSpecialHost(input, 'deepseek', entry);
    expect(result.next).toContain('# retained profile'); expect(result.next).toContain('!!js process.cwd()');
    const document = parseDocument(result.next).toJSON();
    expect(document[1].insert[0]).toEqual({ id: 'mcp-ud', name: '@deepseek-ai/dsh-mcp-client', config: { serverName: 'ud', transport: 'stdio', ...entry } });
    expect(configureSpecialHost(result.next, 'deepseek', entry).current).toEqual(entry);
    const removed = configureSpecialHost(result.next, 'deepseek');
    expect(removed.next).toContain('other-plugin'); expect(removed.next).not.toContain('mcp-ud');
  });
  it('rejects duplicate or incompatible Cordis ownership and non-list patches', () => {
    const once = configureSpecialHost('', 'deepseek', entry).next;
    const parsed = parseDocument(once).toJSON();
    expect(() => configureSpecialHost(JSON.stringify([parsed[0], parsed[0]]), 'deepseek', entry)).toThrow('duplicate');
    expect(() => configureSpecialHost(once.replace('stdio', 'http'), 'deepseek', entry)).toThrow('different');
    expect(() => configureSpecialHost('{}', 'deepseek', entry)).toThrow('operation list');
    expect(specialHostProfile('deepseek')?.file).toBe('.dsh/profiles/web/cordis.patch.yml');
    expect(specialHostProfile('openclaw')?.file).toBe('.openclaw/openclaw.json');
    expect(specialHostProfile('unknown')).toBeUndefined();
  });
});
