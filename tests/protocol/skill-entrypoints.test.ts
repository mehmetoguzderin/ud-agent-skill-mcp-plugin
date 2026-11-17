/** Discovery metadata regression; does not certify native skill delivery or selection. */
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { expect, it } from 'vitest';
import { parse } from 'yaml';
import { loadContracts } from '../../packages/coordinator/src/catalog.js';
import { canonicalSkillFiles, skillInventory } from '../../scripts/generate/skill-files.mjs';

it('serialized discovery metadata decodes exactly and points to a supported operation in its skill scope', async () => {
  const root = process.cwd(), { domain, environment } = loadContracts(root);
  const contracts = new Map([...domain, ...environment].map(contract => [contract.name, contract]));
  const canonical = canonicalSkillFiles(root);
  for (const skill of skillInventory(root)) {
    const source = canonical.get(`${skill.name}/SKILL.md`)!.toString('utf8');
    const header = /^---\r?\n([\s\S]*?)\r?\n---(?:\r?\n|$)/.exec(source)![1];
    const serialized = /^description: (.*)$/m.exec(header)![1];
    const description = JSON.parse(serialized);
    expect(parse(header).description).toBe(description);
    const entrypoint = /\bud-agent describe ([a-z_]+)\b/.exec(description)?.[1];
    expect(entrypoint).toBeDefined();
    const operation = contracts.get(entrypoint!);
    expect(operation, `${skill.name}: executable schema discovery must reference an authoritative installed operation`).toBeDefined();
    expect(skill.operation_ids).toContain(operation!.id);
    expect(description).toContain('.conllu');
    expect(description).toContain('ordinary prose/report wording');
    const packaged = await readFile(path.join(root, 'packaging/grok/ud-agent-skill-mcp-plugin/skills', skill.name, 'SKILL.md'), 'utf8');
    expect(packaged).toBe(source);
  }
});
