import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { isDeepStrictEqual } from 'node:util';
import { domainMetadata } from './generated-contracts.js';

export type Contract = {
  id: string; name: string; original_signature: string; upstream_provenance: string | null;
  runtime_pack: string; handler?: string;
  output_schema?: string;
  parameters: { name: string; required: boolean }[];
  access?: { writes_workspace: boolean; writes_outputs?: boolean; executes_project_code: boolean };
};

/** Locate assets relative to the installed program, not a client's project CWD. */
export function projectRoot(moduleUrl = import.meta.url): string {
  let current = path.dirname(fileURLToPath(moduleUrl));
  while (true) {
    if (existsSync(path.join(current, 'contracts', 'ud-interfaces.json'))) return current;
    const parent = path.dirname(current);
    if (parent === current) throw new Error('The installed contract catalog is missing.');
    current = parent;
  }
}

function loadJson(file: string): unknown { return JSON.parse(readFileSync(file, 'utf8')) as unknown; }

export function loadContracts(root: string): { domain: Contract[]; environment: Contract[] } {
  const domain = loadJson(path.join(root, 'contracts', 'ud-interfaces.json'));
  const environment = loadJson(path.join(root, 'contracts', 'environment.json'));
  if (!Array.isArray(domain) || domain.length !== 102 || !Array.isArray(environment) || environment.length !== 2) {
    throw new Error('The installed contract inventory is incomplete.');
  }
  const combined = [...domain, ...environment] as Contract[];
  const names = new Set<string>();
  for (const [index, contract] of combined.entries()) {
    const expected = index < 102 ? String(index + 1).padStart(3, '0') : `ENV-00${index - 101}`;
    if (contract.id !== expected || typeof contract.name !== 'string' || !/^[a-z][a-z0-9_]*$/.test(contract.name) || names.has(contract.name)) {
      throw new Error('The installed contract inventory is invalid.');
    }
    if (!Array.isArray(contract.parameters)) throw new Error(`The installed contract ${contract.name} lacks its parameters.`);
    if (index < 102) {
      const generated = domainMetadata[index]!;
      const installed = Object.fromEntries(Object.keys(generated).map(key => [key, (contract as unknown as Record<string, unknown>)[key]]));
      if (!isDeepStrictEqual(installed, generated)) throw new Error(`The installed contract ${contract.name} differs from its generated dispatch binding.`);
    }
    names.add(contract.name);
  }
  if (!names.has('check_ud_environment') || !names.has('setup_ud_environment')) throw new Error('The installed environment tools are missing.');
  return { domain: domain as Contract[], environment: environment as Contract[] };
}

export function loadInputSchema(root: string, name: string): Record<string, unknown> {
  if (!/^[a-z][a-z0-9_]*$/.test(name)) throw new Error('Invalid operation identifier.');
  const schema = loadJson(path.join(root, 'contracts', 'schema', 'operations', `${name}.input.schema.json`));
  if (!schema || typeof schema !== 'object' || Array.isArray(schema)) throw new Error(`Invalid input schema for ${name}.`);
  return schema as Record<string, unknown>;
}

export function loadOutputSchema(root: string, name: string): Record<string, unknown> {
  if (!/^[a-z][a-z0-9_]*$/.test(name)) throw new Error('Invalid operation identifier.');
  const schema = loadJson(path.join(root, 'contracts', 'schema', 'results', `${name}.schema.json`));
  if (!schema || typeof schema !== 'object' || Array.isArray(schema)) throw new Error(`Invalid result schema for ${name}.`);
  return schema as Record<string, unknown>;
}
