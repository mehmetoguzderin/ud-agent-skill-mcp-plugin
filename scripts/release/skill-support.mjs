/** Bind every standalone skill resource to the independent six-skill contract. */
import { readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { canonicalSkillFiles, skillInventory } from '../generate/skill-files.mjs';
import { fileReceipt, sha256 } from './candidate.mjs';
import { canonicalJson } from './http-transports.mjs';

export function skillSupport(root) {
  const files = [...canonicalSkillFiles(root)].map(([name, bytes]) => ({ path: `skills/${name}`, sha256: sha256(bytes), size: bytes.length, executable: false })).sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0);
  return { schema_version: 1, policy: 'frozen-unicode-16', contract_sha256: fileReceipt(root, 'quality/skills.json').sha256, skills: skillInventory(root), files };
}

export function writeSkillSupport(root, destination) {
  const support = skillSupport(root);
  for (const item of support.files) {
    const actual = fileReceipt(destination, item.path);
    if (canonicalJson(actual) !== canonicalJson(item)) throw new Error(`Packaged skill resource differs: ${item.path}`);
  }
  writeFileSync(path.join(destination, 'SKILL-SUPPORT.json'), JSON.stringify(support, null, 2) + '\n');
  return support;
}

export function verifySkillSupport(root, destination) {
  const expected = skillSupport(root);
  const actual = JSON.parse(readFileSync(path.join(destination, 'SKILL-SUPPORT.json'), 'utf8'));
  if (canonicalJson(expected) !== canonicalJson(actual)) throw new Error('Packaged skill support inventory differs from the independent contract.');
  for (const item of expected.files) if (canonicalJson(fileReceipt(destination, item.path)) !== canonicalJson(item)) throw new Error(`Packaged skill support bytes differ: ${item.path}`);
  return expected;
}
