/** Complete, self-contained canonical skill files; never follow authoring links. */
import { lstatSync, readFileSync, readdirSync } from 'node:fs';
import path from 'node:path';
import { portablePathKey, validPortablePath } from '../release/portable-policy.mjs';

export function skillInventory(root) {
  const inventory = JSON.parse(readFileSync(path.join(root, 'quality/skills.json'), 'utf8'));
  const expected = ['ud-validate', 'ud-edit', 'ud-investigate', 'ud-compare', 'ud-rules-docs', 'ud-release'];
  if (inventory.schema_version !== 1 || !Array.isArray(inventory.skills) ||
      JSON.stringify(inventory.skills.map(item => item.name)) !== JSON.stringify(expected)) throw new Error('Canonical six-skill inventory differs.');
  for (const item of inventory.skills) {
    if (!Array.isArray(item.required_files) || !item.required_files.includes('SKILL.md') || new Set(item.required_files).size !== item.required_files.length || item.required_files.some(name => !validPortablePath(name)) || !Array.isArray(item.operation_ids) || item.operation_ids.length === 0 || new Set(item.operation_ids).size !== item.operation_ids.length || item.operation_ids.some(id => !/^0(?:0[1-9]|[1-9][0-9])$|^10[0-2]$/.test(id))) throw new Error(`Invalid skill inventory: ${item.name}`);
  }
  return inventory.skills;
}

export function canonicalSkillFiles(root) {
  const files = new Map(), keys = new Set();
  const inventory = skillInventory(root);
  const actualSkills = readdirSync(path.join(root, 'skills')).sort();
  if (JSON.stringify(actualSkills) !== JSON.stringify(inventory.map(item => item.name).sort())) throw new Error('Canonical skills directory adds or omits a skill.');
  let total = 0;
  for (const item of inventory) {
    const base = path.join(root, 'skills', item.name);
    function walk(relative) {
      if (relative.split('/').length > 32) throw new Error('Skill reference depth exceeds its portable limit.');
      const filename = path.join(base, ...relative.split('/').filter(Boolean));
      const info = lstatSync(filename);
      if (info.isSymbolicLink()) throw new Error(`Skill symlink is not portable: ${item.name}/${relative}`);
      if (info.isDirectory()) {
        for (const name of readdirSync(filename).sort()) walk(relative ? `${relative}/${name}` : name);
      } else if (info.isFile()) {
        const name = `${item.name}/${relative}`;
        if (!validPortablePath(name) || keys.has(portablePathKey(name))) throw new Error(`Unsafe or colliding skill path: ${name}`);
        if (info.size > 2 * 1024 * 1024 || total + info.size > 16 * 1024 * 1024 || files.size >= 1024) throw new Error('Canonical skill resources exceed their bounds.');
        const bytes = readFileSync(filename);
        total += bytes.length;
        if (bytes.length !== info.size) throw new Error('Canonical skill resource changed during collection.');
        keys.add(portablePathKey(name)); files.set(name, bytes);
      } else throw new Error(`Skill special file is not portable: ${item.name}/${relative}`);
    }
    walk('');
    for (const required of item.required_files) if (!files.has(`${item.name}/${required}`)) throw new Error(`Required skill resource is missing: ${item.name}/${required}`);
  }
  for (const [name, bytes] of files) {
    if (!name.endsWith('.md')) continue;
    const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    for (const match of text.matchAll(/\[[^\]]*\]\(([^\s)]+)(?:\s+"[^"]*")?\)/g)) {
      const target = match[1];
      if (/^(?:https?:|mailto:|#)/.test(target)) continue;
      const decoded = decodeURIComponent(target.split('#')[0]);
      const resolved = path.posix.normalize(path.posix.join(path.posix.dirname(name), decoded));
      if (decoded.startsWith('/') || decoded.includes('\\') || resolved.split('/')[0] !== name.split('/')[0] || !files.has(resolved)) throw new Error(`Skill reference is unavailable outside its standalone folder: ${name} -> ${target}`);
    }
  }
  return files;
}

export function connectedSkillFiles(root, identity) {
  const files = canonicalSkillFiles(root);
  const connection = readFileSync(path.join(root, 'packaging/skill-connection.md.in'), 'utf8').replace(/\{\{([A-Z_]+)\}\}/g, (_match, key) => {
    const values = { PLUGIN: identity.name, MARKETPLACE: identity.marketplace, NPM: identity.npm, VERSION: identity.version };
    if (!Object.hasOwn(values, key)) throw new Error(`Unknown skill connection substitution: ${key}`);
    return values[key];
  });
  const start = '<!-- BEGIN GENERATED SKILL CONNECTION -->', end = '<!-- END GENERATED SKILL CONNECTION -->';
  for (const [name, bytes] of files) {
    if (!name.endsWith('/SKILL.md')) continue;
    const text = bytes.toString('utf8');
    if (text.indexOf(start) < 0 || text.indexOf(end) < text.indexOf(start) || text.indexOf(start) !== text.lastIndexOf(start) || text.indexOf(end) !== text.lastIndexOf(end)) throw new Error(`Skill connection markers are missing or duplicated: ${name}`);
    files.set(name, Buffer.from(text.slice(0, text.indexOf(start) + start.length) + '\n\n' + connection + text.slice(text.indexOf(end))));
  }
  return files;
}
