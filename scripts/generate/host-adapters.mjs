#!/usr/bin/env node
/** Generate checked-in host metadata and README coordinates, never publish. */
import { mkdirSync, readFileSync, readdirSync, lstatSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadDistributionIdentity, readmeArchives, readmeCoordinates, sourceHostFiles } from '../release/host-adapters.mjs';
import { connectedSkillFiles } from './skill-files.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const args = process.argv.slice(2);
if (args.length !== 1 || !['--write', '--check'].includes(args[0])) throw new Error('Usage: host-adapters.mjs --write|--check');
const identity = loadDistributionIdentity(root);
const files = sourceHostFiles(identity);
const skillFiles = connectedSkillFiles(root, identity);
for (const [name, bytes] of skillFiles) {
  files[`skills/${name}`] = bytes;
  files[`packaging/grok/${identity.name}/skills/${name}`] = bytes;
}
const grokRoot = `packaging/grok/${identity.name}/skills`;
function extraGeneratedFiles(relative) {
  let entries;
  try { entries = readdirSync(path.join(root, relative)); } catch (error) { if (error.code === 'ENOENT') return; throw error; }
  for (const name of entries) {
    const next = `${relative}/${name}`, info = lstatSync(path.join(root, next));
    if (info.isSymbolicLink()) throw new Error(`Generated skill symlink is unsafe: ${next}`);
    if (info.isDirectory()) extraGeneratedFiles(next);
    else if (!info.isFile() || !Object.hasOwn(files, next)) throw new Error(`Unexpected generated skill resource: ${next}`);
  }
}
extraGeneratedFiles(grokRoot);
const readme = readFileSync(path.join(root, 'README.md'), 'utf8');
const start = '<!-- BEGIN GENERATED RELEASE COORDINATES -->';
const end = '<!-- END GENERATED RELEASE COORDINATES -->';
if (readme.indexOf(start) < 0 || readme.indexOf(end) < readme.indexOf(start) || readme.indexOf(start) !== readme.lastIndexOf(start) || readme.indexOf(end) !== readme.lastIndexOf(end)) throw new Error('README coordinate markers are missing or duplicated.');
files['README.md'] = readme.slice(0, readme.indexOf(start) + start.length) + '\n' +
  readmeCoordinates(identity) + '\n' + readme.slice(readme.indexOf(end));
const archiveStart = '<!-- BEGIN GENERATED RELEASE ARCHIVES -->', archiveEnd = '<!-- END GENERATED RELEASE ARCHIVES -->';
const generated = files['README.md'];
if (generated.indexOf(archiveStart) < 0 || generated.indexOf(archiveEnd) < generated.indexOf(archiveStart) || generated.indexOf(archiveStart) !== generated.lastIndexOf(archiveStart) || generated.indexOf(archiveEnd) !== generated.lastIndexOf(archiveEnd)) throw new Error('README archive markers are missing or duplicated.');
files['README.md'] = generated.slice(0, generated.indexOf(archiveStart) + archiveStart.length) + '\n' + readmeArchives(identity) + '\n' + generated.slice(generated.indexOf(archiveEnd));
const hostStart = '<!-- BEGIN GENERATED HOST GUIDES -->', hostEnd = '<!-- END GENERATED HOST GUIDES -->';
const guide = readFileSync(path.join(root, 'packaging/host-guides.md.in'), 'utf8').replace(/\{\{([A-Z_]+)\}\}/g, (_match, key) => {
  const values = { NPM: identity.npm, VERSION: identity.version, REPOSITORY_URL: identity.repositoryUrl, OWNER_REPO: `${identity.github_owner}/${identity.repository}`, PLUGIN: identity.name, MARKETPLACE: identity.marketplace };
  if (!Object.hasOwn(values, key)) throw new Error(`Unknown host guide substitution: ${key}`);
  return values[key];
});
const withArchives = files['README.md'];
if (withArchives.indexOf(hostStart) < 0 || withArchives.indexOf(hostEnd) < withArchives.indexOf(hostStart) || withArchives.indexOf(hostStart) !== withArchives.lastIndexOf(hostStart) || withArchives.indexOf(hostEnd) !== withArchives.lastIndexOf(hostEnd)) throw new Error('README host guide markers are missing or duplicated.');
files['README.md'] = withArchives.slice(0, withArchives.indexOf(hostStart) + hostStart.length) + '\n\n' + guide + '\n' + withArchives.slice(withArchives.indexOf(hostEnd));
let changed = false;
for (const [name, contents] of Object.entries(files)) {
  const filename = path.join(root, ...name.split('/'));
  let existing;
  try { existing = readFileSync(filename); } catch (error) { if (error.code !== 'ENOENT') throw error; }
  const bytes = Buffer.isBuffer(contents) ? contents : Buffer.from(contents);
  if (existing?.equals(bytes)) continue;
  changed = true;
  if (args[0] === '--write') {
    mkdirSync(path.dirname(filename), { recursive: true });
    writeFileSync(filename, bytes);
  } else console.error(`Generated host metadata is stale: ${name}`);
}
if (args[0] === '--check' && changed) process.exitCode = 1;
else console.log(args[0] === '--check' ? 'Generated host metadata is current.' : 'Generated host metadata written.');
