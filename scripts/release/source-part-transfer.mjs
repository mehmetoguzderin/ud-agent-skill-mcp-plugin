/** Move verified source parts into one candidate without retaining duplicate payloads. MIT. */
import { closeSync, existsSync, fsyncSync, linkSync, lstatSync, openSync, readFileSync, realpathSync, renameSync, rmSync, unlinkSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileReceipt } from './candidate.mjs';

const need = (value, message) => { if (!value) throw new Error('Source part transfer: ' + message); };
const inside = (root, file) => file.startsWith(root + path.sep);
const journalPath = root => path.join(root, '.artifacts/storage/source-transfer.json');
export const sourceTransferJournal = journalPath;
function ordinaryParent(root, file) {
  const base = path.join(root, '.artifacts'), parent = path.dirname(file);
  need(inside(base, file), 'path is outside owned artifacts');
  let current = base;
  need(!lstatSync(current).isSymbolicLink() && realpathSync(current) === current, 'artifact root is linked');
  for (const part of path.relative(base, parent).split(path.sep).filter(Boolean)) {
    current = path.join(current, part);
    const info = lstatSync(current); need(info.isDirectory() && !info.isSymbolicLink() && realpathSync(current) === current, 'parent is not an ordinary owned directory');
  }
}
function matching(file, row) {
  const info = lstatSync(file); need(info.isFile() && !info.isSymbolicLink(), 'part is not an ordinary file');
  const actual = fileReceipt(path.dirname(file), path.basename(file));
  need(actual.sha256 === row.sha256 && actual.size === row.size, 'part bytes differ from the frozen receipt');
  return info;
}

/** Preflight exact hard-link aliases, including all owners, before admission. */
export function planSourcePartTransfer(owner, sourceRoot, output, parts, aliasRoots) {
  owner = realpathSync(owner); sourceRoot = realpathSync(sourceRoot); output = path.resolve(output);
  need(Array.isArray(aliasRoots) && aliasRoots.length > 0 && Array.isArray(parts) && parts.length > 0, 'explicit retained alias roots and parts are required');
  need(aliasRoots.every(root => typeof root === 'string' && path.isAbsolute(root)), 'alias roots must be explicit absolute paths');
  const roots = [...new Set(aliasRoots.map(root => realpathSync(root)))];
  const artifactRoot = path.join(owner, '.artifacts');
  for(let current=sourceRoot;inside(artifactRoot,current);current=path.dirname(current))need(!existsSync(path.join(current,'.ud-candidate-owner.json')),'retained candidate parts cannot be adopted as source inputs');
  for (const root of roots) {
    need(inside(artifactRoot, root) && lstatSync(root).isDirectory(), 'alias root is not an owned artifact directory');
    for(let current=root;inside(artifactRoot,current);current=path.dirname(current))need(!existsSync(path.join(current,'.ud-candidate-owner.json')),'retained candidate parts cannot be adopted as input aliases');
  }
  let targetParent = path.dirname(output); while (!existsSync(targetParent)) targetParent = path.dirname(targetParent);
  need(inside(artifactRoot, output) && !lstatSync(targetParent).isSymbolicLink() && realpathSync(targetParent) === targetParent, 'candidate output parent is not an ordinary owned path');
  const targetDevice = lstatSync(targetParent).dev, entries = [], names = new Set();
  for (const row of parts) {
    need(/^corresponding-source-[0-9]{4}$/.test(row.id) && /^[a-f0-9]{64}$/.test(row.sha256) && Number.isSafeInteger(row.size) && row.size >= 0, 'part identity is invalid');
    const source = path.resolve(sourceRoot, row.path), name = path.basename(row.path), destination = path.join(output, 'artifacts', name);
    need(!names.has(name), 'part destinations collide'); names.add(name); ordinaryParent(owner, source);
    const info = matching(source, row); need(info.dev === targetDevice, 'part and candidate are on different filesystems');
    const aliases = [];
    for (const root of roots) {
      const alias = path.join(root, name); if (alias === source || !existsSync(alias)) continue;
      ordinaryParent(owner, alias); const other = lstatSync(alias);
      if (other.dev === info.dev && other.ino === info.ino) { need(other.isFile() && !other.isSymbolicLink(), 'alias is not an ordinary file'); aliases.push(alias); }
    }
    need(info.nlink === aliases.length + 1, 'part has an unexpected or unlisted hard-link alias');
    entries.push({ id: row.id, source, destination, aliases, sha256: row.sha256, size: row.size, device: info.dev, inode: info.ino });
  }
  return entries;
}

/** Persist the complete rollback plan before changing any source-part paths. */
export function beginSourcePartTransfer(owner, output, entries) {
  owner = realpathSync(owner); output = path.resolve(output);
  need(Array.isArray(entries) && entries.length > 0 && !existsSync(journalPath(owner)), 'a new nonempty transfer journal is required');
  const journal = { schema_version: 1, owner_root: owner, output, entries };
  const temporary = journalPath(owner) + '.' + process.pid;
  const fd = openSync(temporary, 'wx', 0o600);
  try { writeFileSync(fd, JSON.stringify(journal) + '\n'); fsyncSync(fd); } finally { closeSync(fd); }
  try { need(!existsSync(journalPath(owner)), 'another transfer appeared'); renameSync(temporary, journalPath(owner)); }
  finally { if (existsSync(temporary)) rmSync(temporary); }
}

/** Rename one verified inode; its other explicitly listed aliases are retired. */
export function moveSourcePart(owner, entry) {
  owner = realpathSync(owner); const journal = JSON.parse(readFileSync(journalPath(owner), 'utf8'));
  need(journal.owner_root === owner && journal.entries.some(row => JSON.stringify(row) === JSON.stringify(entry)), 'part is not in the transfer journal');
  ordinaryParent(owner, entry.source); ordinaryParent(owner, entry.destination);
  const info = matching(entry.source, entry); need(info.dev === entry.device && info.ino === entry.inode && !existsSync(entry.destination), 'source inode or destination differs');
  for (const alias of entry.aliases) { ordinaryParent(owner, alias); const other = lstatSync(alias); need(other.isFile() && !other.isSymbolicLink() && other.dev === info.dev && other.ino === info.ino, 'recorded alias identity differs'); }
  need(info.nlink === entry.aliases.length + 1, 'part acquired an unexpected hard-link alias');
  renameSync(entry.source, entry.destination);
  for (const alias of entry.aliases) unlinkSync(alias);
  matching(entry.destination, entry);
}

/** Commit a completed registered candidate, or roll back its exact part paths. */
export function recoverSourcePartTransfer(owner) {
  owner = realpathSync(owner); const file = journalPath(owner); if (!existsSync(file)) return false;
  const info = lstatSync(file); need(info.isFile() && !info.isSymbolicLink() && info.nlink===1 && info.size <= 1024 * 1024 && !(info.mode&0o077) && (process.getuid===undefined||info.uid===process.getuid()), 'journal is not bounded private ordinary data');
  const journal = JSON.parse(readFileSync(file, 'utf8'));
  need(journal.schema_version === 1 && journal.owner_root === owner && typeof journal.output==='string' && inside(path.join(owner,'.artifacts'),journal.output) && Array.isArray(journal.entries) && journal.entries.length > 0 && journal.entries.length <= 1000, 'journal identity differs');
  const registry = path.join(owner, '.artifacts/storage/candidates.json');
  const current = existsSync(registry) ? JSON.parse(readFileSync(registry, 'utf8')).current : null;
  const committed = current?.output === journal.output && current.manifest;
  for (const row of journal.entries) {
    need(typeof row.source === 'string' && typeof row.destination === 'string' && path.dirname(row.destination)===path.join(journal.output,'artifacts') && Array.isArray(row.aliases) && /^[a-f0-9]{64}$/.test(row.sha256) && Number.isSafeInteger(row.size) && Number.isSafeInteger(row.device) && Number.isSafeInteger(row.inode), 'journal entry is malformed');
    ordinaryParent(owner, row.source); ordinaryParent(owner, row.destination);
    const source = existsSync(row.source), destination = existsSync(row.destination);
    need(source !== destination, 'part path state is ambiguous');
    if (committed) {
      need(destination && current.artifacts.some(item => item.id === row.id && item.sha256 === row.sha256 && item.size === row.size && path.join(journal.output, item.path) === row.destination), 'committed candidate does not bind the transferred part');
      const part = matching(row.destination, row); need(part.dev === row.device && part.ino === row.inode, 'committed part inode differs');
      for (const alias of row.aliases) if (existsSync(alias)) { ordinaryParent(owner, alias); const other=lstatSync(alias); need(other.dev === part.dev && other.ino === part.ino, 'committed alias identity differs'); unlinkSync(alias); }
      need(lstatSync(row.destination).nlink === 1, 'committed part retains an unexpected alias');
    } else {
      if (destination) { matching(row.destination, row); renameSync(row.destination, row.source); }
      const part = matching(row.source, row); need(part.dev === row.device && part.ino === row.inode, 'rollback part inode differs');
      for (const alias of row.aliases) {
        ordinaryParent(owner, alias);
        if (existsSync(alias)) { const other=lstatSync(alias); need(other.dev === part.dev && other.ino === part.ino, 'rollback alias identity differs'); }
        else linkSync(row.source, alias);
      }
      need(lstatSync(row.source).nlink === row.aliases.length + 1, 'rollback part has an unexpected alias');
    }
  }
  rmSync(file); return true;
}
