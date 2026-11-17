#!/usr/bin/env node
/** One source-identical ordinary-test job under the existing storage supervisor. */
import { lstatSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { sha256, sourceReceipt } from '../release/candidate.mjs';
import { retainSourceSnapshot } from '../release/prepare.mjs';
import { canonicalJson } from '../release/http-transports.mjs';
import { inheritedStorageDirectory, storageTreeBytes, STORAGE_LIMITS } from './storage-lifecycle.mjs';
import { copyOriginalDependencies, isWithinStorage } from './original-storage.mjs';
import { nodeDependencyInventory } from './node-dependencies.mjs';
import { runOriginalAcceptance } from './original-acceptance.mjs';

const [root, encoded] = process.argv.slice(2);
if (!root || !encoded || process.argv.length !== 4) throw new Error('Original worker requires a source and options.');
const scratch = inheritedStorageDirectory();
if (!scratch || isWithinStorage(scratch, root)) throw new Error('Original worker needs a detached source and an active storage supervisor.');
const options = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8'));
const before = sourceReceipt(root), modules = path.join(root, 'node_modules');
const inputBytes = before.files.reduce((sum, row) => sum + row.size, 0) + storageTreeBytes(modules);
if (!Number.isSafeInteger(inputBytes) || inputBytes + 256 * 1024 ** 2 > STORAGE_LIMITS.ordinaryBytes) throw new Error('Original test source and dependencies leave no bounded build workspace.');
const working = path.join(scratch, 'original-source');
retainSourceSnapshot(root, before, working);
const dependencies = copyOriginalDependencies(root, path.join(working, 'node_modules'));
const temporary = path.join(scratch, 'tmp'); mkdirSync(temporary, { mode: 0o700 });
Object.assign(process.env, { TMPDIR: temporary, TMP: temporary, TEMP: temporary });
mkdirSync(path.dirname(options.output), { recursive: true, mode: 0o700 });
const defaultParent = path.join(root, '.artifacts/original-tests');
if (path.dirname(options.output) === defaultParent && /^[a-f0-9-]{36}$/.test(path.basename(options.output))) {
  const historyFile = path.join(defaultParent, 'history.json');
  let history = [];
  try { const info = lstatSync(historyFile); if (!info.isFile() || info.isSymbolicLink() || info.size > 65536) throw new Error('Original-test history is not bounded ordinary data.'); history = JSON.parse(readFileSync(historyFile, 'utf8')); }
  catch (error) { if (error.code !== 'ENOENT') throw error; }
  if (!Array.isArray(history) || history.length > 16) throw new Error('Original-test history is invalid.');
  for (const name of readdirSync(defaultParent)) {
    if (!/^[a-f0-9-]{36}$/.test(name) || name === path.basename(options.output)) continue;
    const directory = path.join(defaultParent, name), info = lstatSync(directory), marker = path.join(directory, '.ud-original-owner.json');
    if (!info.isDirectory() || info.isSymbolicLink() || typeof process.getuid === 'function' && info.uid !== process.getuid()) continue;
    let owner;
    try { const item = lstatSync(marker); if (!item.isFile() || item.isSymbolicLink() || item.size > 4096) continue; owner = JSON.parse(readFileSync(marker, 'utf8')); }
    catch (error) { if (error.code === 'ENOENT') continue; throw error; }
    if (owner.schema_version !== 1 || owner.owner_root !== root || owner.id !== name) continue;
    let reportSha256 = null;
    try { const file = path.join(directory, 'report.json'), item = lstatSync(file); if (!item.isFile() || item.isSymbolicLink() || item.size > 128 * 1024 ** 2) throw new Error('Original-test report is not bounded ordinary data.'); reportSha256 = sha256(readFileSync(file)); }
    catch (error) { if (error.code !== 'ENOENT') throw error; }
    history = [...history, { id: name, report_sha256: reportSha256 }].slice(-16);
    writeFileSync(historyFile, JSON.stringify(history) + '\n', { mode: 0o600 });
    rmSync(directory, { recursive: true });
  }
  options.outputOwner = { schema_version: 1, owner_root: root, id: path.basename(options.output) };
}
if (options.candidate) options.candidate = JSON.parse(readFileSync(options.candidate, 'utf8'));
if (options.candidate && options.candidateRoot === undefined && options.candidate.qualification !== 'available-target-preacceptance') options.candidateRoot = root;
const report = runOriginalAcceptance(working, options);
let unchanged = false;
try { unchanged = sourceReceipt(root).sha256 === before.sha256 && canonicalJson(nodeDependencyInventory(modules)) === canonicalJson(dependencies); } catch { /* An unreadable input is not unchanged. */ }
if (!unchanged) {
  report.status = 'failed-or-incomplete'; report.reason = 'Selected original source or QA dependencies changed or became unreadable during execution.';
  if (report.unsigned_evidence) { rmSync(path.join(options.output, report.unsigned_evidence.path), { force: true }); delete report.unsigned_evidence; }
  writeFileSync(path.join(options.output, 'report.json'), JSON.stringify(report, null, 2) + '\n');
}
console.log(JSON.stringify({ status: report.status, scheduled: report.scheduled, executed: report.executed, output: path.resolve(options.output), reason: report.reason ?? null }));
if (report.status !== 'passed-locally') process.exitCode = 1;
