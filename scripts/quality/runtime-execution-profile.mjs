/** Detached original QA execution with an explicitly selected, closed installation. */
import assert from 'node:assert/strict';
import { chmodSync, constants, cpSync, existsSync, lstatSync, mkdirSync, readFileSync, readdirSync, realpathSync, symlinkSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { fileReceipt, readRecordedBytes, sourceReceipt } from '../release/candidate.mjs';
import { canonicalJson } from '../release/http-transports.mjs';
import { isNodeDependencyInput, nodeDependencyInventory, validateNodeTargetPackages } from './node-dependencies.mjs';

function freeze(directory) {
  for (const name of readdirSync(directory)) { const file = path.join(directory, name), info = lstatSync(file); if (info.isSymbolicLink()) continue; if (info.isDirectory()) freeze(file); else { assert.ok(info.isFile(), 'QA copy contains a special entry'); chmodSync(file, (info.mode & 0o777) & ~0o222); } }
  chmodSync(directory, 0o555);
}
function actualTarget() { let libc; if (process.platform === 'linux') { const report = process.report.getReport(); assert.ok(report && typeof report === 'object' && 'header' in report); const header = report.header; assert.ok(header && typeof header === 'object'); libc = 'glibcVersionRuntime' in header && typeof header.glibcVersionRuntime === 'string' ? 'glibc' : 'musl'; } return { os: process.platform, cpu: process.arch, ...(libc === undefined ? {} : { libc }) }; }
function ordinary(root) { const info = lstatSync(root); assert.ok(info.isDirectory() && !info.isSymbolicLink(), 'QA profile directory must be ordinary'); }
function selectedNode() { const executable = realpathSync(process.execPath); return { ...fileReceipt(path.dirname(executable), path.basename(executable)), executable_path: executable, version: process.version }; }

/** Capture the owner's existing locked install; this does not fetch or reproduce vendor bytes. */
export function prepareRuntimeExecutionProfile(sourceRoot, qaRoot, output) {
  sourceRoot = realpathSync(sourceRoot); qaRoot = realpathSync(qaRoot); output = path.resolve(output);
  assert.ok(!existsSync(output) && !output.startsWith(sourceRoot + path.sep) && !output.startsWith(qaRoot + path.sep), 'QA execution requires a new detached profile');
  const source = sourceReceipt(sourceRoot), sourceLock = fileReceipt(sourceRoot, 'package-lock.json'), qaLock = fileReceipt(qaRoot, 'package-lock.json');
  assert.equal(sourceLock.sha256, qaLock.sha256, 'Selected QA package lock differs from frozen source'); assert.equal(sourceLock.size, qaLock.size);
  const selected = path.join(qaRoot, 'node_modules'), modules = realpathSync(selected), inventory = nodeDependencyInventory(modules), target = actualTarget();
  const packages = validateNodeTargetPackages(modules, JSON.parse(readRecordedBytes(qaRoot, qaLock, 16 * 1024 ** 2).toString()), { ...target, libc: target.libc });
  mkdirSync(output, { mode: 0o700 }); const qa = path.join(output, 'qa'), tree = path.join(output, 'tree'); mkdirSync(qa); mkdirSync(tree);
  writeFileSync(path.join(qa, 'package-lock.json'), readRecordedBytes(qaRoot, qaLock, 16 * 1024 ** 2), { flag: 'wx', mode: 0o444 });
  cpSync(modules, path.join(qa, 'node_modules'), { recursive: true, dereference: false, verbatimSymlinks: true, errorOnExist: true, force: false, mode: constants.COPYFILE_FICLONE, filter: file => isNodeDependencyInput(modules, file) });
  assert.equal(canonicalJson(nodeDependencyInventory(path.join(qa, 'node_modules'))), canonicalJson(inventory), 'QA dependency snapshot changed during copy'); freeze(path.join(qa, 'node_modules'));
  for (const row of source.files) { const file = path.join(tree, row.path); mkdirSync(path.dirname(file), { recursive: true }); writeFileSync(file, readRecordedBytes(sourceRoot, row, 512 * 1024 ** 2), { flag: 'wx', mode: row.executable ? 0o555 : 0o444 }); }
  symlinkSync(path.join(qa, 'node_modules'), path.join(tree, 'node_modules'), process.platform === 'win32' ? 'junction' : 'dir');
  freeze(tree);
  assert.equal(realpathSync(selected), modules, 'Selected QA dependency root changed'); assert.equal(canonicalJson(nodeDependencyInventory(modules)), canonicalJson(inventory), 'Selected QA installation changed during snapshot');
  assert.equal(fileReceipt(qaRoot, 'package-lock.json').sha256, qaLock.sha256); assert.equal(canonicalJson(sourceReceipt(sourceRoot)), canonicalJson(source)); assert.equal(canonicalJson(sourceReceipt(tree)), canonicalJson(source));
  writeFileSync(path.join(output, 'source.json'), JSON.stringify(source) + '\n', { flag: 'wx', mode: 0o444 });
  const installation = { schema_version: 1, qualification: 'actual-selected-QA-installation', original_vendor_byte_or_reproduced_build_claim: false, selected_root: qaRoot, selected_node_modules: modules, package_lock: qaLock, target, packages: packages.packages, inventory };
  writeFileSync(path.join(qa, 'installation.json'), JSON.stringify(installation) + '\n', { flag: 'wx', mode: 0o444 });
  const profile = { schema_version: 1, qualification: 'detached-original-QA-execution-not-mutant-isolation', source_root: 'tree', source: fileReceipt(output, 'source.json'), source_sha256: source.sha256, package_lock_sha256: sourceLock.sha256, qa_root: 'qa/node_modules', qa_installation: fileReceipt(output, 'qa/installation.json'), node: selectedNode() };
  writeFileSync(path.join(output, 'runtime-execution.json'), JSON.stringify(profile, null, 2) + '\n', { flag: 'wx', mode: 0o444 });
  return verifyRuntimeExecutionProfile(output);
}

/** @param {string} profileRoot @param {{sourceRoot?: string}} [options] */
export function verifyRuntimeExecutionProfile(profileRoot, { sourceRoot } = {}) {
  profileRoot = realpathSync(profileRoot); ordinary(profileRoot);
  assert.deepEqual(readdirSync(profileRoot).sort(), ['qa', 'runtime-execution.json', 'source.json', 'tree'], 'QA profile has unlisted entries');
  const receipt = fileReceipt(profileRoot, 'runtime-execution.json'), profile = JSON.parse(readRecordedBytes(profileRoot, receipt, 65536).toString());
  assert.equal(profile.schema_version, 1); assert.equal(profile.qualification, 'detached-original-QA-execution-not-mutant-isolation'); assert.equal(profile.source_root, 'tree'); assert.equal(profile.qa_root, 'qa/node_modules');
  const tree = path.join(profileRoot, 'tree'), modules = path.join(profileRoot, 'qa/node_modules'); ordinary(tree); ordinary(modules);
  assert.deepEqual(readdirSync(path.join(profileRoot, 'qa')).sort(), ['installation.json', 'node_modules', 'package-lock.json'], 'QA prefix has unlisted entries');
  if (sourceRoot !== undefined) assert.equal(realpathSync(sourceRoot), tree, 'QA evidence must describe the actual executing source copy');
  assert.ok(lstatSync(path.join(tree, 'node_modules')).isSymbolicLink(), 'QA source dependency alias is missing'); assert.equal(realpathSync(path.join(tree, 'node_modules')), modules, 'QA source alias escapes the explicitly frozen dependency prefix');
  const source = JSON.parse(readRecordedBytes(profileRoot, profile.source, 32 * 1024 ** 2).toString()), installation = JSON.parse(readRecordedBytes(profileRoot, profile.qa_installation, 32 * 1024 ** 2).toString());
  assert.equal(source.sha256, profile.source_sha256); assert.equal(canonicalJson(sourceReceipt(tree)), canonicalJson(source), 'QA execution source copy changed');
  const expected = new Set(source.files.map(row => row.path)), actual = new Set();
  function complete(directory, prefix = '') { for (const name of readdirSync(directory)) { const relative = prefix + name, file = path.join(directory, name); if (relative === 'node_modules') continue; const info = lstatSync(file); assert.ok(!info.isSymbolicLink(), 'QA execution source has an unlisted link'); if (info.isDirectory()) complete(file, relative + '/'); else { assert.ok(info.isFile() && expected.has(relative), 'QA execution source has an unlisted entry'); actual.add(relative); } } }
  complete(tree); assert.equal(actual.size, expected.size, 'QA execution source omits an inventoried member');
  assert.equal(installation.schema_version, 1); assert.equal(installation.qualification, 'actual-selected-QA-installation'); assert.equal(installation.original_vendor_byte_or_reproduced_build_claim, false);
  assert.equal(installation.package_lock.sha256, profile.package_lock_sha256); assert.equal(fileReceipt(tree, 'package-lock.json').sha256, profile.package_lock_sha256); assert.equal(canonicalJson(installation.target), canonicalJson(actualTarget()));
  assert.equal(fileReceipt(profileRoot, 'qa/package-lock.json').sha256, profile.package_lock_sha256);
  assert.equal(canonicalJson(nodeDependencyInventory(modules)), canonicalJson(installation.inventory), 'Closed QA dependency bytes changed');
  assert.equal(canonicalJson(validateNodeTargetPackages(modules, JSON.parse(readFileSync(path.join(tree, 'package-lock.json'), 'utf8')), installation.target).packages), canonicalJson(installation.packages), 'Locked QA package identities changed');
  assert.deepEqual(selectedNode(), profile.node, 'QA execution Node differs from the selected tool');
  return { profile_root: profileRoot, source_root: tree, qa_node_modules: modules, profile: receipt, source_sha256: profile.source_sha256, package_lock_sha256: profile.package_lock_sha256, qa_installation: profile.qa_installation, qualification: installation.qualification, original_vendor_byte_or_reproduced_build_claim: false, node: profile.node };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { const [sourceRoot, qaRoot, output] = process.argv.slice(2); assert.equal(process.argv.length, 5, 'Usage: runtime-execution-profile.mjs FROZEN_SOURCE_ROOT EXPLICIT_QA_ROOT NEW_PROFILE'); console.log(JSON.stringify(prepareRuntimeExecutionProfile(sourceRoot, qaRoot, output))); }
  catch (error) { console.error(error.message); process.exitCode = 1; }
}
