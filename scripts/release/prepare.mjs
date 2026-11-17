#!/usr/bin/env node
/** Assemble unaccepted local development artifacts. Never publishes. */
import { createHash } from 'node:crypto';
import { chmodSync, copyFileSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { fileReceipt, safeRelative, sha256, sourceReceipt, SOURCE_ROOTS } from './candidate.mjs';
import { verifyOciArchive } from './oci.mjs';
import { copyContextAssets } from './context-assets.mjs';
import { auxiliaryArtifacts } from './auxiliary-artifacts.mjs';
import { sourceArtifacts } from './source-artifacts.mjs';
import { selectedUserspaceFiles } from './userspace-assets.mjs';
import { canonicalJson } from './http-transports.mjs';
import { publishedNpmManifest } from './npm-package.mjs';
import { loadDistributionIdentity, nativeHostFiles, npmHostFiles, releasePlatforms as expectedPlatforms, releasePlatformIds as platformIds, windowsNodeDescriptor } from './host-adapters.mjs';
import { writeSkillSupport } from './skill-support.mjs';
import { selectedNativeHelpers } from './native-helpers.mjs';
import { resolveCrossBuildInputs, retainCrossBuildInputs } from './cross-build-inputs.mjs';
import { planSourceMaterials, writeComponentCoverage } from './component-preparation.mjs';
import { reserveStorage, storageTreeBytes } from '../quality/storage-lifecycle.mjs';
import { abortCandidate, beginCandidate, completeLocalCandidate } from './candidate-retention.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const artifacts = path.join(root, '.artifacts');
const python = process.env.UD_AGENT_PYTHON ?? (process.platform === 'win32' ? 'python' : 'python3');
const json = file => JSON.parse(readFileSync(path.join(root, file), 'utf8'));
function command(program, args, options = {}) {
  const result = spawnSync(program, args, { cwd: root, encoding: 'utf8', timeout: 180_000, maxBuffer: 16 * 1024 * 1024, ...options });
  if (result.error || result.status !== 0) throw new Error(`${program} failed: ${result.error?.message ?? result.stderr ?? result.status}`);
  return result.stdout ?? '';
}
function requireCondition(value, message) { if (!value) throw new Error(message); }
/** Compile the retained candidate source using only its selected build inputs. */
/** @param {string} sourceRoot @param {string} buildRoot @param {string} output @param {{tempRoot?: string}} [options] */
export function bundleCoordinator(sourceRoot, buildRoot, output, { tempRoot } = {}) {
  const compiler = fileURLToPath(new URL('./replay-coordinator-bundle.mjs', import.meta.url));
  const env = tempRoot === undefined ? process.env : { ...process.env, TMPDIR: tempRoot, TMP: tempRoot, TEMP: tempRoot };
  const tools = JSON.parse(command(process.execPath, [compiler, '--tool-inputs', buildRoot], { env }));
  const replay = JSON.parse(command(process.execPath, [compiler, sourceRoot, buildRoot, JSON.stringify(tools), '--output', path.resolve(output)], { cwd: sourceRoot, env }));
  const actual = fileReceipt(path.dirname(path.resolve(output)), path.basename(output));
  requireCondition(actual.sha256 === replay.bundle.sha256 && actual.size === replay.bundle.size_bytes, 'Shared coordinator compiler output differs from its exact replay receipt.');
}

function copyTree(source, destination) {
  const info = lstatSync(source);
  if (info.isSymbolicLink()) throw new Error(`Source contains a symbolic link: ${source}`);
  if (info.isDirectory()) {
    mkdirSync(destination, { recursive: true });
    for (const name of readdirSync(source).sort()) {
      if (['.artifacts', '.stryker-tmp', '__pycache__', 'node_modules', 'target'].includes(name) || name.endsWith('.pyc')) continue;
      copyTree(path.join(source, name), path.join(destination, name));
    }
  } else if (info.isFile()) {
    mkdirSync(path.dirname(destination), { recursive: true });
    copyFileSync(source, destination);
    chmodSync(destination, info.mode & 0o111 ? 0o755 : 0o644);
  } else throw new Error(`Unsupported source entry: ${source}`);
}
function launcherSourceHash(sourceRoot = root) {
  function files(directory) {
    const found = [];
    for (const name of readdirSync(directory).sort()) {
      const item = path.join(directory, name);
      const info = lstatSync(item);
      if (info.isSymbolicLink()) throw new Error('Launcher source contains a symbolic link.');
      if (info.isDirectory()) found.push(...files(item));
      else if (info.isFile()) found.push(item);
      else throw new Error('Launcher source contains an unsupported entry.');
    }
    return found;
  }
  const paths = [path.join(sourceRoot, 'Cargo.toml'), path.join(sourceRoot, 'Cargo.lock'), ...files(path.join(sourceRoot, 'packages/launcher'))].sort();
  const digest = createHash('sha256');
  for (const file of paths) { digest.update(path.relative(sourceRoot, file)); digest.update('\0'); digest.update(readFileSync(file)); digest.update('\0'); }
  return digest.digest('hex');
}
function checkNodeReceipt(lock, sourceRoot = root, buildRoot = root, selected = expectedPlatforms) {
  requireCondition(lock.schema_version === 1 && lock.version && expectedPlatforms.every(platform => Object.hasOwn(lock.platforms ?? {}, platform)), 'Incomplete Node distribution lock.');
  const folder = path.join(buildRoot, '.artifacts/node');
  const signed = path.join(folder, 'SHASUMS256.txt.asc');
  const keyring = path.join(folder, 'nodejs-release-keys.kbx');
  requireCondition(sha256(readFileSync(signed)) === lock.signed_manifest_sha256 && sha256(readFileSync(keyring)) === lock.release_keyring_sha256, 'Node signature input differs from its lock.');
  const status = command('gpgv', ['--keyring', keyring, '--status-fd', '1', signed]);
  const fingerprints = [...status.matchAll(/^\[GNUPG:\] VALIDSIG ([A-F0-9]+) /gm)].map(match => match[1]);
  requireCondition(fingerprints.length === 1 && fingerprints[0] === lock.checksum_signer_fingerprint, 'Node checksum signer is not the locked publisher.');
  // A clear-signed file contains the authenticated checksum lines directly;
  // verify the signature first and only consume lines inside its signed body.
  const signedLines = readFileSync(signed, 'utf8').split(/\r?\n/);
  const bodyStart = signedLines.indexOf('') + 1;
  const bodyEnd = signedLines.indexOf('-----BEGIN PGP SIGNATURE-----');
  requireCondition(bodyStart > 0 && bodyEnd > bodyStart, 'Malformed Node signed checksum document.');
  const lines = signedLines.slice(bodyStart, bodyEnd).map(line => line.startsWith('- ') ? line.slice(2) : line);
  for (const platform of expectedPlatforms) {
    const item = lock.platforms[platform];
    requireCondition(/^[0-9a-f]{64}$/.test(item?.sha256 ?? '') && typeof item.filename === 'string' && path.basename(item.filename) === item.filename, 'Invalid Node distribution record.');
    requireCondition(lines.includes(`${item.sha256}  ${item.filename}`), `Node signed checksum missing for ${platform}.`);
    if (platform.startsWith('win32-')) {
      const descriptor = windowsNodeDescriptor(sourceRoot, platform);
      const relative = `win-${platform.slice(6)}/node.exe`;
      requireCondition(descriptor.version === lock.version && lines.includes(`${descriptor.sha256.slice(7)}  ${relative}`), `Standalone Node executable is missing from the signed checksum list: ${platform}.`);
    } else if (selected.includes(platform)) {
      const checked = fileReceipt(buildRoot, `.artifacts/node/${item.filename}`);
      requireCondition(checked.sha256 === item.sha256, `Node archive checksum mismatch for ${platform}.`);
    }
  }
}
function validateCrossReceipt(receipt, sourceRoot = root, buildRoot = root) {
  requireCondition(receipt?.schema_version === 1 && receipt.status === 'unaccepted' && receipt.source_sha256 === launcherSourceHash(sourceRoot), 'Launcher cross-build receipt is missing or stale.');
  const inputs = resolveCrossBuildInputs(buildRoot, '.artifacts/cross-build-receipt.json');
  requireCondition(canonicalJson(receipt) === canonicalJson(inputs.cross), 'Launcher cross-build receipt changed during validation.');
  return inputs;
}
function crossBuildBinary(inputs, platform, name) {
  const binary = inputs.binaries.find(item => item.platform === platform && item.name === name);
  requireCondition(binary, `Launcher or helper receipt mismatch: ${platform}/${name}`);
  return binary.path;
}
export function retainSourceSnapshot(sourceRoot, receipt, output) {
  const relativeOutput = path.relative(path.resolve(sourceRoot), path.resolve(output));
  requireCondition(relativeOutput && (relativeOutput === '..' || relativeOutput.startsWith('..' + path.sep) || path.isAbsolute(relativeOutput) || !SOURCE_ROOTS.includes(relativeOutput.split(path.sep)[0])), 'Source snapshot output must be outside its copied input trees.');
  requireCondition(!existsSync(output) && receipt.sha256 === sourceReceipt(sourceRoot).sha256, 'Diagnostic source snapshot must start from the exact current source receipt.');
  mkdirSync(output, { recursive: true });
  for (const row of receipt.files) {
    const actual = fileReceipt(sourceRoot, row.path);
    requireCondition(actual.sha256 === row.sha256 && actual.size === row.size && actual.executable === row.executable, 'Diagnostic source changed while retaining its snapshot.');
    const target = path.join(output, ...row.path.split('/')); mkdirSync(path.dirname(target), { recursive: true }); copyFileSync(path.join(sourceRoot, ...row.path.split('/')), target); chmodSync(target, row.executable ? 0o755 : 0o644);
    const copied = fileReceipt(output, row.path); requireCondition(copied.sha256 === row.sha256 && copied.size === row.size && copied.executable === row.executable, 'Retained diagnostic source bytes differ.');
  }
  requireCondition(sourceReceipt(output).sha256 === receipt.sha256, 'Retained diagnostic source inventory differs.');
  writeFileSync(path.join(output, 'SOURCE-RECEIPT.json'), JSON.stringify(receipt, null, 2) + '\n');
  return fileReceipt(output, 'SOURCE-RECEIPT.json');
}
export function packageCommon(destination, bundle, targetPlatform = 'all', runtimeRoot = root, qualification = 'local_candidate', sourceRoot = root) {
  requireCondition(['local_candidate', 'preacceptance_candidate'].includes(qualification), 'Unsupported package qualification.');
  const runtimeJson = name => JSON.parse(readFileSync(path.join(runtimeRoot, name), 'utf8'));
  mkdirSync(path.join(destination, 'lib'), { recursive: true });
  copyFileSync(bundle, path.join(destination, 'lib/coordinator.mjs'));
  for (const dir of ['contracts', 'skills']) copyTree(path.join(sourceRoot, dir), path.join(destination, dir));
  writeSkillSupport(sourceRoot, destination);
  mkdirSync(path.join(destination, 'runtime'), { recursive: true });
  copyFileSync(path.join(runtimeRoot, 'runtime/runtime.lock.json'), path.join(destination, 'runtime/runtime.lock.json'));
  if(existsSync(path.join(runtimeRoot,'runtime/engine-distributions.lock.json')))copyFileSync(path.join(runtimeRoot,'runtime/engine-distributions.lock.json'),path.join(destination,'runtime/engine-distributions.lock.json'));
  const lock = runtimeJson('runtime/runtime.lock.json');
  for (const pack of Object.values(lock.packs ?? {})) if (pack.context_manifest) copyContextAssets(runtimeRoot,destination,pack.context_manifest);
  for (const pack of Object.values(lock.packs ?? {})) if (pack.seccomp_profile) {
    const item = pack.seccomp_profile, checked = fileReceipt(runtimeRoot, item.path);
    requireCondition(typeof item.sha256 === 'string' && `sha256:${checked.sha256}` === item.sha256 && checked.size === item.size_bytes, 'Runtime seccomp policy differs from its receipt.');
    const target = path.join(destination, ...item.path.split('/')); mkdirSync(path.dirname(target), { recursive: true }); copyFileSync(path.join(runtimeRoot, ...item.path.split('/')), target); chmodSync(target, 0o644);
  }
  for (const helper of selectedNativeHelpers(lock, targetPlatform)) {
    const item = helper.guard;
    requireCondition(item && typeof item.path === 'string' && typeof item.sha256 === 'string' && /^sha256:[0-9a-f]{64}$/.test(item.sha256), 'Native helper receipt is invalid.');
    const checked = fileReceipt(runtimeRoot, item.path);
    requireCondition(checked.sha256 === item.sha256.slice(7) && checked.size === item.size_bytes && checked.executable, 'Native helper receipt is invalid.');
    const target = path.join(destination, ...item.path.split('/')); mkdirSync(path.dirname(target), { recursive: true }); copyFileSync(path.join(runtimeRoot, ...item.path.split('/')), target); chmodSync(target, 0o755);
  }
  if (lock.userspace_sha256 !== undefined) {
    requireCondition(/^sha256:[0-9a-f]{64}$/.test(lock.userspace_sha256), 'Userspace manifest binding is invalid.');
    const manifestFile = fileReceipt(runtimeRoot, 'runtime/userspace.lock.json');
    requireCondition(manifestFile.sha256 === lock.userspace_sha256.slice(7), 'Userspace manifest differs from the runtime lock.');
    copyFileSync(path.join(runtimeRoot, 'runtime/userspace.lock.json'), path.join(destination, 'runtime/userspace.lock.json'));
    const manifest = runtimeJson('runtime/userspace.lock.json');
    requireCondition(manifest.state === 'frozen' && manifest.platforms && typeof manifest.platforms === 'object', 'Userspace manifest is not frozen.');
    const copied = new Map();
    for (const item of selectedUserspaceFiles(manifest,targetPlatform)) {
        const checked = fileReceipt(runtimeRoot, item.path);
        requireCondition(`sha256:${checked.sha256}` === item.sha256 && checked.size === item.size && (!copied.has(item.path) || copied.get(item.path) === item.sha256), 'Userspace asset differs from its receipt.');
        if (copied.has(item.path)) continue;
        copied.set(item.path, item.sha256);
        const target = path.join(destination, ...item.path.split('/')); mkdirSync(path.dirname(target), { recursive: true });
        copyFileSync(path.join(runtimeRoot, ...item.path.split('/')), target); chmodSync(target, checked.executable ? 0o755 : 0o644);
    }
  }
  for (const file of ['LICENSE', 'NOTICE']) copyFileSync(path.join(sourceRoot, file), path.join(destination, file));
  copyFileSync(path.join(sourceRoot, 'README.md'), path.join(destination, 'README.md'));
  copyTree(path.join(sourceRoot, 'licenses'), path.join(destination, 'licenses'));
  writeFileSync(path.join(destination, qualification === 'preacceptance_candidate' ? 'RELEASE-CANDIDATE.md' : 'UNACCEPTED.md'), qualification === 'preacceptance_candidate' ? 'Immutable release candidate. Acceptance and signatures refer to these exact archive bytes; this marker does not certify them. Do not rewrite or relabel the payload after testing.\n' : 'Development candidate only. OCI runtimes, signatures, native platform and mutation acceptance are not verified. Do not publish.\n');
}
function writeHostFiles(destination, files) {
  for (const [name, contents] of Object.entries(files)) {
    const filename = path.join(destination, ...name.split('/'));
    mkdirSync(path.dirname(filename), { recursive: true });
    writeFileSync(filename, contents);
  }
}
export function packageInventory(destination, kind, platform, sourceHash, runtimeHash, qualification = 'local_candidate') {
  requireCondition(['local_candidate', 'preacceptance_candidate'].includes(qualification), 'Unsupported package qualification.');
  writeFileSync(path.join(destination, 'BUILD-RECEIPT.json'), JSON.stringify({ schema_version: 1, product_version: '0.1.0-beta.1', kind, platform, source_tree_sha256: sourceHash, runtime_lock_sha256: runtimeHash, qualification }, null, 2) + '\n');
  const files = [];
  function walk(directory) {
    for (const name of readdirSync(directory).sort()) {
      const file = path.join(directory, name), info = lstatSync(file);
      requireCondition(!info.isSymbolicLink(), 'Package inventory contains a link.');
      if (info.isDirectory()) walk(file);
      else if (info.isFile()) files.push(fileReceipt(destination, path.relative(destination, file).split(path.sep).join('/')));
      else throw new Error('Package inventory contains a special file.');
    }
  }
  walk(destination);
  writeFileSync(path.join(destination, 'PACKAGE-INVENTORY.json'), JSON.stringify({ schema_version: 1, files }, null, 2) + '\n');
}
function artifactsForStage(output, records) {
  const rootRelative = path.relative(root, output).split(path.sep).join('/');
  return records.map(record => {
    const data = fileReceipt(record.stageRoot, record.filename);
    return { id: record.id, path: `${rootRelative}/${record.filename}`, sha256: data.sha256, size: data.size, platform: record.platform };
  });
}
export function prepare(output, { preacceptance = false, materialsProvisional = false, transientAllowance = undefined } = {}) {
  requireCondition(!(preacceptance && materialsProvisional), 'Provisional material planning cannot be a preacceptance candidate.');
  let outputExists = true;
  try { lstatSync(output); } catch (error) { if (error.code === 'ENOENT') outputExists = false; else throw error; }
  requireCondition(path.isAbsolute(output) && output.startsWith(artifacts + path.sep) && !outputExists, 'Output must be a new directory under .artifacts.');
  mkdirSync(artifacts, { recursive: true });
  let parent = root;
  for (const part of path.relative(root, path.dirname(output)).split(path.sep)) {
    parent = path.join(parent, part);
    const info = lstatSync(parent);
    requireCondition(info.isDirectory() && !info.isSymbolicLink(), 'Output parent must contain only ordinary directories.');
  }
  const source = sourceReceipt(root);
  const cross = json('.artifacts/cross-build-receipt.json');
  const identity = loadDistributionIdentity(root);
  const nodeLock = json('runtime/node-distributions.lock.json');
  const runtime = json('runtime/runtime.lock.json');
  requireCondition(['unbuilt', 'frozen'].includes(runtime.state), 'Candidate packaging requires an unbuilt development or frozen runtime lock.');
  if (preacceptance) {
    requireCondition(runtime.state === 'frozen' && runtime.format_revision === 2, 'Preacceptance packages require a complete current frozen runtime lock.');
    sourceArtifacts(root, { required: true, complete: true });
    const userspace = json('runtime/userspace.lock.json');
    requireCondition(Object.keys(userspace.platforms ?? {}).sort().join(',') === expectedPlatforms.map(platform => platform.replace('-', '/')).join(','), 'Preacceptance packages require the complete published userspace platform set.');
  }
  const qualification = preacceptance ? 'preacceptance_candidate' : 'local_candidate';
  const crossInputs = validateCrossReceipt(cross);
  const userspace=runtime.userspace_sha256?json('runtime/userspace.lock.json'):undefined;
  const nativeBytes=Object.values(userspace?.platforms??{}).reduce((sum,platform)=>sum+(platform.files??[]).reduce((n,row)=>n+row.size,0),0);
  const transports=new Map();
  for(const pack of Object.values(runtime.packs??{}))for(const item of [pack.index_transport,...Object.values(pack.images??{}).flatMap(image=>image.transports??[])].filter(Boolean))transports.set(item.path,item.size_bytes);
  const materialBytes=runtime.state==='frozen'?sourceArtifacts(root,{required:preacceptance}).reduce((sum,row)=>sum+row.size,0):0;
  const plannedBytes=3*source.files.reduce((sum,row)=>sum+row.size,0)+2*storageTreeBytes(path.join(root,'runtime'))+3*nativeBytes+expectedPlatforms.length*3*512*1024**2+2*[...transports.values()].reduce((sum,size)=>sum+size,0)+2*auxiliaryArtifacts(root,userspace,runtime).reduce((sum,row)=>sum+row.size_bytes,0)+materialBytes+128*1024**2;
  let begun = false;
  const storage=reserveStorage({root,plannedBytes,profile:'release',transientAllowance,scratchParent:artifacts,inputRoots:SOURCE_ROOTS.map(name=>path.join(root,name)).filter(name=>existsSync(name)&&lstatSync(name).isDirectory()),label:'release-prepare',onCancel:()=>{if(begun)abortCandidate(root,output);}});
  const temporary = storage.directory;
  try {
    beginCandidate(root, output); begun = true;
    writeFileSync(path.join(output, 'INCOMPLETE'), 'Local candidate assembly incomplete.\n');
    checkNodeReceipt(nodeLock);
    const bundle = path.join(temporary, 'coordinator.mjs');
    bundleCoordinator(root, root, bundle, {tempRoot: temporary});
    const stage = path.join(temporary, 'output');
    const work = path.join(temporary, 'work');
    mkdirSync(stage); mkdirSync(work);
    const records = [];
    retainCrossBuildInputs(root, '.artifacts/cross-build-receipt.json', path.join(stage, 'native-inputs'));
    const runtimeHash = sha256(readFileSync(path.join(root, 'runtime/runtime.lock.json')));
    for (const platform of expectedPlatforms) {
      const packageDir = path.join(work, platform);
      mkdirSync(packageDir);
      packageCommon(packageDir, bundle, platform, root, qualification);
      copyFileSync(path.join(root, 'plugin.json'), path.join(packageDir, 'plugin.json'));
      const extension = platform.startsWith('win32-') ? '.exe' : '';
      const bin = path.join(packageDir, 'bin'); mkdirSync(bin);
      for (const name of ['ud-agent', 'ud-agent-guard']) {
        const target = path.join(bin, name + extension);
        copyFileSync(crossBuildBinary(crossInputs, platform, name), target);
        chmodSync(target, 0o755);
      }
      if (extension) {
        writeFileSync(path.join(packageDir, 'runtime/windows-node.json'), JSON.stringify(windowsNodeDescriptor(root, platform), null, 2) + '\n');
      } else {
        const node = nodeLock.platforms[platform];
        command(python, ['scripts/release/extract-node.py', '--archive', path.join(artifacts, 'node', node.filename), '--output', path.join(packageDir, 'runtime/node'), '--platform', platform, '--version', nodeLock.version, '--sha256', node.sha256]);
        copyFileSync(path.join(root, 'packaging/mcpb-entry.cjs'), path.join(packageDir, 'mcpb-entry.cjs'));
      }
      writeHostFiles(packageDir, nativeHostFiles(identity, platform));
      const format = extension ? 'zip' : 'tar.gz';
      packageInventory(packageDir, 'native', platform, source.sha256, runtimeHash, qualification);
      const filename = `ud-agent-skill-mcp-plugin-${platform}.${format}`;
      command(python, ['scripts/release/archive-dev.py', packageDir, path.join(stage, filename), '--format', format]);
      command(python, ['scripts/release/inspect-package.py', path.join(stage, filename), '--kind', 'native', '--platform', platform, '--source-sha256', source.sha256, '--runtime-sha256', runtimeHash]);
      records.push({ id: `native-${platformIds[platform]}`, platform: platformIds[platform], stageRoot: stage, filename });
      const mcpb = `ud-agent-skill-mcp-plugin-${platform}.mcpb`;
      command(python, ['scripts/release/archive-dev.py', packageDir, path.join(stage, mcpb), '--format', 'zip']);
      command(python, ['scripts/release/inspect-package.py', path.join(stage, mcpb), '--kind', 'native', '--platform', platform, '--source-sha256', source.sha256, '--runtime-sha256', runtimeHash]);
      records.push({ id: `mcpb-${platformIds[platform]}`, platform: platformIds[platform], stageRoot: stage, filename: mcpb });
    }
    const npmDir = path.join(work, 'npm'); mkdirSync(npmDir);
    packageCommon(npmDir, bundle, 'all', root, qualification);
    writeHostFiles(npmDir, npmHostFiles(identity));
    for (const name of ['cli.cjs', 'platforms.json']) copyFileSync(path.join(root, 'packages/npm-distribution', name), path.join(npmDir, name));
    chmodSync(path.join(npmDir, 'cli.cjs'), 0o755);
    const npmPackage = publishedNpmManifest(JSON.parse(readFileSync(path.join(root, 'packages/npm-distribution/package.json.in'), 'utf8')));
    writeFileSync(path.join(npmDir, 'package.json'), JSON.stringify(npmPackage, null, 2) + '\n');
    for (const platform of expectedPlatforms) {
      const folder = path.join(npmDir, 'platforms', platform); mkdirSync(folder, { recursive: true });
      const extension = platform.startsWith('win32-') ? '.exe' : '';
      for (const name of ['ud-agent', 'ud-agent-guard']) {
        const target = path.join(folder, name + extension);
        copyFileSync(crossBuildBinary(crossInputs, platform, name), target); chmodSync(target, 0o755);
      }
    }
    packageInventory(npmDir, 'npm', 'all', source.sha256, runtimeHash, qualification);
    const npmEnv = { ...process.env, npm_config_cache: path.join(temporary, 'npm-cache'), npm_config_userconfig: path.join(temporary, 'npm-userconfig'), npm_config_globalconfig: path.join(temporary, 'npm-globalconfig'), npm_config_ignore_scripts: 'true', npm_config_offline: 'true' };
    const npmOutput = command('npm', ['pack', '--ignore-scripts', '--json', '--pack-destination', stage], { cwd: npmDir, env: npmEnv });
    const packed = JSON.parse(npmOutput);
    requireCondition(Array.isArray(packed) && packed.length === 1 && typeof packed[0].filename === 'string' && path.basename(packed[0].filename) === packed[0].filename, 'npm pack did not return one local tarball.');
    command(python, ['scripts/release/inspect-package.py', path.join(stage, packed[0].filename), '--kind', 'npm', '--platform', 'all', '--source-sha256', source.sha256, '--runtime-sha256', runtimeHash]);
    records.push({ id: 'npm', platform: 'all', stageRoot: stage, filename: packed[0].filename });
    const standalone = path.join(work, 'standalone-skills');
    mkdirSync(standalone);
    copyTree(path.join(root, 'skills'), path.join(standalone, 'skills'));
    writeSkillSupport(root, standalone);
    for (const name of ['LICENSE', 'NOTICE']) copyFileSync(path.join(root, name), path.join(standalone, name));
    copyTree(path.join(root, 'licenses'), path.join(standalone, 'licenses'));
    if (preacceptance) writeFileSync(path.join(standalone, 'RELEASE-CANDIDATE.md'), 'Immutable release candidate; acceptance binds these exact bytes.\n');
    packageInventory(standalone, 'skills', 'all', source.sha256, runtimeHash, qualification);
    const skillsArchive = 'ud-agent-skill-mcp-plugin-skills.tar.gz';
    command(python, ['scripts/release/archive-dev.py', standalone, path.join(stage, skillsArchive), '--format', 'tar.gz']);
    command(python, ['scripts/release/inspect-package.py', path.join(stage, skillsArchive), '--kind', 'skills', '--platform', 'all', '--source-sha256', source.sha256, '--runtime-sha256', runtimeHash]);
    records.push({ id: 'standalone-skills', platform: 'all', stageRoot: stage, filename: skillsArchive });
    const publicationMetadata = [['mcp-registry-record', 'registry/server.json', 'ud-agent-skill-mcp-plugin-mcp-registry.json'], ['catalog-claude', '.claude-plugin/marketplace.json', 'ud-agent-catalog-claude.json'], ['catalog-codex', 'packaging/codex/marketplace.json', 'ud-agent-catalog-codex.json'], ['catalog-grok', '.grok-plugin/marketplace.json', 'ud-agent-catalog-grok.json'], ['catalog-grok-index', '.grok-plugin/plugin-index.json', 'ud-agent-catalog-grok-index.json']];
    for (const [id, sourcePath, filename] of publicationMetadata) {
      const bytes = readFileSync(path.join(root, sourcePath));
      writeFileSync(path.join(stage, filename), id === 'mcp-registry-record' ? canonicalJson(JSON.parse(bytes.toString('utf8'))) : bytes);
      records.push({ id, platform: 'all', stageRoot: stage, filename });
    }
    const sourceDir = path.join(work, 'source'); mkdirSync(sourceDir);
    for (const item of source.files) {
      const target = path.join(sourceDir, ...item.path.split('/')); mkdirSync(path.dirname(target), { recursive: true });
      requireCondition(fileReceipt(root, item.path).sha256 === item.sha256, 'Source changed while assembling source materials.');
      copyFileSync(path.join(root, ...item.path.split('/')), target); chmodSync(target, item.executable ? 0o755 : 0o644);
    }
    const sourceManifest = path.join(temporary, 'source-receipt.json'); writeFileSync(sourceManifest, JSON.stringify(source));
    writeFileSync(path.join(sourceDir, 'SOURCE-MANIFEST.json'), JSON.stringify(source, null, 2) + '\n');
    const sourceArchive = 'ud-agent-skill-mcp-plugin-source.tar.gz';
    command(python, ['scripts/release/archive-dev.py', sourceDir, path.join(stage, sourceArchive), '--format', 'tar.gz']);
    records.push({ id: 'source-archive', platform: 'all', stageRoot: stage, filename: sourceArchive });
    renameSync(sourceDir, path.join(stage, 'source-snapshot'));
    const corresponding = sourceArtifacts(root);
    for (const item of corresponding) {
      const filename = path.posix.basename(item.path);
      requireCondition(!records.some(record => record.filename === filename || record.id === item.id), 'Corresponding-source artifact identity collides.');
      copyFileSync(path.join(root, ...item.path.split('/')), path.join(stage, filename));
      records.push({ id: item.id, platform: 'all', stageRoot: stage, filename });
    }
    const sbomName = 'ud-agent-skill-mcp-plugin-sbom.spdx.json';
    command(python, ['scripts/release/sbom.py', '--root', root, '--source-receipt', sourceManifest, '--created', new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'), '--output', path.join(stage, sbomName)]);
    records.push({ id: 'sbom', platform: 'all', stageRoot: stage, filename: sbomName });
    if (runtime.state === 'frozen') for (const pack of ['core', 'render']) {
      const descriptor = runtime.packs?.[pack]?.index_transport;
      requireCondition(descriptor?.format === 'oci-archive' && typeof descriptor.path === 'string' && typeof descriptor.sha256 === 'string', `Frozen ${pack} index archive is missing.`);
      const checked = fileReceipt(root, descriptor.path); const expectedHash = descriptor.sha256.replace(/^sha256:/, '');
      requireCondition(checked.sha256 === expectedHash && checked.size === descriptor.size_bytes, `Frozen ${pack} archive differs from its receipt.`);
      verifyOciArchive(path.join(root, ...descriptor.path.split('/')), runtime.packs[pack].index_digest, runtime.packs[pack].platforms, checked, runtime.packs[pack].images);
      const filename = `ud-agent-skill-mcp-plugin-${pack}.oci.tar`; copyFileSync(path.join(root, ...descriptor.path.split('/')), path.join(stage, filename));
      records.push({ id: `${pack}-oci-index`, platform: 'linux-multiarch', stageRoot: stage, filename });
      for (const [platform, image] of Object.entries(runtime.packs[pack].images ?? {})) {
        requireCondition(['linux/amd64', 'linux/arm64'].includes(platform) && Array.isArray(image.transports) && image.transports.length > 0, 'Worker platform transports are missing.');
        for (const [number, transport] of image.transports.entries()) {
          requireCondition(['oci-archive', 'docker-archive'].includes(transport.format) && typeof transport.sha256 === 'string' && /^sha256:[0-9a-f]{64}$/.test(transport.sha256), 'Worker platform transport descriptor is invalid.');
          const checked = fileReceipt(root, transport.path);
          requireCondition(checked.sha256 === transport.sha256.slice(7) && checked.size === transport.size_bytes, 'Worker platform transport differs from the runtime lock.');
          const filename = path.posix.basename(transport.path);
          requireCondition(!records.some(item => item.filename === filename), 'Worker transport release filenames collide.');
          copyFileSync(path.join(root, ...transport.path.split('/')), path.join(stage, filename));
          records.push({ id: `${pack}-${platform.replace('/', '-')}-${transport.format}-${number}`, platform, stageRoot: stage, filename });
        }
      }
    }
    if (runtime.userspace_sha256) for (const asset of json('runtime/userspace.lock.json').bootstrap_assets ?? []) {
      requireCondition(asset && typeof asset.id === 'string' && /^[a-z0-9][a-z0-9-]+$/.test(asset.id) && typeof asset.sha256 === 'string' && /^sha256:[0-9a-f]{64}$/.test(asset.sha256), 'Bootstrap asset receipt is invalid.');
      const checked = fileReceipt(root, asset.path);
      requireCondition(checked.sha256 === asset.sha256.slice(7) && checked.size === asset.size, 'Bootstrap asset differs from its receipt.');
      const filename = path.posix.basename(asset.path);
      requireCondition(!records.some(item => item.filename === filename || item.id === asset.id), 'Bootstrap asset release identity collides.');
      copyFileSync(path.join(root, ...asset.path.split('/')), path.join(stage, filename));
      records.push({ id: asset.id, platform: asset.id.replace(/^uv-/, ''), stageRoot: stage, filename });
    }
    for (const asset of auxiliaryArtifacts(root, runtime.userspace_sha256 ? json('runtime/userspace.lock.json') : undefined, runtime)) {
      const filename = path.posix.basename(asset.path);
      requireCondition(!records.some(item => item.filename === filename), 'Duplicate auxiliary artifact filename.');
      copyFileSync(path.join(root, asset.path), path.join(stage, filename));
      records.push({id:asset.id,platform:asset.platform,stageRoot:stage,filename});
    }
    requireCondition(sourceReceipt(root).sha256 === source.sha256 && cross.source_sha256 === launcherSourceHash(), 'Source changed during development packaging.');
    const candidate = { schema_version: 1, status: 'local_candidate', production_ready: false,
      product_version: npmPackage.version, source_tree_sha256: source.sha256,
      launcher_source_sha256: cross.source_sha256, runtime_lock_sha256: sha256(readFileSync(path.join(root, 'runtime/runtime.lock.json'))),
      artifacts: artifactsForStage(output, records),
      blockers: [...(runtime.state === 'unbuilt' ? ['unbuilt_core_and_render_images'] : []), 'unverified_native_platform_runtime', 'missing_signatures', 'missing_mutation_acceptance', 'missing_publication_evidence'] };
    if (preacceptance || materialsProvisional) {
      const coverage = writeComponentCoverage(root, candidate, stage, { python, requireComplete: preacceptance });
      records.push({ id: coverage.id, platform: 'all', stageRoot: stage, filename: coverage.path });
      candidate.artifacts = artifactsForStage(output, records);
      if (materialsProvisional) candidate.blockers.push('provisional_source_material_planning_not_preacceptance');
    }
    writeFileSync(path.join(stage, 'SHA256SUMS'), candidate.artifacts.map(item => `${item.sha256}  ${path.basename(item.path)}`).join('\n') + '\n');
    // The checksum list deliberately omits itself. The candidate separately
    // binds its bytes without introducing a self-referential archive hash.
    records.push({ id: 'checksum-manifest', platform: 'all', stageRoot: stage, filename: 'SHA256SUMS' });
    candidate.artifacts = artifactsForStage(output, records);
    writeFileSync(path.join(stage, 'local-candidate.json'), JSON.stringify(candidate, null, 2) + '\n');
    for (const name of readdirSync(stage)) renameSync(path.join(stage, name), path.join(output, name));
    storage.check(storageTreeBytes(output));
    rmSync(path.join(output, 'INCOMPLETE'));
    completeLocalCandidate(root, output, candidate); begun = false;
    return { output, artifacts: candidate.artifacts.length, status: candidate.status, production_ready: false };
  } catch (error) {
    if (begun) try { abortCandidate(root, output); }
    catch (cleanupError) { throw new AggregateError([error, cleanupError], 'Local candidate assembly or owned-output cleanup failed.'); }
    throw error;
  } finally { storage.cleanup(); }
}
/** @param {{sourceRoot?: string, buildRoot?: string, qualification?: string, python?: string, tempRoot?: string}} [options] */
export function prepareNpmDiagnostic(runtimeRoot, output, options = {}) {
  const sourceRoot = path.resolve(options.sourceRoot ?? root), buildRoot = path.resolve(options.buildRoot ?? root), qualification = options.qualification ?? 'local_candidate', interpreter = options.python ?? python;
  requireCondition(['local_candidate','preacceptance_candidate'].includes(qualification), 'Explicit build qualification is invalid.');
  const read = name => JSON.parse(readFileSync(path.join(sourceRoot, name), 'utf8'));
  runtimeRoot = path.resolve(runtimeRoot); output = path.resolve(output);
  requireCondition(!existsSync(output) && output !== root, 'Diagnostic npm output must be a new directory.');
  const source = sourceReceipt(sourceRoot), cross = JSON.parse(readFileSync(path.join(buildRoot, '.artifacts/cross-build-receipt.json'), 'utf8')), crossInputs = validateCrossReceipt(cross, sourceRoot, buildRoot);
  const identity = loadDistributionIdentity(sourceRoot), runtimeHash = fileReceipt(runtimeRoot, 'runtime/runtime.lock.json').sha256;
  const temporary = mkdtempSync(path.join(options.tempRoot ?? path.join(buildRoot, '.artifacts'), '.npm-build-'));
  try {
    const bundle = path.join(temporary, 'coordinator.mjs');
    bundleCoordinator(sourceRoot, buildRoot, bundle, {tempRoot: temporary});
    const directory = path.join(temporary, 'package'); mkdirSync(directory); packageCommon(directory, bundle, 'all', runtimeRoot, qualification, sourceRoot); writeHostFiles(directory, npmHostFiles(identity));
    for (const name of ['cli.cjs', 'platforms.json']) copyFileSync(path.join(sourceRoot, 'packages/npm-distribution', name), path.join(directory, name));
    chmodSync(path.join(directory, 'cli.cjs'), 0o755); writeFileSync(path.join(directory, 'package.json'), JSON.stringify(publishedNpmManifest(read('packages/npm-distribution/package.json.in')), null, 2) + '\n');
    for (const platform of expectedPlatforms) {
      const folder = path.join(directory, 'platforms', platform); mkdirSync(folder, { recursive: true }); const extension = platform.startsWith('win32-') ? '.exe' : '';
      for (const name of ['ud-agent', 'ud-agent-guard']) { const target = path.join(folder, name + extension); copyFileSync(crossBuildBinary(crossInputs, platform, name), target); chmodSync(target, 0o755); }
    }
    packageInventory(directory, 'npm', 'all', source.sha256, runtimeHash, qualification); mkdirSync(output);
    const env = { ...process.env, TMPDIR: temporary, TMP: temporary, TEMP: temporary, npm_config_cache: path.join(temporary, 'npm-cache'), npm_config_userconfig: path.join(temporary, 'npmrc'), npm_config_globalconfig: path.join(temporary, 'global-npmrc'), npm_config_ignore_scripts: 'true', npm_config_offline: 'true' };
    const packed = JSON.parse(command('npm', ['pack', '--ignore-scripts', '--json', '--pack-destination', output], { cwd: directory, env }));
    requireCondition(packed.length === 1 && path.basename(packed[0].filename) === packed[0].filename, 'Diagnostic npm pack did not return one ordinary tarball.');
    requireCondition(packed[0].size <= 128 * 1024 ** 2 && packed[0].files.every(item => !/\.(?:tar|tar\.gz|tar\.xz|tgz|zip|msi|mcpb)$/.test(item.path)), 'Universal npm payload embeds a dependency archive or exceeds the supported transport.');
    command(interpreter, [path.join(sourceRoot, 'scripts/release/inspect-package.py'), path.join(output, packed[0].filename), '--kind', 'npm', '--platform', 'all', '--source-sha256', source.sha256, '--runtime-sha256', runtimeHash]);
    const artifact = fileReceipt(output, packed[0].filename), report = { schema_version: 1, qualification: qualification === 'local_candidate' ? 'diagnostic-thin-npm-not-final-candidate' : 'immutable-available-target-npm-preacceptance', production_ready: false, source_tree_sha256: source.sha256, source_unchanged: sourceReceipt(sourceRoot).sha256 === source.sha256, runtime_lock_sha256: runtimeHash, artifact, unpacked_size_bytes: packed[0].unpackedSize, files: packed[0].entryCount, embedded_dependency_archives: 0 };
    if (qualification === 'preacceptance_candidate') renameSync(directory, path.join(output, 'npm-installation'));
    writeFileSync(path.join(output, 'measurement.json'), JSON.stringify(report, null, 2) + '\n'); return report;
  } finally { rmSync(temporary, { recursive: true, force: true }); }
}

/** One actual platform payload and both original archive formats for diagnostics. */
/** @param {{sourceRoot?: string, buildRoot?: string, qualification?: string, python?: string, tempRoot?: string}} [options] */
export function preparePlatformDiagnostic(runtimeRoot, platform, output, options = {}) {
  const sourceRoot = path.resolve(options.sourceRoot ?? root), buildRoot = path.resolve(options.buildRoot ?? root), qualification = options.qualification ?? 'local_candidate', interpreter = options.python ?? python;
  requireCondition(['local_candidate','preacceptance_candidate'].includes(qualification), 'Explicit build qualification is invalid.');
  const read = name => JSON.parse(readFileSync(path.join(sourceRoot, name), 'utf8'));
  runtimeRoot = path.resolve(runtimeRoot); output = path.resolve(output);
  requireCondition(expectedPlatforms.includes(platform) && !existsSync(output) && output !== root, 'Diagnostic platform/output must be explicit and new.');
  const source = sourceReceipt(sourceRoot), cross = JSON.parse(readFileSync(path.join(buildRoot, '.artifacts/cross-build-receipt.json'), 'utf8')), crossInputs = validateCrossReceipt(cross, sourceRoot, buildRoot);
  const identity = loadDistributionIdentity(sourceRoot), nodeLock = read('runtime/node-distributions.lock.json'), runtimeHash = fileReceipt(runtimeRoot, 'runtime/runtime.lock.json').sha256;
  const temporary = mkdtempSync(path.join(options.tempRoot ?? path.join(buildRoot, '.artifacts'), '.platform-build-'));
  try {
    const buildCommand = (program, args) => command(program, args, { env: { ...process.env, TMPDIR: temporary, TMP: temporary, TEMP: temporary } });
    const sourceSnapshot = path.join(temporary, 'source-snapshot'); retainSourceSnapshot(sourceRoot, source, sourceSnapshot);
    const nativeInputs = path.join(temporary, 'native-inputs'); retainCrossBuildInputs(buildRoot, '.artifacts/cross-build-receipt.json', nativeInputs);
    checkNodeReceipt(nodeLock, sourceRoot, buildRoot, [platform]);
    const bundle = path.join(temporary, 'coordinator.mjs');
    bundleCoordinator(sourceRoot, buildRoot, bundle, {tempRoot: temporary});
    const payload = path.join(temporary, 'installation'); mkdirSync(payload); packageCommon(payload, bundle, platform, runtimeRoot, qualification, sourceRoot); writeHostFiles(payload, nativeHostFiles(identity, platform)); copyFileSync(path.join(sourceRoot, 'plugin.json'), path.join(payload, 'plugin.json'));
    const suffix = platform.startsWith('win32-') ? '.exe' : ''; mkdirSync(path.join(payload, 'bin'));
    for (const name of ['ud-agent', 'ud-agent-guard']) { const target = path.join(payload, 'bin', name + suffix); copyFileSync(crossBuildBinary(crossInputs, platform, name), target); chmodSync(target, 0o755); }
    if (suffix) {
      writeFileSync(path.join(payload, 'runtime/windows-node.json'), JSON.stringify(windowsNodeDescriptor(sourceRoot, platform), null, 2) + '\n');
    } else {
      const node = nodeLock.platforms[platform];
      buildCommand(interpreter, [path.join(sourceRoot, 'scripts/release/extract-node.py'), '--archive', path.join(buildRoot, '.artifacts/node', node.filename), '--output', path.join(payload, 'runtime/node'), '--platform', platform, '--version', nodeLock.version, '--sha256', node.sha256]);
      copyFileSync(path.join(sourceRoot, 'packaging/mcpb-entry.cjs'), path.join(payload, 'mcpb-entry.cjs'));
    }
    packageInventory(payload, 'native', platform, source.sha256, runtimeHash, qualification); mkdirSync(output);
    const records = [];
    for (const [extension, format] of [[suffix ? 'zip' : 'tar.gz', suffix ? 'zip' : 'tar.gz'], ['mcpb', 'zip']]) {
      const filename = `ud-agent-skill-mcp-plugin-${platform}.${extension}`;
      buildCommand(interpreter, [path.join(sourceRoot, 'scripts/release/archive-dev.py'), payload, path.join(output, filename), '--format', format]); buildCommand(interpreter, [path.join(sourceRoot, 'scripts/release/inspect-package.py'), path.join(output, filename), '--kind', 'native', '--platform', platform, '--source-sha256', source.sha256, '--runtime-sha256', runtimeHash]); records.push({ format: extension === 'mcpb' ? 'mcpb' : 'native', ...fileReceipt(output, filename) });
    }
    // Retain the very same inventoried payload, never an independently rebuilt
    // installation or a source bundle written over a tested archive.
    renameSync(payload, path.join(output, 'installation'));
    renameSync(sourceSnapshot, path.join(output, 'source-snapshot'));
    renameSync(nativeInputs, path.join(output, 'native-inputs'));
    const report = { schema_version: 1, qualification: qualification === 'local_candidate' ? 'diagnostic-original-platform-archives-not-final-candidate' : 'immutable-available-target-platform-preacceptance', production_ready: false, source_tree_sha256: source.sha256, source_snapshot: { root: 'source-snapshot', receipt: fileReceipt(output, 'source-snapshot/SOURCE-RECEIPT.json') }, native_inputs: fileReceipt(output, 'native-inputs/INPUTS.json'), source_unchanged: sourceReceipt(sourceRoot).sha256 === source.sha256, runtime_lock_sha256: runtimeHash, platform, installation: 'installation', artifacts: records };
    writeFileSync(path.join(output, 'measurement.json'), JSON.stringify(report, null, 2) + '\n'); return report;
  } finally { rmSync(temporary, { recursive: true, force: true }); }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) try {
  const args = process.argv.slice(2);
  if (args[0] === '--development-platform') {
    requireCondition(args.length === 7 && args[1] === '--runtime-tree' && args[3] === '--platform' && args[5] === '--output', 'Usage: prepare.mjs --development-platform --runtime-tree FROZEN_TREE --platform HOST --output NEW');
    console.log(JSON.stringify(preparePlatformDiagnostic(args[2], args[4], args[6])));
  } else if (args[0] === '--development-npm') {
    requireCondition(args.length === 5 && args[1] === '--runtime-tree' && args[3] === '--output', 'Usage: prepare.mjs --development-npm --runtime-tree FROZEN_TREE --output NEW');
    console.log(JSON.stringify(prepareNpmDiagnostic(args[2], args[4])));
  } else {
    if (args[0] === '--plan-materials') {
      /** @type {{collections: string[], python: string, candidate?: string, recipe?: string, sourceRoot?: string, candidateRoot?: string, runtimeRoot?: string, output?: string, diagnostic?: boolean, available?: boolean}} */
      const options = { collections: [], python }, keys = { '--candidate': 'candidate', '--recipe': 'recipe', '--source-tree': 'sourceRoot', '--candidate-root': 'candidateRoot', '--runtime-tree': 'runtimeRoot', '--output': 'output', '--collection': 'collections' };
      for (let index = 1; index < args.length; index++) {
        if (args[index] === '--diagnostic') { options.diagnostic = true; continue; }
        if (args[index] === '--available-targets') { options.available = true; continue; }
        const key = keys[args[index]]; requireCondition(key && args[index + 1], 'Invalid source-material planning argument.');
        const value = args[++index]; if (key === 'collections') options.collections.push(value); else { requireCondition(options[key] === undefined, 'Duplicate source-material planning argument.'); options[key] = path.resolve(value); }
      }
      requireCondition(options.candidate && options.recipe && options.output, 'Usage: prepare.mjs --plan-materials --candidate MANIFEST --recipe RECIPE --collection ID=RECEIPT --output NEW [--source-tree RETAINED_SOURCE] [--diagnostic]');
      console.log(JSON.stringify(planSourceMaterials(root, { ...options, candidate: options.candidate, recipe: options.recipe, output: options.output }))); process.exit(0);
    }
    const usage = 'Usage: prepare.mjs --development|--materials-provisional|--candidate [--output .artifacts/new-directory] [--transient-bytes BYTES]';
    requireCondition(['--development', '--materials-provisional', '--candidate'].includes(args[0]), usage);
    const options = new Map();
    for (let index = 1; index < args.length; index += 2) {
      const name = args[index], value = args[index + 1];
      requireCondition(['--output', '--transient-bytes'].includes(name) && value && !options.has(name), usage);
      options.set(name, value);
    }
    const transient = options.get('--transient-bytes');
    requireCondition(transient === undefined || /^\d+$/.test(transient), 'Transient byte allowance must be an integer.');
    const output = path.resolve(root, options.get('--output') ?? '.artifacts/development-candidate');
    console.log(JSON.stringify(prepare(output, { preacceptance: args[0] === '--candidate', materialsProvisional: args[0] === '--materials-provisional', transientAllowance: transient === undefined ? undefined : Number(transient) })));
  }
} catch (error) { console.error(`Development packaging failed: ${error instanceof Error ? error.message : String(error)}`); process.exitCode = 1; }
