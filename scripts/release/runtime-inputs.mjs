#!/usr/bin/env node
/** Closed installed inputs for preacceptance native-provider workflows. */
import { constants, copyFileSync, cpSync, existsSync, lstatSync, mkdirSync, readFileSync, readdirSync, realpathSync, renameSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { fileReceipt, readRecordedBytes, safeRelative, sha256, sourceReceipt, verifyRecordedFile } from './candidate.mjs';
import { canonicalJson } from './http-transports.mjs';
import { validPortablePath, portablePathKey } from './portable-policy.mjs';
import { verifyInstalledPayload } from '../quality/installed-payload.mjs';
import { closeReleaseInterpreter, releasePythonCommand, releaseVerifierReceipt, verifyReleaseInterpreter } from './verifier-runtime.mjs';
import { verifyAvailableCandidateBindings } from './available-candidate.mjs';
import { reserveStorage } from '../quality/storage-lifecycle.mjs';

import { releasePlatforms as platforms, releasePlatformIds as artifactPlatforms } from './host-adapters.mjs';
const HASH = /^[a-f0-9]{64}$/;
function insist(value, message) { if (!value) throw new Error(message); }
function directory(root, relative) {
  safeRelative(relative); let item = path.resolve(root);
  for (const part of relative.split('/')) { item = path.join(item, part); const info = lstatSync(item); insist(info.isDirectory() && !info.isSymbolicLink(), 'Candidate input directory is linked or absent.'); }
  return item;
}
function tree(root) {
  const files = [], keys = new Set(); let size = 0;
  function walk(folder, prefix = '') {
    for (const name of readdirSync(folder).sort()) {
      const relative = prefix + name, file = path.join(folder, name), info = lstatSync(file);
      insist(validPortablePath(relative) && !keys.has(portablePathKey(relative)) && !info.isSymbolicLink(), 'Candidate input path is unsafe or colliding.'); keys.add(portablePathKey(relative));
      if (info.isDirectory()) walk(file, relative + '/'); else { insist(info.isFile() && files.length < 200000, 'Candidate input contains a special file or exceeds its file bound.'); size += info.size; insist(size <= 64 * 1024 ** 3, 'Candidate input exceeds its byte bound.'); files.push(fileReceipt(root, relative)); }
    }
  }
  walk(root); return files;
}
function checkedJson(root, receipt, maximum = 32 * 1024 ** 2) { return JSON.parse(readRecordedBytes(root, { ...receipt, size: receipt.size ?? receipt.size_bytes }, maximum).toString('utf8')); }
function inspectorCommand(python, args, verifierRuntime) {
  if (verifierRuntime !== undefined) return releasePythonCommand(verifierRuntime, args);
  insist(typeof python === 'string' && path.isAbsolute(python), 'Locked original archive verifier interpreter is required.');
  return { executable: python, args: ['-I', ...args], env: { PATH: path.dirname(python), LC_ALL: 'C', ...(process.env.SystemRoot ? { SystemRoot: process.env.SystemRoot } : {}) } };
}
function inspectArchive(root, artifact, platform, source, runtime, python, diagnostic = false, verifierRuntime, format = 'native', contracts = false) {
  insist(verifierRuntime !== undefined || typeof python === 'string' && path.isAbsolute(python), 'Locked original archive verifier interpreter is required.');
  const kind = format === 'npm' ? 'npm' : 'native';
  const command = inspectorCommand(python, [fileURLToPath(new URL('./inspect-package.py', import.meta.url)), path.join(root, artifact.path), '--kind', kind, '--platform', kind === 'npm' ? 'all' : platform, '--source-sha256', source, '--runtime-sha256', runtime, ...(diagnostic ? [] : ['--require-candidate']), ...(contracts ? ['--contracts'] : [])], verifierRuntime);
  const checked = spawnSync(command.executable, command.args, { encoding: 'utf8', timeout: 300000, maxBuffer: (contracts ? 64 : 1) * 1024 ** 2, env: command.env });
  insist(!checked.error && checked.status === 0, `Original package archive rejected: ${checked.stderr}`); return JSON.parse(checked.stdout);
}
function verifyHistory(root, history) {
  insist(history && typeof history.path === 'string', 'Pinned history is required.');
  const base = directory(root, history.path), receipt = checkedJson(root, history.receipt);
  insist(receipt.schema_version === 1 && receipt.kind === 'read-only-existing-git-history' && HASH.test(receipt.inventory_sha256 ?? '') && /^[a-f0-9]{40}$/.test(receipt.commit ?? '') && /^[a-f0-9]{40}$/.test(receipt.tree_oid ?? '') && Array.isArray(receipt.files), 'Pinned history receipt is invalid.');
  const actual = tree(base); insist(canonicalJson(actual) === canonicalJson(receipt.files) && sha256(Buffer.from(canonicalJson(actual))) === receipt.inventory_sha256, 'Pinned history complete byte inventory differs.');
  const env = { PATH: process.env.PATH ?? '', LC_ALL: 'C', GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: process.platform === 'win32' ? 'NUL' : '/dev/null', GIT_NO_REPLACE_OBJECTS: '1', GIT_NO_LAZY_FETCH: '1', GIT_TERMINAL_PROMPT: '0', ...(process.env.SystemRoot ? { SystemRoot: process.env.SystemRoot } : {}) };
  for (const [expression, expected] of [[`${receipt.commit}^{commit}`, receipt.commit], [`${receipt.commit}^{tree}`, receipt.tree_oid]]) {
    const result = spawnSync('git', ['--git-dir', base, '-c', 'core.hooksPath=/dev/null', 'rev-parse', '--verify', '--end-of-options', expression], { env, encoding: 'utf8', timeout: 10000, maxBuffer: 65536 });
    insist(!result.error && result.status === 0 && result.stdout.trim() === expected, 'Pinned history object identity differs.');
  }
  return receipt;
}

function verifyAvailableScope(root, manifest) {
  insist(manifest.available_candidate && typeof manifest.available_candidate.path === 'string', 'Available-target candidate receipt is missing.');
  const available = checkedJson(root, manifest.available_candidate, 8 * 1024 ** 2), scope = available.scope;
  insist([1,2].includes(available.schema_version) && available.qualification === 'available-target-preacceptance' && available.status === 'preacceptance_candidate' && available.production_ready === false && available.material_phase === 'final' && available.source_tree_sha256 === manifest.source_sha256 && available.runtime_lock_sha256 === manifest.runtime_lock_sha256 && scope?.kind === 'available-target-subset', 'Available-target candidate scope or subjects differ.');
  insist(Array.isArray(scope.available_targets) && Array.isArray(scope.required_targets) && canonicalJson([...scope.available_targets].sort()) === canonicalJson(manifest.rows.map(row => row.platform).sort()) && new Set(scope.available_targets).size === scope.available_targets.length && canonicalJson([...scope.required_targets].sort()) === canonicalJson([...platforms].sort()), 'Available-target candidate platform scope differs.');
  insist(Array.isArray(available.installations) && available.installations.length === manifest.rows.length && Array.isArray(available.artifacts), 'Available-target candidate installations are incomplete.');
  const artifacts = new Map(available.artifacts.map(item => [item.id, item])); insist(artifacts.size === available.artifacts.length, 'Available-target candidate artifacts are duplicated.');
  for (const row of manifest.rows) {
    const matches = available.installations.filter(item => item.platform === row.platform); insist(matches.length === 1 && canonicalJson(Object.keys(matches[0].formats).sort()) === canonicalJson(Object.keys(row.formats).sort()), 'Available-target installed formats differ.');
    for (const [format, item] of Object.entries(row.formats)) { const expected=matches[0].formats[format], artifact = artifacts.get(expected.artifact_id); insist(artifact && artifact.sha256 === item.artifact.sha256 && artifact.size === item.artifact.size && artifact.platform === (format === 'npm' ? 'all' : artifactPlatforms[row.platform]), 'Available-target archive identity differs.'); if(manifest.package_paths==='available-candidate') insist(expected.root===item.root&&artifact.path===item.artifact.path,'Referenced candidate package paths differ.'); if(available.schema_version===2) insist(manifest.package_paths==='available-candidate' && item.root===undefined && item.inventory_sha256===expected.inventory_sha256 && item.build_receipt_sha256===expected.build_receipt_sha256,'Archive-backed package contract differs.'); }
  }
  const pending = scope.pending_targets; insist(Array.isArray(pending) && new Set(pending.map(row => row.platform)).size === pending.length && canonicalJson(pending.map(row => row.platform).sort()) === canonicalJson(platforms.filter(platform => !scope.available_targets.includes(platform)).sort()) && pending.every(row => typeof row.code === 'string' && typeof row.reason === 'string' && row.reason.length > 0), 'Unavailable native targets must remain explicit.');
  const candidateRoot = manifest.available_candidate_root === undefined ? directory(root, path.posix.dirname(manifest.available_candidate.path)) : manifest.available_candidate_root;
  if (manifest.available_candidate_root !== undefined) {
    insist(typeof candidateRoot === 'string' && path.isAbsolute(candidateRoot) && realpathSync(candidateRoot) === path.resolve(candidateRoot) && lstatSync(candidateRoot).isDirectory(), 'Available candidate reference is not an ordinary canonical local root.');
    const original = fileReceipt(candidateRoot, 'available-candidate.json');
    insist(original.sha256 === manifest.available_candidate.sha256 && original.size === manifest.available_candidate.size, 'Referenced available candidate manifest differs.');
  }
  const bindings = verifyAvailableCandidateBindings(candidateRoot, available);
  insist(bindings.verified === true && bindings.candidate_bindings_verified === true && bindings.material_bindings_verified === true && bindings.target_execution_eligible === true && bindings.source_replay_performed === false && bindings.source_replay_required === true && bindings.source_coverage_receipt, 'Available-target byte/material bindings are incomplete.');
  return bindings;
}

export function runtimeInputFormats(row) {
  const keys = Object.keys(row?.formats ?? {}).sort();
  insist(['mcpb,native', 'mcpb,native,npm'].includes(keys.join(',')), 'Candidate runtime formats are incomplete or unsupported.');
  return ['native', 'mcpb', ...(keys.includes('npm') ? ['npm'] : [])];
}

/** @param {string} root @param {string | undefined} selectedPlatform @param {{python?: string, allowDiagnostic?: boolean, allowAvailable?: boolean, verifierRuntime?: ReturnType<typeof verifyReleaseInterpreter>}} [options] */
export function verifyRuntimeInputs(root, selectedPlatform, { python, allowDiagnostic = false, allowAvailable = false, verifierRuntime } = {}) {
  const receipt = fileReceipt(root, 'candidate-inputs.json'), manifest = checkedJson(root, receipt);
  const diagnostic = manifest.qualification === 'diagnostic-runtime-inputs';
  const available = manifest.qualification === 'available-target-runtime-inputs';
  insist(manifest.schema_version === 1 && (manifest.qualification === 'preacceptance-runtime-inputs' || diagnostic && allowDiagnostic === true || available && allowAvailable === true) && HASH.test(manifest.source_sha256 ?? '') && HASH.test(manifest.runtime_lock_sha256 ?? '') && Array.isArray(manifest.rows) && manifest.rows.length > 0 && manifest.rows.length <= 6, 'Candidate runtime inputs are invalid or diagnostic/available authority was not explicitly selected.');
  const availableBindings = available ? verifyAvailableScope(root, manifest) : undefined;
  if (!available) insist(manifest.available_candidate === undefined && manifest.available_candidate_root === undefined, 'Available-target scope cannot be relabeled as complete or diagnostic inputs.');
  insist(manifest.package_paths === undefined || available && manifest.package_paths === 'available-candidate' && typeof manifest.available_candidate_root === 'string', 'External package references require an explicitly verified available candidate.');
  const packageRoot = manifest.package_paths === 'available-candidate' ? manifest.available_candidate_root : root;
  const seen = new Set(), requiredAssets = new Map(), vendorContracts = new Map(), inspectedRender = new Map(), archiveSizes = new Map(); let operationNames;
  const requireAsset = (descriptor, filename) => { insist(descriptor && typeof descriptor.sha256 === 'string' && /^sha256:[a-f0-9]{64}$/.test(descriptor.sha256) && Number.isSafeInteger(descriptor.size_bytes ?? descriptor.size), 'Offline asset contract is invalid.'); const value = { sha256: descriptor.sha256.slice(7), size: descriptor.size_bytes ?? descriptor.size }; const key = filename ?? path.posix.basename(descriptor.path ?? new URL(descriptor.url).pathname); insist(!requiredAssets.has(key) || canonicalJson(requiredAssets.get(key)) === canonicalJson(value), 'Offline asset identities conflict.'); requiredAssets.set(key, value); };
  for (const row of manifest.rows) {
    insist(platforms.includes(row.platform) && !seen.has(row.platform), 'Candidate runtime platform is absent or duplicated.'); seen.add(row.platform);
    for (const format of runtimeInputFormats(row)) {
      const item = row.formats[format];
      const archiveBacked = item.root === undefined;
      insist(!archiveBacked || available && manifest.package_paths === 'available-candidate', 'Archive-only inputs require an explicit available candidate.');
      const installation = archiveBacked ? undefined : directory(packageRoot, item.root); verifyRecordedFile(packageRoot, item.artifact);
      const archive = inspectArchive(packageRoot, item.artifact, row.platform, manifest.source_sha256, manifest.runtime_lock_sha256, python, diagnostic, verifierRuntime, format, archiveBacked);
      insist(Number.isSafeInteger(archive.expanded_size) && archive.expanded_size > 0, 'Original archive lacks a bounded expanded-size inventory.');
      archiveSizes.set(row.platform + ':' + format, archive.expanded_size);
      const contract = archive.contracts, metadata = contract?.metadata, members = contract?.members;
      const verified = archiveBacked ? { source_tree_sha256: metadata?.['BUILD-RECEIPT.json']?.source_tree_sha256, runtime_lock_sha256: metadata?.['BUILD-RECEIPT.json']?.runtime_lock_sha256, inventory_sha256: archive.inventory_sha256 } : verifyInstalledPayload(installation);
      const build = archiveBacked ? metadata?.['BUILD-RECEIPT.json'] : JSON.parse(readFileSync(path.join(installation, 'BUILD-RECEIPT.json'), 'utf8'));
      const markerOk = archiveBacked ? contract?.release_candidate === !diagnostic && contract?.unaccepted === diagnostic : existsSync(path.join(installation, diagnostic ? 'UNACCEPTED.md' : 'RELEASE-CANDIDATE.md')) && !existsSync(path.join(installation, diagnostic ? 'RELEASE-CANDIDATE.md' : 'UNACCEPTED.md'));
      insist(build?.qualification === (diagnostic ? 'local_candidate' : 'preacceptance_candidate') && build.kind === (format === 'npm' ? 'npm' : 'native') && build.platform === (format === 'npm' ? 'all' : row.platform) && markerOk, 'Runtime inputs were not assembled before acceptance.');
      insist(item.source_sha256 === manifest.source_sha256 && verified.source_tree_sha256 === manifest.source_sha256 && item.runtime_lock_sha256 === manifest.runtime_lock_sha256 && verified.runtime_lock_sha256 === manifest.runtime_lock_sha256 && verified.inventory_sha256 === item.inventory_sha256 && (archiveBacked ? members?.['BUILD-RECEIPT.json']?.sha256 : fileReceipt(installation, 'BUILD-RECEIPT.json').sha256) === item.build_receipt_sha256, 'Runtime input package subjects differ.');
      const catalogBody = archiveBacked ? metadata?.['contracts/ud-interfaces.json'] : JSON.parse(readFileSync(path.join(installation, 'contracts/ud-interfaces.json'), 'utf8'));
      insist(Array.isArray(catalogBody), 'Installed operation catalog is missing.'); const catalog = catalogBody.map(item => item.name).sort();
      insist(catalog.length === 102 && (!operationNames || canonicalJson(operationNames) === canonicalJson(catalog)), 'Installed operation catalogs differ.'); operationNames = catalog;
      insist(item.archive_inventory_sha256 === item.inventory_sha256 && item.archive_build_receipt_sha256 === item.build_receipt_sha256, 'Runtime archive and installed payload identities differ.');
      insist(archive.inventory_sha256 === item.inventory_sha256 && archive.build_receipt_sha256 === item.build_receipt_sha256, 'Actual immutable archive differs from the workflow installation.');
      insist(format !== 'mcpb' || item.artifact.path.endsWith('.mcpb'), 'MCPB archive has a wrong format.');
      insist(format !== 'npm' || item.artifact.path.endsWith('.tgz'), 'npm archive has a wrong format.');
      const runtime = archiveBacked ? metadata?.['runtime/runtime.lock.json'] : JSON.parse(readFileSync(path.join(installation, 'runtime/runtime.lock.json'), 'utf8')), host = row.platform.replace('-', '/'), worker = row.platform.endsWith('arm64') ? 'linux/arm64' : 'linux/amd64';
      insist(runtime && typeof runtime === 'object', 'Package runtime lock is missing.');
      if (row.platform.startsWith('win32-') && format !== 'npm') {
        const vendorNode = archiveBacked ? metadata?.['runtime/windows-node.json'] : JSON.parse(readFileSync(path.join(installation, 'runtime/windows-node.json'), 'utf8'));
        insist(vendorNode, 'Windows native package lacks pinned vendor Node.');
        requireAsset(vendorNode, `node-${vendorNode.sha256.slice(7)}.exe`);
      }
      for (const pack of Object.values(runtime.packs ?? {})) { const image = pack.images?.[worker]; insist(image && Array.isArray(image.transports) && image.transports.length > 0, `Pending native build: current ${worker} worker is absent.`); for (const transport of image.transports) requireAsset(transport); }
      for (const [name, provider] of Object.entries(runtime.provider_receipts ?? {})) if (name.endsWith('/' + host) && provider.lazy_assets) requireAsset(provider.lazy_assets);
      if (runtime.userspace_sha256) {
        const userspace = archiveBacked ? metadata?.['runtime/userspace.lock.json'] : JSON.parse(readFileSync(path.join(installation, 'runtime/userspace.lock.json'), 'utf8')), selected = userspace?.platforms?.[host]; insist(selected, `Pending native build: userspace dependency record is absent for ${host}.`);
        const userspaceReceipt = archiveBacked ? members?.['runtime/userspace.lock.json'] : fileReceipt(installation, 'runtime/userspace.lock.json');
        insist('sha256:' + userspaceReceipt?.sha256 === runtime.userspace_sha256, 'Package userspace lock identity differs.');
        for (const key of ['lazy_core', 'lazy_render', 'uv_download', 'uv_vendor_download', 'python_download']) if (selected[key]) requireAsset(selected[key]);
        if (selected.perl?.deferred_runtime) {
          const file = selected.perl.deferred_runtime.recipe, bound = selected.files.filter(entry => entry.path === file);
          insist(validPortablePath(file) && bound.length === 1, 'Vendor Perl recipe is not inventory-bound.');
          const vendorKey = 'perl-vendor:' + host;
          if (format === 'npm' && selected.lazy_core) {
            // The thin npm package references the same closed core file
            // inventory as the already inspected native archive and MCPB.
            const native = vendorContracts.get(vendorKey);
            insist(native && 'sha256:' + native.recipe_sha256 === bound[0].sha256 && native.recipe_size === bound[0].size, 'Lazy npm Perl recipe differs from the verified native payload.');
          } else {
            const actual = archiveBacked ? members?.[file] : fileReceipt(installation, file);
            insist(actual && 'sha256:' + actual.sha256 === bound[0].sha256 && actual.size === bound[0].size && actual.size <= 4 * 1024 ** 2, 'Vendor Perl recipe bytes differ.');
            const value = archiveBacked ? metadata?.[file] : JSON.parse(readRecordedBytes(installation, actual, 4 * 1024 ** 2).toString('utf8'));
            insist(value?.schema_version === 1 && value.provider === 'conda-vc-runtime' && value.platform === host, 'Vendor Perl recipe authority differs.');
            for (const [role, descriptor] of [['perl-vendor', value.archive], ...(value.supplier === undefined ? [] : [['perl-supplier', value.supplier?.archive]])]) {
              const archiveFormat = typeof descriptor?.url === 'string' ? descriptor.url.match(/\.(conda|tar\.bz2)$/)?.[1] : undefined;
              insist(archiveFormat && (role !== 'perl-vendor' || archiveFormat === 'conda') && HASH.test(descriptor.sha256 ?? '') && Number.isSafeInteger(descriptor.size_bytes) && descriptor.size_bytes > 0, 'Vendor Perl archive identity is invalid.');
              const key = role + ':' + host, contract = { archive: descriptor, recipe_sha256: actual.sha256, recipe_size: actual.size, archive_format: archiveFormat }, previous = vendorContracts.get(key);
              insist(!previous || canonicalJson(previous) === canonicalJson(contract), 'Vendor Perl recipe differs between package formats.');
              vendorContracts.set(key, contract);
            }
          }
        }
        if (selected.lazy_render) {
          const descriptor = selected.lazy_render;
          if (!inspectedRender.has(descriptor.sha256)) {
            const assets = (manifest.offline_assets ?? []).filter(row => row.sha256 === descriptor.sha256.slice(7) && row.size_bytes === descriptor.size); insist(assets.length === 1, 'Vendor render base archive is missing or ambiguous.'); const asset = verifyRecordedFile(root, { ...assets[0], size: assets[0].size_bytes });
            const command = inspectorCommand(python, [fileURLToPath(new URL('./inspect-runtime-vendor.py', import.meta.url)), '--archive', path.join(root, asset.path), '--manifest', descriptor.manifest], verifierRuntime);
            const result = spawnSync(command.executable, command.args, { encoding: 'utf8', timeout: 120000, maxBuffer: 1024 ** 2, env: command.env }); insist(!result.error && result.status === 0, `Vendor base recipe verification failed: ${result.stderr}`); inspectedRender.set(descriptor.sha256, JSON.parse(result.stdout));
          }
          const value = inspectedRender.get(descriptor.sha256);
          if (value) { insist(value.platform === host && ['google-chrome-for-testing', 'microsoft-edge'].includes(value.provider), 'Vendor render recipe platform differs.'); vendorContracts.set('render-vendor:' + host, { archive: value.archive, recipe_sha256: value.recipe_sha256, archive_format: value.provider === 'google-chrome-for-testing' ? 'zip' : 'msi' }); }
        }
      }
    }
  }
  insist(Array.isArray(manifest.offline_assets), 'Candidate offline acquisition assets are missing.');
  const supplied = new Map(), assetKeys = new Set();
  const suppliedVendors = new Set();
  for (const asset of manifest.offline_assets) {
    insist(validPortablePath(asset.path) && !assetKeys.has(portablePathKey(asset.path)), 'Offline asset paths collide.'); assetKeys.add(portablePathKey(asset.path)); const actual = verifyRecordedFile(root, { ...asset, size: asset.size_bytes }); const name = path.posix.basename(asset.path); insist(!supplied.has(name), 'Offline asset filenames collide.'); supplied.set(name, { sha256: actual.sha256, size: actual.size });
    if (asset.cache_role !== undefined) {
      const key = asset.cache_role + ':' + asset.platform, expected = vendorContracts.get(key); insist(expected && !suppliedVendors.has(key) && asset.recipe_sha256 === expected.recipe_sha256 && asset.archive_format === expected.archive_format && asset.sha256 === expected.archive.sha256 && asset.size_bytes === expected.archive.size_bytes, 'Vendor offline asset is not authorized by its exact recipe.'); suppliedVendors.add(key);
    } else insist(asset.platform === undefined && asset.recipe_sha256 === undefined && asset.archive_format === undefined, 'Offline asset has unbound vendor routing metadata.');
  }
  for (const [name, expected] of requiredAssets) insist([...supplied.values()].some(value => canonicalJson(value) === canonicalJson(expected)), `Offline acquisition asset is missing or stale: ${name}`);
  for (const key of vendorContracts.keys()) insist(suppliedVendors.has(key), `Offline vendor acquisition asset is missing: ${key}`);
  const fixtures = checkedJson(root, manifest.fixtures);
  insist(fixtures.schema_version === 1 && fixtures.scheduled_operations === 102 && Array.isArray(fixtures.cases) && fixtures.cases.length === 102 && canonicalJson(fixtures.cases.map(item => item.operation).sort()) === canonicalJson(operationNames), 'Closed operation fixture inventory differs.');
  verifyHistory(root, manifest.git_history);
  const admitted = verifierRuntime === undefined ? undefined : releaseVerifierReceipt(verifierRuntime);
  if (selectedPlatform !== undefined) { insist(platforms.includes(selectedPlatform) && seen.has(selectedPlatform), `Pending native build: candidate runtime inputs unavailable for ${selectedPlatform}`); const selected = manifest.rows.find(row => row.platform === selectedPlatform); return { ...selected, ...(manifest.package_paths ? { package_root: packageRoot } : {}), operation_names: operationNames, archive_expanded_sizes: Object.fromEntries(Object.keys(selected.formats).map(format => [format, archiveSizes.get(selectedPlatform + ':' + format)])), candidate: manifest, candidate_receipt: receipt, ...(availableBindings ? { available_bindings: availableBindings } : {}), ...(admitted ? { verifier_runtime: admitted } : {}) }; }
  return { ...manifest, candidate_receipt: receipt, ...(availableBindings ? { available_bindings: availableBindings } : {}), ...(admitted ? { verifier_runtime: admitted } : {}) };
}

/** Copy only installed inputs; available verification references its original immutable candidate. */
/** @param {string} sourceRoot @param {any} recipe @param {string} output @param {{python?: string, diagnostic?: boolean, available?: boolean, supportRoot?: string, verifierRuntime?: ReturnType<typeof verifyReleaseInterpreter>, referencePackages?: boolean}} [options] */
export function prepareRuntimeInputs(sourceRoot, recipe, output, { python, diagnostic = false, available = false, supportRoot, verifierRuntime, referencePackages = available } = {}) {
  sourceRoot = realpathSync(sourceRoot); output = path.join(realpathSync(path.dirname(path.resolve(output))), path.basename(output));
  if (supportRoot !== undefined) supportRoot = realpathSync(supportRoot);
  insist(!existsSync(output) && path.resolve(output) !== sourceRoot, 'Runtime input output must be a new directory.');
  insist(recipe.schema_version === 1 && Array.isArray(recipe.rows) && recipe.rows.length > 0 && recipe.rows.length <= 6, 'Runtime input producer recipe is invalid.');
  insist(typeof python === 'string' && path.isAbsolute(python), 'Locked original archive verifier interpreter is required.');
  insist(!(diagnostic && available) && (available || recipe.available_candidate === undefined), 'Available-target scope requires its explicit producer mode.');
  insist(!referencePackages || available, 'Package references require an explicitly verified available candidate.');
  if (available) insist(recipe.available_candidate?.path === 'available-candidate.json' && !output.startsWith(sourceRoot + path.sep), 'Available-target inputs require a closed candidate root and a separate output directory.');
  let availableCandidate;
  if (available) { verifyRecordedFile(sourceRoot, recipe.available_candidate); availableCandidate=checkedJson(sourceRoot,recipe.available_candidate,8 * 1024 ** 2); verifyAvailableCandidateBindings(sourceRoot,availableCandidate); }
  const archiveBacked = availableCandidate?.schema_version === 2;
  insist(!archiveBacked || referencePackages, 'Archive-backed candidates require references to the verified original packages.');
  const origin = item => { insist(item.input_root === undefined || item.input_root === 'support' && supportRoot !== undefined, 'Supplemental input requires its explicit support root.'); return item.input_root === 'support' ? supportRoot : sourceRoot; };
  const sources = new Map(), artifacts = new Map();
  const plannedRows = recipe.rows.map(row => {
    insist(platforms.includes(row.platform), 'Runtime input platform is invalid.');
    const formats = {};
    for (const format of runtimeInputFormats(row)) {
      const item = row.formats[format], original = archiveBacked ? undefined : directory(sourceRoot, item.root), artifact = verifyRecordedFile(sourceRoot, item.artifact);
      if (original && !sources.has(original)) sources.set(original, tree(original));
      const contract = archiveBacked ? availableCandidate.installations.find(value=>value.platform===row.platform)?.formats?.[format] : undefined;
      if (archiveBacked) insist(contract && item.root===undefined && availableCandidate.artifacts.some(value=>value.id===contract.artifact_id && value.path===artifact.path && value.sha256===artifact.sha256 && value.size===artifact.size), 'Archive-backed recipe does not reference its candidate package.');
      artifacts.set(artifact.path, artifact); formats[format] = { item, original, artifact, contract };
    }
    return { ...row, formats };
  });
  insist(Array.isArray(recipe.offline_assets) && recipe.offline_assets.length <= 2000, 'Offline acquisition asset producer inventory is required.');
  const offline = recipe.offline_assets.map(item => ({ item, root: origin(item), original: verifyRecordedFile(origin(item), { ...item, size: item.size_bytes }) }));
  const fixtureRoot = origin(recipe.fixtures), fixture = verifyRecordedFile(fixtureRoot, { ...recipe.fixtures, size: recipe.fixtures.size ?? recipe.fixtures.size_bytes });
  const historyRoot = origin(recipe.git_history), history = verifyHistory(historyRoot, recipe.git_history), historyDirectory = directory(historyRoot, recipe.git_history.path);
  const expandedBytes = referencePackages ? 0 : available ? [...sources.values()].flat().reduce((sum, row) => sum + row.size, 0) : plannedRows.reduce((sum, row) => sum + Object.values(row.formats).reduce((total, value) => total + sources.get(value.original).reduce((size, item) => size + item.size, 0), 0), 0);
  const plannedBytes = expandedBytes + (referencePackages ? 0 : [...artifacts.values()].reduce((sum, row) => sum + row.size, 0)) + offline.reduce((sum, row) => sum + row.original.size, 0) + fixture.size + history.files.reduce((sum, row) => sum + row.size, 0) + 4 * 1024 ** 2;
  const parts = sourceRoot.split(path.sep), artifactIndex = parts.indexOf('.artifacts');
  const storageRoot = process.env.UD_AGENT_STORAGE_ROOT ?? (artifactIndex < 0 ? sourceRoot : parts.slice(0, artifactIndex).join(path.sep) || path.sep);
  const storage = reserveStorage({ root: storageRoot, plannedBytes, profile: 'release', inputRoots: [...sources.keys(), historyDirectory, ...(supportRoot ? [supportRoot] : [])], scratchParent: path.dirname(output), label: 'installed-runtime-inputs' });
  const targetRoot = path.join(storage.directory, 'inputs'); mkdirSync(targetRoot, { mode: 0o700 });
  const result = { schema_version: 1, qualification: available ? 'available-target-runtime-inputs' : diagnostic ? 'diagnostic-runtime-inputs' : 'preacceptance-runtime-inputs', source_sha256: recipe.source_sha256, runtime_lock_sha256: recipe.runtime_lock_sha256, rows: [], offline_assets: [], fixtures: null, git_history: null };
  try {
    if (available) {
      mkdirSync(path.join(targetRoot, 'available-candidate'));
      copyFileSync(path.join(sourceRoot, recipe.available_candidate.path), path.join(targetRoot, 'available-candidate/available-candidate.json'), constants.COPYFILE_EXCL);
      result.available_candidate = fileReceipt(targetRoot, 'available-candidate/available-candidate.json'); result.available_candidate_root = sourceRoot; if(referencePackages) result.package_paths='available-candidate';
    }
    const copied = new Map(), payloads = new Map(), archiveChecks = new Map();
    for (const row of plannedRows) {
      const formats = {};
      for (const [format, value] of Object.entries(row.formats)) {
        const { original, artifact } = value;
        const archiveKey = format + ':' + (format === 'npm' ? 'all' : row.platform) + ':' + artifact.sha256;
        if (!archiveChecks.has(archiveKey)) archiveChecks.set(archiveKey, inspectArchive(sourceRoot, artifact, row.platform, recipe.source_sha256, recipe.runtime_lock_sha256, python, diagnostic, verifierRuntime, format));
        const archive = archiveChecks.get(archiveKey);
        if(referencePackages){
          const inventory=archiveBacked?value.contract.inventory_sha256:fileReceipt(original,'PACKAGE-INVENTORY.json').sha256,build=archiveBacked?value.contract.build_receipt_sha256:fileReceipt(original,'BUILD-RECEIPT.json').sha256;
          insist(archive.inventory_sha256===inventory && archive.build_receipt_sha256===build,'Original archive contract differs from candidate.');
          formats[format]={...(archiveBacked?{}:{root:value.item.root}),artifact,source_sha256:recipe.source_sha256,runtime_lock_sha256:recipe.runtime_lock_sha256,inventory_sha256:inventory,build_receipt_sha256:build,archive_inventory_sha256:archive.inventory_sha256,archive_build_receipt_sha256:archive.build_receipt_sha256};
          continue;
        }
        const copyKey = available ? original : row.platform + ':' + format;
        if (!copied.has(copyKey)) {
          const relative = `installations/${row.platform}/${format}`, target = path.join(targetRoot, relative); mkdirSync(path.dirname(target), { recursive: true });
          cpSync(original, target, { recursive: true, dereference: false, errorOnExist: true, force: false, mode: constants.COPYFILE_FICLONE }); copied.set(copyKey, relative);
        }
        const relative = copied.get(copyKey), target = path.join(targetRoot, relative), artifactPath = `artifacts/${path.basename(artifact.path)}`;
        mkdirSync(path.join(targetRoot, 'artifacts'), { recursive: true });
        if (existsSync(path.join(targetRoot, artifactPath))) { const held = fileReceipt(targetRoot, artifactPath); insist(held.sha256 === artifact.sha256 && held.size === artifact.size, 'Candidate artifacts collide.'); }
        else copyFileSync(path.join(sourceRoot, artifact.path), path.join(targetRoot, artifactPath), constants.COPYFILE_FICLONE | constants.COPYFILE_EXCL);
        payloads.set(artifact.sha256 + ':' + artifact.size, artifactPath);
        formats[format] = { root: relative, artifact: fileReceipt(targetRoot, artifactPath), source_sha256: recipe.source_sha256, runtime_lock_sha256: recipe.runtime_lock_sha256, inventory_sha256: fileReceipt(target, 'PACKAGE-INVENTORY.json').sha256, build_receipt_sha256: fileReceipt(target, 'BUILD-RECEIPT.json').sha256, archive_inventory_sha256: archive.inventory_sha256, archive_build_receipt_sha256: archive.build_receipt_sha256 };
        storage.check();
      }
      result.rows.push({ platform: row.platform, formats });
    }
    const offlinePaths = new Set();
    for (const { item, root, original } of offline) {
      const key = original.sha256 + ':' + original.size;
      let relative = available ? payloads.get(key) : undefined;
      if (relative === undefined || offlinePaths.has(relative)) {
        relative = `offline-assets/${safeRelative(item.path)}`; const target = path.join(targetRoot, relative); insist(!existsSync(target), 'Offline assets collide.'); mkdirSync(path.dirname(target), { recursive: true }); copyFileSync(path.join(root, item.path), target, constants.COPYFILE_FICLONE | constants.COPYFILE_EXCL);
      }
      offlinePaths.add(relative); result.offline_assets.push({ path: relative, sha256: original.sha256, size_bytes: original.size, ...(item.cache_role === undefined ? {} : { cache_role: item.cache_role, platform: item.platform, recipe_sha256: item.recipe_sha256, archive_format: item.archive_format }) }); storage.check();
    }
    mkdirSync(path.join(targetRoot, 'fixtures')); copyFileSync(path.join(fixtureRoot, fixture.path), path.join(targetRoot, 'fixtures/operation-cases.json'), constants.COPYFILE_EXCL); result.fixtures = { ...fileReceipt(targetRoot, 'fixtures/operation-cases.json'), size_bytes: fixture.size };
    cpSync(historyDirectory, path.join(targetRoot, 'git-history'), { recursive: true, dereference: false, force: false });
    writeFileSync(path.join(targetRoot, 'git-history-receipt.json'), canonicalJson(history) + '\n'); result.git_history = { path: 'git-history', receipt: fileReceipt(targetRoot, 'git-history-receipt.json') };
    writeFileSync(path.join(targetRoot, 'candidate-inputs.json'), JSON.stringify(result, null, 2) + '\n'); storage.check();
    const checked = verifyRuntimeInputs(targetRoot, undefined, { python, verifierRuntime, allowDiagnostic: diagnostic, allowAvailable: available });
    renameSync(targetRoot, output); return { ...checked, candidate_receipt: fileReceipt(output, 'candidate-inputs.json') };
  } finally { storage.cleanup(); }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  let verifierRuntime;
  try {
    const [mode, root, file, output, python] = process.argv.slice(2), verifying = ['--verify', '--verify-diagnostic', '--verify-available'].includes(mode), available = ['--prepare-available', '--verify-available'].includes(mode);
    if (available) { const verifierRoot = fileURLToPath(new URL('../../', import.meta.url)); verifierRuntime = verifyReleaseInterpreter(verifierRoot, sourceReceipt(verifierRoot), { python: verifying ? output : python }); }
    if (verifying) console.log(JSON.stringify(verifyRuntimeInputs(path.resolve(root), file, { python: output, verifierRuntime, allowDiagnostic: mode === '--verify-diagnostic', allowAvailable: available })));
    else { insist(['--prepare', '--prepare-diagnostic', '--prepare-available'].includes(mode) && output && python, 'Usage: runtime-inputs.mjs --prepare[-diagnostic|-available] ROOT RECIPE NEW_OUTPUT LOCKED_PYTHON | --verify[-diagnostic|-available] INPUTS PLATFORM LOCKED_PYTHON'); console.log(JSON.stringify(prepareRuntimeInputs(path.resolve(root), JSON.parse(readFileSync(file, 'utf8')), path.resolve(output), { python, verifierRuntime, diagnostic: mode === '--prepare-diagnostic', available }))); }
  } catch (error) { console.error(error.message); process.exitCode = 1; } finally { if (verifierRuntime) closeReleaseInterpreter(verifierRuntime); }
}
