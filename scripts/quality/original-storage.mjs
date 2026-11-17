/** Private, bounded inputs for ordinary original-test execution. MIT. */
import { constants, cpSync, existsSync, lstatSync, readFileSync, readdirSync, realpathSync, openSync, readSync, closeSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonicalJson } from '../release/http-transports.mjs';
import { lockedDockerImages, inspectOwnedDockerStorage } from './docker-owned-storage.mjs';
import { localDockerAuthority } from './mutation-scope.mjs';
import { isNodeDependencyInput, nodeDependencyInventory, validateNodeTargetPackages } from './node-dependencies.mjs';

const CLIENT_IMAGE_LABEL = 'io.github.mehmetoguzderin.ud-agent.local-eval';
const IMAGE_DIGEST = /^sha256:[a-f0-9]{64}$/;
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const requireArchive = (condition, reason) => { if (!condition) throw new Error(`Local evaluation image archive: ${reason}.`); };

/** Pure validation; callers separately establish private file bytes and daemon state. */
export function validateLocalEvaluationImageArchive(record, { receipt, receiptSha256, ancestry, archiveSha256, archiveSize } = {}) {
  const before = record?.before_inspection, verified = record?.verified_reload, validation = record?.archive_validation;
  requireArchive(record?.schema_version === 1 && record.kind === 'verified-local-eval-client-image-archive' && record.inference === false &&
    record.image_id === receipt?.image_id && IMAGE_DIGEST.test(record.image_id ?? '') && record.original_receipt_sha256 === receiptSha256, 'build receipt identity differs');
  requireArchive(typeof record.created_at === 'string' && Number.isFinite(Date.parse(record.created_at)) && record.archive?.sha256 === archiveSha256 && /^[a-f0-9]{64}$/.test(archiveSha256 ?? '') && record.archive.size_bytes === archiveSize && Number.isSafeInteger(archiveSize) && archiveSize > 0, 'archive byte identity differs');
  const root = ancestry?.images?.[0];
  requireArchive(before?.Id === receipt.image_id && before.Architecture === 'arm64' && before.Os === 'linux' && before.Config?.Labels?.[CLIENT_IMAGE_LABEL] === receipt.created_by && before.Size === root?.size_bytes && (before.Parent ?? '') === root?.parent, 'original inspection differs');
  requireArchive(Array.isArray(before.RootFS?.Layers) && before.RootFS.Layers.length > 0 && before.RootFS.Layers.every(value => IMAGE_DIGEST.test(value)), 'root filesystem identity absent');
  requireArchive(verified?.image_id === receipt.image_id && verified.architecture === 'arm64' && verified.os === 'linux' && verified.owner === receipt.created_by && verified.cleanup_verified === true && verified.exit_code === 0 && verified.archive_sha256 === archiveSha256, 'verified reload absent');
  requireArchive(validation?.kind === 'verified-docker-or-oci-save' && validation.archive_sha256 === archiveSha256 && validation.image_id === receipt.image_id && validation.identity_digest === receipt.image_id && ['docker-config','oci-manifest','oci-index'].includes(validation.identity_kind) && validation.layers_verified === true && validation.architecture === 'arm64' && validation.os === 'linux' && validation.owner === receipt.created_by && IMAGE_DIGEST.test(validation.config_digest ?? '') && IMAGE_DIGEST.test(validation.manifest_digest ?? ''), 'archive manifest/config verification absent');
  if (validation.identity_kind === 'docker-config') requireArchive(validation.config_digest === receipt.image_id, 'Docker config identity differs');
  else requireArchive(validation.manifest_digest === receipt.image_id && before.Descriptor?.digest === receipt.image_id, 'OCI descriptor identity differs');
  requireArchive(canonicalJson(validation.diff_ids) === canonicalJson(before.RootFS.Layers) && Array.isArray(validation.layers) && validation.layers.length === validation.diff_ids.length && validation.layers.every((layer, index) => layer.index === index && layer.diff_id === validation.diff_ids[index] && IMAGE_DIGEST.test(layer.blob_digest ?? '') && typeof layer.path === 'string' && !path.posix.isAbsolute(layer.path) && !layer.path.split('/').includes('..') && Number.isSafeInteger(layer.uncompressed_bytes) && layer.uncompressed_bytes > 0), 'archive layer verification differs');
  requireArchive(Number.isSafeInteger(validation.layers.reduce((sum, layer) => sum + layer.uncompressed_bytes, 0)), 'archive layer total is invalid');
  return { image_id: receipt.image_id, archive: { ...record.archive }, before_inspection: before, verification: validation };
}

function privateArchiveFile(root, file, { immutable = false } = {}) {
  requireArchive(path.isAbsolute(file) && file.startsWith(path.join(root, '.artifacts/local-evals') + path.sep) && realpathSync(file) === file, 'archive path escapes owned storage');
  const info = lstatSync(file);
  requireArchive(info.isFile() && !info.isSymbolicLink() && info.nlink === 1 && (process.getuid === undefined || info.uid === process.getuid()) && !(info.mode & 0o077) && (!immutable || !(info.mode & 0o222)), 'archive file is not private and immutable');
  return info;
}

/** Verify the immutable archive itself, not merely a claim that load succeeded. */
export function readLocalEvaluationImageArchive(root, id) {
  requireArchive(typeof id === 'string' && /^[a-z0-9-]+$/.test(id), 'client name invalid');
  const directory = path.join(root, '.artifacts/local-evals/client-images', id), file = path.join(directory, 'archive-availability.json');
  if (!existsSync(file)) return undefined;
  privateArchiveFile(root, file, { immutable: true });
  const record = JSON.parse(readFileSync(file, 'utf8')), receiptBytes = readFileSync(path.join(directory, 'receipt.json')),
    receipt = JSON.parse(receiptBytes), ancestry = JSON.parse(readFileSync(path.join(directory, 'ancestry.json'), 'utf8'));
  requireArchive(typeof record.archive?.path === 'string' && !path.isAbsolute(record.archive.path) && !record.archive.path.split(/[\\/]/).includes('..'), 'archive path invalid');
  const archive = path.resolve(root, record.archive.path), info = privateArchiveFile(root, archive, { immutable: true });
  const handle = openSync(archive, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0)), hash = createHash('sha256'), buffer = Buffer.alloc(1024 * 1024);
  try { for (;;) { const count = readSync(handle, buffer, 0, buffer.length, null); if (!count) break; hash.update(buffer.subarray(0, count)); } } finally { closeSync(handle); }
  const after = lstatSync(archive);
  requireArchive(after.dev === info.dev && after.ino === info.ino && after.size === info.size && after.mtimeMs === info.mtimeMs && after.ctimeMs === info.ctimeMs, 'archive changed during verification');
  return validateLocalEvaluationImageArchive(record, { receipt, receiptSha256: sha256(receiptBytes), ancestry, archiveSha256: hash.digest('hex'), archiveSize: info.size });
}

/** Exact daemon absence plus a verified archive means unavailable, never admitted. */
export function localEvaluationImageAvailability(root, id, docker) {
  const receipt = JSON.parse(readFileSync(path.join(root, '.artifacts/local-evals/client-images', id, 'receipt.json'), 'utf8'));
  try {
    const images = JSON.parse(docker(['image', 'inspect', receipt.image_id])), image = images?.length === 1 ? images[0] : undefined;
    requireArchive(image?.Id === receipt.image_id && image.Architecture === 'arm64' && image.Os === 'linux' && image.Config?.Labels?.[CLIENT_IMAGE_LABEL] === receipt.created_by, 'live client identity differs');
    return { status: 'available', image_id: receipt.image_id, inspection: image };
  } catch (error) {
    if (error?.code !== 'UD_IMAGE_ABSENT' || error.imageId !== receipt.image_id) throw error;
    const archive = readLocalEvaluationImageArchive(root, id);
    if (!archive) throw error;
    return { status: 'archived-unavailable', image_id: receipt.image_id, archive };
  }
}

export function inspectLocalEvaluationImageAvailability(root, id, environment = process.env, run = spawnSync) {
  const docker = args => {
    const result = run('docker', args, { env: environment, encoding: 'utf8', timeout: 10_000, maxBuffer: 4 * 1024 ** 2 });
    if (result.error || result.status !== 0) {
      if (!result.error && result.status === 1 && args.length === 3 && args[0] === 'image' && args[1] === 'inspect' && result.stderr?.trim() === `Error response from daemon: No such image: ${args[2]}`) throw Object.assign(new Error(`Docker image is absent: ${args[2]}`), { code: 'UD_IMAGE_ABSENT', imageId: args[2] });
      throw new Error('Local evaluation image availability cannot inspect the local Docker engine: ' + (result.error?.message ?? result.stderr ?? result.status));
    }
    return result.stdout;
  };
  localDockerAuthority(environment, context => docker(['context', 'inspect', '--format', '{{.Endpoints.docker.Host}}', ...(context ? [context] : [])]).trim());
  return localEvaluationImageAvailability(root, id, docker);
}

/**
 * A fresh checkout with no artifact history has not created resources through
 * this checkout. These native jobs do not create engine resources before the
 * original tests; the ARM mutation job inherits its inspected allowance.
 * A checkout with any prior artifacts must reconcile its engine instead.
 */
function freshNativeJob(root, environment) {
  if (environment.DOCKER_HOST || environment.DOCKER_CONTEXT) return false;
  const hosted = environment.GITHUB_ACTIONS === 'true';
  if (hosted && (environment.RUNNER_ENVIRONMENT !== 'github-hosted' || !['native', 'node24'].includes(environment.GITHUB_JOB ?? '') || !/^[1-9][0-9]*$/.test(environment.GITHUB_RUN_ID ?? '') || !/^[1-9][0-9]*$/.test(environment.GITHUB_RUN_ATTEMPT ?? '') || !environment.GITHUB_WORKSPACE)) return false;
  if (!hosted && (environment.GITHUB_ACTIONS || environment.RUNNER_ENVIRONMENT || environment.GITHUB_JOB || environment.GITHUB_RUN_ID || environment.GITHUB_RUN_ATTEMPT)) return false;
  try {
    if (hosted && realpathSync(root) !== realpathSync(environment.GITHUB_WORKSPACE)) return false;
    const artifacts = path.join(root, '.artifacts');
    if (!existsSync(artifacts)) return true;
    const info = lstatSync(artifacts);
    return info.isDirectory() && !info.isSymbolicLink() && readdirSync(artifacts).length === 0;
  } catch { return false; }
}

/** Copy the selected locked QA dependency tree, never share writable modules. */
export function copyOriginalDependencies(sourceRoot, destination) {
  const selected = path.join(sourceRoot, 'node_modules');
  if (!existsSync(selected) || lstatSync(selected).isSymbolicLink()) throw new Error('Original tests require an ordinary locked Node dependency directory.');
  const before = nodeDependencyInventory(selected);
  const report = /** @type {any} */ (process.report.getReport());
  const libc = process.platform === 'linux' ? (report.header.glibcVersionRuntime ? 'glibc' : 'musl') : undefined;
  validateNodeTargetPackages(selected, JSON.parse(readFileSync(path.join(sourceRoot, 'package-lock.json'), 'utf8')), { os: process.platform, cpu: process.arch, libc });
  // Vitest's top-level transform cache is generated data, not a locked
  // dependency. Its contents can be much larger than the packages themselves
  // and are not needed in an isolated test workspace.
  cpSync(selected, destination, { recursive: true, dereference: false, verbatimSymlinks: true, errorOnExist: true, force: false, mode: constants.COPYFILE_FICLONE, filter: source => isNodeDependencyInput(selected, source) });
  if (canonicalJson(nodeDependencyInventory(destination)) !== canonicalJson(before) || canonicalJson(nodeDependencyInventory(selected)) !== canonicalJson(before)) throw new Error('Original-test Node dependencies changed during the private copy.');
  return before;
}

/** Count owned local engine resources without changing or pruning them. */
export function originalDockerBytes(root, environment = process.env, run = spawnSync) {
  const docker = args => {
    const result = run('docker', args, { env: environment, encoding: 'utf8', timeout: 30_000, maxBuffer: 4 * 1024 ** 2 });
    if (result.error || result.status !== 0) {
      if ((/** @type {NodeJS.ErrnoException} */ (result.error))?.code === 'ENOENT') throw Object.assign(new Error('Docker CLI is absent'), { code: 'ENOENT' });
      if (!result.error && result.status === 1 && args.length === 3 && args[0] === 'image' && args[1] === 'inspect' && /^sha256:[a-f0-9]{64}$/.test(args[2]) && result.stderr?.trim() === `Error response from daemon: No such image: ${args[2]}`) throw Object.assign(new Error(`Docker image is absent: ${args[2]}`), { code: 'UD_IMAGE_ABSENT', imageId: args[2] });
      if (!result.error && result.status === 1 && args[0] === 'image' && args[1] === 'ls' && typeof result.stderr === 'string' && /cannot connect to the docker daemon|the system cannot find the file specified.*docker_engine|open \/\/\.\/pipe\/docker_engine: the system cannot find the file specified\./i.test(result.stderr)) throw Object.assign(new Error('Docker engine is unavailable'), { code: 'UD_ENGINE_UNAVAILABLE' });
      throw new Error('Original-test storage cannot inspect the local Docker engine: ' + (result.error?.message ?? result.stderr ?? result.status));
    }
    return result.stdout;
  };
  try {
    localDockerAuthority(environment, context => docker(['context', 'inspect', '--format', '{{.Endpoints.docker.Host}}', ...(context ? [context] : [])]).trim());
    const knownImageIds = lockedDockerImages(JSON.parse(readFileSync(path.join(root, 'runtime/runtime.lock.json'), 'utf8')));
    const sdk = path.join(root, '.artifacts/mutation-ci-sdk/ci-sdk.json');
    if (existsSync(sdk)) {
      const id = JSON.parse(readFileSync(sdk, 'utf8')).image_id;
      if (!/^sha256:[a-f0-9]{64}$/.test(id ?? '')) throw new Error('Original-test SDK image identity is invalid.');
      knownImageIds.push(id);
    }
    const knownAbsentAncestorIds = [];
    const selectedImages = localEvaluationImageDependencies(root, docker, knownAbsentAncestorIds);
    return inspectOwnedDockerStorage(docker, { selectedImages, knownImageIds, knownAbsentAncestorIds, ...(environment.UD_AGENT_LOCAL_ACTIONS_OWNER ? { activeActionsOwner: environment.UD_AGENT_LOCAL_ACTIONS_OWNER } : {}) }).image_bytes;
  } catch (error) {
    if (error?.code === 'ENOENT' || error?.code === 'UD_ENGINE_UNAVAILABLE') {
      if (freshNativeJob(root, environment)) {
        // This is a checkout starting-state assumption, not an inspection of
        // the engine or any resources belonging to another checkout.
        console.error('Original-test storage: fresh native checkout with no artifact history; no engine resources were created by this checkout before testing.');
        return 0;
      }
      throw new Error('Original-test storage cannot verify project-owned Docker data because the Docker CLI or engine is unavailable.');
    }
    throw error;
  }
}

/** Exact ancestry of a successfully built private client is accounting evidence,
 * never permission to delete an image or to accept unrelated dangling layers. */
export function localEvaluationImageDependencies(root, docker, knownAbsentAncestorIds = []) {
  const directory = path.join(root, '.artifacts/local-evals/client-images');
  if (!existsSync(directory)) return [];
  const selected = new Map(), digest = /^sha256:[a-f0-9]{64}$/;
  for (const name of readdirSync(directory)) {
    const receiptPath = path.join(directory, name, 'receipt.json');
    if (!existsSync(receiptPath)) continue;
    const receipt = JSON.parse(readFileSync(receiptPath, 'utf8'));
    const ancestryPath = path.join(directory, name, 'ancestry.json');
    if (!existsSync(ancestryPath)) throw new Error('Local evaluation client ancestry evidence is absent.');
    const evidence = JSON.parse(readFileSync(ancestryPath, 'utf8'));
    if (!digest.test(receipt.image_id ?? '') || !/^[a-f0-9-]{36}$/.test(receipt.created_by ?? '') || evidence.image_id !== receipt.image_id || evidence.relationship !== 'immutable-dependencies-of-owned-client-image-not-deletion-authority' || !Array.isArray(evidence.images) || !evidence.images.length || evidence.images.length > 33) throw new Error('Local evaluation client ancestry identity is invalid.');
    let expected = receipt.image_id;
    const visited = new Set();
    for (const row of evidence.images) {
      if (row.image_id !== expected || !digest.test(expected) || visited.has(expected) || !Number.isSafeInteger(row.size_bytes) || row.size_bytes < 0 || row.parent !== '' && !digest.test(row.parent)) throw new Error('Local evaluation client ancestry chain is invalid.');
      visited.add(expected);
      let images;
      try { images = JSON.parse(docker(['image', 'inspect', expected])); }
      catch (error) {
        // Builders may remove intermediate image records. Their layers remain
        // charged in the verified live child's Size. Only exact daemon absence
        // of an ancestor permits zero additional resident image bytes; the
        // original receipt chain must still be complete and every present
        // ancestor must still match it. A selected root additionally needs a
        // private, byte-verified archive when it is intentionally unloaded.
        if (error?.code === 'UD_IMAGE_ABSENT' && error.imageId === expected && (expected !== receipt.image_id || readLocalEvaluationImageArchive(root, name))) { knownAbsentAncestorIds.push(expected); expected = row.parent; continue; }
        throw error;
      }
      const image = Array.isArray(images) && images.length === 1 ? images[0] : undefined;
      const archivedRoot = expected === receipt.image_id && ((image?.Parent ?? '') !== row.parent || image?.Size !== row.size_bytes) ? readLocalEvaluationImageArchive(root, name) : undefined;
      if (image?.Id !== expected || image.Architecture !== 'arm64' || image.Os !== 'linux' || image.Size !== row.size_bytes && !archivedRoot || !Number.isSafeInteger(image.Size) || image.Size < 0 || (image.Parent ?? '') !== row.parent && !(archivedRoot && (image.Parent ?? '') === '') || expected === receipt.image_id && image.Config?.Labels?.[CLIENT_IMAGE_LABEL] !== receipt.created_by || archivedRoot && canonicalJson(image.RootFS?.Layers) !== canonicalJson(archivedRoot.before_inspection.RootFS.Layers)) throw new Error('Local evaluation client ancestry changed.');
      if (selected.has(expected) && selected.get(expected).size_bytes !== image.Size) throw new Error('Local evaluation client ancestry size changed.');
      // Docker may report compressed content-store bytes after archive restore.
      // Verify that actual metric while retaining at least the original virtual
      // size and independently verified uncompressed layer bytes for admission.
      const charged = archivedRoot ? Math.max(image.Size, row.size_bytes, archivedRoot.verification.layers.reduce((sum, layer) => sum + layer.uncompressed_bytes, 0)) : image.Size;
      selected.set(expected, { image_id: expected, size_bytes: image.Size, ...(charged > image.Size ? { charged_size_bytes: charged } : {}) });
      expected = row.parent;
    }
    if (expected) throw new Error('Local evaluation client ancestry evidence is incomplete.');
  }
  return [...selected.values()];
}

export function isWithinStorage(directory, filename) {
  const root = realpathSync(directory), selected = realpathSync(filename);
  return selected === root || selected.startsWith(root + path.sep);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [mode, root, destination] = process.argv.slice(2);
  if (mode !== '--copy' || !root || !destination || process.argv.length !== 5) throw new Error('Usage: original-storage.mjs --copy ROOT NEW_MODULES_DIRECTORY');
  copyOriginalDependencies(root, destination);
}
