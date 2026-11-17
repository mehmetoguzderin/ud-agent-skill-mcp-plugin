#!/usr/bin/env node
/** Storage admission for the existing original-code CI SDK bootstrap. MIT. */
import { spawn, spawnSync } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { chmodSync, existsSync, lstatSync, readFileSync, readdirSync, realpathSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { localDockerAuthority } from './mutation-scope.mjs';
import { reserveStorage, storageTreeBytes, STORAGE_LIMITS } from './storage-lifecycle.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const required = ['Images', 'Containers', 'Local Volumes', 'Build Cache'];
const need = (ok, message) => { if (!ok) throw new Error('SDK storage admission: ' + message); };

/** Docker's df output is rounded. Bound each displayed size on both sides. */
export function dockerSizeBounds(value) {
  const match = /^(\d+)(?:\.(\d+))?\s*(B|kB|KB|MB|GB|TB|KiB|MiB|GiB|TiB)$/.exec(value ?? '');
  need(match, 'engine storage size is unavailable');
  const units = { B: 1, kB: 1000, KB: 1000, MB: 1000**2, GB: 1000**3, TB: 1000**4, KiB: 1024, MiB: 1024**2, GiB: 1024**3, TiB: 1024**4 };
  const unit = units[match[3]], precision = 10 ** (match[2]?.length ?? 0), amount = Number(match[1] + (match[2] ?? '')) * unit / precision, rounding = unit / precision;
  need(Number.isSafeInteger(Math.ceil(amount + rounding)), 'engine storage size exceeds numeric bounds');
  if (value === '0B') return { lower: 0, upper: 0 };
  return { lower: Math.max(0, Math.floor(amount - rounding)), upper: Math.ceil(amount + rounding) };
}

/** Include builder cache and all writable engine categories conservatively. */
export function dockerStorageSnapshot(output) {
  const rows = output.trim().split(/\r?\n/).filter(Boolean).map(line => JSON.parse(line));
  need(rows.length === required.length, 'engine storage categories are incomplete');
  const result = {};
  for (const row of rows) {
    need(required.includes(row.Type) && !Object.hasOwn(result, row.Type), 'engine storage category is foreign or duplicated');
    result[row.Type] = dockerSizeBounds(row.Size);
  }
  need(required.every(name => Object.hasOwn(result, name)), 'engine storage categories are incomplete');
  return result;
}

export function dockerStorageGrowth(before, after) {
  return required.reduce((sum, name) => sum + Math.max(0, after[name].upper - before[name].lower), 0);
}

/** Reserve all pre-existing engine categories when ownership is ambiguous. */
export function admittedEngineBytes(snapshot, projectImageBytes) {
  const engine = required.reduce((sum, name) => sum + snapshot[name].upper, 0);
  const nonImages = required.filter(name => name !== 'Images').reduce((sum, name) => sum + snapshot[name].upper, 0);
  const total = Math.max(engine, projectImageBytes + nonImages);
  need(Number.isSafeInteger(total) && total >= 0, 'engine storage baseline is unavailable');
  return total;
}

function ownedPath(value, { optional = false, ownerRoot = root } = {}) {
  if (!value && optional) return undefined;
  const selected = path.resolve(value), artifacts = path.join(ownerRoot, '.artifacts');
  need(selected.startsWith(artifacts + path.sep), 'SDK paths must be checkout-owned artifact directories');
  let current = ownerRoot;
  for (const part of path.relative(ownerRoot, selected).split(path.sep)) {
    current = path.join(current, part);
    const info = lstatSync(current, { throwIfNoEntry: false });
    if (info) need(info.isDirectory() && !info.isSymbolicLink() && realpathSync(current) === current, 'SDK path contains a link or non-directory');
  }
  return selected;
}

export function sdkWorkspaceBytes(assets, context, exporter) {
  const archive = path.join(assets, 'sdk-image.tar');
  const outputs = () => {
    const final = lstatSync(archive, { throwIfNoEntry: false }), identities = [];
    let size = final?.size ?? 0, exportBytes = 0;
    if (final) identities.push(`final:${final.dev}:${final.ino}`);
    const journal = path.join(assets, 'image-export.json');
    if (exporter?.pid && existsSync(journal)) {
      const held = lstatSync(journal);
      need(held.isFile() && !held.isSymbolicLink() && held.nlink === 1 && held.size <= 16384, 'SDK export journal is not ordinary');
      const record = JSON.parse(readFileSync(journal, 'utf8'));
      // A previous completed invocation's journal grants no active-output credit.
      if (record.creator_pid === exporter.pid && record.owner === exporter.owner) {
        need(record.schema_version === 1 && record.qualification === 'owned-SDK-image-export' && record.root === exporter.root && record.assets === assets
          && record.docker?.endpoint === exporter.endpoint && record.docker?.daemon_id === exporter.daemon && /^sha256:[a-f0-9]{64}$/.test(record.image_id ?? '')
          && /^sdk-image\.[a-f0-9]{32}\.tar$/.test(record.path ?? '') && Number.isSafeInteger(record.device) && Number.isSafeInteger(record.inode), 'SDK export ownership differs');
        const temporary = path.join(assets, record.path), partial = lstatSync(temporary, { throwIfNoEntry: false });
        // The same inode moves to the final name; ownership survives that rename.
        const info = partial ?? (final?.dev === record.device && final?.ino === record.inode ? final : undefined);
        if (info) {
          need(info.isFile() && !info.isSymbolicLink() && info.nlink === 1 && info.uid === process.getuid?.() && !(info.mode & 0o077)
            && info.dev === record.device && info.ino === record.inode && realpathSync(partial ? temporary : archive) === (partial ? temporary : archive), 'SDK export inode differs');
          exportBytes = info.size;
          if (partial) size += info.size;
          identities.push(`export:${partial ? record.path : 'final'}:${info.dev}:${info.ino}`);
        }
      }
    }
    return { bytes: size, exportBytes, identity: identities.join('|') };
  };
  for (let attempt = 0; attempt < 10; attempt++) {
    try {
      const before = outputs(), total = storageTreeBytes(assets) + (context ? storageTreeBytes(context) : 0), after = outputs();
      if (before.identity !== after.identity) continue;
      // Growth during a scan is legitimate. Credit the smaller observed size
      // while charging the larger size to output, so both bounds are conservative.
      const credit = Math.min(before.bytes, after.bytes), size = Math.max(before.bytes, after.bytes), exportBytes = Math.max(before.exportBytes, after.exportBytes);
      if (total < credit) continue;
      return { scratch: total - credit, archive: size, ...(exportBytes ? { exportBytes } : {}) };
    } catch (error) { if (error.code === 'ENOENT') continue; throw error; }
  }
  throw new Error('SDK storage admission: export inventory did not settle');
}

/** Completed native closures are retained inputs, not another scratch copy.
 * Credit only byte-verified, read-only files; unknown intermediates still count.
 * All files remain included in reserveStorage's repository-wide limit. */
export function retainedSdkInputs(assets, ownerRoot = root) {
  const markerPath = path.join(assets, 'native-inputs.json');
  if (!existsSync(markerPath)) {
    let completed;
    return () => { if (!completed && existsSync(markerPath)) completed = retainedSdkInputs(assets, ownerRoot); return completed?.() ?? 0; };
  }
  const digest = file => createHash('sha256').update(readFileSync(file)).digest('hex');
  const read = file => { const info = lstatSync(file); need(info.isFile() && !info.isSymbolicLink() && info.nlink === 1 && info.size <= 16 * 1024**2, 'retained SDK receipt is not ordinary'); return JSON.parse(readFileSync(file, 'utf8')); };
  const marker = read(markerPath), cross = read(path.join(assets, 'cross-build-receipt.json'));
  need(marker.qualification === 'original-locked-native-SDK-input-build-no-generated-variants' && cross.qualification === 'native-original-guard-build-not-cross-build' && Array.isArray(cross.source_inputs) && cross.source_inputs.length > 0, 'retained SDK completion evidence is missing');
  for (const row of cross.source_inputs) {
    need(typeof row.path === 'string' && row.path.split('/').every(part => part && part !== '.' && part !== '..') && !path.isAbsolute(row.path) && !row.path.includes('\\') && digest(path.join(ownerRoot, row.path)) === row.sha256, 'retained SDK source binding changed');
  }
  const rustReceipt = path.join(assets, 'mutation-rust-assets/rust-input-receipt.json');
  need(digest(rustReceipt) === marker.rust_receipt_sha256, 'retained Rust receipt changed');
  const specs = [
    ['mutation-rust-assets/export', rustReceipt],
    ['native-perl/linux-arm64-source', path.join(assets, 'native-perl/linux-arm64-source-receipt.json')],
    ['native-git/linux-arm64', path.join(assets, 'native-git/linux-arm64-receipt.json')],
    ['mutation-node-linux-arm64-v4/node_modules', path.join(assets, 'mutation-node-linux-arm64-v4/node-dependencies.json')],
  ];
  const files = [], seen = new Set();
  for (const [relative, receiptPath] of specs) {
    if (!existsSync(receiptPath)) continue;
    const receipt = read(receiptPath);
    need(Array.isArray(receipt.files) && receipt.files.length > 0, 'retained SDK closure has no inventory');
    for (const row of receipt.files) {
      need(typeof row.path === 'string' && !path.isAbsolute(row.path) && !row.path.includes('\\') && row.path.split('/').every(part => part && part !== '.' && part !== '..'), 'retained SDK path is unsafe');
      const file = path.join(assets, relative, row.path), expected = row.sha256?.replace(/^sha256:/, '');
      let info = lstatSync(file);
      // Symbolic aliases receive no storage credit. Docker Desktop bind
      // mounts can preserve a host write bit after the native closure was
      // sealed; seal the exact verified host inode before retaining it.
      if (info.isSymbolicLink()) continue;
      need(!seen.has(file) && info.isFile() && info.nlink === 1 && info.uid === process.getuid?.() && realpathSync(file) === file && info.size === (row.size ?? row.size_bytes) && /^[a-f0-9]{64}$/.test(expected ?? '') && digest(file) === expected, 'retained SDK file differs from its receipt');
      if (info.mode & 0o222) { chmodSync(file, info.mode & 0o555); const sealed = lstatSync(file); need(sealed.dev === info.dev && sealed.ino === info.ino && sealed.size === info.size && !(sealed.mode & 0o222), 'retained SDK sealing changed its identity'); info = sealed; }
      seen.add(file); files.push({ file, size: info.size, dev: info.dev, ino: info.ino, mode: info.mode, mtimeMs: info.mtimeMs, ctimeMs: info.ctimeMs });
    }
  }
  return () => files.reduce((sum, row) => {
    const info = lstatSync(row.file);
    need(info.isFile() && !info.isSymbolicLink() && info.nlink === 1 && ['size', 'dev', 'ino', 'mode', 'mtimeMs', 'ctimeMs'].every(key => info[key] === row[key]), 'retained SDK input identity changed during build');
    return sum + row.size;
  }, 0);
}

/** A completed context contains another retained copy of native input bytes.
 * Match it back to the independently admitted original closure. Modified Node
 * assertion modules and every unmatched byte remain charged as scratch. */
export function retainedSdkContextInputs(assets, contexts, ownerRoot = root) {
  if (!contexts) return () => 0;
  const admitted = retainedSdkInputs(assets, ownerRoot), known = new Map();
  const digest = file => createHash('sha256').update(readFileSync(file)).digest('hex');
  const specs = [['mutation-rust-assets/export', 'rust', 'mutation-rust-assets/rust-input-receipt.json'],
    ['native-perl/linux-arm64-source', 'private-perl', 'native-perl/linux-arm64-source-receipt.json'],
    ['native-git/linux-arm64', 'git', 'native-git/linux-arm64-receipt.json'],
    ['mutation-node-linux-arm64-v4/node_modules', 'node_modules', 'mutation-node-linux-arm64-v4/node-dependencies.json']];
  return () => {
    admitted();
    for (const name of existsSync(contexts) ? readdirSync(contexts) : []) {
      if (!/^context-[a-f0-9]{32}$/.test(name)) continue;
      const directory = path.join(contexts, name), marker = path.join(directory, '.sdk-context-owner.json'), context = path.join(directory, 'context');
      if (known.has(directory) || !existsSync(marker) || !existsSync(path.join(context, 'input-receipt.json'))) continue;
      const info = lstatSync(directory), owner = JSON.parse(readFileSync(marker, 'utf8'));
      need(info.isDirectory() && !info.isSymbolicLink() && realpathSync(directory) === directory && owner.root === ownerRoot && owner.assets === assets && owner.context === directory && owner.device === info.dev && owner.inode === info.ino, 'prepared SDK context ownership changed');
      const input = JSON.parse(readFileSync(path.join(context, 'input-receipt.json'), 'utf8'));
      need(input.qualification === 'development-mutation-runner' && input.platform === 'linux/arm64' && input.package_lock_sha256 === digest(path.join(ownerRoot, 'package-lock.json')), 'prepared SDK context source binding changed');
      const files = [];
      for (const [original, copied, receipt] of specs) {
        const sourceReceipt = path.join(assets, receipt);
        if (!existsSync(sourceReceipt)) continue;
        for (const row of JSON.parse(readFileSync(sourceReceipt, 'utf8')).files) {
          need(typeof row.path === 'string' && !path.isAbsolute(row.path) && !row.path.includes('\\') && row.path.split('/').every(part => part && part !== '.' && part !== '..'), 'prepared SDK input path is unsafe');
          const source = path.join(assets, original, row.path), file = path.join(context, copied, row.path), expected = row.sha256?.replace(/^sha256:/, '');
          let stat = lstatSync(file, { throwIfNoEntry: false });
          if (!stat || !stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || stat.uid !== process.getuid?.() || realpathSync(file) !== file || stat.size !== (row.size ?? row.size_bytes) || digest(file) !== expected) continue;
          need(digest(source) === expected, 'original SDK context input changed');
          if (stat.mode & 0o222) { chmodSync(file, stat.mode & 0o555); const sealed = lstatSync(file); need(sealed.dev === stat.dev && sealed.ino === stat.ino && sealed.size === stat.size, 'SDK context sealing changed its identity'); stat = sealed; }
          files.push({ file, size: stat.size, dev: stat.dev, ino: stat.ino, mode: stat.mode, mtimeMs: stat.mtimeMs, ctimeMs: stat.ctimeMs });
        }
      }
      known.set(directory, files);
    }
    let bytes = 0;
    for (const files of known.values()) for (const row of files) {
      const info = lstatSync(row.file, { throwIfNoEntry: false });
      if (!info) continue; // The owned builder retires its context before export.
      const fields = ['size', 'dev', 'ino', 'mode', 'mtimeMs', 'ctimeMs'];
      const unchanged = info.isFile() && !info.isSymbolicLink() && info.nlink === 1 && fields.every(key => info[key] === row[key]);
      // A path lookup can overlap unlink and observe its now-unlinked inode.
      // Confirm disappearance before dropping credit; a replacement still fails.
      if (!unchanged && !lstatSync(row.file, { throwIfNoEntry: false })) continue;
      need(unchanged, 'retained SDK context identity changed during build: ' + JSON.stringify({ path: path.relative(ownerRoot, row.file), changed: [...fields, 'nlink'].filter(key => info[key] !== (key === 'nlink' ? 1 : row[key])) }));
      bytes += row.size;
    }
    return bytes;
  };
}

export function inspectDocker(args, environment, { run = spawnSync, now = () => performance.now() } = {}) {
  const deadline = now() + 5000;
  const storageQuery = JSON.stringify(args) === JSON.stringify(['system', 'df', '--format', '{{json .}}']);
  let result;
  for (let attempt = 0; attempt < 3; attempt++) {
    const remaining = Math.ceil(deadline - now());
    if (remaining <= 0) break;
    result = run('docker', args, { env: environment, encoding: 'utf8', timeout: remaining, maxBuffer: 4 * 1024**2 });
    need(now() <= deadline, 'engine storage inspection deadline expired');
    // Docker can walk the active BuildKit snapshot just as its read-only
    // payload mount disappears. Retry only this observed lookup race, within
    // the original deadline; never substitute an old or missing observation.
    const retiredMount = !result.error && result.status === 1 && /^Error response from daemon: failed to calculate image disk usage: lstat \/var\/lib\/containerd\/io\.containerd\.snapshotter\.v1\.overlayfs\/snapshots\/[1-9]\d*\/fs\/sdk-inputs\.tar\.xz: no such file or directory\s*$/.test(result.stderr ?? '');
    if (!storageQuery || !retiredMount) break;
  }
  need(result !== undefined, 'engine storage inspection deadline expired');
  need(!result.error && result.status === 0, 'cannot inspect engine storage: ' + (result.error?.message ?? result.stderr ?? result.status));
  return result.stdout;
}

/** Run the verified Python bootstrap under one owned, cancellable lease. */
export async function supervisedSdk({ assets, context, mode, python, download, baseImage, transientBytes }, overrides = {}) {
  const ownerRoot = overrides.ownerRoot ?? root;
  assets = ownedPath(assets, { ownerRoot }); context = ownedPath(context, { optional: mode !== 'ensure', ownerRoot });
  need(['ensure', 'load', 'provider'].includes(mode) && path.isAbsolute(python) && (mode !== 'ensure' || context), 'SDK command is incomplete');
  need(!context || !context.startsWith(assets + path.sep) && !assets.startsWith(context + path.sep) && assets !== context, 'SDK context and assets must not overlap');
  const environment = { ...process.env };
  const authority = overrides.authority ?? localDockerAuthority(environment, name => inspectDocker(['context', 'inspect', '--format', '{{.Endpoints.docker.Host}}', ...(name ? [name] : [])], environment).trim());
  need(authority && ['unix', 'npipe'].includes(authority.transport) && typeof authority.endpoint === 'string', 'local Docker endpoint is unavailable');
  delete environment.DOCKER_CONTEXT;
  environment.DOCKER_HOST = authority.endpoint;
  const readDaemon = overrides.readDaemon ?? (() => inspectDocker(['info', '--format', '{{.ID}}'], environment).trim());
  const daemon = readDaemon();
  need(/^[A-Za-z0-9._:-]{1,128}$/.test(daemon), 'Docker daemon identity is unavailable');
  need(overrides.expectedDaemon === undefined || overrides.expectedDaemon === daemon, 'Docker daemon changed between SDK phases');
  environment.UD_SDK_DOCKER_ENDPOINT = authority.endpoint;
  environment.UD_SDK_DOCKER_DAEMON = daemon;
  const recover = overrides.recover ?? (() => {
    const args = [path.join(ownerRoot, 'scripts/quality/mutation-runtime-bootstrap.py'), '--recover-jobs', '--asset-root', assets];
    if (context) args.push('--output', context);
    const result = spawnSync(python, args, { cwd: ownerRoot, env: environment, encoding: 'utf8', timeout: 60000, maxBuffer: 1024**2 });
    need(!result.error && result.status === 0, 'owned SDK recovery failed: ' + (result.error?.message ?? result.stderr?.slice(-2000) ?? result.status));
  });
  recover();
  // Capacity is admitted once; build/output growth is not a test verdict.
  need(transientBytes === undefined || Number.isSafeInteger(transientBytes) && transientBytes > 0 && transientBytes <= 12_000_000_000, 'explicit local SDK transient allowance is invalid');
  const archiveAllowance = overrides.archiveAllowance ?? 4_000_000_000;
  const scratchAllowance = overrides.scratchAllowance ?? transientBytes ?? STORAGE_LIMITS.releaseBytes;
  need(Number.isSafeInteger(archiveAllowance) && archiveAllowance > 0 && archiveAllowance <= 4_000_000_000 && Number.isSafeInteger(scratchAllowance) && scratchAllowance > 0 && scratchAllowance <= (transientBytes ?? STORAGE_LIMITS.releaseBytes), 'SDK storage budgets are invalid');
  let child, completion, force, stopping = false;
  const exportOwner = randomUUID();
  const group = process.platform !== 'win32';
  function send(signal) { if (!child?.pid) return; try { if (group) process.kill(-child.pid, signal); else child.kill(signal); } catch (error) { if (error.code !== 'ESRCH') throw error; } }
  function stop() { if (stopping) return; stopping = true; send('SIGTERM'); force ??= setTimeout(() => send('SIGKILL'), 10000); force.unref(); }
  const lease = reserveStorage({ root: ownerRoot, profile: 'release', plannedBytes: scratchAllowance, plannedOutputBytes: archiveAllowance,
    ...(scratchAllowance > STORAGE_LIMITS.releaseBytes ? { transientAllowance: scratchAllowance } : {}),
    outputParent: ownerRoot, inputRoots: [ownerRoot], label: 'mutation-sdk', onCancel: async () => { if (child) { stop(); await completion; send('SIGKILL'); } } });
  try {
    need(readDaemon() === daemon, 'Docker daemon changed during SDK preparation');
    const script = path.join(ownerRoot, 'scripts/quality/prepare-mutation-runtime.py');
    const operation = { ensure: '--ensure-ci', load: '--load-ci-image', provider: '--ensure-ci-provider' }[mode];
    const args = [script, operation, '--asset-root', assets, '--sdk-storage-worker'];
    if (context) args.push('--output', context);
    if (download) args.push('--download');
    if (baseImage) args.push('--base-image', baseImage);
    child = spawn(python, args, { cwd: ownerRoot, env: { ...environment, ...lease.env, UD_SDK_EXPORT_OWNER: exportOwner }, stdio: 'inherit', detached: group });
    completion = new Promise((resolve, reject) => { child.once('error', reject); child.once('close', (code, signal) => resolve({ code, signal })); });
    const result = await completion;
    need(readDaemon() === daemon, 'Docker daemon changed during SDK preparation');
    need(!result.signal && result.code === 0, 'original SDK command did not complete successfully');
    if (mode === 'provider') return { authority, daemon };
  } finally { clearTimeout(force); lease.cleanup(); }
}

/** Acquire the immutable provider, release its lease, then run native builds
 * against the same verified daemon. */
export async function prepareSdk(options, overrides = {}) {
  if (options.mode !== 'ensure') return supervisedSdk(options, overrides);
  const binding = await supervisedSdk({ ...options, mode: 'provider' }, overrides);
  return supervisedSdk(options, { ...overrides, authority: binding.authority, expectedDaemon: binding.daemon });
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [mode, python, assets, context, download, baseImage, ...options] = process.argv.slice(2);
  need(options.length === 0 || options.length === 2 && options[0] === '--transient-bytes' && /^\d+$/.test(options[1]), 'unknown SDK storage option');
  await prepareSdk({ mode, python, assets, context: context || undefined, download: download === 'true', baseImage: baseImage || undefined, ...(options.length ? { transientBytes: Number(options[1]) } : {}) });
}
