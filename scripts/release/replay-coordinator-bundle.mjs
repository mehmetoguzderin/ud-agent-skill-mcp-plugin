/** Reproduce source-to-bundle bytes without executing the application. */
import { chmodSync, copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, symlinkSync, writeFileSync } from 'node:fs';
import { rm } from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { pathToFileURL } from 'node:url';
import { fileReceipt, sourceReceipt } from './candidate.mjs';

export const MAX_COORDINATOR_BUNDLE_BYTES = 128 * 1024 ** 2;

export function coordinatorToolInputs(assetsRoot) {
  const binary = process.platform === 'win32' ? 'esbuild.exe' : 'bin/esbuild';
  return ['node_modules/esbuild/lib/main.js', 'node_modules/esbuild/package.json', `node_modules/@esbuild/${process.platform}-${process.arch}/${binary}`].map(name => fileReceipt(assetsRoot, name));
}

export function verifyCoordinatorToolInputs(assetsRoot, expected) {
  const actual = coordinatorToolInputs(assetsRoot);
  if (!Array.isArray(expected) || JSON.stringify(actual) !== JSON.stringify(expected)) throw new Error('Coordinator inspection tools were not verified against original locked npm archives.');
  return actual;
}

/** The producer and independent proof use this identical deterministic layout.
 * Original npm archive admission is still required before trusting SDK inputs.
 * @param {string} sourceRoot
 * @param {string} assetsRoot
 * @param {any[]} expectedTools
 * @param {{output?: string}} [options]
 */
export async function replayCoordinator(sourceRoot, assetsRoot, expectedTools, { output } = {}) {
  if (output !== undefined && (!path.isAbsolute(output) || existsSync(output))) throw new Error('Coordinator output requires a new absolute file.');
  const toolInputs = verifyCoordinatorToolInputs(assetsRoot, expectedTools);
  const source = sourceReceipt(sourceRoot), temporary = mkdtempSync(path.join(os.tmpdir(), 'ud-bundle-source-replay-'));
  const privateTools = mkdtempSync(path.join(os.tmpdir(), 'ud-bundle-verified-tools-'));
  const priorEsbuild = process.env.ESBUILD_BINARY_PATH;
  let esbuild;
  try {
    for (const row of toolInputs) {
      const target = path.join(privateTools, row.path); mkdirSync(path.dirname(target), { recursive: true });
      copyFileSync(path.join(assetsRoot, row.path), target);
      chmodSync(target, row.executable ? 0o555 : 0o444);
      const copied = fileReceipt(privateTools, row.path);
      if (copied.sha256 !== row.sha256 || copied.size !== row.size) throw new Error('Inspection compiler changed while copying verified original bytes.');
    }
    for (const row of source.files) { const target = path.join(temporary, row.path); mkdirSync(path.dirname(target), { recursive: true }); copyFileSync(path.join(sourceRoot, row.path), target); chmodSync(target, row.executable ? 0o755 : 0o644); if (fileReceipt(temporary, row.path).sha256 !== row.sha256) throw new Error('Original source changed during bundle replay.'); }
    symlinkSync(path.join(assetsRoot, 'node_modules'), path.join(temporary, 'node_modules'), 'dir');
    // Fix the verified executable explicitly. Ambient ESBUILD_BINARY_PATH
    // must never select another program after the original-archive check.
    process.env.ESBUILD_BINARY_PATH = path.join(privateTools, toolInputs[2].path);
    verifyCoordinatorToolInputs(assetsRoot, expectedTools);
    esbuild = await import(pathToFileURL(path.join(privateTools, toolInputs[0].path)).href);
    const result = await esbuild.build({ absWorkingDir: temporary, entryPoints: ['packages/coordinator/src/entry.ts'], bundle: true, platform: 'node', format: 'esm', target: 'node24', mainFields: ['module', 'main'], banner: { js: "import { createRequire as __udCreateRequire } from 'node:module'; const require = __udCreateRequire(import.meta.url);" }, preserveSymlinks: true, write: false, metafile: true, logLevel: 'silent' });
    if (result.outputFiles.length !== 1) throw new Error('The coordinator bundle output is ambiguous.');
    const { sha256 } = await import('./candidate.mjs'), bytes = result.outputFiles[0].contents;
    if (bytes.length > MAX_COORDINATOR_BUNDLE_BYTES) throw new Error('Coordinator bundle exceeds its bounded package allocation.');
    const names = new Set(Object.keys(result.metafile.inputs));
    for (const name of [...names]) if (name.startsWith('node_modules/')) {
      for (let directory = path.posix.dirname(name); directory !== 'node_modules' && directory !== '.'; directory = path.posix.dirname(directory)) {
        const manifest = directory + '/package.json';
        if (existsSync(path.join(assetsRoot, manifest))) names.add(manifest);
      }
    }
    const inputs = [...names].sort().map(name => fileReceipt(name.startsWith('node_modules/') ? assetsRoot : temporary, name));
    verifyCoordinatorToolInputs(assetsRoot, expectedTools);
    if (sourceReceipt(sourceRoot).sha256 !== source.sha256) throw new Error('Original coordinator source changed during bundle replay.');
    if (output !== undefined) { writeFileSync(output, bytes, { flag: 'wx', mode: 0o644 }); if (fileReceipt(path.dirname(output), path.basename(output)).sha256 !== sha256(bytes)) throw new Error('Coordinator output changed while writing original bundle bytes.'); }
    return { schema_version: 1, source_inventory_sha256: source.sha256, bundle: { sha256: sha256(bytes), size_bytes: bytes.length }, inputs, tool_inputs: toolInputs, tool_version: esbuild.version };
  } finally {
    try { await esbuild?.stop(); }
    finally {
      if (priorEsbuild === undefined) delete process.env.ESBUILD_BINARY_PATH; else process.env.ESBUILD_BINARY_PATH = priorEsbuild;
      // esbuild.stop() requests child termination; Windows may retain the
      // private executable briefly afterward. Retry only these owned trees,
      // with at most 2.75 seconds of cumulative delay per tree.
      try { await rm(temporary, { recursive: true, force: true, maxRetries: 10, retryDelay: 50 }); }
      finally { await rm(privateTools, { recursive: true, force: true, maxRetries: 10, retryDelay: 50 }); }
    }
  }
}
if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(import.meta.filename)) {
  try {
    if (process.argv.length === 4 && process.argv[2] === '--tool-inputs') console.log(JSON.stringify(coordinatorToolInputs(path.resolve(process.argv[3]))));
    else {
      if (process.argv.length !== 5 && !(process.argv.length === 7 && process.argv[5] === '--output')) throw new Error('Usage: replay-coordinator-bundle.mjs SOURCE_ROOT ASSETS_ROOT VERIFIED_TOOL_INPUTS_JSON [--output ABSOLUTE_NEW_FILE]');
      console.log(JSON.stringify(await replayCoordinator(path.resolve(process.argv[2]), path.resolve(process.argv[3]), JSON.parse(process.argv[4]), process.argv.length === 7 ? { output: process.argv[6] } : {})));
    }
  } catch (error) { console.error(error.message); process.exitCode = 1; }
}
