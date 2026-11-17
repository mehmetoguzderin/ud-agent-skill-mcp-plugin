/** Actual bundled coordinator and byte-pinned native guard for protocol fixtures. */
import { createHash } from 'node:crypto';
import { chmod, copyFile, mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { build } from 'esbuild';
import { writableFixtureCopy } from './writable-copy.mjs';

export async function installedCoordinator(directory: string): Promise<string> {
  await mkdir(directory);
  writableFixtureCopy(path.resolve('contracts'), path.join(directory, 'contracts'), directory);
  writableFixtureCopy(path.resolve('release'), path.join(directory, 'release'), directory);
  const relativeGuard = `runtime/helpers/guard${process.platform === 'win32' ? '.exe' : ''}`;
  const guard = path.join(directory, relativeGuard);
  await mkdir(path.dirname(guard), { recursive: true });
  await copyFile(path.resolve(process.platform === 'win32' ? 'target/debug/ud-agent-guard.exe' : 'target/debug/ud-agent-guard'), guard);
  await chmod(guard, 0o700);
  const bytes = await readFile(guard);
  await writeFile(path.join(directory, 'runtime/runtime.lock.json'), JSON.stringify({
    schema_version: 1, product_version: '0.1.0-beta.1', state: 'frozen', packs: {},
    native_helpers: { [`${process.platform}/${process.arch}`]: { guard: {
      path: relativeGuard, sha256: `sha256:${createHash('sha256').update(bytes).digest('hex')}`, size_bytes: bytes.length,
    } } },
  }));
  const entry = path.join(directory, 'coordinator.mjs');
  await build({ entryPoints: [path.resolve('packages/coordinator/src/entry.ts')], outfile: entry,
    bundle: true, platform: 'node', format: 'esm', target: 'node24', mainFields: ['module', 'main'],
    banner: { js: 'import { createRequire as __udCreateRequire } from "node:module";const require=__udCreateRequire(import.meta.url);' },
  });
  return entry;
}
