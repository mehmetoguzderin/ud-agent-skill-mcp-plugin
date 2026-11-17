import { test, expect } from 'vitest';
import { mkdirSync, mkdtempSync, rmSync, unlinkSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { sourceReceipt } from '../../scripts/release/candidate.mjs';
import { verifyRetainedRuntimeCompatibility } from '../../scripts/runtime/freeze-runtime.mjs';

function write(root, name, data) {
  const file = path.join(root, name);
  mkdirSync(path.dirname(file), { recursive: true });
  writeFileSync(file, typeof data === 'string' ? data : JSON.stringify(data));
}
function fixture(action) {
  const directory = mkdtempSync(path.join(os.tmpdir(), 'ud-retained-runtime-'));
  const source = path.join(directory, 'source'), retained = path.join(directory, 'retained');
  try {
    for (const root of [source, retained]) {
      mkdirSync(root);
      write(root, 'LICENSE', 'MIT');
      write(root, 'workers/ud/src/worker.py', 'worker-v1');
      write(root, 'packages/launcher/src/main.rs', 'launcher-v1');
      write(root, 'runtime/ud-sources.lock.json', 'sources-v1');
      write(root, 'uv.lock', 'dependencies-v1');
      write(root, 'scripts/example.mjs', 'coordinator-v1');
    }
    write(source, 'runtime/runtime.lock.json', { state: 'unbuilt' });
    write(retained, 'runtime/runtime.lock.json', { schema_version: 1, state: 'frozen' });
    write(retained, 'runtime/userspace.lock.json', { schema_version: 1, state: 'frozen' });
    write(retained, 'freeze-composition.json', { schema_version: 1, qualification: 'available-target-inputs', production_ready: false, source_tree_sha256: sourceReceipt(retained).sha256 });
    action(source, retained);
  } finally { rmSync(directory, { recursive: true, force: true }); }
}

test('retained runtime can accompany new coordinator source with identical runtime build inputs', () => fixture((source, retained) => {
  write(source, 'scripts/example.mjs', 'coordinator-v2');
  const result = verifyRetainedRuntimeCompatibility(source, retained);
  expect(result.runtime.state).toBe('frozen');
  expect(result.userspace.state).toBe('frozen');
  expect(result.source.sha256).not.toBe(result.retained.sha256);
}));

test('changed runtime sources, dependency locks, and stale retained composition block reuse', () => fixture((source, retained) => {
  write(source, 'workers/ud/src/worker.py', 'worker-v2');
  expect(() => verifyRetainedRuntimeCompatibility(source, retained)).toThrow(/retained runtime input changed: workers\/ud\/src\/worker.py/);
  write(source, 'workers/ud/src/worker.py', 'worker-v1');
  write(source, 'uv.lock', 'dependencies-v2');
  expect(() => verifyRetainedRuntimeCompatibility(source, retained)).toThrow(/retained runtime input changed: uv.lock/);
  write(source, 'uv.lock', 'dependencies-v1');
  unlinkSync(path.join(source, 'runtime/ud-sources.lock.json'));
  expect(() => verifyRetainedRuntimeCompatibility(source, retained)).toThrow(/retained runtime input was removed: runtime\/ud-sources.lock.json/);
  write(source, 'runtime/ud-sources.lock.json', 'sources-v1');
  write(retained, 'scripts/example.mjs', 'tampered');
  expect(() => verifyRetainedRuntimeCompatibility(source, retained)).toThrow(/composition is incomplete or stale/);
}));
