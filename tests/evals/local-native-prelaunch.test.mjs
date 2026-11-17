/** Native preparation failures retain actual launch/bridge lifecycle evidence. MIT. */
import { test, vi } from 'vitest';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, rmSync, existsSync, readFileSync, realpathSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { parse } from 'yaml';
import { nativeClientDependencyRecipe } from '../../evals/local/native-clients.mjs';

const effects = vi.hoisted(() => ({ bridge: vi.fn(), container: vi.fn(), native: vi.fn() }));
vi.mock('../../evals/local/container.mjs', async original => ({ ...await original(), selectedDockerEnvironment: () => ({ DOCKER_HOST: 'unix:///inert/docker.sock' }), startContainer: effects.container }));
vi.mock('../../evals/local/process.mjs', async original => ({ ...await original(), startOwned: effects.native }));
vi.mock('../../evals/local/coordinator-bridge.mjs', async original => ({ ...await original(), createCoordinatorBridge: effects.bridge }));
import { startNative } from '../../evals/local/native.mjs';

async function fixture(run) {
  const root = realpathSync(mkdtempSync(path.join(os.tmpdir(), 'ud-native-prelaunch-'))), taskRoot = path.join(root, 'task'), profile = path.join(root, 'profile');
  mkdirSync(taskRoot); effects.bridge.mockReset(); effects.container.mockReset(); effects.native.mockReset();
  try { await run({ root, taskRoot, profile, installation: path.join(root, 'not-installed'), harness: { id: 'hermes-agent', container: { image_id: 'sha256:' + 'a'.repeat(64), dependency_recipe_sha256: nativeClientDependencyRecipe('hermes-agent').sha256 } },
    model: 'local-eval-fixture', endpoint: 'http://127.0.0.1:12345', prompt: 'Read probe.txt.', skillsEnabled: true, allowUnverified: true }); }
  finally { rmSync(root, { recursive: true, force: true }); }
}

test('Hermes missing capacity fails before any bridge or native launch and records that control-flow evidence', () => fixture(async options => {
  let failure;
  try { await startNative(options); } catch (error) { failure = error; }
  assert.equal(failure.message, 'HERMES_NATIVE_MINIMUM_CONTEXT_CAPACITY_64000');
  assert.equal(effects.bridge.mock.calls.length, 0); assert.equal(effects.container.mock.calls.length, 0); assert.equal(effects.native.mock.calls.length, 0);
  assert.equal(existsSync(path.join(options.profile, 'bin')), false);
  assert.deepEqual(failure.native_cleanup, { cleanupVerified: true, steps: [
    { step: 'native-start-release', outcome: 'completed', cleanupVerified: true, no_launch_attempted: true },
    { step: 'bridge-start-release', outcome: 'completed', cleanupVerified: true, not_created: true },
  ] });
}));

test('inert 65536 capacity reaches real profile setup, and a failed created-bridge release remains unverified', () => fixture(async options => {
  const stop = vi.fn(async () => ({ cleanupVerified: false, cleanup_error: 'independent bridge release failed' }));
  effects.bridge.mockResolvedValue({ url: 'http://127.0.0.1:12346', token: 'inert-capability', stop });
  let failure;
  try { await startNative({ ...options, modelContextCapacity: 65536 }); } catch (error) { failure = error; }
  assert.ok(failure); assert.notEqual(failure.message, 'HERMES_NATIVE_MINIMUM_CONTEXT_CAPACITY_64000');
  assert.equal(parse(readFileSync(path.join(options.profile, '.hermes/config.yaml'), 'utf8')).model.context_length, 65536);
  assert.equal(effects.bridge.mock.calls.length, 1); assert.equal(stop.mock.calls.length, 1);
  assert.equal(effects.container.mock.calls.length, 0); assert.equal(effects.native.mock.calls.length, 0);
  assert.equal(failure.native_cleanup.cleanupVerified, false);
  assert.equal(failure.native_cleanup.steps[0].no_launch_attempted, true);
  assert.equal(failure.native_cleanup.steps[1].cleanupVerified, false);
  assert.equal(failure.native_cleanup.steps[1].not_created, undefined);
}));
