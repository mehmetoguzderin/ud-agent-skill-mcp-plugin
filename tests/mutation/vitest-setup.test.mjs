import { test, expect } from 'vitest';
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, utimesSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const setup = fileURLToPath(new URL('./vitest-setup.ts', import.meta.url));

test('native setup reuses exact sealed helper bytes and still copies absent or different helpers', () => {
  const root = mkdtempSync(path.join(os.tmpdir(), 'ud-setup-guard-'));
  const guard = path.join(root, 'selected-guard'), target = path.join(root, 'target/debug', process.platform === 'win32' ? 'ud-agent-guard.exe' : 'ud-agent-guard');
  const selected = Buffer.from('exact selected native helper');
  try {
    writeFileSync(guard, selected); mkdirSync(path.dirname(target), { recursive: true });
    writeFileSync(target, selected); utimesSync(target, 1, 1); chmodSync(target, 0o555);
    const before = statSync(target);
    const invoke = () => spawnSync(process.execPath, [setup], { cwd: root, env: { ...process.env, UD_MUTATION_GUARD: guard }, encoding: 'utf8', timeout: 10_000 });
    const reused = invoke(); expect(reused.status, reused.stderr).toBe(0);
    expect(statSync(target).mtimeMs).toBe(before.mtimeMs); expect(readFileSync(target)).toEqual(selected);
    chmodSync(target, 0o700); writeFileSync(target, 'different helper');
    const replaced = invoke(); expect(replaced.status, replaced.stderr).toBe(0); expect(readFileSync(target)).toEqual(selected);
    rmSync(target);
    const created = invoke(); expect(created.status, created.stderr).toBe(0); expect(readFileSync(target)).toEqual(selected);
  } finally {
    try { chmodSync(target, 0o700); } catch (error) { if (error.code !== 'ENOENT') throw error; }
    rmSync(root, { recursive: true, force: true });
  }
});
