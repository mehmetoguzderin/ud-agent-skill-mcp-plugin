import { describe, expect, it } from 'vitest';
import { cpSync, existsSync, lstatSync, mkdtempSync, mkdirSync, readFileSync, realpathSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { abortCandidate, abortCandidateIfActive, beginCandidate, completeCandidate, completeLocalCandidate, markCandidatePassed, recoverAbandonedCandidate } from '../../scripts/release/candidate-retention.mjs';
import { fileReceipt, sourceReceipt } from '../../scripts/release/candidate.mjs';

function fixture(action) {
  const root = realpathSync(mkdtempSync(path.join(os.tmpdir(), 'ud-candidate-retention-')));
  try { return action(root); } finally { rmSync(root, { recursive: true, force: true }); }
}
function assemble(root, name, beforeCompletion = () => {}) {
  const output = path.join(root, '.artifacts', name); beginCandidate(root, output);
  mkdirSync(path.join(output, 'artifacts')); writeFileSync(path.join(output, 'artifacts/payload'), name);
  mkdirSync(path.join(output, 'source-snapshot')); writeFileSync(path.join(output, 'source-snapshot/SOURCE-RECEIPT.json'), JSON.stringify({ sha256: 'a'.repeat(64) }));
  mkdirSync(path.join(output, 'runtime-inputs/runtime'), { recursive: true }); writeFileSync(path.join(output, 'runtime-inputs/runtime/runtime.lock.json'), '{}');
  const manifest = { qualification: 'available-target-preacceptance', status: 'preacceptance_candidate', production_ready: false, source_tree_sha256: 'a'.repeat(64), runtime_lock_sha256: fileReceipt(output, 'runtime-inputs/runtime/runtime.lock.json').sha256, source_snapshot: { root: 'source-snapshot', receipt: fileReceipt(output, 'source-snapshot/SOURCE-RECEIPT.json') }, runtime_root: 'runtime-inputs', artifacts: [{ id: 'payload', ...fileReceipt(output, 'artifacts/payload') }] };
  writeFileSync(path.join(output, 'available-candidate.json'), JSON.stringify(manifest));
  beforeCompletion(output, manifest);
  completeCandidate(root, output, manifest); return { output, manifest };
}
const registry = root => JSON.parse(readFileSync(path.join(root, '.artifacts/storage/candidates.json'), 'utf8'));
function assembleLocal(root, name, beforeCompletion = () => {}) {
  if (!existsSync(path.join(root, 'runtime'))) { mkdirSync(path.join(root, 'runtime')); writeFileSync(path.join(root, 'runtime/runtime.lock.json'), '{}'); }
  const output = path.join(root, '.artifacts', name); beginCandidate(root, output);
  writeFileSync(path.join(output, 'payload'), name);
  const manifest = { schema_version: 1, status: 'local_candidate', production_ready: false, product_version: '0.1.0-beta.1', source_tree_sha256: sourceReceipt(root).sha256, runtime_lock_sha256: fileReceipt(root, 'runtime/runtime.lock.json').sha256, artifacts: [{ id: 'payload', ...fileReceipt(root, path.relative(root, path.join(output, 'payload')).split(path.sep).join('/')) }] };
  writeFileSync(path.join(output, 'local-candidate.json'), JSON.stringify(manifest));
  beforeCompletion(output, manifest); completeLocalCandidate(root, output, manifest); return { output, manifest };
}

describe('local candidate retention', () => {
  it('keeps one current candidate and compact receipts across repeated preparation', () => fixture(root => {
    const first = assemble(root, 'first'), second = assemble(root, 'second'), third = assemble(root, 'third');
    expect(existsSync(first.output)).toBe(false); expect(existsSync(second.output)).toBe(false); expect(existsSync(third.output)).toBe(true);
    const state = registry(root); expect(state.current.output).toBe(third.output); expect(state.last_passed).toBe(null); expect(state.active).toBe(null);
    expect(state.history.map(row => [path.basename(row.output), row.action])).toEqual([['first', 'payload-removed'], ['second', 'payload-removed']]);
    expect(state.history[0].manifest.sha256).toMatch(/^[a-f0-9]{64}$/); expect(state.history[0].artifact_count).toBe(1);
  }));
  it('blocks a second incomplete assembly and cleans only the aborted owned output', () => fixture(root => {
    const output = path.join(root, '.artifacts/incomplete'); beginCandidate(root, output); writeFileSync(path.join(output, 'scratch'), 'owned');
    const next = path.join(root, '.artifacts/next'); expect(() => beginCandidate(root, next)).toThrow(/incomplete/); expect(existsSync(next)).toBe(false);
    abortCandidate(root, output); expect(existsSync(output)).toBe(false); expect(registry(root).active).toBe(null);
    beginCandidate(root, next); abortCandidate(root, next);
  }));
  it('recovers a stopped assembly without removing a live or foreign candidate', () => fixture(root => {
    const output = path.join(root, '.artifacts/interrupted');
    const module = new URL('../../scripts/release/candidate-retention.mjs', import.meta.url).href;
    const code = `import{beginCandidate}from${JSON.stringify(module)};beginCandidate(process.argv[1],process.argv[2]);process.kill(process.pid,'SIGKILL')`;
    const child = spawnSync(process.execPath, ['--input-type=module', '-e', code, root, output]);
    expectForcedStop(child); expect(existsSync(output)).toBe(true);
    const foreign = path.join(root, '.artifacts/foreign'); mkdirSync(foreign); writeFileSync(path.join(foreign, 'data'), 'preserve');
    expect(abortCandidateIfActive(root, foreign)).toBe(false); expect(recoverAbandonedCandidate(root)).toBe(true);
    expect(existsSync(output)).toBe(false); expect(readFileSync(path.join(foreign, 'data'), 'utf8')).toBe('preserve');
    const live = path.join(root, '.artifacts/live'); beginCandidate(root, live);
    expect(() => recoverAbandonedCandidate(root)).toThrow(/still active/); expect(existsSync(live)).toBe(true);
    expect(() => abortCandidateIfActive(root, live)).toThrow(/still active/); abortCandidate(root, live); expect(recoverAbandonedCandidate(root)).toBe(false);
  }));
  it('recovers a stopped registry writer but refuses an active writer', () => fixture(root => {
    const current = assemble(root, 'current'), lock = path.join(root, '.artifacts/storage/candidates.lock'), next = path.join(root, '.artifacts/next');
    mkdirSync(lock); writeFileSync(path.join(lock, 'owner.json'), JSON.stringify({ root, pid: process.pid }));
    expect(() => beginCandidate(root, next)).toThrow(/already active/); expect(existsSync(next)).toBe(false);
    writeFileSync(path.join(lock, 'owner.json'), JSON.stringify({ root, pid: 2147483647 }));
    beginCandidate(root, next); abortCandidate(root, next);
    expect(existsSync(current.output)).toBe(true); expect(existsSync(lock)).toBe(false);
  }));
  it('never adopts existing trees or deletes unrelated outputs or link targets', () => fixture(root => {
    const external = path.join(root, 'external'); mkdirSync(external); writeFileSync(path.join(external, 'user-data'), 'preserve');
    expect(() => beginCandidate(root, external)).toThrow(/owned artifact/);
    const old = path.join(root, '.artifacts/legacy'); mkdirSync(old); writeFileSync(path.join(old, 'data'), 'preserve');
    expect(() => beginCandidate(root, old)).toThrow(/never adopted/);
    const first = assemble(root, 'first'); symlinkSync(external, path.join(first.output, 'scratch-link'), 'dir'); assemble(root, 'second');
    expect(readFileSync(path.join(external, 'user-data'), 'utf8')).toBe('preserve'); expect(readFileSync(path.join(old, 'data'), 'utf8')).toBe('preserve');
  }));
  it('retains last passed only after a complete exact-candidate verifier succeeds', () => fixture(root => {
    const first = assemble(root, 'first'), report = path.join(root, 'acceptance.json'); writeFileSync(report, '{}');
    expect(() => markCandidatePassed(root, first.output, report)).toThrow(/verifier/);
    const firstHash = fileReceipt(first.output, 'available-candidate.json').sha256;
    for (const result of [{ verified: true }, { verified: true, locally_complete: true, source_tree_sha256: 'b'.repeat(64), candidate_manifest_sha256: firstHash }, { verified: true, locally_complete: true, source_tree_sha256: 'a'.repeat(64), candidate_manifest_sha256: 'c'.repeat(64) }]) expect(() => markCandidatePassed(root, first.output, report, () => result)).toThrow(/not verified/);
    markCandidatePassed(root, first.output, report, () => ({ verified: true, locally_complete: true, source_tree_sha256: 'a'.repeat(64), candidate_manifest_sha256: firstHash }));
    const second = assemble(root, 'second'), third = assemble(root, 'third');
    expect(existsSync(first.output)).toBe(false); expect(existsSync(second.output)).toBe(false); expect(existsSync(third.output)).toBe(true);
    expect(registry(root).last_passed.manifest.sha256).toBe(firstHash);
    expect(registry(root).last_passed.acceptance_report_sha256).toMatch(/^[a-f0-9]{64}$/);
    markCandidatePassed(root, third.output, report, () => ({ verified: true, locally_complete: true, source_tree_sha256: 'a'.repeat(64), candidate_manifest_sha256: fileReceipt(third.output, 'available-candidate.json').sha256 }));
    expect(existsSync(first.output)).toBe(false); expect(registry(root).last_passed.output).toBe(third.output);
  }));
  it('migrates a legacy retained passing payload to a compact receipt', () => fixture(root => {
    const passed = assemble(root, 'passed'), report = path.join(root, 'acceptance.json'); writeFileSync(report, '{}');
    markCandidatePassed(root, passed.output, report, () => ({ verified: true, locally_complete: true, source_tree_sha256: passed.manifest.source_tree_sha256, candidate_manifest_sha256: fileReceipt(passed.output, 'available-candidate.json').sha256 }));
    const legacy = registry(root).last_passed, backup = path.join(root, 'legacy-backup'); cpSync(passed.output, backup, { recursive: true });
    const current = assemble(root, 'current'); cpSync(backup, passed.output, { recursive: true });
    const info = lstatSync(passed.output); Object.assign(legacy, { device: info.dev, inode: info.ino, uid: info.uid });
    const state = registry(root); state.last_passed = legacy; writeFileSync(path.join(root, '.artifacts/storage/candidates.json'), JSON.stringify(state));
    const next = path.join(root, '.artifacts/next'); beginCandidate(root, next); abortCandidate(root, next);
    expect(existsSync(passed.output)).toBe(false); expect(existsSync(current.output)).toBe(true);
    expect(registry(root).last_passed.manifest.sha256).toBe(legacy.manifest.sha256);
    expect(registry(root).last_passed.acceptance_report_sha256).toBe(legacy.acceptance_report_sha256);
  }));
  it('rejects changed ownership before removing payloads', () => fixture(root => {
    const first = assemble(root, 'first');
    const state = registry(root); state.current.owner.id = 'foreign'; writeFileSync(path.join(root, '.artifacts/storage/candidates.json'), JSON.stringify(state));
    expect(() => assemble(root, 'third')).toThrow(/ownership marker/); expect(existsSync(first.output)).toBe(true);
  }));
  it('retains payloads when their recorded manifest changed', () => fixture(root => {
    const first = assemble(root, 'first'); writeFileSync(path.join(first.output, 'available-candidate.json'), '{}');
    expect(() => assemble(root, 'second')).toThrow(/manifest changed/);
    expect(existsSync(first.output)).toBe(true); expect(registry(root).cleanup.output).toBe(first.output);
    expect(() => beginCandidate(root, path.join(root, '.artifacts/third'))).toThrow(/manifest changed/);
    expect(existsSync(path.join(root, '.artifacts/third'))).toBe(false);
  }));
  it('rejects a source receipt rebound to different source bytes', () => fixture(root => {
    expect(() => assemble(root, 'different-source', (output, manifest) => {
      writeFileSync(path.join(output, 'source-snapshot/SOURCE-RECEIPT.json'), JSON.stringify({ sha256: 'b'.repeat(64) }));
      manifest.source_snapshot.receipt = fileReceipt(output, 'source-snapshot/SOURCE-RECEIPT.json');
      writeFileSync(path.join(output, 'available-candidate.json'), JSON.stringify(manifest));
    })).toThrow(/another source identity/);
    expect(registry(root).current).toBe(null);
    abortCandidate(root, path.join(root, '.artifacts/different-source'));
  }));
  it('does not mark an incomplete or differently bound candidate as current', () => fixture(root => {
    const current = assemble(root, 'current'), next = path.join(root, '.artifacts/next'); beginCandidate(root, next);
    writeFileSync(path.join(next, 'INCOMPLETE'), 'unfinished'); expect(() => completeCandidate(root, next, current.manifest)).toThrow(/Incomplete/);
    rmSync(path.join(next, 'INCOMPLETE')); writeFileSync(path.join(next, 'available-candidate.json'), '{}');
    expect(() => completeCandidate(root, next, current.manifest)).toThrow(/manifest differs/); expect(registry(root).current.output).toBe(current.output);
    abortCandidate(root, next);
  }));
  it('retains a compact passed receipt and only the latest full local preparation', () => fixture(root => {
    const passed = assemble(root, 'passed'), report = path.join(root, 'acceptance.json'); writeFileSync(report, '{}');
    markCandidatePassed(root, passed.output, report, () => ({ verified: true, locally_complete: true, source_tree_sha256: passed.manifest.source_tree_sha256, candidate_manifest_sha256: fileReceipt(passed.output, 'available-candidate.json').sha256 }));
    const first = assembleLocal(root, 'local-first'), second = assembleLocal(root, 'local-second'), third = assembleLocal(root, 'local-third');
    expect(existsSync(first.output)).toBe(false); expect(existsSync(second.output)).toBe(false); expect(existsSync(passed.output)).toBe(false); expect(existsSync(third.output)).toBe(true);
    expect(third.manifest.status).toBe('local_candidate'); expect(third.manifest.production_ready).toBe(false);
    const state = registry(root); expect(state.current.output).toBe(third.output); expect(state.current.manifest.path).toBe('local-candidate.json'); expect(state.last_passed.output).toBe(passed.output);
    expect(state.history.map(row => [path.basename(row.output), row.action])).toEqual([['passed', 'payload-removed'], ['local-first', 'payload-removed'], ['local-second', 'payload-removed']]);
    expect(state.history[0].artifact_count).toBe(1);
    const next = assemble(root, 'available-next'); expect(existsSync(third.output)).toBe(false); expect(existsSync(passed.output)).toBe(false);
    expect(registry(root).current.output).toBe(next.output);
  }));
  it('preserves nested output paths while refusing links, controls and retained-output overlap', () => fixture(root => {
    mkdirSync(path.join(root, '.artifacts/releases'), { recursive: true });
    const nested = assembleLocal(root, 'releases/current'); expect(existsSync(nested.output)).toBe(true);
    expect(() => beginCandidate(root, path.join(nested.output, 'child'))).toThrow(/nested inside/);
    expect(() => beginCandidate(root, path.join(root, '.artifacts/releases'))).toThrow(/overlaps/);
    expect(() => beginCandidate(root, path.join(root, '.artifacts/storage/output'))).toThrow(/storage controls/);
    symlinkSync(path.join(root, '.artifacts/releases'), path.join(root, '.artifacts/linked'), 'dir');
    expect(() => beginCandidate(root, path.join(root, '.artifacts/linked/output'))).toThrow(/ordinary real/);
    const next = assembleLocal(root, 'releases/next'); expect(existsSync(nested.output)).toBe(false); expect(existsSync(next.output)).toBe(true); expect(existsSync(path.join(root, '.artifacts/releases'))).toBe(true);
  }));
  it('rejects altered local artifacts, source and runtime without replacing current state', () => fixture(root => {
    const current = assembleLocal(root, 'current');
    for (const [name, change, expected] of [
      ['altered', output => writeFileSync(path.join(output, 'payload'), 'altered bytes'), /mismatch/],
      ['stale', () => writeFileSync(path.join(root, 'README.md'), 'changed source'), /source changed/],
      ['runtime', (output, manifest) => { manifest.runtime_lock_sha256 = 'f'.repeat(64); writeFileSync(path.join(output, 'local-candidate.json'), JSON.stringify(manifest)); }, /runtime lock/],
      ['outside', (output, manifest) => { manifest.artifacts[0] = { id: 'outside', ...fileReceipt(root, 'runtime/runtime.lock.json') }; writeFileSync(path.join(output, 'local-candidate.json'), JSON.stringify(manifest)); }, /outside/],
    ]) {
      expect(() => assembleLocal(root, name, change)).toThrow(expected); expect(registry(root).current.output).toBe(current.output);
      abortCandidate(root, path.join(root, '.artifacts', name));
    }
    expect(existsSync(current.output)).toBe(true);
  }));
});

function expectForcedStop(result) {
  expect(result.error).toBeUndefined();expect(result.stderr.toString()).toBe('');
  if (process.platform === 'win32') { expect(result.signal).toBeNull();expect(result.status).toBeTypeOf('number');expect(result.status).not.toBe(0); }
  else expect(result.signal).toBe('SIGKILL');
}
