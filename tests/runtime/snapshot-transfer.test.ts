import { mkdtemp, mkdir, readFile, realpath, rename, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { captureValidationSnapshot } from '../../packages/workspace/src/snapshot.js';
import { receiveVerifiedSnapshot, streamVerifiedSnapshot, TRANSFER_CHUNK_BYTES } from '../../packages/workspace/src/snapshot-transfer.js';
import type { SnapshotFrame, SnapshotTransferSink } from '../../packages/workspace/src/snapshot-transfer.js';

const guard = path.resolve('target/debug/ud-agent-guard' + (process.platform === 'win32' ? '.exe' : ''));
async function fixture<T>(test: (snapshot: Awaited<ReturnType<typeof captureValidationSnapshot>>) => Promise<T>): Promise<T> {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'ud-transfer-source-'));
  let snapshot: Awaited<ReturnType<typeof captureValidationSnapshot>> | undefined;
  try {
    await writeFile(path.join(directory, 'a.conllu'), Buffer.alloc(TRANSFER_CHUNK_BYTES + 23, 0x61));
    await writeFile(path.join(directory, 'empty.conllu'), '');
    const root = await realpath(directory);
    snapshot = await captureValidationSnapshot(guard, root, [root]);
    return await test(snapshot);
  } finally { if (snapshot) await snapshot.cleanup(); await rm(directory, { recursive: true, force: true }); }
}
function memorySink() {
  const files = new Map<string, Buffer>(); let name = ''; let current: Buffer[] = [];
  let committed = false; let aborted = false;
  const sink: SnapshotTransferSink = {
    async begin() {}, async startFile(file) { name = file.path; current = []; },
    async writeChunk(bytes) { current.push(Buffer.from(bytes)); }, async finishFile() { files.set(name, Buffer.concat(current)); },
    async commit() { committed = true; }, async abort() { aborted = true; files.clear(); },
  };
  return { sink, files, status: () => ({ committed, aborted }) };
}
async function collect(frames: AsyncIterable<SnapshotFrame>): Promise<SnapshotFrame[]> { const result: SnapshotFrame[] = []; for await (const frame of frames) result.push(frame); return result; }
async function* values(frames: SnapshotFrame[]): AsyncGenerator<SnapshotFrame> { for (const frame of frames) yield frame; }

describe('identity-bound snapshot byte transfer', () => {
  it('streams bounded bytes and commits only after all file fingerprints match', async () => fixture(async snapshot => {
    const output = memorySink(); const frames = await collect(streamVerifiedSnapshot(guard, snapshot));
    expect(frames.filter(frame => frame.type === 'chunk').every(frame => frame.type === 'chunk' && frame.bytes.length <= TRANSFER_CHUNK_BYTES)).toBe(true);
    await receiveVerifiedSnapshot(values(frames), snapshot.sha256, output.sink);
    expect(output.status()).toEqual({ committed: true, aborted: false });
    expect(output.files.get('a.conllu')).toEqual(await readFile(path.join(snapshot.directory, 'a.conllu')));
    expect(output.files.get('empty.conllu')).toEqual(Buffer.alloc(0));
  }));
  it('rejects changed bytes after manifest emission before sending that file', async () => fixture(async snapshot => {
    const iterator = streamVerifiedSnapshot(guard, snapshot);
    expect((await iterator.next()).value?.type).toBe('begin');
    await writeFile(path.join(snapshot.directory, 'a.conllu'), 'tampered');
    await expect(iterator.next()).rejects.toThrow('Snapshot transfer input changed');
  }));
  it('rejects a replaced snapshot root even after initial inspection', async () => fixture(async snapshot => {
    const iterator = streamVerifiedSnapshot(guard, snapshot);
    expect((await iterator.next()).value?.type).toBe('begin');
    const original = `${snapshot.directory}-original`;
    await rename(snapshot.directory, original);
    try {
      await mkdir(snapshot.directory, { mode: 0o700 });
      await writeFile(path.join(snapshot.directory, 'a.conllu'), Buffer.alloc(TRANSFER_CHUNK_BYTES + 23, 0x61));
      await expect(iterator.next()).rejects.toThrow();
    } finally { await rm(snapshot.directory, { recursive: true, force: true }); await rename(original, snapshot.directory); }
  }));
  it('aborts rather than committing corrupt, reordered, missing or extra frames', async () => fixture(async snapshot => {
    const frames = await collect(streamVerifiedSnapshot(guard, snapshot));
    const chunks = frames.filter(frame => frame.type === 'chunk');
    const first = chunks[0]; if (!first || first.type !== 'chunk') throw new Error('missing test chunk');
    const damaged = frames.map(frame => frame === first ? { ...first, bytes: Buffer.alloc(first.bytes.length) } : frame);
    const secondIndex = frames.findIndex(frame => frame.type === 'chunk' && frame.offset > 0);
    const reordered = [...frames]; const second = reordered[secondIndex]; const firstIndex = reordered.indexOf(first);
    if (!second) throw new Error('missing second chunk');
    reordered[firstIndex] = second; reordered[secondIndex] = first;
    for (const invalid of [damaged, reordered, frames.slice(0, -1), [...frames, frames[0]!]]) {
      const output = memorySink();
      await expect(receiveVerifiedSnapshot(values(invalid), snapshot.sha256, output.sink)).rejects.toThrow();
      expect(output.status()).toEqual({ committed: false, aborted: true });
      expect(output.files.size).toBe(0);
    }
  }));
  it('rejects a mismatched trusted manifest and cancellation', async () => fixture(async snapshot => {
    const frames = await collect(streamVerifiedSnapshot(guard, snapshot));
    const output = memorySink();
    await expect(receiveVerifiedSnapshot(values(frames), '0'.repeat(64), output.sink)).rejects.toThrow('expected manifest');
    expect(output.status().aborted).toBe(true);
    const controller = new AbortController(); controller.abort();
    await expect(collect(streamVerifiedSnapshot(guard, snapshot, controller.signal))).rejects.toThrow('SNAPSHOT_TRANSFER_CANCELLED');
  }));
});
