import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync } from 'node:fs';
import { mkdtemp, readdir, realpath, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { captureValidationSnapshot } from '../../packages/workspace/src/snapshot.js';
import { streamVerifiedSnapshot } from '../../packages/workspace/src/snapshot-transfer.js';
import { encodeSnapshotFrame, encodeSnapshotFrames } from '../../packages/workspace/src/snapshot-wire.js';

const guard = path.resolve('target/debug/ud-agent-guard' + (process.platform === 'win32' ? '.exe' : ''));
const digest = (bytes: Buffer) => createHash('sha256').update(bytes).digest('hex');
const interpreter = process.env.UD_AGENT_PYTHON ?? (existsSync(path.resolve('.venv/bin/python')) ? path.resolve('.venv/bin/python') : 'python3');

describe('Python snapshot wire compatibility', () => {
  it('transfers actual TypeScript frames into the Python worker with an independently supplied digest', async () => {
    const base = await mkdtemp(path.join(os.tmpdir(), 'ud-cross-wire-'));
    let snapshot: Awaited<ReturnType<typeof captureValidationSnapshot>> | undefined;
    try {
      const root = await realpath(base);
      const data = Buffer.alloc(65_536 + 7, 0x61);
      await writeFile(path.join(root, '😀.conllu'), data);
      await writeFile(path.join(root, '\uE000.conllu'), '');
      snapshot = await captureValidationSnapshot(guard, root, [root]);
      const chunks: Buffer[] = [];
      for await (const part of encodeSnapshotFrames(streamVerifiedSnapshot(guard, snapshot))) chunks.push(part);
      const script = `import hashlib, json, os, sys\nfrom ud_agent.snapshot_receiver import receive_snapshot\nwith receive_snapshot(sys.stdin.buffer, sys.argv[1], sys.argv[2]) as stage:\n print(json.dumps({name: hashlib.sha256(open(os.path.join(stage.path,name),'rb').read()).hexdigest() for name in sorted(os.listdir(stage.path))}, ensure_ascii=False))\n`;
      const result = spawnSync(interpreter, ['-c', script, snapshot.sha256, root], {
        input: Buffer.concat(chunks), encoding: 'utf8', maxBuffer: 1024 * 1024,
        env: { ...process.env, PYTHONPATH: path.resolve('workers/ud/src') },
      });
      expect(result.error).toBeUndefined();
      expect(result.status, result.stderr).toBe(0);
      expect(JSON.parse(result.stdout)).toEqual({ '😀.conllu': digest(data), '\uE000.conllu': digest(Buffer.alloc(0)) });
      expect((await readdir(root)).sort()).toEqual(['😀.conllu', '\uE000.conllu'].sort());
    } finally { if (snapshot) await snapshot.cleanup(); await rm(base, { recursive: true, force: true }); }
  });

  it('rejects oversized or empty encoded chunks', () => {
    expect(() => encodeSnapshotFrame({ type: 'chunk', path: 'a', offset: 0, bytes: Buffer.alloc(0) })).toThrow('Invalid snapshot chunk');
    expect(() => encodeSnapshotFrame({ type: 'chunk', path: 'a', offset: 0, bytes: Buffer.alloc(65_537) })).toThrow('Invalid snapshot chunk');
    expect(() => encodeSnapshotFrame({ type: 'chunk', path: 'a', offset: -1, bytes: Buffer.from('x') })).toThrow('Invalid snapshot chunk');
  });
});
