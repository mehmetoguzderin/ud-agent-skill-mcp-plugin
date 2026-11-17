import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { expect, it } from 'vitest';
import { readBoundedReceiptBytes } from '../../packages/runtime-manager/src/receipt.js';

it('keeps ordinary receipts bounded while allowing the explicitly bounded six-platform dependency inventory', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'ud-receipt-bounds-'));
  try {
    const file = path.join(root, 'inventory.json'), exact = Buffer.alloc(1024 * 1024, 32);
    await writeFile(file, exact); expect(await readBoundedReceiptBytes(file)).toEqual(exact);
    const larger = Buffer.concat([exact, Buffer.from('\n')]); await writeFile(file, larger);
    await expect(readBoundedReceiptBytes(file)).rejects.toThrow('bounded regular file');
    expect(await readBoundedReceiptBytes(file, larger.length)).toEqual(larger);
    await expect(readBoundedReceiptBytes(file, larger.length - 1)).rejects.toThrow('bounded regular file');
    for (const invalid of [0, -1, 1.5, NaN, 32 * 1024 * 1024 + 1]) await expect(readBoundedReceiptBytes(file, invalid)).rejects.toThrow('byte limit');
    await expect(readBoundedReceiptBytes('relative.json', 2 * 1024 * 1024)).rejects.toThrow('absolute');
    await expect(readBoundedReceiptBytes(root)).rejects.toThrow('bounded regular file');
  } finally { await rm(root, { recursive: true, force: true }); }
});
