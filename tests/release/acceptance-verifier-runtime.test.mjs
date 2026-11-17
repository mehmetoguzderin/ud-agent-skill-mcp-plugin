import { test, expect } from 'vitest';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { runNativeProviderAcceptance } from '../../scripts/quality/native-provider-acceptance.mjs';

test('native provider acceptance rejects a fake archive interpreter before engine setup or any execution', async () => {
  const root = mkdtempSync(path.join(os.tmpdir(), 'ud-fake-acceptance-runtime-'));
  try {
    mkdirSync(path.join(root, 'bin')); const python = path.join(root, 'bin/python3.15'), marker = path.join(root, 'ran');
    writeFileSync(python, `#!/bin/sh\nprintf ran > '${marker}'\nprintf '{"verified":true}'\n`); chmodSync(python, 0o700);
    await expect(runNativeProviderAcceptance({ candidateRoot: path.join(root, 'missing-candidate'), python, reportPath: path.join(root, 'report.json'), engine: 'docker', qualification: 'candidate' })).rejects.toThrow(/approved release-verifier|receipt mismatch/);
    expect(existsSync(marker)).toBe(false); expect(existsSync(path.join(root, 'report.json'))).toBe(false);
  } finally { rmSync(root, { recursive: true, force: true }); }
}, 30_000);
