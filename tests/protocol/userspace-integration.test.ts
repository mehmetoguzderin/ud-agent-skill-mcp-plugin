import { readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { executeOperation } from '../../packages/coordinator/src/operations.js';
import { loadNativeGuardReceipt } from '../../packages/runtime-manager/src/receipt.js';
import { withFrozenUserspacePack } from './userspace-fixture.js';

describe('public validation dispatch through a frozen userspace pack', () => {
  it('preserves unsuccessful linguistic validation as a completed operation and rejects tampering', async () => withFrozenUserspacePack(async ({release,workspace,options,domain,contract,args,bytes,ready}) => {
      expect(ready, JSON.stringify(ready)).toMatchObject({ status: 'ready', ready: true, runtime: { engine: 'userspace' } });
      expect((await loadNativeGuardReceipt(release, { platform: process.platform, arch: process.arch })).guard).toBe(path.join(release, 'runtime/pack', process.platform === 'win32' ? 'guard.exe' : 'guard'));
      const result = await executeOperation(contract, args, domain, options);
      expect(result.isError, JSON.stringify(result.structuredContent)).toBeUndefined();
      expect(result.structuredContent).toMatchObject({ execution: { status: 'completed' }, result: { passed: false, bytes: bytes.toString('hex') }, scope: { file_paths: ['sample.conllu'] }, provenance: { runtime: 'userspace' } });
      const workerChild = (result.structuredContent.result as { worker_child: number }).worker_child;
      expect(workerChild).toBeGreaterThan(0);
      const reaped = async () => { for (let attempt = 0; attempt < 100; attempt++) { try { process.kill(workerChild, 0); } catch (error) { if ((error as NodeJS.ErrnoException).code === 'ESRCH') return true; throw error; } await new Promise(done => setTimeout(done, 20)); } return false; };
      expect(await reaped(), 'successful userspace workers must reap their helper processes').toBe(true);
      expect(result.structuredContent.diagnostics).toEqual([{ message: 'fixture invalid' }]);
      expect(result.structuredContent.limitations).toContain('Userspace execution runs as the current user without container isolation.');
      expect(await readFile(path.join(workspace, 'sample.conllu'))).toEqual(bytes);
      await writeFile(path.join(release, 'runtime/pack/worker/ud_agent/wire.py'), 'tampered');
      const rejected = await executeOperation(contract, args, domain, options);
      expect(rejected.isError).toBe(true);
      expect(rejected.structuredContent.execution.status).not.toBe('completed');
  }), 60_000);
});
