import { describe, expect, it } from 'vitest';
import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { compileLimaSeccomp, equalLimaSeccomp } from '../../packages/runtime-manager/src/lima-seccomp.js';
import { limaCreateArguments } from '../../packages/runtime-manager/src/lima-nerdctl.js';
const profile = {
  defaultAction: 'SCMP_ACT_ERRNO', defaultErrnoRet: 1,
  archMap: [{ architecture: 'SCMP_ARCH_AARCH64', subArchitectures: ['SCMP_ARCH_ARM'] }, { architecture: 'SCMP_ARCH_X86_64', subArchitectures: ['SCMP_ARCH_X86', 'SCMP_ARCH_X32'] }],
  syscalls: [
    { names: ['read', 'write'], action: 'SCMP_ACT_ALLOW' },
    { names: ['arm_fadvise64_64'], action: 'SCMP_ACT_ALLOW', includes: { arches: ['arm64'] } },
    { names: ['arch_prctl'], action: 'SCMP_ACT_ALLOW', includes: { arches: ['amd64'] } },
    { names: ['mount'], action: 'SCMP_ACT_ALLOW', includes: { caps: ['CAP_SYS_ADMIN'] } },
    { names: ['ptrace'], action: 'SCMP_ACT_ALLOW', includes: { minKernel: '4.8' } },
    { names: ['clone'], action: 'SCMP_ACT_ALLOW', excludes: { arches: ['s390'], caps: ['CAP_SYS_ADMIN'] }, args: [{ index: 0, value: 235012096, valueTwo: 0, op: 'SCMP_CMP_MASKED_EQ' }] },
    { names: ['clone3'], action: 'SCMP_ACT_ERRNO', errnoRet: 38, excludes: { caps: ['CAP_SYS_ADMIN'] } },
    { names: ['foreign_arch'], action: 'SCMP_ACT_ALLOW', excludes: { arches: ['arm64', 'amd64'] } },
  ],
};
function completed(profile: unknown, architecture: 'arm64' | 'amd64') {
  try { return compileLimaSeccomp(profile, architecture); }
  catch (error) {
    if (error instanceof Error && ['LIMA_SECCOMP_PROFILE_INVALID', 'LIMA_SECCOMP_KERNEL_FILTER_UNSUPPORTED', 'LIMA_SECCOMP_ARCHITECTURE_INVALID'].includes(error.message)) expect.fail('A valid receipt-bound seccomp profile must compile: ' + error.message);
    throw error;
  }
}
const expected = (arch: 'arm64' | 'amd64') => ({ defaultAction: 'SCMP_ACT_ERRNO', defaultErrnoRet: 1,
  architectures: arch === 'arm64' ? ['SCMP_ARCH_AARCH64', 'SCMP_ARCH_ARM'] : ['SCMP_ARCH_X86_64', 'SCMP_ARCH_X86', 'SCMP_ARCH_X32'],
  syscalls: [{ names: ['read', 'write'], action: 'SCMP_ACT_ALLOW' }, { names: [arch === 'arm64' ? 'arm_fadvise64_64' : 'arch_prctl'], action: 'SCMP_ACT_ALLOW' }, { names: ['ptrace'], action: 'SCMP_ACT_ALLOW' }, { names: ['clone'], action: 'SCMP_ACT_ALLOW', args: [{ index: 0, value: 235012096, op: 'SCMP_CMP_MASKED_EQ' }] }, { names: ['clone3'], action: 'SCMP_ACT_ERRNO', errnoRet: 38 }] });
describe('Lima receipt-bound OCI seccomp projection', () => {
  it('projects independent exact empty-capability ARM and AMD OCI outputs without broad namespace or mount allowances', () => {
    for (const arch of ['arm64', 'amd64'] as const) expect(completed(profile, arch)).toEqual(expected(arch));
  });
  it('converts the exact shipped render policy and preserves constrained namespace masks and clone3 ENOSYS', async () => {
    const bytes = await readFile('runtime/policies/render-seccomp.json'), provenance = JSON.parse(await readFile('runtime/policies/render-seccomp.provenance.json', 'utf8'));
    expect(createHash('sha256').update(bytes).digest('hex')).toBe(provenance.sha256);
    for (const arch of ['arm64', 'amd64'] as const) {
      const value = completed(JSON.parse(bytes.toString()), arch) as { syscalls: Record<string, unknown>[] };
      expect(value.syscalls).toContainEqual({ names: ['clone'], action: 'SCMP_ACT_ALLOW', args: [{ index: 0, value: 235012096, op: 'SCMP_CMP_MASKED_EQ' }] });
      expect(value.syscalls).toContainEqual({ names: ['unshare'], action: 'SCMP_ACT_ALLOW', args: [{ index: 0, value: 503447680, valueTwo: 268435456, op: 'SCMP_CMP_MASKED_EQ' }] });
      expect(value.syscalls).toContainEqual({ names: ['clone3'], action: 'SCMP_ACT_ERRNO', errnoRet: 38 });
      expect(value.syscalls.some(call => (call.names as string[]).includes('mount'))).toBe(false);
      expect(JSON.stringify(value)).not.toMatch(/includes|excludes|archMap|CAP_SYS_ADMIN/);
    }
  });
  it('rejects unsupported kernel predicates, foreign architectures, unknown fields, malformed arguments, and listener/flag additions', () => {
    const changes = [
      (p: any) => { p.syscalls[4].includes.minKernel = '7.1'; },
      (p: any) => { p.syscalls[0].excludes = { minKernel: '4.8' }; },
      (p: any) => { p.archMap[0].subArchitectures = ['SCMP_ARCH_X86']; },
      (p: any) => { p.archMap.push(p.archMap[0]); },
      (p: any) => { p.listenerPath = '/untrusted'; },
      (p: any) => { p.flags = ['SECCOMP_FILTER_FLAG_SPEC_ALLOW']; },
      (p: any) => { p.defaultAction = 'SCMP_ACT_ALLOW'; },
      (p: any) => { p.syscalls[0].action = 'SCMP_ACT_NOTIFY'; },
      (p: any) => { p.syscalls[5].args[0].index = 6; },
      (p: any) => { p.syscalls[5].args[0].value = -1; },
      (p: any) => { p.syscalls[5].args[0].valueTwo = Number.MAX_SAFE_INTEGER + 1; },
      (p: any) => { p.syscalls[5].args[0].op = 'unknown'; },
      (p: any) => { p.syscalls[0].names = ['read', 'read']; },
      (p: any) => { p.syscalls[0].includes = { caps: 'CAP_SYS_ADMIN' }; },
    ];
    for (const change of changes) { const altered = structuredClone(profile); change(altered); expect(() => compileLimaSeccomp(altered, 'arm64')).toThrow(/LIMA_SECCOMP/); }
  });
  it('passes policy only via inherited stdin for opted-in render creates; ordinary workers retain default policy', () => {
    const job = { name: 'ud-agent-11111111-1111-4111-8111-111111111111-worker', jobId: '11111111-1111-4111-8111-111111111111', image: 'ghcr.io/mehmetoguzderin/ud-agent-skill-mcp-plugin-render@sha256:' + 'a'.repeat(64), volume: 'ud-agent-11111111-1111-4111-8111-111111111111-input', command: ['-c', 'pass'], readOnlyInput: true };
    const ordinary = limaCreateArguments(job), rendered = limaCreateArguments({ ...job, seccompFromStdin: true });
    expect(ordinary.filter(item => item.startsWith('seccomp='))).toEqual([]);expect(rendered.filter(item => item.startsWith('seccomp='))).toEqual(['seccomp=/dev/stdin']);
    for (const flag of ['--cap-drop', 'ALL', '--read-only', 'no-new-privileges', '--pull=never']) expect(rendered).toContain(flag);
  });
  it('compares all compiled OCI controls and tolerates only object field ordering', () => {
    const value = expected('arm64'); expect(equalLimaSeccomp(JSON.parse(JSON.stringify(value)), value)).toBe(true);
    const reorder = Object.fromEntries(Object.entries(value).reverse()); expect(equalLimaSeccomp(reorder, value)).toBe(true);
    for (const change of [(p: any) => { p.defaultAction = 'SCMP_ACT_ALLOW'; }, (p: any) => { p.syscalls.pop(); }, (p: any) => { p.syscalls.push({ names: ['mount'], action: 'SCMP_ACT_ALLOW' }); }, (p: any) => { p.syscalls[3].args[0].value = 0; }, (p: any) => { p.architectures.reverse(); }, (p: any) => { p.listenerPath = '/socket'; }]) {
      const wrong = structuredClone(value); change(wrong); expect(equalLimaSeccomp(wrong, value)).toBe(false);
    }
  });
});
