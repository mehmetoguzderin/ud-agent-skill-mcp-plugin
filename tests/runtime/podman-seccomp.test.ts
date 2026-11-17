import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { verifyPodmanSeccomp } from '../../packages/coordinator/src/podman-seccomp.js';
const profile = JSON.parse(readFileSync('runtime/policies/render-seccomp.json', 'utf8'));
function effective() { return { defaultAction: 'SCMP_ACT_ERRNO', defaultErrnoRet: 1, architectures: ['SCMP_ARCH_AARCH64', 'SCMP_ARCH_ARM'], syscalls: [{ names: ['read', 'write', 'exit_group'], action: 'SCMP_ACT_ALLOW' }, { names: ['clone'], action: 'SCMP_ACT_ALLOW', args: [{ index: 0, value: 2114060288, valueTwo: 0, op: 'SCMP_CMP_MASKED_EQ' }] }, { names: ['clone3'], action: 'SCMP_ACT_ERRNO', errnoRet: 38 }] }; }
describe('effective Podman seccomp rules', () => {
  it('accepts native ABI normalization and stricter effective syscall subsets', () => {
    expect(verifyPodmanSeccomp(effective(), profile, 'arm64', '7.0.14-linuxkit')).toBe(true);
    const applied = effective(); applied.syscalls = []; expect(verifyPodmanSeccomp(applied, profile, 'arm64', '7.0.14')).toBe(true);
  });
  it('never permits capability-conditioned broad clone, mount, or unshare rules', () => {
    for (const name of ['mount', 'unshare', 'bpf', 'setns', 'clone']) {
      const applied = effective(); applied.syscalls.push({ names: [name], action: 'SCMP_ACT_ALLOW' });
      expect(verifyPodmanSeccomp(applied, profile, 'arm64', '7.0.14')).toBe(false);
    }
  });
  it('rejects a wrong ABI, default action, widened syscall argument or extra option', () => {
    const wrongABI = effective(); wrongABI.architectures.push('SCMP_ARCH_X86_64'); expect(verifyPodmanSeccomp(wrongABI, profile, 'arm64', '7.0.14')).toBe(false);
    const wrongDefault = effective(); wrongDefault.defaultAction = 'SCMP_ACT_ALLOW'; expect(verifyPodmanSeccomp(wrongDefault, profile, 'arm64', '7.0.14')).toBe(false);
    const widened = effective(); widened.syscalls[1]!.args![0]!.value = 0; expect(verifyPodmanSeccomp(widened, profile, 'arm64', '7.0.14')).toBe(false);
    expect(verifyPodmanSeccomp({ ...effective(), listenerPath: '/host' }, profile, 'arm64', '7.0.14')).toBe(false);
  });
  it('applies architecture and kernel selectors without inheriting dropped capabilities', () => {
    const applied = effective(); applied.syscalls.push({ names: ['ptrace'], action: 'SCMP_ACT_ALLOW' });
    expect(verifyPodmanSeccomp(applied, profile, 'arm64', '7.0.14')).toBe(true);
    expect(verifyPodmanSeccomp(applied, profile, 'arm64', '4.7.0')).toBe(false);
    const wrongArch = effective(); wrongArch.syscalls.push({ names: ['arch_prctl'], action: 'SCMP_ACT_ALLOW' });
    expect(verifyPodmanSeccomp(wrongArch, profile, 'arm64', '7.0.14')).toBe(false);
  });
});
