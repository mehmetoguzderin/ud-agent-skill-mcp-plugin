import { describe, expect, it } from 'vitest';
import { validateLiveProbeOutput } from '../../packages/runtime-manager/src/podman-probe-script.js';

const accepted = {
  schema_version: 1, uid: 10001, euid: 10001, gid: 10001, egid: 10001,
  interfaces: ['lo'], default_route: false, root_readonly: true, snapshot_readonly: true,
  no_new_privileges: true, capabilities_dropped: true, seccomp_enforced: true,
  memory_max: 2_147_483_648, pids_max: 128, cpu_quota: 200_000, cpu_period: 100_000,
  nofile_soft: 1024, nofile_hard: 1024,
};

describe('live worker probe evidence', () => {
  it('requires independently observed limits and confinement', () => {
    expect(validateLiveProbeOutput(accepted)).toEqual([]);
    expect(validateLiveProbeOutput(null)).toEqual(['invalid_probe_output']);
  });
  it.each([
    ['worker_uid', { euid: 0 }], ['network_isolation', { interfaces: ['lo', 'eth0'] }],
    ['network_isolation', { default_route: true }], ['read_only_mounts', { root_readonly: false }],
    ['read_only_mounts', { snapshot_readonly: false }], ['process_confinement', { seccomp_enforced: false }],
    ['process_confinement', { no_new_privileges: false }], ['process_confinement', { capabilities_dropped: false }],
    ['memory_limit', { memory_max: null }], ['pid_limit', { pids_max: 129 }],
    ['cpu_limit', { cpu_quota: 300_000 }], ['file_limit', { nofile_hard: 2048 }],
  ])('rejects %s when an observed invariant fails', (failure, override) => {
    expect(validateLiveProbeOutput({ ...accepted, ...override })).toContain(failure);
  });
});
