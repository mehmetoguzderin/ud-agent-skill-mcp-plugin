export type DockerJobPolicy = { name: string; jobId: string; imageId: string; containerId: string; volume: string; readOnlyInput: boolean; entrypoint: string[]; command: string[]; seccomp?: Record<string, unknown> };

function object(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : undefined;
}
function same(value: unknown, expected: readonly string[]): boolean {
  const entries = Object(value) as ArrayLike<unknown>;
  return Array.isArray(value) && entries.length === expected.length && Array.prototype.every.call(entries, (entry: unknown, index: number) => entry === expected[index]);
}
function empty(value: unknown): boolean { return value == null || Array.isArray(value) && Object(value).length === 0; }
function confinedTmpfs(value: unknown): boolean {
  if (typeof value !== 'string') return false;
  const flags = String(value).split(',');
  if (flags.length !== 5 || !['rw', 'nosuid', 'nodev', 'noexec'].every(flag => flags.includes(flag))) return false;
  const sizes = flags.filter(flag => /^size=[1-9][0-9]*$/.test(flag));
  return sizes.length === 1 && Number(String(sizes[0]).slice(5)) <= 67108864;
}

/** Check total, untrusted native Docker JSON before starting the stopped job. */
export function inspectDockerJob(value: unknown, policy: DockerJobPolicy): string[] {
  const violations: string[] = [];
  const envelope = Object(value) as Record<string, unknown>;
  const item = Object(object(Array.isArray(value) && envelope.length === 1 ? envelope[0] : undefined)) as Record<string, unknown>;
  const config = Object(object(item.Config)) as Record<string, unknown>, host = Object(object(item.HostConfig)) as Record<string, unknown>, labels = Object(object(config.Labels)) as Record<string, unknown>;
  const identifier = typeof item.Id === 'string' ? item.Id : '';
  if (typeof item.Id !== 'string' || !/^[0-9a-f]{64}$/.test(identifier) || item.Id !== policy.containerId || item.Name !== `/${policy.name}` || item.Image !== policy.imageId || labels['io.ud-agent.job'] !== policy.jobId) violations.push('identity');
  if (config.User !== '10001:10001' || config.Tty !== false || config.OpenStdin !== true || !same(config.Entrypoint, policy.entrypoint) || !same(config.Cmd, policy.command)) violations.push('process');
  if (host.ReadonlyRootfs !== true || host.NetworkMode !== 'none' || host.Privileged !== false || !Array.isArray(host.CapDrop) || !Array.prototype.includes.call(Object(host.CapDrop), 'ALL') || !empty(host.CapAdd) || !empty(host.Devices) || !empty(host.Binds)) violations.push('isolation');
  if ([host.PidMode, host.IpcMode, host.UTSMode, host.CgroupnsMode].some(value => value !== undefined && value !== '' && value !== 'private')) violations.push('namespaces');
  if (!empty(host.DeviceRequests) || !empty(host.DeviceCgroupRules)) violations.push('devices');
  const security = Object(host.SecurityOpt) as ArrayLike<unknown>;
  if (!Array.isArray(host.SecurityOpt) || !Array.prototype.some.call(security, (value: unknown) => value === 'no-new-privileges' || value === 'no-new-privileges:true')) violations.push('no_new_privileges');
  if (Array.isArray(host.SecurityOpt)) {
    const profiles = Array.prototype.filter.call(security, (value: unknown) => typeof value === 'string' && String(value).startsWith('seccomp=')) as string[];
    if (policy.seccomp) {
      try { if (profiles.length !== 1 || JSON.stringify(JSON.parse(String(profiles[0]).slice(8))) !== JSON.stringify(policy.seccomp)) violations.push('seccomp'); }
      catch { violations.push('seccomp'); }
    } else if (profiles.length) violations.push('seccomp');
    if (Array.prototype.some.call(security, (value: unknown) => typeof value !== 'string' || (!['no-new-privileges', 'no-new-privileges:true'].includes(String(value)) && !(policy.seccomp && String(value).startsWith('seccomp='))))) violations.push('security_options');
  }
  if (host.Memory !== 2 * 1024 * 1024 * 1024 || host.NanoCpus !== 2_000_000_000 || host.PidsLimit !== 128) violations.push('limits');
  const mounts = (Array.isArray(item.Mounts) ? Array.prototype.map.call(Object(item.Mounts), (value: unknown) => Object(object(value))) : []) as Record<string, unknown>[];
  const volumes = mounts.filter(mount => mount.Type !== 'tmpfs'), volume = Object(volumes[0]) as Record<string, unknown>;
  if (volumes.length !== 1 || volume.Type !== 'volume' || volume.Name !== policy.volume || volume.Destination !== '/input' || volume.RW !== !policy.readOnlyInput) violations.push('mounts');
  if (mounts.some(mount => mount.Type === 'tmpfs' && (mount.Destination !== '/tmp' || mount.RW !== true))) violations.push('mounts');
  const tmpfs = Object(object(host.Tmpfs)) as Record<string, unknown>;
  if (Object.keys(tmpfs).length !== 1 || !confinedTmpfs(tmpfs['/tmp'])) violations.push('tmpfs');
  return violations;
}

/** Verify that a named volume is the exact locally owned per-job resource. */
export function inspectDockerVolume(value: unknown, name: string, jobId: string): boolean {
  const envelope = Object(value) as Record<string, unknown>;
  const item = Object(object(Array.isArray(value) && envelope.length === 1 ? envelope[0] : undefined)) as Record<string, unknown>;
  const labels = Object(object(item.Labels)) as Record<string, unknown>;
  return item.Name === name && item.Driver === 'local' && item.Scope === 'local' && labels['io.ud-agent.job'] === jobId && (item.Options == null || (!!object(item.Options) && Object.keys(Object(item.Options)).length === 0));
}
