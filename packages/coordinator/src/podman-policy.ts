import path from 'node:path';
import { verifyPodmanSeccomp } from './podman-seccomp.js';

export type PodmanWorkerPolicy = { name: string; jobId: string; imageId: string; containerId: string; volume: string; volumePath: string; graphRoot: string; runRoot?: string; architecture: string; kernelRelease: string; readOnlyInput: boolean; entrypoint: string[]; command: string[]; environment: string[]; seccomp: Record<string, unknown> };
function object(value: unknown): Record<string, unknown> | undefined { return value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : undefined; }
function canonical(value: unknown): string { return JSON.stringify(value, (_key, item: unknown) => item && typeof item === 'object' && !Array.isArray(item) ? Object.fromEntries(Object.entries(item).sort(([a], [b]) => a.localeCompare(b, 'en'))) : item); }
function same(value: unknown, expected: readonly unknown[]): boolean { return Array.isArray(value) && canonical(value) === canonical(expected); }
function below(root: string, name: unknown): name is string { if (typeof name !== 'string') return false; const rel = path.posix.relative(root, name); return rel !== '' && rel !== '..' && !rel.startsWith(`..${path.posix.sep}`) && !path.posix.isAbsolute(rel); }

/** Validate Podman's native inspect fields; Docker's inspect layout is different. */
export function inspectPodmanWorker(value: unknown, policy: PodmanWorkerPolicy): { violations: string[]; configPath?: string } {
  const violations: string[] = [];
  const item = Array.isArray(value) && value.length === 1 ? object(value[0]) : undefined;
  const config = object(item?.Config), host = object(item?.HostConfig), state = object(item?.State), labels = object(config?.Labels);
  if (!item || item.Id !== policy.containerId || item.Name !== policy.name || item.Image !== policy.imageId.slice(7) && item.Image !== policy.imageId || labels?.['io.ud-agent.job'] !== policy.jobId) violations.push('identity');
  if (!['created', 'initialized'].includes(state?.Status as string) || config?.User !== '10001:10001' || config?.Tty !== false || config?.OpenStdin !== true || !(same(config?.Entrypoint, policy.entrypoint) || policy.entrypoint.length === 1 && config?.Entrypoint === policy.entrypoint[0]) || !same(config?.Cmd, policy.command)) violations.push('process');
  if (host?.Privileged !== false || host.ReadonlyRootfs !== true || host.NetworkMode !== 'none' || host.PublishAllPorts !== false || !Array.isArray(host.Devices) || host.Devices.length !== 0) violations.push('isolation');
  if (!(item?.EffectiveCaps === null || same(item?.EffectiveCaps, [])) || !(item?.BoundingCaps === null || same(item?.BoundingCaps, []))) violations.push('capabilities');
  const mounts = Array.isArray(item?.Mounts) ? item.Mounts.map(object).filter(mount => mount?.Type !== 'tmpfs') : [];
  if (mounts.length !== 1 || mounts[0]?.Type !== 'volume' || mounts[0].Name !== policy.volume || mounts[0].Source !== policy.volumePath || mounts[0].Destination !== '/input' || mounts[0].RW !== !policy.readOnlyInput) violations.push('input_volume');
  const configPath = item?.OCIConfigPath;
  if (!below(policy.graphRoot, configPath)) violations.push('oci_config_path');
  return { violations, ...(below(policy.graphRoot, configPath) ? { configPath } : {}) };
}

/** Verify a normal per-job local volume, never an image/host/plugin mount. */
export function inspectPodmanInputVolume(value: unknown, name: string, jobId: string, graphRoot: string): string | undefined {
  const item = Array.isArray(value) && value.length === 1 ? object(value[0]) : undefined;
  const labels = object(item?.Labels), options = object(item?.Options);
  if (!item || item.Name !== name || item.Driver !== 'local' || item.Scope !== 'local' || labels?.['io.ud-agent.job'] !== jobId || options && Object.keys(options).length !== 0 || item.Options != null && !options || !below(graphRoot, item.Mountpoint)) return undefined;
  return item.Mountpoint;
}

/** Independently inspect effective OCI containment, not merely requested flags. */
export function inspectPodmanWorkerSpec(value: unknown, policy: PodmanWorkerPolicy): string[] {
  const violations: string[] = [];
  const spec = object(value), proc = object(spec?.process), root = object(spec?.root), linux = object(spec?.linux);
  if (!spec || !proc || !root || !linux) return ['missing_spec'];
  const user = object(proc.user), caps = object(proc.capabilities);
  if (root.readonly !== true || user?.uid !== 10001 || user.gid !== 10001 || user.additionalGids !== undefined && (!Array.isArray(user.additionalGids) || user.additionalGids.some(gid => gid !== 10001)) || proc.noNewPrivileges !== true || proc.terminal !== undefined && proc.terminal !== false || proc.cwd !== '/tmp') violations.push('process_isolation');
  if (!same(proc.args, [...policy.entrypoint, ...policy.command]) || !Array.isArray(proc.env) || !same([...proc.env].sort(), [...policy.environment].sort())) violations.push('process_identity');
  if (!caps || ['bounding', 'effective', 'inheritable', 'permitted', 'ambient'].some(key => caps[key] !== undefined && !same(caps[key], []))) violations.push('capabilities');
  const nofile = Array.isArray(proc.rlimits) ? proc.rlimits.map(object).filter(limit => limit?.type === 'RLIMIT_NOFILE') : [];
  if (nofile.length !== 1 || !Number.isSafeInteger(nofile[0]?.soft) || !Number.isSafeInteger(nofile[0]?.hard) || (nofile[0]?.soft as number) < 1 || (nofile[0]?.hard as number) > 1024 || (nofile[0]?.soft as number) > (nofile[0]?.hard as number)) violations.push('file_limit');
  for (const kind of ['pid', 'ipc', 'network', 'cgroup', 'user', 'mount', 'uts']) {
    const matches = Array.isArray(linux.namespaces) ? linux.namespaces.map(object).filter(item => item?.type === kind) : [];
    if (matches.length !== 1 || matches[0]?.path) violations.push(`namespace_${kind}`);
  }
  if (!verifyPodmanSeccomp(linux.seccomp, policy.seccomp, policy.architecture, policy.kernelRelease)) violations.push('seccomp');
  const resources = object(linux.resources), memory = object(resources?.memory), cpu = object(resources?.cpu), pids = object(resources?.pids);
  if (!Number.isSafeInteger(memory?.limit) || (memory?.limit as number) < 1 || (memory?.limit as number) > 2_147_483_648) violations.push('memory');
  if (!Number.isSafeInteger(cpu?.quota) || !Number.isSafeInteger(cpu?.period) || (cpu?.quota as number) < 1 || (cpu?.period as number) < 1 || (cpu?.quota as number) / (cpu?.period as number) > 2) violations.push('cpu');
  if (!Number.isSafeInteger(pids?.limit) || (pids?.limit as number) < 1 || (pids?.limit as number) > 128) violations.push('pids');
  const devices: Record<string, readonly [number, number]> = { '/dev/null': [1, 3], '/dev/zero': [1, 5], '/dev/full': [1, 7], '/dev/random': [1, 8], '/dev/urandom': [1, 9], '/dev/tty': [5, 0] };
  if (linux.devices !== undefined && (!Array.isArray(linux.devices) || linux.devices.some(value => { const device = object(value), number = typeof device?.path === 'string' ? devices[device.path] : undefined; return !number || device?.type !== 'c' || device.major !== number[0] || device.minor !== number[1]; }))) violations.push('devices');
  if (resources?.devices !== undefined && (!Array.isArray(resources.devices) || resources.devices.some(value => { const device = object(value); return !device || typeof device.allow !== 'boolean' || device.allow && (device.type !== 'c' || !Object.values(devices).some(([major, minor]) => device.major === major && device.minor === minor)); }))) violations.push('device_permissions');
  const hooks = object(spec.hooks);
  if (spec.hooks !== undefined && (!hooks || Object.values(hooks).some(hook => !Array.isArray(hook) || hook.length))) violations.push('hooks');
  const mounts = Array.isArray(spec.mounts) ? spec.mounts.map(object) : [];
  const inputs = mounts.filter(mount => mount?.destination === '/input');
  if (inputs.length !== 1 || inputs[0]?.type !== 'bind' || inputs[0].source !== policy.volumePath || !Array.isArray(inputs[0].options) || !inputs[0].options.includes(policy.readOnlyInput ? 'ro' : 'rw') || inputs[0].options.includes(policy.readOnlyInput ? 'rw' : 'ro')) violations.push('input_volume');
  const temporary = mounts.filter(mount => mount?.destination === '/tmp');
  if (temporary.length !== 1 || temporary[0]?.type !== 'tmpfs' || !Array.isArray(temporary[0].options) || !['nosuid', 'nodev', 'noexec', 'size=67108864'].every(flag => (temporary[0]?.options as unknown[]).includes(flag)) || temporary[0].options.some(flag => typeof flag !== 'string' || ['exec', 'suid', 'dev'].includes(flag)) || temporary[0].options.filter(flag => typeof flag === 'string' && flag.startsWith('size=')).length !== 1) violations.push('temporary_storage');
  const pseudo: Record<string, readonly string[]> = { '/proc': ['proc'], '/dev': ['tmpfs'], '/dev/pts': ['devpts'], '/dev/shm': ['tmpfs'], '/dev/mqueue': ['mqueue'], '/sys': ['sysfs'], '/sys/fs/cgroup': ['cgroup', 'cgroup2'] };
  const masked = new Set(['/proc/acpi', '/proc/asound', '/proc/bus', '/proc/fs', '/proc/irq', '/proc/kcore', '/proc/keys', '/proc/latency_stats', '/proc/sched_debug', '/proc/scsi', '/proc/sys', '/proc/sysrq-trigger', '/proc/timer_list', '/proc/timer_stats', '/sys/firmware', '/sys/devices/virtual/powercap']);
  const destinations = new Set<string>();
  for (const mount of mounts) {
    if (!mount || typeof mount.destination !== 'string' || destinations.has(mount.destination)) { violations.push('unexpected_mount'); continue; }
    const dest = mount.destination; destinations.add(dest);
    if (dest === '/input' || dest === '/tmp') continue;
    if (typeof mount.type === 'string' && pseudo[dest]?.includes(mount.type)) {
      if (dest.startsWith('/sys') && (!Array.isArray(mount.options) || !mount.options.includes('ro') || mount.options.includes('rw'))) violations.push('writable_system');
      continue;
    }
    // Engine-created, read-only resolver files and standard masked paths are
    // permitted; arbitrary host sources and runtime sockets are never admitted.
    const generated: Record<string, string> = { '/etc/resolv.conf': 'resolv.conf', '/etc/hostname': 'hostname', '/etc/hosts': 'hosts', '/etc/passwd': 'passwd', '/etc/group': 'group', '/run/.containerenv': '.containerenv', '/dev/shm': 'shm' };
    if (generated[dest] && mount.type === 'bind' && [policy.graphRoot, policy.runRoot ?? policy.graphRoot].some(root => path.posix.join(root, 'overlay-containers', policy.containerId, 'userdata', generated[dest]!) === mount.source) && Array.isArray(mount.options) && mount.options.includes('ro') && !mount.options.includes('rw')) continue;
    if (masked.has(dest) && mount.type === 'bind' && mount.source === '/dev/null' && Array.isArray(mount.options) && mount.options.includes('ro')) continue;
    violations.push('unexpected_mount');
  }
  return [...new Set(violations)];
}
