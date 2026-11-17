import path from 'node:path';
import type { ImageReceipt } from './receipt.js';
import { PODMAN_PROBE_SCRIPT } from './podman-probe-script.js';

export type PodmanJob = { name: string; snapshotDirectory: string; hooksDirectory: string; defaultMountsFile: string; seccompProfile: string; image: ImageReceipt; expectedEnvironment: readonly string[]; purpose?: 'probe' | 'validation'; engineMode?: 'rootless' | 'rootful' };

/** Build an argv only from installed policy and broker-owned paths. */
export function podmanCreateArgs(job: PodmanJob): string[] {
  if (!/^ud-agent-[0-9a-f-]{36}$/.test(job.name)) throw new Error('Invalid owned job identifier.');
  if (job.engineMode !== undefined && !['rootless', 'rootful'].includes(job.engineMode)) throw new Error('Invalid Podman engine mode.');
  for (const location of [job.snapshotDirectory, job.hooksDirectory, job.defaultMountsFile, job.seccompProfile]) {
    if (!path.isAbsolute(location) || /[,\0\r\n]/.test(location)) throw new Error('Invalid product-owned runtime path.');
  }
  if (!/^sha256:[0-9a-f]{64}$/.test(job.image.digest) || !/^ghcr\.io\/mehmetoguzderin\/[a-z0-9._/-]+@sha256:[0-9a-f]{64}$/.test(job.image.reference) || !job.image.reference.endsWith(`@${job.image.digest}`)) throw new Error('Worker image is not the locked digest.');
  return [
    '--remote=false', `--hooks-dir=${job.hooksDirectory}`, `--default-mounts-file=${job.defaultMountsFile}`, 'create', '--name', job.name,
    `--label=io.ud-agent.job=${job.name}`, '--interactive', '--user=10001:10001',
    ...(job.engineMode === 'rootful' ? [] : ['--userns=keep-id:uid=10001,gid=10001']), '--network=none', '--pid=private', '--ipc=private', '--cgroupns=private',
    '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges', `--security-opt=seccomp=${job.seccompProfile}`,
    '--pids-limit=128', '--memory=2147483648', '--cpus=2', '--ulimit=nofile=1024:1024',
    '--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=67108864',
    `--mount=type=bind,source=${job.snapshotDirectory},destination=/work,readonly`,
    '--workdir=/work', '--pull=never', '--restart=no',
    ...(job.purpose === 'probe' ? ['--entrypoint=/usr/local/bin/python', job.image.reference, '-c', PODMAN_PROBE_SCRIPT] : [job.image.reference]),
  ];
}

export function podmanIsLocalRootless(info: unknown, expectedArch: 'amd64' | 'arm64'): boolean {
  return podmanLocalMode(info, expectedArch) === 'rootless';
}

/** Distinguish daemon privilege from the worker's separately checked policy. */
export function podmanLocalMode(info: unknown, expectedArch: 'amd64' | 'arm64'): 'rootless' | 'rootful' | undefined {
  if (!info || typeof info !== 'object' || Array.isArray(info)) return undefined;
  const host = (info as Record<string, unknown>).host;
  if (!host || typeof host !== 'object' || Array.isArray(host)) return undefined;
  const item = host as Record<string, unknown>;
  if (item.arch !== expectedArch || !item.security || typeof item.security !== 'object' || Array.isArray(item.security)) return undefined;
  const rootless = (item.security as Record<string, unknown>).rootless;
  return rootless === true ? 'rootless' : rootless === false ? 'rootful' : undefined;
}

export function inspectPodmanJob(raw: unknown, job: PodmanJob, containerId: string, engineGraphRoot: string): { configPath?: string; failures: string[] } {
  const failures: string[] = [];
  const entry = Array.isArray(raw) && raw.length === 1 ? object(raw[0]) : undefined;
  if (!entry || !/^[0-9a-f]{64}$/.test(containerId)) return { failures: ['invalid_inspection'] };
  const config = object(entry.Config); const host = object(entry.HostConfig); const state = object(entry.State); const labels = object(config?.Labels);
  if (entry.Id !== containerId || entry.Name !== job.name || labels?.['io.ud-agent.job'] !== job.name) failures.push('job_ownership');
  if (entry.ImageDigest !== job.image.digest) failures.push('image_digest');
  if (state?.Status !== 'created') failures.push('job_state');
  if (config?.User !== '10001:10001' || config?.Tty !== false || config?.OpenStdin !== true) failures.push('process_configuration');
  if (host?.Privileged !== false || host?.ReadonlyRootfs !== true || host?.NetworkMode !== 'none') failures.push('host_isolation');
  if (!Array.isArray(host?.Devices) || host.Devices.length !== 0 || host.PublishAllPorts !== false) failures.push('host_devices_or_ports');
  const caps = entry.EffectiveCaps; const bounding = entry.BoundingCaps;
  if (!Array.isArray(caps) || caps.length !== 0 || !Array.isArray(bounding) || bounding.length !== 0) failures.push('capabilities');
  const candidate = entry.OCIConfigPath;
  if (typeof candidate !== 'string' || !path.isAbsolute(candidate) || !path.isAbsolute(engineGraphRoot)) failures.push('oci_config_path');
  else {
    const relative = path.relative(engineGraphRoot, candidate);
    if (!relative || relative === '..' || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) failures.push('oci_config_path');
  }
  return { ...(failures.includes('oci_config_path') || typeof candidate !== 'string' ? {} : { configPath: candidate }), failures };
}

function object(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : undefined;
}
function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') return `{${Object.entries(value).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0).map(([key, item]) => `${JSON.stringify(key)}:${canonical(item)}`).join(',')}}`;
  return JSON.stringify(value);
}

/** Independently inspect effective OCI state; requested flags alone are not proof. */
export function validatePodmanOciSpec(spec: unknown, job: PodmanJob, expectedSeccomp: unknown): string[] {
  const failures: string[] = [];
  const source = object(spec); const processConfig = object(source?.process); const root = object(source?.root); const linux = object(source?.linux);
  if (!source || !processConfig || !root || !linux) return ['missing_oci_spec'];
  if (root.readonly !== true) failures.push('writable_root');
  const user = object(processConfig.user);
  if (user?.uid !== 10001 || user?.gid !== 10001) failures.push('worker_uid');
  if (processConfig.terminal !== false || processConfig.noNewPrivileges !== true) failures.push('process_privileges');
  if (processConfig.cwd !== '/work') failures.push('worker_directory');
  const capabilities = object(processConfig.capabilities);
  for (const key of ['bounding', 'effective', 'inheritable', 'permitted', 'ambient']) {
    if (!Array.isArray(capabilities?.[key]) || (capabilities[key] as unknown[]).length !== 0) { failures.push('capabilities'); break; }
  }
  const args = processConfig.args;
  const expectedCommand = job.purpose === 'probe' ? ['/usr/local/bin/python', '-c', PODMAN_PROBE_SCRIPT] : ['python', '-m', 'ud_agent.worker'];
  const alternateCommand = job.purpose === 'probe' ? expectedCommand : ['/usr/local/bin/python', '-m', 'ud_agent.worker'];
  if (!Array.isArray(args) || (canonical(args) !== canonical(expectedCommand) && canonical(args) !== canonical(alternateCommand))) failures.push('worker_command');
  const environment = processConfig.env;
  const environmentNames = Array.isArray(environment) && environment.every(value => typeof value === 'string') ? environment.map(value => (value as string).split('=', 1)[0]) : [];
  if (!Array.isArray(environment) || environment.some(value => typeof value !== 'string' || !/^[A-Za-z_][A-Za-z0-9_]*=/.test(value)) || new Set(environmentNames).size !== environment.length || canonical([...environment].sort()) !== canonical([...job.expectedEnvironment].sort())) failures.push('injected_environment');
  if (user?.additionalGids !== undefined && (!Array.isArray(user.additionalGids) || user.additionalGids.length !== 0)) failures.push('supplementary_groups');
  const rlimits = processConfig.rlimits;
  const nofile = Array.isArray(rlimits) ? rlimits.map(object).filter(item => item?.type === 'RLIMIT_NOFILE') : [];
  if (nofile.length !== 1 || !Number.isSafeInteger(nofile[0]?.hard) || !Number.isSafeInteger(nofile[0]?.soft) || (nofile[0]?.soft as number) < 1 || (nofile[0]?.hard as number) > 1024 || (nofile[0]?.soft as number) > (nofile[0]?.hard as number)) failures.push('file_limit');
  const namespaces = linux.namespaces;
  if (!Array.isArray(namespaces)) failures.push('namespaces');
  else for (const required of ['pid', 'ipc', 'network', 'cgroup', ...(job.engineMode === 'rootful' ? [] : ['user'])]) {
    const matches = namespaces.filter(value => object(value)?.type === required);
    if (matches.length !== 1 || object(matches[0])?.path) failures.push(`namespace_${required}`);
  }
  if (job.engineMode === 'rootful' && Array.isArray(namespaces)) {
    const user = namespaces.filter(value => object(value)?.type === 'user');
    if (user.length > 1 || (user.length === 1 && object(user[0])?.path)) failures.push('namespace_user');
  }
  if (!object(linux.seccomp) || !object(expectedSeccomp) || canonical(linux.seccomp) !== canonical(expectedSeccomp)) failures.push('seccomp');
  const resources = object(linux.resources); const memory = object(resources?.memory); const cpu = object(resources?.cpu); const pids = object(resources?.pids);
  if (!Number.isSafeInteger(memory?.limit) || (memory?.limit as number) < 1 || (memory?.limit as number) > 2_147_483_648) failures.push('memory_limit');
  if (!Number.isSafeInteger(cpu?.quota) || !Number.isSafeInteger(cpu?.period) || (cpu?.period as number) < 1 || (cpu?.quota as number) < 1 || (cpu?.quota as number) / (cpu?.period as number) > 2) failures.push('cpu_limit');
  if (!Number.isSafeInteger(pids?.limit) || (pids?.limit as number) < 1 || (pids?.limit as number) > 128) failures.push('pid_limit');
  const deviceNumbers: Record<string, [number, number]> = {
    '/dev/null': [1, 3], '/dev/zero': [1, 5], '/dev/full': [1, 7], '/dev/random': [1, 8], '/dev/urandom': [1, 9], '/dev/tty': [5, 0], '/dev/console': [5, 1],
  };
  if (linux.devices !== undefined && (!Array.isArray(linux.devices) || linux.devices.some(value => {
    const device = object(value); const numbers = typeof device?.path === 'string' ? deviceNumbers[device.path] : undefined;
    return !device || !numbers || device.type !== 'c' || device.major !== numbers[0] || device.minor !== numbers[1];
  }))) failures.push('host_devices');
  if (resources?.devices !== undefined && (!Array.isArray(resources.devices) || resources.devices.some(value => {
    const device = object(value);
    if (!device || typeof device.allow !== 'boolean') return true;
    if (!device.allow) return false;
    return device.type !== 'c' || !Object.values(deviceNumbers).some(([major, minor]) => device.major === major && device.minor === minor);
  }))) failures.push('device_permissions');
  const hooks = object(source.hooks);
  if ((source.hooks !== undefined && !hooks) || (hooks && Object.values(hooks).some(value => !Array.isArray(value) || value.length > 0))) failures.push('injected_hooks');
  const mounts = source.mounts;
  if (!Array.isArray(mounts)) failures.push('mounts');
  else {
    const binds = mounts.map(object).filter(item => item?.type === 'bind');
    if (binds.length !== 1 || binds[0]?.source !== job.snapshotDirectory || binds[0]?.destination !== '/work' || !Array.isArray(binds[0]?.options) || !(binds[0].options as unknown[]).includes('ro') || (binds[0].options as unknown[]).includes('rw')) failures.push('bind_mounts');
    const allowedTypes: Record<string, string[]> = { '/work': ['bind'], '/proc': ['proc'], '/dev': ['tmpfs'], '/dev/pts': ['devpts'], '/dev/shm': ['tmpfs'], '/dev/mqueue': ['mqueue'], '/sys': ['sysfs'], '/sys/fs/cgroup': ['cgroup', 'cgroup2'], '/tmp': ['tmpfs'] };
    const destinations = new Set<string>();
    if (mounts.some(item => {
      const mount = object(item);
      if (!mount || typeof mount.destination !== 'string' || typeof mount.type !== 'string' || !allowedTypes[mount.destination]?.includes(mount.type) || destinations.has(mount.destination)) return true;
      destinations.add(mount.destination);
      return false;
    })) failures.push('unexpected_mounts');
    const temporary = mounts.map(object).find(item => item?.destination === '/tmp');
    const tmpOptions = temporary?.options;
    if (!Array.isArray(tmpOptions) || !['nosuid', 'nodev', 'noexec', 'size=67108864'].every(option => tmpOptions.includes(option)) || tmpOptions.some(option => typeof option !== 'string' || ['suid', 'dev', 'exec'].includes(option)) || tmpOptions.filter(option => typeof option === 'string' && option.startsWith('size=')).length !== 1) failures.push('temporary_storage');
    const system = mounts.map(object).find(item => item?.destination === '/sys');
    if (system && (!Array.isArray(system.options) || !system.options.includes('ro') || system.options.includes('rw'))) failures.push('writable_system_mount');
  }
  return failures;
}
