/** Fixed internal probe. It executes only against a product-authored fixture. */
export const PODMAN_PROBE_SCRIPT = String.raw`
import errno, json, os, resource

def read(path):
    with open(path, 'r', encoding='utf-8') as stream:
        return stream.read()

status = {}
for line in read('/proc/self/status').splitlines():
    if ':' in line:
        key, value = line.split(':', 1)
        status[key] = value.strip()

mounts = {}
for line in read('/proc/self/mountinfo').splitlines():
    fields = line.split(' - ', 1)[0].split()
    if len(fields) > 5:
        mounts[fields[4]] = fields[5].split(',')

interfaces = sorted(os.listdir('/sys/class/net'))
routes = [line.split() for line in read('/proc/net/route').splitlines()[1:]]
has_default_route = any(len(row) > 1 and row[1] == '00000000' for row in routes)
try:
    ipv6_routes = [line.split() for line in read('/proc/net/ipv6_route').splitlines()]
except FileNotFoundError:
    ipv6_routes = []
has_ipv6_default = any(len(row) > 1 and row[0] == '0' * 32 and row[1] == '00' and row[-1] != 'lo' for row in ipv6_routes)

write_errno = None
try:
    fd = os.open('/work/.ud-agent-probe-write', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(fd)
    os.unlink('/work/.ud-agent-probe-write')
except OSError as exc:
    write_errno = exc.errno

memory = read('/sys/fs/cgroup/memory.max').strip()
pids = read('/sys/fs/cgroup/pids.max').strip()
cpu = read('/sys/fs/cgroup/cpu.max').strip().split()
soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)

result = {
    'schema_version': 1,
    'uid': os.getuid(), 'gid': os.getgid(), 'euid': os.geteuid(), 'egid': os.getegid(),
    'interfaces': interfaces,
    'default_route': has_default_route or has_ipv6_default,
    'root_readonly': 'ro' in mounts.get('/', []),
    'snapshot_readonly': 'ro' in mounts.get('/work', []) and write_errno == errno.EROFS,
    'no_new_privileges': status.get('NoNewPrivs') == '1',
    'capabilities_dropped': int(status.get('CapEff', '-1'), 16) == 0 and int(status.get('CapBnd', '-1'), 16) == 0,
    'seccomp_enforced': status.get('Seccomp') == '2',
    'memory_max': int(memory) if memory.isdigit() else None,
    'pids_max': int(pids) if pids.isdigit() else None,
    'cpu_quota': int(cpu[0]) if len(cpu) == 2 and cpu[0].isdigit() else None,
    'cpu_period': int(cpu[1]) if len(cpu) == 2 and cpu[1].isdigit() else None,
    'nofile_soft': soft, 'nofile_hard': hard,
}
print(json.dumps(result, separators=(',', ':')))
`;

export function validateLiveProbeOutput(raw: unknown): string[] {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return ['invalid_probe_output'];
  const result = raw as Record<string, unknown>; const failures: string[] = [];
  if (result.schema_version !== 1) failures.push('probe_schema');
  if (result.uid !== 10001 || result.euid !== 10001 || result.gid !== 10001 || result.egid !== 10001) failures.push('worker_uid');
  if (!Array.isArray(result.interfaces) || result.interfaces.some(item => item !== 'lo') || result.default_route !== false) failures.push('network_isolation');
  if (result.root_readonly !== true || result.snapshot_readonly !== true) failures.push('read_only_mounts');
  if (result.no_new_privileges !== true || result.capabilities_dropped !== true || result.seccomp_enforced !== true) failures.push('process_confinement');
  if (!Number.isSafeInteger(result.memory_max) || (result.memory_max as number) < 1 || (result.memory_max as number) > 2_147_483_648) failures.push('memory_limit');
  if (!Number.isSafeInteger(result.pids_max) || (result.pids_max as number) < 1 || (result.pids_max as number) > 128) failures.push('pid_limit');
  if (!Number.isSafeInteger(result.cpu_quota) || !Number.isSafeInteger(result.cpu_period) || (result.cpu_quota as number) < 1 || (result.cpu_period as number) < 1 || (result.cpu_quota as number) / (result.cpu_period as number) > 2) failures.push('cpu_limit');
  if (!Number.isSafeInteger(result.nofile_soft) || !Number.isSafeInteger(result.nofile_hard) || (result.nofile_soft as number) < 1 || (result.nofile_hard as number) > 1024 || (result.nofile_soft as number) > (result.nofile_hard as number)) failures.push('file_limit');
  return failures;
}
