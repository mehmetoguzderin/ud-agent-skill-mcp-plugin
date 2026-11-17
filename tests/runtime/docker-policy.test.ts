import { describe, expect, it } from 'vitest';
import { inspectDockerJob, inspectDockerVolume } from '../../packages/coordinator/src/docker-policy.js';

const policy = { name: 'ud-agent-test-loader', jobId: 'job', imageId: `sha256:${'a'.repeat(64)}`, containerId: 'b'.repeat(64), volume: 'ud-agent-test-input', readOnlyInput: false, entrypoint: ['python'], command: ['-I', '-B', '-c', 'fixed'] };
function inspection(readOnly = false) {
  return [{ Id: 'b'.repeat(64), Name: '/ud-agent-test-loader', Image: policy.imageId,
    Config: { User: '10001:10001', Tty: false, OpenStdin: true, Entrypoint: policy.entrypoint, Cmd: policy.command, Labels: { 'io.ud-agent.job': 'job' } },
    HostConfig: { ReadonlyRootfs: true, NetworkMode: 'none', Privileged: false, CapDrop: ['ALL'], CapAdd: null, Devices: null, Binds: null, SecurityOpt: ['no-new-privileges:true'], Memory: 2 * 1024 * 1024 * 1024, NanoCpus: 2_000_000_000, PidsLimit: 128, Tmpfs: { '/tmp': 'rw,nosuid,nodev,noexec,size=67108864' } },
    Mounts: [{ Type: 'volume', Name: policy.volume, Destination: '/input', RW: !readOnly }] }];
}

describe('Docker effective worker policy', () => {
  it('accepts the expected loader and separately read-only worker', () => {
    expect(inspectDockerJob(inspection(), policy)).toEqual([]);
    expect(inspectDockerJob(inspection(true), { ...policy, readOnlyInput: true })).toEqual([]);
  });
  it('rejects different identity, privilege, mounts, commands and limits', () => {
    const item = inspection(); item[0]!.Config.User = '0:0'; item[0]!.HostConfig.Privileged = true;
    item[0]!.HostConfig.Memory = 0; item[0]!.Mounts[0]!.RW = true;
    expect(inspectDockerJob(item, { ...policy, readOnlyInput: true, command: ['other'] })).toEqual(expect.arrayContaining(['process', 'isolation', 'limits', 'mounts']));
    expect(inspectDockerJob([], policy)).toEqual(expect.arrayContaining(['identity', 'process', 'isolation', 'mounts']));
  });
  it('accepts only the exact owned local volume', () => {
    const volume = [{ Name: policy.volume, Driver: 'local', Scope: 'local', Labels: { 'io.ud-agent.job': 'job' }, Options: null }];
    expect(inspectDockerVolume(volume, policy.volume, 'job')).toBe(true);
    expect(inspectDockerVolume(volume, policy.volume, 'other')).toBe(false);
    expect(inspectDockerVolume([{ ...volume[0], Options: { device: '/host' } }], policy.volume, 'job')).toBe(false);
  });
});

type Document = Record<string, any>;
function changed(field: string, value: unknown): unknown[] {
  const item = structuredClone(inspection()) as Document[];
  const parts = field.split('.'); let current: Document = item[0]!;
  for (const part of parts.slice(0, -1)) current = current[part];
  current[parts.at(-1)!] = value;
  return item;
}
function missing(field: string): unknown[] {
  const item = structuredClone(inspection()) as Document[];
  const parts = field.split('.'); let current: Document = item[0]!;
  for (const part of parts.slice(0, -1)) current = current[part];
  delete current[parts.at(-1)!];
  return item;
}

describe('independent Docker containment field contracts', () => {
  it.each([
    ['Id', 'c'.repeat(64), 'identity'], ['Id', '', 'identity'], ['Id', 12, 'identity'],
    ['Name', '/unrelated', 'identity'], ['Image', `sha256:${'c'.repeat(64)}`, 'identity'],
    ['Config.Labels.io.ud-agent.job', 'unrelated', 'identity'],
  ].filter(([key]) => key !== 'Config.Labels.io.ud-agent.job'))('rejects isolated %s=%j with %s', (field, value, violation) => {
    expect(inspectDockerJob(changed(field as string, value), policy)).toEqual([violation]);
  });
  it('binds the complete job label even when all other fields match', () => {
    const item = inspection(); item[0]!.Config.Labels['io.ud-agent.job'] = 'unrelated';
    expect(inspectDockerJob(item, policy)).toEqual(['identity']);
    (item[0]!.Config as Document).Labels = {};
    expect(inspectDockerJob(item, policy)).toEqual(['identity']);
  });
  it.each(['Name', 'Image', 'Id'])('rejects a missing %s identity field', field => {
    expect(inspectDockerJob(missing(field), policy)).toEqual(['identity']);
  });
  it.each([
    ['Config.User', '0:0'], ['Config.User', '10001'], ['Config.Tty', true], ['Config.OpenStdin', false],
    ['Config.Entrypoint', []], ['Config.Entrypoint', ['other']], ['Config.Entrypoint', ['python', 'extra']],
    ['Config.Entrypoint', 'python'], ['Config.Entrypoint', { 0: 'python', length: 1 }],
    ['Config.Cmd', []], ['Config.Cmd', ['-I']], ['Config.Cmd', ['-I', '-B', '-c', 'changed']],
    ['Config.Cmd', ['-I', '-B', '-c', 'fixed', 'extra']], ['Config.Cmd', '-I -B -c fixed'],
  ])('rejects only the process guarantee for %s=%j', (field, value) => {
    expect(inspectDockerJob(changed(field as string, value), policy)).toEqual(['process']);
  });
  it.each(['User', 'Tty', 'OpenStdin', 'Entrypoint', 'Cmd'])('rejects missing process field %s', field => {
    expect(inspectDockerJob(missing(`Config.${field}`), policy)).toEqual(['process']);
  });
  it.each([
    ['HostConfig.ReadonlyRootfs', false], ['HostConfig.NetworkMode', 'host'], ['HostConfig.NetworkMode', 'bridge'],
    ['HostConfig.Privileged', true], ['HostConfig.CapDrop', []], ['HostConfig.CapDrop', ['CAP_SYS_ADMIN']],
    ['HostConfig.CapDrop', 'ALL'], ['HostConfig.CapAdd', ['CAP_SYS_ADMIN']], ['HostConfig.CapAdd', {}],
    ['HostConfig.Devices', [{ PathOnHost: '/dev/sda', PathInContainer: '/dev/sda' }]],
    ['HostConfig.Devices', 'none'], ['HostConfig.Binds', ['/var/run/docker.sock:/socket']], ['HostConfig.Binds', {}],
  ])('rejects isolated daemon control %s=%j', (field, value) => {
    expect(inspectDockerJob(changed(field as string, value), policy)).toEqual(['isolation']);
  });
  it.each(['ReadonlyRootfs', 'NetworkMode', 'Privileged', 'CapDrop'])('rejects missing isolation field %s', field => {
    expect(inspectDockerJob(missing(`HostConfig.${field}`), policy)).toEqual(['isolation']);
  });
  it.each([null, [], undefined])('accepts daemon empty-list encoding %j', value => {
    const item = changed('HostConfig.CapAdd', value) as Document[];
    item[0]!.HostConfig.Devices = value; item[0]!.HostConfig.Binds = value;
    expect(inspectDockerJob(item, policy)).toEqual([]);
  });
  it.each([
    ['HostConfig.Memory', 0], ['HostConfig.Memory', 2147483649], ['HostConfig.Memory', 2147483647],
    ['HostConfig.NanoCpus', 0], ['HostConfig.NanoCpus', 2000000001], ['HostConfig.NanoCpus', 1999999999],
    ['HostConfig.PidsLimit', -1], ['HostConfig.PidsLimit', 0], ['HostConfig.PidsLimit', 127], ['HostConfig.PidsLimit', 129],
  ])('rejects independently changed resource bound %s=%j', (field, value) => {
    expect(inspectDockerJob(changed(field as string, value), policy)).toEqual(['limits']);
  });
  it.each(['Memory', 'NanoCpus', 'PidsLimit'])('rejects missing resource bound %s', field => {
    expect(inspectDockerJob(missing(`HostConfig.${field}`), policy)).toEqual(['limits']);
  });
  it.each([
    [[], ['no_new_privileges']],
    [['seccomp=unconfined'], ['no_new_privileges', 'seccomp', 'security_options']],
    [['no-new-privileges:false'], ['no_new_privileges', 'security_options']],
    [['no-new-privileges:true', 'apparmor=unconfined'], ['security_options']],
    [['no-new-privileges:true', false], ['security_options']],
    [undefined, ['no_new_privileges']],
  ])('checks every security option and actual no-new-privileges %j', (value, violations) => {
    expect(inspectDockerJob(changed('HostConfig.SecurityOpt', value), policy)).toEqual(violations);
  });
  it.each(['no-new-privileges', 'no-new-privileges:true'])('accepts Docker spelling %s', value => {
    expect(inspectDockerJob(changed('HostConfig.SecurityOpt', [value]), policy)).toEqual([]);
  });
  const profile = { defaultAction: 'SCMP_ACT_ERRNO', architectures: ['SCMP_ARCH_AARCH64'], syscalls: [] };
  it('requires exactly the admitted seccomp profile alongside no-new-privileges', () => {
    const selected = { ...policy, seccomp: profile };
    for (const noPrivilege of ['no-new-privileges', 'no-new-privileges:true']) expect(inspectDockerJob(changed('HostConfig.SecurityOpt', [noPrivilege, `seccomp=${JSON.stringify(profile)}`]), selected)).toEqual([]);
    for (const profiles of [[], ['seccomp={}'], ['seccomp=not-json'], [`seccomp=${JSON.stringify(profile)}`, `seccomp=${JSON.stringify(profile)}`], ['prefixseccomp=unconfined'], ['seccomp=']]) {
      expect(inspectDockerJob(changed('HostConfig.SecurityOpt', ['no-new-privileges:true', ...profiles]), selected)).toContain('seccomp');
    }
    expect(inspectDockerJob(changed('HostConfig.SecurityOpt', ['no-new-privileges:true', `seccomp=${JSON.stringify(profile)}`, 'apparmor=unconfined']), selected)).toEqual(['security_options']);
    expect(inspectDockerJob(changed('HostConfig.SecurityOpt', ['no-new-privileges:true', `seccomp=${JSON.stringify({ ...profile, defaultAction: 'SCMP_ACT_ALLOW' })}`]), selected)).toEqual(['seccomp']);
  });
  it.each([
    [], [{ Type: 'bind', Name: policy.volume, Destination: '/input', RW: true }],
    [{ Type: 'volume', Name: 'unrelated', Destination: '/input', RW: true }],
    [{ Type: 'volume', Name: policy.volume, Destination: '/other', RW: true }],
    [{ Type: 'volume', Name: policy.volume, Destination: '/input', RW: false }],
    [{ Type: 'volume', Name: policy.volume, Destination: '/input', RW: true }, { Type: 'bind', Destination: '/socket', RW: true }],
  ].map(value => [value]))('rejects an independently changed mount manifest %j', mounts => {
    expect(inspectDockerJob(changed('Mounts', mounts), policy)).toEqual(['mounts']);
  });
  it('allows the separately confined tmpfs mount entry without adding a data volume', () => {
    const item = inspection() as Document[];
    item[0]!.Mounts.push({ Type: 'tmpfs', Destination: '/tmp', RW: true });
    expect(inspectDockerJob(item, policy)).toEqual([]);
  });
  it.each([
    undefined, null, {}, { '/elsewhere': 'rw,nosuid,nodev,noexec,size=67108864' },
    { '/tmp': false }, { '/tmp': 'rw,nodev,noexec,size=67108864' },
    { '/tmp': 'rw,nosuid,noexec,size=67108864' }, { '/tmp': 'rw,nosuid,nodev,size=67108864' },
    { '/tmp': 'rw,nosuid,nodev,noexec,size=67108864', '/elsewhere': 'rw' },
  ])('requires a confined tmpfs scratch directory %j', tmpfs => {
    expect(inspectDockerJob(changed('HostConfig.Tmpfs', tmpfs), policy)).toEqual(['tmpfs']);
  });
  it.each([undefined, null, {}, [], [null], [inspection()[0], inspection()[0]]].map(value => [value]))('rejects malformed inspection envelopes %j', value => {
    expect(inspectDockerJob(value, policy)).toEqual(['identity', 'process', 'isolation', 'no_new_privileges', 'limits', 'mounts', 'tmpfs']);
  });
});

describe('owned Docker volume field contracts', () => {
  const volume = { Name: policy.volume, Driver: 'local', Scope: 'local', Labels: { 'io.ud-agent.job': policy.jobId }, Options: null };
  it.each([null, undefined, {}])('accepts only empty local driver options %j', Options => {
    expect(inspectDockerVolume([{ ...volume, Options }], policy.volume, policy.jobId)).toBe(true);
  });
  it.each([
    undefined, null, {}, [], [null], [volume, volume],
    [{ ...volume, Name: 'unrelated' }], [{ ...volume, Driver: 'nfs' }], [{ ...volume, Scope: 'global' }],
    [{ ...volume, Labels: undefined }], [{ ...volume, Labels: {} }], [{ ...volume, Labels: { 'io.ud-agent.job': 'unrelated' } }],
    [{ ...volume, Options: [] }], [{ ...volume, Options: '' }], [{ ...volume, Options: 1 }], [{ ...volume, Options: true }], [{ ...volume, Options: { device: '/private' } }],
  ].map(value => [value]))('rejects unrelated or malformed volume metadata %j', value => {
    expect(inspectDockerVolume(value, policy.volume, policy.jobId)).toBe(false);
  });
});

describe('Docker scratch bounds and namespace overrides', () => {
  it.each([
    'rw,nosuid,nodev,noexec', 'rw,nosuid,nodev,noexec,size=67108865',
    'rw,nosuid,nodev,noexec,size=0', 'rw,nosuid,nodev,noexec,size=-1',
    'rw,nosuid,nodev,noexec,size=67108864,exec', 'rw,nosuid,nodev,noexec,size=67108864,dev',
    'ro,nosuid,nodev,noexec,size=67108864', 'rw,nosuid,nodev,noexec,size=67108864,size=67108864',
    'rw,nosuid,nodev,noexec,size=NaN', 'rw,nosuid,nodev,noexec,size=99999999999999999999999999999999',
  ])('rejects unbounded or contradicted tmpfs options %s', value => {
    expect(inspectDockerJob(changed('HostConfig.Tmpfs', { '/tmp': value }), policy)).toEqual(['tmpfs']);
  });
  it.each(['rw,nosuid,nodev,noexec,size=1', 'size=67108864,nodev,noexec,nosuid,rw'])('accepts bounded scratch options %s', value => {
    expect(inspectDockerJob(changed('HostConfig.Tmpfs', { '/tmp': value }), policy)).toEqual([]);
  });
  it.each(['PidMode', 'IpcMode', 'UTSMode', 'CgroupnsMode'])('rejects shared %s independently of the network', field => {
    for (const mode of ['host', 'container:unrelated']) expect(inspectDockerJob(changed(`HostConfig.${field}`, mode), policy)).toEqual(['namespaces']);
    for (const mode of ['', 'private']) expect(inspectDockerJob(changed(`HostConfig.${field}`, mode), policy)).toEqual([]);
  });
  it.each(['DeviceRequests', 'DeviceCgroupRules'])('rejects daemon device grants through %s', field => {
    expect(inspectDockerJob(changed(`HostConfig.${field}`, ['extra device permission']), policy)).toEqual(['devices']);
  });
  it.each([{ Type: 'tmpfs', Destination: '/other', RW: true }, { Type: 'tmpfs', Destination: '/tmp', RW: false }])('rejects scratch mounts outside the verified scratch contract %j', mount => {
    const item = inspection() as Document[]; item[0]!.Mounts.push(mount);
    expect(inspectDockerJob(item, policy)).toEqual(['mounts']);
  });
});

describe('Docker malformed native metadata boundaries', () => {
  it.each(['prefix' + 'a'.repeat(64), 'a'.repeat(64) + 'suffix', 'a'.repeat(63), 'A'.repeat(64)])('rejects even matching malformed container identity %s', containerId => {
    expect(inspectDockerJob(changed('Id', containerId), { ...policy, containerId })).toEqual(['identity']);
  });
  it('does not infer an owned label from absent native labels', () => {
    expect(inspectDockerJob(missing('Config.Labels'), policy)).toEqual(['identity']);
  });
  it.each(['rw,nosuid,nodev,noexec,size=1suffix', 'rw,nosuid,nodev,noexec,prefixsize=1'])('requires the entire numeric scratch bound %s', value => {
    expect(inspectDockerJob(changed('HostConfig.Tmpfs', { '/tmp': value }), policy)).toEqual(['tmpfs']);
  });
  it('rejects non-string security options with an admitted seccomp profile', () => {
    const profile = { defaultAction: 'SCMP_ACT_ERRNO', syscalls: [] };
    expect(inspectDockerJob(changed('HostConfig.SecurityOpt', ['no-new-privileges', `seccomp=${JSON.stringify(profile)}`, false]), { ...policy, seccomp: profile })).toEqual(['security_options']);
  });
  it('inspects each malformed mount without losing the input-volume requirement', () => {
    expect(inspectDockerJob(changed('Mounts', [null]), policy)).toEqual(['mounts']);
    expect(inspectDockerJob(missing('Mounts'), policy)).toEqual(['mounts']);
  });
});

describe('Docker JSON type and numeric-form boundaries', () => {
  it('does not treat an array-like JSON object as a native inspection array', () => {
    const envelope = { 0: inspection()[0], length: 1 };
    expect(inspectDockerJob(envelope, policy)).toEqual(['identity', 'process', 'isolation', 'no_new_privileges', 'limits', 'mounts', 'tmpfs']);
    const volume = { Name: policy.volume, Driver: 'local', Scope: 'local', Labels: { 'io.ud-agent.job': policy.jobId }, Options: null };
    expect(inspectDockerVolume({ 0: volume, length: 1 }, policy.volume, policy.jobId)).toBe(false);
  });
  it.each(['Config.Entrypoint', 'Config.Cmd'])('does not treat an array-like %s as a command vector', field => {
    const data = field.endsWith('Cmd') ? policy.command : policy.entrypoint;
    expect(inspectDockerJob(changed(field, { ...data, length: data.length }), policy)).toEqual(['process']);
  });
  it.each(['HostConfig.CapAdd', 'HostConfig.Devices', 'HostConfig.Binds'])('does not accept a zero-length object as an empty permission list in %s', field => {
    expect(inspectDockerJob(changed(field, { length: 0 }), policy)).toEqual(['isolation']);
  });
  it.each(['rw,nosuid,nodev,noexec,size=1e3', 'rw,nosuid,nodev,noexec,size=1.5'])('requires an integer decimal scratch size %s', value => {
    expect(inspectDockerJob(changed('HostConfig.Tmpfs', { '/tmp': value }), policy)).toEqual(['tmpfs']);
  });
});

describe('Docker scalar types remain explicit after safe coercion', () => {
  it('rejects boxed scratch strings instead of silently coercing metadata', () => {
    expect(inspectDockerJob(changed('HostConfig.Tmpfs', { '/tmp': new String('rw,nosuid,nodev,noexec,size=67108864') }), policy)).toEqual(['tmpfs']);
  });
  it('does not inspect array-like security-option objects as accepted vectors', () => {
    expect(inspectDockerJob(changed('HostConfig.SecurityOpt', { 0: 'seccomp=unconfined', length: 1 }), policy)).toEqual(['no_new_privileges']);
  });
  it('rejects boxed security-option strings', () => {
    expect(inspectDockerJob(changed('HostConfig.SecurityOpt', ['no-new-privileges', new String('no-new-privileges')]), policy)).toEqual(['security_options']);
  });
});

describe('Docker JSON values with shadowed conversion methods', () => {
  it('rejects an object identity without invoking its own conversion properties', () => {
    const metadata = JSON.parse('{"toString":null,"valueOf":null}');
    expect(inspectDockerJob(changed('Id', metadata), policy)).toEqual(['identity']);
  });
});
