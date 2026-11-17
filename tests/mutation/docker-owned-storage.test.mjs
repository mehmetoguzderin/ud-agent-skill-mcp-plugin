import { expect, test } from 'vitest';
import { inspectOwnedDockerStorage, lockedDockerImages } from '../../scripts/quality/docker-owned-storage.mjs';

const sdk = 'sha256:' + 'a'.repeat(64), worker = 'sha256:' + 'b'.repeat(64), foreign = 'sha256:' + 'c'.repeat(64);
const owner = 'd'.repeat(32), label = 'io.github.mehmetoguzderin.ud-agent.act-owner';

function engine({ images = [
  { ID: sdk, Repository: 'localhost/ud-agent-mutation-runtime', Tag: 'ci' },
  { ID: worker, Repository: '<none>', Tag: '<none>' },
  { ID: foreign, Repository: 'ubuntu', Tag: 'latest' },
], containers = [], volumes = [], objects = {} } = {}) {
  const calls = [];
  const docker = args => {
    calls.push(args);
    if (args[0] === 'image' && args[1] === 'ls') return images.map(row => JSON.stringify(row)).join('\n');
    if (args[0] === 'image' && args[1] === 'inspect') return JSON.stringify([{ Id: args[2], Size: { [sdk]: 100, [worker]: 200, [foreign]: 300 }[args[2]] }]);
    if (args[0] === 'ps') return containers.map(row => JSON.stringify(row)).join('\n');
    if (args[0] === 'volume' && args[1] === 'ls') return volumes.map(row => JSON.stringify(row)).join('\n');
    if (['container', 'volume'].includes(args[0]) && args[1] === 'inspect') return JSON.stringify([objects[args[2]]]);
    throw new Error('unexpected command');
  };
  return { docker, calls };
}
const options = { selectedImages: [{ image_id: sdk, size_bytes: 100 }], knownImageIds: [worker] };

test('charges exact selected, tagged and receipt-bound images without touching foreign resources', () => {
  const fixture = engine({ volumes: [{ Name: 'family-backup', Labels: '' }] });
  expect(inspectOwnedDockerStorage(fixture.docker, options)).toEqual({ image_bytes: 300, image_ids: [sdk, worker], active_actions_owner: null });
  expect(fixture.calls.some(args => args.includes('rm') || args.includes('prune'))).toBe(false);
  expect(fixture.calls.some(args => args.includes(foreign))).toBe(false);
  expect(lockedDockerImages({ packs: { core: { images: { 'linux/arm64': { config_digest: worker } } } } })).toEqual([worker]);
  expect(() => lockedDockerImages({ packs: { core: { images: { broken: { config_digest: 'mutable' } } } } })).toThrow(/identity/);
});

test('unidentified dangling images and pre-existing project resources fail closed', () => {
  const dangling = engine({ images: [{ ID: sdk, Repository: 'localhost/ud-agent-sdk', Tag: 'ci' }, { ID: foreign, Repository: '<none>', Tag: '<none>' }] });
  expect(() => inspectOwnedDockerStorage(dangling.docker, options)).toThrow(/unidentified dangling/);
  const stale = engine({ volumes: [{ Name: 'ud-mutation-state-old', Labels: 'io.github.mehmetoguzderin.ud-agent.mutation=old' }], objects: { 'ud-mutation-state-old': { Name: 'ud-mutation-state-old', Labels: {} } } });
  expect(() => inspectOwnedDockerStorage(stale.docker, options)).toThrow(/owned recovery/);
  expect(stale.calls.some(args => args.includes('rm') || args.includes('prune'))).toBe(false);
  const unknown = engine({ volumes: [{ Name: 'family-backup' }] });
  expect(() => inspectOwnedDockerStorage(unknown.docker, options)).toThrow(/labels are unavailable/);
});
test('archive-backed virtual accounting may only increase the inspected daemon byte metric', () => {
  const fixture=engine();
  const charged={selectedImages:[{image_id:sdk,size_bytes:100,charged_size_bytes:500}],knownImageIds:[worker]};
  expect(inspectOwnedDockerStorage(fixture.docker,charged).image_bytes).toBe(700);
  for(const value of [99,-1,NaN,'500'])expect(()=>inspectOwnedDockerStorage(fixture.docker,{...charged,selectedImages:[{image_id:sdk,size_bytes:100,charged_size_bytes:value}]})).toThrow(/selected image/);
  expect(()=>inspectOwnedDockerStorage(fixture.docker,{...charged,selectedImages:[{image_id:sdk,size_bytes:101,charged_size_bytes:500}]})).toThrow(/bytes or identity/);
  expect(inspectOwnedDockerStorage(fixture.docker,{...charged,selectedImages:[...charged.selectedImages,{image_id:sdk,size_bytes:100,charged_size_bytes:600}]}).image_bytes).toBe(800);
});

test('only proven absent ancestor aliases tolerate an exact repeated missing-image result', () => {
  const fixture = engine();
  let failure = Object.assign(new Error('exact daemon absence'), { code: 'UD_IMAGE_ABSENT', imageId: worker });
  const docker = args => {
    if (args[0] === 'image' && args[1] === 'inspect' && args[2] === worker) throw failure;
    return fixture.docker(args);
  };
  const bound = { selectedImages: options.selectedImages, knownAbsentAncestorIds: [worker] };
  expect(inspectOwnedDockerStorage(docker, bound)).toEqual({ image_bytes: 100, image_ids: [sdk], active_actions_owner: null });
  expect(() => inspectOwnedDockerStorage(docker, options)).toThrow(/daemon absence/);
  expect(() => inspectOwnedDockerStorage(docker, { ...bound, knownAbsentAncestorIds: [worker, sdk] })).toThrow(/selected image/);
  for (const error of [new Error('permission denied'), new Error('transport failed'), Object.assign(new Error('foreign missing image'), { code: 'UD_IMAGE_ABSENT', imageId: foreign })]) {
    failure = error; expect(() => inspectOwnedDockerStorage(docker, bound)).toThrow(error.message);
  }
});

test('only exactly bound resources of the active Actions owner can coexist', () => {
  const volume = `ud-agent-act-${owner}-arm64`, id = 'e'.repeat(64);
  const active = engine({
    containers: [{ ID: id, Names: 'act-job', Labels: `${label}=${owner}` }],
    volumes: [{ Name: volume, Labels: `${label}=${owner}` }],
    objects: { [id]: { Id: id, Name: '/act-job', Config: { Labels: { [label]: owner } }, Mounts: [{ Name: volume, Destination: '/opt/hostedtoolcache' }] }, [volume]: { Name: volume, Labels: { [label]: owner } } },
  });
  expect(inspectOwnedDockerStorage(active.docker, { ...options, activeActionsOwner: owner }).active_actions_owner).toBe(owner);
  expect(() => inspectOwnedDockerStorage(active.docker, options)).toThrow(/owned recovery/);
  expect(() => inspectOwnedDockerStorage(active.docker, { ...options, activeActionsOwner: 'f'.repeat(32) })).toThrow(/owned recovery/);
});
