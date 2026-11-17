/** Read-only accounting for project Docker resources before a quality job. MIT. */
const LABELS = ['io.ud-agent.job', 'io.ud-agent.perl-build', 'io.ud-agent.perl-probe', 'io.github.mehmetoguzderin.ud-agent.mutation', 'io.github.mehmetoguzderin.ud-agent.act-owner', 'io.github.mehmetoguzderin.ud-agent.sdk-bootstrap'];
const ACT = 'io.github.mehmetoguzderin.ud-agent.act-owner';
const MUTATION = 'io.github.mehmetoguzderin.ud-agent.mutation';
const SHA = /^sha256:[0-9a-f]{64}$/;
const fail = message => { throw new Error('Docker storage admission: ' + message); };

function rows(text) {
  if (typeof text !== 'string') fail('engine inventory is unavailable');
  const result = text.trim() ? text.trim().split(/\r?\n/).map(line => JSON.parse(line)) : [];
  if (result.length > 50000 || result.some(row => !row || typeof row !== 'object')) fail('engine inventory is not bounded');
  return result;
}
function labelKeys(labels) {
  if (labels === null || labels === '<none>' || labels === '') return [];
  if (typeof labels === 'string') return labels.split(',').map(value => value.split('=', 1)[0]);
  if (labels && typeof labels === 'object' && !Array.isArray(labels)) return Object.keys(labels);
  return fail('resource labels are unavailable');
}
function activeActionsResource(item, kind, owner) {
  if (!/^[a-f0-9]{32}$/.test(owner ?? '')) return false;
  const labels = kind === 'container' ? item.Config?.Labels : item.Labels;
  if (labels?.[ACT] !== owner) return false;
  const name = (item.Name ?? '').replace(/^\//, ''), mutation = labels[MUTATION];
  if (/^[a-f0-9-]{36}$/.test(mutation ?? '')) {
    const names = kind === 'container' ? [`ud-mutation-input-${mutation}`, `ud-mutation-job-${mutation}`, `ud-mutation-job-${mutation}-usage`, `ud-mutation-job-${mutation}-input-usage`, `ud-mutation-job-${mutation}-evidence`] : [`ud-mutation-input-${mutation}`, `ud-mutation-state-${mutation}`];
    return names.includes(name);
  }
  const caches = [`ud-agent-act-${owner}-arm64`, `ud-agent-act-${owner}-amd64`];
  if (kind === 'volume') return caches.includes(name);
  return item.Mounts?.some(mount => caches.includes(mount.Name) && mount.Destination === '/opt/hostedtoolcache') ||
    name === `ud-agent-act-init-${owner}` && item.Mounts?.some(mount => caches.includes(mount.Name) && mount.Destination === '/cache') ||
    name === `ud-agent-act-probe-${owner}` && item.Mounts?.some(mount => mount.Destination === '/engine.sock') ||
    new RegExp('^ud-agent-act-meter-' + owner + '-[0-9]+$').test(name) && item.Mounts?.some(mount => mount.Destination === '/cache' && mount.RW === false);
}

/** A runtime lock's image configuration digests are Docker image identities. */
export function lockedDockerImages(lock) {
  const ids = new Set();
  for (const pack of Object.values(lock?.packs ?? {})) for (const image of Object.values(pack?.images ?? {})) {
    if (image.config_digest !== undefined) { if (!SHA.test(image.config_digest)) fail('runtime image configuration identity is invalid'); ids.add(image.config_digest); }
  }
  return [...ids];
}

/** Counts known project images conservatively and refuses stale or ambiguous
 * resources. No container, volume, image or shared service is changed. */
/** @param {function(string[]):string} docker @param {{selectedImages:{image_id:string,size_bytes:number,charged_size_bytes?:number}[],knownImageIds?:string[],knownAbsentAncestorIds?:string[],activeActionsOwner?:string}} options */
export function inspectOwnedDockerStorage(docker, { selectedImages, knownImageIds = [], knownAbsentAncestorIds = [], activeActionsOwner } = {}) {
  if (typeof docker !== 'function' || !Array.isArray(selectedImages) || !Array.isArray(knownImageIds) || knownImageIds.some(id => !SHA.test(id)) || !Array.isArray(knownAbsentAncestorIds) || knownAbsentAncestorIds.some(id => !SHA.test(id)) || activeActionsOwner !== undefined && !/^[a-f0-9]{32}$/.test(activeActionsOwner)) fail('image or active owner authority is invalid');
  const selected = new Map();
  for (const image of selectedImages) {
    const charged = image?.charged_size_bytes ?? image?.size_bytes;
    if (!SHA.test(image?.image_id ?? '') || !Number.isSafeInteger(image.size_bytes) || image.size_bytes < 0 || !Number.isSafeInteger(charged) || charged < image.size_bytes || selected.has(image.image_id) && selected.get(image.image_id).size !== image.size_bytes) fail('selected image identity or size is invalid');
    selected.set(image.image_id, { size: image.size_bytes, charged: Math.max(charged, selected.get(image.image_id)?.charged ?? 0) });
  }
  if (knownAbsentAncestorIds.some(id => selected.has(id))) fail('a selected image cannot be an absent ancestor');
  const absentAncestors = new Set(knownAbsentAncestorIds);
  const known = new Set([...knownImageIds, ...selected.keys(), ...absentAncestors]), owned = new Map(), seen = new Set();
  for (const row of rows(docker(['image', 'ls', '--all', '--no-trunc', '--format', '{{json .}}']))) {
    const id = row.ID, repo = row.Repository;
    if (!SHA.test(id ?? '') || typeof repo !== 'string' || typeof row.Tag !== 'string') fail('image inventory lacks exact identities');
    const project = repo.startsWith('localhost/ud-agent-') || repo.startsWith('ghcr.io/mehmetoguzderin/ud-agent-skill-mcp-plugin');
    if (repo === '<none>' && row.Tag === '<none>' && !known.has(id)) fail('unidentified dangling image may belong to the project');
    if (!known.has(id) && !project || seen.has(id)) continue;
    seen.add(id);
    let images;
    try { images = JSON.parse(docker(['image', 'inspect', id])); }
    catch (error) {
      // Docker may retain an intermediate alias in image ls after deleting
      // its image record. The caller must already have verified that exact
      // ancestor against a live owned root and observed exact daemon absence.
      // The root's Size still charges its layers; no extra image is resident.
      if (absentAncestors.has(id) && error?.code === 'UD_IMAGE_ABSENT' && error.imageId === id) continue;
      throw error;
    }
    const image = Array.isArray(images) && images.length === 1 ? images[0] : null;
    if (!image || image.Id !== id || !Number.isSafeInteger(image.Size) || image.Size < 0 || selected.has(id) && selected.get(id).size !== image.Size) fail('project image bytes or identity are unavailable');
    owned.set(id, selected.get(id)?.charged ?? image.Size);
  }
  if ([...selected.keys()].some(id => !owned.has(id))) fail('selected image is absent from the engine inventory');
  for (const [kind, listArgs] of [
    ['container', ['ps', '-a', '--no-trunc', '--format', '{{json .}}']],
    ['volume', ['volume', 'ls', '--format', '{{json .}}']],
  ]) for (const row of rows(docker(listArgs))) {
    const names = kind === 'container' ? row.Names?.split(',') : [row.Name];
    if (!Array.isArray(names) || names.some(name => typeof name !== 'string' || !name)) fail('resource names are unavailable');
    const keys = labelKeys(row.Labels);
    if (!names.some(name => /^(?:ud-agent-|ud-mutation-)/.test(name)) && !keys.some(key => LABELS.includes(key))) continue;
    const reference = kind === 'container' ? row.ID : row.Name;
    if (typeof reference !== 'string' || !reference) fail('resource identity is unavailable');
    const inspected = JSON.parse(docker([kind, 'inspect', reference]));
    if (!Array.isArray(inspected) || inspected.length !== 1 || !activeActionsResource(inspected[0], kind, activeActionsOwner)) fail('pre-existing project or ambiguous resource needs owned recovery');
  }
  const size = [...owned.values()].reduce((sum, value) => sum + value, 0);
  if (!Number.isSafeInteger(size)) fail('project image byte count is invalid');
  return { image_bytes: size, image_ids: [...owned.keys()].sort(), active_actions_owner: activeActionsOwner ?? null };
}
