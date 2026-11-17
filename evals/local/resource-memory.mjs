/** Read-only host/process/container observations. Imports never start probes. MIT. */
import { execFile } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import os from 'node:os';
import { promisify } from 'node:util';

const execute = promisify(execFile);
export const MEMORY_RESERVE_BYTES = 2 * 1024 ** 3;
const valid = value => Number.isSafeInteger(value) && value >= 0;
const failure = error => ({ code: error.code ?? 'MEMORY_OBSERVATION_FAILED', message: String(error.message).slice(0, 300) });

export function parseMacMemory(vmstat, pressure, totalBytes) {
  const pageSize = Number(/page size of (\d+) bytes/.exec(vmstat)?.[1]);
  const pages = {};
  for (const line of vmstat.split('\n')) { const match = /^([^:]+):\s+(\d+)\.?\s*$/.exec(line); if (match) pages[match[1]] = Number(match[2]); }
  const level = Number(pressure.trim());
  if (!valid(totalBytes) || !totalBytes || !valid(pageSize) || !pageSize || ![1, 2, 4].includes(level) ||
      !['Pages free', 'Pages inactive', 'Pages speculative', 'Pages wired down', 'Pages occupied by compressor'].every(key => valid(pages[key]))) throw new Error('MAC_MEMORY_MEASUREMENT_INVALID');
  const available = (pages['Pages free'] + pages['Pages inactive'] + pages['Pages speculative']) * pageSize;
  if (!valid(available) || available > totalBytes) throw new Error('MAC_MEMORY_MEASUREMENT_INVALID');
  return { total_bytes: totalBytes, available_bytes: available, available_basis: 'vm_stat:free+inactive+speculative;reclaimable-page-estimate',
    page_size: pageSize, pages, pressure: { source: 'kern.memorystatus_vm_pressure_level', level, state: { 1: 'normal', 2: 'warning', 4: 'critical' }[level] } };
}

export function parseProcessMemory(text, observerPid = process.pid) {
  const rows = [], seen = new Set();
  for (const line of text.split('\n').filter(line => line.trim())) {
    const match = /^\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(.+?)\s*$/.exec(line);
    if (!match) throw new Error('PROCESS_MEMORY_INVENTORY_INVALID');
    const [pid, ppid, pgid, kib] = match.slice(1, 5).map(Number);
    if (![pid, ppid, pgid, kib * 1024].every(valid) || !pid || seen.has(pid)) throw new Error('PROCESS_MEMORY_INVENTORY_INVALID');
    seen.add(pid); rows.push({ pid, ppid, pgid, rss_bytes: kib * 1024, executable: match[5] });
  }
  if (!seen.has(observerPid)) throw new Error('PROCESS_MEMORY_OBSERVER_MISSING');
  return rows;
}

function displayedBytes(value) {
  const match = /^([0-9]+(?:\.[0-9]+)?)\s*(B|kB|MB|GB|TB|KiB|MiB|GiB|TiB)$/.exec(value.trim());
  const units = { B: 1, kB: 1000, MB: 1e6, GB: 1e9, TB: 1e12, KiB: 1024, MiB: 1024 ** 2, GiB: 1024 ** 3, TiB: 1024 ** 4 };
  if (!match) throw new Error('CONTAINER_MEMORY_MEASUREMENT_INVALID');
  const count = Math.round(Number(match[1]) * units[match[2]]);
  if (!valid(count)) throw new Error('CONTAINER_MEMORY_MEASUREMENT_INVALID');
  return count;
}

/** Supply only owned live process-group leaders and exact active container names/IDs.
 * Container usage is contained in VM RSS, so it is never added a second time.
 * Unknown measurements remain failed observations and block the guard. */
export async function sampleResourceMemory({ processes = [], container, signal, platform = process.platform, totalBytes = os.totalmem(),
  observerPid = process.pid, run = (command, args, options) => execute(command, args, options), read = readFile } = {}) {
  const sample = { schema_version: 1, kind: 'local-resource-memory', inference: false, observed_at: new Date().toISOString(),
    platform, reserve_bytes: MEMORY_RESERVE_BYTES, host: null, processes: [], virtual_machines: [], containers: [], failures: [], verified: false };
  if (!Array.isArray(processes) || processes.some(item => !valid(item.pid) || item.pid < 1 || typeof item.role !== 'string') ||
      container && (typeof container.executable !== 'string' || !Array.isArray(container.ids) || container.ids.some(id => typeof id !== 'string' || !/^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$/.test(id)))) throw new Error('MEMORY_OBSERVATION_SCOPE_INVALID');
  const command = async (file, args, env) => (await run(file, args, { encoding: 'utf8', timeout: 2500, maxBuffer: 2 * 1024 ** 2, signal, ...(env ? { env } : {}) })).stdout;
  const host = async () => {
    if (platform === 'darwin') {
      const [pages, pressure] = await Promise.all([command('/usr/bin/vm_stat', []), command('/usr/sbin/sysctl', ['-n', 'kern.memorystatus_vm_pressure_level'])]);
      return parseMacMemory(pages, pressure, totalBytes);
    }
    if (platform === 'linux') {
      const info = await read('/proc/meminfo', 'utf8'), available = Number(/^MemAvailable:\s+(\d+) kB$/m.exec(info)?.[1]) * 1024;
      if (!valid(available) || available > totalBytes) throw new Error('LINUX_MEMORY_MEASUREMENT_INVALID');
      return { total_bytes: totalBytes, available_bytes: available, available_basis: 'proc:MemAvailable', pressure: { source: 'reserve-only;no-macOS-critical-pressure-signal', state: 'not-applicable' } };
    }
    throw new Error('HOST_MEMORY_PLATFORM_UNSUPPORTED');
  };
  const results = await Promise.allSettled([host(), command('/bin/ps', ['-axo', 'pid=,ppid=,pgid=,rss=,comm=']).then(text => parseProcessMemory(text, observerPid)),
    container?.ids.length ? command(container.executable, ['stats', '--no-stream', '--format', '{{json .}}', ...container.ids], container.env) : Promise.resolve(null)]);
  for (const [index, result] of results.entries()) if (result.status === 'rejected') sample.failures.push({ component: ['host', 'processes', 'containers'][index], ...failure(result.reason) });
  if (results[0].status === 'fulfilled') sample.host = results[0].value;
  if (results[1].status === 'fulfilled') {
    const rows = results[1].value, selected = new Set([observerPid]);
    for (const process of [{ role: 'evaluator', pid: observerPid }, ...processes]) {
      const leader = rows.find(row => row.pid === process.pid);
      if (!leader) { sample.failures.push({ component: process.role, code: 'MEMORY_PROCESS_NOT_OBSERVED', pid: process.pid }); continue; }
      const group = process.pid === observerPid ? [leader] : rows.filter(row => row.pgid === leader.pgid);
      for (const row of group) selected.add(row.pid);
      sample.processes.push({ role: process.role, leader_pid: process.pid, group_id: leader.pgid, members: group, rss_bytes: group.reduce((sum, row) => sum + row.rss_bytes, 0) });
    }
    sample.virtual_machines = rows.filter(row => /(?:qemu-system|vfkit|Virtualization|com\.docker\.(?:backend|virtualization)|lima.*hostagent)/i.test(row.executable));
    for (const row of sample.virtual_machines) selected.add(row.pid);
    sample.observed_host_rss_bytes = rows.filter(row => selected.has(row.pid)).reduce((sum, row) => sum + row.rss_bytes, 0);
    sample.rss_basis = 'unique-host-PIDs;RSS-can-share-pages;container-usage-is-nested-in-VM-not-added';
  }
  if (results[2].status === 'fulfilled' && results[2].value !== null) {
    try {
      sample.containers = results[2].value.trim().split('\n').filter(Boolean).map(line => {
        const row = JSON.parse(line), parts = String(row.MemUsage).split('/');
        const selected = container.ids.find(id => row.Name === id || row.Container === id || typeof row.ID === 'string' && id.startsWith(row.ID));
        if (!selected || parts.length !== 2) throw new Error('CONTAINER_MEMORY_IDENTITY_UNVERIFIED');
        return { id: selected, observed_id: row.ID ?? row.Container, usage_bytes: displayedBytes(parts[0]), limit_bytes: displayedBytes(parts[1]), source: 'docker-stats-no-stream', precision: 'native-display-rounded' };
      });
      if (sample.containers.length !== container.ids.length || new Set(sample.containers.map(row => row.id)).size !== container.ids.length) throw new Error('CONTAINER_MEMORY_INVENTORY_INCOMPLETE');
    } catch (error) { sample.failures.push({ component: 'containers', ...failure(error) }); }
  }
  sample.verified = sample.failures.length === 0 && sample.host !== null;
  sample.guard = !sample.verified ? 'measurement-unavailable' : sample.host.pressure.state === 'critical' ? 'critical-pressure'
    : sample.host.available_bytes < MEMORY_RESERVE_BYTES ? 'reserve-exhausted' : 'admitted';
  return sample;
}

export function assertResourceMemory(sample) {
  if (sample?.verified !== true || sample.guard !== 'admitted' || sample.reserve_bytes !== MEMORY_RESERVE_BYTES ||
      !valid(sample.host?.available_bytes) || sample.host.available_bytes < MEMORY_RESERVE_BYTES || sample.host.pressure?.state === 'critical') {
    const error = new Error(`RESOURCE_MEMORY_BLOCKED:${sample?.guard ?? 'missing-measurement'}`); error.observation = sample; throw error;
  }
  return sample;
}
