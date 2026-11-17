import path from 'node:path';
import { runCommand } from './command.js';
import { verifyArchive } from './receipt.js';

type Runner = typeof runCommand;
export type LimaEngineReceipt = { executable: string; binarySha256: string; home?: string };
export type LimaInstance = { name: string; status: 'running' | 'stopped' | 'other'; arch: 'amd64' | 'arm64' | null; vm_type: 'qemu' | 'vz' | null };

const namePattern = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const digestPattern = /^sha256:[0-9a-f]{64}$/;
const options = { timeoutMs: 30_000, maxOutputBytes: 4 * 1024 * 1024 };
// Lima 2.3's `--format json` passes complete configurations through a 64KiB
// bufio.Scanner. Offline dependency scripts can legitimately exceed that size.
// Request only the bounded inventory fields through its native template route.
export const LIMA_INSTANCE_FORMAT = '{{printf "{\\\"name\\\":%q,\\\"status\\\":%q,\\\"arch\\\":%q,\\\"vmType\\\":%q}\\n" .Name .Status .Arch .VMType}}';

/** Lima's JSON list is a stream of objects, not necessarily a JSON array. */
export function parseLimaInstances(raw: Buffer): LimaInstance[] {
  if (raw.length > options.maxOutputBytes) throw new Error('Lima inventory exceeds its byte limit.');
  let decoded: string;
  try { decoded = new TextDecoder('utf-8', { fatal: true }).decode(raw).trim(); }
  catch { throw new Error('Lima returned invalid UTF-8.'); }
  if (!decoded) return [];
  let rows: unknown[];
  try {
    if (decoded.startsWith('[')) {
      const result: unknown = JSON.parse(decoded);
      if (!Array.isArray(result)) throw new Error('not an array');
      rows = result;
    } else rows = decoded.split(/\r?\n/).filter(Boolean).map(line => JSON.parse(line) as unknown);
  } catch { throw new Error('Lima returned invalid instance JSON.'); }
  if (rows.length > 10_000) throw new Error('Lima inventory exceeds its instance limit.');
  const seen = new Set<string>();
  return rows.map(row => {
    if (!row || typeof row !== 'object' || Array.isArray(row)) throw new Error('Lima returned an invalid instance.');
    const item = row as Record<string, unknown>;
    if (typeof item.name !== 'string' || !namePattern.test(item.name) || seen.has(item.name) || typeof item.status !== 'string') throw new Error('Lima returned an invalid or duplicate instance identity.');
    seen.add(item.name);
    return {
      name: item.name,
      status: item.status === 'Running' ? 'running' : item.status === 'Stopped' ? 'stopped' : 'other',
      arch: item.arch === 'x86_64' ? 'amd64' : item.arch === 'aarch64' ? 'arm64' : null,
      vm_type: item.vmType === 'qemu' || item.vmType === 'vz' ? item.vmType : null,
    };
  });
}

/**
 * Inventory only: this never starts, stops, enters, provisions or changes a VM.
 * A signed release receipt must establish the supplied digest and publisher;
 * checking bytes here is not a publisher-signature or runtime acceptance check.
 */
export async function inspectLima(engine: LimaEngineReceipt, instance?: string, runner: Runner = runCommand): Promise<{
  engine: 'lima-nerdctl'; version: string; instances: LimaInstance[];
  selected: LimaInstance | null; ready: false;
  isolation: { model: 'lima-vm'; host_isolation_verified: false; rootless_verified: null; worker_uid_verified: false; network_disabled_verified: false; resource_limits_verified: false };
  missing: string[];
}> {
  if (!path.isAbsolute(engine.executable) || engine.executable.includes('\0') || !digestPattern.test(engine.binarySha256)) throw new Error('A receipt-bound absolute Lima executable is required.');
  if (instance !== undefined && !namePattern.test(instance)) throw new Error('Invalid Lima instance name.');
  await verifyArchive(engine.executable, engine.binarySha256);
  const scopedOptions = { ...options, ...(engine.home ? { limaHome: engine.home } : {}) };
  const versionResult = await runner(engine.executable, ['--version'], scopedOptions);
  if (versionResult.code !== 0 || versionResult.stdout.length > 1024) throw new Error('Lima version inspection failed.');
  const versionOutput = versionResult.stdout.toString('utf8').trim();
  const version = /^limactl version (\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)$/.exec(versionOutput)?.[1];
  if (!version) throw new Error('Lima returned an invalid version.');
  await verifyArchive(engine.executable, engine.binarySha256);
  const result = await runner(engine.executable, ['list', '--format', LIMA_INSTANCE_FORMAT], scopedOptions);
  if (result.code !== 0) throw new Error('Lima instance inspection failed.');
  await verifyArchive(engine.executable, engine.binarySha256);
  const instances = parseLimaInstances(result.stdout);
  const selected = instance === undefined ? null : instances.find(item => item.name === instance) ?? null;
  return {
    engine: 'lima-nerdctl', version, instances, selected, ready: false,
    isolation: { model: 'lima-vm', host_isolation_verified: false, rootless_verified: null, worker_uid_verified: false, network_disabled_verified: false, resource_limits_verified: false },
    missing: [...(instance === undefined ? ['explicit_instance_selection'] : selected === null ? ['selected_instance'] : selected.status !== 'running' ? ['running_instance'] : []), 'verified_engine_publisher', 'verified_nerdctl_and_containerd', 'verified_worker_image', 'worker_isolation_and_transfer_probes', 'offline_execution_proof'],
  };
}
