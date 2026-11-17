import { access, realpath, stat } from 'node:fs/promises';
import { constants } from 'node:fs';
import path from 'node:path';

export const ENGINES = ['auto', 'apple-container', 'wslc', 'lima-nerdctl', 'podman', 'docker-rootless', 'docker', 'userspace'] as const;
export type Engine = (typeof ENGINES)[number];
export type ConcreteEngine = Exclude<Engine, 'auto'>;
export type Host = { platform: NodeJS.Platform; arch: string };

/** Selection never starts a service, creates a machine, or changes defaults. */
export function platformPreferred(host: Host): ConcreteEngine | undefined {
  if (host.arch !== 'arm64' && host.arch !== 'x64') return undefined;
  if (host.platform === 'darwin') return host.arch === 'arm64' ? 'apple-container' : 'lima-nerdctl';
  if (host.platform === 'win32') return 'wslc';
  if (host.platform === 'linux') return 'podman';
  return undefined;
}

export function isEngineSupported(engine: ConcreteEngine, host: Host): boolean {
  if (!platformPreferred(host)) return false;
  switch (engine) {
    case 'apple-container': return host.platform === 'darwin' && host.arch === 'arm64';
    case 'wslc': return host.platform === 'win32';
    case 'lima-nerdctl': return host.platform === 'darwin';
    case 'podman': return host.platform === 'linux' || host.platform === 'darwin' || host.platform === 'win32';
    case 'docker-rootless': return host.platform === 'linux' || host.platform === 'darwin' || host.platform === 'win32';
    case 'docker': return host.platform === 'linux' || host.platform === 'darwin' || host.platform === 'win32';
    case 'userspace': return host.platform === 'linux' || host.platform === 'darwin' || host.platform === 'win32';
  }
}

export function executableName(engine: ConcreteEngine, platform: NodeJS.Platform): string | undefined {
  if (engine === 'userspace') return undefined;
  const base: Record<Exclude<ConcreteEngine, 'userspace'>, string> = {
    'apple-container': 'container', 'wslc': 'wslc', 'lima-nerdctl': 'limactl',
    'podman': 'podman', 'docker-rootless': 'docker', 'docker': 'docker',
  };
  return base[engine] + (platform === 'win32' ? '.exe' : '');
}

/** Search only absolute PATH entries; do not execute the candidate to inspect it. */
export async function findExecutable(engine: ConcreteEngine, host: Host, searchPath: string): Promise<string | undefined> {
  const ext = executableName(engine, host.platform);
  if (!ext) return undefined;
  const pathApi = host.platform === 'win32' ? path.win32 : path.posix;
  const seen = new Set<string>();
  for (const dir of searchPath.split(host.platform === 'win32' ? ';' : ':')) {
    if (!dir || !pathApi.isAbsolute(dir)) continue;
    const candidate = pathApi.join(dir, ext);
    if (seen.has(candidate)) continue;
    seen.add(candidate);
    try {
      const resolved = await realpath(candidate);
      const info = await stat(resolved);
      if (!info.isFile()) continue;
      await access(resolved, host.platform === 'win32' ? constants.F_OK : constants.X_OK);
      return resolved;
    } catch (error: unknown) {
      const code = (error as NodeJS.ErrnoException).code;
      if (code !== 'ENOENT' && code !== 'ENOTDIR' && code !== 'EACCES' && code !== 'ELOOP') throw error;
    }
  }
  return undefined;
}

/** Preference is for already available local engines; no install is implied. */
export function candidateEngines(host: Host, saved?: ConcreteEngine): ConcreteEngine[] {
  const preferred = platformPreferred(host);
  if (!preferred) return [];
  const platformCandidates: ConcreteEngine[] = host.platform === 'darwin'
    ? [preferred, ...(preferred === 'apple-container' ? ['lima-nerdctl' as const] : []), 'podman', 'docker']
    : host.platform === 'win32' ? [preferred, 'podman', 'docker'] : [preferred, 'docker'];
  const ordered = [...(saved && isEngineSupported(saved, host) ? [saved] : []), ...platformCandidates, 'userspace' as const];
  return [...new Set(ordered)].filter(engine => isEngineSupported(engine, host));
}

export function selectEngine(requested: Engine, saved: ConcreteEngine | undefined, host: Host): ConcreteEngine | undefined {
  if (requested !== 'auto') return isEngineSupported(requested, host) ? requested : undefined;
  if (saved && isEngineSupported(saved, host)) return saved;
  return platformPreferred(host);
}
