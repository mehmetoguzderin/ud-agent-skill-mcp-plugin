/** Bind immutable candidate contents to the source/runtime subjects. */
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { readRecordedBytes, sha256 } from './candidate.mjs';
import { releasePythonCommand } from './verifier-runtime.mjs';

export function verifyArtifactContent(root, artifact, source, runtimeHash, candidate, verifierRuntime) {
  if (artifact.id === 'checksum-manifest') {
    const data = readRecordedBytes(root, artifact).toString('utf8');
    const expected = new Map((candidate?.artifacts ?? []).filter(item => item.id !== 'checksum-manifest').map(item => [path.posix.basename(item.path), item.sha256]));
    const seen = new Set();
    for (const line of data.trimEnd().split('\n')) {
      const match = /^([a-f0-9]{64})  ([a-zA-Z0-9][a-zA-Z0-9._-]*)$/.exec(line);
      if (!match || seen.has(match[2]) || expected.get(match[2]) !== match[1]) throw new Error('Checksum manifest differs from candidate artifact inventory.');
      seen.add(match[2]);
    }
    if (!expected.size || seen.size !== expected.size) throw new Error('Checksum manifest is incomplete.');
    return { verified: true, kind: 'checksum-manifest' };
  }
  if (artifact.id === 'sbom') {
    const sbom = JSON.parse(readRecordedBytes(root, artifact).toString('utf8'));
    if (sbom.spdxVersion !== 'SPDX-2.3' || sbom.documentNamespace !== 'https://github.com/mehmetoguzderin/ud-agent-skill-mcp-plugin/sbom/' + source.sha256 || !Array.isArray(sbom.files) || !Array.isArray(sbom.packages) || !sbom.packages.length) throw new Error('SBOM identity or package inventory is missing.');
    const expected = new Map(source.files.map(file => ['./' + file.path, file.sha256]));
    const seen = new Set();
    for (const file of sbom.files) {
      if (!expected.has(file.fileName) || seen.has(file.fileName) || !file.checksums?.some(item => item.algorithm === 'SHA256' && item.checksumValue === expected.get(file.fileName))) throw new Error('SBOM file inventory differs from source.');
      seen.add(file.fileName);
    }
    if (seen.size !== expected.size) throw new Error('SBOM source file inventory is incomplete.');
    const materialLock = source.files.find(file => file.path === 'runtime/source-materials.lock.json');
    if (materialLock) {
      const lock = JSON.parse(readRecordedBytes(root, materialLock).toString('utf8'));
      for (const item of [{ ...lock.index, id: 'corresponding-source-index' }, ...lock.parts]) {
        const id = 'SPDXRef-Package-' + sha256(Buffer.from('source-material:' + item.id)).slice(0, 24), packages = sbom.packages.filter(component => component.SPDXID === id);
        if (packages.length !== 1 || !packages[0].checksums?.some(checksum => checksum.algorithm === 'SHA256' && checksum.checksumValue === item.sha256)) throw new Error('SBOM omits or changes a corresponding-source artifact binding.');
      }
    }
    return { verified: true, kind: 'sbom' };
  }
  let kind, platform = 'all';
  if (artifact.id === 'npm') kind = 'npm';
  else if (artifact.id === 'standalone-skills') kind = 'skills';
  else if (artifact.id === 'source-archive') kind = 'source';
  else {
    const match = /^(?:native|mcpb)-(linux|macos|windows)-(amd64|arm64)$/.exec(artifact.id);
    if (!match) return null; // OCI graph/transports have their dedicated verifier.
    kind = 'native';
    platform = { linux: 'linux', macos: 'darwin', windows: 'win32' }[match[1]] + '-' + (match[2] === 'amd64' ? 'x64' : 'arm64');
  }
  const command = releasePythonCommand(verifierRuntime, [path.join(root, 'scripts/release/inspect-package.py'), path.join(root, ...artifact.path.split('/')), '--kind', kind, '--platform', platform, '--source-sha256', source.sha256, '--runtime-sha256', runtimeHash, '--require-candidate']);
  const result = spawnSync(command.executable, command.args, { env: command.env, encoding: 'utf8', timeout: 300_000, maxBuffer: 1024 * 1024 });
  if (result.error || result.status !== 0) throw new Error(`Artifact content verification failed for ${artifact.id}: ${result.error?.message ?? result.stderr.slice(-2000)}`);
  const receipt = JSON.parse(result.stdout);
  if (receipt.verified !== true || receipt.kind !== kind || receipt.platform !== platform) throw new Error('Archive content verifier returned an invalid receipt.');
  return receipt;
}
