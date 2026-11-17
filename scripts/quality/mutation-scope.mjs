/** Validate diagnostic subsets against closed sources and explicit backends. */
import { createHash } from 'node:crypto';

/** A diagnostic narrows mutations only; the original test suite stays complete. */
export function diagnosticStrykerScope(range, inventory, sourceTreeSha256, readSource) {
  const match = typeof range === 'string' && /^(?<file>(?:packages|scripts|workers|evals)\/(?:[A-Za-z0-9_-][A-Za-z0-9_.-]*\/)*[A-Za-z0-9_-][A-Za-z0-9_.-]*\.(?:ts|tsx|mts|cts|js|mjs|cjs)):(?<sl>[1-9][0-9]{0,5}):(?<sc>[1-9][0-9]{0,5})-(?<el>[1-9][0-9]{0,5}):(?<ec>[1-9][0-9]{0,5})$/.exec(range);
  if (!match || !Array.isArray(inventory) || !/^[a-f0-9]{64}$/.test(sourceTreeSha256 ?? '') || typeof readSource !== 'function') throw new Error('Stryker diagnostic range is not a canonical closed source range.');
  const { file, sl, sc, el, ec } = match.groups;
  const entries = inventory.filter(item => item.path === file);
  if (entries.length !== 1) throw new Error('Stryker diagnostic source is absent or duplicated in its snapshot.');
  const bytes = readSource(file), entry = entries[0];
  if (!Buffer.isBuffer(bytes) || bytes.length > 16 * 1024 ** 2 || bytes.length !== entry.size || createHash('sha256').update(bytes).digest('hex') !== entry.sha256) throw new Error('Stryker diagnostic source differs from its snapshot.');
  const lines = new TextDecoder('utf-8', { fatal: true }).decode(bytes).split('\n').map(line => line.endsWith('\r') ? line.slice(0, -1) : line);
  const start = { line: Number(sl), column: Number(sc) }, end = { line: Number(el), column: Number(ec) };
  if ([start, end].some(position => position.line > lines.length || position.column > lines[position.line - 1].length + 1) || end.line < start.line || end.line === start.line && end.column <= start.column) throw new Error('Stryker diagnostic range is empty, reversed or outside its source.');
  return { schema_version: 1, kind: 'selected-stryker-diagnostic', scope_complete: false, source_tree_sha256: sourceTreeSha256, range, file, source_sha256: entry.sha256, source_size_bytes: bytes.length, start, end };
}

export function assertProtectedMutationSources(backend, files, inventory) {
  if (!Array.isArray(files) || !Array.isArray(inventory)) throw new Error('Mutation source inventory is invalid.');
  const available = new Set(inventory.map(item => item.path));
  for (const file of files) {
    const canonical = typeof file === 'string' && file.length > 0 && !/[\\\0:]/.test(file) && file.normalize('NFC') === file && !file.split('/').some(part => !part || part === '.' || part === '..');
    const permitted = backend === 'rust'
      ? /^(?:packages\/launcher|scripts\/quality\/rust-assertion-parser)\/src\/.+\.rs$/.test(file)
      : /^(?:workers\/ud\/src\/ud_agent|scripts)\/.+\.py$/.test(file);
    if (!canonical || !available.has(file) || !permitted) throw new Error('Mutation source subset is outside the snapshot or declared workspace.');
  }
}

/** Diagnostic source uploads are authorized only to a local Docker endpoint. */
export function localDockerAuthority(environment, inspectContext) {
  const context = environment.DOCKER_CONTEXT, host = environment.DOCKER_HOST;
  if (context && (typeof context !== 'string' || !/^[A-Za-z0-9_][A-Za-z0-9_.-]*$/.test(context))) throw new Error('Docker context name is invalid.');
  // Docker gives DOCKER_CONTEXT priority over DOCKER_HOST. Context inspection
  // reads local metadata; it must not connect to the selected daemon.
  const endpoint = context ? inspectContext(context) : host || inspectContext(undefined);
  if (typeof endpoint !== 'string') throw new Error('Docker endpoint is invalid.');
  if (/^npipe:\/\/\/\/\.\/pipe\/[A-Za-z0-9_.-]+$/.test(endpoint)) return { transport: 'npipe', endpoint, selection: context ? 'explicit-context' : host ? 'explicit-host' : 'current-context' };
  if (endpoint.startsWith('unix:///')) {
    const name = endpoint.slice('unix://'.length);
    if (!/[\\\0\r\n?#%]/.test(name) && name.split('/').slice(1).every(part => part && part !== '.' && part !== '..')) return { transport: 'unix', endpoint, selection: context ? 'explicit-context' : host ? 'explicit-host' : 'current-context' };
  }
  throw new Error('Diagnostic source transfer requires a local Unix socket or local Windows named pipe; remote Docker endpoints are not authorized.');
}
