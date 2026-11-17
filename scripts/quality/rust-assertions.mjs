/** Strict Rust assertion evidence, including explicitly reviewed total boundaries. */
import { createHash } from 'node:crypto';
import { existsSync, lstatSync, readFileSync, readdirSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { fileReceipt, safeRelative } from '../release/candidate.mjs';
import { canonicalJson } from '../release/http-transports.mjs';
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const HASH = /^[0-9a-f]{64}$/;
const PARSER_SOURCES = ['Cargo.toml', 'Cargo.lock', 'src/main.rs', 'src/cfg_regions.rs'].map(name => 'scripts/quality/rust-assertion-parser/' + name);
const ARTIFACT = /^(?:packages\/launcher\/(?:src\/(?:main|fs_guard)|tests\/[A-Za-z0-9_-]+)|scripts\/quality\/rust-assertion-parser\/(?:src\/main|tests\/[A-Za-z0-9_-]+))\.rs$/;
const WORKSPACE_SOURCE = /^(?:packages\/launcher|scripts\/quality\/rust-assertion-parser)\/(?:src|tests)\/[A-Za-z0-9_/-]+\.rs$/;
const keysAre = (value, keys) => value && typeof value === 'object' && !Array.isArray(value) && canonicalJson(Object.keys(value).sort()) === canonicalJson([...keys].sort());

/** The production parser is part of the immutable, independently locked SDK. */
function trustedRustParser(root, mode) {
  const inputs = JSON.parse(readFileSync('/opt/mutation/input-receipt.json', 'utf8'));
  const receiptPath = '/opt/mutation/rust-input-receipt.json';
  const bytes = readFileSync(receiptPath);
  if (inputs.rust?.sha256 !== hash(bytes) || inputs.rust?.size_bytes !== bytes.length) throw new Error('Rust AST SDK receipt differs from the image authority.');
  const receipt = JSON.parse(bytes), binding = receipt.assertion_parser;
  if (binding?.schema_version !== 1 || !keysAre(binding.source_inventory, PARSER_SOURCES)) throw new Error('Rust AST parser has no complete source binding.');
  for (const name of PARSER_SOURCES) if (fileReceipt(root, name).sha256 !== binding.source_inventory[name]) throw new Error('Rust AST parser source binding is stale.');
  const rows = receipt.files.filter(item => item.path === 'bin/ud-rust-assertion-parser');
  if (rows.length !== 1) throw new Error('Rust AST parser executable is absent or ambiguous.');
  const executable = '/opt/mutation/rust/' + rows[0].path, info = lstatSync(executable), content = readFileSync(executable);
  if (!info.isFile() || info.isSymbolicLink() || info.uid !== 0 || info.nlink !== 1 || info.mode & 0o222 || !(info.mode & 0o111) || content.length !== rows[0].size || hash(content) !== rows[0].sha256) throw new Error('Rust AST parser differs from its immutable SDK receipt.');
  const parse = (source, testScope) => {
    const result = spawnSync(executable, mode === 'cfg' ? ['--cfg-regions'] : ['--source', ...(testScope ? ['--test-scope'] : [])], { input: source, encoding: 'utf8', maxBuffer: 8 * 1024 * 1024, timeout: 10_000, env: { PATH: '/usr/bin:/bin', LANG: 'C.UTF-8' } });
    if (result.error || result.signal || result.status !== 0 || result.stderr) throw new Error('Rust AST assertion discovery failed.');
    return JSON.parse(result.stdout);
  };
  parse.receipt = { executable_sha256: rows[0].sha256, source_inventory: binding.source_inventory, qualification: 'immutable-SDK-AST-parser-only', parser_mode: mode === 'cfg' ? 'cfg-regions' : 'source' };
  return parse;
}
export function trustedRustSourceParser(root) { return trustedRustParser(root, 'source'); }
export function trustedRustCfgParser(root) { return trustedRustParser(root, 'cfg'); }

function candidateBytes(root, item, name, inventory) {
  const receipt = fileReceipt(root, name), original = readFileSync(path.join(root, name));
  if (original.length > 16 * 1024 * 1024 || hash(original) !== receipt.sha256) throw new Error('Rust source changed while discovering assertions.');
  inventory[name] = receipt.sha256;
  if (!item || item.file !== name) return original;
  const definition = item.definition;
  if (!HASH.test(item.source_sha256) || item.source_sha256 !== receipt.sha256 || !definition || definition.file !== name || hash(canonicalJson(definition)) !== item.definition_sha256 || typeof definition.replacement !== 'string') throw new Error('Rust scheduled source or definition binding is invalid.');
  const lines = original.toString('utf8').split(/(?<=\n)/), offsets = [0];
  for (const line of lines) offsets.push(offsets.at(-1) + Buffer.byteLength(line));
  const position = point => {
    if (!point || !Number.isSafeInteger(point.line) || !Number.isSafeInteger(point.column) || point.line < 1 || point.line > lines.length || point.column < 1 || point.column > Buffer.byteLength(lines[point.line - 1]) + 1) throw new Error('Rust mutation has an invalid byte span.');
    return offsets[point.line - 1] + point.column - 1;
  };
  const start = position(definition.span?.start), end = position(definition.span?.end);
  if (start >= end || new TextDecoder('utf-8', { fatal: true }).decode(original.subarray(start, end)) === undefined) throw new Error('Rust mutation has an invalid source span.');
  const changed = Buffer.concat([original.subarray(0, start), Buffer.from(definition.replacement), original.subarray(end)]);
  if (changed.equals(original)) throw new Error('Rust mutation does not change its bound source.');
  new TextDecoder('utf-8', { fatal: true }).decode(changed);
  return changed;
}

function assertionInventory(root, item, artifacts, parseSource) {
  const inventory = {}, parsed = new Map(), result = new Map();
  if (item && !WORKSPACE_SOURCE.test(item.file)) throw new Error('Rust mutation is outside the declared workspaces.');
  // Validate the selected source even if its cfg branch is not reached by a
  // particular test artifact. Every candidate must bind the scheduled edit.
  if (item) candidateBytes(root, item, safeRelative(item.file), inventory);
  for (const artifact of artifacts) {
    const names = new Set(), sites = new Map(), visiting = new Set();
    const load = (file, prefix, inheritedScope, crateRoot = false) => {
      safeRelative(file);
      if (!WORKSPACE_SOURCE.test(file) || visiting.has(file)) throw new Error('Rust assertion modules escape their workspace or form a cycle.');
      visiting.add(file);
      const key = file + ':' + inheritedScope;
      let syntax = parsed.get(key);
      if (!syntax) {
        syntax = parseSource(candidateBytes(root, item, file, inventory), inheritedScope);
        if (!keysAre(syntax, ['schema_version', 'sites', 'tests', 'external_modules']) || syntax.schema_version !== 1 || !Array.isArray(syntax.sites) || !Array.isArray(syntax.tests) || !Array.isArray(syntax.external_modules)) throw new Error('Rust AST parser returned an invalid inventory.');
        parsed.set(key, syntax);
      }
      for (const name of syntax.tests) {
        if (typeof name !== 'string' || !name || name.includes('\n') || name.includes('\0')) throw new Error('Rust AST test identity is invalid.');
        names.add([...prefix, name].join('::'));
      }
      for (const site of syntax.sites) {
        if (!keysAre(site, ['line', 'column', 'macro']) || !Number.isSafeInteger(site.line) || site.line < 1 || !Number.isSafeInteger(site.column) || site.column < 1 || !/^(?:debug_)?assert(?:_eq|_ne)?$/.test(site.macro)) throw new Error('Rust AST assertion location is invalid.');
        sites.set(`${file}:${site.line}:${site.column}`, { source: file, source_sha256: inventory[file], ...site });
      }
      for (const external of syntax.external_modules) {
        if (!keysAre(external, ['modules', 'path', 'test_only']) || !Array.isArray(external.modules) || !external.modules.length || external.modules.some(name => typeof name !== 'string' || !/^[_\p{ID_Start}][_\p{ID_Continue}]*$/u.test(name)) || typeof external.test_only !== 'boolean') throw new Error('Rust AST external module is invalid.');
        const base = crateRoot || path.posix.basename(file) === 'mod.rs' ? path.posix.dirname(file) : file.slice(0, -3);
        const parents = external.modules.slice(0, -1), name = external.modules.at(-1);
        let selected;
        if (external.path !== null) {
          safeRelative(external.path);
          // Top-level #[path] is relative to the containing source file even
          // for non-mod-rs files. Inline module parents use the module base.
          selected = path.posix.join(parents.length ? base : path.posix.dirname(file), ...parents, external.path);
          if (!existsSync(path.join(root, selected))) throw new Error('Rust explicit test module is missing.');
        } else {
          const choices = [path.posix.join(base, ...parents, name + '.rs'), path.posix.join(base, ...parents, name, 'mod.rs')].filter(value => existsSync(path.join(root, value)));
          if (choices.length !== 1) throw new Error('Rust module source is missing or ambiguous.');
          selected = choices[0];
        }
        load(selected, [...prefix, ...external.modules], inheritedScope || external.test_only);
      }
      visiting.delete(file);
    };
    load(artifact.artifact_id, [], artifact.artifact_id.includes('/tests/'), true);
    for (const name of artifact.expected_tests) if (!names.has(name)) throw new Error('Rust expected test is absent from the actual AST.');
    result.set(artifact.artifact_id, sites);
  }
  return { artifacts: result, source_inventory: inventory };
}

function completeLibtest(log, expected, status) {
  const starts = [...log.matchAll(/^running (\d+) tests?\r?$/gm)];
  const summaries = [...log.matchAll(/^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out; finished in [^\r\n]+\r?$/gm)];
  const rows = [...log.matchAll(/^test (.+) \.\.\. (ok|FAILED|ignored)\r?$/gm)].map(match => ({ name: match[1], status: match[2], offset: match.index }));
  if (starts.length !== 1 || Number(starts[0][1]) !== expected.length || summaries.length !== 1 || rows.length !== expected.length || new Set(rows.map(row => row.name)).size !== rows.length || rows.some(row => !expected.includes(row.name) || row.status === 'ignored')) return null;
  const summary = summaries[0], passed = rows.filter(row => row.status === 'ok').length, failed = rows.filter(row => row.status === 'FAILED').map(row => row.name);
  if (Number(summary[2]) !== passed || Number(summary[3]) !== failed.length || summary.slice(4, 7).some(value => Number(value) !== 0) || (failed.length ? status !== 101 || summary[1] !== 'FAILED' : status !== 0 || summary[1] !== 'ok') || summary.index < rows.at(-1)?.offset) return null;
  return { failed };
}

/** Reconcile every independently discovered test artifact before grading kills. */
export function rustPhaseEvidence(root, item, phase, { parseSource = trustedRustSourceParser(root) } = {}) {
  const reject = reason => ({ valid: false, artifacts_complete: false, reason, failures: [] });
  if (item !== null && (!item || typeof item !== 'object' || Array.isArray(item) || typeof item.file !== 'string' || typeof item.source_sha256 !== 'string' || !HASH.test(item.source_sha256) || typeof item.definition_sha256 !== 'string' || !HASH.test(item.definition_sha256))) return reject('Rust scheduled mutation identity is invalid.');
  if (!phase || phase.artifacts_complete !== true || !Array.isArray(phase.expected_artifacts) || !phase.expected_artifacts.length || !Array.isArray(phase.invocations) || phase.expected_artifacts.length !== phase.invocations.length || typeof phase.compile_source_root !== 'string' || !/^\/tmp\/ud-mutation-jobs\/[A-Za-z0-9_-]+\/tree$/.test(phase.compile_source_root)) return reject('Rust phase is missing complete independently issued artifact evidence.');
  const expected = new Map();
  for (const artifact of phase.expected_artifacts) {
    if (!keysAre(artifact, ['artifact_id', 'artifact_sha256', 'expected_tests']) || typeof artifact.artifact_id !== 'string' || !ARTIFACT.test(artifact.artifact_id) || typeof artifact.artifact_sha256 !== 'string' || !HASH.test(artifact.artifact_sha256) || expected.has(artifact.artifact_id) || !Array.isArray(artifact.expected_tests) || new Set(artifact.expected_tests).size !== artifact.expected_tests.length || artifact.expected_tests.some(name => typeof name !== 'string' || !name || name.includes('\n') || name.includes('\0'))) return reject('Rust expected artifact inventory is invalid or duplicate.');
    expected.set(artifact.artifact_id, artifact);
  }
  if (![...expected.values()].some(artifact => artifact.expected_tests.length > 0)) return reject('Rust required test inventory is empty.');
  // Derive the full artifact set from the two fixed workspace contracts, rather
  // than accepting a caller's filtered expected_artifacts array as authority.
  const auxiliaryWorkspace = ['scripts/quality/rust-assertion-parser'].find(prefix => [...expected.keys()].every(name => name.startsWith(prefix + '/')));
  const auxiliaryTests = auxiliaryWorkspace && path.join(root, auxiliaryWorkspace, 'tests');
  const required = auxiliaryWorkspace ? [auxiliaryWorkspace + '/src/main.rs',
    ...(existsSync(auxiliaryTests) ? readdirSync(auxiliaryTests).filter(name => /^[A-Za-z0-9_-]+\.rs$/.test(name)).map(name => auxiliaryWorkspace + '/tests/' + name) : []),
  ] : [
    'packages/launcher/src/main.rs', 'packages/launcher/src/fs_guard.rs',
    ...readdirSync(path.join(root, 'packages/launcher/tests')).filter(name => /^[A-Za-z0-9_-]+\.rs$/.test(name)).map(name => 'packages/launcher/tests/' + name),
  ];
  if (canonicalJson([...expected.keys()].sort()) !== canonicalJson(required.sort())) return reject('Rust phase omits or adds an independently required test artifact.');
  let discovered;
  try { discovered = assertionInventory(root, item, [...expected.values()], parseSource); } catch (error) { return reject(error.message); }
  const seen = new Set(), failures = [], observations = [];
  for (const invocation of phase.invocations) {
    const artifact = expected.get(invocation?.artifact_id);
    if (!keysAre(invocation, ['artifact_id', 'artifact_sha256', 'expected_tests', 'status', 'timed_out', 'cancelled', 'owned_descendants_cancelled', 'cleanup_verified', 'log']) || !artifact || seen.has(invocation.artifact_id) || invocation.artifact_sha256 !== artifact.artifact_sha256 || canonicalJson(invocation.expected_tests) !== canonicalJson(artifact.expected_tests) || ![0, 101].includes(invocation.status) || invocation.timed_out !== false || invocation.cancelled !== false || invocation.owned_descendants_cancelled !== false || invocation.cleanup_verified !== true || typeof invocation.log !== 'string' || Buffer.byteLength(invocation.log) > 16 * 1024 * 1024) return reject('Rust invocation is missing, duplicated, unbound, or did not terminate cleanly.');
    seen.add(invocation.artifact_id);
    const completion = completeLibtest(invocation.log, artifact.expected_tests, invocation.status);
    if (!completion) return reject('Rust artifact has missing, unknown, duplicate, ignored, filtered, or inconsistent test outcomes.');
    const parsed = rustAssertionEvidence(invocation.log, item ? totalBoundaries(root, item) : []);
    if (parsed.reason || parsed.boundary_events_complete !== true) return reject('Rust boundary observation framing is malformed or unbound.');
    if (completion.failed.length === 0) {
      if (parsed.failures.length || parsed.total_boundary_observations.length) return reject('Successful Rust artifact contains panic evidence.');
      continue;
    }
    const sites = discovered.artifacts.get(invocation.artifact_id), sourceRoot = phase.compile_source_root;
    const packageRoot = invocation.artifact_id.startsWith('packages/') ? 'packages/launcher' : invocation.artifact_id.split('/').slice(0, 3).join('/');
    for (const failure of parsed.failures) {
      if (failure.kind === 'caught-contract-observation') continue;
      const match = /^(.*):(\d+):(\d+)$/.exec(failure.location);
      if (!match) return reject('Rust assertion has no exact source location.');
      let file = match[1].replaceAll('\\', '/');
      if (file.startsWith(sourceRoot + '/')) file = file.slice(sourceRoot.length + 1);
      else if (file.startsWith('/')) return reject('Rust assertion comes from an unbound absolute source path.');
      if (/^(?:src|tests)\//.test(file)) file = packageRoot + '/' + file;
      const site = sites.get(`${file}:${Number(match[2])}:${Number(match[3])}`);
      if (!site) return reject('Rust assertion is not a real test assertion in the exact candidate AST.');
      if (failure.kind === 'runtime' && !['assert', 'debug_assert'].includes(site.macro)) return reject('Rust comparison assertion has an unexpected runtime panic.');
      // assert!(condition, custom_format, ...) can emit only its custom text.
      // Exact builtin-macro AST location, not a panic-message prefix, proves
      // this is a test assertion. Operand/formatter panics have their own site.
      failure.kind = 'assertion';
      failures.push({ ...failure, artifact_id: invocation.artifact_id, ...site });
    }
    const assertions = parsed.failures.filter(row => row.kind === 'assertion');
    if (!assertions.length || new Set(assertions.map(row => row.test)).size !== assertions.length || canonicalJson(assertions.map(row => row.test).sort()) !== canonicalJson([...completion.failed].sort()) || parsed.failures.some(row => row.kind === 'runtime')) return reject('Rust artifact has a runtime failure or an unbound assertion.');
    observations.push(...parsed.total_boundary_observations);
  }
  return { artifacts_complete: seen.size === expected.size, valid: failures.length > 0, failures, total_boundary_observations: observations, source_inventory: discovered.source_inventory };
}

export function totalBoundaries(root, item) {
  const file = path.join(root, 'quality/rust-total-boundaries.json');
  if (!existsSync(file)) return [];
  const registry = JSON.parse(readFileSync(file, 'utf8'));
  if (registry.schema_version !== 1 || !Array.isArray(registry.boundaries)) throw new Error('Rust total-boundary registry is invalid.');
  const selected = [];
  for (const row of registry.boundaries) {
    for (const name of ['source', 'test_file', 'review_file', 'proof_file']) safeRelative(row[name]);
    if (fileReceipt(root, row.source).sha256 !== row.source_sha256 || fileReceipt(root, row.test_file).sha256 !== row.test_sha256 || fileReceipt(root, row.review_file).sha256 !== row.review_sha256 || fileReceipt(root, row.proof_file).sha256 !== row.proof_sha256) throw new Error('Rust total-boundary review or source fingerprint is stale.');
    const review = JSON.parse(readFileSync(path.join(root, row.review_file), 'utf8'));
    if (review.decision !== 'approved-structured-total-boundary-assertion-only' || review.source !== row.source || review.source_sha256 !== row.source_sha256 || review.definition_sha256 !== row.definition_sha256 || review.test_sha256 !== row.test_sha256 || !review.reviewer || !Array.isArray(row.source_lines) || row.source_lines.length !== 2 || row.source_lines.some(value => !Number.isSafeInteger(value) || value < 1)) throw new Error('Rust total-boundary review does not authorize this exact assertion.');
    const proof = JSON.parse(readFileSync(path.join(root, row.proof_file), 'utf8'));
    if (review.proof_sha256 !== row.proof_sha256 || proof.source_sha256 !== row.source_sha256 || proof.definition_sha256 !== row.definition_sha256 || proof.test_sha256 !== row.test_sha256 || proof.test_name !== row.test_name || canonicalJson(row.source_lines) !== canonicalJson([proof.definition.function.span.start.line,proof.definition.function.span.end.line]) || canonicalJson(proof.event) !== canonicalJson(row.event) || row.assertion !== 'assertion `left == right` failed: public serialized-metadata boundary must never panic') throw new Error('Rust total-boundary proof differs from the independent approval.');
    if (row.source === item.file && row.source_sha256 === item.source_sha256 && row.definition_sha256 === item.definition_sha256) {
      if (hash(canonicalJson(item.definition)) !== item.definition_sha256 || row.event.source_sha256 !== row.source_sha256 || row.event.definition_sha256 !== row.definition_sha256 || row.event.test !== row.test_name || row.event.boundary !== row.boundary) throw new Error('Rust total-boundary event differs from scheduling metadata.');
      selected.push(row);
    }
  }
  return selected;
}

export function rustAssertionEvidence(log, contracts = []) {
  const failures = [...log.matchAll(/^thread '([^']+)'(?: \([^\n]*\))? panicked at ([^\n]+):\n([^\n]+)(?:\n|$)/gm)].map(match => ({ test: match[1], location: match[2], message: match[3], offset: match.index, kind: /^assertion(?: `[^\n]+` failed| failed:)/.test(match[3]) ? 'assertion' : 'runtime' }));
  const events = [];
  for (const match of log.matchAll(/^.*"event"\s*:\s*"caught-boundary-panic".*$/gm)) {
    try { events.push({ value: JSON.parse(match[0]), offset: match.index, used: false }); }
    catch { return { failures, valid: false, reason: 'Malformed total-boundary record.' }; }
  }
  const observations = [];
  for (let index = 0; index < failures.length; index++) {
    const failure = failures[index];
    if (failure.kind !== 'runtime') continue;
    const assertion = failures[index + 1];
    const row = contracts.find(value => value.test_name === failure.test);
    const location = /^(.*):(\d+):(\d+)$/.exec(failure.location);
    const event = events.find(value => !value.used && value.offset > failure.offset && assertion && value.offset < assertion.offset);
    const sourceMatches = row && location && (location[1].replaceAll('\\', '/').endsWith('/' + row.source) || location[1] === row.source) && Number(location[2]) >= row.source_lines[0] && Number(location[2]) <= row.source_lines[1];
    if (!row || !sourceMatches || !assertion || assertion.kind !== 'assertion' || assertion.test !== row.test_name || assertion.message !== row.assertion || !event || canonicalJson(event.value) !== canonicalJson(row.event)) continue;
    event.used = true;
    failure.kind = 'caught-contract-observation';
    observations.push({ test: failure.test, source_sha256: row.source_sha256, definition_sha256: row.definition_sha256, test_sha256: row.test_sha256, review_sha256: row.review_sha256, boundary: row.boundary });
  }
  const assertions = failures.filter(value => value.kind === 'assertion');
  const summaries = [...log.matchAll(/test result: FAILED\. \d+ passed; ([1-9]\d*) failed; 0 ignored/g)].reduce((sum, match) => sum + Number(match[1]), 0);
  return { failures, total_boundary_observations: observations, boundary_events_complete: events.every(value => value.used), valid: failures.length > 0 && assertions.length === summaries && new Set(assertions.map(value => value.test)).size === assertions.length && failures.every(value => value.kind !== 'runtime') && events.every(value => value.used) };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const bytes=readFileSync(0);if(bytes.length>8*1024*1024)throw new Error('Rust assertion input exceeds its bound.');
  const input=JSON.parse(bytes.toString('utf8'));
  if(typeof input.root!=='string'||!input.phase)throw new Error('Rust assertion input lacks the complete protected phase.');
  process.stdout.write(JSON.stringify(rustPhaseEvidence(input.root,input.item??null,input.phase))+'\n');
}
