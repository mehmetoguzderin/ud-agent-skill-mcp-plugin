/** One Vitest invocation inside a fresh kernel-confined mutation job. */
import { createRequire } from 'node:module';
import { closeSync, constants, fstatSync, fsyncSync, lstatSync, mkdirSync, openSync, readFileSync, realpathSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { createHash } from 'node:crypto';
import { captureStrykerError, createStrykerAssertionVerifier, verifyCompiledSources } from './stryker-assertions.mjs';
import { normalizeSubprocessOpacity, validateOpaqueExecutionClosure } from './stryker-opacity.mjs';
export { protectedVitestSetupFiles } from './stryker-config.mjs';

const sha = value => createHash('sha256').update(value).digest('hex');
const assertion = error => error && ['AssertionError', 'AssertionError [ERR_ASSERTION]', 'VitestAssertionError'].includes(error.name) && (error.code === undefined || error.code === null || error.code === 'ERR_ASSERTION');
const demand = (value, message) => { if (!value) throw new Error(`Protected Stryker: ${message}`); };


/** Original fixture compilation uses only the immutable vendor closure. */
export function offlineCargoEnvironment(cache) {
  const home = path.join(cache, 'cargo-home');
  mkdirSync(home, { mode: 0o700 });
  writeFileSync(path.join(home, 'config.toml'), '[net]\noffline = true\n[source.crates-io]\nreplace-with = "verified-vendor"\n[source.verified-vendor]\ndirectory = "/opt/mutation/rust/vendor"\n', { flag: 'wx', mode: 0o600 });
  return { CARGO_HOME: home, CARGO_NET_OFFLINE: 'true', CARGO_BUILD_JOBS: '2', CARGO_INCREMENTAL: '0', CARGO_PROFILE_DEV_DEBUG: '0', CARGO_PROFILE_TEST_DEBUG: '0', RUSTC: '/opt/mutation/rust/bin/rustc' };
}

/** A completed assertion report is protocol success, although Vitest sets 1. */
export function completedAssertionExitCode(report, code) {
  if(['error','timeout'].includes(report?.result?.status)&&(code===undefined||code===0))return 1;
  return code === 1 && report?.result?.status === 'killed' && report.failures?.length > 0 && report.failures.every(failure => failure.failure_kind === 'assertion' && failure.errors?.length > 0 && failure.errors.every(assertion)) && report.outside_errors?.length === 0 ? 0 : code;
}

/** Each file reports its own actual compiled observations from the fixed setup. */
export function compiledSourceInventory(files,childRoot) {
  demand(typeof childRoot==='string'&&path.isAbsolute(childRoot),'compiled source inventory needs its actual job root');
  const entries=new Map();
  for(const file of files){
    const value=file.meta?.ud_agent_compiled_sources_v1;
    demand(value?.schema_version===1&&value.normalization==='ud-job-root-and-inline-map-1'&&value.child_root===childRoot&&Array.isArray(value.entries),'compiled assertion observations missing from an actual test file');
    for(const entry of value.entries){
      demand(typeof entry?.source==='string'&&/^[a-f0-9]{64}$/.test(entry.identity_sha256??''),'compiled assertion identity is missing');
      const key=entry.source+'\0'+entry.identity_sha256,existing=entries.get(key);
      demand(!existing||JSON.stringify(existing)===JSON.stringify(entry),'compiled assertion observations conflict across test files');
      entries.set(key,entry);
    }
  }
  return{schema_version:1,normalization:'ud-job-root-and-inline-map-1',child_root:childRoot,entries:[...entries.values()].sort((a,b)=>a.source<b.source?-1:a.source>b.source?1:a.identity_sha256.localeCompare(b.identity_sha256))};
}

export function requireCompiledTestCases(compiled,tests){
  demand(Array.isArray(compiled?.entries)&&Array.isArray(tests)&&tests.length>0,'actual compiled test case inventory is missing');
  const sources=new Set(compiled.entries.map(entry=>entry.source));
  demand(tests.every(test=>sources.has(test.source)),'an executed test module is absent from actual compiled-source observations');
}

/** The sealed job namespace precreates exactly one empty owned output file. */
export function writeChildResult(filename, report) {
  const bytes = Buffer.from(JSON.stringify(report)); demand(bytes.length <= 32 * 1024 * 1024, 'result exceeds bound');
  const fd = openSync(filename, constants.O_WRONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0));
  try {
    const before = fstatSync(fd);
    demand(before.isFile() && before.nlink === 1 && before.size === 0 && (before.mode & 0o777) === 0o600 && before.uid === process.getuid?.(), 'result is not the empty owned protocol file');
    writeFileSync(fd, bytes); fsyncSync(fd);
    const after = fstatSync(fd);
    demand(after.dev === before.dev && after.ino === before.ino && after.nlink === 1 && after.size === bytes.length, 'result changed during protocol write');
  } finally { closeSync(fd); }
}

export function childTestInventory(tests, root) {
  const occurrences = new Map();
  return tests.map(test => {
    demand(typeof test.id === 'string' && test.fileName && typeof test.name === 'string', 'test identity missing');
    const source = path.relative(root, test.fileName).split(path.sep).join('/');
    demand(source.startsWith('tests/') && !source.split('/').includes('..'), 'test source escapes private handoff');
    const key = `${source}\0${test.name}`, occurrence = occurrences.get(key) ?? 0;
    occurrences.set(key, occurrence + 1);
    const { failureMessage, ...identity } = test;
    return { ...identity, upstream_id: test.id, ...(typeof failureMessage === 'string' ? { failureMessage: failureMessage.slice(0, 4096), failure_message_sha256: sha(failureMessage), failure_message_truncated: failureMessage.length > 4096 } : {}), id: `${source}#ud-case-${sha(JSON.stringify([test.name, occurrence])).slice(0, 24)}`, source, occurrence,
      source_sha256: sha(readFileSync(path.join(root, source))) };
  });
}

function hitCounts(value) {
  demand(value && typeof value === 'object' && !Array.isArray(value), 'coverage hit map missing');
  const result = {};
  for (const [id, hits] of Object.entries(value)) {
    demand(/^(?:0|[1-9][0-9]*)$/.test(id) && Number.isSafeInteger(hits) && hits >= 0, 'invalid coverage mutant identity or hit count');
    result[id] = hits;
  }
  return result;
}

export function protectedSelectionFingerprint(cases) {
  demand(Array.isArray(cases), 'selection case inventory missing');
  return sha(JSON.stringify(cases.map(test => [test.id, test.source, test.source_sha256, test.name, test.occurrence, test.upstream_id])));
}

/** Duplicate upstream display IDs conservatively cover every real occurrence. */
export function normalizeProtectedCoverage(coverage, tests, perFileStatic = {}, opacity = null) {
  demand(coverage && typeof coverage === 'object' && coverage.perTest && typeof coverage.perTest === 'object' && !Array.isArray(coverage.perTest) && Array.isArray(tests) && tests.length > 0, 'complete original coverage missing');
  const aliases = new Map(), sources = new Set(), perTest = {};
  for (const test of tests) {
    demand(test && typeof test.id === 'string' && typeof test.upstream_id === 'string' && typeof test.source === 'string' && test.source.startsWith('tests/') && test.upstream_id === test.source + '#' + test.name, 'coverage test identity is not source bound');
    const values = aliases.get(test.upstream_id) ?? []; values.push(test.id); aliases.set(test.upstream_id, values); sources.add(test.source);
  }
  for (const [raw, counts] of Object.entries(coverage.perTest)) {
    demand(aliases.has(raw), 'coverage identifies an undiscovered test');
    const hits = hitCounts(counts);
    for (const id of aliases.get(raw)) perTest[id] = { ...hits };
  }
  const staticByFile = {};
  demand(perFileStatic && typeof perFileStatic === 'object' && !Array.isArray(perFileStatic), 'static coverage attribution missing');
  for (const [source, counts] of Object.entries(perFileStatic)) {
    demand(sources.has(source), 'static coverage identifies an undiscovered test file');
    staticByFile[source] = hitCounts(counts);
  }
  return { schema_version: 1, contract: 'pristine-per-test-coverage-v1', perTest, static: hitCounts(coverage.static), staticByFile, ...(opacity ? { opacity: normalizeSubprocessOpacity(opacity, tests) } : {}) };
}

/** The trusted parent derives required cases; a framework filter cannot narrow it. */
export function protectedCoverageSelection(mutantId, coverage, tests, { unattributedFullSuite = false, requireOpacity = false } = {}) {
  demand(typeof mutantId === 'string' && /^(?:0|[1-9][0-9]*)$/.test(mutantId) && coverage?.schema_version === 1 && coverage.contract === 'pristine-per-test-coverage-v1' && Array.isArray(tests) && tests.length > 0, 'invalid coverage selection authority');
  const byId = new Map(), sources = new Map();
  for (const test of tests) {
    demand(test && typeof test.source === 'string' && test.source.startsWith('tests/') && !/[\\\0:]/.test(test.source) && !test.source.split('/').some(part => !part || part === '.' || part === '..') && typeof test.upstream_id === 'string' && test.upstream_id === test.source + '#' + test.name && typeof test.name === 'string' && test.name.length > 0 && Number.isSafeInteger(test.occurrence) && test.occurrence >= 0 && test.id === `${test.source}#ud-case-${sha(JSON.stringify([test.name, test.occurrence])).slice(0, 24)}` && /^[a-f0-9]{64}$/.test(test.source_sha256 ?? '') && !byId.has(test.id), 'required test identity is not a complete original case');
    byId.set(test.id, test);
    const values = sources.get(test.source) ?? []; values.push(test.id); sources.set(test.source, values);
  }
  const selected = new Set(), staticTotal = hitCounts(coverage.static)[mutantId] ?? 0;
  demand(coverage.perTest && typeof coverage.perTest === 'object' && !Array.isArray(coverage.perTest) && coverage.staticByFile && typeof coverage.staticByFile === 'object' && !Array.isArray(coverage.staticByFile), 'coverage selection maps missing');
  for (const [id, counts] of Object.entries(coverage.perTest)) {
    demand(byId.has(id), 'coverage contains an unknown case');
    if ((hitCounts(counts)[mutantId] ?? 0) > 0) selected.add(id);
  }
  let attributed = 0;
  for (const [source, counts] of Object.entries(coverage.staticByFile)) {
    demand(sources.has(source), 'coverage contains an unknown file');
    const hits = hitCounts(counts)[mutantId] ?? 0;
    attributed += hits;
    demand(Number.isSafeInteger(attributed), 'static coverage count overflow');
    if (hits > 0) for (const id of sources.get(source)) selected.add(id);
  }
  demand(attributed <= staticTotal, 'attributed static coverage exceeds its complete original total');
  // Startup/hook coverage which cannot be attributed to a closed file requires
  // the entire original suite. It must never become an empty/uncovered slice.
  if (staticTotal > attributed) for (const id of byId.keys()) selected.add(id);
  const unattributed = selected.size === 0;
  demand(!unattributed || unattributedFullSuite === true, 'mutant has no trustworthy original test coverage');
  if (unattributed) for (const id of byId.keys()) selected.add(id);
  demand(!requireOpacity || coverage.opacity, 'complete pristine subprocess/worker opacity is missing');
  const opaque = coverage.opacity ? validateOpaqueExecutionClosure(coverage.opacity, tests) : null;
  if (opaque) {
    for (const id of opaque.case_ids) selected.add(id);
    for (const file of opaque.files) for (const id of sources.get(file)) selected.add(id);
    if (opaque.global) for (const id of byId.keys()) selected.add(id);
  }
  // The pinned upstream name filter is an escaped suffix pattern. Include its
  // full literal closure so aliases or suffix collisions cannot be omitted.
  const names = [...selected].map(id => byId.get(id).name);
  const files = new Set([...selected].map(id => byId.get(id).source));
  for (const test of tests) if (files.has(test.source) && names.some(name => test.name.endsWith(name))) selected.add(test.id);
  const cases = tests.filter(test => selected.has(test.id));
  const identities = cases.map(({ id, source, source_sha256, name, occurrence, upstream_id }) => ({ id, source, source_sha256, name, occurrence, upstream_id }));
  return { schema_version: 1, contract: 'pristine-per-test-selection-v1', strategy: unattributed ? 'unattributed-original-full-suite' : opaque?.global ? 'opaque-original-full-suite' : opaque && (opaque.case_ids.length || opaque.files.length) ? 'observed-original-coverage-plus-opaque-cases' : 'observed-original-coverage', mutant_id: mutantId, cases: identities, sha256: protectedSelectionFingerprint(identities) };
}

/** Apply exactly the source-bound, zero-based Stryker definition. */
export function materializeExactMutation(source, definition) {
  demand(typeof source === 'string' && definition?.tool === 'stryker' && definition.version === '10.1.1' && typeof definition.operator === 'string' && typeof definition.original === 'string' && typeof definition.replacement === 'string', 'invalid exact mutation definition');
  const lines = source.split('\n');
  function offset(position) {
    demand(position && Number.isSafeInteger(position.line) && Number.isSafeInteger(position.column) && position.line >= 0 && position.line < lines.length && position.column >= 0 && position.column <= lines[position.line].length, 'mutation exceeds source coordinates');
    return lines.slice(0, position.line).reduce((count, line) => count + line.length + 1, 0) + position.column;
  }
  const start = offset(definition.location?.start), end = offset(definition.location?.end);
  demand(end >= start && source.slice(start, end) === definition.original, 'mutation original range differs');
  return source.slice(0, start) + definition.replacement + source.slice(end);
}

export function mutationDefinitionFingerprint(definition) {
  const keys = value => value && Object.getPrototypeOf(value) === Object.prototype ? Object.keys(value).sort().join(',') : '';
  demand(keys(definition) === 'location,operator,original,replacement,tool,version' && keys(definition.location) === 'end,start' && keys(definition.location.start) === 'column,line' && keys(definition.location.end) === 'column,line', 'mutation definition shape differs from canonical contract');
  for (const name of ['tool', 'version', 'operator', 'original', 'replacement']) demand(typeof definition[name] === 'string', 'mutation definition has a non-string field');
  for (const end of ['start', 'end']) for (const name of ['line', 'column']) demand(Number.isSafeInteger(definition.location[end][name]) && definition.location[end][name] >= 0, 'mutation definition has invalid coordinates');
  // The closed definition schema is ordered exactly as canonicalJson: only
  // primitive strings and integer source coordinates occur in this contract.
  return sha(JSON.stringify({ location: { end: { column: definition.location.end.column, line: definition.location.end.line }, start: { column: definition.location.start.column, line: definition.location.start.line } }, operator: definition.operator, original: definition.original, replacement: definition.replacement, tool: definition.tool, version: definition.version }));
}

let astTools;
async function mutationAstTools() {
  if (!astTools) astTools = (async () => {
    const require = createRequire(import.meta.url);
    demand(require('@stryker-mutator/instrumenter/package.json').version === '10.1.1', 'instrumenter version differs from schedule');
    const directory = path.dirname(require.resolve('@stryker-mutator/instrumenter'));
    const [parser, mutators, printer, mutant, babel, generator] = await Promise.all([
      import(pathToFileURL(path.join(directory, 'parsers/index.js')).href),
      import(pathToFileURL(path.join(directory, 'mutators/index.js')).href),
      import(pathToFileURL(path.join(directory, 'printers/index.js')).href),
      import(pathToFileURL(path.join(directory, 'mutant.js')).href), import('@babel/core'), import('@babel/generator'),
    ]);
    return { parse: parser.createParser({}), mutators: mutators.allMutators, print: printer.print, Mutant: mutant.Mutant, traverse: babel.traverse, generate: generator.default };
  })();
  return astTools;
}

function semanticAst(value) {
  if (Array.isArray(value)) return value.map(semanticAst);
  if (!value || typeof value !== 'object') return value;
  const metadata = new Set(['start', 'end', 'loc', 'range', 'extra', 'comments', 'leadingComments', 'innerComments', 'trailingComments', 'tokens', 'errors']);
  return Object.fromEntries(Object.keys(value).filter(key => !metadata.has(key) && value[key] !== undefined).sort().map(key => [key, semanticAst(value[key])]));
}

/** Re-derive the exact registered AST mutation, then prove its serialization. */
export async function serializeScheduledMutation(source, definition, filename) {
  materializeExactMutation(source, definition); // Validate exact coordinates and original bytes first.
  const tools = await mutationAstTools(), ast = await tools.parse(source, filename);
  const operator = tools.mutators.find(item => item.name === definition.operator);
  demand(operator, 'mutation operator is not in the locked instrumenter');
  const matches = [];
  tools.traverse(ast.root, { enter(nodePath) {
    const loc = nodePath.node.loc;
    if (!loc || !['start', 'end'].every(end => loc[end].line - 1 === definition.location[end].line && loc[end].column === definition.location[end].column)) return;
    for (const replacement of operator.mutate(nodePath)) if (tools.generate(replacement).code === definition.replacement) matches.push({ original: nodePath.node, replacement });
  } });
  demand(matches.length === 1, 'definition is not one uniquely applicable locked AST operator');
  const selected = new tools.Mutant('exact-materialization', filename, matches[0].original, { replacement: matches[0].replacement, mutatorName: definition.operator });
  const expected = await tools.parse(tools.print({ ...ast, root: selected.applied(ast.root) }), filename);
  const expectedShape = JSON.stringify(semanticAst(expected.root));
  const alternatives = [definition.replacement, ` ${definition.replacement} `, `( ${definition.replacement} )`];
  for (const replacement of alternatives) {
    const content = materializeExactMutation(source, { ...definition, replacement });
    let candidate;
    try { candidate = await tools.parse(content, filename); } catch { continue; }
    if (JSON.stringify(semanticAst(candidate.root)) === expectedShape) return { content, serialized_replacement: replacement, materializer_version: 'stryker-ast-materializer-v1' };
  }
  throw new Error('Protected Stryker: exact AST mutation has no verified private-source serialization.');
}

/** Runtime errors and missing/skipped tests are never converted into kills. */
export function summarizeChildRun({ kind, result, tests, errors, outsideErrors = [], selection = null, perFileStatic = {}, verifyAssertion = null, opacity = null }, root) {
  demand(['dry-run', 'selection-baseline', 'mutant'].includes(kind) && Array.isArray(tests) && Array.isArray(errors) && errors.length === tests.length, 'invalid child run');
  const collected = childTestInventory(tests, root);
  let inventory = collected, selectedErrors = errors, notSelected = [], inconsistentErrors = false;
  if (selection) {
    demand(selection.contract === 'pristine-per-test-selection-v1' && Array.isArray(selection.cases) && selection.cases.length > 0 && Array.isArray(selection.all_cases) && selection.all_cases.length >= selection.cases.length && selection.sha256 === protectedSelectionFingerprint(selection.cases), 'invalid required selection binding');
    const all = new Map(selection.all_cases.map(test => [test.id, test])), wanted = new Map(selection.cases.map(test => [test.id, test]));
    demand(all.size === selection.all_cases.length && wanted.size === selection.cases.length && selection.cases.every(test => all.has(test.id) && protectedSelectionFingerprint([test]) === protectedSelectionFingerprint([all.get(test.id)])), 'selected cases differ from full original inventory');
    demand(protectedSelectionFingerprint(selection.all_cases.filter(test => wanted.has(test.id))) === selection.sha256, 'selected cases do not preserve original manifest order');
    for (let index = 0; index < collected.length; index++) {
      const test = collected[index];
      const original = all.get(test.id);
      demand(original && ['source', 'source_sha256', 'name', 'occurrence', 'upstream_id'].every(key => test[key] === original[key]), 'collected case differs from original coverage identity');
      demand(wanted.has(test.id) || test.status === 2, 'a nonselected case executed unexpectedly');
      if (!wanted.has(test.id) && (!Array.isArray(errors[index]) || errors[index].length > 0)) inconsistentErrors = true;
    }
    inventory = collected.filter(test => wanted.has(test.id));
    selectedErrors = errors.filter((_, index) => wanted.has(collected[index].id));
    demand(inventory.length === wanted.size && new Set(inventory.map(test => test.id)).size === wanted.size, 'required selected cases are missing or duplicated');
    notSelected = selection.all_cases.filter(test => !wanted.has(test.id)).map(test => test.id);
  }
  const failures = [];
  for (let index = 0; index < inventory.length; index++) {
    const test = inventory[index], found = selectedErrors[index];
    demand(Array.isArray(found), 'test errors missing');
    if (test.status === 0 && found.length > 0) inconsistentErrors = true;
    if (test.status === 1) {
      const captured = found.map(error => ({ ...captureStrykerError(error), ...(verifyAssertion ? { assertion_origin: verifyAssertion(test, error) } : {}) }));
      failures.push({ test_id: test.id, failure_kind: captured.length && captured.every(error => assertion(error) && (!verifyAssertion || error.assertion_origin.valid === true)) ? 'assertion' : 'runtime', errors: captured });
    }
  }
  const runtimeFailure = failures.some(item => item.failure_kind !== 'assertion');
  const inconsistent = kind === 'mutant' && ((result?.status === 'killed' && !failures.length) || (result?.status === 'survived' && failures.length));
  const invalid = !inventory.length || inventory.some(test => ![0, 1].includes(test.status)) || outsideErrors.length || runtimeFailure || inconsistent || inconsistentErrors || kind !== 'mutant' && inventory.some(test => test.status !== 0);
  let runnerResult;
  if (invalid) runnerResult = { status: 'error', errorMessage: 'Missing/skipped tests, collection errors or non-assertion runtime failure in protected test job.' };
  else if (kind !== 'mutant') runnerResult = (kind === 'dry-run' ? result?.status === 'complete' : result?.status === 'survived') ? { status: 'complete', tests: inventory, ...(result.mutantCoverage ? { mutantCoverage: normalizeProtectedCoverage(result.mutantCoverage, inventory, perFileStatic, opacity) } : {}) } : { status: 'error', errorMessage: 'Protected dry run did not complete.' };
  else if (!['killed', 'survived'].includes(result?.status)) runnerResult = { status: result?.status === 'timeout' ? 'timeout' : 'error', errorMessage: 'Protected mutant runner did not complete.' };
  else if (failures.length) runnerResult = { status: 'killed', killedBy: failures.map(item => item.test_id), nrOfTests: inventory.length,
    failureMessage: failures[0].errors[0].message, duration: result.duration };
  else runnerResult = { status: 'survived', nrOfTests: inventory.length, duration: result.duration };
  return { schema_version: 1, child_root: root, result: runnerResult, tests: inventory, failures, outside_errors: outsideErrors.map(value => String(value).slice(0, 4096)), ...(opacity ? { subprocess_opacity: opacity } : {}), ...(selection ? { selection_sha256: selection.sha256, not_selected: notSelected } : {}) };
}

export async function runIsolatedVitest(request) {
  demand(request?.schema_version === 1 && ['dry-run', 'selection-baseline', 'mutant'].includes(request.kind) && request.options && request.options.disableBail === true, 'invalid request');
  demand(!request.options.testFilter?.length && !request.options.testFiles?.length && !request.options.hitLimit && (!request.options.coverageAnalysis || ['off', 'perTest'].includes(request.options.coverageAnalysis)), 'filtered or truncated mutation tests');
  const selection = request.options.selection ?? null;
  demand(request.kind !== 'selection-baseline' || selection, 'selected baseline has no required inventory');
  demand(request.kind !== 'dry-run' || selection === null, 'full original coverage may not be narrowed');
  demand(process.platform === 'linux' && process.getuid?.() >= 100001 && process.cwd().startsWith('/tmp/ud-mutation-jobs/'), 'a private kernel-confined UID and workspace are required');
  const status = readFileSync('/proc/self/status', 'utf8');
  for (const name of ['CapEff', 'CapPrm', 'CapInh', 'CapAmb', 'CapBnd']) demand(new RegExp(`^${name}:\\s+0000000000000000$`, 'm').test(status), 'capabilities survived');
  demand(/^NoNewPrivs:\s+1$/m.test(status), 'privilege acquisition survived');
  const root = realpathSync('.');
  demand(request.readonly_tree === true && lstatSync(root).uid === 0 && (lstatSync(root).mode & 0o222) === 0, 'source handoff must be sealed before test execution');
  const cache = realpathSync(process.env.TMPDIR ?? '');
  const cacheInfo = lstatSync(cache);
  demand(cache === path.join(path.dirname(root), 'cache') && cacheInfo.isDirectory() && cacheInfo.uid === process.getuid() && (cacheInfo.mode & 0o077) === 0, 'private writable test cache missing');
  Object.assign(process.env, offlineCargoEnvironment(cache));
  const imageGuard = '/opt/mutation/bin/ud-agent-guard', privateGuard = path.join(root, 'target/debug/ud-agent-guard');
  const privateGuardInfo = lstatSync(privateGuard);
  demand(privateGuardInfo.isFile() && privateGuardInfo.uid === 0 && privateGuardInfo.nlink === 1 && (privateGuardInfo.mode & 0o777) === 0o555 && sha(readFileSync(privateGuard)) === sha(readFileSync(imageGuard)), 'sealed native fixture input differs from image');
  process.env.UD_MUTATION_GUARD = privateGuard;
  delete process.env.UD_STRYKER_EVIDENCE;
  process.env.PYTHONPATH = `${path.join(root, 'workers/ud/src')}:/opt/ud-agent/upstream/udtools/src`;
  let materialization;
  if (request.kind === 'mutant') {
    const change = request.mutation;
    demand(change && typeof change.path === 'string' && !/[\\\0:]/.test(change.path) && !change.path.split('/').some(part => !part || part === '.' || part === '..') && /^(?:packages|scripts|workers|evals)\//.test(change.path), 'mutation target escapes private source');
    const bytes = Buffer.from(change.content_base64, 'base64');
    demand(bytes.length <= 16 * 1024 * 1024 && bytes.length === change.size && sha(bytes) === change.after_sha256 && /^[a-f0-9]{64}$/.test(change.before_sha256), 'materialized source differs from its exact definition');
    const filename = path.join(root, change.path);
    demand(realpathSync(filename) === filename, 'mutation target has a symlink');
    const metadata = lstatSync(filename);
    demand(metadata.isFile() && metadata.nlink === 1 && metadata.uid === 0 && (metadata.mode & 0o222) === 0 && readFileSync(filename).equals(bytes), 'sealed materialization differs from scheduled bytes');
    materialization = { path: change.path, before_sha256: change.before_sha256, after_sha256: change.after_sha256, materializer_version: change.materializer_version, serialized_replacement: change.serialized_replacement, size: bytes.length };
  }
  const require = createRequire(import.meta.url);
  const index = require.resolve('@stryker-mutator/vitest-runner');
  const directory = path.dirname(index);
  demand(JSON.parse(readFileSync(path.resolve(directory, '../../package.json'), 'utf8')).version === '10.1.1', 'Vitest runner version differs from lock');
  const { VitestTestRunner } = await import(pathToFileURL(path.join(directory, 'vitest-test-runner.js')).href);
  const { collectTestsFromSuite, convertTestToTestResult, normalizeCoverage } = await import(pathToFileURL(path.join(directory, 'vitest-helpers.js')).href);
  const { vitestWrapper } = await import(pathToFileURL(path.join(directory, 'vitest-wrapper.js')).href);
  const createVitest = vitestWrapper.createVitest;
  // Vite's default bundled-config loader writes node_modules/.vite-temp before
  // reading cacheDir. Its documented runner loader keeps the closure read-only.
  vitestWrapper.createVitest = (mode, options) => createVitest(mode, { ...options, root, configLoader: 'runner', cacheDir: path.join(cache, '.ud-vite-cache') });
  const logger = Object.fromEntries(['trace', 'debug', 'info', 'warn', 'error', 'fatal'].map(name => [name, () => {}]));
  logger.isDebugEnabled = () => false;
  const config = path.join(cache, '.ud-protected-vitest.config.mjs');
  const assertionContext={schema_version:1,source_root:root,source_inventory:request.source_inventory,kind:request.kind};
  writeFileSync(config, `import original from ${JSON.stringify(pathToFileURL(path.join(root, 'vitest.config.mts')).href)};\nimport {protectedVitestSetupFiles} from ${JSON.stringify(new URL('./stryker-config.mjs', import.meta.url).href)};\nexport default {...original, root: ${JSON.stringify(root)}, cacheDir: ${JSON.stringify(path.join(cache, '.ud-vite-cache'))}, test: {...original.test, provide:{...original.test?.provide,ud_agent_assertion_context_v1:${JSON.stringify(assertionContext)}},setupFiles: protectedVitestSetupFiles(original.test?.setupFiles), cache: false, fsModuleCache: false, includeTaskLocation: true}};\n`, { flag: 'wx', mode: 0o600 });
  const runner = new VitestTestRunner({ vitest: { configFile: config, related: false, pool: 'forks' }, disableBail: true }, logger, '__stryker__');
  // The pinned upstream runner exposes this generated setup-file path. Its
  // contents stay unchanged; only generated output belongs in the job cache.
  demand(typeof runner.localSetupFile === 'string', 'locked runner setup-file contract changed');
  runner.localSetupFile = path.join(cache, 'stryker-setup.js');
  let perFileStatic = {};
  const readCoverage = runner.readMutantCoverage?.bind(runner);
  demand(typeof readCoverage === 'function', 'locked runner coverage contract changed');
  runner.readMutantCoverage = () => {
    // The pinned upstream merger mutates its first file's accumulator. Capture
    // original per-file numbers before that merge loses their attribution.
    perFileStatic = {};
    for (const file of runner.ctx.state.getFiles()) if (file.meta.mutantCoverage) {
      const source = path.relative(root, file.filepath).split(path.sep).join('/');
      const counts = hitCounts(normalizeCoverage(file.meta.mutantCoverage).static);
      const total = perFileStatic[source] ?? {};
      for (const [id, hits] of Object.entries(counts)) {
        total[id] = (total[id] ?? 0) + hits;
        demand(Number.isSafeInteger(total[id]), 'per-file static coverage count overflow');
      }
      perFileStatic[source] = total;
    }
    return readCoverage();
  };
  try {
    await runner.init();
    const options = { ...request.options, ...(request.options.sandboxFileName ? { sandboxFileName: path.join(root, request.options.sandboxFileName) } : {}) };
    delete options.selection;
    if (selection) {
      demand(selection.contract === 'pristine-per-test-selection-v1' && selection.sha256 === protectedSelectionFingerprint(selection.cases), 'required case fingerprint changed');
      options.testFilter = [...new Set(selection.cases.map(test => {
        demand(typeof test.upstream_id === 'string' && test.upstream_id === test.source + '#' + test.name && test.source.startsWith('tests/') && !/[\\\0:]/.test(test.source) && !test.source.split('/').some(part => !part || part === '.' || part === '..'), 'unsafe selected test filter');
        return test.upstream_id;
      }))];
      demand(options.testFilter.length > 0, 'selected test set is empty');
    }
    if (request.kind === 'selection-baseline') Object.assign(options, { activeMutant: { id: 'ud-pristine-selection-baseline' }, mutantActivation: 'static', reloadEnvironment: true, sandboxFileName: path.join(root, selection.cases[0].source) });
    const result = await (request.kind === 'dry-run' ? runner.dryRun(options) : runner.mutantRun(options));
    const files = runner.ctx.state.getFiles();
    const tasks = files.flatMap(collectTestsFromSuite);
    const converted=tasks.map(test=>convertTestToTestResult(test,' > ')),canonical=childTestInventory(converted,root),byTask=new Map(tasks.map((task,index)=>[task,canonical[index]]));
    const opacity={schema_version:1,contract:'pristine-subprocess-opacity-source-v1',files:files.map(file=>({
      source:path.relative(root,file.filepath).split(path.sep).join('/'),source_sha256:sha(readFileSync(file.filepath)),observations:file.meta.ud_agent_subprocess_opacity_v1,
      case_tasks:collectTestsFromSuite(file).map(task=>({native_id:task.id,case_id:byTask.get(task).id})),
    }))};
    // A fixed setup must have observed the complete original task inventory.
    // Selection-baseline/mutant catalogs may contain only selected files, but
    // their own actual task tables remain checked before report harvesting.
    normalizeSubprocessOpacity(opacity,canonical);
    const outsideErrors = [...runner.ctx.state.errorsSet].map(error => error?.message ?? error);
    for (const file of files) if (file.result?.state === 'fail' && !collectTestsFromSuite(file).some(test => test.result?.state === 'fail')) outsideErrors.push(...(file.result.errors?.length ? file.result.errors.map(error => error.message) : ['Test file failed outside a completed test.']));
    const compiled=compiledSourceInventory(files,root),pristine=request.kind==='dry-run'?compiled:request.assertion_compiled_sources;
    requireCompiledTestCases(compiled,canonical.filter(test=>selection===null||selection.cases.some(selected=>selected.id===test.id)));
    verifyCompiledSources(pristine,compiled,{sourceRoot:root,sourceInventory:request.source_inventory});
    const verifyAssertion = await createStrykerAssertionVerifier({ sourceRoot: root, childRoot: root, sourceInventory: request.source_inventory, immutableSdkContext: request.assertion_sdk_context,compiledSources:pristine });
    return { ...summarizeChildRun({ kind: request.kind, result, tests: converted, errors: tasks.map(test => test.result?.errors ?? []), outsideErrors, selection, perFileStatic, verifyAssertion, opacity }, root), assertion_sdk_context: request.assertion_sdk_context, assertion_compiled_sources:compiled, ...(materialization ? { materialization } : {}) };
  } finally { await runner.dispose(); }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  demand(process.argv.length === 4, 'expected exact request and result file paths');
  const [input, output] = process.argv.slice(2);
  demand(path.basename(input) === 'request.json' && path.basename(output) === 'result.json' && path.dirname(input) === path.dirname(process.cwd()) && path.dirname(output) === path.dirname(process.cwd()) && path.basename(process.cwd()) === 'tree', 'result files must belong to this job');
  let report;
  try {
    const bytes = readFileSync(input); demand(bytes.length <= 32 * 1024 * 1024, 'request exceeds bound');
    report = await runIsolatedVitest(JSON.parse(bytes.toString('utf8')));
  } catch (error) { report = { schema_version: 1, child_root: process.cwd(), result: { status: 'error', errorMessage: String(error?.stack ?? error).slice(0, 65536) }, tests: [], failures: [], outside_errors: [] }; }
  writeChildResult(output, report);
  // This follows successful manifest creation and runner disposal. Unexpected
  // exceptions, missing manifests and all non-assertion outcomes retain failure.
  process.exitCode = completedAssertionExitCode(report, process.exitCode);
}
