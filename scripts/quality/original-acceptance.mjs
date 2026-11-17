#!/usr/bin/env node
/** Execute original tests and reconcile every case with prior runner discovery. */
import { spawn, spawnSync } from 'node:child_process';
import { mkdirSync, readFileSync, realpathSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { acceptanceInputHash, discoverAcceptance, discoveryEnvironment } from '../release/discover-acceptance.mjs';
import { fileReceipt, sha256, sourceReceipt } from '../release/candidate.mjs';
import { canonicalJson } from '../release/http-transports.mjs';
import { bindOriginalCandidate } from './original-candidate-binding.mjs';
import { originalPythonOutcomes, originalRustOutcomes, originalVitestOutcomes, reconcileOriginalOutcomes } from './original-outcomes.mjs';
import { inheritedStorageDirectory, prepareStorageControl, STORAGE_LIMITS } from './storage-lifecycle.mjs';
import { windowsStorageEnvironment } from './windows-storage.mjs';
import { isWithinStorage } from './original-storage.mjs';

/** Resource reservation only; the release profile makes no release claim.
 * @param {NodeJS.Platform} [platform]
 * @returns {{plannedBytes:number,profile:'ordinary'|'release',transientAllowance?:number}} */
export function originalStoragePlan(platform = process.platform) {
  return platform === 'win32'
    ? { plannedBytes: 8_000_000_000, profile: 'release', transientAllowance: 8_000_000_000 }
    : { plannedBytes: STORAGE_LIMITS.ordinaryBytes, profile: 'ordinary' };
}

/** @param {string} root @param {{output:string,python:string,cargo:string,candidate?:any,candidateRoot?:string,outputOwner?:any}} options */
export function runOriginalAcceptance(root, { output, python, cargo, candidate, candidateRoot, outputOwner }) {
  root = realpathSync(root); output = path.resolve(output);
  if (!path.isAbsolute(python ?? '') || !path.isAbsolute(cargo ?? '') || output === root) throw new Error('Original acceptance requires absolute Python/cargo and a new output directory.');
  // The private copy used by the mutation baseline has no .artifacts tree;
  // create the parent only. The output leaf itself must still be new.
  mkdirSync(path.dirname(output), { recursive: true, mode: 0o700 });
  mkdirSync(output, { recursive: false, mode: 0o700 });
  if (outputOwner) writeFileSync(path.join(output, '.ud-original-owner.json'), JSON.stringify(outputOwner) + '\n', { flag: 'wx', mode: 0o600 });
  const source = sourceReceipt(root), report = { schema_version: 1, kind: 'original-test-acceptance', qualification: 'actual-local-original-tests-not-installed-or-mutation-certification', suite_id: 'unit', status: 'incomplete', source_tree_sha256: source.sha256, input_sha256: acceptanceInputHash(source), environment: { os: process.platform, process_arch: process.arch, host_machine: os.machine(), provider: 'local-host', node_version: process.version }, commands: [], tests: [], executed: 0, skipped: 0 };
  const save = () => writeFileSync(path.join(output, 'report.json'), JSON.stringify(report, null, 2) + '\n');
  const env = { ...discoveryEnvironment(root), UD_AGENT_PYTHON: python, UD_RELEASE_PYTHON: python };
  report.environment.python = { path: python, canonical_path: realpathSync(python), sha256: sha256(readFileSync(realpathSync(python))) };
  function command(program, args, prefix, discovered) {
    const executable = realpathSync(program), before = sha256(readFileSync(executable)), started = performance.now();
    if (discovered && (executable !== discovered.command || before !== discovered.executable_sha256)) throw new Error(`Original acceptance executable changed after discovery: ${prefix}`);
    // Windows fixtures retain their individual deadlines and cancellation.
    // Do not kill an advancing complete suite with another aggregate timer.
    const result = spawnSync(program, args, { cwd: root, env, encoding: 'utf8', ...(process.platform === 'win32' ? {} : { timeout: 30 * 60 * 1000 }), maxBuffer: 64 * 1024 ** 2 });
    for (const [name, text] of [['stdout', result.stdout ?? ''], ['stderr', result.stderr ?? '']]) writeFileSync(path.join(output, `${prefix}.${name}`), text, { flag: 'wx', mode: 0o600 });
    report.commands.push({ executable, executable_sha256: before, args, exit_code: result.status, signal: result.signal, error: result.error?.message ?? null, elapsed_ms: performance.now() - started, stdout: fileReceipt(output, `${prefix}.stdout`), stderr: fileReceipt(output, `${prefix}.stderr`) }); save();
    if (result.error || result.signal || result.status !== 0 || sha256(readFileSync(executable)) !== before) throw new Error(`Original acceptance command failed: ${prefix}`);
    return result.stdout;
  }
  save();
  try {
    if (candidateRoot !== undefined && candidate === undefined) throw new Error('Original evidence candidate root requires a candidate manifest.');
    const binding = candidate === undefined ? undefined : bindOriginalCandidate(root, { candidate, candidateRoot });
    if (binding) { report.candidate_binding = binding; save(); }
    // Discovery executes collection, including parameterized cases, before
    // reading any original execution outcomes.
    const catalog = discoverAcceptance(root, { python, cargo });
    writeFileSync(path.join(output, 'discovery.json'), JSON.stringify(catalog, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
    report.discovery = fileReceipt(output, 'discovery.json'); report.scheduled = catalog.tests.length;
    if (catalog.native_applicability) {
      report.native_applicability = catalog.native_applicability;
      // Foreign declarations remain obligations. They are never scheduled,
      // executed, passed or skipped case observations on this native host.
      report.pending_native_scopes = catalog.native_applicability.scopes.filter(row => row.status === 'pending-native');
    }
    save();
    const nodeDiscovery = catalog.transcripts.find(item => item.runner === 'vitest');
    command(cargo, ['build', '--locked', '-p', 'ud-agent-launcher', '--bin', 'ud-agent-guard'], 'guard-build', catalog.build_transcript);
    // Retain independent later-runner diagnostics after a failed command or
    // outcome parser. These errors can never become acceptance observations.
    function collectRunner(runner, phase, action) {
      try { return { completed: true, value: action() }; }
      catch (error) {
        (report.runner_errors ??= []).push({ runner, phase, message: String(error) }); save();
        return { completed: false };
      }
    }
    collectRunner('static', 'execution', () => command(process.execPath, [path.join(root, 'scripts/quality/check.mjs')], 'static', nodeDiscovery));
    const vitestFile = path.join(output, 'vitest.json');
    // JSON includes case outcomes but can omit unhandled errors that make the
    // runner exit nonzero. Retain its human diagnostics alongside that receipt.
    const vitest = collectRunner('vitest', 'execution', () => command(process.execPath, [path.join(root, 'node_modules/vitest/vitest.mjs'), 'run', '--reporter=default', '--reporter=json', `--outputFile=${vitestFile}`], 'vitest', nodeDiscovery));
    const observations = [];
    collectRunner('vitest', 'outcomes', () => {
      report.vitest = fileReceipt(output, 'vitest.json');
      if (vitest.completed) observations.push(...originalVitestOutcomes(root, JSON.parse(readFileSync(vitestFile, 'utf8'))));
    });
    let index = 0;
    for (const transcript of catalog.transcripts.filter(item => item.runner === 'python')) {
      const prefix = `python-${index++}`, filename = path.join(output, prefix + '.json');
      const result = collectRunner(prefix, 'execution', () => command(python, ['-I', '-B', path.join(root, 'scripts/quality/original-python.py'), '--root', root, '--directory', transcript.directory, '--output', filename], prefix, transcript));
      collectRunner(prefix, 'outcomes', () => {
        (report.python ??= []).push(fileReceipt(output, prefix + '.json'));
        if (result.completed) {
          const data = JSON.parse(readFileSync(filename, 'utf8'));
          if (data.directory !== transcript.directory) throw new Error('Original Python report identifies another directory.');
          observations.push(...originalPythonOutcomes(data));
        }
      });
      save();
    }
    index = 0;
    for (const transcript of catalog.transcripts.filter(item => item.runner === 'rust')) {
      const count = catalog.tests.filter(test => test.runner === 'rust' && test.source === transcript.source).length;
      // Stable libtest has no JSON execution mode. Its complete pretty output
      // is retained and parsed against the independently listed binary cases.
      const prefix = `rust-${index++}`;
      const result = collectRunner(prefix, 'execution', () => command(transcript.command, ['--format', 'pretty', '--color', 'never', '--test-threads', '1'], prefix, transcript));
      if (result.completed) collectRunner(prefix, 'outcomes', () => observations.push(...originalRustOutcomes(transcript.source, result.value, count)));
    }
    if (report.runner_errors?.length) throw new Error('Original acceptance runner failures: ' + report.runner_errors.map(item => `${item.runner} (${item.phase}): ${item.message}`).join('; '));
    report.tests = reconcileOriginalOutcomes(root, catalog, observations); report.executed = report.tests.length;
    report.source_unchanged = sourceReceipt(root).sha256 === source.sha256;
    if (!report.source_unchanged || catalog.input_sha256 !== report.input_sha256) throw new Error('Original acceptance sources changed during execution.');
    if (binding) {
      if (canonicalJson(bindOriginalCandidate(root, { candidate, candidateRoot })) !== canonicalJson(binding)) throw new Error('Original evidence candidate changed during execution.');
      const evidence = { schema_version: 1, qualification: 'unsigned-local-original-tests-not-installed-or-mutation-certification', suite_id: 'unit', verdict: 'passed', executed: report.executed, skipped: 0, errors: 0, tests: report.tests, ...binding.subjects, candidate_binding: binding, environment: report.environment,
        ...(report.native_applicability ? { native_applicability: report.native_applicability, pending_native_scopes: report.pending_native_scopes } : {}),
        raw_execution: { discovery: report.discovery, vitest: report.vitest, python: report.python ?? [], commands: report.commands } };
      writeFileSync(path.join(output, 'unit-evidence.unsigned.json'), JSON.stringify(evidence, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
      report.unsigned_evidence = fileReceipt(output, 'unit-evidence.unsigned.json');
    }
    report.status = 'passed-locally';
  } catch (error) { report.status = 'failed-or-incomplete'; report.reason = String(error); report.source_unchanged = sourceReceipt(root).sha256 === source.sha256; }
  save(); return report;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  /** @type {any} */
  const options = {};
  for (let i = 0; i < args.length; i += 2) {
    const key = { '--output': 'output', '--python': 'python', '--cargo': 'cargo', '--candidate': 'candidate', '--candidate-root': 'candidateRoot' }[args[i]];
    if (!key || !args[i + 1] || options[key]) throw new Error('Usage: original-acceptance.mjs --output NEW_DIRECTORY --python ABSOLUTE_PYTHON --cargo ABSOLUTE_CARGO [--candidate ACTUAL_CANDIDATE_JSON [--candidate-root ABSOLUTE_ARTIFACT_ROOT]]');
    options[key] = args[i + 1];
  }
  if (!options.output) throw new Error('Original acceptance output is required.');
  const root = realpathSync(path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..'));
  options.output = path.resolve(options.output);
  if (options.candidate) options.candidate = path.resolve(options.candidate);
  if (options.candidateRoot) options.candidateRoot = path.resolve(options.candidateRoot);
  // ACL admission precedes the native guard build. Preserve the selected
  // existing Python through the first supervisor and its nested fixture leases.
  if (process.platform === 'win32') Object.assign(process.env, windowsStorageEnvironment(options.python));
  const inherited = inheritedStorageDirectory();
  if (inherited) {
    if (!isWithinStorage(inherited, root)) throw new Error('Original acceptance must execute in the inherited private workspace.');
    if (options.candidate) options.candidate = JSON.parse(readFileSync(options.candidate, 'utf8'));
    const report = runOriginalAcceptance(root, options);
    console.log(JSON.stringify({ status: report.status, scheduled: report.scheduled, executed: report.executed, output: options.output, reason: report.reason ?? null }));
    if (report.status !== 'passed-locally') process.exitCode = 1;
  } else {
    // Native original tests use local private inputs and do not require a
    // Docker engine, including when earlier diagnostics remain in .artifacts.
    if (process.platform === 'win32') prepareStorageControl(root);
    mkdirSync(path.dirname(options.output), { recursive: true, mode: 0o700 });
    const encoded = Buffer.from(JSON.stringify(options)).toString('base64url');
    const supervisor = path.join(root, 'scripts/quality/storage-lifecycle.mjs');
    const worker = path.join(root, 'scripts/quality/original-worker.mjs');
    const storage = originalStoragePlan();
    const args = [supervisor, '--run', root, String(storage.plannedBytes), storage.profile, ...(storage.transientAllowance === undefined ? [] : ['--transient-bytes', String(storage.transientAllowance)]), '--output', options.output, '--output-bytes', String(128 * 1024 ** 2), ...(process.platform === 'darwin' ? ['--scratch-parent', '/private/tmp'] : []), '--', process.execPath, worker, root, encoded];
    const child = spawn(process.execPath, args, { stdio: 'inherit' });
    for (const signal of /** @type {NodeJS.Signals[]} */ (['SIGINT', 'SIGTERM'])) process.once(signal, () => child.kill(signal));
    const result = await new Promise((resolve, reject) => { child.once('error', reject); child.once('close', (code, signal) => resolve({ code, signal })); });
    process.exitCode = result.signal ? 1 : result.code ?? 1;
  }
}
