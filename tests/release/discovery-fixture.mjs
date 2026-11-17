/** Synthetic transcript inputs for testing the release verifier, no outcomes. */
import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { acceptanceInputHash, parseDiscoveryTranscript } from '../../scripts/release/discover-acceptance.mjs';
import { sha256, sourceReceipt } from '../../scripts/release/candidate.mjs';

export function discoveryFixture(root, names = ['one', 'two']) {
  const rust = 'packages/launcher/tests/discovery.rs';
  mkdirSync(path.dirname(path.join(root, rust)), { recursive: true });
  writeFileSync(path.join(root, rust), '// Synthetic empty target for verifier fixtures.\n');
  const common = { collection_root: root, command: path.join(root, 'fixture-runner'), executable_sha256: 'a'.repeat(64), stderr: '' };
  const stdout = JSON.stringify(names.map(name => ({ file: path.join(root, 'tests/fixture.test.mjs'), name })));
  const vitest = { ...common, runner: 'vitest', args: [path.join(root, 'node_modules/vitest/vitest.mjs'), 'list', '--json', '--staticParse=false'], stdout, stdout_sha256: sha256(stdout) };
  const rustList = { ...common, runner: 'rust', args: ['--list', '--format', 'terse'], source: rust, stdout: '', stdout_sha256: sha256('') };
  const buildStdout = JSON.stringify({ reason: 'compiler-artifact', profile: { test: true }, executable: common.command, target: { src_path: path.join(root, rust) } }) + '\n';
  const build = { ...common, runner: 'cargo-build', args: ['test', '--locked', '-p', 'ud-agent-launcher', '--no-run', '--message-format=json'], stdout: buildStdout, stdout_sha256: sha256(buildStdout) };
  const tests = parseDiscoveryTranscript(root, vitest).sort((a, b) => a.id < b.id ? -1 : a.id > b.id ? 1 : 0);
  return { schema_version: 1, kind: 'acceptance-discovery', qualification: 'inventory-only-no-outcomes', collection_root: root,
    environment: { os: 'synthetic', process_arch: 'fixture' }, input_sha256: acceptanceInputHash(sourceReceipt(root)), transcripts: [vitest, rustList], build_transcript: build, tests };
}
