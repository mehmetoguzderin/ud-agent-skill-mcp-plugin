import { test } from 'vitest';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync, realpathSync, symlinkSync, readFileSync, existsSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import { parse } from 'yaml';
import { parse as parseToml } from 'smol-toml';
import { NATIVE_RECIPES, configureNativeProfile, finalizeNativeProfile, nativeArguments } from '../../evals/local/native-recipes.mjs';
import { CLIENT_LOCK, prepareNativeClients } from '../../evals/local/native-clients.mjs';
import { nativeTranscript, nativeConformance, nativeConformanceDirectory, nativeAdapterIdentity, oracleIsolationPolicy } from '../../evals/local/native.mjs';
import { DESKTOP_SURFACES, startDesktop } from '../../evals/local/desktop.mjs';
import { containerArguments, selectedDockerEnvironment, privateBridgeNetwork } from '../../evals/local/container.mjs';
import { validateCoordinatorArguments, createCoordinatorBridge } from '../../evals/local/coordinator-bridge.mjs';
import { runOwned } from '../../evals/local/process.mjs';
import { observedSkillBody } from '../../evals/local/native-conformance.mjs';
import { sha256, sourceReceipt } from '../../scripts/release/candidate.mjs';

test('mini skill evidence decodes its native JSON result without assuming activation', () => {
  const body = '# Skill\nRead <evidence>.', requests = [{ body: { messages: [] } }, { body: { messages: [{ role: 'tool', content: JSON.stringify({ returncode: 0, output: body }).replaceAll('<', '\\u003c') }] } }];
  assert.equal(observedSkillBody('mini-swe-agent', requests, body), true);
  assert.equal(observedSkillBody('mini-swe-agent', requests, body + ' absent'), false);
  requests[1].body.messages[0].content = JSON.stringify({ returncode: 1, output: body });
  assert.equal(observedSkillBody('mini-swe-agent', requests, body), false);
});

test('every native surface has an explicit recipe or actual desktop identity', async () => {
  assert.equal(Object.keys(NATIVE_RECIPES).length, 11); assert.equal(Object.keys(DESKTOP_SURFACES).length, 7);
  assert.deepEqual(new Set(CLIENT_LOCK.clients.map(row => row.id)), new Set(Object.keys(NATIVE_RECIPES)));
  assert.equal(NATIVE_RECIPES['mini-swe-agent'].skillMechanism, 'registered-shell-workflow-catalog');
  assert.equal(NATIVE_RECIPES['mini-swe-agent'].requiresContainer, true);
  await assert.rejects(startDesktop({ harness: { id: 'codex-ide' } }), /LIFECYCLE_UNVERIFIED/);
});
test('private clients never acquire implicitly or during CI', async () => {
  await assert.rejects(prepareNativeClients('/repository', { ids: [] }), /opt-in/);
});
test('Codex private profiles disable unbudgeted web and subagent tools through supported native settings', () => {
  const profile=mkdtempSync(path.join(os.tmpdir(),'ud-codex-profile-'));
  try {
    configureNativeProfile('codex-cli',{profile,taskRoot:'/private/task',model:'fixture',endpoint:'http://127.0.0.1:9999',env:{},skillsEnabled:true});
    const text=readFileSync(path.join(profile,'.codex/config.toml'),'utf8');
    assert.match(text,/^web_search = "disabled"/);assert.match(text,/\[features\]\nmulti_agent = false/);
    assert.match(text,/trust_level = "trusted"/);
  } finally {rmSync(profile,{recursive:true,force:true});}
});
test('Codex delegates sandboxing only to the verified outer container adapter', () => {
  const options = { model: 'fixture', endpoint: 'http://127.0.0.1:9999', taskRoot: '/task', output: '/profile/output', prompt: 'natural request' };
  const native = nativeArguments('codex-cli', options), container = nativeArguments('codex-cli', { ...options, isolatedContainer: true });
  assert.equal(native[native.indexOf('--sandbox') + 1], 'workspace-write');
  assert.equal(container[container.indexOf('--sandbox') + 1], 'danger-full-access');
});
test('Codex separates its positional prompt from the variadic image option', () => {
  const options = { model: 'fixture', endpoint: 'http://127.0.0.1:9999', taskRoot: '/task', output: '/profile/output', prompt: 'Read the attached image.' };
  const args = nativeArguments('codex-cli', { ...options, image: '/task/diagram.png' });
  assert.deepEqual(args.slice(args.indexOf('--image')), ['--image', '/task/diagram.png', '--', options.prompt]);
  assert.deepEqual(nativeArguments('codex-cli', { ...options, prompt: '--literal user request' }).slice(-2), ['--', '--literal user request']);
});
test('Gemini uses its documented endpoint variable and Qwen preserves native discovery', () => {
  const profile = mkdtempSync(path.join(os.tmpdir(), 'ud-native-profile-'));
  try {
    const configured = configureNativeProfile('gemini-cli', { profile, model: 'fixture', endpoint: 'http://127.0.0.1:9999', env: {}, skillsEnabled: true });
    assert.equal(configured.env.GOOGLE_GEMINI_BASE_URL, 'http://127.0.0.1:9999');
    assert.equal(configured.env.GEMINI_API_BASE_URL, undefined);
    const args = nativeArguments('qwen-code', { model: 'fixture', endpoint: 'http://127.0.0.1:9999', prompt: 'natural request' });
    assert.ok(!args.includes('--bare')); assert.ok(!args.includes('--safe-mode'));
    assert.equal(args[args.indexOf('--max-tool-calls') + 1], '12');
    assert.equal(args[args.indexOf('--advisor') + 1], 'off');
  } finally { rmSync(profile, { recursive: true, force: true }); }
});
test('Qwen settings version is prepared before snapshots without changing MCP registration', () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), 'ud-qwen-version-')), taskRoot = path.join(directory, 'task'), profile = path.join(directory, 'profile');
  const file = path.join(taskRoot, '.qwen/settings.json'), registered = { mcpServers: { ud: { command: '/private/ud-agent', args: ['mcp', '--allow-root', taskRoot] } }, custom: { retain: true } };
  mkdirSync(path.dirname(file), { recursive: true }); writeFileSync(file, JSON.stringify(registered));
  try {
    configureNativeProfile('qwen-code', { profile, model: 'fixture', endpoint: 'http://127.0.0.1:9999', env: {}, skillsEnabled: true });
    finalizeNativeProfile('qwen-code', { profile, taskRoot, skillsEnabled: true });
    assert.deepEqual(JSON.parse(readFileSync(file, 'utf8')), { ...registered, $version: 4 });
    assert.equal(JSON.parse(readFileSync(path.join(profile, '.qwen/settings.json'), 'utf8')).$version, 4);
    const before = readFileSync(file, 'utf8');
    finalizeNativeProfile('qwen-code', { profile, taskRoot, skillsEnabled: true });
    assert.equal(readFileSync(file, 'utf8'), before);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});
test('Codex requires the exact registered live MCP connection before its first provider request', () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), 'ud-codex-required-')), taskRoot = path.join(directory, 'task'), profile = path.join(directory, 'profile');
  const file = path.join(taskRoot, '.codex/config.toml');
  mkdirSync(path.dirname(file), { recursive: true });
  const registration = '[mcp_servers.ud]\ncommand = "/private/node"\nargs = ["/private/shim.mjs", "mcp", "--allow-root", "/private/task"]\n';
  writeFileSync(file, registration);
  try {
    configureNativeProfile('codex-cli', { profile, taskRoot, model: 'fixture', endpoint: 'http://127.0.0.1:9999', env: {}, skillsEnabled: true });
    finalizeNativeProfile('codex-cli', { profile, taskRoot, skillsEnabled: true });
    const config = parseToml(readFileSync(path.join(profile, '.codex/config.toml'), 'utf8'));
    assert.deepEqual({ ...config.mcp_servers.ud }, { ...parseToml(registration).mcp_servers.ud, required: true, startup_timeout_sec: 20, startup_readiness: 'connection' });
    assert.equal(config.projects[taskRoot].trust_level, 'trusted');
    assert.equal(config.web_search, 'disabled'); assert.equal(config.features.multi_agent, false);
    assert.equal(readFileSync(file, 'utf8'), registration, 'Private runtime policy must not modify packaged or project registration');
  } finally { rmSync(directory, { recursive: true, force: true }); }
});
test('Qwen qualification requires observed startup metadata stability', () => {
  const root = mkdtempSync(path.join(os.tmpdir(), 'ud-qwen-conformance-')), identity = 'inert-client';
  writeFileSync(path.join(root, 'package.json'), '{"name":"inert-native-proof"}\n');
  const directory = nativeConformanceDirectory(root, 'qwen-code', identity);
  mkdirSync(directory, { recursive: true });
  const evidence = path.join(directory, 'evidence.json'); writeFileSync(evidence, '{}');
  const receipt = { schema_version: 1, status: 'mechanically-admitted', harness_id: 'qwen-code', adapter_sha256: nativeAdapterIdentity(), client_identity: identity, product_source_sha256: sourceReceipt(root).sha256, inference: false,
    checks: Object.fromEntries(['provider_roundtrip', 'tool_roundtrip', 'skill_discovery', 'final_output', 'cancellation', 'oracle_isolation', 'budget_enforced', 'native_recovery_observed', 'fresh_conversation', 'owned_release'].map(name => [name, true])),
    evidence: [{ path: evidence, sha256: sha256(readFileSync(evidence)) }] };
  const releasePath = path.join(directory, 'release.json'), release = { kind: 'inert-native-owned-release', owned_cleanup_verified: true,
    product_source_sha256: receipt.product_source_sha256, adapter_sha256: receipt.adapter_sha256, client_identity: identity };
  writeFileSync(releasePath, JSON.stringify(release));
  receipt.release = { path: releasePath, sha256: sha256(readFileSync(releasePath)) }; receipt.evidence.push(receipt.release);
  const save = () => writeFileSync(path.join(directory, 'receipt.json'), JSON.stringify(receipt));
  try {
    save(); assert.equal(nativeConformance(root, 'qwen-code', identity), undefined);
    receipt.checks.startup_metadata_stable = false; save(); assert.equal(nativeConformance(root, 'qwen-code', identity), undefined);
    receipt.checks.startup_metadata_stable = true; save(); assert.deepEqual(nativeConformance(root, 'qwen-code', identity), receipt);
    receipt.status = 'blocked'; save(); assert.equal(nativeConformance(root, 'qwen-code', identity), undefined); receipt.status = 'mechanically-admitted';
    release.owned_cleanup_verified = false; writeFileSync(releasePath, JSON.stringify(release)); receipt.release.sha256 = sha256(readFileSync(releasePath)); save();
    assert.equal(nativeConformance(root, 'qwen-code', identity), undefined, 'Unknown release cannot qualify even with matching hashes.');
    release.owned_cleanup_verified = true; writeFileSync(releasePath, JSON.stringify(release)); receipt.release.sha256 = sha256(readFileSync(releasePath)); save();
    writeFileSync(path.join(root, 'package.json'), '{"name":"inert-native-proof","version":"0.0.1"}\n');
    assert.notEqual(nativeConformanceDirectory(root, 'qwen-code', identity), directory);
    assert.equal(nativeConformance(root, 'qwen-code', identity), undefined, 'A prior product cannot certify a repaired registration.');
    assert.equal(readFileSync(path.join(directory, 'receipt.json'), 'utf8'), JSON.stringify(receipt), 'Old conformance evidence remains unchanged.');
  } finally { rmSync(root, { recursive: true, force: true }); }
});
test('container commands bind exact native image and forbid engine authority mounts/env', () => {
  const input = { name: 'ud-agent-local-eval-12345678-1234-1234-1234-123456789012', owner: '12345678-1234-1234-1234-123456789012', image: 'sha256:' + 'a'.repeat(64), network: 'ud-agent-local-eval-12345678-1234-1234-1234-123456789012', taskRoot: '/private/task', profile: '/private/profile', command: '/opt/client/qwen' };
  const args = containerArguments(input);
  for (const required of ['linux/arm64', '--read-only', '--cap-drop', '--pids-limit', '--memory']) assert.ok(args.includes(required));
  assert.throws(() => containerArguments({ ...input, image: 'latest' }), /IDENTITY_INVALID/);
  assert.throws(() => containerArguments({ ...input, mounts: [{ source: '/var/run/docker.sock', target: '/engine.sock' }] }), /MOUNT_FORBIDDEN/);
  assert.throws(() => containerArguments({ ...input, env: { DOCKER_HOST: 'unix:///engine.sock' } }), /ENVIRONMENT_FORBIDDEN/);
  assert.deepEqual(selectedDockerEnvironment({ DOCKER_HOST: 'unix:///private/docker.sock' }), { DOCKER_HOST: 'unix:///private/docker.sock' });
  assert.throws(() => selectedDockerEnvironment({ DOCKER_HOST: 'tcp://unrelated:2375' }), /local Unix/);
  const bridge = { Driver: 'bridge', Labels: { 'io.github.mehmetoguzderin.ud-agent.local-eval': input.owner }, Options: { 'com.docker.network.bridge.enable_icc': 'false' }, IPAM: { Config: [{ Subnet: '172.26.0.0/16' }] }, Containers: {} };
  assert.equal(privateBridgeNetwork(bridge, input.owner), true);
  assert.equal(privateBridgeNetwork({ ...bridge, IPAM: { Config: [{ Subnet: '8.8.8.0/24' }] } }, input.owner), false);
});
test('Mini keeps its native system and exposes optional skill metadata with neutral task framing', () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), 'ud-mini-profile-')), clientDirectory = path.join(directory, 'client');
  const source = path.join(clientDirectory, 'venv/lib/python3.12/site-packages/minisweagent/config/mini.yaml');
  mkdirSync(path.dirname(source), { recursive: true }); writeFileSync(source, 'agent:\n  system_template: Native pinned system\n  instance_template: Native pinned task\nenvironment:\n  env:\n    PIP_PROGRESS_BAR: "off"\nmodel: {}\n');
  const taskRoot = path.join(directory, 'task'), profile = path.join(directory, 'enabled'), disabled = path.join(directory, 'disabled');
  mkdirSync(path.join(taskRoot, '.ud-agent'), { recursive: true }); writeFileSync(path.join(taskRoot, '.ud-agent/WORKFLOW.md'), 'UD guidance');
  writeFileSync(path.join(taskRoot, '.ud-agent/mini-swe-agent.json'), '{"coordinator":"fixture"}');
  try {
    const options = { clientDirectory, installation: process.cwd(), taskRoot, model: 'fixture', endpoint: 'http://127.0.0.1:9999', output: path.join(profile, 'trajectory.json'), env: {} };
    const enabled = configureNativeProfile('mini-swe-agent', { ...options, profile, skillsEnabled: true });
    const control = configureNativeProfile('mini-swe-agent', { ...options, profile: disabled, skillsEnabled: false });
    assert.match(readFileSync(enabled.config, 'utf8'), /Native pinned system/); assert.match(readFileSync(enabled.config, 'utf8'), /ud-validate/);
    const configured = parse(readFileSync(enabled.config, 'utf8'), { version: '1.1' });
    assert.equal(configured.environment.env.PIP_PROGRESS_BAR, 'off');
    // mini-swe 2.4.6 increments before testing its inclusive failure threshold.
    // Keep one correction possible without increasing the inference ceiling.
    assert.equal(configured.agent.max_consecutive_format_errors, 2);
    assert.equal(configured.agent.step_limit, 10);
    assert.equal(configured.model.model_kwargs.num_retries, 0);
    assert.match(configured.agent.instance_template, /^\{\{task\}\}/);
    assert.doesNotMatch(configured.agent.instance_template, /reproduce|repair|edit.*source|ud-compare|predictions_evaluate/);
    const historical = configureNativeProfile('mini-swe-agent', { ...options, profile: path.join(directory, 'historical'), skillsEnabled: false, studyVariant: 'current' });
    const historicalConfig = parse(readFileSync(historical.config, 'utf8'), { version: '1.1' });
    assert.equal(historicalConfig.agent.instance_template, 'Native pinned task');
    assert.doesNotMatch(readFileSync(control.config, 'utf8'), /ud-validate|Installed optional workflow skills/);
    finalizeNativeProfile('mini-swe-agent', { taskRoot, profile: disabled, skillsEnabled: false });
    assert.equal(existsSync(path.join(taskRoot, '.ud-agent/WORKFLOW.md')), false);
    assert.equal(existsSync(path.join(taskRoot, '.ud-agent/mini-swe-agent.json')), true);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});
test('coordinator transport permits only exact task grants and rejects input escapes', () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), 'ud-bridge-grant-')), task = path.join(directory, 'task'); mkdirSync(task);
  writeFileSync(path.join(directory, 'private.json'), '{}'); symlinkSync(path.join(directory, 'private.json'), path.join(task, 'escape.json'));
  try {
    assert.deepEqual(validateCoordinatorArguments(['mcp', '--allow-root', task], task), ['mcp', '--allow-root', task]);
    assert.throws(() => validateCoordinatorArguments(['uninstall', '--owned-runtime'], task), /COMMAND_FORBIDDEN/);
    assert.throws(() => validateCoordinatorArguments(['mcp', '--allow-root', directory], task), /GRANT_FORBIDDEN/);
    assert.throws(() => validateCoordinatorArguments(['call', 'fixture', '--input', 'escape.json'], task), /INPUT_FORBIDDEN/);
    const resource = ['read-resource', 'ud://reports/published-id?cursor=opaque', '--allow-root', task, '--json'];
    assert.deepEqual(validateCoordinatorArguments(resource, task), resource);
    for (const args of [
      ['read-resource', '/private/other'], ['read-resource', 'file:///private/other'],
      ['read-resource', 'ud://reports/id', '--input', 'private.json'],
      ['read-resource', 'ud://reports/id', '--working-tree', task],
      ['read-resource', 'ud://reports/id', '--json', '--json'],
      ['read-resource', 'ud://reports/id', 'ud://reports/another'],
    ]) assert.throws(() => validateCoordinatorArguments(args, task), /RESOURCE_ARGUMENTS_INVALID/);
    assert.throws(() => validateCoordinatorArguments(['read-resource', 'ud://reports/id', '--allow-root', directory], task), /GRANT_FORBIDDEN/);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});
test('bridge authenticates health and enforces native containment before forwarding raw coordinator stdout', async () => {
  const directory = realpathSync(mkdtempSync(path.join(os.tmpdir(), 'ud-stdio-'))), coordinator = path.join(directory, 'coordinator.mjs');
  writeFileSync(coordinator, 'process.stdout.write(JSON.stringify({argv:process.argv.slice(2),root:process.env.UD_AGENT_ALLOWED_ROOTS}));');
  let launches = 0;
  const bridge = await createCoordinatorBridge({ coordinator, taskRoot: directory, environment: { PATH: process.env.PATH },
    ...(process.platform === 'darwin' ? {} : { start: () => { launches++; throw new Error('Unsupported host must reject before spawning'); } }) });
  try {
    assert.equal((await fetch(bridge.url + '/health')).status, 404);
    assert.equal((await fetch(bridge.url + '/health', { headers: { authorization: 'Bearer ' + bridge.token } })).status, 200);
    if (process.platform !== 'darwin') {
      const status = await new Promise((resolve, reject) => {
        const request = http.request(new URL('/stdio', bridge.url), { headers: {
          authorization: 'Bearer ' + bridge.token, connection: 'Upgrade', upgrade: 'ud-coordinator-stdio',
          'x-ud-argv': Buffer.from(JSON.stringify(['help'])).toString('base64url'),
        } });
        request.setTimeout(5000, () => request.destroy(new Error('Bridge platform rejection timed out')));
        request.on('error', reject);
        request.on('response', response => { response.resume(); response.once('end', () => resolve(response.statusCode)); });
        request.on('upgrade', (_response, socket) => { socket.destroy(); reject(new Error('Unsupported host accepted coordinator transport')); });
        request.end();
      });
      assert.equal(status, 501); assert.equal(launches, 0);
      assert.deepEqual((await bridge.stop()).completed_children, []);
      return;
    }
    const result = await runOwned(process.execPath, [path.resolve('evals/local/coordinator-stdio.mjs'), 'help'], {
      env: { PATH: process.env.PATH, UD_EVAL_COORDINATOR_BRIDGE: JSON.stringify({ url: bridge.url, token: bridge.token }) }, timeout: 5000 });
    assert.deepEqual(JSON.parse(result.stdout), { argv: ['help'], root: JSON.stringify([directory]) });
    assert.equal(result.cleanupVerified, true);
  } finally { assert.equal((await bridge.stop()).cleanupVerified, true); rmSync(directory, { recursive: true, force: true }); }
});
test('temporary CLI request carriers do not grant their profile or foreign files as operation roots', async () => {
  const directory = realpathSync(mkdtempSync(path.join(os.tmpdir(), 'ud-bridge-input-')));
  const task = path.join(directory, 'task'), profile = path.join(directory, 'profile'), temporaryInputRoot = path.join(profile, 'tmp');
  mkdirSync(task); mkdirSync(temporaryInputRoot, { recursive: true });
  const request = path.join(temporaryInputRoot, 'request.json'), privateFile = path.join(profile, 'private.json');
  writeFileSync(request, '{}'); writeFileSync(privateFile, '{}'); symlinkSync(privateFile, path.join(temporaryInputRoot, 'escape.json'));
  try {
    const args = ['call', 'fixture', '--input', request, '--allow-root', task];
    assert.deepEqual(validateCoordinatorArguments(args, task, { temporaryInputRoot }), args);
    for (const file of [request, privateFile, path.join(temporaryInputRoot, 'escape.json')]) {
      assert.throws(() => validateCoordinatorArguments(['call', 'fixture', '--input', file], task), /INPUT_FORBIDDEN/);
    }
    for (const file of [privateFile, path.join(temporaryInputRoot, 'escape.json')]) assert.throws(() => validateCoordinatorArguments(['call', 'fixture', '--input', file], task, { temporaryInputRoot }), /INPUT_FORBIDDEN/);
    assert.throws(() => validateCoordinatorArguments(['call', 'fixture', '--input', request, '--allow-root', temporaryInputRoot], task, { temporaryInputRoot }), /GRANT_FORBIDDEN/);
    await assert.rejects(createCoordinatorBridge({ coordinator: request, taskRoot: task, environment: { HOME: profile }, temporaryInputRoot: task }), /TEMPORARY_INPUT_INVALID/);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});
test('mini trajectory terminal evidence is real and missing conformance never admits', () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), 'ud-trajectory-')), output = path.join(directory, 'trajectory.json');
  try {
    assert.equal(nativeConformance(directory, 'qwen-code', 'unknown'), undefined);
    writeFileSync(output, JSON.stringify({ trajectory_format: 'mini-swe-agent-1.1', info: { exit_status: 'LimitsExceeded', submission: '' }, messages: [] }));
    assert.equal(nativeTranscript('mini-swe-agent', {}, output).events[0].type, 'turn.failed');
    writeFileSync(output, JSON.stringify({ trajectory_format: 'mini-swe-agent-1.1', info: { exit_status: 'Submitted', submission: 'actual answer' }, messages: [] }));
    assert.equal(nativeTranscript('mini-swe-agent', {}, output).finalAnswer, 'actual answer');
    assert.throws(() => oracleIsolationPolicy('/repo', ['/unrelated']), /isolation roots/);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});
