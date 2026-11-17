/** MIT. Native applications own the agent loop; adapters only configure/observe. */
import { mkdirSync, readFileSync, writeFileSync, existsSync, realpathSync, copyFileSync } from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { pathToFileURL } from 'node:url';
import { randomUUID } from 'node:crypto';
import { HARNESSES } from './registry.mjs';
import { executable, privateEnvironment } from './preparation.mjs';
import { startOwned } from './process.mjs';
import { sha256, sourceReceipt } from '../../scripts/release/candidate.mjs';
import { readPreparedClient, assertNativeClientDependencyRecipe } from './native-clients.mjs';
import { NATIVE_RECIPES, nativeArguments, configureNativeProfile, finalizeNativeProfile, nativeClientPin } from './native-recipes.mjs';
import { inspectDesktop, startDesktop } from './desktop.mjs';
import { createCoordinatorBridge } from './coordinator-bridge.mjs';
import { startContainer, selectedDockerEnvironment } from './container.mjs';
import { nativeLogResults, nativeTrajectoryResults, nativeKimiProfileResults } from './native-observations.mjs';
import { inspectLocalEvaluationImageAvailability } from '../../scripts/quality/original-storage.mjs';
import { cleanupObservation, failureObservation } from './lifecycle.mjs';
import { nativeHermesProfileResults, nativeHermesProfileFinalOutput } from './hermes-observations.mjs';
import { nativeOpenClawProfileResults } from './openclaw-observations.mjs';

export { nativeArguments } from './native-recipes.mjs';
export function nativeAdapterIdentity() {
  return sha256(JSON.stringify(['native.mjs', 'native-recipes.mjs', 'native-conformance.mjs', 'native-observations.mjs', 'hermes-observer.py', 'hermes-observations.mjs', 'openclaw-observations.mjs', 'container.mjs', 'coordinator-bridge.mjs', 'coordinator-stdio.mjs', 'pi-mcp-extension.mjs', 'desktop.mjs', 'vscode-driver.cjs', 'gateway.mjs', 'responses-namespace.mjs', 'budget.mjs', 'process.mjs', 'lifecycle.mjs', 'native-clients.mjs', 'native-clients.lock.json', 'native-client-dependencies.lock.json', '../../scripts/quality/original-storage.mjs', '../../scripts/quality/docker-owned-storage.mjs', '../../scripts/quality/verify-client-image-archive.py'].map(name => [name, sha256(readFileSync(new URL(name, import.meta.url)))])));
}
export function nativeConformance(root, id, identity) {
  if (!existsSync(path.join(root, '.artifacts/local-evals/native-conformance', id))) return undefined;
  const directory = nativeConformanceDirectory(root, id, identity), file = path.join(directory, 'receipt.json');
  if (!existsSync(file)) return undefined;
  const receipt = JSON.parse(readFileSync(file));
  if (receipt.schema_version !== 1 || receipt.status !== 'mechanically-admitted' || receipt.harness_id !== id || receipt.adapter_sha256 !== nativeAdapterIdentity() || receipt.client_identity !== identity || receipt.product_source_sha256 !== sourceReceipt(root).sha256 || receipt.inference !== false) return undefined;
  if (!['provider_roundtrip', 'tool_roundtrip', 'skill_discovery', 'final_output', 'cancellation', 'oracle_isolation', 'budget_enforced', 'native_recovery_observed', 'fresh_conversation', 'owned_release', ...(id === 'codex-cli' ? ['image_delivery'] : []), ...(id === 'qwen-code' ? ['startup_metadata_stable'] : []), ...(id === 'mini-swe-agent' ? ['native_format_recovery'] : [])].every(name => receipt.checks?.[name] === true)) return undefined;
  if (!Array.isArray(receipt.evidence) || !receipt.evidence.length || receipt.evidence.some(item => typeof item.path !== 'string' || !path.isAbsolute(item.path) || !item.path.startsWith(directory + path.sep) || !existsSync(item.path) || sha256(readFileSync(item.path)) !== item.sha256)) return undefined;
  if (receipt.release?.path !== path.join(directory, 'release.json') || !receipt.evidence.some(item => item.path === receipt.release.path && item.sha256 === receipt.release.sha256)) return undefined;
  const release = JSON.parse(readFileSync(receipt.release.path));
  if (release.owned_cleanup_verified !== true || release.product_source_sha256 !== receipt.product_source_sha256 || release.adapter_sha256 !== receipt.adapter_sha256 || release.client_identity !== identity) return undefined;
  return receipt;
}
export const nativeConformanceDirectory = (root, id, identity) => path.join(root, '.artifacts/local-evals/native-conformance', id, nativeAdapterIdentity(), sha256(JSON.stringify([String(identity), sourceReceipt(root).sha256])));
export async function inspectHarnesses(root, { includeDesktops = true } = {}) {
  const results = [];
  for (const harness of HARNESSES) {
    const recipe = NATIVE_RECIPES[harness.id];
    if (!recipe) {
      if (!includeDesktops) { results.push({ ...harness, status: 'interface unsupported', reason: 'Desktop surface is outside the selected headless profile; no application execution evidence was collected.' }); continue; }
      const desktop = await inspectDesktop(harness.id), proof = desktop.client_identity && nativeConformance(root, harness.id, desktop.client_identity);
      results.push({ ...harness, ...desktop, ...(desktop.driver_available && proof ? { status: 'mechanically-admitted', conformance: proof } : {}) }); continue;
    }
    const pin = nativeClientPin(harness.id);
    try {
      const prepared = readPreparedClient(root, harness.id);
      const binary = prepared?.executable ?? executable(pin.command);
      const imageFile = path.join(root, '.artifacts/local-evals/client-images', harness.id, 'receipt.json');
      const image = existsSync(imageFile) ? JSON.parse(readFileSync(imageFile)) : undefined;
      if (image) assertNativeClientDependencyRecipe(harness.id, image);
      const availability = image ? inspectLocalEvaluationImageAvailability(root, harness.id) : undefined;
      if (!binary && !image) { results.push({ ...harness, status: 'interface unsupported', reason: `Native ${pin.command} is absent. A pinned private acquisition recipe is available.`, acquisition: pin }); continue; }
      const executableIdentity = binary ? sha256(readFileSync(realpathSync(binary))) : undefined;
      const identity = image?.image_id ?? executableIdentity;
      const proof = nativeConformance(root, harness.id, identity);
      const record = { ...harness, ...(prepared ? { prepared_client: prepared } : {}), ...(binary ? { executable: binary, executable_sha256: executableIdentity } : {}),
        ...(image ? { container: image } : {}), execution_location: image ? 'arm64-container' : 'native-macos', skill_mechanism: recipe.skillMechanism, acquisition: pin };
      if (availability?.status === 'archived-unavailable') results.push({ ...record, status: 'interface unsupported', image_availability: 'archived-unavailable', reason: 'Pinned client image is preserved in a verified private archive and must be restored before this native route can execute.' });
      else if (proof && recipe.canRun && image) results.push({ ...record, status: 'mechanically-admitted', conformance: proof });
      else results.push({ ...record, ...(proof ? { preliminary_native_conformance: proof } : {}), status: 'interface unsupported', reason: !image ? 'Private native client prepared; the required ARM64 container route has no verified image and native-loop conformance yet.' : recipe.reason ?? 'Client installed; native provider/tool/skill/cancellation conformance is not yet verified for these exact bytes.' });
    } catch (error) { results.push({ ...harness, status: 'interface unsupported', reason: error.message }); }
  }
  return results;
}
export function oracleIsolationPolicy(root, allowed, { writable = [] } = {}) {
  if (!path.isAbsolute(root) || allowed.some(directory => !path.isAbsolute(directory) || !directory.startsWith(root + path.sep)) || writable.some(directory => !allowed.includes(directory))) throw new Error('Invalid oracle isolation roots.');
  return `(version 1) (allow default) (deny file-read-data (require-all (subpath ${JSON.stringify(root)}) ${allowed.map(directory => `(require-not (subpath ${JSON.stringify(directory)}))`).join(' ')}))`
    + (writable.length ? ` (deny file-write* (require-all (subpath ${JSON.stringify(root)}) ${writable.map(directory => `(require-not (subpath ${JSON.stringify(directory)}))`).join(' ')}))` : '');
}
const containerUrl = value => { const url = new URL(value); if (url.hostname !== '127.0.0.1') throw new Error('LOCAL_PROVIDER_ENDPOINT_REQUIRED'); url.hostname = 'host.docker.internal'; return url.toString().replace(/\/$/, ''); };
export function nativeTranscript(id, result, output) {
  if (id === 'mini-swe-agent') {
    if (!existsSync(output)) return { events: [], finalAnswer: '' };
    const trajectory = JSON.parse(readFileSync(output));
    if (trajectory.trajectory_format !== 'mini-swe-agent-1.1' || !Array.isArray(trajectory.messages)) throw new Error('MINISWE_TRAJECTORY_UNVERIFIED');
    const completed = trajectory.info?.exit_status === 'Submitted';
    return { events: [{ type: completed ? 'turn.completed' : 'turn.failed', source: 'native-trajectory', exit_status: trajectory.info?.exit_status }],
      finalAnswer: completed ? trajectory.info.submission || trajectory.messages.filter(message => message.role === 'assistant').at(-1)?.content || '' : '', trajectory };
  }
  const events = result.stdout.split('\n').filter(Boolean).flatMap(line => { try { return [JSON.parse(line)]; } catch { return []; } });
  let finalAnswer = existsSync(output) ? readFileSync(output, 'utf8') : '';
  if (!finalAnswer) finalAnswer = events.filter(event => event.type === 'result').map(event => event.result ?? '').join('\n');
  if (id === 'hermes-agent') {
    const final = nativeHermesProfileFinalOutput(path.dirname(output));
    finalAnswer = final?.finalAnswer ?? '';
    if (final) events.push(final.event);
  }
  if (id === 'gemini-cli') finalAnswer = events.filter(event => event.type === 'message' && event.role === 'assistant').map(event => event.content ?? '').join('');
  if (id === 'kimi-code') finalAnswer = events.filter(event => event.role === 'assistant').map(event => event.content ?? '').join('');
  if (id === 'deepseek-harness') finalAnswer = events.findLast(event => event.type === 'final')?.text ?? '';
  if (id === 'pi') finalAnswer = events.findLast(event => event.type === 'message_end' && event.message?.role === 'assistant')?.message.content.filter(item => item.type === 'text').map(item => item.text).join('') ?? '';
  if (id === 'openclaw') {
    try {
      const document = JSON.parse(result.stdout);
      // Pinned --local --json completeDelivery writes normalized assistant reply
      // payloads at the top level; raw tool results are not a final-answer source.
      finalAnswer = document.meta?.terminalReply?.text ?? document.meta?.finalAssistantVisibleText ??
        (Array.isArray(document.payloads) ? document.payloads.filter(payload => payload?.isError !== true && typeof payload?.text === 'string').map(payload => payload.text).join('\n') : '');
      events.push({ type: 'native.openclaw.result', value: document });
    } catch { /* Incomplete JSON remains incomplete evidence. */ }
  }
  // This is an adapter observation derived from an actual owned process and
  // parsed native output. It is not a fabricated native application event.
  if (result.code === 0 && result.cleanupVerified === true && finalAnswer.trim()) events.push({ type: 'native.adapter.completed', source: 'owned-process-and-native-final-output', harness_id: id });
  return { events, finalAnswer };
}
/** Fresh private registration and a native session. Only mechanical conformance
 * may set allowUnverified; campaign inspection never admits an absent proof. */
export async function startNative({ root, harness, model, endpoint, taskRoot, profile, prompt, image, skillsEnabled, budgetEnvironment, hostBudgetEnvironment = budgetEnvironment,
  signal, installation, beforeStart, beforeLaunch, allowUnverified = false, record = () => {}, modelContextCapacity, studyVariant }) {
  const recipe = NATIVE_RECIPES[harness.id];
  if (!recipe) return startDesktop({ root, harness, model, endpoint, taskRoot, profile, prompt, image, skillsEnabled, budgetEnvironment, hostBudgetEnvironment, signal, installation, beforeStart, beforeLaunch, allowUnverified, record });
  let bridge, owned, launchAttempted = false;
  try {
    if (!recipe?.canRun || !allowUnverified && harness.status !== 'mechanically-admitted') throw new Error('NATIVE_ROUTE_NOT_ADMITTED');
    if (!allowUnverified && !harness.container) throw new Error('HEADLESS_ARM64_CONTAINER_REQUIRED');
    if (recipe.requiresContainer && !harness.container) throw new Error('NATIVE_CONTAINER_REQUIRED_FOR_DESCENDANT_CONTAINMENT');
    mkdirSync(profile, { recursive: true, mode: 0o700 });
    mkdirSync(path.join(profile, 'tmp'), { mode: 0o700 });
    const privateEnv = { ...privateEnvironment(root, profile), TMPDIR: path.join(profile, 'tmp'), TMP: path.join(profile, 'tmp'), TEMP: path.join(profile, 'tmp') }, coordinator = path.join(installation, 'dist/packages/coordinator/src/entry.js');
    const hostEnv = { ...privateEnv, ...hostBudgetEnvironment, ...selectedDockerEnvironment() };
    const inContainer = Boolean(harness.container);
    if (inContainer) assertNativeClientDependencyRecipe(harness.id, harness.container);
    const output = path.join(profile, recipe.events === 'trajectory' ? 'trajectory.json' : 'final-answer.txt');
    const selectedEndpoint = inContainer ? containerUrl(endpoint) : endpoint;
    const configured = configureNativeProfile(harness.id, { profile, taskRoot, installation, model, endpoint: selectedEndpoint,
      env: privateEnv, skillsEnabled, clientDirectory: harness.prepared_client?.directory, output, modelContextCapacity, studyVariant });
    const env = configured.env;
    let entry = { command: process.execPath, args: [coordinator, 'mcp', '--allow-root', taskRoot] };
    const bin = path.join(profile, 'bin'); mkdirSync(bin, { mode: 0o700 });
    bridge = await createCoordinatorBridge({ coordinator, taskRoot, environment: hostEnv, temporaryInputRoot: path.join(profile, 'tmp'), signal, record });
    const capability = { url: inContainer ? containerUrl(bridge.url) : bridge.url, token: bridge.token };
    env.UD_EVAL_COORDINATOR_BRIDGE = JSON.stringify(capability);
    const shim = path.join(bin, 'coordinator-stdio.mjs'); copyFileSync(new URL('./coordinator-stdio.mjs', import.meta.url), shim);
    writeFileSync(path.join(bin, 'coordinator-capability.json'), JSON.stringify(capability), { flag: 'wx', mode: 0o600 });
    entry = { command: inContainer ? '/usr/local/bin/node' : process.execPath, args: [shim, 'mcp', '--allow-root', taskRoot] };
    writeFileSync(path.join(bin, 'ud-agent'), '#!/usr/bin/env node\nimport ' + JSON.stringify(pathToFileURL(shim).href) + ';\n', { mode: 0o700 });
    env.PATH = inContainer ? `${bin}:/opt/client/venv/bin:/opt/client/node_modules/.bin:/usr/local/bin:/usr/bin:/bin` : `${bin}:${env.PATH}`;
    const { connectHost } = await import(pathToFileURL(path.join(installation, 'dist/packages/coordinator/src/connect.js')).href);
    await connectHost(recipe.connect, { sourceRoot: installation, workingTree: taskRoot, home: profile, stateRoot: path.join(profile, 'connections'), noSkills: !skillsEnabled, launch: entry });
    finalizeNativeProfile(harness.id, { profile, taskRoot, skillsEnabled });
    // The verified outer OCI container already supplies task/profile mounts,
    // dropped capabilities and no engine socket. Nested bwrap cannot create its
    // namespaces there. Native macOS retains the normal workspace sandbox.
    const session = randomUUID(), args = nativeArguments(harness.id, { model, endpoint: selectedEndpoint, taskRoot, output, prompt, image, config: configured.config, session, isolatedContainer: inContainer });
    await beforeStart?.();
    if (inContainer) {
      launchAttempted = true;
      owned = await startContainer({ root, image: harness.container.image_id, taskRoot, profile, command: harness.container.command, args, env,
        signal, beforeLaunch, log: path.join(profile, 'native.jsonl'), probeUrls: [{ url: selectedEndpoint + '/v1/models' }, { url: containerUrl(bridge.url) + '/health', headers: { authorization: `Bearer ${bridge.token}` } }] });
    } else {
      if (process.platform !== 'darwin') throw new Error('NATIVE_ORACLE_CONTAINMENT_UNAVAILABLE');
      const allowed = [installation, taskRoot, profile, ...(harness.prepared_client ? [harness.prepared_client.directory] : [])];
      const policy = oracleIsolationPolicy(root, allowed, { writable: [taskRoot, profile] })
        + ` (deny file-read-data (require-all (subpath ${JSON.stringify(os.homedir())}) ${allowed.map(directory => `(require-not (subpath ${JSON.stringify(directory)}))`).join(' ')}))`
        + ` (deny file-write* (require-all ${[taskRoot, profile].map(directory => `(require-not (subpath ${JSON.stringify(directory)}))`).join(' ')} (require-not (literal "/dev/null"))))`
        + ` (deny network-outbound) (allow network-outbound (remote ip "localhost:*")) (allow network-outbound (remote unix-socket (subpath ${JSON.stringify(profile)})))`;
      await beforeLaunch?.();
      launchAttempted = true;
      owned = startOwned('/usr/bin/sandbox-exec', ['-p', policy, harness.executable, ...args], { cwd: taskRoot, env, signal, timeout: 90_000, log: path.join(profile, 'native.jsonl') });
      owned.child.stdin.end();
    }
    const stop = async reason => {
      const [nativeResult, bridgeResult] = await Promise.all([owned.stop(reason), bridge?.stop()]);
      return { ...nativeResult, bridge_cleanup: bridgeResult, cleanupVerified: nativeResult.cleanupVerified === true && (!bridge || bridgeResult.cleanupVerified === true) };
    };
    const done = owned.done.then(async result => { const cleanup = await bridge?.stop(); return { ...result, bridge_cleanup: cleanup, cleanupVerified: result.cleanupVerified === true && (!bridge || cleanup.cleanupVerified === true) }; });
    return { ...owned, stop, done, observedResults: () => {
      const log = path.join(profile, 'native.jsonl'), observed = existsSync(log) ? nativeLogResults(readFileSync(log, 'utf8')) : [];
      if (harness.id === 'mini-swe-agent' && existsSync(output)) { try { observed.push(...nativeTrajectoryResults(JSON.parse(readFileSync(output)))); } catch { /* An incomplete trajectory cannot establish a result. */ } }
      if (harness.id === 'kimi-code') observed.push(...nativeKimiProfileResults(profile));
      if (harness.id === 'openclaw') observed.push(...nativeOpenClawProfileResults(profile, session));
      if (harness.id === 'hermes-agent') observed.push(...nativeHermesProfileResults(profile));
      return observed;
    }, finalAnswer: result => nativeTranscript(harness.id, result, output).finalAnswer, events: result => nativeTranscript(harness.id, result, output).events,
      identity: { ...owned.identity, harness_id: harness.id, execution_location: inContainer ? 'arm64-container' : 'native-macos', runtime_location: 'native-macos', skill_mechanism: recipe.skillMechanism } };
  } catch (error) {
    const stopped = await Promise.allSettled([
      owned ? owned.stop('native-start-failed') : Promise.resolve(error.container_cleanup ?? { cleanupVerified: !launchAttempted, no_launch_attempted: !launchAttempted }),
      bridge ? bridge.stop() : Promise.resolve({ cleanupVerified: true, not_created: true }),
    ]);
    error.native_cleanup = { cleanupVerified: stopped.every(item => item.status === 'fulfilled' && item.value?.cleanupVerified === true),
      steps: stopped.map((item, index) => ({ step: index === 0 ? 'native-start-release' : 'bridge-start-release', ...(item.status === 'fulfilled'
        ? { outcome: 'completed', ...cleanupObservation(item.value), ...(item.value?.no_launch_attempted === true ? { no_launch_attempted: true } : {}), ...(item.value?.not_created === true ? { not_created: true } : {}) }
        : { outcome: 'failed', failure: failureObservation(item.reason) }) })) };
    throw error;
  }
}
