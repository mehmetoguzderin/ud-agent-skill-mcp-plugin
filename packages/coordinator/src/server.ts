import { McpServer, ResourceTemplate, fromJsonSchema, inputRequired, inputResponse } from '@modelcontextprotocol/server';
import type { ServerContext } from '@modelcontextprotocol/server';
import { parseGrantedRoots } from '../../workspace/src/authorization.js';
import { loadContracts, loadInputSchema, loadOutputSchema, projectRoot } from './catalog.js';
import { executeOperation } from './operations.js';
import { toolDescription } from './tool-descriptions.js';
import { ResourceStore } from './resources.js';
import { resolveProductGuard } from './docker-authority.js';
import { userspaceStateRoot } from '../../runtime-manager/src/userspace.js';
import { loadNativeGuardReceipt } from '../../runtime-manager/src/receipt.js';
import { Continuations } from './continuations.js';
import type { ContinuationProgress } from './continuations.js';
import { hostRoots, RootChallenges } from './host-grants.js';

const VERSION = '0.1.0-beta.1';
/** Sent in the MCP initialize result; hosts place it in the system prompt. Chosen by
 * loop-interpret margin (evals/local/README.md): it lowers skill-name calls. */
export const SERVER_INSTRUCTIONS = 'Never call ud-validate, ud-edit or other skill names as tools. For .txt or prose wording requests, read the file and answer without UD tools. For .conllu checks, load the matching ud-* skill first, then run its tool; reading the files is not a check.';
type TaskSignals = { signalForRequest(id: string | number): AbortSignal | undefined };

export function createServer(root = projectRoot(), tasks?: TaskSignals, launchGrants: readonly string[] = []): McpServer {
  const { domain, environment } = loadContracts(root);
  const allowedRoots = [...new Set([...parseGrantedRoots(process.env.UD_AGENT_ALLOWED_ROOTS), ...launchGrants])];
  const configuredRoots = [...allowedRoots];
  const runtimeOptions = { sourceRoot: root, allowedRoots, autoSetup: true };
  const server = new McpServer({ name: 'ud-agent-skill-mcp-plugin', version: VERSION }, { instructions: SERVER_INSTRUCTIONS });
  const lifetime = new AbortController();
  let rootScope = new AbortController();
  let continuations = new Continuations(JSON.stringify({ root, allowedRoots, version: VERSION }));
  const previousClose = server.server.onclose;
  server.server.onclose = () => { lifetime.abort(); rootScope.abort(); continuations.close(); previousClose?.(); };
  let resources: Promise<ResourceStore> | undefined;
  let challenges = new RootChallenges();
  let legacyRoots: Promise<void> | undefined;
  server.server.setNotificationHandler('notifications/roots/list_changed', () => {
    if (configuredRoots.length !== 0) return;
    rootScope.abort(); rootScope = new AbortController();
    allowedRoots.splice(0); resources = undefined; legacyRoots = undefined; challenges = new RootChallenges(); continuations.close();
    continuations = new Continuations(JSON.stringify({ root, allowedRoots, version: VERSION }));
  });
  const getResources = async (writes = false) => {
    const guard = writes ? (await resolveProductGuard(root, { platform: process.platform, arch: process.arch })).guard : process.platform === 'win32' ? (await loadNativeGuardReceipt(root, { platform: process.platform, arch: process.arch })).guard : undefined;
    const store = await (resources ??= ResourceStore.open(`${userspaceStateRoot()}-resources`, [...allowedRoots], guard));
    return writes && guard ? store.withGuard(guard) : store;
  };
  function updateHostRoots(roots: string[]): void {
    if (JSON.stringify([...allowedRoots].sort()) === JSON.stringify([...roots].sort())) return;
    rootScope.abort(); rootScope = new AbortController(); allowedRoots.splice(0, allowedRoots.length, ...roots);
    resources = undefined; continuations.close(); continuations = new Continuations(JSON.stringify({ root, allowedRoots, version: VERSION }));
  }
  async function ensureHostRoots(operation: string, args: Record<string, unknown>, context: ServerContext) {
    if (configuredRoots.length !== 0) return;
    const envelope = context.mcpReq.envelope as Record<string, unknown> | undefined;
    const capabilities = (envelope?.['io.modelcontextprotocol/clientCapabilities'] ?? server.server.getClientCapabilities()) as { roots?: unknown } | undefined;
    const version = envelope?.['io.modelcontextprotocol/protocolVersion'] ?? server.server.getNegotiatedProtocolVersion();
    // Modern MCP has no roots/list_changed notification. Obtain the host's
    // current snapshot on each authorized operation rather than cache a grant.
    if (version === '2026-07-28' && capabilities?.roots) {
      const state = context.mcpReq.requestState();
      if (state === undefined) {
        const id = challenges.issue(operation, args);
        return inputRequired({ inputRequests: { [id]: inputRequired.listRoots() }, requestState: id });
      }
      const selected = typeof state === 'string' ? inputResponse(context.mcpReq.inputResponses, state) : { kind: 'missing' as const };
      if (selected.kind !== 'roots') throw new Error('HOST_ROOT_CHALLENGE_INVALID');
      updateHostRoots(await challenges.accept(state, operation, args, selected.roots)); return;
    }
    if (allowedRoots.length === 0 && capabilities?.roots) {
      legacyRoots ??= (async () => { const listed = await server.server.listRoots({}, { timeout: 10000 }); updateHostRoots(await hostRoots(listed.roots)); })();
      await legacyRoots;
    }
  }
  for (const contract of [...domain, ...environment]) {
    const schema = loadInputSchema(root, contract.name);
    const hostTool = contract.id.startsWith('ENV-');
    server.registerTool(contract.name, {
      description: toolDescription(contract.name),
      inputSchema: fromJsonSchema<Record<string, unknown>>(schema),
      outputSchema: fromJsonSchema<Record<string, unknown>>(loadOutputSchema(root, contract.name)),
      ...(hostTool ? { annotations: { readOnlyHint: contract.name === 'check_ud_environment', idempotentHint: true, destructiveHint: false, openWorldHint: contract.name === 'setup_ud_environment' } } : {}),
      ...(!hostTool ? { annotations: { readOnlyHint: !contract.access?.writes_workspace && !contract.access?.writes_outputs, idempotentHint: !contract.access?.writes_workspace, destructiveHint: contract.access?.writes_workspace === true, openWorldHint: false } } : {}),
    }, async (args, context) => {
      if (typeof args.working_tree_path === 'string') { const required = await ensureHostRoots(contract.name, args, context); if (required) return required; }
      const progressToken = context.mcpReq._meta?.progressToken;
      const progress: ContinuationProgress | undefined = typeof progressToken === 'string' || typeof progressToken === 'number'
        ? (progress, total, message) => context.mcpReq.notify({ method: 'notifications/progress', params: { progressToken, progress, total, message } }) : undefined;
      const taskSignal = tasks?.signalForRequest(context.mcpReq.id);
      const selectedScope = rootScope.signal;
      const execute = async (signal: AbortSignal, progress: ContinuationProgress | undefined) => executeOperation(contract, args, domain, { ...runtimeOptions, allowedRoots: [...allowedRoots] }, AbortSignal.any([signal, selectedScope]), {
        ...(!hostTool ? { resources: await getResources(true) } : {}),
        ...(progress ? { progress } : {}),
      });
      const control = context.mcpReq._meta?.['io.github.mehmetoguzderin/ud-agent/continuation'];
      if (control !== undefined) {
        if (!control || typeof control !== 'object' || Array.isArray(control) || Object.keys(control).some(key => !['token', 'budget_ms', 'cancel'].includes(key))) throw new Error('CONTINUATION_CONTROL_INVALID');
        return continuations.run(contract, args, control as { token?: string; budget_ms?: number; cancel?: boolean }, (signal, progress) => execute(AbortSignal.any([signal, lifetime.signal, ...(taskSignal ? [taskSignal] : [])]), progress), context.mcpReq.signal, progress);
      }
      return execute(AbortSignal.any([context.mcpReq.signal, lifetime.signal, ...(taskSignal ? [taskSignal] : [])]), progress);
    });
  }
  server.registerResource('catalog', 'ud://catalog/v1', {
    title: 'Universal Dependencies operation catalog',
    description: 'The installed domain and environment operation inventory.', mimeType: 'application/json',
  }, async uri => ({ contents: [{ uri: uri.href, mimeType: 'application/json', text: JSON.stringify([...domain, ...environment]) }] }));
  const readAuthorizedResource = async (uri: URL, context: ServerContext) => {
    const required = await ensureHostRoots('resources/read', { uri: uri.href }, context); if (required) return required;
    const scope = rootScope.signal; const result = continuations.read(uri) ?? await (await getResources()).read(uri);
    if (scope.aborted) throw new Error('HOST_GRANT_REVOKED'); return result;
  };
  for (const kind of ['reports', 'plans', 'contexts', 'operations', 'artifacts']) {
    // The pinned SDK's query-template matcher requires a query even for the
    // optional RFC6570 form. Retain that advertised pagination route and add
    // an explicit initial-page route rather than returning unreadable URIs.
    for (const [name, template] of [[kind, `ud://${kind}/{id}{?cursor}`], [`${kind}-base`, `ud://${kind}/{id}`]]) {
      server.registerResource(name!, new ResourceTemplate(template!, { list: undefined }), { title: `Authorized ${kind}`, description: 'Authorized product resource; immutable report cursors and workspace grants are verified.' }, (uri, _variables, context) => readAuthorizedResource(uri, context));
    }
  }
  return server;
}
