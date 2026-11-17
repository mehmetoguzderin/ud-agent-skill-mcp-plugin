import { open } from 'node:fs/promises';
import { discoverOperations, describeOperation, formatOperationDescription } from './discovery.js';
import { readAuthorizedResource } from './resource-reader.js';
import path from 'node:path';
import { fromJsonSchema } from '@modelcontextprotocol/server';
import { serveStdio } from '@modelcontextprotocol/server/stdio';
import { parseGrantedRoots } from '../../workspace/src/authorization.js';
import { loadContracts, loadInputSchema, projectRoot } from './catalog.js';
import { executeOperation } from './operations.js';
import { createServer } from './server.js';
import { cleanUserspaceState } from '../../runtime-manager/src/userspace.js';
import { loadNativeGuardReceipt } from '../../runtime-manager/src/receipt.js';
import { TaskTransport } from './task-transport.js';
import { discoverWorkspace } from '../../workspace/src/discovery.js';
import { connectHost, projectSkillDirectories } from './connect.js';
import { commandGuidance, skillCommandAlias } from './skill-routes.js';
import { existsSync, readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { maintainProviderRuntime } from './provider-maintenance.js';
import { candidateEngines, ENGINES, findExecutable, isEngineSupported } from '../../runtime-manager/src/profiles.js';
import type { ConcreteEngine } from '../../runtime-manager/src/profiles.js';
import { loadSavedSelection, selectionRoot } from '../../runtime-manager/src/selection.js';

const usage = `ud-agent [mcp]
ud-agent connect HOST [--working-tree PATH] [--check | --remove | --dry-run] [--no-skills]
ud-agent doctor [--working-tree PATH] [--engine NAME] [--offline] [--fix] [--json]
ud-agent check [--working-tree PATH] [--required-tools NAME,...] [--engine NAME] [--offline]
ud-agent setup [--working-tree PATH] [--required-tools NAME,...] [--engine NAME] [--mode MODE] [--network MODE] [--dry-run]
ud-agent validate --working-tree PATH [--lang CODE] [--level 1-5] [--no-setup]
ud-agent tools [--query TEXT] [--json]
ud-agent describe TOOL [--path INPUT_JSON_POINTER] [--json]
ud-agent read-resource URI [--allow-root PATH ...] [--json]
ud-agent call TOOL --input FILE [--allow-root PATH ...]
ud-agent shell-aliases --bin DIR [--dry-run] [--json]
ud-agent clean [--cache] --dry-run | ud-agent clean --cache [--engine NAME | --all]
ud-agent uninstall --owned-runtime [--dry-run] [--engine NAME | --all]

MCP uses your host's project roots. Use --allow-root PATH for an explicit grant,
or --discover-workspace for bounded discovery in a treebank folder.
UD_AGENT_ALLOWED_ROOTS also accepts the legacy JSON array of workspace grants.
`;

type Parsed = { positional: string[]; flags: Record<string, string[]>; switches: Set<string> };
function parse(args: string[], valueFlags: readonly string[], switchFlags: readonly string[]): Parsed {
  const parsed: Parsed = { positional: [], flags: {}, switches: new Set() };
  for (let index = 0; index < args.length; index++) {
    const item = args[index];
    if (item === undefined) break;
    if (switchFlags.includes(item)) { if (parsed.switches.has(item)) throw new Error(`Duplicate option: ${item}`); parsed.switches.add(item); continue; }
    if (valueFlags.includes(item)) {
      const value = args[++index];
      if (value === undefined || value.startsWith('--')) throw new Error(`Missing value for ${item}.`);
      if (item !== '--allow-root' && parsed.flags[item]) throw new Error(`Duplicate option: ${item}`);
      (parsed.flags[item] ??= []).push(value);
      continue;
    }
    if (item.startsWith('-')) throw new Error(`Unknown option: ${item}. Accepted options: ${[...valueFlags.map(flag => `${flag} VALUE`), ...switchFlags].join(', ') || 'none'}.`);
    parsed.positional.push(item);
  }
  return parsed;
}

async function readInput(filename: string): Promise<Record<string, unknown>> {
  const file = await open(filename, 'r');
  try {
    const info = await file.stat();
    if (!info.isFile() || info.size > 1024 * 1024) throw new Error('Request input must be a regular file of at most 1 MiB.');
    const bytes = await file.readFile();
    if (bytes.length > 1024 * 1024) throw new Error('Request input exceeds 1 MiB.');
    const value: unknown = JSON.parse(bytes.toString('utf8'));
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Request input must be a JSON object.');
    return value as Record<string, unknown>;
  } finally { await file.close(); }
}

export async function main(argv: string[]): Promise<number> {
  const command = argv[0] ?? 'mcp';
  if (command === '--help' || command === '-h' || command === 'help') { process.stdout.write(usage); return 0; }
  if (command === 'read-resource') {
    const parsed = parse(argv.slice(1), ['--allow-root'], ['--json']);
    if (parsed.positional.length !== 1) throw new Error('read-resource requires one product resource URI.');
    const grants = [...parseGrantedRoots(process.env.UD_AGENT_ALLOWED_ROOTS), ...(parsed.flags['--allow-root'] ?? [])];
    if (grants.some(root => !path.isAbsolute(root) || root.includes('\0'))) throw new Error('Workspace grants must be absolute paths.');
    const result = await readAuthorizedResource(projectRoot(), parsed.positional[0]!, grants);
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    return 0;
  }
  if (command === 'tools' || command === 'describe') {
    const parsed = parse(argv.slice(1), command === 'tools' ? ['--query'] : ['--path'], ['--json']);
    if (parsed.positional.length !== (command === 'describe' ? 1 : 0)) throw new Error(command === 'describe' ? 'Invalid arguments for describe. Usage: ud-agent describe OPERATION (for example validation_report); find operations with ud-agent tools --query WORD.' : 'Invalid arguments for tools. Usage: ud-agent tools [--query WORD].');
    const root = projectRoot();
    if (command === 'tools') {
      const result = discoverOperations(root, parsed.flags['--query']?.[0]);
      process.stdout.write(parsed.switches.has('--json') ? `${JSON.stringify(result, null, 2)}\n` : result.operations.map(operation => `${operation.name}: ${operation.purpose}\n`).join(''));
    } else {
      const result = describeOperation(root, parsed.positional[0]!, parsed.flags['--path']?.[0]);
      process.stdout.write(parsed.switches.has('--json') ? `${JSON.stringify(result, null, 2)}\n` : formatOperationDescription(result));
    }
    return 0;
  }
  if (command === 'mcp') {
    const parsed = parse(argv.slice(1), ['--allow-root'], ['--discover-workspace']);
    if (parsed.positional.length) throw new Error('The MCP command accepts only workspace grants or bounded discovery.');
    const grants = parsed.flags['--allow-root'] ?? [];
    if (grants.some(root => !path.isAbsolute(root))) throw new Error('Workspace grants must be absolute paths.');
    if (parsed.switches.has('--discover-workspace')) {
      const discovered = await discoverWorkspace();
      if (discovered) grants.push(discovered);
    }
    const transport = new TaskTransport();
    await serveStdio(() => createServer(undefined, transport, grants), { transport });
    return 0;
  }
  if (command === 'connect') {
    const parsed = parse(argv.slice(1), ['--working-tree'], ['--check', '--remove', '--dry-run', '--no-skills', '--json']);
    if (parsed.positional.length !== 1 || (parsed.switches.has('--check') && parsed.switches.has('--remove'))) throw new Error('Use connect HOST with --check or --remove, or neither to connect.');
    const workingTree = parsed.flags['--working-tree']?.[0];
    const result = await connectHost(parsed.positional[0]!, { sourceRoot: projectRoot(), ...(workingTree ? { workingTree } : {}), check: parsed.switches.has('--check'), remove: parsed.switches.has('--remove'), dryRun: parsed.switches.has('--dry-run'), noSkills: parsed.switches.has('--no-skills') });
    if (parsed.switches.has('--json')) process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    else process.stdout.write(`${result.host}: ${result.status}.\n${result.configuration ? `Configuration: ${result.configuration}\n` : ''}${result.next ?? ''}\n`);
    return ['not_connected', 'recovery_required'].includes(result.status as string) && parsed.switches.has('--check') ? 1 : 0;
  }
  if (command === 'shell-aliases') {
    // Opt-in for shell-only hosts: each skill name becomes a command in an explicit directory that answers with
    // the skill-load guidance (never an operation). Existing files are never replaced.
    const parsed = parse(argv.slice(1), ['--bin'], ['--dry-run', '--json']);
    const bin = parsed.flags['--bin']?.[0];
    if (parsed.positional.length || !bin || !path.isAbsolute(bin) || !existsSync(bin) || !statSync(bin).isDirectory()) throw new Error('Usage: ud-agent shell-aliases --bin DIR, where DIR is an existing absolute directory on the shell PATH.');
    const root = projectRoot(), entry = process.argv[1];
    const launcher = entry && path.resolve(entry) !== process.execPath ? [process.execPath, path.resolve(entry)] : [process.execPath];
    const skills = readdirSync(path.join(root, 'skills')).filter(name => existsSync(path.join(root, 'skills', name, 'SKILL.md'))).sort();
    const written: string[] = [], kept: string[] = [];
    for (const name of skills) {
      const file = path.join(bin, name);
      if (existsSync(file)) { kept.push(file); continue; }
      if (!parsed.switches.has('--dry-run')) writeFileSync(file, skillCommandAlias(launcher, name), { mode: 0o755, flag: 'wx' });
      written.push(file);
    }
    const result = { bin, dry_run: parsed.switches.has('--dry-run'), written, kept };
    process.stdout.write(parsed.switches.has('--json') ? `${JSON.stringify(result, null, 2)}\n` : `${result.dry_run ? 'Would write' : 'Wrote'} ${written.length} skill aliases in ${bin}${kept.length ? `; kept ${kept.length} existing files` : ''}.\n`);
    return 0;
  }
  if (command === 'doctor') {
    const parsed = parse(argv.slice(1), ['--working-tree', '--engine', '--required-tools'], ['--fix', '--offline', '--json']);
    if (parsed.positional.length) throw new Error('doctor does not accept positional arguments.');
    const root = projectRoot(), { domain, environment } = loadContracts(root);
    const workspace = parsed.flags['--working-tree']?.[0] ? path.resolve(parsed.flags['--working-tree']![0]!) : await discoverWorkspace();
    const name = parsed.switches.has('--fix') ? 'setup_ud_environment' : 'check_ud_environment';
    const contract = environment.find(item => item.name === name)!;
    const args = { ...(name === 'setup_ud_environment' ? { mode: 'repair' } : {}), ...(workspace ? { working_tree_path: workspace } : {}), ...(parsed.flags['--engine'] ? { engine: parsed.flags['--engine']![0] } : {}), required_tools: parsed.flags['--required-tools']?.[0]?.split(',') ?? ['validation_report'], ...(parsed.switches.has('--offline') ? name === 'setup_ud_environment' ? { network: 'offline' } : { offline: true } : {}) };
    const response = await executeOperation(contract, args, domain, { sourceRoot: root, allowedRoots: workspace ? [workspace] : [] });
    const result = response.structuredContent.result as Record<string, unknown>, runtime = result.runtime as Record<string, unknown> | undefined;
    if (parsed.switches.has('--json')) process.stdout.write(`${JSON.stringify(response.structuredContent, null, 2)}\n`);
    else process.stdout.write(`UD environment: ${result.status ?? 'rejected'}\n${workspace ? `Workspace: ${workspace}\n` : ''}${runtime?.engine ? `Runtime: ${runtime.engine}\n` : ''}${result.reason ? `${result.reason}\n` : ''}${result.ready ? 'Ready. Return to your host and ask it to validate your treebank.' : parsed.switches.has('--fix') ? 'Setup could not finish. The reported missing prerequisite must be resolved before retrying doctor --fix.' : 'Run ud-agent doctor --fix to prepare or repair the verified local runtime.'}\n`);
    return response.isError || result.status === 'failed' || result.status === 'rejected' ? 1 : 0;
  }
  if (command === 'clean' || command === 'uninstall') {
    const parsed = parse(argv.slice(1), ['--engine'], command === 'clean' ? ['--cache', '--dry-run', '--all'] : ['--owned-runtime', '--dry-run', '--all']);
    if (parsed.positional.length || (command === 'clean' && !parsed.switches.has('--cache') && !parsed.switches.has('--dry-run')) || (command === 'uninstall' && !parsed.switches.has('--owned-runtime'))) throw new Error(`Invalid arguments for ${command}.`);
    if (parsed.switches.has('--all') && parsed.flags['--engine']) throw new Error('Choose --engine or --all.');
    const dryRun = parsed.switches.has('--dry-run');
    const action = command === 'clean' ? 'cache' : 'owned-runtime';
    const host = { platform: process.platform, arch: process.arch }, root = projectRoot();
    const guard = process.platform === 'win32' ? (await loadNativeGuardReceipt(root, host)).guard : undefined;
    const requested = parsed.flags['--engine']?.[0] ?? 'auto';
    if (!ENGINES.includes(requested as typeof ENGINES[number]) || requested !== 'auto' && !isEngineSupported(requested as ConcreteEngine, host)) throw new Error('Unsupported cleanup engine.');
    const saved = requested === 'auto' ? await loadSavedSelection(selectionRoot(host), host, guard) : undefined;
    const engines = parsed.switches.has('--all') ? candidateEngines(host) : [requested === 'auto' ? saved ?? 'userspace' : requested as ConcreteEngine];
    const outcome = engines.includes('userspace') ? await cleanUserspaceState(undefined, action, dryRun, guard) : { paths: [], dry_run: dryRun };
    const providers = [];
    for (const engine of engines) if (engine !== 'userspace') {
      const executable = await findExecutable(engine, host, process.env.PATH ?? '');
      providers.push(await maintainProviderRuntime({ sourceRoot: root }, engine, executable ?? '', host, { action, dryRun }));
    }
    process.stdout.write(`${JSON.stringify({ action, scope: providers.length ? 'owned-runtimes' : 'userspace', ...outcome, providers, limitations: providers.flatMap(result => result.limitations) }, null, 2)}\n`);
    return 0;
  }
  if (!['check', 'setup', 'validate', 'call'].includes(command)) {
    const root = projectRoot(), { domain, environment } = loadContracts(root);
    const guidance = commandGuidance(command, {
      arguments: argv.slice(1),
      operations: [...domain, ...environment].map(item => item.name),
      skillFile: skill => {
        const local = projectSkillDirectories().map(directory => path.join(directory, skill, 'SKILL.md')).find(file => existsSync(file));
        return local ?? (existsSync(path.join(root, 'skills', skill, 'SKILL.md')) ? path.join(root, 'skills', skill, 'SKILL.md') : undefined);
      },
      describes: skill => {
        try { return /ud-agent describe ([a-z_]+)/.exec(readFileSync(path.join(root, 'skills', skill, 'SKILL.md'), 'utf8').split('\n---')[0] ?? '')?.[1]; } catch { return undefined; }
      },
    });
    throw new Error(guidance ?? `Unknown command: ${command}`);
  }

  const commonFlags = ['--working-tree', '--required-tools', '--engine', '--allow-root'];
  const setupFlags = ['--mode', '--network', '--continuation-token', '--target-release'];
  const valueFlags = command === 'call' ? ['--input', '--allow-root'] : command === 'validate' ? ['--working-tree', '--lang', '--level', '--allow-root'] : [...commonFlags, ...(command === 'setup' ? setupFlags : [])];
  const switchFlags = command === 'check' ? ['--offline'] : command === 'setup' ? ['--dry-run'] : command === 'validate' ? ['--no-setup'] : [];
  const parsed = parse(argv.slice(1), valueFlags, switchFlags);
  if ((command === 'call' && parsed.positional.length !== 1) || (command !== 'call' && command !== 'validate' && parsed.positional.length !== 0)) throw new Error(`Invalid arguments for ${command}.`);
  const root = projectRoot();
  const { domain, environment } = loadContracts(root);
  const suppliedRoot = parsed.flags['--working-tree']?.[0];
  const grants = [...parseGrantedRoots(process.env.UD_AGENT_ALLOWED_ROOTS), ...(parsed.flags['--allow-root'] ?? []), ...(suppliedRoot ? [suppliedRoot] : [])];
  if (grants.some(grant => !path.isAbsolute(grant))) throw new Error('Workspace grants must be absolute paths.');
  const options = { sourceRoot: root, allowedRoots: grants };
  const operation = command === 'check' ? 'check_ud_environment' : command === 'setup' ? 'setup_ud_environment' : command === 'validate' ? 'validation_report' : parsed.positional[0];
  if (!operation) throw new Error('A tool name is required.');
  const contract = [...domain, ...environment].find(item => item.name === operation);
  if (!contract) throw new Error(`Unknown tool: ${operation}`);
  let args: Record<string, unknown> = {};
  if (command === 'call') {
    const filename = parsed.flags['--input']?.[0];
    if (!filename) throw new Error('call requires --input FILE.');
    args = await readInput(filename);
  } else {
    if (suppliedRoot) args.working_tree_path = suppliedRoot;
    if (command === 'validate') {
      if (!suppliedRoot) throw new Error('validate requires --working-tree PATH.');
      const levelString = parsed.flags['--level']?.[0] ?? '5';
      if (!/^[1-5]$/.test(levelString)) throw new Error('Validation level must be between 1 and 5.');
      // Files named after the options select those files (relative to the working tree); none selects every .conllu file.
      const prose = parsed.positional.filter(name => !/\.conllu$/i.test(name));
      if (prose.length) throw new Error(`validate checks CoNLL-U .conllu files only; ${prose.join(', ')} ${prose.length === 1 ? 'is' : 'are'} not CoNLL-U. For prose or report wording, read the file and answer without ud-agent.`);
      args.file_paths = parsed.positional.map(name => path.isAbsolute(name) ? path.relative(suppliedRoot, name) : name);
      args.ud_context_path = '';
      const language = parsed.flags['--lang']?.[0];
      if (!language) throw new Error('validate requires --lang until language detection is available; add the data language code, e.g. --lang en.');
      args.options = { language_code: language, level: Number(levelString) };
      if (!parsed.switches.has('--no-setup')) {
        const setup = environment.find(item => item.name === 'setup_ud_environment');
        if (!setup) throw new Error('The environment setup contract is missing.');
        const prepared = await executeOperation(setup, { working_tree_path: suppliedRoot, required_tools: ['validation_report'] }, domain, options);
        if (prepared.isError || prepared.structuredContent.result.ready !== true) {
          process.stdout.write(`${JSON.stringify(prepared.structuredContent, null, 2)}\n`);
          return 1;
        }
      }
    } else {
      const required = parsed.flags['--required-tools']?.[0];
      if (required !== undefined) args.required_tools = required.split(',');
      if (parsed.flags['--engine']?.[0]) args.engine = parsed.flags['--engine'][0];
      if (parsed.switches.has('--offline')) args.offline = true;
      if (parsed.switches.has('--dry-run')) args.dry_run = true;
      for (const [flag, key] of [['--mode', 'mode'], ['--network', 'network'], ['--continuation-token', 'continuation_token'], ['--target-release', 'target_release']] as const) {
        if (parsed.flags[flag]?.[0]) args[key] = parsed.flags[flag][0];
      }
    }
  }
  const schema = fromJsonSchema<Record<string, unknown>>(loadInputSchema(root, operation));
  const validated = await schema['~standard'].validate(args);
  if (validated.issues) throw new Error(validated.issues.map(issue => issue.message).join('; '));
  const outcome = await executeOperation(contract, validated.value, domain, options, undefined, command === 'validate' ? { selectAllFiles: true } : undefined);
  process.stdout.write(`${JSON.stringify(outcome.structuredContent, null, 2)}\n`);
  if (outcome.isError) return 1;
  if (command === 'setup' && !parsed.switches.has('--dry-run') && outcome.structuredContent.result.ready === false) return 1;
  return 0;
}
