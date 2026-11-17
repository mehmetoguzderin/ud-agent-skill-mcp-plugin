import { test } from 'vitest';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { loadDistributionIdentity, nativeHostFiles, npmHostFiles, readmeCoordinates, sourceHostFiles } from '../../scripts/release/host-adapters.mjs';

const root = process.cwd();
const identity = loadDistributionIdentity(root);
const require = createRequire(import.meta.url);
const { launchOptions } = require('../../packaging/mcpb-entry.cjs');

test('registry and marketplace advertise the coordinator with the same pinned npm identity', () => {
  const files = sourceHostFiles(identity);
  const registry = JSON.parse(files['registry/server.json']);
  const claude = JSON.parse(files['.claude-plugin/marketplace.json']);
  const codex = JSON.parse(files['packaging/codex/marketplace.json']);
  const npmPackage = JSON.parse(readFileSync(path.join(root, 'packages/npm-distribution/package.json.in'), 'utf8'));
  assert.equal(registry.name, npmPackage.mcpName);
  assert.deepEqual(registry.packages, [{ registryType: 'npm', identifier: npmPackage.name,
    version: npmPackage.version, transport: { type: 'stdio' } }]);
  for (const catalog of [claude, codex]) {
    assert.equal(catalog.name, 'ud-agent-skill-mcp-plugin');
    assert.equal(catalog.plugins.length, 1);
    assert.equal(catalog.plugins[0].name, identity.name);
    assert.deepEqual(catalog.plugins[0].source, { source: 'npm', package: npmPackage.name, version: npmPackage.version });
  }
  for (const filename of ['plugin.json', 'mcp.json', '.mcp.json', '.claude-plugin/']) assert.ok(npmPackage.files.includes(filename));
});

test('six native manifests use their own platform launcher and MCPB workspace input', () => {
  for (const platform of ['darwin-arm64', 'darwin-x64', 'linux-arm64', 'linux-x64', 'win32-arm64', 'win32-x64']) {
    const files = nativeHostFiles(identity, platform);
    const suffix = platform.startsWith('win32') ? '.exe' : '';
    const portable = JSON.parse(files['mcp.json']).mcpServers.ud;
    const claude = JSON.parse(files['.mcp.json']).mcpServers.ud;
    const gemini = JSON.parse(files['gemini-extension.json']).mcpServers.ud;
    const mcpb = JSON.parse(files['manifest.json']);
    assert.equal(portable.command, `\${PLUGIN_ROOT}/bin/ud-agent${suffix}`);
    assert.equal(claude.command, `\${CLAUDE_PLUGIN_ROOT}/bin/ud-agent${suffix}`);
    assert.equal(gemini.command, `\${extensionPath}/bin/ud-agent${suffix}`);
    assert.deepEqual(mcpb.server, suffix ? {
      type: 'binary', entry_point: 'bin/ud-agent.exe',
      mcp_config: { command: '${__dirname}/bin/ud-agent.exe', args: ['--mcpb-workspace', '${user_config.workspace}'] },
    } : {
      type: 'node', entry_point: 'mcpb-entry.cjs',
      mcp_config: { command: '${__dirname}/runtime/node/bin/node', args: ['${__dirname}/mcpb-entry.cjs', '${user_config.workspace}'] },
    });
    assert.equal(mcpb.user_config.workspace.type, 'directory');
    assert.equal(mcpb.user_config.workspace.required, true);
    assert.equal(mcpb.compatibility.platforms[0], platform.split('-')[0]);
  }
  assert.throws(() => nativeHostFiles(identity, 'freebsd-x64'), /Unsupported/);
});

test('npm plugin configs launch the packaged coordinator with Node rather than relying on a global command', () => {
  const files = npmHostFiles(identity);
  for (const [filename, variable] of [['mcp.json', '${PLUGIN_ROOT}'], ['.mcp.json', '${CLAUDE_PLUGIN_ROOT}']]) {
    const command = JSON.parse(files[filename]).mcpServers.ud;
    assert.equal(command.command, 'node');
    assert.deepEqual(command.args, [`${variable}/cli.cjs`, 'mcp', '--discover-workspace']);
  }
});

test('MCPB workspace selection creates a JSON grant without inheriting launcher overrides', () => {
  const temp = mkdtempSync(path.join(os.tmpdir(), 'ud mcpb test '));
  try {
    // Windows filenames cannot contain double quotes; apostrophes and spaces
    // still exercise literal path handling, alongside JSON-escaped backslashes.
    const workspace = path.join(temp, process.platform === 'win32' ? "tree 'with quotes'" : 'tree "with quotes"');
    mkdirSync(workspace);
    const input = { UD_AGENT_NODE: '/evil/node', UD_AGENT_COORDINATOR: '/evil/server', OTHER: 'preserved' };
    const launch = launchOptions(temp, workspace, input);
    assert.equal(launch.executable, path.join(temp, 'bin', process.platform === 'win32' ? 'ud-agent.exe' : 'ud-agent'));
    assert.deepEqual(launch.args, ['mcp']);
    assert.deepEqual(JSON.parse(launch.options.env.UD_AGENT_ALLOWED_ROOTS), [workspace]);
    assert.equal(launch.options.env.OTHER, 'preserved');
    assert.equal(launch.options.env.UD_AGENT_NODE, undefined);
    assert.equal(launch.options.env.UD_AGENT_COORDINATOR, undefined);
    assert.equal(input.UD_AGENT_NODE, '/evil/node');
    assert.throws(() => launchOptions(temp, 'relative'), /absolute workspace/);
    const file = path.join(temp, 'file'); writeFileSync(file, 'x');
    assert.throws(() => launchOptions(temp, file), /real directory/);
  } finally { rmSync(temp, { recursive: true, force: true }); }
});

test('README contains identity-derived coordinates and all requested host routes', () => {
  const readme = readFileSync(path.join(root, 'README.md'), 'utf8');
  assert.ok(readme.includes(readmeCoordinates(identity)));
  for (const name of ['ChatGPT Desktop', 'Codex desktop, CLI, and IDE', 'Claude Code', 'Claude Desktop and Cowork',
    'Grok Build', 'mini-swe-agent', 'Kimi Code', 'Hermes Agent', 'Qwen Code', 'DeepSeek Harness',
    'OpenClaw', 'Pi harness', 'Gemini CLI', 'Cursor', 'VS Code GitHub Copilot']) {
    assert.ok(readme.includes(`### ${name}`), `missing guide: ${name}`);
  }
});

test('Copilot and VS Code Local examples use the correct separate configuration envelopes', () => {
  const readme = readFileSync(path.join(root, 'README.md'), 'utf8');
  const blocks = [...readme.matchAll(/```json\n([\s\S]*?)\n```/g)].map(match => JSON.parse(match[1]));
  const portable = blocks.find(block => block.mcpServers?.ud);
  const local = blocks.find(block => block.servers?.ud);
  assert.ok(portable, 'portable MCP example is missing');
  assert.ok(local, 'VS Code Local MCP example is missing');
  assert.equal(local.servers.ud.type, 'stdio');
  assert.deepEqual(local.servers.ud.args, ['mcp']);
  for (const entry of [portable.mcpServers.ud, local.servers.ud]) {
    assert.deepEqual(JSON.parse(entry.env.UD_AGENT_ALLOWED_ROOTS), ['/absolute/path/to/your-treebank']);
  }
  assert.match(readme, /~\/\.copilot\/mcp-config\.json/);
  assert.match(readme, /\.github\/skills\//);
  assert.match(readme, /~\/\.copilot\/skills\//);
});


test('native Grok marketplace points at a nonempty vendored plugin with six exact skills and an MCP server', () => {
  const files = sourceHostFiles(identity);
  const market = JSON.parse(files['.grok-plugin/marketplace.json']);
  const relative = market.plugins[0].source.path.replace(/^\.\//, '');
  assert.equal(relative, `packaging/grok/${identity.name}`);
  assert.equal(JSON.parse(files[`${relative}/.grok-plugin/plugin.json`]).name, identity.name);
  assert.deepEqual(JSON.parse(files[`${relative}/.mcp.json`]).mcpServers.ud.args,
    ['-y', `${identity.npm}@${identity.version}`, 'mcp', '--discover-workspace']);
  const index = JSON.parse(files['.grok-plugin/plugin-index.json']).plugins[identity.name];
  assert.deepEqual(index.components.mcpServers, [{name:'ud',description:'stdio'}]);
  for (const skill of index.components.skills) {
    assert.equal(readFileSync(path.join(root,relative,'skills',skill.name,'SKILL.md'),'utf8'), readFileSync(path.join(root,'skills',skill.name,'SKILL.md'),'utf8'));
  }
});
