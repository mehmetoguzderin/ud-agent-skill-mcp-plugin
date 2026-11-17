/** Host-specific distribution metadata derived from the owned identity. */
import { readFileSync } from 'node:fs';
import path from 'node:path';

export const releasePlatformIds = Object.freeze({
  'darwin-arm64': 'macos-arm64',
  'linux-arm64': 'linux-arm64',
  'linux-x64': 'linux-amd64',
  'win32-arm64': 'windows-arm64',
  'win32-x64': 'windows-amd64',
});
export const releasePlatforms = Object.freeze(Object.keys(releasePlatformIds));

export function windowsNodeDescriptor(root, platform) {
  const lock = JSON.parse(readFileSync(path.join(root, 'packages/launcher/src/windows-node.json'), 'utf8'));
  const pin = lock.platforms?.[platform];
  if (lock.schema_version !== 1 || !/^\d+\.\d+\.\d+$/.test(lock.version) || !/^win32-(arm64|x64)$/.test(platform) ||
      !/^[0-9a-f]{64}$/.test(pin?.sha256 ?? '') || !Number.isSafeInteger(pin.size_bytes) || pin.size_bytes < 1) {
    throw new Error('Invalid Windows vendor Node acquisition lock.');
  }
  return { schema_version: 1, version: lock.version, platform, sha256: `sha256:${pin.sha256}`, size_bytes: pin.size_bytes,
    url: `https://nodejs.org/dist/v${lock.version}/${platform.replace('win32-', 'win-')}/node.exe` };
}

function readFlatYaml(filename) {
  const result = {};
  for (const line of readFileSync(filename, 'utf8').split(/\r?\n/)) {
    if (!line.trim() || line.trimStart().startsWith('#')) continue;
    const match = /^([a-z_]+):\s+([^#\s]+)\s*$/.exec(line);
    if (!match || Object.hasOwn(result, match[1])) throw new Error(`Invalid distribution metadata in ${filename}`);
    result[match[1]] = match[2];
  }
  return result;
}

export function loadDistributionIdentity(root) {
  const identity = readFlatYaml(path.join(root, 'release/identity.yaml'));
  const product = readFlatYaml(path.join(root, 'release/product.yaml'));
  for (const key of ['github_owner', 'repository', 'npm_scope', 'npm_package', 'mcp_namespace', 'ghcr_core', 'ghcr_render', 'marketplace']) {
    if (!identity[key]) throw new Error(`Missing distribution identity: ${key}`);
  }
  if (!/^[a-z0-9][a-z0-9-]*$/.test(identity.github_owner) ||
      !/^[a-z0-9][a-z0-9-]*$/.test(identity.repository) ||
      !/^[a-z0-9][a-z0-9-]*$/.test(identity.marketplace) ||
      identity.npm_scope !== identity.github_owner || identity.npm_package !== identity.repository ||
      identity.mcp_namespace !== `io.github.${identity.github_owner}` ||
      identity.ghcr_core !== `ghcr.io/${identity.github_owner}/${identity.repository}-core` ||
      identity.ghcr_render !== `ghcr.io/${identity.github_owner}/${identity.repository}-render` ||
      product.name !== identity.repository || !/^\d+\.\d+\.\d+(?:-[a-z0-9.]+)?$/.test(product.version ?? '')) {
    throw new Error('Distribution coordinates are inconsistent or unsafe.');
  }
  return Object.freeze({ ...identity, name: product.name, version: product.version,
    npm: `@${identity.npm_scope}/${identity.npm_package}`,
    mcpName: `${identity.mcp_namespace}/${identity.repository}`,
    repositoryUrl: `https://github.com/${identity.github_owner}/${identity.repository}` });
}

const description = 'Local Universal Dependencies (UD) and CONLL-U (conllu) validation, editing, and analysis with agentic skills, MCP, CLI, and plugin.';
const geminiDescription = description;
const json = value => JSON.stringify(value, null, 2) + '\n';
const server = command => ({ command, args: ['mcp', '--discover-workspace'] });

export function sourceHostFiles(id) {
  const claudePlugin = { name: id.name, version: id.version, description, author: { name: id.github_owner }, repository: id.repositoryUrl, license: 'MIT' };
  const marketplace = {
    name: id.marketplace, description: 'Universal Dependencies local tools and skills.',
    owner: { name: id.github_owner },
    plugins: [{ name: id.name, description, source: { source: 'npm', package: id.npm, version: id.version },
      policy: { installation: 'AVAILABLE', authentication: 'ON_INSTALL' }, category: 'Productivity' }],
  };
  const codexMarketplace = {
    name: id.marketplace, interface: { displayName: 'Universal Dependencies tools' },
    plugins: [{ name: id.name, source: { source: 'npm', package: id.npm, version: id.version },
      policy: { installation: 'AVAILABLE', authentication: 'ON_INSTALL' }, category: 'Productivity' }],
  };
  const registry = {
    $schema: 'https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json',
    name: id.mcpName, description: 'Local Universal Dependencies and CoNLL-U validation, editing and analysis with six agent skills.',
    version: id.version, repository: { url: id.repositoryUrl, source: 'github' },
    packages: [{ registryType: 'npm', identifier: id.npm, version: id.version, transport: { type: 'stdio' } }],
  };
  const sourceMcp = { command: 'npx', args: ['-y', `${id.npm}@${id.version}`, 'mcp', '--discover-workspace'] };
  const grokMarketplace = { name: id.marketplace, description: 'Universal Dependencies tools and six skills.', owner: { name: id.github_owner }, plugins: [{ name: id.name, version: id.version, description, source: { type: 'local', path: `./packaging/grok/${id.name}` } }] };
  const grokIndex = { version: 1, plugins: { [id.name]: { version: id.version, components: { mcpServers: [{ name: 'ud', description: 'stdio' }], skills: ['ud-validate', 'ud-edit', 'ud-investigate', 'ud-compare', 'ud-rules-docs', 'ud-release'].map(name => ({ name, description: `Universal Dependencies ${name.slice(3)} workflow.` })) } } } };
  return {
    '.claude-plugin/plugin.json': json(claudePlugin),
    '.claude-plugin/marketplace.json': json(marketplace),
    '.mcp.json': json({ mcpServers: { ud: sourceMcp } }),
    '.grok-plugin/plugin.json': json(claudePlugin),
    '.grok-plugin/marketplace.json': json(grokMarketplace),
    '.grok-plugin/plugin-index.json': json(grokIndex),
    [`packaging/grok/${id.name}/.grok-plugin/plugin.json`]: json(claudePlugin),
    [`packaging/grok/${id.name}/.mcp.json`]: json({ mcpServers: { ud: sourceMcp } }),
    'kimi.plugin.json': json({ name: id.name, version: id.version, description, author: id.github_owner, license: 'MIT', skills: './skills/', mcpServers: { ud: sourceMcp } }),
    'gemini-extension.json': json({ name: id.name, version: id.version, description: geminiDescription, mcpServers: { ud: sourceMcp } }),
    'packaging/codex/marketplace.json': json(codexMarketplace),
    'registry/server.json': json(registry),
  };
}

/** Generate one platform's host manifests. No host command invokes a shell. */
export function nativeHostFiles(id, platform) {
  if (!['darwin-arm64', 'darwin-x64', 'linux-arm64', 'linux-x64', 'win32-arm64', 'win32-x64'].includes(platform)) throw new Error('Unsupported native package platform.');
  const ext = platform.startsWith('win32-') ? '.exe' : '';
  const os = platform.startsWith('darwin-') ? 'darwin' : platform.startsWith('win32-') ? 'win32' : 'linux';
  const source = sourceHostFiles(id);
  const mcpb = {
    $schema: 'https://raw.githubusercontent.com/modelcontextprotocol/mcpb/main/schemas/mcpb-manifest-v0.4.schema.json',
    manifest_version: '0.4', name: id.name, version: id.version, description,
    author: { name: id.github_owner }, repository: { type: 'git', url: id.repositoryUrl }, license: 'MIT',
    server: os === 'win32' ? {
      type: 'binary', entry_point: 'bin/ud-agent.exe',
      mcp_config: { command: '${__dirname}/bin/ud-agent.exe', args: ['--mcpb-workspace', '${user_config.workspace}'] },
    } : {
      type: 'node', entry_point: 'mcpb-entry.cjs',
      mcp_config: { command: '${__dirname}/runtime/node/bin/node',
        args: ['${__dirname}/mcpb-entry.cjs', '${user_config.workspace}'] },
    },
    compatibility: { platforms: [os] }, tools_generated: true,
    user_config: { workspace: { type: 'directory', title: 'Authorized workspace',
      description: 'The treebank directory this local server may access.', required: true } },
  };
  return {
    'mcp.json': json({ $schema: 'https://agent-plugins.org/schemas/1.0.0/mcp.schema.json',
      mcpServers: { ud: { type: 'stdio', ...server(`\${PLUGIN_ROOT}/bin/ud-agent${ext}`) } } }),
    '.mcp.json': json({ mcpServers: { ud: server(`\${CLAUDE_PLUGIN_ROOT}/bin/ud-agent${ext}`) } }),
    '.claude-plugin/plugin.json': source['.claude-plugin/plugin.json'],
    '.claude-plugin/marketplace.json': source['.claude-plugin/marketplace.json'],
    '.agents/plugins/marketplace.json': source['packaging/codex/marketplace.json'],
    '.grok-plugin/plugin.json': source['.grok-plugin/plugin.json'],
    'kimi.plugin.json': json({ name: id.name, version: id.version, description, author: id.github_owner, license: 'MIT', skills: './skills/', mcpServers: { ud: { command: `./bin/ud-agent${ext}`, args: ['mcp', '--discover-workspace'] } } }),
    'gemini-extension.json': json({ name: id.name, version: id.version, description: geminiDescription,
      mcpServers: { ud: server(`\${extensionPath}/bin/ud-agent${ext}`) } }),
    'manifest.json': json(mcpb),
  };
}

export function npmHostFiles(id) {
  const source = sourceHostFiles(id);
  return {
    'plugin.json': json({ $schema: 'https://agent-plugins.org/schemas/1.0.0/plugin.schema.json',
      name: id.name, version: id.version, description, author: { name: id.github_owner },
      repository: id.repositoryUrl, license: 'MIT' }),
    'mcp.json': json({ $schema: 'https://agent-plugins.org/schemas/1.0.0/mcp.schema.json',
      mcpServers: { ud: { type: 'stdio', command: 'node', args: ['${PLUGIN_ROOT}/cli.cjs', 'mcp', '--discover-workspace'] } } }),
    '.mcp.json': json({ mcpServers: { ud: { command: 'node', args: ['${CLAUDE_PLUGIN_ROOT}/cli.cjs', 'mcp', '--discover-workspace'] } } }),
    '.claude-plugin/plugin.json': source['.claude-plugin/plugin.json'],
    '.grok-plugin/plugin.json': source['.grok-plugin/plugin.json'],
    'kimi.plugin.json': source['kimi.plugin.json'],
  };
}

export function readmeCoordinates(id) {
  return [
    '| Distribution | Release coordinate |',
    '| --- | --- |',
    `| npm | \`${id.npm}@${id.version}\` |`,
    `| GitHub Releases | [${id.github_owner}/${id.repository} \`v${id.version}\`](${id.repositoryUrl}/releases/tag/v${id.version}) |`,
    `| Core worker image | \`${id.ghcr_core}\` |`,
    `| Render worker image | \`${id.ghcr_render}\` |`,
    `| MCP Registry | \`${id.mcpName}\` |`,
    `| Owned marketplace | \`${id.name}@${id.marketplace}\` |`,
  ].join('\n');
}

export function readmeArchives(id) {
  const base = `${id.repositoryUrl}/releases/download/v${id.version}`;
  const rows = [
    ['macOS', 'Apple silicon', 'darwin-arm64', 'tar.gz'],
    ['Linux', 'arm64', 'linux-arm64', 'tar.gz'], ['Linux', 'x86-64', 'linux-x64', 'tar.gz'],
    ['Windows', 'arm64', 'win32-arm64', 'zip'], ['Windows', 'x86-64', 'win32-x64', 'zip'],
  ];
  return ['| OS | CPU | Native archive | MCPB |', '| --- | --- | --- | --- |',
    ...rows.map(([os, cpu, platform, extension]) => `| ${os} | ${cpu} | [\`${id.name}-${platform}.${extension}\`](${base}/${id.name}-${platform}.${extension}) | [bundle](${base}/${id.name}-${platform}.mcpb) |`),
    '', `Download [SHA256SUMS](${base}/SHA256SUMS) alongside your selected asset. The checksum manifest covers the final release files and intentionally does not hash itself.`].join('\n');
}
