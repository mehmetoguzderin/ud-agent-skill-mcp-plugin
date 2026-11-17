/** Select and verify an already assembled installation without rebuilding it. */
import { existsSync, lstatSync, readFileSync, readdirSync } from 'node:fs';
import path from 'node:path';
import { fileReceipt } from '../release/candidate.mjs';
import { canonicalJson } from '../release/http-transports.mjs';

export function verifyInstalledPayload(root, { platform = process.platform } = {}) {
  const inventoryReceipt = fileReceipt(root, 'PACKAGE-INVENTORY.json');
  const inventory = JSON.parse(readFileSync(path.join(root, 'PACKAGE-INVENTORY.json'), 'utf8'));
  if (inventory.schema_version !== 1 || !Array.isArray(inventory.files) || !inventory.files.length) throw new Error('Installed package inventory is missing or empty.');
  const seen = new Set();
  for (const item of inventory.files) {
    if (!item || typeof item.executable !== 'boolean' || item.path === 'PACKAGE-INVENTORY.json' || seen.has(item.path)) throw new Error('Installed payload differs from its complete package inventory.');
    const actual = fileReceipt(root, item.path);
    // Windows does not preserve POSIX executable mode bits on extraction.
    // Bytes, names and sizes remain exact; native PE identity is verified by
    // package inspection and the launcher/runtime authority paths.
    if (canonicalJson(actual) !== canonicalJson(platform === 'win32' ? { ...item, executable: actual.executable } : item)) throw new Error('Installed payload differs from its complete package inventory.');
    seen.add(item.path);
  }
  const actual = [];
  function walk(directory, prefix = '') {
    for (const name of readdirSync(directory).sort()) {
      const relative = prefix + name, filename = path.join(directory, name), info = lstatSync(filename);
      if (info.isSymbolicLink()) throw new Error('Installed payload contains a symbolic link.');
      if (info.isDirectory()) walk(filename, relative + '/');
      else if (info.isFile()) actual.push(relative);
      else throw new Error('Installed payload contains a special file.');
    }
  }
  walk(root);
  if (canonicalJson(actual.filter(name => name !== 'PACKAGE-INVENTORY.json').sort()) !== canonicalJson([...seen].sort())) throw new Error('Installed package inventory omits or adds payload files.');
  const build = JSON.parse(readFileSync(path.join(root, 'BUILD-RECEIPT.json'), 'utf8'));
  if (build.schema_version !== 1 || build.product_version !== '0.1.0-beta.1' || !/^[0-9a-f]{64}$/.test(build.source_tree_sha256) || fileReceipt(root, 'runtime/runtime.lock.json').sha256 !== build.runtime_lock_sha256) throw new Error('Installed package build and runtime subjects differ.');
  return { inventory_sha256: inventoryReceipt.sha256, source_tree_sha256: build.source_tree_sha256, runtime_lock_sha256: build.runtime_lock_sha256, kind: build.kind, platform: build.platform, files: inventory.files.length };
}

export function installedMcpLaunch(root, workspace, { format = 'coordinator', node = process.execPath, bundleName = 'coordinator.mjs', platform = process.platform, localAppData = process.env.LOCALAPPDATA } = {}) {
  if (!['coordinator', 'native', 'npm', 'mcpb'].includes(format) || !/^coordinator(?:-node(?:24|26))?\.mjs$/.test(bundleName)) throw new Error('Unsupported installed MCP entry profile.');
  if (format !== 'coordinator' && bundleName !== 'coordinator.mjs') throw new Error('Packaged launcher profiles use their original coordinator entry.');
  const suffix = platform === 'win32' ? '.exe' : '', entry = path.join(root, 'lib', bundleName);
  fileReceipt(root, 'lib/' + bundleName);
  if (platform === 'win32' && ['native', 'mcpb'].includes(format) && existsSync(path.join(root, 'runtime/windows-node.json'))) {
    fileReceipt(root, 'runtime/windows-node.json'); fileReceipt(root, 'bin/ud-agent.exe');
    const pinned = JSON.parse(readFileSync(path.join(root, 'runtime/windows-node.json'), 'utf8'));
    if (!/^sha256:[0-9a-f]{64}$/.test(pinned.sha256 ?? '') || !localAppData || !path.isAbsolute(localAppData)) throw new Error('Windows installed MCP needs a pinned Node and an absolute LocalAppData directory.');
    return { command: path.join(root, 'bin/ud-agent.exe'), args: format === 'mcpb' ? ['--mcpb-workspace', workspace] : ['mcp', '--allow-root', workspace],
      node: path.join(localAppData, 'ud-agent/data/node-cache', `node-${pinned.sha256.slice(7)}.exe`), coordinator: entry, env: {} };
  }
  if (format === 'native') {
    const relative = 'bin/ud-agent' + suffix, receipt = fileReceipt(root, relative);
    if (platform !== 'win32' && !receipt.executable) throw new Error('Installed native launcher is not executable.');
    const bundledNode = path.join(root, 'runtime/node/bin/node' + suffix); fileReceipt(root, 'runtime/node/bin/node' + suffix);
    return { command: path.join(root, relative), args: ['mcp', '--allow-root', workspace], node: bundledNode, coordinator: entry, env: {} };
  }
  if (!path.isAbsolute(node)) throw new Error('Installed MCP Node executable must be absolute.');
  if (format === 'mcpb') {
    fileReceipt(root, 'mcpb-entry.cjs'); fileReceipt(root, 'bin/ud-agent' + suffix); fileReceipt(root, 'runtime/node/bin/node' + suffix);
    return { command: node, args: [path.join(root, 'mcpb-entry.cjs'), workspace], node: path.join(root, 'runtime/node/bin/node' + suffix), coordinator: entry, env: {} };
  }
  const relative = format === 'npm' ? 'cli.cjs' : 'lib/' + bundleName;
  fileReceipt(root, relative);
  return { command: node, args: [path.join(root, relative), 'mcp', '--allow-root', workspace], node, coordinator: entry, env: {} };
}
