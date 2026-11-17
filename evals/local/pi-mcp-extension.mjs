/** MIT. Pi's documented extension API, with transparent MCP stdio transport.
 * No prompt selection, argument rewriting, model request, or agent loop lives here. */
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';

export default async function registerMcp(pi) {
  const configuration = JSON.parse(readFileSync(path.join(process.cwd(), '.pi/mcp.json'), 'utf8'));
  const servers = Object.entries(configuration.mcpServers ?? {});
  const children = [];
  for (const [server, entry] of servers) {
    if (!entry || typeof entry.command !== 'string' || !Array.isArray(entry.args)) throw new Error('MCP_STDIO_CONFIGURATION_INVALID');
    const child = spawn(entry.command, entry.args, { cwd: process.cwd(), env: process.env, stdio: ['pipe', 'pipe', 'pipe'] });
    children.push(child); child.stderr.on('data', data => process.stderr.write(data));
    const pending = new Map(); let sequence = 0, buffer = '';
    child.stdout.setEncoding('utf8'); child.stdout.on('data', chunk => {
      buffer += chunk;
      if (buffer.length > 8 * 1024 ** 2) { child.kill('SIGTERM'); return; }
      let end; while ((end = buffer.indexOf('\n')) >= 0) {
        const line = buffer.slice(0, end); buffer = buffer.slice(end + 1);
        if (!line.trim()) continue;
        try { const response = JSON.parse(line), request = pending.get(response.id); if (request) { pending.delete(response.id); clearTimeout(request.timer); response.error ? request.reject(new Error(response.error.message)) : request.resolve(response.result); } }
        catch { child.kill('SIGTERM'); }
      }
    });
    const fail = () => { for (const request of pending.values()) { clearTimeout(request.timer); request.reject(new Error('MCP_STDIO_CLOSED')); } pending.clear(); };
    child.on('error', fail); child.on('exit', fail); child.stdin.on('error', fail);
    const notify = (method, params) => child.stdin.write(JSON.stringify({ jsonrpc: '2.0', method, ...(params ? { params } : {}) }) + '\n');
    const request = (method, params, signal) => new Promise((resolve, reject) => {
      const id = ++sequence, timer = setTimeout(() => { pending.delete(id); reject(new Error('MCP_REQUEST_TIMEOUT')); }, 85_000);
      const cancel = () => notify('notifications/cancelled', { requestId: id, reason: 'native Pi cancellation' });
      signal?.addEventListener('abort', cancel, { once: true });
      pending.set(id, { timer, resolve: value => { signal?.removeEventListener('abort', cancel); resolve(value); }, reject: error => { signal?.removeEventListener('abort', cancel); reject(error); } });
      child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n');
    });
    await request('initialize', { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'ud-local-eval-pi-mcp-transport', version: '1' } });
    notify('notifications/initialized');
    let cursor;
    do {
      const listing = await request('tools/list', cursor ? { cursor } : {});
      for (const tool of listing.tools ?? []) pi.registerTool({ name: `mcp__${server}__${tool.name}`, label: tool.title ?? tool.name, description: tool.description ?? '', parameters: tool.inputSchema,
        async execute(_id, arguments_, signal) { const result = await request('tools/call', { name: tool.name, arguments: arguments_ }, signal); return { content: result.content, details: result }; } });
      cursor = listing.nextCursor;
    } while (cursor);
  }
  pi.on('session_shutdown', async () => { for (const child of children) { child.stdin.end(); child.kill('SIGTERM'); } });
}
