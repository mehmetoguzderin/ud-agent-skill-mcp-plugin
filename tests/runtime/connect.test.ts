import { mkdir, mkdtemp, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { expect, it, vi } from 'vitest';
import { connectHost } from '../../packages/coordinator/src/connect.js';
import { GuardedWorkspace, TransactionBroker } from '../../packages/workspace/src/transactions.js';

const guard = path.resolve(process.platform === 'win32' ? 'target/debug/ud-agent-guard.exe' : 'target/debug/ud-agent-guard');
const fixtureTimeout = process.platform === 'win32' ? 90_000 : 30_000;
it.each([
  ['codex', '.codex/config.toml', '# Existing host comment\n[mcp_servers.other]\ncommand = "other"\n'],
  ['codex-global', '.codex/config.toml', '# Existing host comment\n[mcp_servers.other]\ncommand = "other"\n'],
  ['chatgpt-desktop', '.codex/config.toml', '# Existing host comment\n[mcp_servers.other]\ncommand = "other"\n'],
  ['vscode', '.vscode/mcp.json', '{\n // Existing host comment\n "servers": { "other": {"command":"other"} }\n}\n'],
  ['vscode-copilot', '.vscode/mcp.json', '{\n // Existing host comment\n "servers": { "other": {"command":"other"} }\n}\n'],
  ['hermes', '.hermes/config.yaml', '# Existing host comment\nmcp_servers:\n  other:\n    command: other\n'],
  ['claude-code', '.mcp.json', '{\n // Existing host comment\n "mcpServers": { "other": {"command":"other"} }\n}\n'],
  ['grok', '.grok/config.toml', '# Existing host comment\n[mcp_servers.other]\ncommand = "other"\n'],
  ['kimi', '.kimi-code/mcp.json', '{\n // Existing host comment\n "mcpServers": { "other": {"command":"other"} }\n}\n'],
  ['qwen', '.qwen/settings.json', '{\n // Existing host comment\n "mcpServers": { "other": {"command":"other"} }\n}\n'],
  ['pi', '.pi/mcp.json', '{\n // Existing host comment\n "mcpServers": { "other": {"command":"other"} }\n}\n'],
  ['gemini', '.gemini/settings.json', '{\n // Existing host comment\n "mcpServers": { "other": {"command":"other"} }\n}\n'],
  ['cursor', '.cursor/mcp.json', '{\n // Existing host comment\n "mcpServers": { "other": {"command":"other"} }\n}\n'],
  ['copilot', '.mcp.json', '{\n // Existing host comment\n "mcpServers": { "other": {"command":"other"} }\n}\n'],
  ['deepseek', '.dsh/profiles/web/cordis.patch.yml', '# Existing host comment\n- insert:\n    - id: other\n      name: other\n'],
  ['openclaw', '.openclaw/openclaw.json', '{\n // Existing host comment\n "mcp": { "servers": { "other": {"command":"other"} } }\n}\n'],
  ['mini-swe-agent', '.ud-agent/mini-swe-agent.json', '{\n // Existing host comment\n "coordinators": { "other": {"command":"other"} }\n}\n'],
] as const)('connects and removes %s with workspace grants, idempotent skills and existing settings preserved', async (host, file, existing) => {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'ud-connect-')));
  try {
    const install = path.join(root, 'install'), workspace = path.join(root, 'workspace'), home = path.join(root, 'home');
    await mkdir(workspace); await mkdir(home); await writeFile(path.join(workspace, 'a.conllu'), '');
    for (const name of ['ud-validate', 'ud-edit', 'ud-investigate', 'ud-compare', 'ud-rules-docs', 'ud-release']) { await mkdir(path.join(install, 'skills', name), { recursive: true }); await writeFile(path.join(install, 'skills', name, 'SKILL.md'), `# ${name}\n`); }
    const base = ['hermes', 'deepseek', 'openclaw', 'codex-global', 'chatgpt-desktop'].includes(host) ? home : workspace, target = path.join(base, file);
    await mkdir(path.dirname(target), { recursive: true }); await writeFile(target, existing);
    const options = { sourceRoot: install, cwd: workspace, home, stateRoot: path.join(root, 'state'), guard, launch: { command: '/verified/ud-agent', args: ['mcp', '--allow-root', workspace] } };
    expect(await connectHost(host, { ...options, dryRun: true })).toMatchObject({ status: 'preview' });
    expect(await readFile(target, 'utf8')).toBe(existing);
    expect(await connectHost(host, options)).toMatchObject({ status: 'connected', skills: expect.arrayContaining(['ud-validate']) });
    const content = await readFile(target, 'utf8'); expect(content).toContain('Existing host comment'); expect(content).toContain('other'); expect(content).toContain('--allow-root');
    expect(await connectHost(host, { ...options, check: true })).toMatchObject({ status: 'connected', changed: [] });
    expect(await connectHost(host, options)).toMatchObject({ status: 'connected', changed: [] });
    expect(await connectHost(host, { ...options, remove: true })).toMatchObject({ status: 'disconnected' });
    expect(await readFile(target, 'utf8')).toContain('other');
    expect(await readFile(target, 'utf8')).not.toContain('/verified/ud-agent');
  } finally { await rm(root, { recursive: true, force: true }); }
}, fixtureTimeout);

it('leaves modified or unrelated host registration intact and gives native-UI hosts an explicit next step', async () => {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'ud-connect-conflict-')));
  try {
    await mkdir(path.join(root, '.cursor')); await writeFile(path.join(root, 'a.conllu'), '');
    const target = path.join(root, '.cursor/mcp.json'), original = '{"mcpServers":{"ud":{"command":"unrelated-server"}}}'; await writeFile(target, original);
    await expect(connectHost('cursor', { sourceRoot: root, cwd: root, home: '/unused-home', guard, stateRoot: path.join(root, 'state'), noSkills: true, launch: { command: '/verified/ud-agent', args: ['mcp'] } })).rejects.toThrow('belongs to another installation');
    expect(await readFile(target, 'utf8')).toBe(original);
    expect(await connectHost('cowork', { sourceRoot: root })).toMatchObject({ status: 'host_managed_install', changed: [] });
    await expect(connectHost('unknown', { sourceRoot: root })).rejects.toThrow('Unknown host');
  } finally { await rm(root, { recursive: true, force: true }); }
}, fixtureTimeout);

it.each(['darwin','win32','linux'] as const)('uses the documented %s Claude Desktop path in a portable private configuration fixture', async platform => {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'ud-connect-desktop-')));
  try {
    const install = path.join(root,'install'), home = path.join(root,'home'), workspace = path.join(root,'workspace');
    const appData = path.join(root,'roaming-profile'), xdgConfigHome = path.join(root,'xdg-config');
    for (const directory of [home,workspace,appData,xdgConfigHome]) await mkdir(directory);
    await writeFile(path.join(workspace,'one.conllu'),'');
    for (const name of ['ud-validate','ud-edit','ud-investigate','ud-compare','ud-rules-docs','ud-release']) { await mkdir(path.join(install,'skills',name),{recursive:true}); await writeFile(path.join(install,'skills',name,'SKILL.md'),`# ${name}\n`); }
    const base = platform === 'darwin' ? home : platform === 'win32' ? appData : xdgConfigHome;
    const file = platform === 'darwin' ? 'Library/Application Support/Claude/claude_desktop_config.json' : 'Claude/claude_desktop_config.json';
    const target = path.join(base,file), original = '{\n // preserve this comment\n "mcpServers":{"other":{"command":"other"}}\n}\n';
    await mkdir(path.dirname(target),{recursive:true}); await writeFile(target,original);
    const options = { sourceRoot:install,cwd:workspace,home,platform,appData,xdgConfigHome,stateRoot:path.join(root,'state'),guard,launch:{command:'/verified/ud-agent',args:['mcp','--allow-root',workspace]} };
    expect(await connectHost('claude-desktop',{...options,dryRun:true})).toMatchObject({status:'preview',configuration:target});
    expect(await readFile(target,'utf8')).toBe(original);
    const result = await connectHost('claude-desktop',options);
    expect(result).toMatchObject({status:'connected',configuration:target,skills:['ud-validate','ud-edit','ud-investigate','ud-compare','ud-rules-docs','ud-release'],skill_activation:{mode:'manual_upload'}});
    const actual = await readFile(target,'utf8'); expect(actual).toContain('preserve this comment'); expect(actual).toContain('"other"'); expect(actual).toContain('--allow-root');
    expect(await connectHost('claude-desktop',{...options,check:true})).toMatchObject({status:'connected',changed:[]});
    expect(await connectHost('claude-desktop',options)).toMatchObject({status:'connected',changed:[]});
    // Older version1 receipts did not record their base directory. They remain
    // readable while newly written receipts bind redirected configuration roots.
    const receipts = await import('node:fs/promises');
    for (const name of await receipts.readdir(options.stateRoot)) if (/^[a-f0-9]{64}\.json$/.test(name)) {
      const selected = path.join(options.stateRoot,name), value = JSON.parse(await readFile(selected,'utf8'));
      if (value.host === 'claude-desktop') { delete value.base; await writeFile(selected,JSON.stringify(value)); }
    }
    expect(await connectHost('claude-desktop',{...options,check:true})).toMatchObject({status:'connected'});
    expect(await connectHost('claude-desktop',{...options,remove:true})).toMatchObject({status:'disconnected',skills:[]});
    expect(await readFile(target,'utf8')).toContain('"other"'); expect(await readFile(target,'utf8')).not.toContain('/verified/ud-agent');
  } finally { await rm(root,{recursive:true,force:true}); }
}, fixtureTimeout);

it.each(['first-write', 'completed-response'] as const)('recovers a connection interrupted after %s before recalculating its configuration', async phase => {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'ud-connect-recovery-')));
  try {
    const install = path.join(root, 'install'), workspace = path.join(root, 'workspace');
    await mkdir(workspace); await writeFile(path.join(workspace, 'a.conllu'), '');
    for (const skill of ['ud-validate', 'ud-edit', 'ud-investigate', 'ud-compare', 'ud-rules-docs', 'ud-release']) { await mkdir(path.join(install, 'skills', skill), { recursive: true }); await writeFile(path.join(install, 'skills', skill, 'SKILL.md'), `# ${skill}\n`); }
    const options = { sourceRoot: install, cwd: workspace, home: '/unused-home', stateRoot: path.join(root, 'state'), guard, launch: { command: '/verified/ud-agent', args: ['mcp', '--allow-root', workspace] } };
    if (phase === 'first-write') {
      const original = GuardedWorkspace.prototype.create;
      vi.spyOn(GuardedWorkspace.prototype, 'create').mockImplementationOnce(async function(...args) { await original.apply(this, args); throw new Error('fixture response lost after creation'); });
    } else {
      const original = TransactionBroker.prototype.apply;
      vi.spyOn(TransactionBroker.prototype, 'apply').mockImplementationOnce(async function(...args) { await original.apply(this, args); throw new Error('fixture response lost after completion'); });
    }
    await expect(connectHost('vscode', options)).rejects.toThrow('response lost'); vi.restoreAllMocks();
    expect(await connectHost('vscode', { ...options, check: true })).toMatchObject({ status: 'recovery_required', changed: [] });
    expect(await connectHost('vscode', options)).toMatchObject({ status: 'connected', skills: expect.arrayContaining(['ud-validate']) });
    expect(await readFile(path.join(workspace, '.vscode/mcp.json'), 'utf8')).toContain('/verified/ud-agent');
    expect(await readFile(path.join(workspace, '.github/skills/ud-edit/SKILL.md'), 'utf8')).toBe('# ud-edit\n');
    expect(await connectHost('vscode', options)).toMatchObject({ status: 'connected', changed: [] });
    expect(await connectHost('vscode', { ...options, remove: true })).toMatchObject({ status: 'disconnected' });
  } finally { vi.restoreAllMocks(); await rm(root, { recursive: true, force: true }); }
}, fixtureTimeout);

it('shares the ChatGPT user registration with codex-global while retaining the Codex project route', async () => {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(),'ud-connect-shared-')));
  try {
    const home=path.join(root,'home'),workspace=path.join(root,'workspace'); await mkdir(home); await mkdir(workspace); await writeFile(path.join(workspace,'a.conllu'),'');
    const options={sourceRoot:root,cwd:workspace,home,guard,stateRoot:path.join(root,'state'),noSkills:true,launch:{command:'/verified/ud-agent',args:['mcp','--allow-root',workspace]}};
    const shared=await connectHost('chatgpt-desktop',options); expect(shared).toMatchObject({host:'codex-global',configuration:path.join(home,'.codex/config.toml'),status:'connected'});
    expect(await connectHost('codex-global',options)).toMatchObject({status:'connected',changed:[]});
    const current=await readFile(path.join(home,'.codex/config.toml'),'utf8');
    expect(await connectHost('codex',options)).toMatchObject({status:'connected',configuration:path.join(workspace,'.codex/config.toml')});
    expect(await readFile(path.join(home,'.codex/config.toml'),'utf8')).toBe(current);
    await connectHost('codex-global',{...options,remove:true});
    expect(await readFile(path.join(workspace,'.codex/config.toml'),'utf8')).toContain('/verified/ud-agent');
  } finally { await rm(root,{recursive:true,force:true}); }
},fixtureTimeout);

it('binds redirected Desktop configuration ownership and never claims skipped skills were staged', async () => {
  const root=await realpath(await mkdtemp(path.join(os.tmpdir(),'ud-connect-redirected-')));
  try {
    const home=path.join(root,'home'),workspace=path.join(root,'workspace'),first=path.join(root,'first-appdata'),second=path.join(root,'second-appdata');
    for(const directory of [home,workspace,first,second])await mkdir(directory);await writeFile(path.join(workspace,'a.conllu'),'');
    const options={sourceRoot:root,cwd:workspace,home,guard,stateRoot:path.join(root,'state'),noSkills:true,platform:'win32' as const,appData:first,launch:{command:'/verified/ud-agent',args:['mcp','--allow-root',workspace]}};
    const result=await connectHost('claude-desktop',options);expect(result).toMatchObject({status:'connected',skills:[]});expect(result).not.toHaveProperty('skill_activation');
    const file=path.join(first,'Claude/claude_desktop_config.json'),before=await readFile(file);
    await expect(connectHost('claude-desktop',{...options,appData:second})).rejects.toThrow('profile location changed');
    expect(await readFile(file)).toEqual(before);await expect(readFile(path.join(second,'Claude/claude_desktop_config.json'))).rejects.toMatchObject({code:'ENOENT'});
    await connectHost('claude-desktop',{...options,remove:true});
  } finally { await rm(root,{recursive:true,force:true}); }
},fixtureTimeout);

it('previews and removes only receipt-owned unchanged skills after their distribution files are gone', async () => {
  const root=await realpath(await mkdtemp(path.join(os.tmpdir(),'ud-connect-old-skills-')));
  try {
    const install=path.join(root,'install'),workspace=path.join(root,'workspace');await mkdir(workspace);await writeFile(path.join(workspace,'a.conllu'),'');
    const names=['ud-validate','ud-edit','ud-investigate','ud-compare','ud-rules-docs','ud-release'];
    for(const name of names){await mkdir(path.join(install,'skills',name),{recursive:true});await writeFile(path.join(install,'skills',name,'SKILL.md'),`# ${name}\n`);}
    await mkdir(path.join(install,'skills/ud-validate/resources'));await writeFile(path.join(install,'skills/ud-validate/resources/old.json'),'old owned resource');
    const options={sourceRoot:install,cwd:workspace,home:'/unused-home',guard,stateRoot:path.join(root,'state'),launch:{command:'/verified/ud-agent',args:['mcp','--allow-root',workspace]}};
    await connectHost('cursor',options);
    const modified=path.join(workspace,'.cursor/skills/ud-edit/SKILL.md'),unrelated=path.join(workspace,'.cursor/skills/ud-validate/user.txt');
    await writeFile(modified,'User edited this skill.');await writeFile(unrelated,'User file, never owned.');await rm(path.join(install,'skills'),{recursive:true});
    const configuration=path.join(workspace,'.cursor/mcp.json'),before=await readFile(configuration);
    const preview=await connectHost('cursor',{...options,remove:true,dryRun:true});
    expect(preview).toMatchObject({status:'preview'});expect(preview.changed).toContain('.cursor/skills/ud-validate/resources/old.json');expect(preview.changed).not.toContain('.cursor/skills/ud-edit/SKILL.md');
    expect(await readFile(configuration)).toEqual(before);expect(await readFile(path.join(workspace,'.cursor/skills/ud-validate/resources/old.json'),'utf8')).toBe('old owned resource');
    const receiptName=createHash('sha256').update(`cursor\0${workspace}`).digest('hex')+'.json',receiptFile=path.join(options.stateRoot,receiptName),receipt=JSON.parse(await readFile(receiptFile,'utf8'));
    const foreign=path.join(workspace,'foreign.txt');await writeFile(foreign,'foreign bytes');
    receipt.skills.push({path:'foreign.txt',sha256:createHash('sha256').update('foreign bytes').digest('hex')});await writeFile(receiptFile,JSON.stringify(receipt));
    await expect(connectHost('cursor',{...options,remove:true})).rejects.toThrow('out-of-scope');expect(await readFile(configuration)).toEqual(before);expect(await readFile(foreign,'utf8')).toBe('foreign bytes');
    receipt.skills.pop();await writeFile(receiptFile,JSON.stringify(receipt));
    expect(await connectHost('cursor',{...options,remove:true})).toMatchObject({status:'disconnected'});
    await expect(readFile(path.join(workspace,'.cursor/skills/ud-validate/resources/old.json'))).rejects.toMatchObject({code:'ENOENT'});
    expect(await readFile(modified,'utf8')).toBe('User edited this skill.');expect(await readFile(unrelated,'utf8')).toBe('User file, never owned.');
  }finally{await rm(root,{recursive:true,force:true});}
},fixtureTimeout);
