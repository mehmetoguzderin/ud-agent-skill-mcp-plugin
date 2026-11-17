import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { chmod, copyFile, mkdir, mkdtemp, readFile, realpath, rm, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { loadContracts } from '../../packages/coordinator/src/catalog.js';
import { setupEnvironment } from '../../packages/runtime-manager/src/environment.js';

const sha = (data: Buffer | string) => `sha256:${createHash('sha256').update(data).digest('hex')}`;

import type { Contract } from '../../packages/coordinator/src/catalog.js';
export type FrozenUserspaceFixture = { base: string; release: string; state: string; workspace: string; options: {sourceRoot:string;searchPath:string;userspaceStateRoot:string;allowedRoots:string[]}; domain: Contract[]; contract: Contract; args: Record<string,unknown>; bytes: Buffer; ready: Record<string,unknown> };
export async function withFrozenUserspacePack(test: (fixture: FrozenUserspaceFixture) => Promise<void>): Promise<void> {
    const temporary = await mkdtemp(path.join(os.tmpdir(), 'ud-userspace-public-'));
    try {
      const base = await realpath(temporary); const release = path.join(base, 'release'); const bin = path.join(base, 'bin');
      const guardPath = process.platform === 'win32' ? 'runtime/pack/guard.exe' : 'runtime/pack/guard';
      const guardBytes = await readFile(path.resolve(process.platform === 'win32' ? 'target/debug/ud-agent-guard.exe' : 'target/debug/ud-agent-guard'));
      const state = path.join(base, 'state'); const workspace = path.join(base, 'bank');
      for (const dir of ['runtime/pack/worker/ud_agent', 'runtime/pack/upstream/udtools', 'runtime/pack/upstream/udapi', 'runtime/pack/context/rules', 'runtime/pack/wheels']) await mkdir(path.join(release, dir), { recursive: true });
      await mkdir(bin); await mkdir(workspace);
      // The stdlib-only helper inherits the worker Job. Select the Windows
      // base interpreter directly so a venv redirector cannot introduce a nested Job.
      const sources = new Map<string, Buffer>([
        ['runtime/pack/worker/ud_agent/__init__.py', Buffer.from('')],
        ['runtime/pack/worker/ud_agent/worker.py', Buffer.from('')],
        ['runtime/pack/worker/ud_agent/contexts.py', await readFile(path.resolve('workers/ud/src/ud_agent/contexts.py'))],
        ['runtime/pack/worker/ud_agent/evidence.py', await readFile(path.resolve('workers/ud/src/ud_agent/evidence.py'))],
        ['runtime/pack/worker/ud_agent/errors.py', await readFile(path.resolve('workers/ud/src/ud_agent/errors.py'))],
        ['runtime/pack/worker/ud_agent/snapshot_receiver.py', await readFile(path.resolve('workers/ud/src/ud_agent/snapshot_receiver.py'))],
        ['runtime/pack/worker/ud_agent/unicode_paths.py', await readFile(path.resolve('workers/ud/src/ud_agent/unicode_paths.py'))],
        ['runtime/pack/worker/ud_agent/unicode_casefold.json', await readFile(path.resolve('workers/ud/src/ud_agent/unicode_casefold.json'))],
        ['runtime/pack/worker/ud_agent/userspace_operations.json', await readFile(path.resolve('workers/ud/src/ud_agent/userspace_operations.json'))],
        ['runtime/pack/worker/ud_agent/wire.py', Buffer.from(`import json, pathlib, subprocess, sys\nMAX_REQUEST_BYTES=16*1024*1024\ndef encode(value): return (json.dumps(value)+'\\n').encode()\ndef process(request):\n a=request['arguments']; data=pathlib.Path(a['working_tree_path'],a['file_paths'][0]).read_bytes()\n child=subprocess.Popen([sys._base_executable if sys.platform=='win32' else sys.executable,'-c','import time;time.sleep(300)'])\n return {'ok':True,'result':{'passed':False,'incidents':[{'message':'fixture invalid'}], 'scope':{'file_paths':a['file_paths']},'coverage':{'content':'completed'},'bytes':data.hex(),'worker_child':child.pid}}\n`)],
        ['runtime/pack/upstream/source.py', Buffer.from('UPSTREAM = True\n')],
        ['runtime/pack/upstream/udtools/__init__.py', Buffer.from('')],
        ['runtime/pack/upstream/udapi/__init__.py', Buffer.from('')],
        ['runtime/pack/upstream/regex.py', Buffer.from('')],
        ['runtime/pack/bootstrap.py', await readFile(path.resolve('workers/ud/src/ud_agent/userspace_bootstrap.py'))],
        [guardPath, guardBytes],
        ['runtime/pack/requirements.txt', Buffer.from('')],
      ]);
      const rules = Object.fromEntries(['data.json', 'deprels.json', 'edeprels.json', 'feats.json', 'tospace.json', 'udeprels.json', 'upos.json'].map(name => {
        const content = Buffer.from('{}'); sources.set(`runtime/pack/context/rules/${name}`, content); return [name, sha(content).slice(7)];
      }));
      sources.set('runtime/pack/context/context.json', Buffer.from(JSON.stringify({ rule_dir: 'rules', rules, context_sha256: sha(JSON.stringify(rules)).slice(7) })));
      const files = [];
      for (const [name, data] of sources) { await writeFile(path.join(release, name), data); files.push({ path: name, sha256: sha(data), size: data.length }); }
      await chmod(path.join(release, guardPath), 0o700);
      const manifest = JSON.stringify({ schema_version: 1, product_version: '0.1.0-beta.1', state: 'frozen', platforms: {
        [`${process.platform}/${process.arch}`]: { worker: 'runtime/pack/worker', upstream: 'runtime/pack/upstream', context: 'runtime/pack/context/context.json', bootstrap: 'runtime/pack/bootstrap.py', guard: guardPath, requirements: 'runtime/pack/requirements.txt', wheels: 'runtime/pack/wheels', packs: ['core'], files },
      } }) + '\n';
      await writeFile(path.join(release, 'runtime/userspace.lock.json'), manifest);
      await writeFile(path.join(release, 'runtime/runtime.lock.json'), JSON.stringify({ schema_version: 1, product_version: '0.1.0-beta.1', state: 'frozen', userspace_sha256: sha(manifest), native_helpers: { [`${process.platform}/${process.arch}`]: { guard: { path: guardPath, sha256: sha(guardBytes), size_bytes: guardBytes.length } } } }));
      const interpreter = spawnSync(process.env.UD_AGENT_PYTHON ?? (process.platform === 'win32' ? 'python' : 'python3'), ['-c', 'import sys; print(sys.executable)'], { encoding: 'utf8' });
      if (interpreter.status !== 0) throw new Error('A supported Python is required.');
      const actualPython = await realpath(interpreter.stdout.trim());
      if (process.platform === 'win32') {
        const shim = path.join(base, 'python-shim.rs');
        await writeFile(shim, `use std::{env,process::{self,Command}}; fn main(){let result=Command::new(r###"${actualPython}"###).args(env::args_os().skip(1)).status().unwrap();process::exit(result.code().unwrap_or(1));}\n`);
        const built = spawnSync('rustc', [shim, '-o', path.join(bin, 'python3.exe')], { encoding: 'utf8' });
        if (built.status !== 0) throw new Error(`Could not create isolated Python fixture: ${built.stderr}`);
      } else await symlink(actualPython, path.join(bin, 'python3'));
      const bytes = Buffer.from('# sent_id = a\r\n1\tÄ\t_\tX\t_\t_\t0\troot\t_\t_\r\n');
      await writeFile(path.join(workspace, 'sample.conllu'), bytes);
      const { domain } = loadContracts(path.resolve('.'));
      const contract = domain.find(item => item.name === 'validation_report'); if (!contract) throw new Error('Missing validation contract.');
      const options = { sourceRoot: release, searchPath: bin, userspaceStateRoot: state, allowedRoots: [workspace] };
      const ready = await setupEnvironment({ working_tree_path: workspace, required_tools: ['validation_report'] }, domain, options);
      const args = { working_tree_path: workspace, file_paths: ['sample.conllu'], ud_context_path: '', options: { language_code: 'en' } };
      await test({ base, release, state, workspace, options, domain, contract, args, bytes, ready });
    } finally { await rm(temporary, { recursive: true, force: true }); }
}
