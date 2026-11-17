import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, readFile, realpath, rm, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { expect, it } from 'vitest';
import { captureOperationSnapshot } from '../../packages/workspace/src/input-broker.js';
import { verifySnapshotIntegrity } from '../../packages/workspace/src/snapshot.js';
const guard = path.resolve('target/debug/ud-agent-guard' + (process.platform === 'win32' ? '.exe' : ''));
const hash = (s: string) => createHash('sha256').update(s).digest('hex');

it('captures explicitly granted peer inputs and contexts without unrequested siblings', async () => {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'ud-operation-inputs-')));
  try {
    const bank = path.join(root, 'bank'), peers = path.join(root, 'peers'), context = path.join(root, 'context');
    await mkdir(bank); await mkdir(peers); await mkdir(path.join(context, 'rules'), { recursive: true });
    await writeFile(path.join(bank, 'a.conllu'), 'current bytes');
    await writeFile(path.join(peers, 'peer.tsv'), 'selected peer'); await writeFile(path.join(peers, 'private.txt'), 'must not transfer');
    const rules = Object.fromEntries(['data.json', 'deprels.json', 'edeprels.json', 'feats.json', 'tospace.json', 'udeprels.json', 'upos.json'].map(name => [name, hash('{}\n')]));
    for (const name of Object.keys(rules)) await writeFile(path.join(context, 'rules', name), '{}\n');
    await writeFile(path.join(context, 'context.json'), JSON.stringify({ rule_dir: 'rules', rules, context_sha256: hash(JSON.stringify(rules)) }));
    const result = await captureOperationSnapshot(guard, { working_tree_path: bank, source_annotation_paths: [path.join(peers, 'peer.tsv')], ud_context_path: path.join(context, 'context.json'), output_dir_path: '/never/read/output' }, [root]);
    try {
      expect(result.arguments.output_dir_path).toBe('/never/read/output');
      const selected = (result.arguments.source_annotation_paths as string[])[0]!;
      expect(selected).toMatch(/^\.ud-agent-inputs\//);
      expect(await readFile(path.join(result.snapshot.directory, selected), 'utf8')).toBe('selected peer');
      expect(result.snapshot.files.some(file => file.path.endsWith('private.txt'))).toBe(false);
      expect(result.snapshot.files.filter(file => file.path.endsWith('.json'))).toHaveLength(8);
      expect(result.sourceMap.some(file => file.original_path === path.join(peers, 'peer.tsv'))).toBe(true);
      expect(await verifySnapshotIntegrity(guard, result.snapshot)).toBe(result.snapshot.directory);
    } finally { await result.snapshot.cleanup(); }
    await expect(captureOperationSnapshot(guard, { working_tree_path: bank, plan_path: path.join(peers, 'peer.tsv') }, [bank])).rejects.toThrow('outside');
    await symlink(path.join(peers, 'peer.tsv'), path.join(peers, 'linked'));
    await expect(captureOperationSnapshot(guard, { working_tree_path: bank, plan_path: path.join(peers, 'linked') }, [root])).rejects.toThrow('ordinary');
  } finally { await rm(root, { recursive: true, force: true }); }
}, 30_000);

it('rejects a quoted-empty ud_context_path with the exact correction', async () => {
  const workspace = path.resolve(os.tmpdir(), 'ud-agent-quoted-context');
  for (const value of ['""', "''"]) {
    await expect(captureOperationSnapshot('unused-guard', { ud_context_path: value, working_tree_path: workspace, file_paths: ['a.conllu'] }, [workspace]))
      .rejects.toThrow('CONTEXT_INPUT_INVALID: ud_context_path is the two-character text "" (quote marks); send an empty string with no characters for the default context.');
  }
  await expect(captureOperationSnapshot('unused-guard', { ud_context_path: 7, working_tree_path: workspace }, [workspace])).rejects.toThrow('CONTEXT_INPUT_INVALID: ud_context_path must be a string');
});
