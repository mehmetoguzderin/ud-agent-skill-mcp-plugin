import { mkdir, mkdtemp, realpath, rm, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { expect, it } from 'vitest';
import { discoverWorkspace } from '../../packages/workspace/src/discovery.js';
import { hostRoots, RootChallenges } from '../../packages/coordinator/src/host-grants.js';

it('discovers only bounded launch workspaces and validates host-selected roots with one-use request-bound challenges', async () => {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'ud-discovery-')));
  try {
    const home = path.join(root, 'home'), workspace = path.join(root, 'bank'); await mkdir(home); await mkdir(workspace);
    expect(await discoverWorkspace(home, home)).toBeUndefined();
    expect(await discoverWorkspace(workspace, home)).toBeUndefined();
    await writeFile(path.join(workspace, 'bank.conllu'), '');
    expect(await discoverWorkspace(workspace, home)).toBe(workspace);
    const linked = path.join(root, 'linked'); await symlink(workspace, linked);
    expect(await discoverWorkspace(linked, home)).toBeUndefined();
    const roots = [{ uri: pathToFileURL(workspace).href, name: 'Host-selected workspace' }];
    expect(await hostRoots(roots)).toEqual([workspace]);
    await expect(hostRoots([{ uri: 'https://example.com/private' }])).rejects.toThrow('HOST_ROOTS_INVALID');
    const challenges = new RootChallenges(), args = { working_tree_path: workspace };
    const token = challenges.issue('validation_report', args);
    await expect(challenges.accept(token, 'token_edit', args, roots)).rejects.toThrow('HOST_ROOT_CHALLENGE_INVALID');
    expect(await challenges.accept(token, 'validation_report', args, roots)).toEqual([workspace]);
    await expect(challenges.accept(token, 'validation_report', args, roots)).rejects.toThrow('HOST_ROOT_CHALLENGE_INVALID');
  } finally { await rm(root, { recursive: true, force: true }); }
});
