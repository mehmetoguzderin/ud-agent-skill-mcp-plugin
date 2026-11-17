import { describe, expect, it, vi } from 'vitest';
import { mkdir, mkdtemp, realpath, rm, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { absoluteFileArguments, absolutePathReason, outsideRootsReason, authorizeWorkspace, parseGrantedRoots, workspaceArgumentReason, workspaceFileArguments, quotedEmptyContextArguments, relativeWorkspaceArguments } from '../../packages/workspace/src/authorization.js';

describe('workspace grants', () => {
  it('makes absolute file arguments relative to the workspace, including a missed folder level', async () => {
    const base = await realpath(await mkdtemp(path.join(os.tmpdir(), 'ud-abs-'))), root = path.join(base, 'treebank');
    try {
      await mkdir(root); await writeFile(path.join(root, 'gold.conllu'), 'x'); await writeFile(path.join(base, 'outside.conllu'), 'y');
      const result = await absoluteFileArguments({ working_tree_path: root, gold_file_paths: [path.join(base, 'gold.conllu')], prediction_file_paths: [path.join(root, 'gold.conllu')], other_path: path.join(base, 'outside.conllu'), ud_context_path: path.join(base, 'gold.conllu') });
      expect(result?.args.gold_file_paths).toEqual(['gold.conllu']);
      expect(result?.args.prediction_file_paths).toEqual(['gold.conllu']);
      expect(result?.args.other_path).toBe(path.join(base, 'outside.conllu'));
      expect(result?.args.ud_context_path).toBe(path.join(base, 'gold.conllu'));
      expect(await absoluteFileArguments({ working_tree_path: root, file_paths: ['gold.conllu'] })).toBeUndefined();
    } finally { await rm(base, { recursive: true, force: true }); }
  });
  it('reads quote characters with surrounding whitespace, or whitespace alone, as the empty context', () => {
    expect(quotedEmptyContextArguments({ ud_context_path: ' ""' })?.args.ud_context_path).toBe('');
    expect(quotedEmptyContextArguments({ ud_context_path: '  ' })?.args.ud_context_path).toBe('');
    expect(quotedEmptyContextArguments({ ud_context_path: '' })).toBeUndefined();
    expect(quotedEmptyContextArguments({ ud_context_path: 'ctx/context.json' })).toBeUndefined();
  });
  it('after a file working_tree_path becomes its folder, that folder as ud_context_path reads as the default context', async () => {
    const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'ud-requote-')));
    try {
      await writeFile(path.join(root, 'guidelines.md'), '# x\n');
      const args = { working_tree_path: path.join(root, 'guidelines.md'), example_markup_path: 'guidelines.md', output_dir_path: 'preview', ud_context_path: root };
      expect(quotedEmptyContextArguments(args)).toBeUndefined();
      const located = await workspaceFileArguments(args, [root]);
      expect(located?.args.working_tree_path).toBe(root);
      expect(quotedEmptyContextArguments(located!.args)?.args.ud_context_path).toBe('');
    } finally { await rm(root, { recursive: true, force: true }); }
  });
  it('names the rejected path and the single grant when a path is outside every root', async () => {
    const grant = path.resolve('/tmp/w/treebank');
    expect(outsideRootsReason('/', [grant])).toBe(`Workspace is outside the configured authorized roots: "/" is not inside "${grant}". Use working_tree_path "${grant}" and give the other paths relative to it (inside that folder); a placeholder such as "/" is not a path.`);
    expect(outsideRootsReason('/', ['/a', '/b'])).toBe('Workspace is outside the configured authorized roots.');
    const base = await realpath(await mkdtemp(path.join(os.tmpdir(), 'ud-outside-'))), root = path.join(base, 'treebank'), other = path.join(base, 'other');
    try {
      await mkdir(root); await mkdir(other);
      await expect(authorizeWorkspace(other, [root])).rejects.toThrow(`"${other}" is not inside "${root}"`);
    } finally { await rm(base, { recursive: true, force: true }); }
  });

  it('requires a trusted grant, rejects siblings and does not accept a symlink root', async () => {
    const temporary = await realpath(await mkdtemp(path.join(os.tmpdir(), 'ud-agent-grants-')));
    try {
      const root = path.join(temporary, 'project');
      const child = path.join(root, 'bank');
      const sibling = path.join(temporary, 'project-sibling');
      const link = path.join(root, 'link');
      const regularFile = path.join(root, 'document');
      await mkdir(child, { recursive: true });
      await mkdir(sibling);
      await writeFile(regularFile, 'not a directory');
      await symlink(sibling, link, 'dir');
      expect(await authorizeWorkspace(child, [root])).toBe(await realpath(child));
      expect(await authorizeWorkspace(root, [root])).toBe(await realpath(root));
      await expect(authorizeWorkspace(child, [])).rejects.toThrow('authorized roots');
      await expect(authorizeWorkspace(child, [])).rejects.toMatchObject({ code: 'WORKSPACE_NOT_AUTHORIZED' });
      await expect(authorizeWorkspace(sibling, [root])).rejects.toThrow('authorized roots');
      await expect(authorizeWorkspace(root, [child])).rejects.toThrow('authorized roots');
      await expect(authorizeWorkspace(link, [root])).rejects.toThrow('symbolic link');
      await expect(authorizeWorkspace('relative', [root])).rejects.toThrow('absolute');
      await expect(authorizeWorkspace(regularFile, [root])).rejects.toThrow('not a directory');
      await expect(authorizeWorkspace(child, [path.relative(process.cwd(), root)])).rejects.toThrow('authorized roots');
      await expect(authorizeWorkspace(child, [`${root}\0`])).rejects.toMatchObject({ code: 'WORKSPACE_NOT_AUTHORIZED' });
      expect(await authorizeWorkspace(child, [path.join(temporary, 'missing-root'), root])).toBe(await realpath(child));
      const loop = path.join(temporary, 'loop');
      await symlink(loop, loop);
      await expect(authorizeWorkspace(child, [loop])).rejects.toMatchObject({ code: 'ELOOP' });
    } finally { await rm(temporary, { recursive: true, force: true }); }
  });

  it('names the single granted workspace when a relative path is rejected', async () => {
    const root = path.resolve(os.tmpdir(), 'ud-agent-hint-root');
    await expect(authorizeWorkspace('treebank', [root])).rejects.toThrow(`retry with working_tree_path "${root}"`);
    expect(absolutePathReason([root, path.resolve(os.tmpdir(), 'other')])).toBe('Workspace must be an absolute host path.');
    expect(absolutePathReason([])).toBe('Workspace must be an absolute host path.');
    expect(absolutePathReason(['relative', `${root}\0`])).toBe('Workspace must be an absolute host path.');
  });

  it('reads a granted file given as working_tree_path as its folder plus that file, and nothing else', async () => {
    const temporary = await realpath(await mkdtemp(path.join(os.tmpdir(), 'ud-agent-grants-')));
    try {
      const root = await realpath(temporary), outside = await mkdtemp(path.join(os.tmpdir(), 'ud-agent-outside-'));
      await mkdir(path.join(root, 'sub'));
      await writeFile(path.join(root, 'a.conllu'), '# sent_id = 1\n'); await writeFile(path.join(root, 'sub', 'c.conllu'), '# sent_id = 2\n'); await writeFile(path.join(outside, 'x.conllu'), '# sent_id = 3\n');
      await symlink(path.join(root, 'a.conllu'), path.join(root, 'link.conllu'));
      const base = { ud_context_path: '', options: { language_code: 'en' } };
      for (const file_paths of [[], ['a.conllu'], ['./a.conllu']]) {
        const corrected = await workspaceFileArguments({ ...base, working_tree_path: path.join(root, 'a.conllu'), file_paths }, [root]);
        expect(corrected?.args).toEqual({ ...base, working_tree_path: root, file_paths: ['a.conllu'] });
        expect(corrected?.note).toBe(`working_tree_path named a file; used its folder "${root}" as working_tree_path with file_paths ["a.conllu"].`);
      }
      expect((await workspaceFileArguments({ working_tree_path: path.join(root, 'sub', 'c.conllu'), file_paths: [] }, [root]))?.args).toEqual({ working_tree_path: path.join(root, 'sub'), file_paths: ['c.conllu'] });
      // Ambiguous, unsafe or already-correct inputs are left for the normal checks and their rejections.
      expect(await workspaceFileArguments({ working_tree_path: path.join(root, 'a.conllu'), file_paths: ['a.conllu', 'b.conllu'] }, [root])).toBeUndefined();
      expect(await workspaceFileArguments({ working_tree_path: path.join(root, 'a.conllu'), file_paths: ['../a.conllu'] }, [root])).toBeUndefined();
      expect(await workspaceFileArguments({ working_tree_path: path.join(root, 'a.conllu') }, [root])).toBeUndefined();
      expect(await workspaceFileArguments({ working_tree_path: root, file_paths: [] }, [root])).toBeUndefined();
      expect(await workspaceFileArguments({ working_tree_path: path.join(root, 'link.conllu'), file_paths: [] }, [root])).toBeUndefined();
      expect(await workspaceFileArguments({ working_tree_path: path.join(outside, 'x.conllu'), file_paths: [] }, [root])).toBeUndefined();
      expect(await workspaceFileArguments({ working_tree_path: 'a.conllu', file_paths: [] }, [root])).toBeUndefined();
      expect(await workspaceFileArguments({ working_tree_path: path.join(root, 'missing.conllu'), file_paths: [] }, [root])).toBeUndefined();
      expect(await workspaceFileArguments({ working_tree_path: path.join(root, 'a.conllu'), file_paths: [] }, [])).toBeUndefined();
      // Without file_paths, references naming the same file keep the scope exact; other or missing references do not.
      const ref = { tree_ref: { file_path: 'a.conllu', sent_id: 's1' } };
      const located = await workspaceFileArguments({ working_tree_path: path.join(root, 'a.conllu'), token_ref: { ...ref, token_id: 1 } }, [root]);
      expect(located?.args).toEqual({ working_tree_path: root, token_ref: { ...ref, token_id: 1 } });
      expect(located?.note).toBe(`working_tree_path named a file; used its folder "${root}" as working_tree_path (the references name "a.conllu").`);
      expect((await workspaceFileArguments({ working_tree_path: path.join(root, 'a.conllu'), ...ref }, [root]))?.args).toEqual({ working_tree_path: root, ...ref });
      expect(await workspaceFileArguments({ working_tree_path: path.join(root, 'a.conllu'), tree_ref: { file_path: 'b.conllu', sent_id: 's1' } }, [root])).toBeUndefined();
      expect(await workspaceFileArguments({ working_tree_path: path.join(root, 'a.conllu'), tree_ref: { sent_id: 's1' } }, [root])).toBeUndefined();
      expect(await workspaceFileArguments({ working_tree_path: path.join(root, 'a.conllu'), ...ref }, [])).toBeUndefined();
      await rm(outside, { recursive: true, force: true });
    } finally { await rm(temporary, { recursive: true, force: true }); }
  });

  it('resolves a relative working_tree_path inside the single grant and never outside it', async () => {
    const temporary = await realpath(await mkdtemp(path.join(os.tmpdir(), 'ud-agent-grants-')));
    try {
      const root = path.join(temporary, 'bank'); await mkdir(path.join(root, 'sub'), { recursive: true });
      await writeFile(path.join(root, 'gold.conllu'), 'x'); await writeFile(path.join(root, 'pred.conllu'), 'y');
      for (const value of ['.', './', 'sub']) {
        const result = await relativeWorkspaceArguments({ working_tree_path: value }, [root]);
        expect(result?.args.working_tree_path).toBe(path.resolve(root, value));
        expect(result?.note).toBe(`working_tree_path "${value}" was relative; resolved it inside the granted workspace as "${path.resolve(root, value)}".`);
      }
      for (const value of ['..', '../bank-other', 'missing', '', '/abs']) expect(await relativeWorkspaceArguments({ working_tree_path: value }, [root])).toBeUndefined();
      expect(await relativeWorkspaceArguments({ working_tree_path: '.' }, [root, temporary])).toBeUndefined();
      expect(await relativeWorkspaceArguments({ working_tree_path: '.' }, [])).toBeUndefined();
      // A relative file then becomes its folder when the other path arguments are relative names inside it.
      const file = (await relativeWorkspaceArguments({ working_tree_path: 'pred.conllu' }, [root]))!.args;
      const located = await workspaceFileArguments({ ...file, gold_file_paths: ['gold.conllu'], prediction_file_paths: ['pred.conllu'] }, [root]);
      expect(located?.args).toEqual({ working_tree_path: root, gold_file_paths: ['gold.conllu'], prediction_file_paths: ['pred.conllu'] });
      expect(await workspaceFileArguments({ ...file, gold_file_paths: ['../gold.conllu'] }, [root])).toBeUndefined();
      expect(await workspaceFileArguments({ ...file, gold_file_paths: [path.join(root, 'gold.conllu')] }, [root])).toBeUndefined();
    } finally { await rm(temporary, { recursive: true, force: true }); }
  });

  it('reads placeholder words and a repeated workspace as the default context, and the grant name as the grant', async () => {
    for (const value of ['empty', 'None', '{}', '[]', 'default', '/', '.']) expect(quotedEmptyContextArguments({ ud_context_path: value })?.args.ud_context_path).toBe('');
    expect(quotedEmptyContextArguments({ working_tree_path: '/w/bank', ud_context_path: '/w/bank/' })?.note).toBe('ud_context_path repeated working_tree_path; used the installed default context (empty string).');
    expect(quotedEmptyContextArguments({ working_tree_path: '/w/bank', ud_context_path: '/w/ctx' })).toBeUndefined();
    const temporary = await realpath(await mkdtemp(path.join(os.tmpdir(), 'ud-agent-grants-')));
    try {
      const root = path.join(temporary, 'treebank'); await mkdir(root);
      expect((await relativeWorkspaceArguments({ working_tree_path: 'treebank' }, [root]))?.args.working_tree_path).toBe(root);
      expect((await relativeWorkspaceArguments({ working_tree_path: path.relative(path.parse(root).root, root) }, [root]))?.args.working_tree_path).toBe(root);
      expect(await relativeWorkspaceArguments({ working_tree_path: 'other' }, [root])).toBeUndefined();
    } finally { await rm(temporary, { recursive: true, force: true }); }
  });

  it('reads "./name" and an absent "/name" for the grant folder name as the grant, never a real folder', async () => {
    const temporary = await realpath(await mkdtemp(path.join(os.tmpdir(), 'ud-agent-grants-')));
    try {
      const name = `ud-grant-${path.basename(temporary)}`, root = path.join(temporary, name); await mkdir(root);
      expect((await relativeWorkspaceArguments({ working_tree_path: `./${name}/` }, [root]))?.args.working_tree_path).toBe(root);
      expect((await relativeWorkspaceArguments({ working_tree_path: `.${path.sep}${name}${path.sep}` }, [root]))?.args.working_tree_path).toBe(root);
      const absent = await relativeWorkspaceArguments({ working_tree_path: `/${name}` }, [root]);
      expect(absent?.args.working_tree_path).toBe(root);
      expect(absent?.note).toBe(`working_tree_path "/${name}" does not exist; it names the granted workspace folder, so used "${root}".`);
      expect(await relativeWorkspaceArguments({ working_tree_path: path.parse(temporary).root }, [root])).toBeUndefined();
      expect(await relativeWorkspaceArguments({ working_tree_path: '/elsewhere' }, [root])).toBeUndefined();
      await writeFile(path.join(root, 'gold.conllu'), '');
      expect((await relativeWorkspaceArguments({ working_tree_path: `${name}/gold.conllu` }, [root]))?.args.working_tree_path).toBe(path.join(root, 'gold.conllu'));
      expect((await relativeWorkspaceArguments({ working_tree_path: path.join(name, 'gold.conllu') }, [root]))?.args.working_tree_path).toBe(path.join(root, 'gold.conllu'));
      expect(await relativeWorkspaceArguments({ working_tree_path: [name, '..', '..', 'outside'].join(path.sep) }, [root])).toBeUndefined();
      await mkdir(path.join(root, name)); await writeFile(path.join(root, name, 'gold.conllu'), '');
      expect((await relativeWorkspaceArguments({ working_tree_path: `${name}/gold.conllu` }, [root]))?.args.working_tree_path).toBe(path.join(root, name, 'gold.conllu'));
      expect((await relativeWorkspaceArguments({ working_tree_path: path.join(name, 'gold.conllu') }, [root]))?.args.working_tree_path).toBe(path.join(root, name, 'gold.conllu'));
    } finally { await rm(temporary, { recursive: true, force: true }); }
  });

  it('reads a CoNLL-U data file named as ud_context_path as the installed default', () => {
    const result = quotedEmptyContextArguments({ ud_context_path: 'gold.conllu' });
    expect(result?.args).toEqual({ ud_context_path: '' });
    expect(result?.note).toBe('ud_context_path named the data file "gold.conllu", which cannot be a rules context; used the installed default context (empty string).');
  });

  it('reads a quoted-empty ud_context_path as the installed default and says so', () => {
    for (const quoted of ['""', "''"]) {
      const result = quotedEmptyContextArguments({ working_tree_path: '/w', ud_context_path: quoted });
      expect(result?.args).toEqual({ working_tree_path: '/w', ud_context_path: '' });
      expect(result?.note).toBe(`ud_context_path was the quote characters ${quoted}; used the installed default context (empty string).`);
    }
    for (const value of ['', '"x"', 'rules/context.json', undefined, 3]) expect(quotedEmptyContextArguments({ ud_context_path: value })).toBeUndefined();
  });

  it('names the argument roles and the single grant when a file or a missing path is the workspace', async () => {
    const temporary = await realpath(await mkdtemp(path.join(os.tmpdir(), 'ud-agent-grants-')));
    try {
      const root = await realpath(temporary);
      await writeFile(path.join(root, 'a.conllu'), '# sent_id = 1\n');
      await expect(authorizeWorkspace(path.join(root, 'a.conllu'), [root])).rejects.toThrow(`Workspace is not a directory; working_tree_path is the folder and file_paths names files inside it: retry with working_tree_path "${root}".`);
      await expect(authorizeWorkspace(path.join(root, 'a.conllu'), [root])).rejects.toMatchObject({ code: 'WORKSPACE_NOT_AUTHORIZED' });
      await expect(authorizeWorkspace('/a.conllu-missing-ud-agent', [root])).rejects.toMatchObject({ code: 'ENOENT', message: expect.stringContaining(`retry with working_tree_path "${root}"`) });
      await expect(authorizeWorkspace(path.join(root, 'a.conllu'), [root, path.join(root, 'other')])).rejects.toThrow(/inside it\.$/);
      expect(workspaceArgumentReason('Workspace is not a directory', [])).toBe('Workspace is not a directory; working_tree_path is the folder and file_paths names files inside it.');
    } finally { await rm(temporary, { recursive: true, force: true }); }
  });

  it('rejects a cross-volume absolute relative path', async () => {
    const temporary = await realpath(await mkdtemp(path.join(os.tmpdir(), 'ud-agent-grants-')));
    try {
      const root = await realpath(temporary);
      const child = path.join(root, 'bank'); await mkdir(child);
      vi.spyOn(path, 'relative').mockReturnValueOnce(path.resolve('/other-volume'));
      await expect(authorizeWorkspace(child, [root])).rejects.toThrow('authorized roots');
    } finally { vi.restoreAllMocks(); await rm(temporary, { recursive: true, force: true }); }
  });

  it('accepts only JSON arrays of absolute configured roots', () => {
    expect(parseGrantedRoots(undefined)).toEqual([]);
    expect(parseGrantedRoots('')).toEqual([]);
    expect(parseGrantedRoots('["/tmp"]')).toEqual(['/tmp']);
    expect(() => parseGrantedRoots('not json')).toThrow('valid JSON');
    expect(() => parseGrantedRoots('["relative"]')).toThrow('absolute');
    expect(() => parseGrantedRoots('["/tmp", "relative"]')).toThrow('absolute');
    expect(() => parseGrantedRoots('[1]')).toThrow('absolute');
  });
});
