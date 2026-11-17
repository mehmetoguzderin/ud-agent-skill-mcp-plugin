import { describe, expect, it } from 'vitest';
import path from 'node:path';
import { gitConfigText, gitWildmatch, includeConditionMatches, includeTarget, parseGitConfig, parseGitAlternates, quoteGitAlternate } from '../../packages/workspace/src/git-config.js';
describe('non-executing Git config preflight', () => {
  it('preserves byte-oriented names, quoted comments, escapes and continued values', () => {
    const values = parseGitConfig(Buffer.from('\ufeff[Core]\n repositoryFormatVersion = 1 # comment\n bare\n[include]\n path = "one #; \\"two\\""\\\n "/three"\n[includeIf "gitdir/i:~/Work/"]\n path = ../config\n[Remote.Origin]\n url = https://example.invalid/a.git\n', 'utf8'));
    expect(values).toEqual([{ section: 'core', key: 'repositoryformatversion', value: '1' }, { section: 'core', key: 'bare', value: null }, { section: 'include', key: 'path', value: 'one #; "two" /three' }, { section: 'includeif', subsection: 'gitdir/i:~/Work/', key: 'path', value: '../config' }, { section: 'remote', subsection: 'origin', key: 'url', value: 'https://example.invalid/a.git' }]);
    expect(parseGitConfig(Buffer.from('[core] bare=true\n x=value\\'))).toEqual([{ section:'core',key:'bare',value:'true' },{section:'core',key:'x',value:'value'}]);
    expect(gitConfigText(parseGitConfig(Buffer.from('[remote "Å"]\nurl=x\n'))[0]!.subsection!)).toBe('Å');
  });
  it('rejects malformed config before a Git process is needed', () => {
    for (const input of ['path = bad', '[include]\npath="unterminated', '[include]\npath="\\q"', '[core]\n0bad=yes', '[core]\npath\0=x', '[include] trailing garbage\npath=x', '[x]\ninvalid key = y']) expect(() => parseGitConfig(Buffer.from(input))).toThrow('GIT_METADATA_CONFIG_INVALID');
    expect(() => parseGitConfig(Buffer.alloc(1024 * 1024 + 1))).toThrow();
  });
  it('matches slash-aware wildcards without unbounded regex backtracking', () => {
    for (const [pattern, text, expected] of [['**/work/**', '/home/work/repo/.git', true], ['**/work/**', 'work/.git', true], ['a/**/b', 'a/b', true], ['a/**/b', 'a/x/y/b', true], ['a/*/b', 'a/x/y/b', false], ['foo?', 'fooa', true], ['foo?', 'foo/', false], ['[a-c][!0-3]', 'b9', true], ['[a-c][!0-3]', 'b2', false], ['a\\*b', 'a*b', true], ['[[:digit:]][[:upper:]]', '5A', true], ['[[:alpha:]]', '5', false], ['Å', 'Å', true], ['?', 'Å', false], ['', '', true]] as const) expect(gitWildmatch(pattern, text), pattern + ':' + text).toBe(expected);
    expect(gitWildmatch('A/[B-D]', 'a/c', true)).toBe(true);
    expect(() => gitWildmatch('*'.repeat(3000), 'x'.repeat(3000))).toThrow('GIT_CONFIG_CONDITION_TOO_LARGE');
  });
  it('evaluates active/inactive Git directories, branches and remote URL conditions', () => {
    const base = path.resolve('fixture'), context = { gitDir: path.join(base, 'project/.git'), configFile: path.join(base, 'config'), home: base, branch: 'feature/topic', remoteUrls: ['https://example.invalid/team/repo.git'] };
    expect(includeConditionMatches('gitdir:~/project/', context)).toBe(true);
    expect(includeConditionMatches('gitdir:./project/.git', context)).toBe(true);
    expect(includeConditionMatches('gitdir:other/', context)).toBe(false);
    expect(includeConditionMatches('onbranch:feature/', context)).toBe(true);
    expect(includeConditionMatches('onbranch:main', context)).toBe(false);
    expect(includeConditionMatches('hasconfig:remote.*.url:https://example.invalid/**', context)).toBe(true);
    expect(includeConditionMatches('unknown:future', context)).toBe(false);
    expect(includeConditionMatches(Buffer.from('hasconfig:remote.*.url:**'), {...context,remoteUrls:[Buffer.from([255])]})).toBe(true);
    expect(includeConditionMatches(Buffer.concat([Buffer.from('onbranch:'),Buffer.from([255])]), {...context,branch:Buffer.from([255])})).toBe(true);
    expect(includeTarget('../allowed.cfg', path.join(base, 'a/config'), base)).toBe(path.join(base, 'allowed.cfg'));
    expect(includeTarget('~/allowed.cfg', path.join(base, 'a/config'), base)).toBe(path.join(base, 'allowed.cfg'));
    for (const input of [null, '~someone/config', 'bad\npath']) expect(() => includeTarget(input, context.configFile, base)).toThrow();
  });
});

it('calibrates active include conditions against the installed original Git implementation', async () => {
  const { spawnSync } = await import('node:child_process'), fs = await import('node:fs/promises'), os = await import('node:os');
  const root = await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(), 'ud-git-config-oracle-')));
  const result = (args: string[]) => spawnSync('git', args, { encoding:'utf8', env:{ ...process.env, GIT_CONFIG_NOSYSTEM:'1', GIT_CONFIG_GLOBAL:process.platform === 'win32' ? 'NUL' : '/dev/null' } });
  try {
    const initialized = result(['init','--quiet','--initial-branch=main',root]); expect(initialized.status, initialized.stderr).toBe(0);
    const config = path.join(root,'.git/config'), before = await fs.readFile(config,'utf8'), selected = path.join(root,'marker.cfg'); await fs.writeFile(selected,'[marker]\nvalue=active\n');
    const directory = path.join(root,'.git').split(path.sep).join('/'), context = { gitDir:path.join(root,'.git'),configFile:config,home:os.homedir(),branch:'main',remoteUrls:['https://example.invalid/team/repo.git'] };
    const conditions = [`gitdir:${directory}`, `gitdir:${directory.slice(0,-1)}[[:alpha:]]`, `gitdir:${directory.slice(0,-1)}[![:digit:]]`, `gitdir/i:${directory.toUpperCase()}`, 'gitdir:**/workspace/**', 'onbranch:main','onbranch:m[[:alpha:]]in','onbranch:m[[:upper:]]in','onbranch:other','hasconfig:remote.*.url:https://example.invalid/**','hasconfig:remote.*.url:https://other.invalid/**','unknown:future'];
    for (const condition of conditions) {
      await fs.writeFile(config,before + `\n[remote "origin"]\nurl=https://example.invalid/team/repo.git\n[includeIf "${condition.replace(/\\/g,'\\\\').replace(/"/g,'\\"')}"]\npath=${selected.split(path.sep).join('/')}\n`);
      const actual = result(['-C',root,'config','--includes','--get','marker.value']); expect([0,1]).toContain(actual.status);
      expect(includeConditionMatches(condition,context),condition).toBe(actual.status === 0);
    }
  } finally { await fs.rm(root,{recursive:true,force:true}); }
});

it('decodes Git alternate C quoting, comments, exact octals and literal malformed-quote fallback', () => {
  expect(parseGitAlternates(Buffer.from('# ignored\nplain path\n"one\\040space"\n"back\\\\slash"\n"\\303\\205"\n"quote\\\"x"\n'))).toEqual(['plain path','one space','back\\slash','Å','quote"x']);
  for (const value of ['"unterminated','"bad\\q"','"short\\12"']) expect(parseGitAlternates(Buffer.from(value+'\n'))).toEqual([value]);
  for (const value of ['one space','back\\slash','Å','quote"x','line\nname','tab\tname']) expect(parseGitAlternates(Buffer.from(quoteGitAlternate(value)+'\n'))).toEqual([value]);
  for (const bytes of [Buffer.from('bad\0path'),Buffer.from('"\\000"'),Buffer.alloc(65537)]) expect(() => parseGitAlternates(bytes)).toThrow('GIT_ALTERNATE_INVALID');
});
