import { test, expect } from 'vitest';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { copyAvailableTree, validateAvailableTreePaths } from '../../scripts/release/available-candidate.mjs';

test('package directory aliases retain disjoint ordinary-file paths', () => {
  const entries = [
    { path:'perl/Pod', kind:'directory' }, { path:'perl/pod', kind:'directory' },
    { path:'perl/Pod/Usage.pm', kind:'file' }, { path:'perl/pod/perl.pod', kind:'file' },
  ];
  expect(validateAvailableTreePaths(entries)).toBe(true);
  expect(validateAvailableTreePaths([...entries].reverse())).toBe(true);
});

test('package admission rejects full-file Unicode collisions despite directory aliases', () => {
  for (const paths of [['perl/Pod/Usage.pm','perl/pod/usage.pm'],['perl/Straße.pm','perl/STRASSE.pm']]) {
    const entries = paths.map(value => ({path:value,kind:'file'}));
    expect(() => validateAvailableTreePaths(entries)).toThrow(/Unicode file or directory conflict/);
    expect(() => validateAvailableTreePaths([...entries].reverse())).toThrow(/Unicode file or directory conflict/);
  }
});

test('package admission rejects file-directory and implicit-prefix conflicts in both orders', () => {
  for (const other of [{path:'perl/pod',kind:'directory'},{path:'perl/pod/perl.pod',kind:'file'}]) {
    const entries = [{path:'perl/Pod',kind:'file'},other];
    expect(() => validateAvailableTreePaths(entries)).toThrow(/Unicode file or directory conflict/);
    expect(() => validateAvailableTreePaths([...entries].reverse())).toThrow(/Unicode file or directory conflict/);
  }
  expect(() => validateAvailableTreePaths([{path:'perl/../escape',kind:'file'}])).toThrow(/unsafe path/);
});

test('directory alias copying preserves original file bytes without changing the source', () => {
  const root = mkdtempSync(path.join(os.tmpdir(),'ud-available-directory-alias-'));
  try {
    const source = path.join(root,'source'), destination = path.join(root,'copy');
    const originals = [['perl/Pod/Usage.pm',Buffer.from('package Pod::Usage;\n')],['perl/pod/perl.pod',Buffer.from('=head1 Perl documentation\n')]];
    for (const [name,bytes] of originals) { mkdirSync(path.dirname(path.join(source,name)),{recursive:true}); writeFileSync(path.join(source,name),bytes); }
    copyAvailableTree(source,destination);
    for (const [name,bytes] of originals) { expect(readFileSync(path.join(destination,name))).toEqual(bytes); expect(readFileSync(path.join(source,name))).toEqual(bytes); }
  } finally { rmSync(root,{recursive:true,force:true}); }
});
