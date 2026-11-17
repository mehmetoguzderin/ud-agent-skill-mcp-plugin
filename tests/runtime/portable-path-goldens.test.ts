/** Literal Unicode16/path-policy expectations, independent of the Python peer. */
import { expect, test } from 'vitest';
import { portablePathKey, validPortablePath } from '../../packages/workspace/src/portable-path.js';

test('portable canonical keys preserve the independent Unicode casefold and composition goldens', () => {
  const cases: [string, string][] = [
    ['Straße.conllu', 'strasse.conllu'], ['ẞ.CONLLU', 'ss.conllu'],
    ['A\u0315\u0300.conllu', 'à\u0315.conllu'], ['\u1100\u1161.conllu', '가.conllu'],
    ['\u212A.conllu', 'k.conllu'], ['İ.conllu', 'i\u0307.conllu'],
    ['A\u0315\u1ACF\u0300.conllu', 'a\u0315\u1ACF\u0300.conllu'],
  ];
  for (const [input, expected] of cases) expect(portablePathKey(input)).toBe(expected);
});
test('portable paths reject independent escape and Windows device-name counterexamples', () => {
  for (const name of ['', 'a//b', 'a/./b', 'a/../b', 'C:/x', '/absolute', 'a\\b', 'NUL.txt', 'aux', 'LPT9.conllu', 'com1.txt', 'name.', 'name ', 'bad\u0000name', 'a\nb']) expect(validPortablePath(name), name).toBe(false);
  for (const name of ['normal/tree.conllu', '字/😀.conllu', '.hidden/a.conllu', 'COM10.txt']) expect(validPortablePath(name), name).toBe(true);
});
