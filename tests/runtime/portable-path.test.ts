import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { portablePathKey, validPortablePath } from '../../packages/workspace/src/portable-path.js';

const python = process.env.UD_AGENT_PYTHON ?? (existsSync(path.resolve('.venv/bin/python')) ? path.resolve('.venv/bin/python') : 'python3');

describe('portable snapshot paths', () => {
  it('matches Python validation and frozen case folding across languages', () => {
    const paths = [
      'a/é.conllu', 'a/e\u0301.conllu', 'Straße.conllu', 'STRASSE.conllu',
      'ẞ.conllu', 'SS.conllu', 'Σ.conllu', 'ς.conllu', 'İ.conllu',
      '😀/字.conllu', '.GIT/data.conllu', 'a/../b', 'CON.txt', 'a/evil\nname',
      'a'.repeat(256), Array(65).fill('a').join('/'),
    ];
    const script = `import json, sys\nfrom ud_agent.snapshot_receiver import _path, _path_key\nitems=json.load(sys.stdin)\nresult=[]\nfor item in items:\n try:\n  _path(item); result.append([True,_path_key(item)])\n except (ValueError,UnicodeError): result.append([False,None])\nprint(json.dumps(result,ensure_ascii=False))\n`;
    const result = spawnSync(python, ['-c', script], {
      input: JSON.stringify(paths), encoding: 'utf8', env: { ...process.env, PYTHONPATH: path.resolve('workers/ud/src') },
    });
    expect(result.error).toBeUndefined();
    expect(result.status, result.stderr).toBe(0);
    expect(JSON.parse(result.stdout)).toEqual(paths.map(item => [validPortablePath(item), validPortablePath(item) ? portablePathKey(item) : null]));
    expect(portablePathKey('Straße.conllu')).toBe(portablePathKey('STRASSE.conllu'));
    expect(portablePathKey('ẞ.conllu')).toBe(portablePathKey('SS.conllu'));
    expect(portablePathKey('a/é.conllu')).toBe(portablePathKey('a/e\u0301.conllu'));
  });

  it('rejects malformed UTF-16 without replacing it during transport', () => {
    expect(validPortablePath('a\ud800b')).toBe(false);
    expect(validPortablePath('😀.conllu')).toBe(true);
  });
});

describe('Unicode16 normalization under newer host Unicode tables', () => {
  it('keeps newly assigned combining marks as frozen starter boundaries', () => {
    for (const codepoint of [0x1acf, 0x1ad0, 0x1ae0, 0x1aeb, 0x10efa]) {
      const mark = String.fromCodePoint(codepoint);
      expect(portablePathKey(`A\u0315${mark}.conllu`)).toBe(`a\u0315${mark}.conllu`);
      expect(portablePathKey(`A\u0315${mark}`)).not.toBe(portablePathKey(`A${mark}\u0315`));
    }
    expect(portablePathKey('A\u0315\u0300.conllu')).toBe('à\u0315.conllu');
    expect(portablePathKey('e\u0301.conllu')).toBe('é.conllu');
    expect(portablePathKey('\u1100\u1161.conllu')).toBe('가.conllu');
  });
});
