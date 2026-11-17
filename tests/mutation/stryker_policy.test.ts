import { describe, expect, it } from 'vitest';
import { execFileSync } from 'node:child_process';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import config from '../../stryker.config.mjs';

describe('mutation gate policy', () => {
  it('keeps the project compiler on TypeScript 7 when the compatibility loader is active', () => {
    const loader = path.resolve('scripts/quality/stryker-compat.mjs');
    const version = execFileSync(process.execPath, ['--import', pathToFileURL(loader).href, '-e', "process.stdout.write(require('typescript/package.json').version)"], { encoding: 'utf8' });
    expect(version).toBe('7.0.2');
  });

  it('keeps mutation thresholds strict and disables incremental reuse', () => {
    expect(config.thresholds).toEqual({ high: 100, low: 100, break: 100 });
    expect(config.incremental).toBe(false);
    expect(config.allowEmpty).toBe(false);
    expect(config.ignoreStatic).toBe(false);
    expect(config.inPlace).toBe(false);
    expect(config.disableBail).toBe(true);
    expect(config.disableTypeChecks).toBe(false);
    expect(config.coverageAnalysis).toBe('off');
    expect(config.dryRunTimeoutMinutes).toBe(9);
  });
});
