// SPDX-License-Identifier: MIT
import { test, expect } from 'vitest';
import path from 'node:path';
import { parseArguments } from '../../scripts/quality/run-local-model-evals.mjs';

test('container preparation and headless profile are additive explicit options', () => {
  expect(parseArguments(['prepare', '--opt-in', '--containers']).options).toMatchObject({ optIn: true, containers: true });
  expect(parseArguments(['iterate-prepare', '--opt-in', '--session', '/private/session', '--profile', 'headless-12h-v2']).options).toMatchObject({ profile: 'headless-12h-v2', session: path.resolve('/private/session') });
  expect(parseArguments(['iterate-report', '--session', '/private/session', '--output', '/private/report', '--require-headless-qualified']).options.requireHeadlessQualified).toBe(true);
});
test('qualification and profile switches reject unsupported commands and values', () => {
  for (const args of [
    ['run', '--containers'], ['study-prepare', '--containers'], ['run', '--retry-acquisition'], ['prepare', '--retry-acquisition', '--repair-runtime'],
    ['iterate', '--session', '/private/session', '--profile', 'headless-12h-v2'],
    ['iterate-prepare', '--session', '/private/session', '--profile', 'unknown'],
    ['iterate-prepare', '--session', '/private/session', '--require-headless-qualified'],
    ['iterate-report', '--session', '/private/session', '--output', '/private/report', '--require-headless-qualified', '--require-headless-qualified'],
  ]) expect(() => parseArguments(args)).toThrow();
});
