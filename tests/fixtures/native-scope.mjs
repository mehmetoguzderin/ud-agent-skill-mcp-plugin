/** Source-declared native obligations: foreign cases are not test outcomes. */
import { test } from 'vitest';

export function createPosixTest(register, platform) {
  if (typeof register !== 'function' || !['darwin', 'linux', 'win32'].includes(platform)) throw new Error('Native test scope requires a supported native platform and test registrar.');
  if (platform !== 'win32') return register;
  const foreign = () => undefined;
  foreign.each = () => foreign;
  return Object.freeze(foreign);
}

export const posixTest = createPosixTest(test, process.platform);
