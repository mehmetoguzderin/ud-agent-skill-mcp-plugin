/** Side-effect-free config helpers; never import an executable child entrypoint. */
import { fileURLToPath } from 'node:url';

export function protectedVitestSetupFiles(original) {
  const previous = original === undefined ? [] : typeof original === 'string' ? [original] : original;
  if (!Array.isArray(previous) || !previous.every(value => typeof value === 'string' && value.length > 0)) throw new Error('Protected Stryker: invalid original Vitest setup files');
  const fixed = fileURLToPath(new URL('./stryker-assertion-setup.mjs', import.meta.url));
  return [fixed, ...previous.filter(value => value !== fixed)];
}
