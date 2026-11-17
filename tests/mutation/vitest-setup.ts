import { copyFileSync, lstatSync, mkdirSync, readFileSync } from 'node:fs';
import path from 'node:path';

// Stryker runs tests in isolated source copies, so provide the already built
// guard for subprocess tests without copying the whole Cargo target tree.
const guard = process.env.UD_MUTATION_GUARD;
if (guard) {
  if (!path.isAbsolute(guard)) throw new Error('UD_MUTATION_GUARD must be absolute');
  const target = path.resolve('target', 'debug', process.platform === 'win32' ? 'ud-agent-guard.exe' : 'ud-agent-guard');
  if (target !== guard) {
    // Protected jobs already receive this exact helper in their sealed tree.
    // Reuse identical ordinary bytes without trying to rewrite that tree.
    const staged = lstatSync(target, { throwIfNoEntry: false });
    if (!(staged?.isFile() && !staged.isSymbolicLink() && readFileSync(target).equals(readFileSync(guard)))) {
      mkdirSync(path.dirname(target), { recursive: true });
      copyFileSync(guard, target);
    }
  }
}

// The original-test supervisor accounts for this whole process tree. Test
// fixtures create and verify their own reservations, so they must not join the
// supervisor's lease implicitly; a test that runs a nested original job passes
// the retained supervisor lease explicitly.
if (process.env.UD_STORAGE_LEASE) process.env.UD_SUPERVISOR_STORAGE_LEASE = process.env.UD_STORAGE_LEASE;
delete process.env.UD_STORAGE_LEASE;
