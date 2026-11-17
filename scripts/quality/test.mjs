#!/usr/bin/env node
/** Default original tests use the same independent discovery and reconciliation as evidence. */
import { accessSync, constants, existsSync, mkdirSync, statSync } from 'node:fs';
import { randomUUID } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { runOriginalAcceptance } from './original-acceptance.mjs';

export function resolveOriginalExecutable(selected, { cwd = process.cwd(), environment = process.env, platform = process.platform } = {}) {
  if (typeof selected !== 'string' || !selected || /[\0\r\n]/.test(selected)) throw new Error('A required original-test executable was not selected.');
  const api = platform === 'win32' ? path.win32 : path.posix;
  const qualified = api.isAbsolute(selected) || selected.includes('/') || selected.includes('\\');
  const candidates = qualified ? [api.resolve(cwd, selected)] : (environment.PATH ?? '').split(platform === 'win32' ? ';' : ':').filter(Boolean).filter(directory => api.isAbsolute(directory)).map(directory => api.join(directory, selected));
  for (const filename of candidates) {
    try {
      if (!statSync(filename).isFile()) continue;
      accessSync(filename, platform === 'win32' ? constants.F_OK : constants.X_OK);
      // Keep the selected path: resolving a venv Python or rustup cargo symlink
      // to its target changes interpreter/shim behavior.
      return filename;
    } catch (error) { if (!['ENOENT', 'ENOTDIR', 'EACCES'].includes(error.code)) throw error; }
  }
  throw new Error(`Required original-test executable is unavailable: ${selected}`);
}

/** @param {string} root @param {{output?:string,python?:string,cargo?:string,environment?:NodeJS.ProcessEnv}} [options] */
export function runDefaultTests(root, { output, python, cargo, environment = process.env } = {}) {
  root = path.resolve(root);
  const venvPython = path.join(root, '.venv', process.platform === 'win32' ? 'Scripts/python.exe' : 'bin/python');
  const selectedPython = python ?? environment.UD_AGENT_PYTHON ?? (existsSync(venvPython) ? venvPython : process.platform === 'win32' ? 'python.exe' : 'python3');
  const selectedCargo = cargo ?? (process.platform === 'win32' ? 'cargo.exe' : 'cargo');
  const options = { cwd: root, environment };
  const resolvedPython = resolveOriginalExecutable(selectedPython, options), resolvedCargo = resolveOriginalExecutable(selectedCargo, options);
  if (output === undefined) {
    const parent = path.join(root, '.artifacts/original-tests'); mkdirSync(parent, { recursive: true, mode: 0o700 });
    output = path.join(parent, randomUUID());
  }
  return { report: runOriginalAcceptance(root, { output, python: resolvedPython, cargo: resolvedCargo }), output: path.resolve(output) };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.length !== 2) throw new Error('Usage: node scripts/quality/test.mjs');
  const root = path.resolve(import.meta.dirname, '../..');
  const venvPython = path.join(root, '.venv', process.platform === 'win32' ? 'Scripts/python.exe' : 'bin/python');
  const python = resolveOriginalExecutable(process.env.UD_AGENT_PYTHON ?? (existsSync(venvPython) ? venvPython : process.platform === 'win32' ? 'python.exe' : 'python3'), { cwd: root });
  const cargo = resolveOriginalExecutable(process.platform === 'win32' ? 'cargo.exe' : 'cargo', { cwd: root });
  const output = path.join(root, '.artifacts/original-tests', randomUUID());
  const original = [path.join(root, 'scripts/quality/original-acceptance.mjs'), '--output', output, '--python', python, '--cargo', cargo];
  // Elevated Windows runners can default newly created state to Administrators
  // ownership. Provision only this original-test child token before copying or
  // creating fixtures; the product's current-user ACL policy stays unchanged.
  const program = process.platform === 'win32' ? python : process.execPath;
  const args = process.platform === 'win32' ? ['-I', '-B', path.join(root, 'scripts/quality/windows-original-token.py'), '--cwd', root, '--', process.execPath, ...original] : original;
  const child = spawn(program, args, { stdio: 'inherit' });
  for (const signal of /** @type {NodeJS.Signals[]} */ (['SIGINT', 'SIGTERM'])) process.once(signal, () => child.kill(signal));
  const result = await new Promise((resolve, reject) => { child.once('error', reject); child.once('close', (code, signal) => resolve({ code, signal })); });
  process.exitCode = result.signal ? 1 : result.code ?? 1;
}
