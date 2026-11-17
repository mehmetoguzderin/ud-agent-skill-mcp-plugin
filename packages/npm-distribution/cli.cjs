#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { spawn } = require('node:child_process');

try {
  const root = __dirname;
  const map = require('./platforms.json');
  const tuple = `${process.platform}-${process.arch}`;
  const selected = map[tuple];
  if (!selected) throw new Error(`Unsupported operating system or architecture: ${tuple}`);
  const launcher = path.join(root, 'platforms', selected);
  const coordinator = path.join(root, 'lib', 'coordinator.mjs');
  const launcherInfo = fs.lstatSync(launcher);
  if (!launcherInfo.isFile() || launcherInfo.isSymbolicLink()) throw new Error('Packaged launcher is not a regular file.');
  if (process.platform !== 'win32' && (launcherInfo.mode & 0o111) === 0) throw new Error('Packaged launcher is not executable.');
  if (!fs.lstatSync(coordinator).isFile()) throw new Error('Packaged coordinator is not a regular file.');
  const child = spawn(launcher, process.argv.slice(2), {
    stdio: 'inherit',
    shell: false,
    env: { ...process.env, UD_AGENT_NODE: process.execPath, UD_AGENT_COORDINATOR: coordinator },
  });
  for (const signal of ['SIGINT', 'SIGTERM', 'SIGHUP']) {
    process.on(signal, () => { if (!child.killed) child.kill(signal); });
  }
  child.on('error', error => {
    process.stderr.write(`ud-agent: ${error.message}\n`);
    process.exitCode = 1;
  });
  child.on('exit', (code, signal) => {
    process.exitCode = code === null ? 1 : code;
    if (signal) process.stderr.write(`ud-agent: launcher terminated by ${signal}\n`);
  });
} catch (error) {
  process.stderr.write(`ud-agent: ${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
}
