#!/usr/bin/env node
'use strict';

// The extension supplies the workspace as an argument, avoiding JSON escaping
// errors when a Windows path is substituted into an environment variable.
const { lstatSync } = require('node:fs');
const path = require('node:path');
const { spawn } = require('node:child_process');

function launchOptions(root, workspace, inherited = process.env) {
  if (typeof workspace !== 'string' || !path.isAbsolute(workspace) || workspace.includes('\0')) {
    throw new Error('Choose an absolute workspace directory.');
  }
  const info = lstatSync(workspace);
  if (!info.isDirectory() || info.isSymbolicLink()) throw new Error('Workspace must be a real directory.');
  const executable = path.join(root, 'bin', process.platform === 'win32' ? 'ud-agent.exe' : 'ud-agent');
  const env = { ...inherited, UD_AGENT_ALLOWED_ROOTS: JSON.stringify([workspace]) };
  delete env.UD_AGENT_NODE;
  delete env.UD_AGENT_COORDINATOR;
  return { executable, args: ['mcp'], options: { env, shell: false, stdio: 'inherit' } };
}

if (require.main === module) {
  try {
    if (process.argv.length !== 3) throw new Error('Select one workspace directory in extension settings.');
    const launch = launchOptions(__dirname, process.argv[2]);
    const child = spawn(launch.executable, launch.args, launch.options);
    for (const signal of ['SIGINT', 'SIGTERM', 'SIGHUP']) {
      process.on(signal, () => { if (!child.killed) child.kill(signal); });
    }
    child.on('error', error => { process.stderr.write(`ud-agent extension: ${error.message}\n`); process.exitCode = 1; });
    child.on('exit', (code, signal) => {
      process.exitCode = code === null ? 1 : code;
      if (signal) process.stderr.write(`ud-agent extension: launcher terminated by ${signal}\n`);
    });
  } catch (error) {
    process.stderr.write(`ud-agent extension: ${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  }
}

module.exports = { launchOptions };
