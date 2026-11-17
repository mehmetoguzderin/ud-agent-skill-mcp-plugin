/** Native, hashable test shim. Fixed fixture scripts remain test inputs only. */
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { writeFile } from 'node:fs/promises';
import path from 'node:path';

export async function writeNativeEngine(options: { root: string; name: string; program: string; language?: 'node' | 'python'; interpreter?: string }): Promise<string> {
  const { root, name, program } = options;
  const language = options.language ?? 'node'; const interpreter = options.interpreter ?? (language === 'node' ? process.execPath : undefined);
  if (!path.isAbsolute(root) || !/^[a-zA-Z0-9_-]{1,80}$/.test(name) || !interpreter || !path.isAbsolute(interpreter) || [root, interpreter].some(value => value.includes('\0') || value.includes('"###'))) throw new Error('NATIVE_ENGINE_FIXTURE_INVALID');
  const digest = createHash('sha256').update(program).digest('hex').slice(0, 16); const extension = language === 'python' ? 'py' : program.includes('require(') ? 'cjs' : 'mjs';
  const script = path.join(root, `${name}-model-${digest}.${extension}`); const source = path.join(root, `${name}-native.rs`); const executable = path.join(root, name + (process.platform === 'win32' ? '.exe' : ''));
  await writeFile(script, program, { mode: 0o600 });
  const python = "import pathlib,sys;source,identity=sys.argv[1:3];sys.argv=[identity,*sys.argv[3:]];exec(compile(pathlib.Path(source).read_bytes(),identity,'exec'),{'__name__':'__main__','__file__':identity})";
  const argumentsCode = language === 'python' ? `.arg("-c").arg(r###"${python}"###).arg(r###"${script}"###).arg(r###"${executable}"###)` : `.arg(r###"${script}"###)`;
  await writeFile(source, `fn main(){let mut command=std::process::Command::new(r###"${interpreter}"###);command${argumentsCode}.args(std::env::args_os().skip(1));#[cfg(unix)]{use std::os::unix::process::CommandExt;let error=command.exec();eprintln!("fixture interpreter failed: {error}");std::process::exit(126);}#[cfg(windows)]{let status=command.status().expect("fixture interpreter startup");std::process::exit(status.code().unwrap_or(1));}}`);
  const result = spawnSync('rustc', [source, '-o', executable], { encoding: 'utf8', timeout: 60000, maxBuffer: 1024 * 1024 });
  if (result.error || result.status !== 0) throw new Error(`NATIVE_ENGINE_FIXTURE_COMPILE_FAILED: ${result.error?.message ?? result.stderr}`);
  return executable;
}
