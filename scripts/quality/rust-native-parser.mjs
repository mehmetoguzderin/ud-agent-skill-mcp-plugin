/** Run only the original Rust AST parser built from the frozen source snapshot.
 * Mutated Rust is parsed as data; no candidate is compiled or executed here.
 */
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { lstatSync, readFileSync, realpathSync } from 'node:fs';
import path from 'node:path';

const digest = bytes => createHash('sha256').update(bytes).digest('hex');
const sources = ['Cargo.toml', 'Cargo.lock', 'src/main.rs', 'src/cfg_regions.rs'].map(name => 'scripts/quality/rust-assertion-parser/' + name);

function nativeRustParser(root, executable, inventory, mode) {
  for (const name of sources) {
    const filename = path.join(root, name), info = lstatSync(filename);
    if (!info.isFile() || info.isSymbolicLink() || digest(readFileSync(filename)) !== inventory[name]) throw new Error('Native Rust parser source differs from the frozen inventory.');
  }
  if (!path.isAbsolute(executable) || lstatSync(executable).isSymbolicLink()) throw new Error('Native Rust parser path is not an absolute ordinary executable.');
  executable = realpathSync(executable);
  const original = lstatSync(executable), fingerprint = digest(readFileSync(executable));
  if (!original.isFile() || original.isSymbolicLink() || original.nlink !== 1 || (process.platform !== 'win32' && (!(original.mode & 0o111) || (original.mode & 0o022)))) throw new Error('Native Rust parser executable is not privately owned.');
  const cache = new Map();
  const verify = () => {
    const info = lstatSync(executable);
    if (!info.isFile() || info.isSymbolicLink() || info.dev !== original.dev || info.ino !== original.ino || info.nlink !== 1 || info.mode !== original.mode || digest(readFileSync(executable)) !== fingerprint) throw new Error('Native Rust parser executable changed.');
  };
  const parse = (source, testScope) => {
    verify();
    const key = digest(source) + ':' + testScope;
    if (cache.has(key)) return structuredClone(cache.get(key));
    const result = spawnSync(executable, mode === 'cfg' ? ['--cfg-regions'] : ['--source', ...(testScope ? ['--test-scope'] : [])], { input: source, encoding: 'utf8', timeout: 10_000, maxBuffer: 8 * 1024 * 1024, env: { PATH: process.platform === 'win32' ? path.dirname(executable) : '/usr/bin:/bin', LANG: 'C.UTF-8' } });
    verify();
    if (result.error || result.signal || result.status !== 0 || result.stderr) throw new Error('Native Rust AST parser failed.');
    const syntax = JSON.parse(result.stdout);
    cache.set(key, syntax);
    return structuredClone(syntax);
  };
  parse.receipt = { executable_sha256: fingerprint, source_inventory: Object.fromEntries(sources.map(name => [name, inventory[name]])), qualification: 'unmutated-native-AST-parser-only' };
  if(mode === 'cfg')parse.receipt.parser_mode = 'cfg-regions';
  return parse;
}
export function nativeRustSourceParser(root, executable, inventory) { return nativeRustParser(root, executable, inventory, 'source'); }
export function nativeRustCfgParser(root, executable, inventory) { return nativeRustParser(root, executable, inventory, 'cfg'); }
