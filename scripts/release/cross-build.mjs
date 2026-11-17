/** Build the five release launcher/helper targets on an Apple Silicon development host. */
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { fileReceipt, verifyRecordedFile } from './candidate.mjs';
import { OPEN_WINDOWS_PROFILE, OPEN_WINDOWS_TARGETS, verifyOpenWindowsMap, verifyWindowsBootstrapImports } from './windows-linkage.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
if (process.platform !== 'darwin' || process.arch !== 'arm64') throw new Error('This local cross-builder requires a macOS arm64 host.');

const artifacts = path.join(root, '.artifacts');
const rust = path.join(artifacts, 'rustup/toolchains/1.99.1-aarch64-apple-darwin');
const cargo = path.join(rust, 'bin/cargo');
const zigbuild = path.join(artifacts, 'cargo/bin/cargo-zigbuild');
const cachedZig = path.join(artifacts, 'public-beta-zig/ziglang/zig');
const zig = existsSync(cachedZig) ? cachedZig : path.join(root, '.venv/lib/python3.14/site-packages/ziglang/zig');
for (const file of [cargo, zigbuild, zig]) {
  if (!statSync(file).isFile()) throw new Error('Required locked cross-build tool is unavailable: ' + file);
}
const targetRoot = path.join(artifacts, 'cross-build-target');
const env = {
  ...process.env,
  PATH: [path.join(rust, 'bin'), path.join(rust, 'lib/rustlib/aarch64-apple-darwin/bin'), path.join(artifacts, 'cargo/bin'), '/opt/homebrew/bin', '/usr/bin', '/bin'].join(':'),
  RUSTC: path.join(rust, 'bin/rustc'),
  DYLD_LIBRARY_PATH: path.join(rust, 'lib'),
  CARGO_HOME: path.join(artifacts, 'cargo'),
  CARGO_TARGET_DIR: targetRoot,
  CARGO_PROFILE_RELEASE_STRIP: 'none',
  CARGO_ZIGBUILD_ZIG_PATH: zig,
  CARGO_ZIGBUILD_CACHE_DIR: path.join(artifacts, 'zigbuild-cache'),
  ZIG_GLOBAL_CACHE_DIR: path.join(artifacts, 'zig-cache'),
  MACOSX_DEPLOYMENT_TARGET: '14.0',
};
for (const variable of ['RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER', 'CARGO_BUILD_TARGET']) delete env[variable];

const targets = [
  ['darwin-arm64', 'aarch64-apple-darwin', cargo, 'build', 'aarch64-apple-darwin'],
  ['linux-arm64', 'aarch64-unknown-linux-gnu', zigbuild, 'zigbuild', 'aarch64-unknown-linux-gnu.2.28'],
  ['linux-x64', 'x86_64-unknown-linux-gnu', zigbuild, 'zigbuild', 'x86_64-unknown-linux-gnu.2.28'],
];
const names = ['ud-agent', 'ud-agent-guard'];
const cargoArguments = ['--locked', '--offline', '--release', '-p', 'ud-agent-launcher'];

function inputs(dir) {
  return readdirSync(dir, { withFileTypes: true }).flatMap(entry => {
    const full = path.join(dir, entry.name);
    return entry.isDirectory() ? inputs(full) : entry.isFile() ? [full] : [];
  });
}

const sourceFiles = [path.join(root, 'Cargo.toml'), path.join(root, 'Cargo.lock'), ...inputs(path.join(root, 'packages/launcher'))].sort();
function sourceHash() {
  const hash = createHash('sha256');
  for (const file of sourceFiles) {
    hash.update(path.relative(root, file)); hash.update('\0'); hash.update(readFileSync(file)); hash.update('\0');
  }
  return hash.digest('hex');
}

function run(program, args, options = {}) {
  const result = spawnSync(program, args, { cwd: root, env, stdio: 'inherit', ...options });
  if (result.error || result.status !== 0) throw new Error(path.basename(program) + ' failed: ' + (result.error?.message ?? result.stderr ?? result.status));
  return result.stdout;
}

function relative(file) {
  return path.relative(root, file);
}
function binaryReceipt(file) {
  const receipt = fileReceipt(root, relative(file));
  if (!receipt.executable) throw new Error('Cross-build output is not executable: ' + receipt.path);
  return receipt;
}

const windowsLockPath = 'runtime/materials/windows-open-toolchain.lock.json';
const windowsLockReceipt = fileReceipt(root, windowsLockPath);
const windowsLock = JSON.parse(readFileSync(path.join(root, windowsLockPath), 'utf8'));
const inputDirectory = '.artifacts/llvm-mingw-inputs';
function pinnedInput(input) {
  if (!input || !/^[A-Za-z0-9][A-Za-z0-9._-]+$/.test(input.filename)) throw new Error('Invalid LLVM-MinGW archive name');
  return verifyRecordedFile(root, { path: inputDirectory + '/' + input.filename, sha256: input.sha256, size: input.size_bytes });
}

const compilerArchive = pinnedInput(windowsLock.archive);
verifyRecordedFile(root, { ...windowsLock.notice, size: windowsLock.notice.size_bytes });
verifyRecordedFile(root, { ...windowsLock.mingw_notice, size: windowsLock.mingw_notice.size_bytes });
const sourceInputs = windowsLock.sources.map(input => {
  pinnedInput(input);
  return { path: input.filename, sha256: input.sha256, size_bytes: input.size_bytes, url: input.url };
});
const sourceReceiptPath = path.join(root, inputDirectory, 'source-receipt.json');
const sourceReceipt = JSON.stringify({ schema_version: 1, qualification: 'exact-locked-source-subinventory', status: 'passed', files: sourceInputs }, null, 2) + '\n';
if (!existsSync(sourceReceiptPath)) writeFileSync(sourceReceiptPath, sourceReceipt, { flag: 'wx' });
if (readFileSync(sourceReceiptPath, 'utf8') !== sourceReceipt) throw new Error('Retained LLVM-MinGW source receipt differs from its pins');

const before = sourceHash();
const result = {};
for (const [platform, triple, program, command, target] of targets) {
  process.stderr.write('Cross-building ' + platform + '\n');
  run(program, [command, ...cargoArguments, '--target', target]);
  result[platform] = Object.fromEntries(names.map(name => [name, binaryReceipt(path.join(targetRoot, triple, 'release', name))]));
}

const mapRoot = path.join(artifacts, 'windows-open-link-maps');
mkdirSync(mapRoot, { recursive: true });
const windowsLinkage = {};
const unpack = mkdtempSync(path.join(artifacts, 'llvm-mingw-build-'));
try {
  run('/usr/bin/tar', ['-xf', path.join(root, compilerArchive.path), '-C', unpack]);
  const toolchain = path.join(unpack, windowsLock.archive.filename.replace(/\.tar\.xz$/, ''));
  const extractedNotice = path.join(toolchain, 'LICENSE.TXT');
  verifyRecordedFile(root, { path: relative(extractedNotice), sha256: windowsLock.notice.sha256, size: windowsLock.notice.size_bytes });
  for (const [platform, triple] of Object.entries(OPEN_WINDOWS_TARGETS)) {
    process.stderr.write('Cross-building ' + platform + ' with LLVM-MinGW\n');
    const architecture = triple.split('-')[0];
    const linker = path.join(toolchain, 'bin', architecture + '-w64-mingw32-clang');
    const buildEnv = { ...env,
      ['CARGO_TARGET_' + triple.replaceAll('-', '_').toUpperCase() + '_LINKER']: linker,
      ['CC_' + triple.replaceAll('-', '_')]: linker,
    };
    const linkage = { profile: OPEN_WINDOWS_PROFILE, target: triple, target_execution: false, objects: {} };
    windowsLinkage[platform] = linkage;
    result[platform] = {};
    for (const name of names) {
      const map = path.join(mapRoot, triple + '-' + name + '.map');
      const args = ['rustc', ...cargoArguments, '--bin', name, '--target', triple, '--',
        '-C', 'target-feature=+crt-static', '-C', 'link-arg=-Wl,-Map,' + map];
      run(cargo, args, { env: buildEnv });
      const bin = binaryReceipt(path.join(targetRoot, triple, 'release', name + '.exe'));
      const script = 'import json,sys;sys.path.insert(0,sys.argv[1]);from windows_pe import inspect_pe;print(json.dumps(inspect_pe(open(sys.argv[2],"rb").read(),sys.argv[3])["imports"]))';
      const imports = run(path.join(root, '.venv/bin/python'), ['-I', '-B', '-c', script, path.join(root, 'scripts/runtime'), path.join(root, bin.path), platform.split('-')[1]],
        { stdio: 'pipe', encoding: 'utf8', maxBuffer: 1024 * 1024, timeout: 30_000 });
      const linkMap = readFileSync(map, 'utf8');
      verifyOpenWindowsMap(linkMap, toolchain, triple);
      const normalized = map + '.json';
      const contents = linkMap.replaceAll(toolchain + '/', 'llvm-mingw/').replaceAll(root + '/', '');
      writeFileSync(normalized, JSON.stringify({ format: 'lld-link-map', contents }) + '\n');
      linkage.objects[name] = {
        ...verifyWindowsBootstrapImports(JSON.parse(imports), OPEN_WINDOWS_PROFILE),
        binary_sha256: bin.sha256,
        map: fileReceipt(root, relative(normalized)),
      };
      result[platform][name] = bin;
    }
  }
} finally {
  rmSync(unpack, { recursive: true, force: true });
}

if (sourceHash() !== before) throw new Error('Launcher sources changed during cross-build; discard this receipt.');
writeFileSync(path.join(artifacts, 'cross-build-receipt.json'), JSON.stringify({
  schema_version: 1, status: 'unaccepted', source_sha256: before, rust: '1.99.1',
  node: '26.13.0', zig: '0.17.1', cargo_zigbuild: '0.24.1',
  windows_toolchain: windowsLockReceipt, platforms: result, windows_linkage: windowsLinkage,
}, null, 2) + '\n');
console.log('Five release targets cross-built. Run native acceptance on the packaged files.');
