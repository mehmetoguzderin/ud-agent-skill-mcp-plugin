/** Data-only source/PE/static-object binding for locally cross-built uv. */
import assert from 'node:assert/strict';
import { constants, openSync, fstatSync, readFileSync, closeSync, realpathSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { staticCrtObjectMembers, archiveObjectBytes } from '../release/windows-linkage.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const targets = new Map([['aarch64-pc-windows-msvc', 'arm64'], ['x86_64-pc-windows-msvc', 'x64']]);
function readStable(file, expected) {
  const fd = openSync(file, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const before = fstatSync(fd, { bigint: true }); assert.ok(before.isFile() && before.size > 0n && before.size <= 1024n ** 3n);
    const bytes = readFileSync(fd), after = fstatSync(fd, { bigint: true });
    for (const key of ['dev', 'ino', 'size', 'mtimeNs', 'ctimeNs']) assert.equal(after[key], before[key], 'Provenance input changed while read');
    assert.equal(BigInt(bytes.length), before.size);
    if (expected) { assert.equal(hash(bytes), expected.sha256); assert.equal(bytes.length, expected.size_bytes); }
    return bytes;
  } finally { closeSync(fd); }
}
function python(code, args) {
  const result = spawnSync(path.join(root, '.venv/bin/python'), ['-I', '-B', '-c', code, ...args], { cwd: root, env: { PATH: '/usr/bin:/bin', LANG: 'C', LC_ALL: 'C' }, encoding: 'utf8', maxBuffer: 1024 * 1024, timeout: 120000 });
  assert.ifError(result.error); assert.equal(result.status, 0, 'Original provenance verifier failed: ' + result.stderr); return JSON.parse(result.stdout);
}
export function validateBuildReceipt(receipt) {
  assert.equal(receipt.schema_version, 1); assert.equal(receipt.qualification, 'locally-built-original-uv-unaccepted'); assert.equal(receipt.source_commit, '316c827e058c16b71d5c507a20729c2995a7bcce'); assert.equal(receipt.version, '0.13.7'); assert.equal(receipt.rust, '1.99.1'); assert.equal(receipt.publisher_redistribution_authority, 'unverified-external');
  assert.match(receipt.producer_sha256, /^[a-f0-9]{64}$/);
  assert.equal(receipt.records.length, 2); assert.deepEqual(new Set(receipt.records.map(row => row.target)), new Set(targets.keys()));
  for (const row of receipt.records) {
    assert.equal(row.target_execution, false); assert.equal(row.path, `target/${row.target}/release/uv.exe`); assert.equal(row.map.path, row.target + '.map');
    assert.match(row.sha256, /^[a-f0-9]{64}$/); assert.match(row.map.sha256, /^[a-f0-9]{64}$/); assert.ok(Number.isSafeInteger(row.size_bytes) && row.size_bytes > 0 && Number.isSafeInteger(row.map.size_bytes) && row.map.size_bytes > 0);
    assert.ok(row.command.includes('--offline') && row.command.includes('--locked') && row.command.includes('--release'));
    assert.equal(row.command[row.command.indexOf('--target') + 1], row.target); assert.equal(row.command[row.command.indexOf('--bin') + 1], 'uv');
    assert.ok(row.command.includes(`target.${row.target}.rustflags=["-C","target-feature=+crt-static"]`));
  }
  return receipt;
}
export function finalizeWindowsUv(directory, { write = true } = {}) {
  assert.equal(typeof write, 'boolean');
  const output = realpathSync(directory), buildBytes = readStable(path.join(output, 'build-receipt.json')), receipt = validateBuildReceipt(JSON.parse(buildBytes));
  assert.equal(receipt.producer_sha256, hash(readStable(path.join(root, 'scripts/runtime/prepare-windows-uv.py'))), 'Original source build recipe is stale');
  const sourceBytes = readStable(path.join(output, 'source-receipt.json')); assert.equal(hash(sourceBytes), receipt.source_receipt_sha256);
  assert.equal(receipt.header_overlay.path, 'windows-headers.vfs.json'); readStable(path.join(output, receipt.header_overlay.path), receipt.header_overlay);
  const sdk = realpathSync(path.join(root, '.artifacts/xwin-cache/xwin'));
  for (const row of receipt.header_overlay.headers) { assert.ok(typeof row.path === 'string' && !row.path.startsWith('/') && !row.path.includes('\\') && row.path.split('/').every(part => part !== '' && part !== '.' && part !== '..')); const actual = realpathSync(path.join(sdk, row.path)); assert.ok(actual.startsWith(sdk + path.sep)); readStable(actual, row); }
  assert.deepEqual(Object.keys(receipt.host_tools), ['mt.exe']); const manifestTool = receipt.host_tools['mt.exe']; assert.equal(manifestTool.execution_architecture, 'darwin-arm64'); assert.equal(manifestTool.path, 'tools/mt.exe'); assert.equal(realpathSync(path.join(output, manifestTool.path)), manifestTool.source); const manifestBytes = readStable(manifestTool.source, manifestTool); assert.ok(manifestBytes.subarray(0, 8).equals(Buffer.from('cffaedfe0c000001', 'hex')));
  // Replay all 654 original registry archives, rather than trusting generated
  // checksum files or only files read by this particular compiler target.
  const verified = python('import importlib.util,json,sys;from pathlib import Path;s=importlib.util.spec_from_file_location("uvbuild",sys.argv[1]);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);o=Path(sys.argv[2]);r=json.loads((o/"source-receipt.json").read_text());assert m.source_inventory(o/"source")==r["source_tree"];print(json.dumps(m.verify_vendor(o,Path(sys.argv[3]))))', [path.join(root, 'scripts/runtime/prepare-windows-uv.py'), output, path.join(root, '.artifacts/source-materials-data/package-sources-uv')]);
  if (receipt.vendor_inventory !== undefined) assert.deepEqual(verified, receipt.vendor_inventory);
  const records = [];
  for (const row of receipt.records) {
    const binary = path.join(output, row.path), bytes = readStable(binary, row), architecture = targets.get(row.target);
    const inspected = python('import json,sys;sys.path.insert(0,sys.argv[1]);from windows_pe import inspect_pe,system_dll;r=inspect_pe(open(sys.argv[2],"rb").read(),sys.argv[3]);assert r["imports"] and all(system_dll(n) for n in r["imports"]);assert not any(n.startswith(("vcruntime","msvcp","concrt","vcomp","msvcr")) for n in r["imports"]);print(json.dumps(r))', [path.join(root, 'scripts/runtime'), binary, architecture]);
    assert.equal(inspected.sha256, 'sha256:' + hash(bytes)); assert.equal(inspected.size, bytes.length);
    const mapBytes = readStable(path.join(output, row.map.path), row.map), members = staticCrtObjectMembers(mapBytes.toString('utf8')), libraries = [];
    for (const library of new Set(members.map(member => member.library))) {
      const base = library === 'libucrt' ? 'sdk/lib/ucrt' : 'crt/lib', arch = architecture === 'arm64' ? 'aarch64' : 'x86_64', file = path.join(root, '.artifacts/xwin-cache/xwin', base, arch, library + '.lib'), archive = readStable(file);
      const objects = archiveObjectBytes(archive, members.filter(member => member.library === library).map(member => member.object));
      libraries.push({ library, archive: { path: path.relative(root, file), sha256: hash(archive), size_bytes: archive.length }, members: objects.map(object => ({ name: object.member, sha256: hash(object.bytes), size_bytes: object.bytes.length })) });
    }
    records.push({ target: row.target, platform: 'win32/' + architecture, binary: { path: row.path, sha256: row.sha256, size_bytes: row.size_bytes }, map: row.map, imports: inspected.imports, profile: 'static-msvc-crt', private_crt_dlls: [], libraries, target_execution: false });
  }
  const toolchain = ['.artifacts/rustup/toolchains/1.99.1-aarch64-apple-darwin/bin/rustc', '.artifacts/rustup/toolchains/1.99.1-aarch64-apple-darwin/bin/cargo', '.artifacts/cargo/bin/cargo-xwin', '.artifacts/xwin-cache/clang-cl', '.artifacts/xwin-cache/lld-link'].map(name => { const actual = realpathSync(path.join(root, name)), bytes = readStable(actual); return { requested_path: name, resolved_path: actual, sha256: hash(bytes), size_bytes: bytes.length }; });
  const result = { schema_version: 1, qualification: 'original-source-crossbuild-linkage-not-native-acceptance', source_commit: receipt.source_commit, version: receipt.version, build_receipt_sha256: hash(buildBytes), source_receipt_sha256: hash(sourceBytes), vendor_inventory: verified, records, toolchain, host_tools: receipt.host_tools, generators: Object.fromEntries(['scripts/runtime/prepare-windows-uv.py', 'scripts/runtime/finalize-windows-uv.mjs', 'scripts/runtime/windows_pe.py', 'scripts/release/windows-linkage.mjs'].map(name => [name, hash(readStable(path.join(root, name)))])), license: 'LicenseRef-Microsoft-VisualStudio-2026-CRT', publisher_redistribution_authority: 'unverified-external', limitations: ['These are local builds of the exact original uv source, not reproduced upstream vendor binaries.', 'Windows target execution remains pending; component provenance does not establish publisher redistribution authority.'] };
  if (write) writeFileSync(path.join(output, 'linkage-receipt.json'), JSON.stringify(result, null, 2) + '\n'); return result;
}
export function verifyWindowsUv(directory) { return finalizeWindowsUv(directory, { write: false }); }
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) { assert.equal(process.argv.length, 3); const result = finalizeWindowsUv(process.argv[2]); console.log(JSON.stringify({ records: result.records.map(row => ({ platform: row.platform, sha256: row.binary.sha256, size_bytes: row.binary.size_bytes, crt_objects: row.libraries.reduce((sum, library) => sum + library.members.length, 0) })) })); }
