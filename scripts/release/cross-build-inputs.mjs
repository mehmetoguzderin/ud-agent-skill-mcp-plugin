/** Preserve the original cross-build recipe and its exact binary subjects. */
import { chmodSync, copyFileSync, existsSync, lstatSync, mkdirSync, readdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileReceipt, readRecordedBytes, safeRelative } from './candidate.mjs';
import { releasePlatforms } from './host-adapters.mjs';
import { OPEN_WINDOWS_PROFILE, OPEN_WINDOWS_TARGETS, verifyOpenWindowsMap, verifyWindowsBootstrapImports } from './windows-linkage.mjs';

function crossBuildPlatforms(receipt) {
  const platforms = Object.keys(receipt.platforms ?? {}).sort();
  const selected = platforms.filter(platform => platform !== 'darwin-x64');
  insist(selected.length === releasePlatforms.length && releasePlatforms.every(platform => selected.includes(platform)), 'Cross-build recipe has no complete original platform inventory.');
  return platforms;
}
function insist(value, message) { if (!value) throw new Error(message); }

function openWindowsMaps(cross) {
  if (!cross.windows_toolchain) return [];
  insist(cross.windows_toolchain.path === 'runtime/materials/windows-open-toolchain.lock.json', 'Windows cross-build toolchain lock differs.');
  return Object.entries(OPEN_WINDOWS_TARGETS).flatMap(([platform, target]) => {
    const linkage = cross.windows_linkage?.[platform];
    insist(linkage?.profile === OPEN_WINDOWS_PROFILE && linkage.target === target && linkage.target_execution === false, 'Windows cross-build linkage profile differs.');
    return ['ud-agent', 'ud-agent-guard'].map(name => {
      const object = linkage.objects?.[name];
      insist(object?.profile === OPEN_WINDOWS_PROFILE && object.binary_sha256 === cross.platforms[platform]?.[name]?.sha256 && object.private_crt_dlls?.length === 0, 'Windows link map does not bind the original executable.');
      verifyWindowsBootstrapImports(object.system_imports, OPEN_WINDOWS_PROFILE);
      safeRelative(object.map?.path);
      return { platform, name, target, map: object.map };
    });
  });
}

function verifyMap(root, record, target) {
  const map = JSON.parse(readRecordedBytes(root, record, 8 * 1024 ** 2).toString('utf8'));
  insist(map.format === 'lld-link-map' && typeof map.contents === 'string', 'Windows link map format differs.');
  verifyOpenWindowsMap(map.contents, 'llvm-mingw', target);
}

/** Reuse an exact retained build when its disposable original target is gone. */
/** @param {string} root @param {string} receiptPath @param {{retainedRoot?: string,names?: string[]}} [options] */
export function resolveCrossBuildInputs(root, receiptPath, { retainedRoot, names = ['ud-agent', 'ud-agent-guard'] } = {}) {
  root = path.resolve(root);
  insist(Array.isArray(names) && names.length > 0 && new Set(names).size === names.length && names.every(name => ['ud-agent', 'ud-agent-guard'].includes(name)), 'Cross-build binary selection is invalid.');
  const input = fileReceipt(root, receiptPath), bytes = readRecordedBytes(root, input, 16 * 1024 ** 2), cross = JSON.parse(bytes.toString('utf8'));
  insist(cross.schema_version === 1 && /^[a-f0-9]{64}$/.test(cross.source_sha256 ?? ''), 'Cross-build recipe has no complete original platform inventory.');
  const platforms = crossBuildPlatforms(cross);
  const fallback = path.resolve(retainedRoot ?? path.join(root, '.artifacts', `native-inputs-${input.sha256.slice(0, 8)}`));
  let retained;
  function retainedInputs() {
    if (retained) return retained;
    const relative = path.relative(root, fallback).split(path.sep).join('/');
    safeRelative(relative);
    // Validate every parent through the original root before accepting the
    // separate content-addressed copy as a replacement for missing outputs.
    fileReceipt(root, `${relative}/INPUTS.json`);
    const verified = verifyRetainedCrossBuildInputs(fallback);
    insist(verified.cross_build_receipt_sha256 === input.sha256 && verified.source_sha256 === cross.source_sha256, 'Retained cross-build recipe differs from the original.');
    retained = JSON.parse(readRecordedBytes(fallback, fileReceipt(fallback, 'INPUTS.json')).toString('utf8'));
    return retained;
  }
  const binaries = platforms.flatMap(platform => names.map(name => {
    const row = cross.platforms[platform][name]; safeRelative(row?.path);
    const original = path.join(root, ...row.path.split('/'));
    // An existing corrupt input is a hard error; only a genuinely absent
    // disposable build output may be supplied by its retained equivalent.
    const exists = lstatSync(original, { throwIfNoEntry: false }) !== undefined;
    if (exists) {
      const actual = fileReceipt(root, row.path);
      insist(actual.sha256 === row.sha256 && actual.executable, 'Cross-build subject differs from its original recipe.');
      return { platform, name, original_path: row.path, path: original, sha256: actual.sha256, size: actual.size, executable: actual.executable };
    }
    const item = retainedInputs().binaries.find(value => value.platform === platform && value.name === name);
    insist(item?.original_path === row.path && item.sha256 === row.sha256, 'Retained cross-build subject differs from its original recipe.');
    return { platform, name, original_path: row.path, path: path.join(fallback, item.path), sha256: item.sha256, size: item.size, executable: true };
  }));
  const maps = openWindowsMaps(cross).map(({ platform, name, target, map }) => {
    if (lstatSync(path.join(root, map.path), { throwIfNoEntry: false })) {
      verifyMap(root, map, target);
      return { platform, name, root, record: map };
    }
    const record = retainedInputs().link_maps?.find(row => row.platform === platform && row.name === name);
    insist(record?.sha256 === map.sha256, 'Retained Windows link map differs from the original recipe.');
    return { platform, name, root: fallback, record };
  });
  return { cross, receipt: input, binaries, maps };
}

/** @param {string} root @param {string} receiptPath @param {string} output @param {{retainedRoot?: string}} [options] */
export function retainCrossBuildInputs(root, receiptPath, output, options = {}) {
  insist(!existsSync(output), 'Retained cross-build output must be new.');
  // A retained receipt is the complete recipe even when callers
  // subsequently select only one executable kind for an assembly stage.
  const resolved = resolveCrossBuildInputs(root, receiptPath, { retainedRoot: options.retainedRoot }), { cross } = resolved;
  const bytes = readRecordedBytes(root, resolved.receipt, 16 * 1024 ** 2);
  // Verify every subject before writing any retained output. Original paths
  // remain in the unmodified recipe; the separate manifest locates copies.
  const binaries = resolved.binaries.map(({ path: source, ...item }) => ({ ...item, source, path: `files/${item.sha256}` }));
  mkdirSync(path.join(output, 'files'), { recursive: true });
  writeFileSync(path.join(output, 'cross-build-receipt.json'), bytes, { flag: 'wx', mode: 0o444 });
  for (const row of binaries) {
    const target = path.join(output, row.path);
    if (!existsSync(target)) { copyFileSync(row.source, target); chmodSync(target, 0o555); }
    const actual = fileReceipt(output, row.path);
    insist(actual.sha256 === row.sha256 && actual.size === row.size && actual.executable, 'Cross-build subject changed while retaining it.');
  }
  const linkMaps = resolved.maps.map(({ platform, name, root: mapRoot, record }) => {
    const target = 'maps/' + record.sha256 + '.json';
    mkdirSync(path.join(output, 'maps'), { recursive: true });
    const destination = path.join(output, target);
    if (!existsSync(destination)) writeFileSync(destination, readRecordedBytes(mapRoot, record, 8 * 1024 ** 2), { flag: 'wx', mode: 0o444 });
    return { platform, name, ...fileReceipt(output, target) };
  });
  const result = { schema_version: 1, qualification: 'retained-original-cross-build-recipe-and-binary-inputs', source_sha256: cross.source_sha256, cross_build_receipt: fileReceipt(output, 'cross-build-receipt.json'), binaries: binaries.map(({ source, ...item }) => item), ...(linkMaps.length ? { link_maps: linkMaps } : {}) };
  writeFileSync(path.join(output, 'INPUTS.json'), JSON.stringify(result, null, 2) + '\n', { flag: 'wx', mode: 0o444 });
  return fileReceipt(output, 'INPUTS.json');
}

export function verifyRetainedCrossBuildInputs(root) {
  const manifest = JSON.parse(readRecordedBytes(root, fileReceipt(root, 'INPUTS.json')).toString('utf8')), cross = JSON.parse(readRecordedBytes(root, manifest.cross_build_receipt).toString('utf8'));
  const platforms = crossBuildPlatforms(cross);
  insist(manifest.schema_version === 1 && manifest.qualification === 'retained-original-cross-build-recipe-and-binary-inputs' && manifest.source_sha256 === cross.source_sha256 && manifest.binaries?.length === platforms.length * 2, 'Retained cross-build inventory differs.');
  const expected = new Set(['INPUTS.json', 'cross-build-receipt.json']), seen = new Set();
  for (const item of manifest.binaries) {
    const key = item.platform + '/' + item.name, original = cross.platforms[item.platform]?.[item.name];
    insist(platforms.includes(item.platform) && ['ud-agent', 'ud-agent-guard'].includes(item.name) && !seen.has(key) && item.original_path === original?.path && item.sha256 === original.sha256 && item.path === 'files/' + item.sha256 && item.executable === true, 'Retained binary has a duplicate or foreign original identity.'); seen.add(key);
    const actual = fileReceipt(root, item.path); insist(actual.sha256 === item.sha256 && actual.size === item.size && actual.executable, 'Retained binary differs.'); expected.add(item.path);
  }
  const maps = openWindowsMaps(cross);
  insist((manifest.link_maps?.length ?? 0) === maps.length, 'Retained Windows link map inventory differs.');
  for (const { platform, name, target, map } of maps) {
    const matches = manifest.link_maps.filter(row => row.platform === platform && row.name === name);
    insist(matches.length === 1 && matches[0].path === 'maps/' + map.sha256 + '.json' && matches[0].sha256 === map.sha256 && matches[0].size === map.size, 'Retained Windows link map has a foreign original identity.');
    verifyMap(root, matches[0], target);
    expected.add(matches[0].path);
  }
  function walk(folder, prefix = '') {
    for (const name of readdirSync(folder)) { const relative = prefix + name, file = path.join(folder, name), info = lstatSync(file); insist(!info.isSymbolicLink(), 'Retained input contains a link.'); if (info.isDirectory()) { insist(relative === 'files' || relative === 'maps' && maps.length, 'Retained input has an unlisted directory.'); walk(file, relative + '/'); } else { insist(info.isFile() && expected.delete(relative), 'Retained input has an unlisted file.'); } }
  }
  walk(root); insist(expected.size === 0, 'Retained input omits files.');
  return { source_sha256: manifest.source_sha256, cross_build_receipt_sha256: manifest.cross_build_receipt.sha256 };
}
