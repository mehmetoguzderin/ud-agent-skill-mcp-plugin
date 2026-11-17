import { posixTest } from '../fixtures/native-scope.mjs';
import { test, expect } from 'vitest';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileReceipt, sourceReceipt } from '../../scripts/release/candidate.mjs';
import { closeReleaseInterpreter, releasePythonCommand, releaseVerifierOwnedRoot, stageVerifierPrefix, verifyReleaseInterpreter } from '../../scripts/release/verifier-runtime.mjs';

test('private verifier staging rejects substituted runtime imports and extra files while excluding host pyc', () => {
  const root = mkdtempSync(path.join(os.tmpdir(), 'ud-verifier-files-'));
  try {
    const prefix = path.join(root, 'original'); mkdirSync(path.join(prefix, 'bin'), { recursive: true }); mkdirSync(path.join(prefix, 'lib/python3.15/__pycache__'), { recursive: true });
    writeFileSync(path.join(prefix, 'bin/python3.15'), 'fixture executable bytes'); writeFileSync(path.join(prefix, 'lib/python3.15/os.py'), '# original source\n'); writeFileSync(path.join(prefix, 'lib/python3.15/__pycache__/os.pyc'), 'untrusted ignored cache'); symlinkSync('python3.15', path.join(prefix, 'bin/python3'));
    const inventory = { files: ['bin/python3.15', 'lib/python3.15/os.py'].map(name => fileReceipt(prefix, name)), links: [{ path: 'bin/python3', linkname: 'python3.15', resolved_target: 'bin/python3.15' }] };
    const target = path.join(root, 'staged'); expect(stageVerifierPrefix(prefix, inventory, target)).toEqual({ files: 2, aliases: 1 });
    expect(readFileSync(path.join(target, 'bin/python3'), 'utf8')).toBe('fixture executable bytes');
    expect(() => readFileSync(path.join(target, 'lib/python3.15/__pycache__/os.pyc'))).toThrow(/ENOENT/);
    writeFileSync(path.join(prefix, 'lib/python3.15/os.py'), '# substituted source');
    expect(() => stageVerifierPrefix(prefix, inventory, path.join(root, 'changed'))).toThrow(/receipt mismatch/);
    writeFileSync(path.join(prefix, 'lib/python3.15/os.py'), '# original source\n'); writeFileSync(path.join(prefix, 'lib/python3.15/sitecustomize.py'), 'unapproved startup code');
    expect(() => stageVerifierPrefix(prefix, inventory, path.join(root, 'extra'))).toThrow(/unapproved file/);
    expect(() => releasePythonCommand({}, ['untrusted.py'])).toThrow(/authenticated privately staged/);
    expect(() => releaseVerifierOwnedRoot({})).toThrow(/authenticated verifier runtime/);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('reviewed optional payload exclusions still authenticate original bytes and are absent from the private prefix', () => {
  const root = mkdtempSync(path.join(os.tmpdir(), 'ud-verifier-optional-'));
  try {
    const prefix = path.join(root, 'original'); mkdirSync(prefix);
    writeFileSync(path.join(prefix, 'python.exe'), 'required runtime'); writeFileSync(path.join(prefix, 'optional.dll'), 'original unused optional bytes');
    const files = ['python.exe', 'optional.dll'].map(name => fileReceipt(prefix, name));
    const optional = files[1], inventory = { entrypoint: 'python.exe', files, links: [], excluded_optional_payloads: [{ path: optional.path, sha256: optional.sha256, size: optional.size, reason: 'Source-bound optional component with no retained imports.' }] };
    const target = path.join(root, 'private'); expect(stageVerifierPrefix(prefix, inventory, target)).toEqual({ files: 1, aliases: 0, excluded_optional_files: 1 });
    expect(readFileSync(path.join(target, 'python.exe'), 'utf8')).toBe('required runtime'); expect(existsSync(path.join(target, 'optional.dll'))).toBe(false);
    writeFileSync(path.join(prefix, 'optional.dll'), 'substituted excluded bytes');
    expect(() => stageVerifierPrefix(prefix, inventory, path.join(root, 'changed'))).toThrow(/receipt mismatch/);
    expect(() => stageVerifierPrefix(prefix, { ...inventory, excluded_optional_payloads: [{ ...inventory.excluded_optional_payloads[0], path: 'python.exe' }] }, path.join(root, 'bad'))).toThrow(/optional exclusion/);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

function approvedFixture(run) {
  const root = mkdtempSync(path.join(os.tmpdir(), 'ud-verifier-admission-'));
  try {
    const release = path.join(root, 'release'), prefix = path.join(root, 'prefix'), scratch = path.join(root, 'scratch');
    mkdirSync(release); mkdirSync(path.join(prefix, 'bin'), { recursive: true }); mkdirSync(scratch);
    const python = path.join(prefix, 'bin/python'); writeFileSync(python, 'fixture'); chmodSync(python, 0o700);
    const archive = { name: 'python.tar', sha256: 'a'.repeat(64), size: 7, url: 'https://example.invalid/python.tar' };
    writeFileSync(path.join(release, 'generator.py'), '# fixture\n');
    writeFileSync(path.join(release, 'origin.json'), JSON.stringify({ assets: [{ name: archive.name, digest: 'sha256:' + archive.sha256, size: archive.size, browser_download_url: archive.url }] }));
    const generator = fileReceipt(root, 'release/generator.py'), origin = fileReceipt(root, 'release/origin.json');
    const platform = `${process.platform}-${process.arch}`, inventory = { schema_version: 1, qualification: 'publisher-archive-verifier-prefix-inventory-not-approval', platform, version: 'fixture', site_initialization: 'disabled-with-S', pycache_policy: 'private-empty-prefix-with-B', unresolved_dependencies: [], files: [fileReceipt(prefix, 'bin/python')], links: [], native_files: [{ path: 'bin/python', architectures: [platform] }], entrypoint: 'bin/python', generator, origin: { archive, release_receipt: origin } };
    writeFileSync(path.join(release, 'inventory.json'), JSON.stringify(inventory)); const inventoryReceipt = fileReceipt(root, 'release/inventory.json');
    writeFileSync(path.join(release, 'approval.json'), JSON.stringify({ qualification: 'independent-verifier-runtime-origin-and-byte-closure-review', decision: 'approved-for-release-verification', inventory: inventoryReceipt, origin_archive_sha256: archive.sha256, generator_sha256: generator.sha256 }));
    const approval = fileReceipt(root, 'release/approval.json');
    writeFileSync(path.join(release, 'verifier-runtimes.lock.json'), JSON.stringify({ schema_version: 1, purpose: 'release-verifier-python', profiles: [{ id: 'fixture', platform, status: 'approved', inventory: inventoryReceipt, approval }] }));
    run({ root, source: sourceReceipt(root), python, scratch });
  } finally { rmSync(root, { recursive: true, force: true }); }
}

posixTest('approved verifier staging is admitted before writing and stays inside its supplied scratch', () => approvedFixture(({ root, source, python, scratch }) => {
    let requested = 0;
    expect(() => verifyReleaseInterpreter(root, source, { python, scratchParent: scratch, beforeStage: size => { requested = size; throw new Error('no room'); } })).toThrow('no room');
    expect(requested).toBe(7); expect(readdirSync(scratch)).toEqual([]);
    const session = verifyReleaseInterpreter(root, source, { python, scratchParent: scratch, beforeStage: size => expect(size).toBe(7) });
    expect(releasePythonCommand(session, []).executable.startsWith(realpathSync(scratch) + path.sep)).toBe(true);
    expect(releasePythonCommand(session, []).executable.startsWith(releaseVerifierOwnedRoot(session) + path.sep)).toBe(true);
    closeReleaseInterpreter(session); expect(readdirSync(scratch)).toEqual([]);
    expect(() => releaseVerifierOwnedRoot(session)).toThrow(/authenticated verifier runtime/);
}));

if (process.platform === 'win32') test('verifier admission refuses absent POSIX executable authority before staging any bytes', () => approvedFixture(({ source, root, python, scratch }) => {
  let admitted = false;
  expect(() => verifyReleaseInterpreter(root, source, { python, scratchParent: scratch, beforeStage: () => { admitted = true; } })).toThrow('Verifier runtime executable is not in the approved closure.');
  expect(admitted).toBe(false);expect(readdirSync(scratch)).toEqual([]);expect(readFileSync(python, 'utf8')).toBe('fixture');
}));
