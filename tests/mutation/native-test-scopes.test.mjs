import { test, expect } from 'vitest';
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createPosixTest } from '../fixtures/native-scope.mjs';
import { NATIVE_TEST_HELPER, NATIVE_TEST_MANIFEST, nativeTestApplicability, verifyNativeTestApplicability } from '../../scripts/quality/native-test-scopes.mjs';
import { acceptanceInputHash, compileAcceptanceInventory, parseDiscoveryTranscript, verifyLocalAcceptanceDiscovery } from '../../scripts/release/discover-acceptance.mjs';
import { fileReceipt, sha256, sourceReceipt } from '../../scripts/release/candidate.mjs';
import { reconcileSuiteInventory } from '../../scripts/release/acceptance.mjs';
import { originalVitestOutcomes, reconcileOriginalOutcomes } from '../../scripts/quality/original-outcomes.mjs';
import { discoveryFixture } from '../release/discovery-fixture.mjs';

const repository = path.resolve(import.meta.dirname, '../..');
function fixture(platform = 'win32') {
  const root = mkdtempSync(path.join(os.tmpdir(), 'ud-native-scopes-'));
  const put = (name, bytes) => { mkdirSync(path.dirname(path.join(root, name)), { recursive: true }); writeFileSync(path.join(root, name), bytes); };
  put('tests/fixture.test.mjs', `import {test} from 'vitest';\nimport {posixTest} from './fixtures/native-scope.mjs';\ntest('portable',()=>{});\nposixTest('native owner',()=>{});\nposixTest.each([1,2])('native row %s',()=>{});\n`);
  mkdirSync(path.join(root, 'tests/fixtures')); copyFileSync(path.join(repository, NATIVE_TEST_HELPER), path.join(root, NATIVE_TEST_HELPER));
  const manifest = { schema_version: 1, scopes: [{ source: 'tests/fixture.test.mjs', supported_os: ['darwin', 'linux'], purpose: 'Real POSIX ownership and native process authority.' }] };
  put(NATIVE_TEST_MANIFEST, JSON.stringify(manifest));
  const catalog = discoveryFixture(root, platform === 'win32' ? ['portable'] : ['portable', 'native owner', 'native row 1', 'native row 2']);
  catalog.environment.os = platform;
  catalog.native_applicability = nativeTestApplicability(root, platform);
  return { root, put, manifest, catalog, cleanup: () => rmSync(root, { recursive: true, force: true }) };
}
const requirements = { schema_version: 1, required_suites: ['unit'] };
const observations = catalog => catalog.tests.map(({ runner, source, name }) => ({ runner, source, name, status: 'passed' }));

test('POSIX declarations retain the actual test and each API; Windows adds no pass or skipped registration', () => {
  const registrations = [], register = (...args) => registrations.push(args);
  register.each = values => (...args) => registrations.push([values, ...args]);
  for (const platform of ['linux', 'darwin']) expect(createPosixTest(register, platform)).toBe(register);
  const foreign = createPosixTest(register, 'win32');
  const body = () => { throw new Error('foreign body ran'); };
  expect(foreign('foreign native body', body)).toBeUndefined();
  expect(foreign.each([1, 2])('parameter %s', body)).toBeUndefined();
  expect(foreign.each`value\n${1}`('tagged $value', body)).toBeUndefined();
  expect(registrations).toEqual([]); expect(foreign.skip).toBeUndefined(); expect(foreign.only).toBeUndefined();
  for (const platform of ['aix', 'freebsd', '', undefined]) expect(() => createPosixTest(register, platform)).toThrow(/supported native platform/);
  expect(() => createPosixTest({}, 'win32')).toThrow(/registrar/);
});

test('foreign declaration obligations retain source, helper and manifest hashes without entering local case outcomes', () => {
  const f = fixture();
  try {
    const receipt = f.catalog.native_applicability, scope = receipt.scopes[0];
    expect(receipt.manifest).toEqual(fileReceipt(f.root, NATIVE_TEST_MANIFEST));
    expect(receipt.declaration_helper).toEqual(fileReceipt(f.root, NATIVE_TEST_HELPER));
    expect(scope.source_sha256).toBe(fileReceipt(f.root, scope.source).sha256);
    expect(scope.status).toBe('pending-native'); expect(scope.declarations.map(row => [row.line, row.registration])).toEqual([[4, 'test'], [5, 'each']]);
    expect(scope.declarations.every(row => /^[a-f0-9]{64}$/.test(row.declaration_sha256))).toBe(true);
    const completed = reconcileOriginalOutcomes(f.root, f.catalog, observations(f.catalog));
    expect(completed).toHaveLength(1); expect(completed[0].name).toBe('portable');
    expect(f.catalog.tests.some(row => row.status === 'pending-native')).toBe(false);
    expect(() => reconcileOriginalOutcomes(f.root, f.catalog, [...observations(f.catalog), { runner: 'vitest', source: scope.source, name: 'native owner', status: 'passed' }])).toThrow(/unexpected/);
    const forged = structuredClone(f.catalog); forged.native_applicability.scopes[0].status = 'passed';
    expect(() => reconcileOriginalOutcomes(f.root, forged, observations(f.catalog))).toThrow(/native obligations differ/);
  } finally { f.cleanup(); }
});

test('manifest, helper, declarations and native platform cannot be changed beneath an applicability receipt', () => {
  for (const target of [NATIVE_TEST_MANIFEST, NATIVE_TEST_HELPER, 'tests/fixture.test.mjs']) {
    const f = fixture();
    try {
      const filename = path.join(f.root, target); writeFileSync(filename, readFileSync(filename, 'utf8') + '\n');
      expect(() => verifyNativeTestApplicability(f.root, f.catalog.native_applicability, 'win32')).toThrow(/native obligations differ/);
    } finally { f.cleanup(); }
  }
  const f = fixture();
  try {
    expect(() => verifyNativeTestApplicability(f.root, f.catalog.native_applicability, 'linux')).toThrow(/native obligations differ/);
    expect(() => nativeTestApplicability(f.root, 'unsupported')).toThrow(/unsupported native platform/);
    expect(() => verifyNativeTestApplicability(f.root, undefined, 'win32')).toThrow(/native obligations differ/);
    f.put(NATIVE_TEST_MANIFEST, JSON.stringify({ ...f.manifest, scopes: [] }));
    expect(() => nativeTestApplicability(f.root, 'win32')).toThrow(/manifest differs/);
    f.put(NATIVE_TEST_MANIFEST, JSON.stringify({ ...f.manifest, scopes: [{ ...f.manifest.scopes[0], supported_os: ['win32'] }] }));
    expect(() => nativeTestApplicability(f.root, 'win32')).toThrow(/scope platforms/);
  } finally { f.cleanup(); }
});

test('native manifest declaration coverage and reviewed scope shape are mandatory', () => {
  const f = fixture();
  try {
    const row = f.manifest.scopes[0];
    for (const scopes of [[row, row], [{ ...row, source: 'tests/../foreign.test.mjs' }], [{ ...row, purpose: '' }], [{ ...row, supported_os: ['darwin', 'linux', 'win32'] }], [{ ...row, status: 'passed' }]]) {
      f.put(NATIVE_TEST_MANIFEST, JSON.stringify({ schema_version: 1, scopes }));
      expect(() => nativeTestApplicability(f.root, 'win32')).toThrow(/Native test applicability/);
    }
    f.put(NATIVE_TEST_MANIFEST, JSON.stringify(f.manifest));
    f.put('tests/undeclared.test.mjs', "import {posixTest} from './fixtures/native-scope.mjs';posixTest('unlisted',()=>{});\n");
    expect(() => nativeTestApplicability(f.root, 'win32')).toThrow(/manifest differs/);
    rmSync(path.join(f.root, NATIVE_TEST_MANIFEST)); rmSync(path.join(f.root, NATIVE_TEST_HELPER));
    expect(() => nativeTestApplicability(f.root, 'win32', sourceReceipt(f.root))).toThrow(/both required/);
  } finally { f.cleanup(); }
});

test('frozen inventory and signed unit reconciliation cannot discard or complete foreign native obligations', () => {
  const f = fixture();
  try {
    const inventory = compileAcceptanceInventory(f.root, f.catalog, requirements), suite = inventory.suites[0];
    expect(suite.tests).toHaveLength(1); expect(inventory.native_applicability).toEqual(f.catalog.native_applicability);
    expect(suite.native_applicability).toEqual(f.catalog.native_applicability);
    const report = { suite_id: 'unit', environment: f.catalog.environment, tests: reconcileOriginalOutcomes(f.root, f.catalog, observations(f.catalog)), native_applicability: f.catalog.native_applicability, pending_native_scopes: f.catalog.native_applicability.scopes };
    expect(() => reconcileSuiteInventory(suite, report)).toThrow(/foreign native unit obligations remain pending/);
    expect(() => reconcileSuiteInventory(suite, { ...report, pending_native_scopes: [] })).toThrow(/omitted or changed/);
    const discarded = { ...report }; delete discarded.native_applicability;
    expect(() => reconcileSuiteInventory(suite, discarded)).toThrow(/receipt differs/);
    f.put('.artifacts/catalog.json', JSON.stringify(f.catalog));
    inventory.discovery = { schema_version: 1, algorithm: 'native-runner-discovery-v1', catalog: fileReceipt(f.root, '.artifacts/catalog.json'), schedules: [] };
    expect(() => verifyLocalAcceptanceDiscovery(f.root, inventory, requirements)).not.toThrow();
    delete inventory.native_applicability;
    expect(() => verifyLocalAcceptanceDiscovery(f.root, inventory, requirements)).toThrow(/frozen native obligations/);
  } finally { f.cleanup(); }
  const native = fixture('linux');
  try {
    const suite = compileAcceptanceInventory(native.root, native.catalog, requirements).suites[0];
    const report = { suite_id: 'unit', environment: native.catalog.environment, tests: reconcileOriginalOutcomes(native.root, native.catalog, observations(native.catalog)), native_applicability: native.catalog.native_applicability, pending_native_scopes: [] };
    expect(report.tests).toHaveLength(4); expect(() => reconcileSuiteInventory(suite, report)).not.toThrow();
    expect(() => reconcileSuiteInventory(suite, { ...report, environment: { os: 'win32' } })).toThrow(/execution platform differs/);
  } finally { native.cleanup(); }
});

test('native scoping never exempts an empty applicable source file or a skipped actual case', () => {
  const f = fixture();
  try {
    f.put('tests/other.test.mjs', "test('actual other case',()=>{});\n");
    const transcript = f.catalog.transcripts[0]; transcript.stdout = JSON.stringify([{ file: path.join(f.root, 'tests/other.test.mjs'), name: 'actual other case' }]); transcript.stdout_sha256 = sha256(transcript.stdout);
    f.catalog.tests = parseDiscoveryTranscript(f.root, transcript); f.catalog.input_sha256 = acceptanceInputHash(sourceReceipt(f.root));
    expect(() => compileAcceptanceInventory(f.root, f.catalog, requirements)).toThrow(/test file omitted by runners: tests\/fixture/);
    expect(() => originalVitestOutcomes(f.root, { success: true, numFailedTests: 0, numPendingTests: 1, numTodoTests: 0, numFailedTestSuites: 0, numPendingTestSuites: 0 })).toThrow(/skipped/);
  } finally { f.cleanup(); }
});
