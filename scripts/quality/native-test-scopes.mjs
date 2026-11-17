/** Bind foreign native original-test obligations to reviewed source declarations. */
import path from 'node:path';
import { existsSync } from 'node:fs';
import ts from 'typescript-compat';
import { fileReceipt, readRecordedBytes, sha256, sourceReceipt } from '../release/candidate.mjs';
import { canonicalJson } from '../release/http-transports.mjs';

export const NATIVE_TEST_MANIFEST = 'quality/native-test-scopes.json';
export const NATIVE_TEST_HELPER = 'tests/fixtures/native-scope.mjs';
const TEST_SOURCE = /^tests\/.*\.test\.[cm]?[jt]sx?$/;
const POSIX = ['darwin', 'linux'];
const need = (ok, message) => { if (!ok) throw new Error('Native test applicability: ' + message); };
const keys = value => value && !Array.isArray(value) && typeof value === 'object' ? Object.keys(value).sort().join(',') : '';

function declarations(source, text) {
  const tree = ts.createSourceFile(source, text, ts.ScriptTarget.Latest, true, /\.tsx?$/.test(source) ? ts.ScriptKind.TS : ts.ScriptKind.JS);
  const names = new Set();
  for (const node of tree.statements) {
    if (!ts.isImportDeclaration(node) || !ts.isStringLiteral(node.moduleSpecifier)) continue;
    const specifier = node.moduleSpecifier.text;
    if (!specifier.startsWith('.') || path.posix.normalize(path.posix.join(path.posix.dirname(source), specifier)) !== NATIVE_TEST_HELPER) continue;
    const bindings = node.importClause?.namedBindings;
    need(bindings && ts.isNamedImports(bindings), `scope helper must use named imports: ${source}`);
    for (const item of bindings.elements) if ((item.propertyName ?? item.name).text === 'posixTest') names.add(item.name.text);
  }
  if (!names.size) return undefined;
  need(tree.parseDiagnostics.length === 0, `native declarations do not parse: ${source}`);
  const rows = [];
  const direct = node => ts.isIdentifier(node) && names.has(node.text);
  const each = node => ts.isPropertyAccessExpression(node) && direct(node.expression) && node.name.text === 'each';
  function visit(node) {
    if (ts.isCallExpression(node)) {
      const kind = direct(node.expression) ? 'test'
        : ts.isCallExpression(node.expression) && each(node.expression.expression) ? 'each'
          : ts.isTaggedTemplateExpression(node.expression) && each(node.expression.tag) ? 'each' : undefined;
      if (kind) {
        const start = tree.getLineAndCharacterOfPosition(node.getStart(tree));
        rows.push({ line: start.line + 1, column: start.character + 1, registration: kind, declaration_sha256: sha256(node.getText(tree)) });
      }
    }
    ts.forEachChild(node, visit);
  }
  visit(tree);
  need(rows.length > 0 && rows.length <= 4096, `scope helper import has no bounded explicit declarations: ${source}`);
  return rows;
}

/** These are source declaration obligations, never discovered/executed cases. */
export function nativeTestApplicability(root, platform, source) {
  // Legacy reconciliation fixtures can contain just one root-level test file,
  // outside the release source roots, and no native declaration mechanism.
  if (source === undefined && !existsSync(path.join(root, NATIVE_TEST_MANIFEST)) && !existsSync(path.join(root, NATIVE_TEST_HELPER))) return undefined;
  source ??= sourceReceipt(root);
  const inputs = new Map(source.files.map(row => [row.path, row]));
  const manifestRecord = inputs.get(NATIVE_TEST_MANIFEST), helperRecord = inputs.get(NATIVE_TEST_HELPER);
  const actual = new Map();
  for (const record of source.files.filter(row => TEST_SOURCE.test(row.path))) {
    const text = readRecordedBytes(root, record, 4 * 1024 ** 2).toString('utf8');
    if (!text.includes('native-scope.mjs')) continue;
    const sites = declarations(record.path, text);
    if (sites) actual.set(record.path, sites);
  }
  // Tiny source-bound verifier fixtures can have no native declarations at all.
  if (!manifestRecord && !helperRecord && actual.size === 0) return undefined;
  need(manifestRecord && helperRecord, 'manifest and declaration helper are both required');
  need(['darwin', 'linux', 'win32'].includes(platform), 'unsupported native platform');
  const manifest = JSON.parse(readRecordedBytes(root, manifestRecord, 1024 ** 2).toString('utf8'));
  readRecordedBytes(root, helperRecord, 1024 ** 2);
  need(keys(manifest) === 'schema_version,scopes' && manifest.schema_version === 1 && Array.isArray(manifest.scopes) && manifest.scopes.length <= 1024, 'invalid source-owned manifest');
  const declared = new Map();
  for (const row of manifest.scopes) {
    need(keys(row) === 'purpose,source,supported_os' && typeof row.source === 'string' && TEST_SOURCE.test(row.source) && !row.source.includes('\\') && !row.source.split('/').some(part => !part || part === '.' || part === '..'), 'invalid native scope source');
    need(typeof row.purpose === 'string' && row.purpose.trim() === row.purpose && row.purpose.length > 0 && row.purpose.length <= 2048 && !/[\x00-\x1f]/.test(row.purpose), 'native scope needs a bounded purpose');
    need(Array.isArray(row.supported_os) && canonicalJson([...row.supported_os].sort()) === canonicalJson(POSIX), 'scope platforms differ from the POSIX declaration helper');
    need(!declared.has(row.source) && inputs.has(row.source), 'duplicate or missing native scope source');
    declared.set(row.source, row);
  }
  need(canonicalJson([...declared.keys()].sort()) === canonicalJson([...actual.keys()].sort()), 'manifest differs from explicit source-native declarations');
  const scopes = [...declared.values()].sort((a, b) => a.source.localeCompare(b.source, 'en')).map(row => ({
    source: row.source, source_sha256: inputs.get(row.source).sha256, purpose: row.purpose, supported_os: [...POSIX],
    status: platform === 'win32' ? 'pending-native' : 'applicable-native', declarations: actual.get(row.source),
  }));
  return { schema_version: 1, qualification: 'source-bound-native-obligations-no-outcomes', environment_os: platform,
    manifest: fileReceipt(root, NATIVE_TEST_MANIFEST), declaration_helper: fileReceipt(root, NATIVE_TEST_HELPER), scopes };
}

export function verifyNativeTestApplicability(root, recorded, platform, source) {
  const expected = nativeTestApplicability(root, platform, source);
  need(expected === undefined ? recorded === undefined : recorded !== undefined && canonicalJson(recorded) === canonicalJson(expected), 'recorded native obligations differ from current source and platform');
  return expected;
}
