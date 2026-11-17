/** Reconcile the limited Perl guard-negation runner against frozen bytes. */
import { createHash } from 'node:crypto';
const sha = value => createHash('sha256').update(value).digest('hex');
const file = 'workers/ud/src/ud_agent/perl/graph_bridge.pl';
const testFile = 'tests/domain/perl/test_graph_bridge.py';

export function assessPerlGuards(report, source, hashes) {
  const errors = [];
  const result = { total: 0, killed: 0, equivalent: 0, errors };
  if (!Buffer.isBuffer(source) || !report || report.tool !== 'perl-guard-negation' || report.scope_complete !== false || !Array.isArray(report.inventory) || !Array.isArray(report.outcomes)) {
    errors.push('Perl targeted mutation report missing or malformed.'); return result;
  }
  if (hashes[file] !== sha(source) || report.test_sha256 !== hashes[testFile]) errors.push('Perl source or test fingerprint differs from frozen snapshot.');
  if (report.baseline?.status !== 0 || report.baseline?.passed !== true) errors.push('Perl mutation baseline did not pass.');
  const text = source.toString('latin1');
  const pattern = /\bfail\('[a-z_]+'\)[ \t\r\n\f\v]+(if|unless)\b/g;
  const expected = [];
  for (const match of text.matchAll(pattern)) {
    const original = match[1];
    const start = match.index + match[0].length - original.length;
    const definition = { end: start + original.length, operator: 'postfix_fail_guard_negation', original, replacement: original === 'if' ? 'unless' : 'if', start };
    expected.push({ id: `${file}#${start}`, file, source_sha256: sha(source), definition_sha256: sha(JSON.stringify(definition)), definition });
  }
  if (!expected.length || report.scheduled !== expected.length || report.inventory.length !== expected.length || report.outcomes.length !== expected.length) errors.push('Perl scheduled and recorded mutation counts do not match.');
  const inventory = new Map();
  for (const item of report.inventory) {
    if (!item || inventory.has(item.id)) { errors.push('Duplicate or invalid Perl mutant inventory.'); continue; }
    inventory.set(item.id, item);
  }
  for (const item of expected) {
    const recorded = inventory.get(item.id);
    if (!recorded || recorded.file !== item.file || recorded.source_sha256 !== item.source_sha256 || recorded.definition_sha256 !== item.definition_sha256 || JSON.stringify(recorded.definition && Object.fromEntries(Object.entries(recorded.definition).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0))) !== JSON.stringify(item.definition)) errors.push(`Perl mutation definition mismatch: ${item.id}`);
  }
  const seen = new Set();
  for (const outcome of report.outcomes) {
    result.total++;
    const item = inventory.get(outcome?.id);
    if (!item || seen.has(outcome.id) || outcome.definition_sha256 !== item.definition_sha256) { errors.push(`Unknown or duplicate Perl mutation outcome: ${outcome?.id}`); continue; }
    seen.add(outcome.id);
    if (outcome.status === 'Killed' && outcome.reason === 'assertion failure' && Array.isArray(outcome.tests) && outcome.tests.length > 0 && outcome.tests.every(test => typeof test === 'string' && test.length > 0)) result.killed++;
    else errors.push(`Perl ${outcome.status ?? 'missing status'}: ${outcome.id}`);
  }
  for (const item of expected) if (!seen.has(item.id)) errors.push(`Perl mutant has no outcome: ${item.id}`);
  return result;
}
