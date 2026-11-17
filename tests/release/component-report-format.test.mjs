import { test } from 'vitest';
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileReceipt, sourceReceipt, sha256 } from '../../scripts/release/candidate.mjs';
import { canonicalJson } from '../../scripts/release/http-transports.mjs';
import { conditionalPublisherComponents } from '../../scripts/release/publisher-authority.mjs';

// These are post-replay fixture subjects, not source or publisher certification.
function fixture() {
  const root = mkdtempSync(path.join(os.tmpdir(), 'ud-component-report-format-'));
  const write = (name, value) => { const file = path.join(root, name); mkdirSync(path.dirname(file), { recursive: true }); writeFileSync(file, typeof value === 'string' ? value : JSON.stringify(value)); };
  write('licenses/original.txt', 'Original fixture terms.\n'); write('.artifacts/runtime.bin', 'Actual fixture bytes.');
  const file = fileReceipt(root, 'licenses/original.txt'), term = { path: file.path, sha256: file.sha256, size_bytes: file.size };
  const artifact = { id: 'provider-assets-fixture', ...fileReceipt(root, '.artifacts/runtime.bin') };
  const definition = { subject: 'fixture', classification: 'linked-object', binary_sha256: artifact.sha256, terms: [term] }, definitionHash = sha256(Buffer.from(canonicalJson(definition)));
  const proposal = 'runtime/materials/component-source-duties.proposal.json';
  write(proposal, { schema_version: 1, qualification: 'component-level-source-duty-review-proposal-not-approval', groups: [{ ...definition, definition_sha256: definitionHash }] });
  const original = fileReceipt(root, proposal);
  write('quality/reviews/component-source-duties-root-review.json', { schema_version: 1, qualification: 'independent-exact-component-source-duty-review-not-publisher-authority', proposal: { path: proposal, sha256: original.sha256, size_bytes: original.size }, groups: [{ definition_sha256: definitionHash, binary_sha256: [artifact.sha256], terms: [term], decision: 'conditional-object-code-source-treatment', source_availability: 'unspecified' }] });
  const source = sourceReceipt(root), facts = ['1'.repeat(64), '2'.repeat(64)];
  const report = { schema_version: 1, qualification: 'replayed-actual-shipped-component-source-license-closure', source_inventory_sha256: source.sha256, runtime_lock_sha256: '3'.repeat(64), complete_available_shipped_component_coverage: true, complete_product_coverage: true, unresolved_shipped_members: [], missing_distribution_subjects: [], subjects: [{ id: artifact.id, artifact_sha256: artifact.sha256, bindings: [{ path: 'runtime/fixture.bin', sha256: artifact.sha256, size_bytes: artifact.size, facts }] }] };
  const read = () => { write('.artifacts/coverage.json', report); const candidate = { runtime_lock_sha256: report.runtime_lock_sha256, artifacts: [artifact, { id: 'component-source-coverage', ...fileReceipt(root, '.artifacts/coverage.json') }] }; return conditionalPublisherComponents(root, candidate, source); };
  return { report, facts, read, expected: [{ id: `component-duty-${definitionHash}-${artifact.sha256}`, definition_sha256: definitionHash, binary_sha256: artifact.sha256 }], close: () => rmSync(root, { recursive: true, force: true }) };
}

test('public publisher selection reads legacy and indexed reports with the same exact physical subjects', () => {
  const value = fixture();
  try {
    assert.deepEqual(value.read(), value.expected);
    value.report.format_revision = 2; value.report.binding_fact_sets = [value.facts]; value.report.subjects[0].bindings[0].facts = 0;
    assert.deepEqual(value.read(), value.expected);
    value.report.subjects[0].bindings[0].facts = ['4'.repeat(64)]; value.report.binding_fact_sets = [];
    assert.deepEqual(value.read(), value.expected);
  } finally { value.close(); }
});

test('indexed reports reject invalid references, altered tables and unsupported revisions', () => {
  for (const change of [
    report => { report.format_revision = 3; },
    report => { report.format_revision = null; report.subjects[0].bindings[0].facts = report.binding_fact_sets[0]; delete report.binding_fact_sets; },
    report => { report.subjects[0].bindings[0].facts = -1; },
    report => { report.subjects[0].bindings[0].facts = 1; },
    report => { report.subjects[0].bindings[0].facts = true; },
    report => { report.binding_fact_sets[0] = ['not-a-fact', '2'.repeat(64)]; },
    report => { report.binding_fact_sets[0].reverse(); },
    report => { report.binding_fact_sets.push(report.binding_fact_sets[0]); },
    report => { report.binding_fact_sets.push(['5'.repeat(64), '6'.repeat(64)]); },
  ]) {
    const value = fixture();
    try {
      value.report.format_revision = 2; value.report.binding_fact_sets = [value.facts]; value.report.subjects[0].bindings[0].facts = 0; change(value.report);
      assert.throws(value.read, /component (?:report|fact|inline)|inline component fact|physical member binding/);
    } finally { value.close(); }
  }
});
