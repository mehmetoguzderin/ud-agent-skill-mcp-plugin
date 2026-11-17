/** Separate source/component facts from a publisher's right to redistribute. */
import { createPublicKey, verify } from 'node:crypto';
import { MAX_COMPONENT_SOURCE_REPORT_BYTES } from './component-closure.mjs';
import { existsSync } from 'node:fs';
import path from 'node:path';
import { readRecordedBytes, sha256 } from './candidate.mjs';
import { canonicalJson } from './http-transports.mjs';

const HASH = /^[a-f0-9]{64}$/;
const DUTY_PROPOSAL = 'runtime/materials/component-source-duties.proposal.json';
const DUTY_REVIEW = 'quality/reviews/component-source-duties-root-review.json';
const DUTY_CLASSES = {
  'no-separate-source-object': ['import-metadata', 'no-recorded-image-contribution'],
  'conditional-object-code-source-treatment': ['linked-object', 'linked-compiler-runtime-component', 'incorporated-build-inputs-not-raw-header-redistribution'],
  'open-source-STL-original-license-notice-and-source-identity': ['linked-open-source-STL-component'],
};
function insist(value, message) { if (!value) throw new Error(message); }
function sourceBound(root, source, name, maximum = 16 * 1024 ** 2) {
  const rows = source.files.filter(row => row.path === name);
  insist(rows.length === 1, 'Component source-duty input is missing or duplicated in protected source: ' + name);
  return { row: rows[0], bytes: readRecordedBytes(root, rows[0], maximum) };
}
function groupBinaries(group) {
  const values = Array.isArray(group.bindings) ? group.bindings.map(row => row.binary_sha256) : [group.binary_sha256 ?? group.binary?.sha256];
  insist(values.length > 0 && values.length <= 10000 && values.every(value => typeof value === 'string' && HASH.test(value)), 'Component source-duty group has no exact binary universe.');
  return [...new Set(values)].sort();
}

/** Called after mandatory independent component replay in the production path.
 * Re-read its exact artifact rather than accepting a caller-selected binary list. */
function shippedBinaryHashes(root, candidate, source) {
  const rows = candidate.artifacts.filter(row => row.id === 'component-source-coverage');
  insist(rows.length === 1, 'Conditional publisher authority requires exact shipped-component coverage.');
  const report = JSON.parse(readRecordedBytes(root, rows[0], MAX_COMPONENT_SOURCE_REPORT_BYTES).toString('utf8'));
  insist(report.schema_version === 1 && report.qualification === 'replayed-actual-shipped-component-source-license-closure' && report.complete_available_shipped_component_coverage === true && report.complete_product_coverage === true && report.source_inventory_sha256 === source.sha256 && report.runtime_lock_sha256 === candidate.runtime_lock_sha256 && Array.isArray(report.unresolved_shipped_members) && report.unresolved_shipped_members.length === 0 && Array.isArray(report.missing_distribution_subjects) && report.missing_distribution_subjects.length === 0, 'Conditional publisher authority has stale or incomplete shipped-component coverage.');
  const subjects = candidate.artifacts.filter(row => !['component-source-coverage', 'publisher-authority', 'checksum-manifest'].includes(row.id));
  insist(Array.isArray(report.subjects) && report.subjects.length === subjects.length && subjects.every((row, index) => report.subjects[index]?.id === row.id && report.subjects[index]?.artifact_sha256 === row.sha256), 'Conditional publisher authority changes actual artifact subjects.');
  const revision = Object.hasOwn(report, 'format_revision') ? report.format_revision : 1, groups = report.binding_fact_sets, used = new Set();
  insist(revision === 1 || revision === 2, 'Conditional publisher authority has an unsupported component report format.');
  if (revision === 1) insist(groups === undefined, 'Conditional publisher authority has an unexpected component fact table.');
  else {
    insist(Array.isArray(groups) && groups.length <= 100000, 'Conditional publisher authority has no bounded component fact table.');
    const compare = (left, right) => { for (let index = 0; index < Math.min(left.length, right.length); index++) { if (left[index] !== right[index]) return left[index] < right[index] ? -1 : 1; } return left.length - right.length; };
    for (let index = 0; index < groups.length; index++) {
      const group = groups[index];
      insist(Array.isArray(group) && group.length >= 2 && group.length <= 10000 && group.every((value, position) => typeof value === 'string' && HASH.test(value) && (position === 0 || group[position - 1] < value)) && (index === 0 || compare(groups[index - 1], group) < 0), 'Conditional publisher authority has an invalid component fact set.');
    }
  }
  const binaries = new Set();
  for (const subject of report.subjects) {
    insist(Array.isArray(subject.bindings), 'Conditional publisher authority has no physical member bindings.');
    for (const row of subject.bindings) {
      let facts = row.facts;
      if (revision === 2 && Number.isSafeInteger(facts)) { insist(facts >= 0 && facts < groups.length, 'Conditional publisher authority has an invalid component fact index.'); used.add(facts); facts = groups[facts]; }
      else if (revision === 2) insist(Array.isArray(facts) && facts.length === 1 && typeof facts[0] === 'string' && HASH.test(facts[0]), 'Conditional publisher authority has an invalid inline component fact.');
      insist(typeof row.path === 'string' && row.path.length > 0 && HASH.test(row.sha256 ?? '') && Number.isSafeInteger(row.size_bytes) && row.size_bytes >= 0 && Array.isArray(facts) && facts.length > 0, 'Conditional publisher authority has an invalid physical member binding.');
      binaries.add(row.sha256);
    }
  }
  if (revision === 2) insist(used.size === groups.length, 'Conditional publisher authority has unused component fact sets.');
  return binaries;
}

/** Source-duty classification is never a publisher redistribution grant. */
export function conditionalPublisherComponents(root, candidate, source, shipped = null) {
  const present = name => source.files.some(row => row.path === name) || existsSync(path.join(root, name));
  if (!present(DUTY_PROPOSAL) && !present(DUTY_REVIEW)) return [];
  const proposalInput = sourceBound(root, source, DUTY_PROPOSAL), reviewInput = sourceBound(root, source, DUTY_REVIEW);
  const proposal = JSON.parse(proposalInput.bytes.toString('utf8')), review = JSON.parse(reviewInput.bytes.toString('utf8'));
  insist(proposal.schema_version === 1 && proposal.qualification === 'component-level-source-duty-review-proposal-not-approval' && Array.isArray(proposal.groups) && proposal.groups.length > 0 && proposal.groups.length <= 1000 && review.schema_version === 1 && review.qualification === 'independent-exact-component-source-duty-review-not-publisher-authority' && canonicalJson(review.proposal) === canonicalJson({ path: DUTY_PROPOSAL, sha256: proposalInput.row.sha256, size_bytes: proposalInput.row.size }) && Array.isArray(review.groups) && review.groups.length === proposal.groups.length, 'Independent component source-duty review is missing, stale or incomplete.');
  const decisions = new Map();
  for (const row of review.groups) {
    insist(HASH.test(row?.definition_sha256 ?? '') && !decisions.has(row.definition_sha256), 'Independent component source-duty decisions are duplicated or invalid.');
    decisions.set(row.definition_sha256, row);
  }
  shipped ??= shippedBinaryHashes(root, candidate, source);
  const known = new Set(), components = [];
  for (const group of proposal.groups) {
    const { definition_sha256: fingerprint, ...definition } = group;
    // The Python proposal producer uses sorted, ASCII-escaped canonical JSON.
    const encoded = canonicalJson(definition).replace(/[\u007f-\uffff]/g, character => '\\u' + character.charCodeAt(0).toString(16).padStart(4, '0'));
    insist(HASH.test(fingerprint ?? '') && !known.has(fingerprint) && fingerprint === sha256(Buffer.from(encoded)), 'Component source-duty definition changed or duplicated.'); known.add(fingerprint);
    const decision = decisions.get(fingerprint), binaries = groupBinaries(group);
    insist(Array.isArray(group.terms) && group.terms.length > 0 && group.terms.length <= 1000, 'Original component source-duty terms are missing.');
    const terms = group.terms.map(({ path, sha256, size_bytes }) => ({ path, sha256, size_bytes }));
    insist(decision && canonicalJson(decision.binary_sha256) === canonicalJson(binaries) && canonicalJson(decision.terms) === canonicalJson(terms), 'Independent component source-duty review changes binary or original-term identities.');
    const applicable = binaries.filter(binary => shipped.has(binary));
    if (decision.decision === 'unresolved') {
      insist(applicable.length === 0, 'Conditional shipped component source duties remain unresolved.');
      continue;
    }
    insist(Object.hasOwn(DUTY_CLASSES, decision.decision) && DUTY_CLASSES[decision.decision].includes(group.classification), 'Independent component source-duty decision has an incompatible contribution class.');
    if (decision.decision === 'conditional-object-code-source-treatment') insist(decision.source_availability === 'unspecified', 'Conditional component duties cannot assert source unavailability.');
    for (const term of terms) {
      insist(HASH.test(term.sha256 ?? '') && Number.isSafeInteger(term.size_bytes) && term.size_bytes >= 0, 'Original component source-duty term identity is invalid.');
      const bound = sourceBound(root, source, term.path);
      insist(bound.row.sha256 === term.sha256 && bound.row.size === term.size_bytes, 'Original component source-duty terms are not source-bound.');
    }
    if (decision.decision === 'conditional-object-code-source-treatment') for (const binary of applicable) components.push({ id: `component-duty-${fingerprint}-${binary}`, definition_sha256: fingerprint, binary_sha256: binary });
  }
  insist(decisions.size === known.size && [...decisions.keys()].every(key => known.has(key)), 'Independent component source-duty review contains unrelated definitions.');
  return components;
}
export function publisherAuthoritySubjects(source, candidate, components) {
  const excluded = new Set(['publisher-authority']);
  // The beta's checksum list includes the grant itself. The outer release
  // manifest binds both files without a circular grant/checksum dependency.
  if (candidate.signing_profile === 'publisher-beta') excluded.add('checksum-manifest');
  const artifacts = candidate.artifacts.filter(row => !excluded.has(row.id)).map(({ id, sha256, size }) => ({ id, sha256, size })).sort((a, b) => a.id < b.id ? -1 : a.id > b.id ? 1 : 0);
  return { schema_version: 1, purpose: 'publisher-redistribution-authority', scope: 'exact-candidate-only', source_tree_sha256: source.sha256, runtime_lock_sha256: candidate.runtime_lock_sha256, artifact_set_sha256: sha256(Buffer.from(canonicalJson(artifacts))), components: components.map(row => ({ id: row.id, definition_sha256: row.definition_sha256, binary_sha256: row.binary_sha256, rights: ['redistribute-object-code'] })).sort((a, b) => a.id < b.id ? -1 : a.id > b.id ? 1 : 0) };
}

export function verifyPublisherAuthorityEnvelope(payload, signatures, policy) {
  if (payload?.schema_version !== 1 || payload.purpose !== 'publisher-redistribution-authority' || payload.scope !== 'exact-candidate-only' || !HASH.test(payload.source_tree_sha256 ?? '') || !HASH.test(payload.runtime_lock_sha256 ?? '') || !HASH.test(payload.artifact_set_sha256 ?? '') || !HASH.test(payload.legal_evidence_sha256 ?? '') || !Array.isArray(payload.components) || payload.components.length === 0 || payload.components.some(row => typeof row.id !== 'string' || !row.id || !HASH.test(row.definition_sha256 ?? '') || !HASH.test(row.binary_sha256 ?? '') || canonicalJson(row.rights) !== '["redistribute-object-code"]') || new Set(payload.components.map(row => row.id)).size !== payload.components.length) throw new Error('Publisher authority signature domain differs.');
  if (!Array.isArray(signatures) || signatures.length !== 2 || !Array.isArray(policy?.redistribution_keys)) throw new Error('PUBLISHER_AUTHORITY_PENDING_EXTERNAL: separately trusted owner and review attestations are required.');
  const used = new Set(), materials = new Set();
  for (const role of ['publisher-owner', 'independent-reviewer']) {
    const envelopes = signatures.filter(row => row?.role === role);
    if (envelopes.length !== 1) throw new Error('Publisher authority signature roles differ.');
    const envelope = envelopes[0], keys = policy.redistribution_keys.filter(key => key.id === envelope.key_id && key.role === role && key.purpose === 'publisher-redistribution-authority' && key.status === 'active' && key.algorithm === 'ed25519');
    if (keys.length !== 1 || used.has(envelope.key_id) || typeof envelope.signature !== 'string' || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(envelope.signature)) throw new Error('No unique independent publisher authority key.');
    const key = createPublicKey(keys[0].public_key_pem), raw = Buffer.from(envelope.signature, 'base64');
    const fingerprint = sha256(key.export({ format: 'der', type: 'spki' }));
    if (key.asymmetricKeyType !== 'ed25519' || materials.has(fingerprint) || raw.length !== 64 || !verify(null, Buffer.from(canonicalJson(payload)), key, raw)) throw new Error('Publisher authority signature verification failed or role key material is reused.');
    used.add(envelope.key_id);
    materials.add(fingerprint);
  }
  return { verified: true, roles: ['publisher-owner', 'independent-reviewer'] };
}

export function verifySourceDutyReview(root, declaration, source) {
  const file = 'quality/reviews/msvc-source-duty-root-review.json', bound = source.files.find(row => row.path === file);
  if (!bound) throw new Error('Independent exact proprietary source-duty review is missing.');
  const review = JSON.parse(readRecordedBytes(root, bound).toString('utf8'));
  const declared = source.files.find(row => row.path === review.component_declaration?.path);
  if (review.schema_version !== 1 || review.qualification !== 'independent-exact-source-duty-review-not-publisher-license-authority' || !declared || declared.sha256 !== review.component_declaration.sha256 || declared.size !== review.component_declaration.size || review.cross_build_receipt_sha256 !== declaration.cross_build_receipt_sha256 || !Array.isArray(review.components) || review.components.length !== declaration.components.length) throw new Error('Proprietary source-duty review is stale or incomplete.');
  for (const component of declaration.components) {
    const rows = review.components.filter(row => row.id === component.id);
    if (rows.length !== 1 || rows[0].definition_sha256 !== component.definition_sha256 || rows[0].binary_sha256 !== component.binary_sha256 || rows[0].decision !== 'source-unavailable-proprietary-declaration-accepted' || canonicalJson(rows[0].terms) !== canonicalJson(component.terms.map(({ path, sha256, size }) => ({ path, sha256, size })))) throw new Error('Source-duty review omits or changes an exact proprietary component.');
  }
  return { verified: true, scope: 'source-duty-only-no-publisher-authority', components: declaration.components.length, review_sha256: bound.sha256 };
}

/** Production only. Local builds/acceptance do not fabricate a legal grant. */
export function verifyPublisherAuthority(root, candidate, source, policy) {
  const name = 'runtime/materials/msvc-static-components.lock.json', bound = source.files.find(row => row.path === name);
  const publisherBeta = candidate.signing_profile === 'publisher-beta';
  const shipped = publisherBeta ? shippedBinaryHashes(root, candidate, source) : null;
  const conditional = conditionalPublisherComponents(root, candidate, source, shipped);
  const shipsWindowsCode = candidate.artifacts.some(row => row.id === 'npm' || /^(?:native|mcpb)-windows-/.test(row.id));
  if (!bound && shipsWindowsCode && !publisherBeta) throw new Error('Publisher component declaration is missing from the frozen source.');
  const declaration = bound ? JSON.parse(readRecordedBytes(root, bound).toString('utf8')) : undefined;
  if (declaration) {
  if (declaration.schema_version !== 1 || declaration.qualification !== 'exact-proprietary-component-declarations-no-publisher-grant' || !Array.isArray(declaration.components) || declaration.components.length === 0 || declaration.raw_sdk_payloads_redistributed !== false) throw new Error('Publisher component declaration is invalid.');
  const ids = new Set();
  for (const item of declaration.components) {
    const { definition_sha256: fingerprint, ...definition } = item;
    if (typeof item.id !== 'string' || ids.has(item.id) || !HASH.test(item.binary_sha256 ?? '') || fingerprint !== sha256(Buffer.from(canonicalJson(definition))) || item.classification !== 'proprietary-static-object-code' || !Array.isArray(item.static_libraries) || !item.static_libraries.length || !Array.isArray(item.terms) || !item.terms.length) throw new Error('Exact proprietary component inventory differs.'); ids.add(item.id);
    for (const term of item.terms) { const sourceTerm = source.files.find(row => row.path === term.path); if (!sourceTerm || sourceTerm.sha256 !== term.sha256 || sourceTerm.size !== term.size) throw new Error('Original proprietary terms are not source-bound.'); readRecordedBytes(root, sourceTerm); }
  }
  verifySourceDutyReview(root, declaration, source);
  }
  const proprietary = (declaration?.components ?? []).filter(item => shipped === null || shipped.has(item.binary_sha256));
  const components = [...proprietary, ...conditional];
  if (components.length === 0) return { verified: true, components: 0 };
  if (new Set(components.map(row => row.id)).size !== components.length) throw new Error('Publisher component subjects collide.');
  const grants = candidate.artifacts.filter(row => row.id === 'publisher-authority');
  if (grants.length !== 1) throw new Error('PUBLISHER_AUTHORITY_PENDING_EXTERNAL: original terms and source-duty review do not establish publisher redistribution authority.');
  const record = JSON.parse(readRecordedBytes(root, grants[0], 1024 * 1024).toString('utf8')), expected = publisherAuthoritySubjects(source, candidate, components);
  if (!record.payload || !HASH.test(record.payload.legal_evidence_sha256 ?? '')) throw new Error('Publisher authority evidence identity is missing.');
  const { legal_evidence_sha256: _evidence, ...subjects } = record.payload;
  if (canonicalJson(subjects) !== canonicalJson(expected)) throw new Error('Publisher authority does not bind this exact component/source/artifact set.');
  return { ...verifyPublisherAuthorityEnvelope(record.payload, record.signatures, policy), components: components.length };
}
