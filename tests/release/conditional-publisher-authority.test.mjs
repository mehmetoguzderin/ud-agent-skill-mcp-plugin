import { test, expect } from 'vitest';
import { generateKeyPairSync, sign } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { fileReceipt, sourceReceipt, sha256 } from '../../scripts/release/candidate.mjs';
import { canonicalJson } from '../../scripts/release/http-transports.mjs';
import { conditionalPublisherComponents, publisherAuthoritySubjects, verifyPublisherAuthority } from '../../scripts/release/publisher-authority.mjs';

const proposalPath = 'runtime/materials/component-source-duties.proposal.json';
const reviewPath = 'quality/reviews/component-source-duties-root-review.json';
const digest = text => sha256(Buffer.from(text));
const json = (root, name) => JSON.parse(readFileSync(path.join(root, name), 'utf8'));

// Synthetic post-component-replay subjects and ephemeral keys have no real
// license authority. Production independently replays all physical subjects
// before this separate attestation gate.
function fixture(withProposal = true) {
  const root = mkdtempSync(path.join(os.tmpdir(), 'ud-conditional-authority-'));
  const write = (name, value) => { const file = path.join(root, name); mkdirSync(path.dirname(file), { recursive: true }); writeFileSync(file, typeof value === 'string' ? value : JSON.stringify(value, null, 2) + '\n'); };
  const binary = Object.fromEntries(['old', 'node', 'perl', 'unshipped', 'uv', 'imports', 'zero', 'stl'].map(name => [name, digest(name)]));
  write('licenses/vendor/fixture.txt', 'Original fixture term bytes.\n');
  const termFile = fileReceipt(root, 'licenses/vendor/fixture.txt');
  const term = { path: termFile.path, sha256: termFile.sha256, size_bytes: termFile.size };
  const oldDefinition = { id: 'existing-static-fixture', binary_sha256: binary.old, classification: 'proprietary-static-object-code', static_libraries: ['recorded-fixture.lib'], terms: [{ path: term.path, sha256: term.sha256, size: term.size_bytes }] };
  const old = { ...oldDefinition, definition_sha256: digest(canonicalJson(oldDefinition)) };
  const oldName = 'runtime/materials/msvc-static-components.lock.json';
  write(oldName, { schema_version: 1, qualification: 'exact-proprietary-component-declarations-no-publisher-grant', raw_sdk_payloads_redistributed: false, cross_build_receipt_sha256: digest('cross'), components: [old] });
  write('quality/reviews/msvc-source-duty-root-review.json', { schema_version: 1, qualification: 'independent-exact-source-duty-review-not-publisher-license-authority', component_declaration: fileReceipt(root, oldName), cross_build_receipt_sha256: digest('cross'), components: [{ ...old, decision: 'source-unavailable-proprietary-declaration-accepted' }] });
  const group = value => { const definition = { terms: [term], ...value }; return { ...definition, definition_sha256: digest(canonicalJson(definition)) }; };
  const groups = [
    group({ subject: 'node', classification: 'linked-compiler-runtime-component', binary: { sha256: binary.node, size_bytes: 10 } }),
    group({ subject: 'private-perl', classification: 'linked-object', bindings: [{ binary_sha256: binary.perl }, { binary_sha256: binary.unshipped }] }),
    group({ subject: 'owned-uv', classification: 'incorporated-build-inputs-not-raw-header-redistribution', binary_sha256: binary.uv }),
    group({ subject: 'private-perl', classification: 'import-metadata', bindings: [{ binary_sha256: binary.imports }] }),
    group({ subject: 'private-perl', classification: 'no-recorded-image-contribution', bindings: [{ binary_sha256: binary.zero }] }),
    group({ subject: 'owned-uv', classification: 'linked-open-source-STL-component', binary_sha256: binary.stl }),
  ];
  if (withProposal) {
    write(proposalPath, { schema_version: 1, qualification: 'component-level-source-duty-review-proposal-not-approval', groups });
    const identity = fileReceipt(root, proposalPath);
    write(reviewPath, { schema_version: 1, qualification: 'independent-exact-component-source-duty-review-not-publisher-authority', proposal: { path: proposalPath, sha256: identity.sha256, size_bytes: identity.size }, groups: groups.map((value, index) => ({ definition_sha256: value.definition_sha256, decision: index < 3 ? 'conditional-object-code-source-treatment' : index < 5 ? 'no-separate-source-object' : 'open-source-STL-original-license-notice-and-source-identity', binary_sha256: (value.bindings ? value.bindings.map(row => row.binary_sha256) : [value.binary_sha256 ?? value.binary.sha256]).sort(), terms: [term], ...(index < 3 ? { source_availability: 'unspecified' } : {}) })) });
  }
  write('.artifacts/fixture/native.zip', 'Original fixture artifact bytes.');
  const actualArtifact = { id: 'native-windows-arm64', ...fileReceipt(root, '.artifacts/fixture/native.zip') };
  const pairs = ['publisher-owner', 'independent-reviewer'].map(role => ({ role, ...generateKeyPairSync('ed25519') }));
  const policy = { redistribution_keys: pairs.map(({ role, publicKey }) => ({ id: role, role, purpose: 'publisher-redistribution-authority', status: 'active', algorithm: 'ed25519', public_key_pem: publicKey.export({ type: 'spki', format: 'pem' }) })) };
  const expected = [old, ...(withProposal ? groups.slice(0, 3).map((value, index) => { const hash = [binary.node, binary.perl, binary.uv][index]; return { id: `component-duty-${value.definition_sha256}-${hash}`, definition_sha256: value.definition_sha256, binary_sha256: hash }; }) : [])];
  function refresh({ granted = expected, coveragePatch = {}, withGrant = true } = {}) {
    const source = sourceReceipt(root), coverage = { schema_version: 1, qualification: 'replayed-actual-shipped-component-source-license-closure', complete_available_shipped_component_coverage: true, complete_product_coverage: true, source_inventory_sha256: source.sha256, runtime_lock_sha256: digest('runtime'), unresolved_shipped_members: [], missing_distribution_subjects: [], subjects: [{ id: actualArtifact.id, artifact_sha256: actualArtifact.sha256, bindings: ['node', 'perl', 'uv', 'imports', 'zero', 'stl'].map(name => ({ path: `runtime/${name}.bin`, sha256: binary[name], size_bytes: 10, facts: ['retained-exact-fixture-fact'] })) }], ...coveragePatch };
    write('.artifacts/fixture/coverage.json', coverage);
    const candidate = { runtime_lock_sha256: digest('runtime'), artifacts: [actualArtifact, { id: 'component-source-coverage', ...fileReceipt(root, '.artifacts/fixture/coverage.json') }] };
    if (withGrant) {
      const payload = { ...publisherAuthoritySubjects(source, candidate, granted), legal_evidence_sha256: digest('separately reviewed fixture legal evidence') };
      write('.artifacts/fixture/authority.json', { payload, signatures: pairs.map(({ role, privateKey }) => ({ role, key_id: role, signature: sign(null, Buffer.from(canonicalJson(payload)), privateKey).toString('base64') })) });
      candidate.artifacts.push({ id: 'publisher-authority', ...fileReceipt(root, '.artifacts/fixture/authority.json') });
    }
    return { source, candidate, verify: () => verifyPublisherAuthority(root, candidate, source, policy) };
  }
  return { root, write, groups, old, expected, binary, policy, actualArtifact, refresh, close: () => rmSync(root, { recursive: true, force: true }) };
}

test('legacy exact authority succeeds without a new proposal, while shipped Node/Perl/UV conditional subjects require their own exact grant', () => {
  for (const enabled of [false, true]) {
    const f = fixture(enabled);
    try {
      const value = f.refresh();
      expect(value.verify()).toEqual({ verified: true, roles: ['publisher-owner', 'independent-reviewer'], components: enabled ? 4 : 1 });
      const conditional = conditionalPublisherComponents(f.root, value.candidate, value.source);
      expect(conditional).toEqual(enabled ? f.expected.slice(1) : []);
      if (enabled) {
        expect(conditional.map(row => row.binary_sha256)).toEqual([f.binary.node, f.binary.perl, f.binary.uv]);
        for (const hash of [f.binary.imports, f.binary.zero, f.binary.stl, f.binary.unshipped]) expect(conditional.some(row => row.binary_sha256 === hash)).toBe(false);
        expect(() => f.refresh({ granted: [f.old] }).verify()).toThrow(/exact component\/source\/artifact set/);
        expect(() => f.refresh({ withGrant: false }).verify()).toThrow(/PUBLISHER_AUTHORITY_PENDING_EXTERNAL/);
      }
    } finally { f.close(); }
  }
});

test('missing or stale review/proposal and altered original terms fail even with newly signed source/artifact subjects', () => {
  for (const change of ['missing-review', 'missing-proposal', 'stale-proposal', 'missing-group', 'altered-terms', 'missing-terms', 'omitted-source-row']) {
    const f = fixture();
    try {
      if (change === 'missing-review') rmSync(path.join(f.root, reviewPath));
      if (change === 'missing-proposal') rmSync(path.join(f.root, proposalPath));
      if (change === 'stale-proposal') { const proposal = json(f.root, proposalPath); proposal.extra = 'changed bytes'; f.write(proposalPath, proposal); }
      if (change === 'missing-group') { const review = json(f.root, reviewPath); review.groups.pop(); f.write(reviewPath, review); }
      if (change === 'altered-terms') f.write('licenses/vendor/fixture.txt', 'Changed term bytes.');
      if (change === 'missing-terms') rmSync(path.join(f.root, 'licenses/vendor/fixture.txt'));
      const value = f.refresh();
      if (change === 'omitted-source-row') value.source.files = value.source.files.filter(row => row.path !== proposalPath);
      expect(() => value.verify(), change).toThrow(/source-duty|source-bound/);
    } finally { f.close(); }
  }
});

test('review decisions cannot change exact binary/term universes, misclassify contributions or assert unavailable conditional source', () => {
  for (const change of ['binary', 'term', 'class', 'unavailable', 'duplicate', 'unresolved']) {
    const f = fixture();
    try {
      const review = json(f.root, reviewPath);
      if (change === 'binary') review.groups[0].binary_sha256 = [f.binary.perl];
      if (change === 'term') review.groups[0].terms[0].sha256 = digest('substituted terms');
      if (change === 'class') review.groups[0].decision = 'no-separate-source-object';
      if (change === 'unavailable') review.groups[0].source_availability = 'unavailable';
      if (change === 'duplicate') review.groups[1] = review.groups[0];
      if (change === 'unresolved') review.groups[0].decision = 'unresolved';
      f.write(reviewPath, review);
      const message = {
        binary: 'Independent component source-duty review changes binary or original-term identities.',
        term: 'Independent component source-duty review changes binary or original-term identities.',
        class: 'Independent component source-duty decision has an incompatible contribution class.',
        unavailable: 'Conditional component duties cannot assert source unavailability.',
        duplicate: 'Independent component source-duty decisions are duplicated or invalid.',
        unresolved: 'Conditional shipped component source duties remain unresolved.',
      }[change];
      expect(() => f.refresh().verify(), change).toThrow(message);
    } finally { f.close(); }
  }
});

test('physical coverage must bind the exact frozen source, runtime, artifact set and member identities', () => {
  for (const coveragePatch of [{ source_inventory_sha256: digest('foreign source') }, { runtime_lock_sha256: digest('foreign runtime') }, { subjects: [] }, { unresolved_shipped_members: [{}] }, { complete_product_coverage: false }, { subjects: [{ id: 'native-windows-arm64', artifact_sha256: digest('other archive'), bindings: [] }] }]) {
    const f = fixture();
    try { expect(() => f.refresh({ coveragePatch }).verify()).toThrow(/coverage|artifact subjects/); }
    finally { f.close(); }
  }
});

test('conditional grants remain mandatory for auxiliary shipped bytes even without the legacy static declaration', () => {
  const f = fixture();
  try {
    rmSync(path.join(f.root, 'runtime/materials/msvc-static-components.lock.json'));
    f.actualArtifact.id = 'provider-assets-fixture';
    expect(() => f.refresh({ withGrant: false }).verify()).toThrow('PUBLISHER_AUTHORITY_PENDING_EXTERNAL');
    expect(f.refresh({ granted: f.expected.slice(1) }).verify().components).toBe(3);
  } finally { f.close(); }
});

test('publisher beta grants cover carried historical components by actual shipped hash', () => {
  const f = fixture(false);
  try {
    const absent = f.refresh({ withGrant: false });
    absent.candidate.signing_profile = 'publisher-beta';
    expect(absent.verify()).toEqual({ verified: true, components: 0 });
    const present = f.refresh({ withGrant: false, coveragePatch: {
      subjects: [{
        id: f.actualArtifact.id, artifact_sha256: f.actualArtifact.sha256,
        bindings: [{ path: 'bin/ud-agent.exe', sha256: f.binary.old, size_bytes: 10, facts: ['fixture-fact'] }],
      }],
    } });
    present.candidate.signing_profile = 'publisher-beta';
    expect(() => present.verify()).toThrow('PUBLISHER_AUTHORITY_PENDING_EXTERNAL');
  } finally { f.close(); }
});

test('signed component subjects cannot include excluded grants or substitute an exact conditional definition or binary', () => {
  const f = fixture();
  try {
    for (const granted of [
      [...f.expected, { id: 'unneeded-import-grant', definition_sha256: f.groups[3].definition_sha256, binary_sha256: f.binary.imports }],
      f.expected.map((row, index) => index === 1 ? { ...row, binary_sha256: f.binary.perl } : row),
      f.expected.map((row, index) => index === 1 ? { ...row, definition_sha256: digest('other group') } : row),
    ]) expect(() => f.refresh({ granted }).verify()).toThrow('Publisher authority does not bind this exact component/source/artifact set.');
  } finally { f.close(); }
});

test('a freshly referenced proposal must still have exact canonical definitions and physical coverage bytes', () => {
  const f = fixture();
  try {
    const proposal = json(f.root, proposalPath); proposal.groups[0].classification = 'import-metadata'; f.write(proposalPath, proposal);
    const current = fileReceipt(f.root, proposalPath), review = json(f.root, reviewPath);
    review.proposal = { path: proposalPath, sha256: current.sha256, size_bytes: current.size }; f.write(reviewPath, review);
    expect(() => f.refresh().verify()).toThrow('Component source-duty definition changed or duplicated.');
  } finally { f.close(); }
  const exact = fixture();
  try {
    const value = exact.refresh(); exact.write('.artifacts/fixture/coverage.json', 'substituted report');
    expect(() => value.verify()).toThrow('Artifact receipt mismatch');
    const fresh = exact.refresh(); fresh.candidate.artifacts = fresh.candidate.artifacts.filter(row => row.id !== 'component-source-coverage');
    expect(() => fresh.verify()).toThrow('Conditional publisher authority requires exact shipped-component coverage.');
  } finally { exact.close(); }
});
