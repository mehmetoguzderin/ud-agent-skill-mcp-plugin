/** Complete mutation discovery identities, independent of scheduled outcomes. */
import { fileReceipt, readRecordedBytes, sha256, verifyRecordedFile } from './candidate.mjs';
import { canonicalJson } from './http-transports.mjs';
import { boundedFaultDefinitions } from '../quality/fault-assess.mjs';

const SHA = /^[a-f0-9]{64}$/;
const verifiedMaterializations = new WeakMap();
function immutable(value) {
  if (value && typeof value === 'object') { for (const item of Object.values(value)) immutable(item); Object.freeze(value); }
  return value;
}
const orchestration = ['scripts/quality/mutation-session.mjs', 'scripts/quality/mutation-plan.mjs', 'scripts/quality/mutation-generation.mjs', 'scripts/quality/normalize-schedule.mjs', 'scripts/quality/prove-generation.mjs', 'scripts/quality/stream-plan.py', 'scripts/quality/prove-source-generation.py', 'scripts/quality/collect-mutation-tests.mjs', 'scripts/quality/oci-python-diagnostic.mjs', 'scripts/quality/original-candidate-binding.mjs', 'scripts/quality/original-acceptance.mjs', 'scripts/release/discover-acceptance.mjs'];
const specifications = Object.freeze({
  stryker: { version: '10.1.1', source: /^(?:packages|scripts|workers|evals)\/.*\.(?:ts|tsx|mts|cts|js|mjs|cjs)$/, generators: ['stryker.config.mjs', 'scripts/quality/discover-stryker.mjs', 'scripts/quality/prove-stryker-generation.mjs', 'scripts/quality/stryker-child.mjs', 'scripts/quality/stryker-config.mjs', 'scripts/quality/stryker-assertions.mjs', 'scripts/quality/stryker-assertion-setup.mjs', 'scripts/quality/stryker-native-assertions.cjs', 'scripts/quality/stryker-assertion-sdk.mjs', 'scripts/quality/stryker-sdk-evidence.mjs', 'scripts/quality/stryker-opacity.mjs', 'scripts/quality/stryker-baseline-authority.mjs', 'scripts/quality/stryker-selection-evidence.mjs', 'scripts/quality/assertion-obligations.mjs', 'scripts/quality/stryker-protected-runner.mjs', 'scripts/quality/stryker-exec.py', 'scripts/quality/oci-stryker.py', 'scripts/quality/oci-exec.py', 'scripts/quality/oci-isolation.py', 'scripts/quality/prepare-mutation-runtime.py', 'scripts/quality/node-dependencies.mjs', 'scripts/quality/stryker-evidence-reporter.mjs', 'scripts/quality/stryker-compat.mjs', 'scripts/quality/mutation-inventory.mjs'], configuration: ['package.json', 'package-lock.json', 'quality/assertion-obligations.json', 'quality/reviews/assertion-obligations-root-review.json'] },
  mutmut: { version: '3.8.1', source: /^(?:workers\/ud\/src\/ud_agent|scripts)\/.*\.py$/, generators: ['scripts/quality/mutmut-driver.py', 'scripts/quality/python-runtime-projection.py', 'scripts/quality/python-operators.py', 'scripts/quality/prove-python-generation.py', 'scripts/quality/oci-mutation.py', 'scripts/quality/oci-isolation.py', 'scripts/quality/oci-exec.py', 'scripts/quality/prepare-mutation-runtime.py', 'tests/mutation/mutmut_adapter.py'], configuration: ['pyproject.toml', 'uv.lock', 'quality/python-operator-repairs.json', 'quality/reviews/python-operator-repairs-domain-review.json', 'quality/python-graph-operator-proposals.json', 'quality/reviews/python-graph-operators-root-review.json', 'quality/python-graph-operators.activation.json'] },
  'python-static': { version: '1.0.0', source: /^(?:workers\/ud\/src\/ud_agent|scripts)\/.*\.py$/, generators: ['tests/mutation/python_static.py', 'scripts/quality/oci-secondary.py', 'scripts/quality/secondary-child.py', 'scripts/quality/oci-exec.py', 'scripts/quality/oci-isolation.py', 'scripts/quality/oci-mutation.py', 'scripts/quality/oci-stryker.py', 'scripts/quality/prepare-mutation-runtime.py'], configuration: ['pyproject.toml'] },
  'cargo-mutants': { version: '27.1.0', source: /^(?:packages\/|scripts\/quality\/rust-assertion-parser\/).*\.rs$/, generators: ['scripts/quality/rust-literal.py', 'scripts/quality/rust-diagnostic.py', 'scripts/quality/rust-test-runtime.py', 'scripts/quality/rust-protected.py', 'scripts/quality/rust-compile-child.py', 'scripts/quality/rust-assertions.mjs', 'scripts/quality/rust-applicability.mjs', 'scripts/quality/rust-applicability-cli.mjs', 'scripts/quality/prepare-rust-assertion-parser.py', 'scripts/quality/oci-exec.py', 'scripts/quality/oci-isolation.py', 'scripts/quality/oci-mutation.py', 'scripts/quality/prepare-mutation-runtime.py'], configuration: ['Cargo.toml', 'Cargo.lock', 'packages/launcher/Cargo.toml', 'scripts/quality/rust-assertion-parser/Cargo.toml', 'scripts/quality/rust-assertion-parser/Cargo.lock', 'quality/rust-total-boundaries.json'] },
  'ppi-perl': { version: '1.0.0', source: /^(?:packages|scripts|workers)\/.*\.(?:pl|pm)$/, generators: ['scripts/quality/perl-mutation.py', 'scripts/quality/perl-test-evidence.py', 'scripts/quality/perl_tokens.pl', 'scripts/quality/perl-test-runtime.py', 'scripts/quality/prove-perl-generation.py', 'scripts/quality/perl-guard-mutation.py', 'scripts/quality/perl-guard-assess.mjs', 'scripts/quality/oci-mutation.py', 'scripts/quality/oci-isolation.py', 'scripts/quality/oci-exec.py', 'scripts/quality/prepare-mutation-runtime.py'], configuration: ['quality/perl-operators.json', 'quality/perl-parser.lock.json'] },
  'fault-canary': { version: '1.0.0', generators: ['scripts/quality/oci-secondary.py', 'scripts/quality/secondary-child.py', 'scripts/quality/oci-exec.py', 'scripts/quality/oci-isolation.py', 'scripts/quality/oci-mutation.py', 'scripts/quality/oci-stryker.py', 'scripts/quality/prepare-mutation-runtime.py', 'scripts/quality/fault-assess.mjs', 'scripts/quality/rust-protected.py', 'scripts/quality/rust-compile-child.py', 'scripts/quality/rust-test-runtime.py', 'scripts/quality/rust-assertions.mjs', 'scripts/quality/rust-applicability.mjs', 'scripts/quality/prepare-rust-assertion-parser.py'], configuration: ['tests/mutation/fault-cases.json', 'pyproject.toml', 'package.json', 'package-lock.json', 'vitest.config.mts'] },
});
function insist(value, message) { if (!value) throw new Error(`Mutation backend discovery: ${message}`); }
const order = rows => [...rows].sort((a, b) => a.id < b.id ? -1 : a.id > b.id ? 1 : 0);
const project = item => ({ id: item.id, file: item.file, source_sha256: item.source_sha256, definition_sha256: item.definition_sha256 });
const receipts = (root, paths) => paths.map(name => fileReceipt(root, name)).sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0);
const equal = (left, right) => canonicalJson(left) === canonicalJson(right);
export const BOUNDED_MUTATION_POLICY = 'bounded-reviewed-v1';
export const BOUNDED_MUTATION_SUITE = 'mutation-bounded';
export const BOUNDED_MUTATION_LANGUAGES = Object.freeze(['typescript', 'python', 'rust', 'perl']);

/** The bounded corpus is an explicit reviewed sample, never an exhaustive claim. */
export function boundedMutationPolicy(root, source) {
  const corpus = fileReceipt(root, 'tests/mutation/fault-cases.json');
  const manifest = JSON.parse(readRecordedBytes(root, corpus, 4 * 1024 ** 2));
  insist(manifest.schema_version === 1 && manifest.profile === 'bounded' && manifest.policy === BOUNDED_MUTATION_POLICY && manifest.qualification === 'bounded-reviewed-corpus' && manifest.exhaustive === false && Array.isArray(manifest.cases) && manifest.cases.length === 18, 'explicit reviewed eighteen-case bounded corpus required');
  const files = new Map(source.files.map(row => [row.path, row])), ids = new Set(), languages = {};
  const definitions = new Map(boundedFaultDefinitions(manifest, name => readRecordedBytes(root, files.get(name), 16 * 1024 ** 2), new Map(source.files.map(row => [row.path, row.sha256]))).map(row => [row.id, row]));
  const cases = manifest.cases.map(row => {
    insist(row && typeof row.id === 'string' && row.id.length > 0 && !ids.has(row.id) && ['typescript', 'python', 'rust', 'perl', 'data'].includes(row.language) && typeof row.category === 'string' && row.category.length > 0 && typeof row.test === 'string' && typeof row.assertion === 'string' && row.assertion.length > 0 && ['vitest', 'pytest', 'rust'].includes(row.runner), 'bounded case metadata is invalid or duplicated');
    ids.add(row.id); languages[row.language] = (languages[row.language] ?? 0) + 1;
    const target = files.get(row.file), testName = row.test.split('::')[0].split('#')[0], test = files.get(testName);
    insist(target && test && typeof row.find === 'string' && row.find.length > 0 && typeof row.replace === 'string' && row.find !== row.replace, 'bounded case source, test or replacement is absent');
    const bytes = readRecordedBytes(root, target, 64 * 1024 ** 2), find = Buffer.from(row.find);
    const start = bytes.indexOf(find); insist(start >= 0 && bytes.indexOf(find, start + 1) < 0, 'bounded case source anchor is missing or ambiguous');
    if (row.language === 'rust') insist(row.runner === 'rust' && row.file.endsWith('.rs') && testName.endsWith('.rs'), 'bounded Rust case lacks an actual Rust route');
    return { id: row.id, file: row.file, source_sha256: target.sha256, definition_sha256: definitions.get(row.id).definition_sha256, test: row.test, test_source: testName, test_source_sha256: test.sha256, runner: row.runner, assertion: row.assertion, language: row.language, category: row.category };
  });
  insist(BOUNDED_MUTATION_LANGUAGES.every(language => languages[language] > 0), 'bounded corpus omits a required executable language');
  const names = [...new Set(cases.map(row => row.file))], tests = [...new Set(cases.map(row => row.test_source))];
  return { profile: 'bounded', policy: BOUNDED_MUTATION_POLICY, qualification: 'bounded-reviewed-corpus', exhaustive: false, suite_id: BOUNDED_MUTATION_SUITE, scheduled: 18, corpus, cases, per_language: languages, sources: receipts(root, names), tests: receipts(root, tests), generators: receipts(root, [...new Set([...mutationBackendFiles({ tool: 'fault-canary', version: '1.0.0' }).generators, 'scripts/quality/fault-assess.mjs'])]), configuration: receipts(root, ['quality/requirements.json', 'tests/mutation/fault-cases.json']) };
}

/** Legacy callers keep their original suites unless bounded is explicitly selected. */
export function mutationRequirements(requirements, profile = 'exhaustive') {
  insist(['exhaustive', 'bounded'].includes(profile), 'unknown mutation requirements profile');
  if (profile === 'exhaustive') return requirements;
  const configured = requirements?.mutation_profiles?.bounded;
  insist(configured?.policy === BOUNDED_MUTATION_POLICY && configured.suite === BOUNDED_MUTATION_SUITE && configured.scheduled === 18 && configured.exhaustive === false, 'bounded requirements policy is missing or changed');
  insist(configured.signing_profile === undefined || configured.signing_profile === 'publisher-beta', 'unknown bounded signing profile');
  const legacySigning = configured.signing_profile === 'publisher-beta' ? ['signing-macos', 'signing-windows'] : [];
  const ordinary = requirements.required_suites.filter(id => !id.startsWith('mutation-') && !legacySigning.includes(id));
  return { ...requirements, required_suites: [...ordinary, BOUNDED_MUTATION_SUITE] };
}
export function mutationBackendFiles(backend) {
  const specification = typeof backend?.tool === 'string' && Object.hasOwn(specifications, backend.tool) ? specifications[backend.tool] : undefined;
  insist(specification && backend.version === specification.version, 'unsupported tool or version');
  const assertionOrigins=['mutmut','python-static','ppi-perl','fault-canary'].includes(backend.tool)?['tests/mutation/pytest_evidence.py']:[];
  return { generators: [...new Set([...specification.generators, ...orchestration,...assertionOrigins])], configuration: [...specification.configuration] };
}
export const requiredMutationBackends = Object.freeze({
  'mutation-typescript': ['stryker'], 'mutation-python': ['mutmut', 'python-static'], 'mutation-rust': ['cargo-mutants'], 'mutation-perl': ['ppi-perl'],
  'mutation-policies': ['fault-canary'], 'mutation-generators': ['fault-canary'], 'mutation-release': ['fault-canary'], 'mutation-graders': ['fault-canary'], 'mutation-faults': ['fault-canary'],
  'mutation-bounded': ['fault-canary'],
});

export function mutationBackendContract(root, source, backend) {
  const specification = typeof backend?.tool === 'string' && Object.hasOwn(specifications, backend.tool) ? specifications[backend.tool] : undefined;
  insist(specification && backend.version === specification.version, 'unsupported tool or version');
  let sources;
  if (backend.tool === 'fault-canary') {
    const manifest = JSON.parse(readRecordedBytes(root, fileReceipt(root, 'tests/mutation/fault-cases.json'), 4 * 1024 * 1024));
    insist(manifest.schema_version === 1 && Array.isArray(manifest.cases) && manifest.cases.length > 0, 'missing fault definitions');
    const names = new Set(manifest.cases.map(item => item.file));
    sources = source.files.filter(item => names.has(item.path));
    insist(sources.length === names.size, 'fault source absent from current snapshot');
  } else sources = source.files.filter(item => specification.source.test(item.path));
  insist(sources.length > 0, 'empty applicable source scope');
  const configuration=[...specification.configuration];
  if(backend.tool==='mutmut'){
    const review=JSON.parse(readRecordedBytes(root,fileReceipt(root,'quality/reviews/python-operator-repairs-domain-review.json'),4*1024**2));
    if(Object.hasOwn(review,'format_revision')){
      const packets=new Map([['domain_completion','quality/reviews/python-operator-repairs-domain-review-v1.json'],['root','quality/reviews/python-operator-repairs-root-f11.json']]);
      insist(review.format_revision===2&&review.reviewer==='source-bound-review-packets'&&Array.isArray(review.packets)&&review.packets.length===2,'invalid typed-operator review wrapper');
      for(const descriptor of review.packets){
        insist(descriptor&&descriptor.path===packets.get(descriptor.reviewer)&&SHA.test(descriptor.sha256??'')&&Number.isSafeInteger(descriptor.size_bytes)&&descriptor.size_bytes>0&&descriptor.size_bytes<=4*1024**2,'invalid typed-operator review packet');
        readRecordedBytes(root,{path:descriptor.path,sha256:descriptor.sha256,size:descriptor.size_bytes},4*1024**2);configuration.push(descriptor.path);packets.delete(descriptor.reviewer);
      }
      insist(packets.size===0,'incomplete typed-operator review packets');
    }
    const activation=JSON.parse(readRecordedBytes(root,fileReceipt(root,'quality/python-graph-operators.activation.json'),1024*1024));
    if(activation.active===true&&activation.format_revision===2){
      for(const field of['registry','review']){
        const descriptor=activation[field];
        insist(descriptor&&typeof descriptor.path==='string'&&descriptor.path.startsWith('quality/')&&SHA.test(descriptor.sha256??''),'invalid active graph registry configuration');
        insist(fileReceipt(root,descriptor.path).sha256===descriptor.sha256,'active graph registry bytes differ from configuration');configuration.push(descriptor.path);
      }
    }
  }
  return { sources, generators: receipts(root, mutationBackendFiles(backend).generators), configuration: receipts(root, [...new Set(configuration)]) };
}

/** A complete generation master is produced from actual backend materialization.
 * The signature is checked separately under dedicated inventory authority. */
export function verifyMutationBackendDiscovery(root, receipt, source, inputSha256, verifyAuthority) {
  const bytes = readRecordedBytes(root, receipt, 64 * 1024 * 1024);
  const authority = JSON.parse(bytes.toString('utf8'));
  insist(authority?.schema_version === 1 && authority.kind === 'mutation-backend-discovery' && authority.qualification === 'complete-backend-inventory-no-outcomes' && authority.scope_complete === true && authority.input_sha256 === inputSha256, 'complete source-bound authority is required');
  const expected = mutationBackendContract(root, source, authority.backend);
  for (const field of ['sources', 'generators', 'configuration']) insist(equal(authority[field], expected[field]), `incomplete or changed ${field}`);
  const generationBytes = readRecordedBytes(root, authority.raw_generation, 64 * 1024 * 1024);
  const generation = JSON.parse(generationBytes.toString('utf8'));
  insist(generation?.schema_version === 1 && generation.kind === 'mutation-backend-generation' && generation.qualification === 'complete-backend-generation-no-outcomes' && generation.scope_complete === true && generation.input_sha256 === inputSha256 && equal(generation.backend, authority.backend), 'actual complete backend generation is required');
  for (const value of [authority, generation]) insist(!['outcomes', 'results', 'killed', 'survivors', 'killed_by', 'failure_kind'].some(key => key in value), 'discovery contains supplied outcomes');
  for (const field of ['sources', 'generators', 'configuration']) insist(equal(generation[field], expected[field]), `generation omitted or changed ${field}`);
  insist(Array.isArray(generation.raw_artifacts) && generation.raw_artifacts.length > 0 && generation.raw_artifacts.length <= 100_000, 'actual raw discovery and generated metadata receipts are required');
  const paths = new Set();
  for (const record of generation.raw_artifacts) {
    insist(record && !paths.has(record.path) && Number.isSafeInteger(record.size) && record.size >= 0 && record.size <= 1024 * 1024 * 1024, 'invalid or duplicate generation artifact');
    paths.add(record.path); verifyRecordedFile(root, record);
  }
  insist(Array.isArray(authority.inventory) && authority.inventory.length > 0 && authority.inventory.length <= 2_000_000 && Array.isArray(generation.inventory), 'empty or oversized complete backend inventory');
  const hashes = new Map(expected.sources.map(item => [item.path, item.sha256]));
  const ids = new Set(), definitions = new Set();
  for (const item of authority.inventory) {
    const definition = `${item?.file}\0${item?.definition_sha256}`;
    insist(typeof item?.id === 'string' && item.id.length > 0 && !ids.has(item.id) && !definitions.has(definition) && hashes.get(item.file) === item.source_sha256 && SHA.test(item.definition_sha256 ?? '') && equal(item, project(item)), 'duplicate, unbound or invalid master definition');
    ids.add(item.id); definitions.add(definition);
  }
  const inventory = order(authority.inventory);
  const digest = sha256(canonicalJson(inventory));
  insist(equal(authority.inventory, inventory) && authority.inventory_sha256 === digest && generation.inventory_sha256 === digest && equal(generation.inventory, inventory), 'master differs from actual generated definitions');
  const execution = generation.execution;
  insist(execution && equal(authority.execution, execution) && Array.isArray(execution.command) && execution.command.length > 0 && execution.command.length <= 256 && execution.command.every(value => typeof value === 'string' && value.length > 0 && !value.includes('\0')) && !execution.command.some(value => /^(?:--file|--mutant-filter|--source-subset)(?:=|$)/.test(value)), 'unbound or filtered actual generation command');
  const runtime = execution.runtime;
  insist(runtime && (runtime.kind === 'oci' && /^sha256:[a-f0-9]{64}$/.test(runtime.image_id ?? '') || runtime.kind === 'native' && SHA.test(runtime.executable_sha256 ?? '') && runtime.version_receipt && paths.has(runtime.version_receipt.path)), 'actual generation runtime identity is missing');
  if (runtime.kind === 'native') verifyRecordedFile(root, runtime.version_receipt);
  insist(Array.isArray(generation.source_materializations) && generation.source_materializations.length === expected.sources.length, 'actual per-source generation coverage is incomplete');
  const materialized = new Set();
  const idsByFile = new Map();
  for (const item of inventory) { const values = idsByFile.get(item.file) ?? []; values.push(item.id); idsByFile.set(item.file, values); }
  for (const item of generation.source_materializations) {
    const expectedIds = [...(idsByFile.get(item?.source) ?? [])].sort();
    insist(item && hashes.get(item.source) === item.source_sha256 && !materialized.has(item.source) && equal(item.mutant_ids, expectedIds) && Array.isArray(item.artifacts) && item.artifacts.length > 0, 'source materialization differs from complete generated definitions');
    for (const record of item.artifacts) insist(generation.raw_artifacts.some(actual => equal(actual, record)), 'source materialization lacks raw parser/generated evidence');
    materialized.add(item.source);
  }
  let signer;
  if (verifyAuthority) {
    signer = verifyAuthority(bytes, receipt.signature, authority);
    insist(typeof signer === 'string' && signer.length > 0, 'inventory authority verification failed');
  }
  const verified = { inventory, backend: authority.backend, signer };
  verifiedMaterializations.set(verified, immutable(JSON.parse(JSON.stringify({ backend: authority.backend, input_sha256: inputSha256, inventory, source_materializations: generation.source_materializations }))));
  return verified;
}

/** Only an actual successful verifier result can expose materialization scope.
 * A supplied JSON zero-source list is never generation authority. */
export function verifiedMutationMaterializations(verified) {
  const materializations = verifiedMaterializations.get(verified);
  insist(materializations, 'verified backend materialization identity is required');
  return materializations;
}

/** Construct only an unsigned discovery authority, after validating actual raw
 * generation. Production still requires an independent inventory signature. */
export function authorityFromGeneration(root, source, inputSha256, generationReceipt) {
  const generation = JSON.parse(readRecordedBytes(root, generationReceipt, 64 * 1024 * 1024));
  const expected = mutationBackendContract(root, source, generation.backend);
  return { schema_version: 1, kind: 'mutation-backend-discovery', qualification: 'complete-backend-inventory-no-outcomes', scope_complete: true, input_sha256: inputSha256, backend: generation.backend, ...expected, raw_generation: generationReceipt, inventory: generation.inventory, inventory_sha256: generation.inventory_sha256, execution: generation.execution };
}
