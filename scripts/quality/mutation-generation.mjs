/** Export actual protected generation through the existing release inventory format. */
import { spawnSync } from 'node:child_process';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileReceipt, sourceReceipt, sha256 } from '../release/candidate.mjs';
import { canonicalJson } from '../release/http-transports.mjs';
import { acceptanceInputHash, compileAcceptanceInventory } from '../release/discover-acceptance.mjs';
import { authorityFromGeneration, mutationBackendContract, verifyMutationBackendDiscovery, requiredMutationBackends, mutationRequirements } from '../release/mutation-backends.mjs';
import { provePythonGeneration, provePerlGeneration } from './prove-generation.mjs';
import { reconcileStrykerGeneration } from './prove-stryker-generation.mjs';
import { normalizeScheduleFile } from './normalize-schedule.mjs';
const tools = { typescript: { tool: 'stryker', version: '10.1.1' }, rust: { tool: 'cargo-mutants', version: '27.1.0' }, 'python-static': { tool: 'python-static', version: '1.0.0' }, faults: { tool: 'fault-canary', version: '1.0.0' } };
const plans = { typescript: 'stryker-discovery-plan.json', rust: 'rust/schedule.json', 'python-static': 'python-static-schedule.json', faults: 'fault-schedule.json', python: 'schedule.json', perl: 'perl-schedule.json' };
const insist = (value, message) => { if (!value) throw new Error('Mutation generation export: ' + message); };
const project = ({ id, file, source_sha256, definition_sha256 }) => ({ id, file, source_sha256, definition_sha256 });
const sorted = rows => [...rows].sort((a, b) => a.id < b.id ? -1 : a.id > b.id ? 1 : 0);

function additionalGeneration(root, state, output, selected, python) {
  const source = sourceReceipt(root), backend = tools[selected], contract = mutationBackendContract(root, source, backend);
  const plan = JSON.parse(readFileSync(path.join(state, plans[selected]), 'utf8'));
  mkdirSync(output, { recursive: true, mode: 0o700 });
  const raw = [], record = file => { const receipt = fileReceipt(root, path.relative(root, file).split(path.sep).join('/')); if (!raw.some(item => item.path === receipt.path)) raw.push(receipt); return receipt; };
  const planReceipt = record(path.join(state, plans[selected]));
  let inventory;
  if (selected === 'typescript') {
    inventory = reconcileStrykerGeneration(plan, source, contract);
    record(path.join(state, 'stryker-generation.json'));
  } else {
    const reconstructed = path.join(output, 'reconstructed.json');
    const checked = spawnSync(python, ['-B', path.join(root, 'scripts/quality/prove-source-generation.py'), '--root', root, '--state', selected === 'rust' ? path.join(state, 'rust') : state, '--plan', path.join(state, plans[selected]), '--backend', selected, '--output', reconstructed], { encoding: 'utf8', timeout: 300000, maxBuffer: 1024 * 1024, env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1' } });
    insist(checked.status === 0 && !checked.signal && !checked.error, 'complete original generator replay failed: ' + (checked.stderr ?? checked.error?.message));
    inventory = sorted(JSON.parse(readFileSync(reconstructed, 'utf8')).inventory.map(project)); record(reconstructed);
  }
  const materializations = contract.sources.map(item => {
    const artifacts = [planReceipt];
    if (selected === 'python-static') artifacts.push(record(path.join(state, 'static-generation', item.path + '.json')));
    if (selected === 'rust') {
      const label = item.path.startsWith('scripts/quality/rust-assertion-parser/') ? 'assertion-parser' : 'launcher';
      artifacts.push(record(path.join(state, 'rust/discovery-' + label + '.json')));
    }
    return { source: item.path, source_sha256: item.sha256, mutant_ids: inventory.filter(row => row.file === item.path).map(row => row.id), artifacts };
  });
  const runner = JSON.parse(readFileSync(path.join(state, 'runner.json'), 'utf8'));
  for (const name of ['runner.json', 'runtime-input-receipt.json', 'isolation-proof.json', 'exec-isolation-proof.json']) record(path.join(state, name));
  const runtime = JSON.parse(readFileSync(path.join(state, 'runtime-input-receipt.json'), 'utf8'));
  for (const item of runtime.harness) record(path.join(state, 'verified-harness', item.path));
  const generation = { schema_version: 1, kind: 'mutation-backend-generation', qualification: 'complete-backend-generation-no-outcomes', scope_complete: true, input_sha256: acceptanceInputHash(source), backend, ...contract,
    execution: { command: runner.generator_argv, runtime: { kind: 'oci', image_id: runner.image } }, inventory, inventory_sha256: sha256(canonicalJson(inventory)), source_materializations: materializations, raw_artifacts: raw };
  const file = path.join(output, 'raw-generation.json'); writeFileSync(file, JSON.stringify(generation) + '\n', { flag: 'wx' });
  const generationReceipt = fileReceipt(root, path.relative(root, file).split(path.sep).join('/'));
  const authority = authorityFromGeneration(root, source, generation.input_sha256, generationReceipt), authorityFile = path.join(output, 'backend-discovery.json');
  writeFileSync(authorityFile, JSON.stringify(authority) + '\n', { flag: 'wx' });
  verifyMutationBackendDiscovery(root, fileReceipt(root, path.relative(root, authorityFile).split(path.sep).join('/')), source, generation.input_sha256);
  return { generation: generationReceipt };
}

export async function exportMutationSchedules(root, directory, catalog, rows, python, { profile = 'exhaustive' } = {}) {
  const requirements = JSON.parse(readFileSync(path.join(root, 'quality/requirements.json'), 'utf8'));
  const selected = mutationRequirements(requirements, profile);
  const receipts = [];
  for (const row of rows) {
    const state = path.join(directory, row.discovery), output = path.join(directory, 'generation', row.backend);
    const proof = row.backend === 'python' ? provePythonGeneration(root, state, output, python) : row.backend === 'perl' ? provePerlGeneration(root, state, output, python) : additionalGeneration(root, state, output, row.backend, python);
    const master = JSON.parse(readFileSync(path.join(root, proof.generation.path), 'utf8'));
    const frozen = JSON.parse(readFileSync(path.join(root, row.frozen.path), 'utf8'));
    insist(canonicalJson(master.inventory) === canonicalJson(frozen.plan.mutants), 'compact frozen plan differs from independently reconstructed full generation');
    const tool = row.backend === 'python' ? 'mutmut' : row.backend === 'perl' ? 'ppi-perl' : tools[row.backend].tool;
    for (const [suite, required] of Object.entries(requiredMutationBackends)) if (selected.required_suites.includes(suite) && required.includes(tool)) {
      const normalized = await normalizeScheduleFile(root, { planFile: path.join(state, plans[row.backend]), catalog, suiteId: suite, generation: proof.generation, output: path.join(directory, 'normalized', suite + '-' + row.backend), python });
      const firstShard = JSON.parse(readFileSync(path.join(root, normalized.shards[0].path), 'utf8'));
      insist(canonicalJson(firstShard.tests) === canonicalJson(row.tests), 'raw generation test header differs from the frozen discovered test set');
      receipts.push(...normalized.shards);
    }
  }
  const catalogReceipt = fileReceipt(root, path.relative(root, path.join(directory, 'catalog.json')).split(path.sep).join('/'));
  function* schedules() { for (const record of receipts) yield JSON.parse(readFileSync(path.join(root, record.path), 'utf8')); }
  const inventory = compileAcceptanceInventory(root, catalog, requirements, schedules(), { profile });
  inventory.discovery = { schema_version: 1, algorithm: 'native-runner-discovery-v1', catalog: catalogReceipt, schedules: receipts };
  const file = path.join(directory, 'acceptance-inventory.json'); writeFileSync(file, JSON.stringify(inventory, null, 2) + '\n', { flag: 'wx', mode: 0o400 });
  return fileReceipt(root, path.relative(root, file).split(path.sep).join('/'));
}
