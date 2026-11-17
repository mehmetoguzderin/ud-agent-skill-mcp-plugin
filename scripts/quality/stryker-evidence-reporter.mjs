/** Capture Stryker's actual plan before execution and every final raw outcome. */
import { declareClassPlugin, PluginKind } from '@stryker-mutator/api/plugin';
import { TestStatus } from '@stryker-mutator/api/test-runner';
import { PlanKind } from '@stryker-mutator/api/core';
import { appendFileSync, readFileSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import path from 'node:path';
import { mutationDefinition } from './mutation-inventory.mjs';
import { verifyFrozenMutationPlan } from './mutation-plan.mjs';

const sha = bytes => createHash('sha256').update(bytes).digest('hex');
export function executionScheduleScope(environment = process.env, read = readFileSync) {
  if (environment.UD_STRYKER_DIAGNOSTIC_SCOPE === undefined) return { scope_complete: true };
  if (environment.UD_STRYKER_DIAGNOSTIC_SCOPE !== '/state/stryker-diagnostic-scope.json') throw new Error('Diagnostic Stryker scope must come from the fixed coordinator.');
  const bytes = read(environment.UD_STRYKER_DIAGNOSTIC_SCOPE);
  if (!Buffer.isBuffer(bytes) || bytes.length > 65536) throw new Error('Diagnostic Stryker scope is unbounded.');
  const scope = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  if (scope?.schema_version !== 1 || scope.kind !== 'selected-stryker-diagnostic' || scope.scope_complete !== false || scope.source_tree_sha256 !== environment.UD_MUTATION_SNAPSHOT_SHA256 || !/^[a-f0-9]{64}$/.test(scope.source_sha256 ?? '') || typeof scope.file !== 'string' || typeof scope.range !== 'string' || !scope.range.startsWith(scope.file + ':')) throw new Error('Diagnostic Stryker scope is not source-bound.');
  return { scope_complete: false, qualification: 'selected-diagnostic', diagnostic_scope: scope };
}
function relative(filename) { const name = path.relative(process.cwd(), filename).split(path.sep).join('/'); if (!name || name.startsWith('../') || path.isAbsolute(name)) throw new Error('Mutation source escapes its frozen snapshot.'); return name; }
function normalizedTest(id) { const split = id.indexOf('#'); if (split < 0) throw new Error('Mutation test identity lacks its source.'); return `${relative(path.resolve(id.slice(0, split)))}${id.slice(split)}`; }

/** Opaque child-process coverage must broaden execution, never invent hits. */
export function protectExecutionPlans(plans, timing) {
  if (!Array.isArray(plans) || !timing || !Number.isFinite(timing.net) || timing.net < 0 || !Number.isFinite(timing.overhead) || timing.overhead < 0) throw new Error('Complete original timing is required for mutation execution policy.');
  const timeout = Math.min(540000, Math.max(30000, Math.ceil(2 * (timing.net + timing.overhead) + 30000))), fallback = [];
  for (const plan of plans) if (plan.plan === PlanKind.Run) {
    if (!plan.runOptions || !/^(?:0|[1-9][0-9]*)$/.test(String(plan.mutant?.id))) throw new Error('Mutation run plan has no exact identity/options.');
    delete plan.runOptions.hitLimit;
    plan.runOptions.reloadEnvironment = true;
    if (Array.isArray(plan.runOptions.testFilter) && plan.runOptions.testFilter.length === 0) {
      fallback.push(String(plan.mutant.id));
      delete plan.runOptions.testFilter;
      plan.runOptions.mutantActivation = 'static';
      plan.runOptions.timeout = timeout;
    }
  }
  return { schema_version: 1, kind: 'pristine-per-test-with-conservative-full-fallback', unattributed_full_suite: true, fallback_mutant_ids: fallback.sort(), hit_limits: 'disabled', fresh_environment: true, opaque_executions: 'all-observed-cases-and-file-fixtures;global-uncertainty-full-suite', test_source_preprocessing: 'disabled', full_suite_timeout_ms: timeout };
}

export class EvidenceReporter {
  constructor() { this.tests = []; this.definitions = new Map(); }
  onDryRunCompleted(event) {
    this.timing = event.timing;
    this.tests = event.result.tests.map(test => {
      const source = relative(test.fileName); return { id: normalizedTest(test.id), source, source_sha256: sha(readFileSync(test.fileName)), name: test.name, occurrence: test.occurrence ?? 0, status: test.status === TestStatus.Success ? 'Success' : test.status === TestStatus.Skipped ? 'Skipped' : 'Failed' };
    });
  }
  onMutationTestingPlanReady(event) {
    const directory = process.env.UD_STRYKER_EVIDENCE;
    if (!directory) throw new Error('Structured Stryker evidence directory is required.');
    const executionPolicy = protectExecutionPlans(event.mutantPlans, this.timing);
    const mutants = event.mutantPlans.map(({ mutant }) => {
      const file = relative(mutant.fileName), source = readFileSync(mutant.fileName, 'utf8');
      const definition = mutationDefinition(file, source, mutant); this.definitions.set(String(mutant.id), definition); return definition;
    });
    const plan = { schema_version: 1, tool: 'stryker', tool_version: '10.1.1', source_tree_sha256: process.env.UD_MUTATION_SNAPSHOT_SHA256, tests: this.tests, mutants, execution_policy: executionPolicy, ...executionScheduleScope() };
    if (plan.scope_complete && process.env.UD_MUTATION_FROZEN_PLAN === '1') verifyFrozenMutationPlan(plan, JSON.parse(readFileSync(path.join(directory, 'pre-outcome-plan.json'), 'utf8')), 'typescript');
    writeFileSync(path.join(directory, 'stryker-schedule.json'), JSON.stringify(plan), { flag: 'wx', mode: 0o600 });
  }
  onMutantTested(result) {
    const expected = this.definitions.get(String(result.id));
    if (!expected) throw new Error('Stryker returned an unscheduled mutation.');
    appendFileSync(path.join(process.env.UD_STRYKER_EVIDENCE, 'stryker-outcomes.jsonl'), JSON.stringify({ id: String(result.id), file: expected.file, definition_sha256: expected.definition_sha256, status: result.status, killedBy: result.killedBy?.map(normalizedTest) ?? [], testsCompleted: result.testsCompleted }) + '\n', { mode: 0o600 });
  }
}

export const strykerPlugins = [declareClassPlugin(PluginKind.Reporter, 'ud-evidence', EvidenceReporter)];
