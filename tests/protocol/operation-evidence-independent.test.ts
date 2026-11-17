/** Independent envelope expectations; no worker or engine is simulated ready. */
import { expect, test } from 'vitest';
import { operationCoverage, operationResourceKind, operationScope } from '../../packages/coordinator/src/operation-evidence.js';

test('scope uses the worker selection verbatim and keeps typed non-path selections', () => {
  expect(operationScope({ scope: ['second.conllu', 'first.conllu'] }, {}, [])).toEqual({ file_paths: ['second.conllu', 'first.conllu'] });
  expect(operationScope({ scope: [{ file_path: 'a.conllu', sentence_index: 2 }] }, {}, [])).toEqual({ selections: [{ file_path: 'a.conllu', sentence_index: 2 }] });
  expect(operationScope({ scope: { file_paths: ['chosen.conllu'], sentence_only: true } }, { working_tree_path: '/different' }, [{ path: 'unselected.conllu' }])).toEqual({ file_paths: ['chosen.conllu'], sentence_only: true });
});
test('derived scope excludes staged external inputs and retains the actual current inputs and references', () => {
  const args = { working_tree_path: '/workspace', sentence_conllu: 'inline sentence', tree_ref: { file_path: 'current.conllu', sentence_index: 0 }, token_ref: { token_id: '2' } };
  expect(operationScope({}, args, [{ path: 'current.conllu' }, { path: '.ud-agent-inputs/peer/base.conllu' }, { path: 'README.md' }])).toEqual({ working_tree_path: '/workspace', file_paths: ['current.conllu', 'README.md'], input_kind: 'inline_sentence', tree_ref: { file_path: 'current.conllu', sentence_index: 0 }, token_ref: { token_id: '2' } });
  expect(operationScope({}, {}, [{ path: 'only.conllu' }])).toEqual({ file_paths: ['only.conllu'] });
});
test('check-family completion excludes not-requested checks and preserves incomplete work as incomplete', () => {
  expect(operationCoverage({ coverage: { content: 'completed', documentation: 'not_requested', repository: 'incomplete', requested: 10, complete: 8 } })).toEqual({ requested: ['content', 'repository'], completed: ['content'], skipped: [{ name: 'repository', reason: 'incomplete' }] });
  expect(operationCoverage({ coverage: { documentation: 'not_requested' } })).toEqual({ requested: [], completed: [], skipped: [] });
});
test('domain metrics and drawing descriptions never invent linguistic validation', () => {
  for (const coverage of [{ requested: 10, complete: 8 }, { basic_dependencies: 'drawn', enhanced_dependencies: 'drawn' }, { base_identity_verified: true }]) expect(operationCoverage({ coverage })).toEqual({ requested: ['domain_operation'], completed: ['domain_operation'], skipped: [] });
  expect(operationCoverage({ status: 'incomplete' })).toEqual({ requested: ['domain_operation'], completed: [], skipped: [{ name: 'domain_operation', reason: 'incomplete' }] });
});
test('versioned plans and legacy plan results stay distinct from ordinary reports', () => {
  expect(operationResourceKind('metadata_change_plan', { schema_version: 'ud-plan-v1', status: 'complete', actions: [] })).toBe('plans');
  expect(operationResourceKind('treebank_edit', { status: 'plan' })).toBe('plans');
  expect(operationResourceKind('workspace_sync_plan', { status: 'complete' })).toBe('plans');
  expect(operationResourceKind('changes_review', { status: 'complete' })).toBe('reports');
  expect(operationResourceKind('treebank_profile', { status: 'incomplete' })).toBe('reports');
});
