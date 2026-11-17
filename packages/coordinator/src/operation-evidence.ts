/** Normalize observed domain evidence without inventing linguistic checks. */
export function operationScope(result: Record<string, unknown>, args: Record<string, unknown>, files: readonly { path: string }[]): Record<string, unknown> {
  if (result.scope && typeof result.scope === 'object' && !Array.isArray(result.scope)) return result.scope as Record<string, unknown>;
  if (Array.isArray(result.scope)) return result.scope.every(value => typeof value === 'string') ? { file_paths: result.scope } : { selections: result.scope };
  const names = files.filter(file => !file.path.startsWith('.ud-agent-inputs/')).map(file => file.path);
  return { ...(typeof args.working_tree_path === 'string' ? { working_tree_path: args.working_tree_path } : {}), file_paths: names,
    ...(typeof args.sentence_conllu === 'string' ? { input_kind: 'inline_sentence' } : {}),
    ...(args.tree_ref && typeof args.tree_ref === 'object' ? { tree_ref: args.tree_ref } : {}),
    ...(args.token_ref && typeof args.token_ref === 'object' ? { token_ref: args.token_ref } : {}) };
}

export function operationCoverage(result: Record<string, unknown>): Record<string, unknown> {
  // Several operations expose numeric alignment counts or render descriptions
  // as domain coverage. Those stay intact in result; they are not check-family
  // statuses and must not become skipped checks with numeric/boolean reasons.
  const checks = result.coverage && typeof result.coverage === 'object' && !Array.isArray(result.coverage) ? result.coverage as Record<string, unknown> : {};
  const observed = Object.entries(checks).filter(([, status]) => status === 'completed' || status === 'incomplete' || status === 'not_requested');
  const entries = observed.length ? observed : [['domain_operation', result.status === 'incomplete' ? 'incomplete' : 'completed']];
  return { requested: entries.filter(([, status]) => status !== 'not_requested').map(([name]) => name),
    completed: entries.filter(([, status]) => status === 'completed').map(([name]) => name),
    skipped: entries.filter(([, status]) => status !== 'completed' && status !== 'not_requested').map(([name, reason]) => ({ name, reason })) };
}

export function operationResourceKind(operation: string, result: Record<string, unknown>): 'plans' | 'reports' {
  return result.schema_version === 'ud-plan-v1' || result.status === 'plan' || operation.endsWith('_plan') ? 'plans' : 'reports';
}
