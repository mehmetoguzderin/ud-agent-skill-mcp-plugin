/** Evidence projections for owned process release and failures. MIT. */
export function failureObservation(error, depth = 0) {
  if (!error || depth > 3) return null;
  const value = { name: String(error.name ?? 'Error'), message: String(error.message ?? error).slice(0, 4000) };
  for (const key of ['code', 'errno', 'syscall', 'address', 'port']) if (['string', 'number'].includes(typeof error[key])) value[key] = error[key];
  if (error.cause) value.cause = failureObservation(error.cause, depth + 1);
  if (error.result) value.owned_process = cleanupObservation(error.result);
  if (error.native_cleanup) value.native_cleanup = cleanupObservation(error.native_cleanup);
  if (error.budget_cleanup) value.budget_cleanup = error.budget_cleanup;
  return value;
}

/** Keep the complete cleanup evidence without duplicating captured transcripts. */
export function cleanupObservation(result) {
  if (!result) return null;
  const value = { cleanupVerified: result.cleanupVerified === true };
  for (const key of ['code', 'signal', 'stop_reason', 'cleanup_error', 'error', 'elapsed_ms', 'container_id', 'image_id', 'network_id',
    'cleanup_evidence', 'container_cleanup', 'native_cleanup', 'bridge_cleanup', 'coordinator_cleanup', 'alias_cleanup', 'completed_children', 'steps', 'deadline', 'finished_at']) if (result[key] !== undefined) value[key] = result[key];
  return value;
}

/** Budget counters count known output; incomplete usage cannot become zero. */
export function observedCounters(state) {
  if (!state?.counters) return null;
  return { ...state.counters, output: state.output_usage_verified === true ? state.counters.output : null };
}
