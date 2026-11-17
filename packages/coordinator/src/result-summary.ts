/** Bounded factual projection; the structured envelope remains authoritative. MIT. */
type Envelope = { operation: string; operation_id: string; execution: { status: string }; result: Record<string, unknown>; diagnostics: unknown[]; coverage: Record<string, unknown>; artifacts: unknown[]; limitations: string[] };
const MAX_BYTES = 4096;
const record = (value: unknown): Record<string, unknown> | undefined => value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : undefined;
const pointer = (value: string): string => value.replaceAll('~', '~0').replaceAll('/', '~1');

const round = (value: number): number => Math.round(value * 10000) / 10000;
/** "4 of 5 gold correct (denominator gold_total 5; system_total 5; precision 0.8, recall 0.8, f1 0.8)". */
export function scoreFact(value: Record<string, unknown>): string | undefined {
  const number = (key: string): number | undefined => typeof value[key] === 'number' && Number.isFinite(value[key]) ? value[key] as number : undefined;
  const correct = number('correct'), gold = number('gold_total'), system = number('system_total');
  if (correct === undefined || gold === undefined || system === undefined || Array.isArray(value)) return undefined;
  const metrics = ['precision', 'recall', 'f1', 'aligned_accuracy'].filter(key => number(key) !== undefined).map(key => `${key} ${round(number(key)!)}`);
  const aligned = number('aligned_total');
  return `${correct} of ${gold} gold correct (denominator gold_total ${gold}; system_total ${system}${aligned !== undefined ? `; aligned_total ${aligned}` : ''}${metrics.length ? `; ${metrics.join(', ')}` : ''})`;
}

/** A small record of scalars as one line ("count 3, before_head 2, after_head 1"); undefined otherwise. */
export function flatRecordLine(value: unknown): string | undefined {
  const item = record(value);
  if (!item) return undefined;
  const entries = Object.entries(item);
  if (!entries.length || entries.length > 10 || entries.some(([, field]) => !(field === null || typeof field === 'boolean' || typeof field === 'number' && Number.isFinite(field) || typeof field === 'string' && Buffer.byteLength(field) <= 80))) return undefined;
  return entries.map(([key, field]) => `${key} ${typeof field === 'number' ? round(field) : String(field)}`).join(', ');
}
/** A record of such records ({news: {count 3, ...}, fiction: {...}}) as "news: count 3, ...; fiction: ..." (at most 8). */
function nestedRecordLine(value: unknown): string | undefined {
  const item = record(value);
  if (!item) return undefined;
  const entries = Object.entries(item);
  if (!entries.length || entries.length > 8) return undefined;
  const lines = entries.map(([key, field]) => [key, flatRecordLine(field)] as const);
  return lines.every(([, line]) => line !== undefined) ? lines.map(([key, line]) => `${key}: ${line}`).join('; ') : undefined;
}

export function summarizeOperationResult(envelope: Envelope, options: { guidance?: string | undefined } = {}): string {
  const facts: Record<string, unknown> = {}, collections: Record<string, unknown> = {};
  const resources: { uri: string; mime_type?: string; size_bytes?: number; sha256?: string }[] = [];
  const summary = { kind: 'ud-result-summary', projection: true, operation: envelope.operation, operation_id: envelope.operation_id,
    execution: envelope.execution.status, facts, collections, diagnostic_count: envelope.diagnostics.length, resources,
    omitted_nodes: 0, authoritative_result: 'structuredContent',
    // A rejected call may name where its exact arguments are documented (never a synthesized argument).
    ...(options.guidance ? { guidance: options.guidance } : {}) };
  let visited = 0;
  const seen = new WeakSet<object>();
  const fits = (): boolean => Buffer.byteLength(JSON.stringify(summary)) <= MAX_BYTES - 128;
  const put = (target: Record<string, unknown>, key: string, value: unknown): void => {
    target[key] = value;
    if (!fits()) { delete target[key]; summary.omitted_nodes++; }
  };
  function reference(value: unknown): void {
    const item = record(value);
    if (!item || typeof item.uri !== 'string' || !/^ud:\/\/(?:reports|plans|contexts|operations|artifacts)\//.test(item.uri) || resources.some(row => row.uri === item.uri) || resources.length >= 4) return;
    const selected = { uri: item.uri, ...(typeof item.mime_type === 'string' ? { mime_type: item.mime_type } : {}), ...(Number.isSafeInteger(item.size_bytes) ? { size_bytes: item.size_bytes as number } : {}), ...(typeof item.sha256 === 'string' ? { sha256: item.sha256 } : {}) };
    resources.push(selected); if (!fits()) { resources.pop(); summary.omitted_nodes++; }
  }
  reference(envelope.result.report_resource); for (const value of envelope.artifacts) reference(value);
  if (record(envelope.result.report_resource) && resources.some(value => value.uri === record(envelope.result.report_resource)!.uri)) summary.authoritative_result = 'structuredContent; returned report_resource provides complete stored result';
  function visit(value: unknown, name: string, depth: number): void {
    if (++visited > 192) { summary.omitted_nodes++; return; }
    if (value === null || typeof value === 'boolean' || typeof value === 'number' && Number.isFinite(value)) { put(facts, name, value); return; }
    if (typeof value === 'string') {
      if (Buffer.byteLength(value) <= 240) put(facts, name, value);
      else { put(collections, name, { string_bytes: Buffer.byteLength(value), prefix: value.slice(0, 160), content_omitted: true }); summary.omitted_nodes++; }
      return;
    }
    if (!value || typeof value !== 'object' || seen.has(value)) { summary.omitted_nodes++; return; }
    seen.add(value);
    if (Array.isArray(value)) {
      // Deep rows that are small scalar records (locations, examples) are stated as one line each instead of omitted.
      // Nested lists such as a manifest's files keep up to four rows this way.
      if (depth >= 2 && value.length && value.slice(0, 4).every(item => flatRecordLine(item) !== undefined)) {
        put(collections, name, { count: value.length, attempted_items: Math.min(value.length, 4) });
        for (const [index, item] of value.slice(0, 4).entries()) put(facts, `${name}/${index}`, flatRecordLine(item));
        if (value.length > 4) summary.omitted_nodes++;
        return;
      }
      put(collections, name, { count: value.length, attempted_items: depth < 3 ? Math.min(value.length, 2) : 0 });
      if (depth < 3) for (const [index, item] of value.slice(0, 2).entries()) visit(item, `${name}/${index}`, depth + 1);
      if (value.length > (depth < 3 ? 2 : 0)) summary.omitted_nodes++;
      return;
    }
    // A scorer count record ({correct, gold_total, system_total, ...}) is stated as one plain fact, so the
    // denominator is explicit and a dozen metrics fit instead of eight numeric fields each.
    const score = scoreFact(value as Record<string, unknown>);
    if (score) { put(facts, name, score); return; }
    if (depth >= 4) {
      const line = flatRecordLine(value) ?? nestedRecordLine(value);
      if (line && Buffer.byteLength(line) <= 600) { put(facts, name, line); return; }
      put(collections, name, { fields: Object.keys(value).length, content_omitted: true }); summary.omitted_nodes++; return;
    }
    // Scalar results come first so a large row collection cannot hide an
    // explicitly returned ready/passed/status/count value later in the object.
    const entries = Object.entries(value).sort((left, right) => Number(typeof left[1] === 'object' && left[1] !== null) - Number(typeof right[1] === 'object' && right[1] !== null));
    for (const [key, item] of entries) {
      if (name === '/result' && key === 'report_resource') continue;
      visit(item, `${name}/${pointer(key)}`, depth + 1);
    }
  }
  visit(envelope.result, '/result', 0);
  visit(envelope.coverage, '/coverage', 0);
  if (envelope.limitations.length) visit(envelope.limitations, '/limitations', 0);
  // No argument completion, interpretation of missing facts, or success claim
  // is synthesized. The projection explicitly signals omitted content.
  return JSON.stringify(summary);
}
