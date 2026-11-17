/** Reconcile independently scheduled PPI definitions and clean assertion outcomes. */
import { createHash } from 'node:crypto';
const sha = value => createHash('sha256').update(value).digest('hex');
const canonical = value => JSON.stringify(value && typeof value === 'object' ? Array.isArray(value) ? value.map(canonicalValue) : Object.fromEntries(Object.keys(value).sort().map(key => [key, canonicalValue(value[key])])) : value);
function canonicalValue(value) { return value && typeof value === 'object' ? Array.isArray(value) ? value.map(canonicalValue) : Object.fromEntries(Object.keys(value).sort().map(key => [key, canonicalValue(value[key])])) : value; }

export function assessPerlCoverage(coverage, inventory, sources, operators) {
  if (!operators?.operator_replacements || !operators.structural_operators || !operators.keyword_replacements || !operators.ternary_replacements || !coverage || canonical(Object.keys(coverage).sort()) !== canonical(Object.keys(sources).sort()) || !Array.isArray(inventory)) return false;
  const seen = new Set(), definitions = new Map(inventory.map(item => [item.id, item]));
  if (definitions.size !== inventory.length) return false;
  for (const [file, source] of Object.entries(sources)) {
    if (!Array.isArray(coverage[file])) return false;
    let cursor = 0;
    for (const token of coverage[file]) {
      if (!token || !Number.isSafeInteger(token.start) || !Number.isSafeInteger(token.end) || token.start !== cursor || token.end <= token.start || token.end > source.length || typeof token.content !== 'string' || !source.subarray(token.start, token.end).equals(Buffer.from(token.content)) || !['scheduled', 'structural', 'outside-selected-family'].includes(token.classification) || typeof token.reason !== 'string' || !token.reason || typeof token.class !== 'string' || !token.class.startsWith('PPI::Token::') || !Array.isArray(token.mutant_ids) || (token.classification === 'scheduled') !== (token.mutant_ids.length > 0)) return false;
      if (token.class === 'PPI::Token::Operator') {
        if (Object.hasOwn(operators.structural_operators, token.content)) {
          if (token.classification !== 'structural' || token.reason !== operators.structural_operators[token.content]) return false;
        } else if (token.content === '?' || Object.hasOwn(operators.operator_replacements, token.content)) {
          if (token.classification !== 'scheduled') return false;
        } else return false;
      } else if (token.classification === 'structural') return false;
      if ((token.class.startsWith('PPI::Token::Number') || token.class.includes('Regexp') || ['PPI::Token::Quote::Single', 'PPI::Token::Quote::Double'].includes(token.class) || token.class === 'PPI::Token::Word' && Object.hasOwn(operators.keyword_replacements, token.content)) && token.classification !== 'scheduled') return false;
      for (const id of token.mutant_ids) {
        const item = definitions.get(id);
        if (!item || seen.has(id) || item.file !== file || item.definition?.start !== token.start || item.definition?.end !== token.end || item.definition?.original !== token.content) return false;
        seen.add(id);
      }
      cursor = token.end;
    }
    if (cursor !== source.length) return false;
  }
  return seen.size === definitions.size;
}

export function assessPerlTestEvidence(value, expected, hashes = {}, readSource = () => null) {
  const invalid = { valid: false, failures: [] };
  if (!Array.isArray(expected) || !expected.length || new Set(expected.map(item => item?.id)).size !== expected.length || !value || value.schema_version !== 1 || value.contract !== 'python-test-source-origin-v2' || canonical(value.expected) !== canonical(expected) || !Array.isArray(value.cases) || value.tests_run !== expected.length || value.cases.length !== expected.length) return invalid;
  const validSite = (source, fingerprint, line) => {
    if (typeof source !== 'string' || !source.startsWith('tests/') || !source.endsWith('.py') || source.includes('\\') || source.includes(':') || source.split('/').some(part => ['', '.', '..'].includes(part)) || hashes[source] !== fingerprint || !Number.isSafeInteger(line) || line < 1) return false;
    try {
      const bytes = readSource(source);
      if (!Buffer.isBuffer(bytes) || bytes.length > 4 * 1024 ** 2 || sha(bytes) !== fingerprint) return false;
      const lines = bytes.toString('utf8').split(/\r\n|\n|\r/u);
      return line <= lines.length - (lines.at(-1) === '' ? 1 : 0);
    } catch { return false; }
  };
  const failures = [];
  for (let index = 0; index < expected.length; index++) {
    const wanted = expected[index], item = value.cases[index];
    if (!wanted || typeof wanted.id !== 'string' || !wanted.id || typeof wanted.source !== 'string' || !/^[a-f0-9]{64}$/.test(wanted.source_sha256 ?? '') || !item || Object.entries(wanted).some(([key, expected]) => item[key] !== expected) || item.completed !== true || !Array.isArray(item.events) || !item.events.length) return invalid;
    for (const event of item.events) {
      if (!event || !['success', 'failure'].includes(event.kind)) return invalid;
      if (event.kind === 'failure') {
        const origin = event.assertion_origin;
        if (event.assertion !== true || typeof event.exception_type !== 'string' || !event.exception_type || !origin || origin.contract !== 'python-test-source-origin-v2' || origin.test_id !== wanted.id || origin.test_source !== wanted.source || origin.test_source_sha256 !== wanted.source_sha256 || !validSite(origin.source, origin.source_sha256, origin.line) || !validSite(origin.test_source, origin.test_source_sha256, origin.test_line)) return invalid;
        failures.push(item.id);
      }
    }
  }
  if (value.successful !== (failures.length === 0)) return invalid;
  return { valid: true, failures: [...new Set(failures)].sort() };
}

export function assessPerl(report, plan, sources, hashes, exceptions = [], used = new Set(), readReview = () => null, expectedSource = undefined) {
  const result = { total: 0, killed: 0, equivalent: 0, errors: [] };
  const fail = message => result.errors.push(message);
  if (!plan || !report || report.tool !== 'ppi-perl' || plan.tool !== 'ppi-perl' || report.tool_version !== '1.0.0' || plan.scope_complete !== true || report.scope_complete !== true || report.complete !== true || !Array.isArray(plan.inventory) || !Array.isArray(report.inventory) || !Array.isArray(report.outcomes)) {
    fail('PPI Perl mutation report or independent schedule is missing or incomplete.'); return result;
  }
  if (!expectedSource || !Array.isArray(expectedSource.files) || !expectedSource.files.length || !expectedSource.sha256 || plan.source_tree_sha256 !== expectedSource.sha256 || report.source_tree_sha256 !== expectedSource.sha256 || canonical(plan.source_inventory) !== canonical(expectedSource.files) || canonical(report.source_inventory) !== canonical(expectedSource.files)) fail('Perl full source snapshot differs from the independently captured inventory.');
  const expectedFiles = Object.keys(sources).sort();
  let operators;
  try { const bytes = readReview('quality/perl-operators.json'); if (bytes && sha(bytes) === hashes['quality/perl-operators.json']) operators = JSON.parse(bytes.toString('utf8')); } catch { /* missing source authority remains invalid */ }
  if (canonical(plan.operator_coverage) !== canonical(report.operator_coverage) || !assessPerlCoverage(plan.operator_coverage, plan.inventory, sources, operators)) fail('Perl per-token operator coverage is missing, unclassified or differs from exact scheduled definitions.');
  for (const value of [plan.sources, report.sources]) if (!value || canonical(Object.keys(value).sort()) !== canonical(expectedFiles) || expectedFiles.some(file => sha(sources[file]) !== value[file] || hashes[file] !== value[file])) fail('Perl mutation source inventory differs from discovered frozen sources.');
  if (plan.operator_sha256 !== hashes['quality/perl-operators.json'] || report.operator_sha256 !== plan.operator_sha256 || plan.parser_release !== 'PPI-1.291' || report.parser_release !== plan.parser_release) fail('Perl parser or operator identity differs from its frozen inputs.');
  if (!report.tests || !Object.keys(report.tests).length || canonical(report.tests) !== canonical(plan.tests) || Object.entries(plan.tests ?? {}).some(([file, fingerprint]) => hashes[file] !== fingerprint)) fail('Perl required test inventory is missing or stale.');
  if (!plan.case_inventory || canonical(report.case_inventory) !== canonical(plan.case_inventory) || canonical(Object.keys(plan.case_inventory).sort()) !== canonical(['bridge', 'tool']) || ['bridge', 'tool'].some(suite => !Array.isArray(plan.case_inventory[suite]) || !plan.case_inventory[suite].length || plan.case_inventory[suite].some(item => !item || hashes[item.source] !== item.source_sha256 || !Object.hasOwn(plan.tests ?? {}, item.source) || (typeof item.id !== 'string' || !item.id.startsWith(item.source.split('/').at(-1).replace(/\.py$/, '') + '.'))))) fail('Perl independent case inventory is missing or stale.');
  if (!plan.inventory.length || plan.scheduled !== plan.inventory.length || report.scheduled !== plan.scheduled || canonical(report.inventory) !== canonical(plan.inventory) || report.outcomes.length !== plan.inventory.length) fail('Perl scheduling and recorded inventories do not match.');
  if (!['bridge', 'tool'].every(key => {
    const evidence = assessPerlTestEvidence(report.baseline?.[key]?.unittest, plan.case_inventory?.[key], hashes, readReview);
    return report.baseline?.[key]?.passed === true && report.baseline[key].status === 0 && evidence.valid && evidence.failures.length === 0;
  })) fail('Perl baseline is missing or failed.');
  const definitions = new Map();
  for (const item of plan.inventory) {
    const definition = item?.definition;
    if (!definition || definitions.has(item.id) || !sources[item.file] || item.source_sha256 !== hashes[item.file] || sha(canonical(definition)) !== item.definition_sha256 || definition.tool !== 'ppi-perl' || definition.version !== '1.0.0' || !Number.isInteger(definition.start) || !Number.isInteger(definition.end) || definition.start < 0 || definition.end <= definition.start || sources[item.file].subarray(definition.start, definition.end).toString('utf8') !== definition.original || definition.replacement === definition.original) {
      fail(`Invalid or duplicate Perl mutation definition: ${item?.id}`); continue;
    }
    definitions.set(item.id, item);
  }
  const seen = new Set();
  for (const item of report.outcomes) {
    result.total++;
    const definition = definitions.get(item?.id);
    if (!definition || seen.has(item.id) || item.file !== definition.file || item.definition_sha256 !== definition.definition_sha256) { fail(`Unknown or duplicate Perl outcome: ${item?.id}`); continue; }
    seen.add(item.id);
    const evidence = item.evidence;
    const output = evidence ? `${evidence.stdout}\n${evidence.stderr}` : '';
    const failure = output.match(/^FAILED \(failures=(\d+)\)\s*$/m);
    const assertions = [...output.matchAll(/^AssertionError(?::.*)?$/gm)];
    const typed = assessPerlTestEvidence(evidence?.unittest, plan.case_inventory?.[item.file.startsWith('scripts/') ? 'tool' : 'bridge'], hashes, readReview);
    if (item.status === 'Killed' && item.failure_kind === 'assertion' && evidence?.phase === 'test' && evidence.status === 1 && typed.valid && typed.failures.length > 0 && canonical(typed.failures) === canonical(item.tests) && failure && Number(failure[1]) > 0 && Number(failure[1]) === assertions.length && !/^ERROR:/m.test(output) && !/\b(?:skipped|expected failures|unexpected successes)=/.test(output) && !output.includes('UD_COMPONENT_UNEXPECTED_EXIT:') && !output.includes("self.assertEqual(result.stderr, b'')")) result.killed++;
    else if (item.status === 'Survived' && evidence?.phase === 'test' && evidence.status === 0 && typed.valid && typed.failures.length === 0) {
      const exception = exceptions.find(entry => entry.tool === 'ppi-perl' && entry.id === item.id);
      let accepted = false;
      if (exception && exception.file === item.file && exception.source_sha256 === hashes[item.file] && exception.definition_sha256 === item.definition_sha256 && exception.author !== exception.reviewed_by && exception.proof?.length >= 40 && typeof exception.review?.path === 'string' && !exception.review.path.includes('..') && exception.review.path.startsWith('quality/reviews/') && hashes[exception.review.path] === exception.review.sha256) {
        try {
          const bytes = readReview(exception.review.path);
          if (bytes && sha(bytes) === exception.review.sha256) {
            const review = JSON.parse(bytes.toString('utf8'));
            const exact = review.reviews?.find(entry => entry.id === item.id);
            accepted = review.reviewer === exception.reviewed_by && exact?.equivalent === true && exact.source_sha256 === exception.source_sha256 && exact.definition_sha256 === exception.definition_sha256 && exact.reason === exception.proof && canonical(exact.definition) === canonical(definition.definition);
          }
        } catch { /* malformed review remains unresolved */ }
      }
      if (accepted) { result.equivalent++; used.add(`ppi-perl\0${item.id}`); }
      else fail(`Perl survivor has no exact independent equivalent review: ${item.id}`);
    } else fail(`Perl ${item.status ?? 'missing outcome'} without clean assertion evidence: ${item.id}`);
  }
  for (const id of definitions.keys()) if (!seen.has(id)) fail(`Perl mutant has no outcome: ${id}`);
  return result;
}
