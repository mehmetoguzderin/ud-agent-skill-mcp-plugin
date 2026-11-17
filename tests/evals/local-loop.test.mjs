import { test } from 'vitest';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { parse } from 'yaml';
import { DEFAULT_LOOP_HARNESSES, DEFAULT_REQUEST_TIMEOUT_MS, LOOP_GROUPS, LOOP_HARNESSES, gradeLoopEpisode, loopRequestTimeoutMs, requestJson, searchDeferredTools, splitScopedTools, declaredToolTokens, loopModel, loadableSchemas, unknownToolMessage, parseList, skillCatalog, skillOperations, systemPrompt, skillLoadHint, skillsMatchingPrompt, skillMatchTokens } from '../../evals/local/loop.mjs';
import { parseArguments } from '../../scripts/quality/run-local-model-evals.mjs';

// Inert: no model, worker, MCP server or network listener is started here.
const root = process.cwd();
const episode = (scenario, harness, extra) => ({ scenario_id: scenario, harness, seed: 17, stop: 'final_answer', requests: [{ status: 200, prompt_tokens: 3000 }], events: [], inputs_unchanged: true, new_files: [], final_answer: '', ...extra });

test('loop groups cover every skill once and keep the validation negative in G1', () => {
  assert.deepEqual(Object.values(LOOP_GROUPS).map(group => group.skill).sort(), ['ud-compare', 'ud-edit', 'ud-investigate', 'ud-release', 'ud-rules-docs', 'ud-validate']);
  assert.deepEqual(LOOP_GROUPS.G1.scenarios, ['S1', 'S7']);
  assert.deepEqual(DEFAULT_LOOP_HARNESSES, ['mcp-all', 'mcp-scoped', 'cli-shell']);
  assert.equal(LOOP_HARNESSES['mcp-eager'].diagnostic, true);
  assert.ok(skillOperations(root, 'ud-validate').includes('validation_report'));
  assert.throws(() => parseList('mcp-all,unknown', Object.keys(LOOP_HARNESSES), 'harness list'), /Invalid/);
});

test('catalog and prompt expose only frontmatter descriptions before activation', async () => {
  const catalog = skillCatalog(root), prompt = systemPrompt('mcp-scoped', '/w/treebank', catalog);
  assert.equal(catalog.length, 6);
  const validate = catalog.find(skill => skill.name === 'ud-validate');
  assert.match(validate.description, /load to read first/i);
  assert.match(validate.description, /check or find those errors in \.conllu files/);
  assert.match(validate.description, /Not for ordinary prose\/report wording/);
  assert.match(validate.description, /Never use it for \.txt or other non-CoNLL-U files/);
  assert.doesNotMatch(validate.description, /\bHEAD\b|\bsent_id\b/);
  assert.match(validate.description, /\bud-agent describe validation_report\b/);
  // Descriptions are the decoded YAML scalars hosts show, not the escaped source text.
  // Schema-discovery commands are public metadata; activation-only guidance
  // must still come solely from the body, never from the catalog projection.
  for (const skill of catalog) {
    const source = readFileSync(path.join(root, 'skills', skill.name, 'SKILL.md'), 'utf8');
    const header = /^---\r?\n([\s\S]*?)\r?\n---/.exec(source)[1];
    assert.equal(skill.description, parse(header).description, skill.name);
    assert.ok(!skill.description.includes('\\"') && !skill.description.startsWith('"'), skill.name);
  }
  const { mkdtempSync, mkdirSync, writeFileSync, rmSync } = await import('node:fs'), os = await import('node:os');
  const fake = mkdtempSync(path.join(os.tmpdir(), 'ud-catalog-'));
  try {
    mkdirSync(path.join(fake, 'skills/x'), { recursive: true });
    writeFileSync(path.join(fake, 'skills/x/SKILL.md'), '---\nname: x\ndescription: "Run ud-agent validate --working-tree \\"$PWD\\" (a\\\\b)."\n---\nBODY_ONLY_GUIDANCE_7d3c\n');
    assert.equal(skillCatalog(fake)[0].description, 'Run ud-agent validate --working-tree "$PWD" (a\\b).');
    assert.doesNotMatch(systemPrompt('mcp-scoped', '/w/treebank', skillCatalog(fake)), /BODY_ONLY_GUIDANCE_7d3c/);
  } finally { rmSync(fake, { recursive: true, force: true }); }
  for (const skill of catalog) { assert.ok(prompt.includes(`- ${skill.name}: ${skill.description}`)); assert.ok(!prompt.includes(skill.body.slice(0, 80))); }
  assert.match(systemPrompt('cli-shell', '/w/treebank', catalog), /\.agents\/skills\/NAME\/SKILL\.md/);
  assert.match(systemPrompt('mcp-scoped', '/w/treebank', catalog, [], [], 'Be brief.'), /Instructions from MCP server ud:\nBe brief\.$/);
  assert.doesNotMatch(systemPrompt('cli-shell', '/w/treebank', catalog, [], [], 'Be brief.'), /Be brief/);
});

test('the skill catalog sits where the mirrored host puts it; the legacy system layout is reproducible', async () => {
  const { initialMessages, catalogPlacement } = await import('../../evals/local/loop.mjs');
  const catalog = skillCatalog(root), line = `- ${catalog[0].name}: ${catalog[0].description}`;
  assert.deepEqual(['mcp-all', 'mcp-scoped', 'cli-shell', 'mcp-eager'].map(harness => catalogPlacement(harness)), ['reminder', 'reminder', 'system', 'system']);
  const [system, user] = initialMessages('mcp-scoped', '/w/treebank', catalog, [], [], '', 'Check a.conllu.');
  assert.ok(!system.content.includes(line)); assert.match(system.content, /\n\nCall activate_skill with a skill name/);
  assert.equal(user.content, `<system-reminder>\nAvailable skills:\n${catalog.map(skill => `- ${skill.name}: ${skill.description}`).join('\n')}\n</system-reminder>\n\nCheck a.conllu.`);
  const legacy = initialMessages('mcp-scoped', '/w/treebank', catalog, [], [], '', 'Check a.conllu.', 'system');
  assert.deepEqual(legacy, [{ role: 'system', content: systemPrompt('mcp-scoped', '/w/treebank', catalog) }, { role: 'user', content: 'Check a.conllu.' }]);
  assert.ok(legacy[0].content.includes(`Available skills:\n${line}`));
  assert.deepEqual(initialMessages('cli-shell', '/w/treebank', catalog, [], [], '', 'Check.'), initialMessages('cli-shell', '/w/treebank', catalog, [], [], '', 'Check.', 'system'));
  assert.throws(() => catalogPlacement('mcp-all', 'tool'), /Unknown catalog layout/);
});

test('S2 (G2) grading requires an exact applied edit, a later validation and an accurate report', async () => {
  const { createHash } = await import('node:crypto');
  const { SCENARIOS } = await import('../../evals/local/scenarios.mjs');
  const exact = createHash('sha256').update(SCENARIOS.find(item => item.id === 'S2').expected.bytes).digest('hex');
  const skill = { name: 'activate_skill', arguments: { name: 'ud-edit' }, ok: true, output: '' };
  const edit = { name: 'treebank_edit', ok: true, arguments: {}, output: '' }, check = { name: 'validation_report', ok: true, arguments: { file_paths: ['edit.conllu'] }, output: '' };
  const report = 'Applied: token 1 FORM Birds -> Swallows, LEMMA bird -> swallow, text "Swallows fly". Validation passed on the candidate; the correction completed.';
  const graded = extra => gradeLoopEpisode(episode('S2', 'mcp-scoped', { inputs_unchanged: false, outputs: { 'edit.conllu': exact }, final_answer: report, events: [skill, edit, check], ...extra }));
  assert.equal(graded().passed, true, JSON.stringify(graded().stages));
  assert.deepEqual([graded({ events: [edit, check] }).passed, graded({ events: [edit, check] }).task_passed], [false, true]);
  assert.equal(graded({ events: [skill, check, edit] }).first_failure, 'validated_after_edit');
  assert.equal(graded({ outputs: { 'edit.conllu': 'f'.repeat(64) } }).first_failure, 'exact_candidate');
  assert.equal(graded({ events: [skill, { ...edit, ok: false }, check] }).first_failure, 'edit_succeeded');
  assert.equal(graded({ events: [skill, { name: 'token_get', ok: true, arguments: {}, output: '' }, check] }).first_failure, 'edit_tool_called');
  assert.equal(graded({ final_answer: 'Validation passed. Nothing changed.' }).first_failure, 'completion_reported');
  const shell = graded({ harness: 'cli-shell', events: [{ name: 'bash', ok: true, arguments: { command: 'cat .agents/skills/ud-edit/SKILL.md' }, output: '' }, { name: 'bash', ok: true, arguments: { command: 'ud-agent call treebank_edit --input edit.json' }, output: '' }, { name: 'bash', ok: true, arguments: { command: 'ud-agent validate --working-tree "$PWD" --lang en' }, output: 'edit.conllu' }] });
  assert.equal(shell.passed, true, JSON.stringify(shell.stages));
  // The edit's own candidate validation counts only when it completed and passed.
  const self = status => ({ ...edit, structured: { result: { validation: status } } });
  assert.equal(graded({ events: [skill, self({ status: 'completed', passed: true })] }).passed, true);
  assert.equal(graded({ events: [skill, self({ status: 'completed', passed: false })] }).first_failure, 'validated_after_edit');
  assert.equal(graded({ events: [skill, self({ status: 'incomplete', passed: true })] }).first_failure, 'validated_after_edit');
});

test('mcp-scoped sends skill operations eagerly within a token budget and defers the rest by name', () => {
  const tool = (name, chars) => ({ name, description: name, inputSchema: { type: 'object', description: 'x'.repeat(chars) } });
  const listed = [tool('big_edit', 30_000), tool('a_get', 300), tool('b_set', 300), tool('c_list', 300), tool('other', 300)];
  const scoped = ['big_edit', 'a_get', 'b_set', 'c_list'];
  const split = splitScopedTools('mcp-scoped', listed, scoped, 'Use b_set, then big_edit; read with c_list.', 1_000);
  assert.deepEqual(split.eager.map(item => item.name), ['a_get', 'b_set', 'c_list']);
  assert.deepEqual(split.deferred.map(item => item.name), ['big_edit']);
  // Mentioned operations win when the budget is tight; catalog order is kept in what is sent.
  const tight = splitScopedTools('mcp-scoped', listed, scoped, 'Use b_set, then big_edit; read with c_list.', declaredToolTokens(listed[2]) + declaredToolTokens(listed[3]));
  assert.deepEqual(tight.eager.map(item => item.name), ['b_set', 'c_list']);
  assert.deepEqual(tight.deferred.map(item => item.name), ['big_edit', 'a_get']);
  assert.deepEqual(splitScopedTools('mcp-scoped', listed, scoped, '', 1e9).deferred, []);
  assert.deepEqual(splitScopedTools('mcp-all', listed, scoped).eager, []);
  assert.equal(splitScopedTools('mcp-eager', listed, scoped).eager.length, 5);
  assert.match(systemPrompt('mcp-scoped', '/w', [], ['big_edit']), /Deferred tools \(server ud[^\n]*\n.*big_edit/);
  assert.doesNotMatch(systemPrompt('mcp-scoped', '/w', [], []), /Deferred tools/);
});

test('S1 grading requires one scoped successful validation and both reported findings', () => {
  const call = { name: 'validation_report', ok: true, arguments: { file_paths: ['a.conllu', 'b.conllu'] }, structured: { scope: { file_paths: ['a.conllu', 'b.conllu'] } }, output: '' };
  const passed = gradeLoopEpisode(episode('S1', 'mcp-scoped', { events: [{ name: 'activate_skill', arguments: { name: 'ud-validate' }, ok: true, output: '' }, call],
    final_answer: 'b.conllu sentence duplicate has HEAD 9 for token 1, which does not exist. sent_id duplicate is repeated in a.conllu and b.conllu. Files were not changed.' }));
  assert.equal(passed.passed, true, JSON.stringify(passed.stages));
  const direct = gradeLoopEpisode(episode('S1', 'mcp-scoped', { events: [call], final_answer: passed.stages && 'b.conllu sentence duplicate has HEAD 9 for token 1, which does not exist. sent_id duplicate is repeated in a.conllu and b.conllu.' }));
  assert.deepEqual([direct.passed, direct.task_passed, direct.first_failure], [false, true, 'skill_activated']);
  const separate = gradeLoopEpisode(episode('S1', 'mcp-scoped', { events: [{ ...call, arguments: { file_paths: ['a.conllu'] }, structured: { scope: { file_paths: ['a.conllu'] } } }], final_answer: 'x' }));
  assert.equal(separate.first_failure, 'skill_activated');
  assert.equal(separate.stages.find(stage => stage.name === 'both_files_in_one_scope').passed, false);
  const overflow = gradeLoopEpisode(episode('S1', 'mcp-all', { stop: 'CONTEXT_ENVELOPE_EXCEEDED', requests: [{ status: 422, error: 'CONTEXT_ENVELOPE_EXCEEDED' }] }));
  assert.equal(overflow.first_failure, 'context_fits');
  const shellValidate = gradeLoopEpisode(episode('S1', 'cli-shell', { events: [{ name: 'bash', arguments: { command: 'cat .agents/skills/ud-validate/SKILL.md' }, ok: true, output: '' }, { name: 'bash', arguments: { command: 'ud-agent validate --working-tree "$PWD" --lang en' }, ok: true, output: '"file_paths": ["a.conllu", "b.conllu"]' }],
    final_answer: 'b.conllu sentence duplicate: HEAD 9 of token 1 does not exist. sent_id duplicate is repeated in a.conllu and b.conllu.' }));
  assert.equal(shellValidate.passed, true, JSON.stringify(shellValidate.stages));
  const leaked = gradeLoopEpisode(episode('S1', 'cli-shell', { final_answer: '<tool_call>\n<function=ud-validate>' }));
  assert.equal(leaked.first_failure, 'tool_call_wellformed');
});

test('S7 grading fails any UD activation on prose and checks preserved facts', () => {
  const answer = 'Suggested wording:\nThe team completed all planned interviews, so we can finalize the summary. The response rate rose from 40 percent to 55 percent. The next review is on Friday.';
  assert.equal(gradeLoopEpisode(episode('S7', 'mcp-scoped', { final_answer: answer })).passed, true);
  const activated = gradeLoopEpisode(episode('S7', 'mcp-scoped', { final_answer: answer, events: [{ name: 'activate_skill', arguments: { name: 'ud-validate' }, ok: true, output: '' }] }));
  assert.equal(activated.first_failure, 'no_ud_activation');
  const shell = gradeLoopEpisode(episode('S7', 'cli-shell', { final_answer: answer, events: [{ name: 'bash', arguments: { command: 'cat .agents/skills/ud-validate/SKILL.md' }, ok: true, output: '' }] }));
  assert.equal(shell.first_failure, 'no_ud_activation');
  // Every product operation counts, not only the validation family (r5: language_rules_report on prose); host discovery does not.
  const rules = gradeLoopEpisode(episode('S7', 'mcp-all', { final_answer: answer, events: [{ name: 'read_file', ok: true, arguments: {}, output: '' }, { name: 'tool_search', ok: true, arguments: {}, output: '' }, { name: 'language_rules_report', via: 'tool_call', ok: false, arguments: {}, output: '' }] }));
  assert.equal(rules.first_failure, 'no_ud_activation');
  assert.equal(gradeLoopEpisode(episode('S7', 'mcp-all', { final_answer: answer, events: [{ name: 'read_file', ok: true, arguments: {}, output: '' }, { name: 'tool_search', ok: true, arguments: {}, output: '' }] })).passed, true);
  assert.throws(() => gradeLoopEpisode(episode('S9', 'mcp-scoped')), /not defined yet/);
});

test('G3-G6 grading requires a successful plugin operation and the independently known answer facts', () => {
  const skill = name => ({ name: 'activate_skill', arguments: { name }, ok: true, output: '' });
  const op = name => ({ name, ok: true, arguments: {}, output: '' });
  const s3 = 'UAS 80% (4/5), LAS 60% (3/5) over 5 eligible tokens. compare-1: token 1 head differs; token 2 relation nsubj vs obj.';
  const g3 = extra => gradeLoopEpisode(episode('S3', 'mcp-scoped', { final_answer: s3, events: [skill('ud-compare'), op('attachment_score_report')], ...extra }));
  assert.equal(g3().passed, true, JSON.stringify(g3().stages));
  assert.equal(g3({ events: [skill('ud-compare'), op('read_file')] }).first_failure, 'ud_operation_succeeded');
  assert.equal(g3({ events: [skill('ud-compare'), { ...op('x_report'), ok: false }] }).first_failure, 'ud_operation_succeeded');
  assert.equal(g3({ final_answer: 'UAS 75%, LAS 60% (3/5), 5 tokens.' }).first_failure, 'uas_reported');
  assert.equal(g3({ events: [{ name: 'bash', ok: true, arguments: { command: 'cat .agents/skills/ud-compare/SKILL.md' }, output: '' }, { name: 'bash', ok: true, arguments: { command: 'ud-agent call parse_score_report --input r.json --allow-root "$PWD"' }, output: '' }], harness: 'cli-shell' }).passed, true);
  assert.equal(g3({ events: [skill('ud-compare'), { name: 'bash', ok: true, arguments: { command: 'echo ud-agent call x' }, output: '' }] }).first_failure, 'ud_operation_succeeded');
  const s4 = 'Nominal subjects precede their heads in 2 of 3 cases (news-1 token 1 before head 2; news-2 token 2 after head 1). The denominator is 3 nsubj relations; fiction is excluded, only news sentences.';
  assert.equal(gradeLoopEpisode(episode('S4', 'mcp-all', { final_answer: s4, events: [skill('ud-investigate'), { ...op('corpus_query'), via: 'tool_call' }] })).passed, true);
  assert.equal(gradeLoopEpisode(episode('S4', 'mcp-all', { final_answer: s4.replace('fiction is excluded, only news sentences', 'all sentences'), events: [skill('ud-investigate'), op('corpus_query')] })).first_failure, 'scope_explained');
  const preview = { 'preview/arc.svg': '<svg><text>Cats</text><text>chased</text><text>mice</text></svg>' };
  const g5 = extra => gradeLoopEpisode(episode('S5', 'mcp-scoped', { final_answer: 'The red arc is obj from chased to mice; preview written.', new_files: ['preview/arc.svg'], output_texts: preview, events: [skill('ud-rules-docs'), { name: 'read_file', ok: true, arguments: { path: 'diagram.png' }, output: '' }], ...extra }));
  assert.equal(g5().passed, true, JSON.stringify(g5().stages));
  assert.equal(g5({ events: [skill('ud-rules-docs')] }).first_failure, 'image_viewed');
  assert.equal(g5({ output_texts: { 'preview/arc.txt': 'Cats chased mice' } }).first_failure, 'preview_written');
  assert.equal(g5({ new_files: ['preview/arc.svg', 'notes.md'] }).first_failure, 'inputs_unchanged');
  const hash = 'a'.repeat(64);
  const s6 = `Packaged treebank.conllu, README.md and LICENSE (archive sha256 ${hash}); validation completed on the packaged bytes. Official registry readiness is not assessed.`;
  const g6 = extra => gradeLoopEpisode(episode('S6', 'mcp-scoped', { final_answer: s6, new_files: ['handover/local-eval-1.tar'], events: [skill('ud-release'), op('release_package_plan')], ...extra }));
  assert.equal(g6().passed, true, JSON.stringify(g6().stages));
  assert.equal(g6({ new_files: [] }).first_failure, 'handover_written');
  assert.equal(g6({ final_answer: `${s6} It was officially accepted.` }).first_failure, 'no_official_acceptance_claim');
});

test('loop commands parse separately and require explicit opt-in inputs', () => {
  const parsed = parseArguments(['loop-run', '--opt-in', '--group', 'G1', '--label', 'before', '--installation', 'i', '--python', 'p', '--model-dir', 'm', '--harness', 'mcp-scoped', '--generation-seconds', '120']);
  assert.deepEqual(parsed, { command: 'loop-run', options: { optIn: true, group: 'G1', label: 'before', installation: path.resolve('i'), python: path.resolve('p'), modelDir: path.resolve('m'), harness: 'mcp-scoped', generationSeconds: 120 } });
  assert.throws(() => parseArguments(['loop-run', '--opt-in', '--group', 'G1']), /requires/);
  assert.throws(() => parseArguments(['loop-run', '--session', 'x']), /unsupported loop option/);
  assert.deepEqual(parseArguments(['loop-analyze', '--runs', 'a,b', '--output', 'o', '--python', 'p']).options.runs, [path.resolve('a'), path.resolve('b')]);
  assert.equal(parseArguments(['loop-groups']).command, 'loop-groups');
});

test('deferred discovery selects exact schemas and lists bounded keyword matches', () => {
  const tools = [{ name: 'validation_report', description: 'Validate .conllu files, not prose.' }, { name: 'sentence_validation_report', description: 'Validate one pasted sentence.' }, { name: 'tree_edit', description: 'Edit one tree.' }];
  assert.deepEqual(searchDeferredTools(tools, 'select:mcp__ud__validation_report,tree_edit').selected.map(tool => tool.name), ['validation_report', 'tree_edit']);
  assert.deepEqual(searchDeferredTools(tools, 'validation_report').selected.map(tool => tool.name), ['validation_report']);
  const found = searchDeferredTools(tools, 'validate conllu files', 1);
  assert.deepEqual([found.selected.length, found.matches.map(tool => tool.name)], [0, ['validation_report']]);
  assert.deepEqual(searchDeferredTools(tools, 'weather'), { selected: [], matches: [] });
  assert.match(systemPrompt('mcp-all', '/w/treebank', [], ['validation_report']), /Deferred tools[^\n]*\nvalidation_report$/);
});

test('loop-interpret parses separately and extracts only skill-name call prefixes from first requests', async () => {
  const parsed = parseArguments(['loop-interpret', '--opt-in', '--installation', 'i', '--python', 'p', '--model-dir', 'm', '--output', 'o', '--runs', 'a', '--candidates', 'c.json']);
  assert.deepEqual(parsed.options, { optIn: true, installation: path.resolve('i'), python: path.resolve('p'), modelDir: path.resolve('m'), output: path.resolve('o'), runs: [path.resolve('a')], candidates: path.resolve('c.json') });
  assert.throws(() => parseArguments(['loop-interpret', '--opt-in', '--output', 'o']), /requires/);
  const { mkdtempSync, mkdirSync, writeFileSync, rmSync } = await import('node:fs');
  const os = await import('node:os');
  const { skillCallPrefixes } = await import('../../evals/local/loop.mjs');
  const run = mkdtempSync(path.join(os.tmpdir(), 'ud-loop-prefix-'));
  try {
    mkdirSync(path.join(run, 'episodes')); mkdirSync(path.join(run, 'generations'));
    writeFileSync(path.join(run, 'run.json'), JSON.stringify({ rows: [{ id: 'S1-cli-shell-seed-17', harness: 'cli-shell', scenario_id: 'S1', seed: 17 }] }));
    writeFileSync(path.join(run, 'episodes', 'S1-cli-shell-seed-17.json'), JSON.stringify({ episode: { requests: [{ prompt_tokens: 700 }] } }));
    writeFileSync(path.join(run, 'generations', 'a.json'), JSON.stringify({ seed: 17, prompt_tokens: 700, parser_status: 'rejected', text: 'Let me check.\n<tool_call>\n<function=ud-validate>\n</function>\n</tool_call>' }));
    writeFileSync(path.join(run, 'generations', 'b.json'), JSON.stringify({ seed: 17, prompt_tokens: 700, parser_status: 'rejected', text: '<tool_call>\n<function=bash>\n</parameter>' }));
    writeFileSync(path.join(run, 'generations', 'c.json'), JSON.stringify({ seed: 18, prompt_tokens: 900, parser_status: 'rejected', text: '<tool_call>\n<function=ud-edit>' }));
    const found = skillCallPrefixes([run], ['ud-validate', 'ud-edit']);
    assert.deepEqual(found.map(item => [item.emitted, item.prefix]), [['ud-validate', 'Let me check.\n<tool_call>\n<function=']]);
  } finally { rmSync(run, { recursive: true, force: true }); }
});

test('loop-interpret uptake objective contrasts loading the skill with observed first actions', async () => {
  const parsed = parseArguments(['loop-interpret', '--opt-in', '--installation', 'i', '--python', 'p', '--model-dir', 'm', '--output', 'o', '--objective', 'uptake']);
  assert.equal(parsed.options.objective, 'uptake');
  assert.throws(() => parseArguments(['loop-interpret', '--opt-in', '--installation', 'i', '--python', 'p', '--model-dir', 'm', '--output', 'o', '--objective', 'other']), /Invalid --objective/);
  const { mkdtempSync, mkdirSync, writeFileSync, rmSync } = await import('node:fs');
  const os = await import('node:os');
  const { observedFirstActions, uptakeReference, LOOP_GROUPS } = await import('../../evals/local/loop.mjs');
  assert.deepEqual(LOOP_GROUPS.G1.negatives, ['S7']);
  assert.deepEqual(uptakeReference('cli-shell', 'ud-validate', '/w/treebank'), { prefix: '<tool_call>\n<function=bash>\n<parameter=command>\n', sequences: ['cat .agents/skills/ud-validate/SKILL.md\n', 'cat /w/treebank/.agents/skills/ud-validate/SKILL.md\n'] });
  assert.deepEqual(uptakeReference('mcp-scoped', 'ud-validate', '/w/treebank'), { prefix: '<tool_call>\n<function=', sequences: ['activate_skill>'] });
  const run = mkdtempSync(path.join(os.tmpdir(), 'ud-loop-uptake-'));
  try {
    mkdirSync(path.join(run, 'episodes'));
    const rows = [['S1-cli-shell-seed-17', 'cli-shell', [{ type: 'tool_call', name: 'bash', arguments: { command: 'ls -la' } }]],
      ['S1-cli-shell-seed-23', 'cli-shell', [{ type: 'format_error', name: 'format_error' }, { type: 'tool_call', name: 'bash', arguments: { command: 'ls -la\necho' } }]],
      ['S1-cli-shell-seed-47', 'cli-shell', [{ type: 'tool_call', name: 'bash', arguments: { command: 'cat .agents/skills/ud-validate/SKILL.md' } }]],
      ['S1-mcp-all-seed-17', 'mcp-all', [{ type: 'tool_call', name: 'validation_report', via: 'tool_call', arguments: {} }]]];
    writeFileSync(path.join(run, 'run.json'), JSON.stringify({ rows: rows.map(([id, harness]) => ({ id, harness, scenario_id: 'S1' })) }));
    for (const [id, harness, events] of rows) writeFileSync(path.join(run, 'episodes', `${id}.json`), JSON.stringify({ episode: { harness, events } }));
    assert.deepEqual(observedFirstActions([run], { harness: 'cli-shell', scenarioId: 'S1', skill: 'ud-validate' }), [{ text: 'ls -la\n', count: 2 }]);
    assert.deepEqual(observedFirstActions([run], { harness: 'mcp-all', scenarioId: 'S1', skill: 'ud-validate' }), [{ text: 'tool_call>', count: 1 }]);
  } finally { rmSync(run, { recursive: true, force: true }); }
});

test('loop-interpret after-skill case teacher-forces the skill load and targets the routes the skill advertises', async () => {
  const { afterSkillCase } = await import('../../evals/local/loop.mjs');
  const [skill] = skillCatalog(root).filter(item => item.name === 'ud-validate');
  const request = { harness: 'mcp-scoped', scenario_id: 'S1', body: { messages: [{ role: 'system', content: 's' }, { role: 'user', content: 'u' }], tools: ['activate_skill', 'read_file', 'validation_report'].map(name => ({ function: { name } })) } };
  const scoped = afterSkillCase(request, skill, [], root);
  assert.equal(scoped.label, 'mcp-scoped/S1@after-skill');
  assert.deepEqual([scoped.valid_sequences, scoped.invalid_sequences], [['validation_report>'], ['read_file>']]);
  assert.deepEqual(scoped.body.messages.slice(2).map(message => message.role), ['assistant', 'tool']);
  assert.equal(scoped.body.messages[3].content, skill.body);
  const shell = afterSkillCase({ ...request, harness: 'cli-shell' }, skill, ['ls -la\n'], root);
  assert.ok(shell.valid_sequences.length > 0 && shell.valid_sequences.every(text => text.startsWith('ud-agent ') && !/FILE|OPERATION/.test(text)));
  assert.match(shell.body.messages[3].content, /^exit 0\n---\nname: ud-validate/);
  assert.deepEqual(shell.invalid_sequences, ['ls -la\n']);
});

test('tool_search refuses schemas over the tool budget and names smaller related tools that fit', () => {
  const tool = (name, description, chars) => ({ name, description, inputSchema: { type: 'object', description: 'x'.repeat(chars) } });
  const deferred = [tool('tree_edit', 'Preview or apply sentence edits.', 90_000), tool('tree_replace', 'Replace a sentence.', 600), tool('tree_text_set', 'Set sentence text comment.', 600), tool('token_get', 'Read token.', 600)];
  const refused = loadableSchemas([deferred[0]], deferred, [], 8_192);
  assert.deepEqual(refused.load, []);
  assert.equal(refused.refused[0].tool.name, 'tree_edit');
  assert.deepEqual(refused.refused[0].alternatives.map(item => item.name), ['tree_replace', 'tree_text_set']);
  assert.deepEqual(loadableSchemas([deferred[1]], deferred, [], 8_192).load.map(item => item.name), ['tree_replace']);
  // Already loaded schemas count against the budget; re-selecting a loaded tool is always allowed.
  const room = declaredToolTokens(deferred[1]) + declaredToolTokens(deferred[2]);
  assert.deepEqual(loadableSchemas([deferred[2]], deferred, ['tree_replace'], room - 1).load, []);
  assert.deepEqual(loadableSchemas([deferred[1]], deferred, ['tree_replace'], 1).load.map(item => item.name), ['tree_replace']);
});

test('undeclared tool names get the mirrored host reply', () => {
  assert.equal(unknownToolMessage('mcp-scoped', 'tree_lst', ['activate_skill', 'read_file', 'tree_list', 'tree_get']), 'Tool "tree_lst" not found in registry. Tools must use the exact names that are registered. Did you mean one of: "tree_list", "tree_get", "read_file"?');
  assert.equal(unknownToolMessage('mcp-all', 'x', ['tool_search']), 'Tool "x" not found in registry. Tools must use the exact names that are registered. Did you mean "tool_search"?');
  assert.match(unknownToolMessage('cli-shell', 'ud-validate', ['bash']), /The only tool is bash/);
  assert.equal(unknownToolMessage('cli-shell', 'ud-validate', ['bash'], ['ud-validate']), 'That call was not run. The only tool is bash; ud-validate is a shell command here, not a tool: call bash {"command": "ud-validate FILE"} with the file you mean, or answer in plain text.');
  assert.equal(unknownToolMessage('mcp-all', 'ud-edit', ['activate_skill', 'tool_search', 'tree_edit'], ['ud-edit']), 'Tool "ud-edit" not found in registry. "ud-edit" is a skill (an instructions document), not a tool. Only if the task matches its description, load it with activate_skill {"name": "ud-edit"}; otherwise continue without it.');
  assert.match(unknownToolMessage('mcp-all', 'ud-edit', ['tool_search', 'tree_edit'], ['ud-edit']), /Did you mean/);
  assert.equal(unknownToolMessage('cli-shell', 'grep_tool', ['bash'], ['ud-validate']), 'That call was not run. The only tool is bash; call bash with one shell command, or answer in plain text.');
});

test('activate_skill mirrors Gemini CLI: enum of installed names, names in the description, and the not-found reply', async () => {
  const { activateSkillTool, unknownSkillMessage } = await import('../../evals/local/loop.mjs');
  const tool = activateSkillTool(['ud-edit', 'ud-validate']).function;
  assert.deepEqual(tool.parameters.properties.name.enum, ['ud-edit', 'ud-validate']);
  assert.match(tool.description, /^Activates a specialized agent skill by name \(Available: 'ud-edit', 'ud-validate'\)\./);
  assert.equal(activateSkillTool([]).function.parameters.properties.name.enum, undefined);
  assert.equal(unknownSkillMessage('tree_list', ['ud-edit', 'ud-validate']), 'Skill "tree_list" not found. Available skills are: ud-edit, ud-validate');
});

test('cli-shell catalog lines carry the SKILL.md path like Codex render_skills_section; MCP lines do not', () => {
  const catalog = [{ name: 'ud-validate', description: 'Find errors.' }];
  assert.match(systemPrompt('cli-shell', '/w', catalog), /\n- ud-validate: Find errors\. \(file: \.agents\/skills\/ud-validate\/SKILL\.md\)\n/);
  assert.match(systemPrompt('mcp-scoped', '/w', catalog), /\n- ud-validate: Find errors\.\n/);
});

test('host file tools name the other tool for a folder given to read_file or a file given to list_directory', async () => {
  const { readOrList } = await import('../../evals/local/loop.mjs');
  const { mkdtempSync, writeFileSync, rmSync } = await import('node:fs');
  const os = await import('node:os'), path = await import('node:path');
  const root = mkdtempSync(path.join(os.tmpdir(), 'ud-host-')), file = path.join(root, 'a.conllu');
  try {
    writeFileSync(file, '# x\n');
    assert.equal(readOrList('read_file', file, 'a.conllu'), '# x\n');
    assert.equal(readOrList('list_directory', root, '.'), 'a.conllu');
    assert.throws(() => readOrList('read_file', root, '.'), /^Error: Path is a directory, not a file: \.\. List it with list_directory \{"path": "\."\}\.$/);
    assert.throws(() => readOrList('list_directory', file, 'a.conllu'), /^Error: Path is not a directory: a\.conllu\. It is a file; read it with read_file \{"path": "a\.conllu"\}\.$/);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('loop-run selects a registry model and its server; MiniCPM stays the default', () => {
  assert.equal(loopModel().model.id, 'minicpm');
  assert.equal(loopModel().server, 'evals/local/minicpm_server.py');
  for (const id of ['lfm3', 'bonsai']) {
    assert.equal(loopModel(id).model.id, id);
    assert.equal(loopModel(id).server, 'evals/local/loop_mlx_server.py');
  }
  assert.throws(() => loopModel('qwen'), /Unknown registry model: qwen/);
  const base = ['loop-run', '--opt-in', '--group', 'G1', '--label', 'x', '--installation', 'i', '--python', 'p', '--model-dir', 'm'];
  assert.equal(parseArguments([...base, '--model-id', 'lfm3']).options.modelId, 'lfm3');
  assert.throws(() => parseArguments([...base, '--model-id', 'qwen']), /Invalid --model-id/);
});

test('the model request timeout stays at 300 s by default and can be raised by flag or env', async () => {
  assert.equal(DEFAULT_REQUEST_TIMEOUT_MS, 300_000);
  assert.equal(loopRequestTimeoutMs(), 300_000);
  assert.equal(loopRequestTimeoutMs({ env: {} }), 300_000);
  assert.equal(loopRequestTimeoutMs({ env: { UD_LOOP_REQUEST_TIMEOUT_MS: '1800000' } }), 1_800_000);
  assert.equal(loopRequestTimeoutMs({ requestTimeoutSeconds: 1800, env: { UD_LOOP_REQUEST_TIMEOUT_MS: '300000' } }), 1_800_000);
  assert.equal(loopRequestTimeoutMs({ requestTimeoutSeconds: 0, env: { UD_LOOP_REQUEST_TIMEOUT_MS: '1800000' } }), 1_800_000);
  const base = ['loop-run', '--opt-in', '--group', 'G1', '--label', 'x', '--installation', 'i', '--python', 'p', '--model-dir', 'm'];
  assert.equal(parseArguments([...base, '--request-timeout-seconds', '1800']).options.requestTimeoutSeconds, 1800);
  assert.throws(() => parseArguments([...base, '--request-timeout-seconds', '0']), /Invalid --request-timeout-seconds/);
  const http = await import('node:http');
  const server = http.createServer((request, response) => setTimeout(() => { response.writeHead(200, { 'content-type': 'application/json' }); response.end(JSON.stringify({ ok: true })); }, 250));
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const url = `http://127.0.0.1:${server.address().port}/`;
  try {
    await assert.rejects(() => requestJson(url, { timeoutMs: 50 }), /REQUEST_TIMEOUT:50/);
    assert.deepEqual(await requestJson(url, { timeoutMs: 2000 }), { status: 200, value: { ok: true }, text: '{"ok":true}' });
  } finally { await new Promise(resolve => server.close(resolve)); }
});

test('skillLoadHint names the load how-to on .conllu or tool_search and stays silent on S7 .txt', () => {
  assert.equal(skillLoadHint('mcp-all', { loaded: true, pathOrCommand: 'a.conllu' }), '');
  assert.match(skillLoadHint('mcp-all', { pathOrCommand: '' }), /activate_skill \{"name": "NAME"\}/);
  assert.match(skillLoadHint('mcp-scoped', { pathOrCommand: 'a.conllu' }), /activate_skill/);
  assert.match(skillLoadHint('cli-shell', { pathOrCommand: 'cat a.conllu b.conllu' }), /cat \.agents\/skills\/NAME\/SKILL\.md/);
  assert.match(skillLoadHint('cli-shell', { pathOrCommand: 'cat report.txt' }), /no UD skill applies/);
  assert.equal(skillLoadHint('mcp-scoped', { pathOrCommand: 'report.txt' }), 'This is not a CoNLL-U .conllu file, so no UD skill applies.');
  assert.equal(skillLoadHint('cli-shell', { pathOrCommand: 'ls -la /tmp/treebank/' }), '');
});

test('each G2-G6 and S1 prompt matches only its skill; the S7 prose negative matches none', async () => {
  const { SCENARIOS } = await import('../../evals/local/scenarios.mjs');
  const catalog = skillCatalog(process.cwd());
  const byId = Object.fromEntries((Array.isArray(SCENARIOS) ? SCENARIOS : Object.values(SCENARIOS)).map(item => [item.id, item]));
  const expected = { S1: 'ud-validate', S2: 'ud-edit', S3: 'ud-compare', S4: 'ud-investigate', S5: 'ud-rules-docs', S6: 'ud-release' };
  for (const [id, skill] of Object.entries(expected)) {
    const hits = skillsMatchingPrompt(byId[id].prompt, catalog);
    assert.deepEqual(hits, [skill], `${id} matched ${hits} expected [${skill}] tokens=${skillMatchTokens(catalog.find(s => s.name === skill).description)}`);
  }
  assert.deepEqual(skillsMatchingPrompt(byId.S7.prompt, catalog), [], `S7 matched ${skillsMatchingPrompt(byId.S7.prompt, catalog)}`);
});

test('loop-run accepts --scenario to run a subset of a group', () => {
  const base = ['loop-run', '--opt-in', '--group', 'G1', '--label', 'x', '--installation', 'i', '--python', 'p', '--model-dir', 'm'];
  assert.equal(parseArguments([...base, '--scenario', 'S1']).options.scenario, 'S1');
  assert.equal(parseArguments([...base, '--scenario', 'S1,S7']).options.scenario, 'S1,S7');
});
