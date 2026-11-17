// SPDX-License-Identifier: MIT
import { test } from 'vitest';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { projectWordingSuggestion } from '../../evals/local/wording-oracle.mjs';

const original = readFileSync(new URL('../../evals/local/fixtures/report.txt', import.meta.url), 'utf8');
const valid = 'Because the team completed the planned interviews, we can finalize the summary. The response rate increased from 40 percent to 55 percent. The next review is Friday.';

test('S7 projects a fact-preserving rewrite independently of an exact original quotation', () => {
  for (const answer of [valid, `**Current content:**\n\n${original}\n\n**Suggested clearer version:**\n\n${valid}`, `${original}\n\n${valid}`, original.split('\n').map(line => `> ${line}`).join('\n') + '\n\n' + valid]) {
    const result = projectWordingSuggestion(answer, original);
    assert.equal(result.changed, true); assert.equal(result.facts, true);
  }
});
test('S7 recognizes a separately labelled concise rewrite with an enabling clause', () => {
  const answer = `**Current content:**\n"${original.trim()}"\n\n**Suggested clearer version:**\n"Quarterly Operations Report\n\nThe team completed all planned interviews, enabling us to finalize the summary. Response rates improved from 40% to 55%. The next review is scheduled for Friday."`;
  const result = projectWordingSuggestion(answer, original);
  assert.equal(result.facts, true); assert.equal(result.changed, true);
  assert.equal(projectWordingSuggestion(valid + ' This is a 15 point increase.', original).facts, null, 'additional derived facts need independent review');
});
test('S7 never lets original quoted facts rescue an incorrect suggestion', () => {
  for (const bad of [valid.replace('55', '65'), valid.replace('Friday', 'Monday'), valid.replace('increased', 'decreased'), valid.replace('completed', 'not completed'), valid.replace('completed the planned interviews', 'completed some planned interviews'), valid.replace('can finalize', 'cannot finalize'), valid.replace('is Friday', 'is not Friday'), valid.replace('40 percent to 55', '55 percent to 40')]) {
    const result = projectWordingSuggestion(`Current content:\n${original}\n\nSuggested version:\n${bad}`, original);
    assert.equal(result.facts, false, bad);
  }
});
test('unchanged text fails and unrecognized or multiple suggestions stay incomplete', () => {
  for (const answer of [original, `Suggested version:\n${original}`]) assert.equal(projectWordingSuggestion(answer, original).changed, false);
  assert.equal(projectWordingSuggestion('Friday has 40 and 55. Clearer wording could improve this report.', original).facts, null);
  const ambiguous = projectWordingSuggestion(`Suggested version:\n${valid}\n\nRevised wording:\n${valid}`, original);
  assert.equal(ambiguous.facts, null); assert.equal(ambiguous.changed, null);
  assert.equal(projectWordingSuggestion('x'.repeat(65_537), original).facts, null);
});
