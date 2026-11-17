/** MIT. Conservative projection of a wording suggestion, separate from quoted source. */
const normalize = value => value.replace(/^[ \t]*>[ \t]?/gm, '').replace(/[*_`]/g, '').replace(/\s+/g, ' ').trim();
const suggestionHeading = /^(?:#{1,6}\s*)?(?:\*\*)?(?:(?:suggested|revised|clearer|improved|edited|rewritten|recommended)(?:\s+(?:clearer|report|business|quarterly))?\s+(?:version|wording|phrasing|text|report|paragraph|revision)|(?:suggestion|rewrite|revision))(?:\*\*)?\s*:?(?:\*\*)?\s*$/i;

/** No unrestricted semantic grading: recognizable suggestions get bounded fact
 * checks; unsupported prose stays incomplete for independent review. */
export function projectWordingSuggestion(answer, original) {
  if (typeof answer !== 'string' || !answer.trim() || answer.length > 65_536 || typeof original !== 'string') return { text: '', changed: null, facts: null };
  const lines = answer.split(/\r?\n/), headings = lines.map((line, index) => suggestionHeading.test(line.trim()) ? index : -1).filter(index => index >= 0);
  let selected = answer;
  if (headings.length > 1) return { text: '', changed: null, facts: null, reason: 'Multiple suggestions need independent review.' };
  if (headings.length === 1) {
    const after = lines.slice(headings[0] + 1);
    const end = after.findIndex(line => /^\s*(?:#{1,6}\s+|\*\*(?:why|changes|explanation|notes|original|current)\b)/i.test(line));
    selected = after.slice(0, end < 0 ? after.length : end).join('\n');
  } else {
    // Exact quotation removal allows an unlabelled rewrite after an original
    // quote. It does not allow original facts to satisfy the rewrite checks.
    const paragraphs = original.trim().split(/\n\s*\n/).filter(value => value.length > 40).map(normalize);
    selected = normalize(selected).replace(normalize(original), '');
    for (const paragraph of paragraphs) selected = selected.replaceAll(paragraph, '');
  }
  const text = normalize(selected), source = normalize(original);
  const originalParagraphs = original.trim().split(/\n\s*\n/).filter(value => value.length > 40).map(normalize);
  if (!text) return { text, changed: false, facts: false };
  const changed = text.length >= 80 && text !== source && !originalParagraphs.some(value => text.includes(value));
  const interview = /(?:complet(?:e|ed)|finish(?:ed)?|conducted|done).{0,45}interviews|interviews.{0,45}(?:complet(?:e|ed)|finish(?:ed)?|conducted|done)/i.test(text);
  const summary = /(?:can|could|ready|able|position|now|will|enabl(?:e[sd]?|ing)).{0,55}finali[sz]e.{0,30}summary|summary.{0,30}ready.{0,30}finali[sz]/i.test(text);
  const rate = /(?:increas(?:e[ds]?|ing)|rose|risen|grew|improv(?:e[ds]?|ing)).{0,35}(?:from\s*)?40(?:\s*(?:percent|%))?\s*(?:to|→|–|-)\s*55\s*(?:percent|%)/i.test(text);
  const review = /(?:next\s+)?review.{0,45}Friday|Friday.{0,45}(?:next\s+)?review/i.test(text);
  const contradicted = /\b(?:not|never|haven['’]t|hasn['’]t|incomplete|unfinished)\b.{0,30}(?:complete|finish|interviews)|interviews.{0,30}\b(?:not|incomplete|unfinished)\b/i.test(text) ||
    /\b(?:some|most|few|half|remaining|unfinished)\b.{0,20}(?:planned\s+)?interviews|interviews.{0,20}(?:remain|pending|unfinished)/i.test(text) ||
    /\b(?:cannot|can['’]t|unable|not ready)\b.{0,35}finali[sz]|\b(?:not|isn['’]t|won['’]t)\b.{0,20}Friday/i.test(text) ||
    /\b(?:Monday|Tuesday|Wednesday|Thursday|Saturday|Sunday)\b/i.test(text) ||
    /\b55(?:\s*(?:percent|%))?\s*(?:to|→|–|-)\s*40\b/i.test(text) ||
    /\b(?:decreas(?:e[ds]?|ing)|fell|dropped|declin(?:e[ds]?|ing))\b.{0,45}\b(?:40|55)\b/i.test(text);
  const numbers = [...text.matchAll(/\b\d+(?:\.\d+)?\b/g)].map(match => match[0]);
  const unexpectedNumber = numbers.some(value => !['40', '55'].includes(value));
  const ratePair = /(?:increas(?:e[ds]?|ing)|rose|risen|grew|improv(?:e[ds]?|ing)).{0,35}?(\d+(?:\.\d+)?)(?:\s*(?:percent|%))?\s*(?:to|→|–|-)\s*(\d+(?:\.\d+)?)/i.exec(text);
  const wrongRate = ratePair && (ratePair[1] !== '40' || ratePair[2] !== '55');
  return { text, changed, facts: contradicted || wrongRate ? false : unexpectedNumber ? null : interview && summary && rate && review ? true : null,
    checks: { interviews_completed: interview, summary_can_be_finalized: summary, rate_increased_40_to_55: rate, review_friday: review, contradicted, unexpected_number: unexpectedNumber } };
}
