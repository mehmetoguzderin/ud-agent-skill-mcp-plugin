import casefoldData from '../../../workers/ud/src/ud_agent/unicode_casefold.json' with { type: 'json' };

// Both the coordinator and the worker use the same frozen Unicode mapping.
// Do not depend on the host JavaScript and Python Unicode versions agreeing.
const folds: Readonly<Record<string, string>> = casefoldData.mapping;
const assigned: readonly (readonly number[])[] = casefoldData.normalization_assigned_ranges;

function assigned16(codepoint: number): boolean {
  let left = 0, right = assigned.length;
  while (left < right) {
    const middle = Math.floor((left + right) / 2), range = assigned[middle]!;
    if (codepoint < range[0]!) right = middle;
    else if (codepoint > range[1]!) left = middle + 1;
    else return true;
  }
  return false;
}

/** Unicode16-unassigned scalars retain CCC0 even in newer host Unicode data. */
function frozenNfc(value: string): string {
  let chunk = '', result = '';
  for (const character of value) {
    if (assigned16(character.codePointAt(0)!)) chunk += character;
    else { result += chunk.normalize('NFC') + character; chunk = ''; }
  }
  return result + chunk.normalize('NFC');
}

export function portablePathKey(value: string): string {
  return Array.from(frozenNfc(value), character => folds[character] ?? character).join('');
}

/** Path rules shared with the Python worker receiver. */
export function validPortablePath(value: string): boolean {
  if (!value || Buffer.byteLength(value, 'utf8') > 4096 || /[\u0000-\u001f\u007f\\:]/u.test(value)) return false;
  // Unpaired UTF-16 surrogates cannot be encoded losslessly as UTF-8.
  if (Array.from(value).some(character => character.length === 1 && /[\ud800-\udfff]/u.test(character))) return false;
  const parts = value.split('/');
  if (parts.length > 64) return false;
  return parts.every(part => part !== '' && Buffer.byteLength(part, 'utf8') <= 255 && part !== '.' && part !== '..' && part.toLowerCase() !== '.git' &&
    !/^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i.test(part) && !/[. ]$/.test(part));
}
