/** Non-executing Git config/include preflight. The source config is never
 * supplied to Git; only read-only revision-resolution settings are projected. */
import path from 'node:path';

export type GitConfigEntry = { section: string; subsection?: string; key: string; value: string | null };
const lower = (value: string) => value.replace(/[A-Z]/g, character => character.toLowerCase());
const trim = (value: string) => value.replace(/^[ \t\r]+|[ \t\r]+$/g, '');
function invalid(): never { throw new Error('GIT_METADATA_CONFIG_INVALID'); }
function value(raw: string): string {
  const output: { value: string; protected: boolean }[] = []; let quoted = false;
  for (let at = 0; at < raw.length; at++) {
    const character = raw[at]!;
    if (character === '"') { quoted = !quoted; continue; }
    if (character === '\\') {
      const escaped = raw[++at]; const decoded = ({ n: '\n', t: '\t', b: '\b', '\\': '\\', '"': '"' } as Record<string, string>)[escaped ?? ''];
      if (decoded === undefined) invalid(); output.push({ value: decoded, protected: true });
    } else output.push({ value: character, protected: quoted });
  }
  if (quoted) invalid();
  while (output.length && !output[0]!.protected && /^[ \t\r]$/.test(output[0]!.value)) output.shift();
  while (output.length && !output.at(-1)!.protected && /^[ \t\r]$/.test(output.at(-1)!.value)) output.pop();
  return output.map(item => item.value).join('');
}
export function parseGitConfig(bytes: Buffer): GitConfigEntry[] {
  if (bytes.length > 1024 * 1024 || bytes.includes(0)) invalid();
  let source = bytes.toString('latin1'); if (source.startsWith('\xef\xbb\xbf')) source = source.slice(3);
  const lines: string[] = []; let line = '', quote = false, escape = false, comment = false;
  for (const character of source + '\n') {
    if (character === '\n') {
      if (!comment && escape) { line = line.slice(0, -1); escape = false; continue; }
      if (quote) invalid(); lines.push(line); line = ''; comment = false; escape = false; continue;
    }
    if (comment) continue;
    if (escape) { line += character; escape = false; continue; }
    if (character === '\\') { line += character; escape = true; continue; }
    if (character === '"') { quote = !quote; line += character; continue; }
    if (!quote && (character === '#' || character === ';')) { comment = true; continue; }
    line += character;
  }
  if (line) { if (quote) invalid(); lines.push(line); }
  const result: GitConfigEntry[] = []; let section: string | undefined, subsection: string | undefined;
  for (const physical of lines) {
    let line = trim(physical); if (!line) continue;
    if (line.startsWith('[')) {
      const match = /^\[[ \t]*([A-Za-z0-9.-]+)(?:[ \t]+"((?:[^"\\]|\\.)*)")?[ \t]*\](.*)$/.exec(line); if (!match) invalid();
      section = lower(match[1]!); subsection = match[2]?.replace(/\\(.)/g, '$1');
      if (subsection === undefined && section.includes('.')) { const dot = section.indexOf('.'); subsection = section.slice(dot + 1); section = section.slice(0, dot); }
      line = trim(match[3]!); if (!line) continue;
    }
    const match = /^([A-Za-z][A-Za-z0-9-]*)(?:[ \t]*=[ \t]*(.*))?$/.exec(line); if (!match || !section) invalid();
    if (result.length >= 20000) invalid(); result.push({ section, ...(subsection === undefined ? {} : { subsection }), key: lower(match[1]!), value: match[2] === undefined ? null : value(match[2]) });
  }
  return result;
}
export function gitConfigText(value: string): string { return new TextDecoder('utf-8', { fatal: true }).decode(Buffer.from(value, 'latin1')); }

type GlobToken = { kind: 'char'; value: string } | { kind: 'set'; values: Set<string>; negative: boolean } | { kind: 'star' } | { kind: 'all' } | { kind: 'directories' } | { kind: 'one' };
/** Byte-oriented wildcard DP, bounded O(pattern*text), without regex backtracking. */
export function gitWildmatch(pattern: string | Buffer, text: string | Buffer, insensitive = false): boolean {
  pattern = Buffer.from(pattern).toString('latin1'); text = Buffer.from(text).toString('latin1');
  if (pattern.length * Math.max(1, text.length) > 2_000_000 || pattern.length > 4096 || text.length > 32768) throw new Error('GIT_CONFIG_CONDITION_TOO_LARGE');
  if (insensitive) { pattern = lower(pattern); text = lower(text); }
  const tokens: GlobToken[] = [];
  for (let at = 0; at < pattern.length; at++) {
    const character = pattern[at]!;
    if (character === '\\' && at + 1 < pattern.length) { tokens.push({ kind: 'char', value: pattern[++at]! }); continue; }
    if (character === '?') { tokens.push({ kind: 'one' }); continue; }
    if (character === '*') {
      let end = at + 1; while (pattern[end] === '*') end++;
      if (end - at >= 2 && (at === 0 || pattern[at - 1] === '/') && (end === pattern.length || pattern[end] === '/')) { tokens.push({ kind: end === pattern.length ? 'all' : 'directories' }); at = end === pattern.length ? end - 1 : end; }
      else { tokens.push({ kind: 'star' }); at = end - 1; } continue;
    }
    if (character === '[') {
      let end = at + 1; const negative = pattern[end] === '!' || pattern[end] === '^'; if (negative) end++;
      const values = new Set<string>(); let first = true;
      while (end < pattern.length && (pattern[end] !== ']' || first)) {
        first = false;
        if (pattern.slice(end, end + 2) === '[:') {
          const close = pattern.indexOf(':]', end + 2), category = close < 0 ? '' : pattern.slice(end + 2, close);
          const classes: Record<string, (code: number) => boolean> = { alnum: c => c >= 48 && c <= 57 || c >= 65 && c <= 90 || c >= 97 && c <= 122, alpha: c => c >= 65 && c <= 90 || c >= 97 && c <= 122, blank: c => c === 9 || c === 32, cntrl: c => c < 32 || c === 127, digit: c => c >= 48 && c <= 57, graph: c => c >= 33 && c <= 126, lower: c => c >= 97 && c <= 122, print: c => c >= 32 && c <= 126, punct: c => c >= 33 && c <= 126 && !(c >= 48 && c <= 57 || c >= 65 && c <= 90 || c >= 97 && c <= 122), space: c => c === 32 || c >= 9 && c <= 13, upper: c => c >= 65 && c <= 90, xdigit: c => c >= 48 && c <= 57 || c >= 65 && c <= 70 || c >= 97 && c <= 102 };
          const accepts = classes[category]; if (!accepts) throw new Error('GIT_CONFIG_CONDITION_UNSUPPORTED');
          for (let code = 0; code < 128; code++) if (accepts(code)) values.add(String.fromCharCode(code)); end = close + 2; continue;
        }
        let start = pattern[end++]!; if (start === '\\' && end < pattern.length) start = pattern[end++]!;
        if (pattern[end] === '-' && pattern[end + 1] !== ']' && end + 1 < pattern.length) { end++; let finish = pattern[end++]!; if (finish === '\\' && end < pattern.length) finish = pattern[end++]!; for (let code = start.charCodeAt(0); code <= finish.charCodeAt(0); code++) values.add(String.fromCharCode(code)); }
        else values.add(start);
      }
      if (pattern[end] === ']') { tokens.push({ kind: 'set', values: insensitive ? new Set([...values].map(lower)) : values, negative }); at = end; continue; }
    }
    tokens.push({ kind: 'char', value: character });
  }
  let states = new Uint8Array(text.length + 1); states[0] = 1;
  for (const token of tokens) {
    const next = new Uint8Array(text.length + 1);
    if (token.kind === 'star' || token.kind === 'all') {
      for (let at = 0; at <= text.length; at++) { if (states[at]) next[at] = 1; if (at < text.length && next[at] && (token.kind === 'all' || text[at] !== '/')) next[at + 1] = 1; }
    } else if (token.kind === 'directories') {
      let active = false; for (let at = 0; at <= text.length; at++) { active ||= states[at] === 1; if (states[at] || active && at > 0 && text[at - 1] === '/') next[at] = 1; }
    } else {
      for (let at = 0; at < text.length; at++) if (states[at]) { const character = text[at]!; const matches = token.kind === 'char' ? character === token.value : token.kind === 'one' ? character !== '/' : character !== '/' && (token.negative !== token.values.has(character)); if (matches) next[at + 1] = 1; }
    }
    states = next;
  }
  return states[text.length] === 1;
}

export type GitIncludeContext = { gitDir: string; configFile: string; home: string; branch?: string | Buffer; remoteUrls: readonly (string | Buffer)[]; budget?: { remaining: number } };
export function includeConditionMatches(rawCondition: string | Buffer, context: GitIncludeContext): boolean {
  const condition = Buffer.from(rawCondition).toString('latin1');
  const matches = (pattern: string, selected: string | Buffer, insensitive = false) => { if (context.budget) { context.budget.remaining -= Math.max(1, pattern.length) * Math.max(1, Buffer.byteLength(selected)); if (context.budget.remaining < 0) throw new Error('GIT_CONFIG_CONDITION_TOO_LARGE'); } return gitWildmatch(Buffer.from(pattern, 'latin1'), selected, insensitive); };
  if (condition.startsWith('onbranch:')) { let pattern = condition.slice(9); if (pattern.endsWith('/')) pattern += '**'; return context.branch !== undefined && matches(pattern, context.branch); }
  const remotePrefix = 'hasconfig:remote.*.url:';
  if (condition.startsWith(remotePrefix)) return context.remoteUrls.some(url => matches(condition.slice(remotePrefix.length), url));
  const insensitive = condition.startsWith('gitdir/i:'); if (!insensitive && !condition.startsWith('gitdir:')) return false;
  let pattern = condition.slice(insensitive ? 9 : 7); const actual = context.gitDir.split(path.sep).join('/');
  if (pattern === '~' || pattern.startsWith('~/')) pattern = Buffer.from(context.home.split(path.sep).join('/')).toString('latin1') + pattern.slice(1);
  else if (pattern.startsWith('./')) pattern = Buffer.from(path.dirname(context.configFile).split(path.sep).join('/')).toString('latin1').replace(/[\\*?[\]]/g, '\\$&') + pattern.slice(1);
  else if (!path.isAbsolute(pattern)) pattern = '**/' + pattern;
  if (pattern.endsWith('/')) pattern += '**'; return matches(pattern, actual, insensitive);
}

export function includeTarget(raw: string | null, file: string, home: string): string {
  if (raw === null) invalid(); let value = gitConfigText(raw);
  if (!value || /[\0\r\n]/.test(value)) invalid();
  if (value.startsWith('%(prefix)')) throw new Error('GIT_CONFIG_INSTALL_PREFIX_UNSUPPORTED');
  if (value === '~' || value.startsWith('~/')) value = home + value.slice(1); else if (value.startsWith('~')) throw new Error('GIT_CONFIG_NAMED_HOME_UNSUPPORTED');
  return path.resolve(path.dirname(file), value);
}

/** Git quote.c C quoting; broken quoting follows Git's literal-path fallback.
 * Separators/comments are processed as bytes before any Unicode conversion. */
export function parseGitAlternates(bytes: Buffer): string[] {
  if (bytes.length > 65536 || bytes.includes(0)) throw new Error('GIT_ALTERNATE_INVALID');
  const output: string[] = []; let cursor = 0;
  while (cursor < bytes.length) {
    let end = bytes.indexOf(10, cursor); if (end < 0) end = bytes.length;
    if (bytes[cursor] === 35) { cursor = Math.min(bytes.length, end + 1); continue; }
    let decoded: Buffer | undefined;
    if (bytes[cursor] === 34) {
      const value: number[] = []; let at = cursor + 1;
      for (; at < bytes.length; at++) {
        const byte = bytes[at]!;
        if (byte === 34) { decoded = Buffer.from(value); end = at + 1; break; }
        if (byte !== 92) { value.push(byte); continue; }
        const escaped = bytes[++at]; const special: Record<number, number> = { 97:7,98:8,116:9,110:10,118:11,102:12,114:13,34:34,92:92 };
        if (escaped !== undefined && special[escaped] !== undefined) value.push(special[escaped]!);
        else if (escaped !== undefined && escaped >= 48 && escaped <= 51 && bytes[at + 1] !== undefined && bytes[at + 1]! >= 48 && bytes[at + 1]! <= 55 && bytes[at + 2] !== undefined && bytes[at + 2]! >= 48 && bytes[at + 2]! <= 55) { value.push((escaped - 48) * 64 + (bytes[at + 1]! - 48) * 8 + bytes[at + 2]! - 48); at += 2; }
        else break;
      }
    }
    const value = decoded ?? bytes.subarray(cursor, end); if (value.includes(0)) throw new Error('GIT_ALTERNATE_INVALID');
    if (value.length) output.push(new TextDecoder('utf-8', { fatal: true }).decode(value));
    cursor = Math.min(bytes.length, end + 1);
  }
  return output;
}
export function quoteGitAlternate(value: string): string {
  return '"' + [...Buffer.from(value)].map(byte => byte === 34 || byte === 92 ? '\\' + String.fromCharCode(byte) : byte >= 32 && byte < 127 ? String.fromCharCode(byte) : '\\' + byte.toString(8).padStart(3,'0')).join('') + '"';
}
