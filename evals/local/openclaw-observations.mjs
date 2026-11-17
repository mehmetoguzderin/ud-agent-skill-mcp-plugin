/** MIT. Read-only projection of the pinned OpenClaw 2026.11.3 transcript. */
import { lstatSync } from 'node:fs';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { zstdDecompressSync } from 'node:zlib';

const object = value => value && typeof value === 'object' && !Array.isArray(value);
const nonempty = value => typeof value === 'string' && value.length > 0;
const MAX_BYTES = 32 * 1024 ** 2, MAX_EVENT_BYTES = 4 * 1024 ** 2, MAX_EVENTS = 4096;

/** Canonical assistant/toolResult messages preserve isError, unlike the chat
 * provider wire and CLI final JSON. Runtime trajectory events are buffered and
 * cannot establish status before the next provider request. */
export function nativeOpenClawTranscriptResults(events, sessionId) {
  const headers = events.filter(event => event?.type === 'session');
  if (!nonempty(sessionId) || headers.length !== 1 || headers[0].version !== 4 || headers[0].id !== sessionId) return [];
  const calls = new Map(), invalid = new Set(), completed = new Set(), results = [];
  for (const event of events) {
    if (event?.type !== 'message' || !nonempty(event.id) || !object(event.message)) continue;
    const message = event.message, runId = message.__openclaw?.runId;
    if (!nonempty(runId)) continue;
    if (message.role === 'assistant' && Array.isArray(message.content)) {
      for (const call of message.content) {
        if (call?.type !== 'toolCall' || !nonempty(call.id) || !nonempty(call.name) || !object(call.arguments)) continue;
        if (calls.has(call.id)) { invalid.add(call.id); continue; }
        calls.set(call.id, { name: call.name, arguments: call.arguments, runId, entryId: event.id });
      }
    }
    if (message.role !== 'toolResult') continue;
    const id = message.toolCallId, call = calls.get(id);
    if (!call || call.name !== message.toolName || call.runId !== runId || typeof message.isError !== 'boolean' ||
        !Array.isArray(message.content) || message.details?.openclawSyntheticMissingToolResult === true) continue;
    if (completed.has(id)) { invalid.add(id); continue; }
    completed.add(id);
    results.push({ id, name: call.name, arguments: call.arguments, failed: message.isError, source: 'native-openclaw-persistent-tool-result',
      native_evidence: { session_id: sessionId, run_id: runId, call_entry_id: call.entryId, result_entry_id: event.id, isError: message.isError } });
  }
  return results.filter(result => !invalid.has(result.id));
}

/** Read only the exact freshly launched main-agent session. SQLite transactions
 * see committed WAL data without copying a potentially inconsistent live DB.
 * All paths and sidecars are private, bounded ordinary files; no native code,
 * extensions, migrations, write statements, or other profiles are loaded. */
export function nativeOpenClawProfileResults(profile, sessionId) {
  if (!nonempty(sessionId)) throw new Error('OPENCLAW_NATIVE_SESSION_REQUIRED');
  let directory = profile;
  for (const name of ['', '.openclaw', 'agents', 'main', 'agent']) {
    if (name) directory = path.join(directory, name);
    const info = lstatSync(directory, { throwIfNoEntry: false });
    if (!info) return [];
    if (!info.isDirectory() || info.isSymbolicLink()) throw new Error('OPENCLAW_NATIVE_EVIDENCE_PATH_INVALID');
  }
  const file = path.join(directory, 'openclaw-agent.sqlite');
  let bytes = 0;
  for (const suffix of ['', '-wal', '-shm', '-journal']) {
    const info = lstatSync(file + suffix, { throwIfNoEntry: false });
    if (!info) { if (!suffix) return []; continue; }
    if (!info.isFile() || info.isSymbolicLink() || (bytes += info.size) > MAX_BYTES) throw new Error('OPENCLAW_NATIVE_EVIDENCE_PATH_INVALID');
  }
  const database = new DatabaseSync(file, { readOnly: true, allowExtension: false });
  try {
    database.exec('PRAGMA trusted_schema=OFF; PRAGMA query_only=ON; BEGIN');
    const tables = database.prepare("SELECT name FROM sqlite_schema WHERE type='table' AND name IN ('session_windows','transcript_events')").all();
    if (tables.length !== 2) return [];
    const session = database.prepare('SELECT session_key FROM session_windows WHERE session_id = ?').get(sessionId);
    if (!session) return [];
    if (session.session_key !== `agent:main:explicit:${sessionId}`) throw new Error('OPENCLAW_NATIVE_EVIDENCE_SESSION_INVALID');
    const rows = database.prepare('SELECT seq,event_json,event_zstd,event_utf8_bytes FROM transcript_events WHERE session_id = ? ORDER BY seq LIMIT ?').all(sessionId, MAX_EVENTS + 1);
    if (rows.length > MAX_EVENTS) throw new Error('OPENCLAW_NATIVE_EVIDENCE_TOO_LARGE');
    let total = 0, previous = -1;
    const events = rows.map(row => {
      if (!Number.isSafeInteger(row.seq) || row.seq <= previous) throw new Error('OPENCLAW_NATIVE_EVIDENCE_SEQUENCE_INVALID');
      previous = row.seq;
      if (!Number.isSafeInteger(row.event_utf8_bytes) || row.event_utf8_bytes < 1 || row.event_utf8_bytes > MAX_EVENT_BYTES ||
          (row.event_json === null) === (row.event_zstd === null)) throw new Error('OPENCLAW_NATIVE_EVIDENCE_EVENT_INVALID');
      const data = row.event_json === null ? zstdDecompressSync(row.event_zstd, { maxOutputLength: MAX_EVENT_BYTES }) : Buffer.from(row.event_json, 'utf8');
      if (data.length !== row.event_utf8_bytes || (total += data.length) > MAX_BYTES) throw new Error('OPENCLAW_NATIVE_EVIDENCE_EVENT_INVALID');
      return JSON.parse(data.toString('utf8'));
    });
    return nativeOpenClawTranscriptResults(events, sessionId);
  } finally { database.close(); }
}
