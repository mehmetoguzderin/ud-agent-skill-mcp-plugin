// SPDX-License-Identifier: MIT
import { lstatSync, readFileSync } from 'node:fs';
import path from 'node:path';

/** These statuses are emitted by pinned model_tools._emit_post_tool_call_hook
 * and agent.tool_executor. Interpret the native status; never reclassify prose. */
export function nativeHermesResults(text) {
  const results = [], sessions = new Set(), ids = new Set();
  for (const line of text.split('\n')) {
    let event; try { event = JSON.parse(line); } catch { continue; }
    if (event?.type !== 'hermes.post_tool_call' || event.schema_version !== 1) continue;
    if (typeof event.tool_call_id !== 'string' || !event.tool_call_id || typeof event.tool_name !== 'string' || !event.tool_name
      || typeof event.session_id !== 'string' || !event.session_id || !event.args || typeof event.args !== 'object' || Array.isArray(event.args)
      || !Object.hasOwn(event, 'result') || !['ok', 'error', 'blocked', 'cancelled', 'timeout'].includes(event.status)) continue;
    if (ids.has(event.tool_call_id)) throw new Error('HERMES_NATIVE_RESULT_AMBIGUOUS');
    ids.add(event.tool_call_id); sessions.add(event.session_id);
    results.push({ id: event.tool_call_id, name: event.tool_name, arguments: event.args, failed: event.status !== 'ok',
      source: 'native-hermes-post-tool-call-status', native_evidence: event });
  }
  if (sessions.size > 1) throw new Error('HERMES_NATIVE_EVIDENCE_SESSION_AMBIGUOUS');
  return results;
}

function readProfile(profile) {
  const file = path.join(profile, 'native-hermes.jsonl'), info = lstatSync(file, { throwIfNoEntry: false });
  if (!info) return '';
  if (!info.isFile() || info.isSymbolicLink() || info.nlink !== 1 || info.size > 32 * 1024**2) throw new Error('HERMES_NATIVE_EVIDENCE_PATH_INVALID');
  return readFileSync(file, 'utf8');
}

export const nativeHermesProfileResults = profile => nativeHermesResults(readProfile(profile));

/** Pinned agent.turn_finalizer emits this once after the final transformation;
 * cli.py prints the same assistant_response. Startup stdout is not an answer. */
export function nativeHermesFinalOutput(text) {
  let final;
  const sessions = new Set(), turns = new Set();
  for (const line of text.split('\n')) {
    let event; try { event = JSON.parse(line); } catch { continue; }
    if (!['hermes.post_tool_call', 'hermes.post_llm_call'].includes(event?.type) || event.schema_version !== 1) continue;
    if (typeof event.session_id === 'string' && event.session_id) sessions.add(event.session_id);
    if (typeof event.turn_id === 'string' && event.turn_id) turns.add(event.turn_id);
    if (event.type !== 'hermes.post_llm_call') continue;
    if (final) throw new Error('HERMES_NATIVE_FINAL_AMBIGUOUS');
    if (typeof event.session_id !== 'string' || !event.session_id || typeof event.turn_id !== 'string' || !event.turn_id
      || typeof event.model !== 'string' || !event.model || typeof event.assistant_response !== 'string' || !event.assistant_response) throw new Error('HERMES_NATIVE_FINAL_UNVERIFIED');
    final = event;
  }
  if (sessions.size > 1) throw new Error('HERMES_NATIVE_EVIDENCE_SESSION_AMBIGUOUS');
  if (turns.size > 1) throw new Error('HERMES_NATIVE_EVIDENCE_TURN_AMBIGUOUS');
  return final ? { finalAnswer: final.assistant_response, event: final } : undefined;
}

export const nativeHermesProfileFinalOutput = profile => nativeHermesFinalOutput(readProfile(profile));
