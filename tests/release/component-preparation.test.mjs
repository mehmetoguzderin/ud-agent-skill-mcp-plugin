import { posixTest } from '../fixtures/native-scope.mjs';
import { test, expect } from 'vitest';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, unlinkSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileReceipt, sha256 } from '../../scripts/release/candidate.mjs';
import { projectCoverageCandidate, validateInspectionReceipt, writeComponentCoverage } from '../../scripts/release/component-preparation.mjs';
import { retainCrossBuildInputs, verifyRetainedCrossBuildInputs } from '../../scripts/release/cross-build-inputs.mjs';
const required = JSON.parse(readFileSync('quality/requirements.json')).required_artifacts;
function fixture(root) {
  mkdirSync(path.join(root, 'quality')); writeFileSync(path.join(root, 'quality/requirements.json'), JSON.stringify({ required_artifacts: required }));
  const stage = path.join(root, '.artifacts/stage'); mkdirSync(stage, { recursive: true });
  const candidate = { schema_version: 1, source_tree_sha256: 'a'.repeat(64), runtime_lock_sha256: 'b'.repeat(64), artifacts: required.map((id, index) => { const name = `subject-${index}`; writeFileSync(path.join(stage, name), id); return { id, ...fileReceipt(stage, name), path: `.artifacts/final/${name}` }; }) };
  return { stage, candidate };
}

test('coverage inspects exact staged bytes and requires all sixteen actual subjects before final admission', () => {
  const root = mkdtempSync(path.join(os.tmpdir(), 'ud-component-stage-'));
  try {
    const { stage, candidate } = fixture(root), projected = projectCoverageCandidate(root, candidate, stage, { requireComplete: true });
    expect(projected.artifacts).toHaveLength(16); expect(projected.artifacts[0].path).toBe('.artifacts/stage/subject-0');
    for (const change of [rows => rows.slice(1), rows => [rows[0], ...rows], rows => rows.map((row, index) => index ? row : { ...row, sha256: 'f'.repeat(64) })]) expect(() => projectCoverageCandidate(root, { ...candidate, artifacts: change(candidate.artifacts) }, stage, { requireComplete: true })).toThrow();
    writeFileSync(path.join(stage, 'unlisted-software'), 'unexpected runtime'); expect(() => projectCoverageCandidate(root, candidate, stage)).toThrow(/undeclared/); unlinkSync(path.join(stage, 'unlisted-software'));
    unlinkSync(path.join(stage, 'subject-0')); symlinkSync(path.join(stage, 'subject-1'), path.join(stage, 'subject-0')); expect(() => projectCoverageCandidate(root, candidate, stage)).toThrow(/link/i);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('coverage report/checksum self-reference is omitted from the replay subjects, but actual files are still verified', () => {
  const root = mkdtempSync(path.join(os.tmpdir(), 'ud-component-attestations-'));
  try {
    const { stage, candidate } = fixture(root);
    for (const id of ['component-source-coverage', 'checksum-manifest']) { writeFileSync(path.join(stage, id), 'actual attestation bytes'); candidate.artifacts.push({ id, ...fileReceipt(stage, id) }); }
    expect(projectCoverageCandidate(root, candidate, stage, { requireComplete: true }).artifacts.map(row => row.id)).toEqual(required);
    writeFileSync(path.join(stage, 'component-source-coverage'), 'changed report'); expect(() => projectCoverageCandidate(root, candidate, stage)).toThrow(/differs/);
    expect(() => writeComponentCoverage(root, candidate, stage, { python: process.execPath })).toThrow(/replay recipe is missing/);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

posixTest('a retained private input directory must remain a complete closed inventory', () => {
  const root = mkdtempSync(path.join(os.tmpdir(), 'ud-component-native-inputs-'));
  try {
    const cross = { schema_version: 1, source_sha256: 'a'.repeat(64), platforms: {} };
    for (const host of ['darwin-arm64','darwin-x64','linux-arm64','linux-x64','win32-arm64','win32-x64']) { cross.platforms[host] = {}; for (const name of ['ud-agent','ud-agent-guard']) { const relative = `${host}/${name}`; mkdirSync(path.join(root, host), { recursive: true }); writeFileSync(path.join(root, relative), host + name, { mode: 0o755 }); cross.platforms[host][name] = fileReceipt(root, relative); } }
    writeFileSync(path.join(root, 'cross.json'), JSON.stringify(cross)); const retained = path.join(root, 'native-inputs'); retainCrossBuildInputs(root, 'cross.json', retained);
    expect(verifyRetainedCrossBuildInputs(retained).source_sha256).toBe(cross.source_sha256);
    writeFileSync(path.join(retained, 'unlisted'), 'foreign input'); expect(() => verifyRetainedCrossBuildInputs(retained)).toThrow(/unlisted/);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('compact receipt checks real metadata and subjects without claiming source replay', () => {
  const source='a'.repeat(64),subjects=[{id:'native',sha256:'b'.repeat(64)}],body=Buffer.from('{"ok":true}');
  const metadata={path:'family.json',sha256:sha256(body),size_bytes:body.length,executable:false,retention:{kind:'retained-json-metadata',base64:body.toString('base64')}};
  const receipt={schema_version:2,qualification:'compact-family-replay-inputs-no-unretained-input-waiver',source_inventory_sha256:source,subjects,input_count:2,inventory_sha256:'c'.repeat(64),metadata:[metadata],tools:[],unretained_count:0,unretained_sha256:sha256(Buffer.from('[]'))};
  expect(validateInspectionReceipt(receipt,source,subjects)).toEqual({version:2,source_replay_performed:false});
  expect(validateInspectionReceipt({qualification:'observed-component-replay-inputs-no-unretained-input-waiver',unretained_inputs:[]},source,subjects).version).toBe(1);
  const cases=[{...receipt,source_inventory_sha256:'f'.repeat(64)},{...receipt,subjects:[{id:'native',sha256:'d'.repeat(64)}]},{...receipt,input_count:0},{...receipt,unretained_count:1},{...receipt,unretained_sha256:'0'.repeat(64)},{...receipt,extra:true},{...receipt,metadata:[{...metadata,sha256:'0'.repeat(64)}]},{...receipt,metadata:[{...metadata,retention:{...metadata.retention,base64:'@@@@'}}]},{...receipt,tools:[{name:'../tool',sha256:'f'.repeat(64),size_bytes:1,distribution:'nonredistributed-inspection-tool-prerequisite'}]}];
  for(const value of cases)expect(()=>validateInspectionReceipt(value,source,subjects)).toThrow();
  expect(()=>validateInspectionReceipt({qualification:'observed-component-replay-inputs-no-unretained-input-waiver',unretained_inputs:['missing']},source,subjects)).toThrow(/unretained/);
});

test('compact metadata order matches Python Unicode codepoint order', () => {
  const source='a'.repeat(64),body=Buffer.from('{}'),item=name=>({path:name,sha256:sha256(body),size_bytes:body.length,executable:false,retention:{kind:'retained-json-metadata',base64:body.toString('base64')}});
  const receipt={schema_version:2,qualification:'compact-family-replay-inputs-no-unretained-input-waiver',source_inventory_sha256:source,subjects:[],input_count:2,inventory_sha256:'b'.repeat(64),metadata:[item('\uE000.json'),item('\u{10000}.json')],tools:[],unretained_count:0,unretained_sha256:sha256(Buffer.from('[]'))};
  expect(validateInspectionReceipt(receipt,source,[]).version).toBe(2);
  expect(()=>validateInspectionReceipt({...receipt,metadata:[...receipt.metadata].reverse()},source,[])).toThrow(/metadata receipt/);
});
