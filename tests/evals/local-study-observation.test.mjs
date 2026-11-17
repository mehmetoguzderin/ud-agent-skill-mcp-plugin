/** Inert lossless codec and decompression boundary tests. MIT. */
import { test } from 'vitest';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { gzipSync } from 'node:zlib';
import { writeCompressedObservation, readObservation, MAXIMUM_OBSERVATION_BYTES } from '../../evals/local/study-observation.mjs';
import { compareForwardResults } from '../../evals/local/study-forward-process.mjs';
import { sha256 } from '../../scripts/release/candidate.mjs';
test('compressed observations preserve every logit and parity without redundant JSON files', () => {
 const root=mkdtempSync(path.join(os.tmpdir(),'ud-observation-'));
 try { const value={response:{status:'observed',next_logits:Array.from({length:10000},(_,i)=>Math.sin(i)/3),continuation_log_probabilities:[-0.123456789,-9.2]},request:{text:'Skill instructions'}};
 const evidence=writeCompressedObservation(path.join(root,'row.json.gz'),value),roundtrip=readObservation(evidence);
 assert.deepEqual(roundtrip,value);assert.equal(compareForwardResults(value.response,roundtrip.response).status,'passed');assert.ok(evidence.compressed_bytes<evidence.decompressed_bytes);
 assert.throws(()=>readObservation({...evidence,payload_sha256:'a'.repeat(64)}),/PAYLOAD_CHANGED/);assert.throws(()=>readObservation({...evidence,sha256:'b'.repeat(64)}),/BYTES_CHANGED/);
 }finally{rmSync(root,{recursive:true,force:true});}
});
test('compressed evidence rejects decompression bombs before parsing or allocating an unbounded document',()=>{
 const root=mkdtempSync(path.join(os.tmpdir(),'ud-observation-limit-'));
 try{const file=path.join(root,'too-large.gz'),bytes=gzipSync(Buffer.alloc(MAXIMUM_OBSERVATION_BYTES+1,32));writeFileSync(file,bytes);
 assert.throws(()=>readObservation({path:file,sha256:sha256(bytes),payload_codec:'gzip-json-v1'}),/larger than|LIMIT|buffer/i);
 assert.throws(()=>writeCompressedObservation(path.join(root,'too-large-write.gz'),{text:'x'.repeat(MAXIMUM_OBSERVATION_BYTES)}),/DECOMPRESSED_LIMIT/);
 }finally{rmSync(root,{recursive:true,force:true});}
});
