/** The fixed quality image retains npm-original bytes next to its derived SDK. */
import {createHash} from 'node:crypto';
import {readFileSync,realpathSync} from 'node:fs';
import path from 'node:path';
const EXPECTED='abf79e430d545f69e3a732e816e0d3d3fc26c6bb56e29aa9337102ee673d02a1';
const hash=value=>createHash('sha256').update(value).digest('hex');
export function originalVitestAssertionSdk(vitest){
  const current=readFileSync(path.join(vitest,'dist/chunks/index.CZzC1gGg.js'));
  if(hash(current)===EXPECTED)return current;
  if(realpathSync(vitest)!=='/opt/mutation/node_modules/vitest')throw new Error('Original calibration requires the exact frozen Vitest source.');
  const original=readFileSync('/opt/mutation/node-assertion-sdk-upstream.js');
  if(hash(original)!==EXPECTED)throw new Error('Retained original calibration SDK bytes are stale or corrupt.');
  return original;
}
export function originalVitestSerializerSdk(vitest){
  const expected='695282581b97d7049132e1097f9c7421931cb00b9308bd533b4f7f709f5fedc3',current=readFileSync(path.join(vitest,'dist/chunks/run.CjdgFZiW.js'));
  if(hash(current)===expected)return current;
  if(realpathSync(vitest)!=='/opt/mutation/node_modules/vitest')throw new Error('Original serializer calibration requires the exact frozen Vitest source.');
  const original=readFileSync('/opt/mutation/node-assertion-sdk-serializer-upstream.js');
  if(hash(original)!==expected)throw new Error('Retained original serializer SDK bytes are stale or corrupt.');
  return original;
}

export function originalChaiAssertionSdk(chai){
  const expected='89e5418f06b7871fadf9230618d78a7eb352c62840fd576b51db3509ccb96a1f',current=readFileSync(path.join(chai,'index.js'));
  if(hash(current)===expected)return current;
  if(realpathSync(chai)!=='/opt/mutation/node_modules/chai')throw new Error('Original Chai calibration requires the exact frozen source.');
  const original=readFileSync('/opt/mutation/node-assertion-sdk-chai-upstream.js');
  if(hash(original)!==expected)throw new Error('Retained original Chai SDK bytes are stale or corrupt.');
  return original;
}
