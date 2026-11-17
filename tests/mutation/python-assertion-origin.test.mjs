import {test,expect}from'vitest';
import{createHash}from'node:crypto';
import{assessMutmut,pythonAssertionOrigin}from'../../scripts/quality/mutation-gate.mjs';

// Synthetic producer-transport fixtures, not proof of an actual traceback.
const sha=value=>createHash('sha256').update(value).digest('hex');
const testSource='tests/test_rule.py',helper='tests/helpers.py',testId=testSource+'::test_rule';
const contents={[testSource]:'def test_rule():\n    helper()\n',[helper]:'def helper():\n    assert False\n'};
const hashes=Object.fromEntries(Object.entries(contents).map(([name,body])=>[name,sha(body)]));
const plan={tests:[{id:testId,source:testSource,source_sha256:hashes[testSource]}]};
const event={event:'failure',phase:'call',nodeid:testId,mutant:'scripts.rule.x_allowed__mutmut_1',exception_type:'builtins.AssertionError',assertion_contract:'python-test-source-origin-v2',assertion_origin:{contract:'python-test-source-origin-v2',source:helper,source_sha256:hashes[helper],line:2,test_id:testId,test_source:testSource,test_source_sha256:hashes[testSource],test_line:2}};

test('a source-bound helper assertion identifies the current frozen test and remains one clean kill',()=>{
 expect(pythonAssertionOrigin(event,plan,hashes,name=>contents[name])).toBe(true);
 expect(assessMutmut({'scripts/rule.py':{exit_code_by_key:{[event.mutant]:1}}},[event],['scripts/rule.py'],hashes,[],new Set(),plan,name=>contents[name])).toEqual({total:1,killed:1,equivalent:0,errors:[]});
});

test('production, unknown, stale, wrong-test and impossible source locations cannot qualify from exception name alone',()=>{
 const invalid=[{...event,assertion_contract:'python-exception-ancestry-v1'},{...event,assertion_origin:null},...[
  {source:'scripts/production.py'},{source:'tests/unknown.py'},{source_sha256:'0'.repeat(64)},{test_id:'foreign'},{test_source:helper},{test_source_sha256:'0'.repeat(64)},{line:999},{test_line:999},{line:3},{test_line:3},{line:0}
 ].map(change=>({...event,assertion_origin:{...event.assertion_origin,...change}}))];
 for(const changed of invalid)expect(pythonAssertionOrigin(changed,plan,hashes,name=>contents[name])).toBe(false);
 expect(pythonAssertionOrigin(event,plan,hashes,()=>'changed source bytes')).toBe(false);
});
