import { test } from 'vitest';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { assessPerlCoverage } from '../../scripts/quality/perl-assess.mjs';
const operators=JSON.parse(readFileSync(new URL('../../quality/perl-operators.json',import.meta.url)));

test('Perl exact token reconciliation rejects uncovered live operators even when labelled complete',()=>{
  const file='scripts/example.pl',source=Buffer.from('if **'),item={id:'if-one',file,definition:{start:0,end:2,original:'if'}};
  const rows=[{start:0,end:2,class:'PPI::Token::Word',content:'if',classification:'scheduled',reason:'declared',mutant_ids:[item.id]},{start:2,end:3,class:'PPI::Token::Whitespace',content:' ',classification:'outside-selected-family',reason:'syntax',mutant_ids:[]},{start:3,end:5,class:'PPI::Token::Operator',content:'**',classification:'unimplemented',reason:'unknown live operator',mutant_ids:[]}];
  for(const classification of ['unimplemented','structural','outside-selected-family','scheduled']){
    const changed=structuredClone(rows);changed[2].classification=classification;
    assert.equal(assessPerlCoverage({[file]:changed},[item],{[file]:source},operators),false);
  }
  const complete=rows.slice(0,2);assert.equal(assessPerlCoverage({[file]:complete},[item],{[file]:Buffer.from('if ')},operators),true);
  for(const change of [value=>value.pop(),value=>value[0].mutant_ids=[],value=>value[0].mutant_ids.push(item.id),value=>value[0].end=1,value=>value[1].start=1]){
    const changed=structuredClone(complete);change(changed);assert.equal(assessPerlCoverage({[file]:changed},[item],{[file]:Buffer.from('if ')},operators),false);
  }
  assert.equal(assessPerlCoverage({[file]:complete},[],{[file]:Buffer.from('if ')},operators),false);
});
