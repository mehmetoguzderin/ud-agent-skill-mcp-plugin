import { test, expect } from 'vitest';
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileReceipt } from '../../scripts/release/candidate.mjs';
import { refreshStagedImplementationInventory } from '../../scripts/runtime/freeze-runtime.mjs';

test('staging regenerates original implementation bindings after installing frozen runtime locks', () => {
  const stage = mkdtempSync(path.join(os.tmpdir(), 'ud-staged-inventory-'));
  try {
    for (const name of ['scripts/generate','contracts','quality','runtime','tests']) mkdirSync(path.join(stage,name),{recursive:true});
    copyFileSync('scripts/generate/implementation-inventory.py',path.join(stage,'scripts/generate/implementation-inventory.py'));
    writeFileSync(path.join(stage,'contracts/implementation-requirements.json'),JSON.stringify({schema_version:1,requirements:[{id:'runtime',requirement:'Bind actual frozen runtime inputs.',authorities:['runtime/runtime.lock.json'],implementation:['runtime/runtime.lock.json'],tests:['tests/original.py'],required_suites:['runtime']}]}));
    writeFileSync(path.join(stage,'quality/requirements.json'),JSON.stringify({required_suites:['runtime'],required_artifacts:['fixture']}));
    writeFileSync(path.join(stage,'tests/original.py'),'# original fixture contract\n'); writeFileSync(path.join(stage,'runtime/runtime.lock.json'),'{"state":"frozen","digest":"actual"}\n');
    writeFileSync(path.join(stage,'contracts/implementation-inventory.json'),'{"stale":"unbuilt root metadata"}\n');
    const originalRoot = readFileSync('contracts/implementation-inventory.json');
    refreshStagedImplementationInventory(stage,process.env.UD_AGENT_PYTHON ?? path.resolve('.venv/bin/python'));
    const inventory = JSON.parse(readFileSync(path.join(stage,'contracts/implementation-inventory.json'),'utf8'));
    expect(inventory.requirements[0].implementation[0].sha256).toBe(fileReceipt(stage,'runtime/runtime.lock.json').sha256);
    expect(readFileSync('contracts/implementation-inventory.json').equals(originalRoot)).toBe(true);
  } finally { rmSync(stage,{recursive:true,force:true}); }
});
