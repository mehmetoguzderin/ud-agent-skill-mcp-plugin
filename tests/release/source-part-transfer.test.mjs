import { posixTest } from '../fixtures/native-scope.mjs';
import { expect, test } from 'vitest';
import { existsSync, linkSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileReceipt } from '../../scripts/release/candidate.mjs';
import { transferredOutputBytes } from '../../scripts/quality/storage-lifecycle.mjs';
import { beginSourcePartTransfer, moveSourcePart, planSourcePartTransfer, recoverSourcePartTransfer, sourceTransferJournal } from '../../scripts/release/source-part-transfer.mjs';
import { selectedSourceTransfers } from '../../scripts/release/available-candidate.mjs';

function fixture() {
  const root=realpathSync(mkdtempSync(path.join(os.tmpdir(),'ud-source-transfer-'))), artifacts=path.join(root,'.artifacts');
  for(const name of ['source','alias','candidate/artifacts','storage'])mkdirSync(path.join(artifacts,name),{recursive:true});
  const source=path.join(artifacts,'source'),alias=path.join(artifacts,'alias'),output=path.join(artifacts,'candidate'),name='source-0000.tar.part';
  writeFileSync(path.join(source,name),'verified original source');linkSync(path.join(source,name),path.join(alias,name));
  const part={id:'corresponding-source-0000',...fileReceipt(source,name)};
  return {root,source,alias,output,name,part};
}
const clean = value => rmSync(value.root,{recursive:true,force:true});

test('candidate source transfer remains optional for the legacy copy route',()=>{
  const f=fixture();try{
    expect(selectedSourceTransfers(f.root,f.source,f.output,[f.part],[])).toEqual([]);
    expect(readFileSync(path.join(f.source,f.name),'utf8')).toBe('verified original source');
    expect(lstatSync(path.join(f.source,f.name)).nlink).toBe(2);
    expect(selectedSourceTransfers(f.root,f.source,f.output,[f.part],[f.alias])).toHaveLength(1);
    expect(()=>selectedSourceTransfers(f.root,f.source,f.output,[f.part],null)).toThrow(/must be an array/);
  }finally{clean(f);}
});

posixTest('source parts move once, receive exact storage credit and recover every original alias',()=>{
  const f=fixture();try{
    expect(()=>planSourcePartTransfer(f.root,f.source,f.output,[f.part],[])).toThrow(/explicit/);
    const entries=planSourcePartTransfer(f.root,f.source,f.output,[f.part],[f.alias]);
    const inode=lstatSync(path.join(f.source,f.name)).ino;
    beginSourcePartTransfer(f.root,f.output,entries);moveSourcePart(f.root,entries[0]);
    const dest=path.join(f.output,'artifacts',f.name);
    expect(existsSync(path.join(f.source,f.name))).toBe(false);expect(existsSync(path.join(f.alias,f.name))).toBe(false);
    expect(lstatSync(dest).ino).toBe(inode);expect(lstatSync(dest).nlink).toBe(1);
    expect(transferredOutputBytes(f.root,f.output,sourceTransferJournal(f.root))).toBe(f.part.size);
    expect(recoverSourcePartTransfer(f.root)).toBe(true);expect(existsSync(dest)).toBe(false);
    expect(readFileSync(path.join(f.source,f.name),'utf8')).toBe('verified original source');
    expect(lstatSync(path.join(f.alias,f.name)).ino).toBe(inode);expect(lstatSync(path.join(f.source,f.name)).nlink).toBe(2);
  }finally{clean(f);}
});

posixTest('completed candidate keeps its exact source part and old aliases stay retired',()=>{
  const f=fixture();try{
    const entries=planSourcePartTransfer(f.root,f.source,f.output,[f.part],[f.alias]);beginSourcePartTransfer(f.root,f.output,entries);moveSourcePart(f.root,entries[0]);
    writeFileSync(path.join(f.root,'.artifacts/storage/candidates.json'),JSON.stringify({current:{output:f.output,manifest:{path:'available-candidate.json'},artifacts:[{id:f.part.id,path:'artifacts/'+f.name,sha256:f.part.sha256,size:f.part.size}]}}));
    expect(recoverSourcePartTransfer(f.root)).toBe(true);expect(readFileSync(path.join(f.output,'artifacts',f.name),'utf8')).toBe('verified original source');
    expect(existsSync(path.join(f.source,f.name))).toBe(false);expect(existsSync(path.join(f.alias,f.name))).toBe(false);
  }finally{clean(f);}
});

posixTest('unlisted aliases and altered parts fail before deletion or replacement',()=>{
  const f=fixture();try{
    const foreign=path.join(f.root,'.artifacts/foreign');mkdirSync(foreign);linkSync(path.join(f.source,f.name),path.join(foreign,f.name));
    expect(()=>planSourcePartTransfer(f.root,f.source,f.output,[f.part],[f.alias])).toThrow(/unlisted/);
    rmSync(path.join(foreign,f.name));const entries=planSourcePartTransfer(f.root,f.source,f.output,[f.part],[f.alias]);
    beginSourcePartTransfer(f.root,f.output,entries);writeFileSync(path.join(f.source,f.name),'altered original');
    expect(()=>moveSourcePart(f.root,entries[0])).toThrow(/bytes differ/);expect(existsSync(path.join(f.alias,f.name))).toBe(true);expect(existsSync(path.join(f.output,'artifacts',f.name))).toBe(false);
    expect(()=>recoverSourcePartTransfer(f.root)).toThrow(/bytes differ/);
  }finally{clean(f);}
});

if (process.platform === 'win32') test('source transfer recovery refuses unproved POSIX journal privacy and preserves every original alias', () => {
  const f = fixture();
  try {
    const entries = planSourcePartTransfer(f.root, f.source, f.output, [f.part], [f.alias]);beginSourcePartTransfer(f.root, f.output, entries);
    const journal = sourceTransferJournal(f.root), bytes = readFileSync(journal);
    expect(() => recoverSourcePartTransfer(f.root)).toThrow(/journal is not bounded private ordinary data/);
    expect(readFileSync(journal)).toEqual(bytes);
    expect(readFileSync(path.join(f.source, f.name), 'utf8')).toBe('verified original source');
    expect(lstatSync(path.join(f.alias, f.name)).ino).toBe(lstatSync(path.join(f.source, f.name)).ino);
    expect(existsSync(path.join(f.output, 'artifacts', f.name))).toBe(false);
  } finally { clean(f); }
});
