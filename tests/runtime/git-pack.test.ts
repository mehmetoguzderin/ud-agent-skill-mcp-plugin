import { expect, it } from 'vitest';
import { midxNameRegion, validateMidxNames } from '../../packages/workspace/src/git-pack.js';
function specimen(version = 2, hash = 1) {
  const header = Buffer.alloc(12); header.write('MIDX'); header[4]=version; header[5]=hash; header[6]=1; header.writeUInt32BE(1,8);
  const table = Buffer.alloc(24); table.write('PNAM'); table.writeBigUInt64BE(36n,4);
  const name = Buffer.from('pack-'+'a'.repeat(hash === 1 ? 40 : 64)+'.idx\0'); const pnam = Buffer.concat([name,Buffer.alloc((4-name.length%4)%4)]);
  table.writeBigUInt64BE(BigInt(36+pnam.length),16); return {header,table,pnam,size:36+pnam.length+(hash === 1 ? 20 : 32)};
}
it('validates both MIDX versions and hash widths from independently laid out byte records', () => {
  for (const version of [1,2]) for (const hash of [1,2]) { const v=specimen(version,hash), region=midxNameRegion(v.header,v.table,v.size); expect(region).toEqual({offset:36,size:v.pnam.length,packs:1,hashLength:hash === 1 ? 20 : 32}); expect(()=>validateMidxNames(v.pnam,region.packs,region.hashLength)).not.toThrow(); }
});
it('rejects path-bearing pack names, duplicates, trailing data and malformed chunk tables before engine use', () => {
  for (const name of ['../../outside.idx','/outside.idx','pack-'+ 'a'.repeat(40)+':stream.idx','pack-'+ 'a'.repeat(40)+'.pack']) expect(()=>validateMidxNames(Buffer.from(name+'\0'),1,20)).toThrow('GIT_PACK_LOOKUP_UNSAFE');
  expect(()=>validateMidxNames(Buffer.from('custom pack.idx\0'),1,20)).not.toThrow();
  const v=specimen(); expect(()=>validateMidxNames(Buffer.from('pack-'+ 'a'.repeat(40)+'.idx\0'.repeat(5)),1,20)).toThrow();
  expect(()=>validateMidxNames(Buffer.concat([v.pnam,v.pnam]),2,20)).toThrow(); expect(()=>validateMidxNames(v.pnam.subarray(0,10),1,20)).toThrow();
  for (const mutate of [(h:Buffer,t:Buffer)=>{h[4]=3;},(h:Buffer,t:Buffer)=>{h[5]=0;},(h:Buffer,t:Buffer)=>{h.writeUInt32BE(50001,8);},(h:Buffer,t:Buffer)=>{t.writeBigUInt64BE(0xffffffffffffffffn,4);},(h:Buffer,t:Buffer)=>{t.writeBigUInt64BE(0n,4);},(h:Buffer,t:Buffer)=>{t.write('PNAM',12);},(h:Buffer,t:Buffer)=>{t.write('OIDF');}]) { const h=Buffer.from(v.header),t=Buffer.from(v.table); mutate(h,t); expect(()=>midxNameRegion(h,t,v.size)).toThrow('GIT_PACK_LOOKUP_UNSAFE'); }
});
