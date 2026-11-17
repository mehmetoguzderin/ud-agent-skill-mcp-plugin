/** Validate the only pathname-bearing MIDX chunk before handing it to Git.
 * Format authority: https://git-scm.com/docs/gitformat-pack (v1 and v2).
 * OID contents remain independently verified by the object consumer. */
import { constants } from 'node:fs';
import { open } from 'node:fs/promises';
function invalid(): never { throw new Error('GIT_PACK_LOOKUP_UNSAFE'); }
export function midxNameRegion(header: Buffer, table: Buffer, fileSize: number): { offset:number; size:number; packs:number; hashLength:number } {
  if (header.length !== 12 || !header.subarray(0,4).equals(Buffer.from('MIDX')) || ![1,2].includes(header[4]!) || ![1,2].includes(header[5]!) || !Number.isSafeInteger(fileSize)) invalid();
  const count = header[6]!, hashLength = header[5] === 1 ? 20 : 32, packs = header.readUInt32BE(8);
  if (!count || packs > 50_000 || table.length !== (count + 1) * 12 || fileSize < 12 + table.length + hashLength) invalid();
  const ids = new Set<string>(); let previous = 12 + table.length; let region: {offset:number;size:number} | undefined;
  for (let at = 0; at <= count; at++) {
    const record = at * 12, id = table.subarray(record,record + 4).toString('hex'), raw = table.readBigUInt64BE(record + 4);
    if (raw > BigInt(fileSize - hashLength) || raw < BigInt(previous)) invalid(); const offset = Number(raw);
    if (at === count) { if (id !== '00000000') invalid(); } else { if (id === '00000000' || ids.has(id)) invalid(); ids.add(id); }
    if (at && table.toString('ascii',(at - 1) * 12,(at - 1) * 12 + 4) === 'PNAM') region = { offset: previous, size: offset - previous };
    previous = offset;
  }
  if (!region || region.size > 4 * 1024 * 1024 || previous !== fileSize - hashLength) invalid();
  return { ...region, packs, hashLength };
}
export function validateMidxNames(bytes: Buffer, packs: number, hashLength: number): void {
  if (bytes.length > 4 * 1024 * 1024 || !Number.isSafeInteger(packs) || packs < 0 || packs > 50_000 || ![20,32].includes(hashLength)) invalid();
  let offset = 0; const seen = new Set<string>();
  for (let at = 0; at < packs; at++) {
    const end = bytes.indexOf(0,offset); if (end < 0) invalid(); const value = new TextDecoder('utf-8', { fatal: true }).decode(bytes.subarray(offset,end));
    if (!/^[^/:\\\0\r\n]+\.idx$/.test(value) || value.length > 255 || process.platform === 'win32' && /^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i.test(value) || seen.has(value)) invalid(); seen.add(value); offset = end + 1;
  }
  if (bytes.length - offset > 3 || bytes.subarray(offset).some(value => value !== 0)) invalid();
}
export async function validatePrivateMidx(file: string): Promise<void> {
  const handle = await open(file, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const info = await handle.stat(); if (!info.isFile()) invalid();
    const read = async (size:number,position:number) => { const bytes = Buffer.alloc(size); let offset = 0; while (offset < size) { const result = await handle.read(bytes,offset,size - offset,position + offset); if (!result.bytesRead) invalid(); offset += result.bytesRead; } return bytes; };
    const header = await read(12,0), table = await read((header[6]! + 1) * 12,12), region = midxNameRegion(header,table,info.size);
    validateMidxNames(await read(region.size,region.offset),region.packs,region.hashLength);
  } finally { await handle.close(); }
}
