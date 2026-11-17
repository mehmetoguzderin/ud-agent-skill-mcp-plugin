/** Read immutable MCP resource pages and independently verify advertised bytes. */
import { sha256 } from '../release/candidate.mjs';

export async function verifiedWorkflowResource(client, reference) {
  if (!reference || typeof reference.uri !== 'string' || !/^ud:\/\/(?:reports|plans|contexts|operations|artifacts)\//.test(reference.uri) || !/^[a-f0-9]{64}$/.test(reference.sha256 ?? '') || !Number.isSafeInteger(reference.size_bytes) || reference.size_bytes < 0 || reference.size_bytes > 64 * 1024 * 1024) throw new Error('Workflow resource reference is invalid.');
  const chunks = [], seen = new Set(); let uri = reference.uri, size = 0;
  for (;;) {
    if (seen.has(uri) || seen.size >= 1025) throw new Error('Workflow resource pagination repeats or exceeds bounds.');
    seen.add(uri);
    const result = await client.readResource({ uri });
    if (result.contents?.length !== 1) throw new Error('Workflow resource page is incomplete.');
    const content = result.contents[0]; let bytes, next;
    if (typeof content.blob === 'string') {
      bytes = Buffer.from(content.blob, 'base64');
      if (bytes.toString('base64') !== content.blob || seen.size !== 1) throw new Error('Workflow resource blob encoding is invalid.');
    } else if (typeof content.text === 'string') {
      let page;
      try { page = JSON.parse(content.text); } catch { /* Ordinary text resource. */ }
      if (page?.resource?.uri === reference.uri && typeof page.content_base64 === 'string') {
        if (page.resource.sha256 !== reference.sha256 || page.resource.size_bytes !== reference.size_bytes || page.offset !== size || page.encoding !== 'base64' || !(page.next_cursor === null || typeof page.next_cursor === 'string')) throw new Error('Workflow resource page identity is invalid.');
        bytes = Buffer.from(page.content_base64, 'base64');
        if (bytes.toString('base64') !== page.content_base64 || !bytes.length || bytes.length > 65536) throw new Error('Workflow resource page encoding is invalid.');
        if (page.next_cursor !== null) next = reference.uri + '?cursor=' + encodeURIComponent(page.next_cursor);
      } else {
        if (seen.size !== 1) throw new Error('Workflow resource page disappeared.');
        bytes = Buffer.from(content.text);
      }
    } else throw new Error('Workflow resource content is absent.');
    size += bytes.length;
    if (size > reference.size_bytes) throw new Error('Workflow resource exceeds declared size.');
    chunks.push(bytes);
    if (!next) break;
    uri = next;
  }
  const bytes = Buffer.concat(chunks);
  if (bytes.length !== reference.size_bytes || sha256(bytes) !== reference.sha256) throw new Error('Workflow resource bytes differ from advertised identity.');
  return bytes;
}
