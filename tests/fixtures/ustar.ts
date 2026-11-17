import { gzipSync } from 'node:zlib';
export function tar(files: { name: string; bytes: Buffer; type?: string; mode?: number }[]): Buffer {
  const chunks: Buffer[] = [];
  for (const file of files) {
    const header = Buffer.alloc(512); header.write(file.name, 0); header.write((file.mode ?? 0o644).toString(8).padStart(7, '0'), 100); header.write('0000000', 108); header.write('0000000', 116); header.write(file.bytes.length.toString(8).padStart(11, '0'), 124); header.write('00000000000', 136); header.fill(32, 148, 156); header.write(file.type ?? '0', 156); header.write('ustar\0', 257); header.write('00', 263); const sum = header.reduce((a, b) => a + b, 0); header.write(sum.toString(8).padStart(6, '0') + '\0 ', 148); chunks.push(header, file.bytes, Buffer.alloc((512 - file.bytes.length % 512) % 512));
  }
  return gzipSync(Buffer.concat([...chunks, Buffer.alloc(1024)]), { mtime: 0 } as never);
}
