/** MIT. Deterministic source for diagram.png; never copied into an agent task. */
import { deflateSync } from 'node:zlib';
import { writeFileSync } from 'node:fs';
const width = 780, height = 280;
const pixels = Buffer.alloc(width * height * 3, 255);
const ink = [35, 42, 52], highlight = [205, 35, 45];
const glyphs = {
  A: ['01110','10001','10001','11111','10001','10001','10001'],
  B: ['11110','10001','10001','11110','10001','10001','11110'],
  C: ['01111','10000','10000','10000','10000','10000','01111'],
  D: ['11110','10001','10001','10001','10001','10001','11110'],
  E: ['11111','10000','10000','11110','10000','10000','11111'],
  H: ['10001','10001','10001','11111','10001','10001','10001'],
  I: ['11111','00100','00100','00100','00100','00100','11111'],
  J: ['00111','00010','00010','00010','10010','10010','01100'],
  M: ['10001','11011','10101','10101','10001','10001','10001'],
  N: ['10001','11001','10101','10011','10001','10001','10001'],
  O: ['01110','10001','10001','10001','10001','10001','01110'],
  R: ['11110','10001','10001','11110','10100','10010','10001'],
  S: ['01111','10000','10000','01110','00001','00001','11110'],
  T: ['11111','00100','00100','00100','00100','00100','00100'],
  U: ['10001','10001','10001','10001','10001','10001','01110'],
};
function dot(x, y, color, radius = 1) {
  for (let dy = -radius; dy <= radius; dy++) for (let dx = -radius; dx <= radius; dx++) {
    const xx = Math.round(x) + dx, yy = Math.round(y) + dy;
    if (xx >= 0 && xx < width && yy >= 0 && yy < height) pixels.set(color, (yy * width + xx) * 3);
  }
}
function line(x1, y1, x2, y2, color, radius = 1) {
  const steps = Math.max(Math.abs(x2 - x1), Math.abs(y2 - y1));
  for (let i = 0; i <= steps; i++) dot(x1 + (x2 - x1) * i / steps, y1 + (y2 - y1) * i / steps, color, radius);
}
function text(value, center, top, color = ink, scale = 3) {
  const left = Math.round(center - (value.length * 6 - 1) * scale / 2);
  for (const [index, letter] of [...value].entries()) {
    const glyph = glyphs[letter];
    if (!glyph) throw new Error(`Missing glyph ${letter}`);
    for (let y = 0; y < 7; y++) for (let x = 0; x < 5; x++) if (glyph[y][x] === '1') {
      for (let dy = 0; dy < scale; dy++) for (let dx = 0; dx < scale; dx++) dot(left + index * 6 * scale + x * scale + dx, top + y * scale + dy, color, 0);
    }
  }
}
function arrow(x, y, color) { line(x, y, x - 9, y - 15, color, 2); line(x, y, x + 9, y - 15, color, 2); }
// Both dependencies are labeled. Only the object arc is red; the selected answer
// is not present in a filename, PNG text chunk, task metadata, or alternate text.
line(390, 185, 390, 110, ink, 2); line(390, 110, 150, 110, ink, 2); line(150, 110, 150, 185, ink, 2); arrow(150, 185, ink);
line(402, 185, 402, 135, highlight, 2); line(402, 135, 630, 135, highlight, 2); line(630, 135, 630, 185, highlight, 2); arrow(630, 185, highlight);
line(390, 65, 390, 95, ink, 2); arrow(390, 95, ink);
text('ROOT', 390, 30); text('NSUBJ', 260, 72); text('OBJ', 520, 97, highlight);
text('CATS', 150, 212, ink, 4); text('CHASED', 390, 212, ink, 4); text('MICE', 630, 212, ink, 4);
const crc = (bytes) => { let value = 0xffffffff; for (const byte of bytes) { value ^= byte; for (let i = 0; i < 8; i++) value = (value >>> 1) ^ ((value & 1) ? 0xedb88320 : 0); } return (value ^ 0xffffffff) >>> 0; };
function chunk(type, bytes) { const name = Buffer.from(type); const size = Buffer.alloc(4); size.writeUInt32BE(bytes.length); const checksum = Buffer.alloc(4); checksum.writeUInt32BE(crc(Buffer.concat([name, bytes]))); return Buffer.concat([size, name, bytes, checksum]); }
const header = Buffer.alloc(13); header.writeUInt32BE(width); header.writeUInt32BE(height, 4); header[8] = 8; header[9] = 2;
const scanlines = Buffer.alloc(height * (width * 3 + 1));
for (let y = 0; y < height; y++) pixels.copy(scanlines, y * (width * 3 + 1) + 1, y * width * 3, (y + 1) * width * 3);
writeFileSync(new URL('./diagram.png', import.meta.url), Buffer.concat([Buffer.from([137,80,78,71,13,10,26,10]), chunk('IHDR', header), chunk('IDAT', deflateSync(scanlines, { level: 9 })), chunk('IEND', Buffer.alloc(0))]));
