/** Capture independent diagnostic sources; never mutate or restore the live tree. */
import { copyFileSync, chmodSync, mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { fileReceipt, sourceReceipt } from '../release/candidate.mjs';

export function captureDiagnosticSnapshot(root, output) {
  root = path.resolve(root); output = path.resolve(output);
  const source = sourceReceipt(root);
  const destination = path.join(output, source.sha256);
  mkdirSync(output, { recursive: true, mode: 0o700 });
  mkdirSync(destination, { mode: 0o700 });
  for (const item of source.files) {
    const target = path.join(destination, ...item.path.split('/'));
    mkdirSync(path.dirname(target), { recursive: true, mode: 0o700 });
    copyFileSync(path.join(root, ...item.path.split('/')), target);
    chmodSync(target, item.executable ? 0o755 : 0o644);
    if (fileReceipt(destination, item.path).sha256 !== item.sha256) throw new Error('Diagnostic source changed during capture.');
  }
  if (sourceReceipt(root).sha256 !== source.sha256 || sourceReceipt(destination).sha256 !== source.sha256) throw new Error('Diagnostic snapshot is stale before execution.');
  const receipt = { schema_version: 1, qualification: 'diagnostic-only', source_tree_sha256: source.sha256, source: root, copy: destination, files: source.files, mutation_writes: 'copy-only' };
  writeFileSync(path.join(output, 'snapshot.json'), JSON.stringify(receipt, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
  return receipt;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.length !== 3) throw new Error('Usage: diagnostic-snapshot.mjs NEW_OUTPUT_DIRECTORY');
  const result = captureDiagnosticSnapshot(process.cwd(), process.argv[2]);
  console.log(JSON.stringify({ source_tree_sha256: result.source_tree_sha256, copy: result.copy, qualification: result.qualification }));
}
