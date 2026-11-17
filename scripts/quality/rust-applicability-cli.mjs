/** Replay every exact Rust definition against an independently issued compiler
 * transcript and the original source-locked AST parser. No candidate executes.
 */
import { createHash } from 'node:crypto';
import { closeSync, fstatSync, openSync, readFileSync, readSync } from 'node:fs';
import { constants } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { canonicalJson } from '../release/http-transports.mjs';
import { discoverRustApplicability, verifyRustCfgGeneration } from './rust-applicability.mjs';
import { trustedRustCfgParser } from './rust-assertions.mjs';

const hash = bytes => createHash('sha256').update(bytes).digest('hex');
export function replayRustApplicability(root, inventory, generation, authority, parseCfg) {
  const receipts = verifyRustCfgGeneration(generation, authority);
  const issued = new Set(receipts.map(canonicalJson));
  return discoverRustApplicability(root, inventory, receipts, { parseCfg, verifyTargetCfg: row => issued.has(canonicalJson(row)) });
}
export function verifyRustApplicabilityEvidence({ root, schedule, runtime, sdkBytes, generationBytes, proofBytes, source_sha256, parseCfg }) {
  if (!Buffer.isBuffer(sdkBytes) || !Buffer.isBuffer(generationBytes) || !Buffer.isBuffer(proofBytes) || sdkBytes.length > 16 * 1024 ** 2 || generationBytes.length > 1024 ** 2 || proofBytes.length > 64 * 1024 ** 2) throw new Error('Rust applicability evidence is missing or unbounded.');
  const descriptor = schedule?.applicability;
  if (schedule?.source_tree_sha256 !== source_sha256 || schedule?.current_target !== 'aarch64-unknown-linux-gnu' || !Array.isArray(schedule?.inventory) || descriptor?.path !== 'applicability.json' || descriptor?.generation_path !== 'target-cfg-generation.json' || descriptor?.sdk_receipt_path !== 'rust-sdk-receipt.json' || descriptor.sha256 !== hash(proofBytes) || descriptor.generation_sha256 !== hash(generationBytes) || descriptor.sdk_receipt_sha256 !== hash(sdkBytes) || runtime?.rust?.sha256 !== hash(sdkBytes) || runtime.rust.size_bytes !== sdkBytes.length) throw new Error('Rust applicability does not bind the frozen source, complete schedule, and image SDK.');
  const sdk = JSON.parse(sdkBytes), generation = JSON.parse(generationBytes), proof = JSON.parse(proofBytes);
  if (sdk.qualification !== 'development-mutation-toolchain' || sdk.platform !== 'linux/arm64' || !Array.isArray(sdk.files)) throw new Error('Rust applicability SDK authority is malformed.');
  const compiler = sdk.files.filter(row => row.path === 'bin/rustc'), parser = sdk.files.filter(row => row.path === 'bin/ud-rust-assertion-parser');
  if (compiler.length !== 1 || parser.length !== 1 || !/^[a-f0-9]{64}$/.test(compiler[0].sha256) || !/^[a-f0-9]{64}$/.test(parser[0].sha256)) throw new Error('Rust applicability SDK executable inventory is absent or ambiguous.');
  const authority = { compiler_sha256: compiler[0].sha256, sdk_receipt_sha256: hash(sdkBytes), source_tree_sha256: source_sha256 };
  const expected = replayRustApplicability(root, schedule.inventory, generation, authority, parseCfg);
  const binding = proof?.parser_receipt;
  if (sdk.assertion_parser?.schema_version !== 1 || !binding || binding.executable_sha256 !== parser[0].sha256 || binding.qualification !== 'immutable-SDK-AST-parser-only' || binding.parser_mode !== 'cfg-regions' || canonicalJson(binding.source_inventory) !== canonicalJson(sdk.assertion_parser.source_inventory) || canonicalJson(binding.source_inventory) !== canonicalJson(parseCfg.receipt?.source_inventory)) throw new Error('Rust applicability parser differs from its source-locked original SDK.');
  const { parser_receipt: suppliedParser, ...supplied } = proof;
  const { parser_receipt: replayParser, ...replayed } = expected;
  if (canonicalJson(supplied) !== canonicalJson(replayed)) throw new Error('Rust applicability does not replay every exact source and candidate definition.');
  return { proof, proof_sha256: descriptor.sha256, generation_sha256: descriptor.generation_sha256, current_target: schedule.current_target };
}
function immutableBytes(file, maxBytes, executable = false) {
  const fd = openSync(file, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const before = fstatSync(fd);
    if (!before.isFile() || before.uid !== 0 || before.nlink !== 1 || before.mode & 0o222 || executable && !(before.mode & 0o111) || before.size > maxBytes) throw new Error('Rust applicability authority is not a bounded immutable coordinator file.');
    const bytes = readFileSync(fd), after = fstatSync(fd);
    if (bytes.length !== before.size || ['dev','ino','uid','mode','size','mtimeMs','ctimeMs'].some(key => before[key] !== after[key])) throw new Error('Rust applicability authority changed while reading.');
    return bytes;
  } finally { closeSync(fd); }
}
function input() {
  const chunks = []; let size = 0;
  for (;;) { const part = Buffer.alloc(65536), count = readSync(0, part); if (!count) break; size += count; if (size > 64 * 1024 ** 2) throw new Error('Rust applicability request exceeds its bound.'); chunks.push(part.subarray(0,count)); }
  return JSON.parse(Buffer.concat(chunks).toString('utf8'));
}
if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  try {
    if (process.argv.length !== 2 || process.getuid?.() !== 0) throw new Error('Rust applicability issuance requires its trusted OCI coordinator.');
    const request = input(), runtime = JSON.parse(immutableBytes('/opt/mutation/input-receipt.json', 16 * 1024 ** 2));
    const sdkBytes = immutableBytes('/opt/mutation/rust-input-receipt.json', 16 * 1024 ** 2), sdk = JSON.parse(sdkBytes);
    if (runtime.rust?.sha256 !== hash(sdkBytes) || runtime.rust?.size_bytes !== sdkBytes.length) throw new Error('Rust cfg compiler SDK differs from its image authority.');
    const rows = sdk.files.filter(row => row.path === 'bin/rustc');
    if (rows.length !== 1) throw new Error('Rust cfg compiler inventory is absent or ambiguous.');
    const compiler = immutableBytes('/opt/mutation/rust/bin/rustc', 128 * 1024 ** 2, true);
    if (hash(compiler) !== rows[0].sha256 || compiler.length !== rows[0].size) throw new Error('Rust cfg compiler differs from its frozen binary.');
    const authority = { compiler_sha256: rows[0].sha256, sdk_receipt_sha256: hash(sdkBytes), source_tree_sha256: request.source_tree_sha256 };
    const proof = replayRustApplicability(request.root, request.inventory, request.generation, authority, trustedRustCfgParser(request.root));
    process.stdout.write(JSON.stringify(proof) + '\n');
  } catch (error) { process.stderr.write(String(error.stack ?? error) + '\n'); process.exitCode = 1; }
}
