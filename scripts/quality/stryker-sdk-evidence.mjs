/** Independently replay retained upstream/derived quality SDK evidence. */
import { createHash } from 'node:crypto';
import { verifyStrykerAssertionSdk, verifyStrykerAssertionSdkClosure } from './stryker-assertion-sdk.mjs';
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const files = { receipt: 'node-assertion-sdk.json', upstream_source: 'node-assertion-sdk-upstream.js', serializer_upstream_source: 'node-assertion-sdk-serializer-upstream.js', chai_upstream_source:'node-assertion-sdk-chai-upstream.js', upstream_dependencies: 'node-upstream-dependencies.json' };

export function verifyRecordedStrykerSdk(runtime, read) {
  if (!runtime || typeof read !== 'function' || !runtime.node_assertion_sdk) throw new Error('Derived assertion SDK authority is missing.');
  function bound(descriptor, expected, exported) {
    if (!descriptor || descriptor.path !== expected || !/^[a-f0-9]{64}$/.test(descriptor.sha256 ?? '') || !Number.isSafeInteger(descriptor.size_bytes) || descriptor.size_bytes < 1 || descriptor.size_bytes > 32 * 1024 ** 2) throw new Error('Derived assertion SDK content receipt is invalid.');
    const bytes = read(exported);
    if (!Buffer.isBuffer(bytes) || bytes.length !== descriptor.size_bytes || sha(bytes) !== descriptor.sha256) throw new Error('Derived assertion SDK retained bytes differ.');
    return bytes;
  }
  const finalBytes = bound(runtime.node_dependencies, 'node-dependencies.json', 'runtime-node-dependencies.json');
  const installationBytes = bound(runtime.node_installation, 'node-installation-receipt.json', 'runtime-node-installation-receipt.json');
  const bytes = Object.fromEntries(Object.entries(files).map(([key, name]) => [key, bound(runtime.node_assertion_sdk[key], name, 'runtime-' + name)]));
  const decode = value => JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(value));
  const receipt = decode(bytes.receipt), upstream = decode(bytes.upstream_dependencies), final = decode(finalBytes), installation = decode(installationBytes);
  if(receipt.schema_version!==3)throw new Error('Derived assertion SDK lacks authenticated fresh-error construction authority.');
  if (installation.qualification !== 'locked-native-sdk-data-preparation-no-lifecycle-execution' || installation.inputs?.['package-lock.json'] !== runtime.package_lock_sha256 || installation.closure?.sha256 !== sha(JSON.stringify(upstream) + '\n') || installation.closure.files !== upstream.files?.length || installation.closure.links !== upstream.links?.length) throw new Error('Derived assertion SDK upstream installation is unbound.');
  const derived = read('runtime-node-assertion-sdk-derived.js');
  verifyStrykerAssertionSdk(bytes.upstream_source, derived, receipt,{serializerOriginal:bytes.serializer_upstream_source,serializerDerived:read('runtime-node-assertion-sdk-serializer-derived.js'),chaiOriginal:bytes.chai_upstream_source,chaiDerived:read('runtime-node-assertion-sdk-chai-derived.js')});
  verifyStrykerAssertionSdkClosure(upstream, final, receipt);
  return { schema_version: 1, root: '/opt/mutation/node_modules', receipt_sha256: runtime.node_dependencies.sha256 };
}
