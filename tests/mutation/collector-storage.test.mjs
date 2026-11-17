import { test } from 'vitest';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { parse } from '@babel/parser';
import { traverse } from '@babel/core';

test('verbose worker output retains an exact bounded prefix without stopping execution', () => {
  const source = readFileSync(new URL('../../scripts/quality/oci-python-diagnostic.mjs', import.meta.url), 'utf8'), ast = parse(source, { sourceType: 'module' });
  let callback;
  traverse(ast, { VariableDeclarator(value) { if (value.node.id.type === 'Identifier' && value.node.id.name === 'capture') callback = value.node.init; } });
  assert.ok(callback);
  const retained = [];
  const actual = new Function('writeSync', `let logBytes=0,logTruncated=false,storageError,terminated=false;const log=1,terminateChild=()=>{terminated=true};const capture=(${source.slice(callback.start, callback.end)});return {capture,state:()=>({logBytes,logTruncated,storageError,terminated})};`)((_fd, bytes) => retained.push(Buffer.from(bytes)));
  actual.capture(Buffer.alloc(16 * 1024 ** 2 - 1, 0x61)); actual.capture(Buffer.from('bc')); actual.capture(Buffer.from('d'));
  assert.deepEqual(actual.state(), { logBytes: 16 * 1024 ** 2, logTruncated: true, storageError: undefined, terminated: false });
  const prefix = Buffer.concat(retained); assert.equal(prefix.length, 16 * 1024 ** 2); assert.equal(prefix.at(-1), 0x62);
});

test('actual launch argv and journal give full collection a bounded two-GiB temporary budget', () => {
  const source = readFileSync(new URL('../../scripts/quality/oci-python-diagnostic.mjs', import.meta.url), 'utf8'), ast = parse(source, { sourceType: 'module' });
  const declarations = new Map(); let journal, mount;
  traverse(ast, {
    VariableDeclarator(value) { if (value.node.id.type === 'Identifier' && ['workerMemoryGiB', 'workerMemory', 'temporaryBytes'].includes(value.node.id.name)) declarations.set(value.node.id.name, source.slice(value.node.start, value.node.end)); },
    AssignmentExpression(value) { const left = value.node.left; if (left.type === 'MemberExpression' && !left.computed && left.object.name === 'journal' && left.property.name === 'resource_limits') journal = value.node.right; },
    CallExpression(value) { const args = value.node.arguments, index = args.findIndex(item => item.type === 'StringLiteral' && item.value === '--tmpfs'); if (index >= 0) mount = args[index + 1]; },
  });
  assert.equal(declarations.size, 3);
  assert.equal(journal?.type, 'ObjectExpression');
  assert.equal(mount?.type, 'TemplateLiteral');
  const model = new Function('backend', 'const ' + [...declarations.values()].join(',') + ';return {limits:(' + source.slice(journal.start, journal.end) + '), mount:(' + source.slice(mount.start, mount.end) + '), memory:workerMemory};');
  for (const backend of ['catalog', 'typescript', 'faults']) {
    const result = model(backend);
    assert.deepEqual(result.limits, { cpus: 2, memory_bytes: 3221225472, processes: 256, temporary_bytes: 2147483648 });
    assert.equal(result.mount, '/tmp:rw,exec,nosuid,nodev,size=2147483648');
    assert.equal(result.memory, '3g');
  }
  for (const backend of ['rust', 'python', 'python-static', 'perl', 'unknown']) {
    const result = model(backend);
    assert.equal(result.limits.temporary_bytes, 2147483648);
    assert.equal(result.mount, '/tmp:rw,exec,nosuid,nodev,size=2147483648');
    assert.equal(result.limits.memory_bytes, backend === 'rust' ? 2147483648 : 3221225472);
    assert.equal(result.memory, backend === 'rust' ? '2g' : '3g');
  }
});
