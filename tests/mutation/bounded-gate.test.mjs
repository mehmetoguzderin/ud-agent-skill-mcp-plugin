import { test, expect } from 'vitest';
import { mutationGateOptions, finalizeMutationSummary, mutationImageFootprint, runMutationGate } from '../../scripts/quality/mutation-gate.mjs';

const passing = () => ({
  profile: 'bounded', exhaustive: false, qualification: 'bounded-reviewed-corpus', errors: [],
  backends: { bounded: { total: 18, killed: 18, errors: [], per_language: {
    typescript: { scheduled: 11, killed: 11 }, python: { scheduled: 3, killed: 3 },
    rust: { scheduled: 2, killed: 2 }, perl: { scheduled: 1, killed: 1 }, data: { scheduled: 1, killed: 1 },
  } } },
});

test('bounded candidate commands select the complete reviewed profile without changing legacy defaults', () => {
  expect(mutationGateOptions(['--profile', 'bounded', '--session', '/frozen', '--candidate', '/candidate.json', '--candidate-root', '/packages'])).toEqual({ profile: 'bounded', sessionDirectory: '/frozen', candidatePath: '/candidate.json', candidateRoot: '/packages' });
  expect(mutationGateOptions([])).toEqual({});
  expect(mutationGateOptions(['--profile', 'exhaustive'])).toEqual({ profile: 'exhaustive' });
  expect(mutationGateOptions(['--profile', 'bounded', '--image', 'sha256:' + 'a'.repeat(64)])).toEqual({ profile: 'bounded', image: 'sha256:' + 'a'.repeat(64) });
  for (const args of [ ['--image', 'localhost/mutable:latest'], ['--profile', 'unknown'], ['--profile', 'bounded', '--backend', 'python'], ['--profile', 'bounded', '--preflight'], ['--profile', 'bounded', '--candidate', '/candidate.json'], ['--profile', 'bounded', '--profile', 'exhaustive'] ]) expect(() => mutationGateOptions(args)).toThrow();
});

test('the bounded corpus selects the protected or portable runner explicitly; portable never takes protected inputs', () => {
  expect(mutationGateOptions(['--profile', 'bounded', '--runner', 'portable'])).toEqual({ profile: 'bounded', runner: 'portable' });
  expect(mutationGateOptions(['--profile', 'bounded', '--runner', 'protected'])).toEqual({ profile: 'bounded', runner: 'protected' });
  for (const args of [ ['--runner', 'portable'], ['--profile', 'exhaustive', '--runner', 'portable'], ['--profile', 'bounded', '--runner', 'portable', '--image', 'sha256:' + 'a'.repeat(64)], ['--profile', 'bounded', '--runner', 'portable', '--session', '/frozen'], ['--profile', 'bounded', '--runner', 'host'] ]) expect(() => mutationGateOptions(args)).toThrow();
});

test('bounded admission rejects a subset before reading source or starting work', async () => {
  await expect(runMutationGate('/absent', { profile: 'bounded', backend: 'faults' })).rejects.toThrow(/complete reviewed corpus/);
});

test('protected image storage charge comes from the exact local image before work', () => {
  const image = 'sha256:' + 'a'.repeat(64), calls = [];
  const inspect = (_command, args) => {
    calls.push(args);
    if (args[0] === 'image' && args[1] === 'inspect') return { status: 0, stdout: JSON.stringify([{ Id: image, Os: 'linux', Architecture: 'arm64', Size: 1234 }]) };
    if (args[0] === 'image' && args[1] === 'ls') return { status: 0, stdout: JSON.stringify({ ID: image, Repository: 'localhost/ud-agent-sdk', Tag: 'local' }) };
    return { status: 0, stdout: '' };
  };
  expect(mutationImageFootprint(image, { DOCKER_HOST: 'unix:///tmp/docker.sock' }, inspect)).toEqual({ image_id: image, size_bytes: 1234 });
  expect(calls[0]).toEqual(['image', 'inspect', image]);
  expect(() => mutationImageFootprint(image, { DOCKER_HOST: 'tcp://example.com:2375' }, inspect)).toThrow(/local Unix socket/);
  expect(() => mutationImageFootprint('sha256:' + 'b'.repeat(64), { DOCKER_HOST: 'unix:///tmp/docker.sock' }, inspect)).toThrow(/identity/);
  expect(() => mutationImageFootprint(image, { DOCKER_HOST: 'unix:///tmp/docker.sock' }, () => ({ status: 0, stdout: JSON.stringify([{ Id: image, Os: 'linux', Architecture: 'amd64', Size: 1234 }]) }))).toThrow(/architecture/);
});

test('bounded passing results describe only their selected all-language corpus', () => {
  const result = finalizeMutationSummary(passing());
  expect(result.status).toBe('passed');
  expect(result.exhaustive).toBe(false);
  expect(result.qualification).toBe('bounded-reviewed-corpus');
});

test('bounded aggregation rejects missing languages, incomplete outcomes and exhaustive claims', () => {
  for (const change of [
    value => { value.backends.bounded.killed = 17; },
    value => { value.backends.bounded.total = 17; },
    value => { delete value.backends.bounded.per_language.rust; },
    value => { value.backends.bounded.per_language.python.killed = 0; },
    value => { value.backends.bounded.per_language.python = { scheduled: 4, killed: 4 }; },
    value => { value.backends.bounded.errors.push('runner failed'); },
    value => { delete value.backends.bounded; },
    value => { value.exhaustive = true; },
    value => { value.qualification = 'full-gate'; },
  ]) {
    const value = passing(); change(value);
    expect(finalizeMutationSummary(value).status).toBe('failed');
  }
  const failure = passing(); failure.errors.push('protected execution timed out');
  expect(finalizeMutationSummary(failure).status).toBe('failed');
});
