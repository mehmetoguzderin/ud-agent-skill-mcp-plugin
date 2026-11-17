import { afterEach, inject } from 'vitest';
import { appendFileSync } from 'node:fs';
import path from 'node:path';

if (process.env.UD_STRYKER_EVIDENCE) {
  const mode = inject('mode');
  const mutant = inject('activeMutant');
  const separator = inject('testNameSeparator');
  if (mode === 'mutant') afterEach(({ task }) => {
    if (task.result?.state !== 'fail') return;
    const names = [task.name]; for (let suite = task.suite; suite; suite = suite.suite) names.unshift(suite.name);
    const file = path.relative(process.cwd(), task.file.filepath).split(path.sep).join('/');
    const errors = task.result.errors ?? [];
    const assertion = errors.length > 0 && errors.every(error => ['AssertionError', 'AssertionError [ERR_ASSERTION]', 'VitestAssertionError'].includes(error.name) || error.code === 'ERR_ASSERTION');
    appendFileSync(path.join(process.env.UD_STRYKER_EVIDENCE, 'stryker-test-failures.jsonl'), JSON.stringify({ mutant_id: String(mutant), test_id: `${file}#${names.join(separator).trim()}`, failure_kind: assertion ? 'assertion' : 'runtime', errors: errors.map(error => ({ name: error.name, code: error.code, message: error.message })) }) + '\n', { mode: 0o600 });
  });
}
