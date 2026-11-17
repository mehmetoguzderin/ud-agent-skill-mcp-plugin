/** Full first-party JavaScript/TypeScript mutation scope, without incremental reuse. */
import { existsSync, readdirSync } from 'node:fs';
import path from 'node:path';

function containsJavaScript(directory) {
  if (!existsSync(directory)) return false;
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const target = path.join(directory, entry.name);
    if (entry.isDirectory() && entry.name !== 'node_modules' && entry.name !== '__pycache__' && containsJavaScript(target)) return true;
    if (entry.isFile() && /\.(?:ts|tsx|mts|cts|js|mjs|cjs)$/.test(entry.name)) return true;
  }
  return false;
}

export default {
  $schema: './node_modules/@stryker-mutator/core/schema/stryker-schema.json',
  mutate: ['packages/**/*.{ts,tsx,mts,cts,js,mjs,cjs}', 'scripts/**/*.{ts,tsx,mts,cts,js,mjs,cjs}', ...(containsJavaScript('workers') ? ['workers/**/*.{ts,tsx,mts,cts,js,mjs,cjs}'] : []), ...(containsJavaScript('evals') ? ['evals/**/*.{ts,tsx,mts,cts,js,mjs,cjs}'] : [])],
  ignorePatterns: ['/.venv/**', '/.artifacts/**', '/target/**', '/dist/**', '/mutants/**', '/**/__pycache__/**'],
  testRunner: 'vitest',
  plugins: ['@stryker-mutator/*', './scripts/quality/stryker-evidence-reporter.mjs'],
  vitest: { related: false },
  coverageAnalysis: 'off',
  ignoreStatic: false,
  allowEmpty: false,
  inPlace: false,
  incremental: false,
  disableBail: true,
  disableTypeChecks: false,
  // Complete original regression collection includes native compiler/IO cases.
  // The protected runner independently caps each invocation at 540000 ms.
  dryRunTimeoutMinutes: 9,
  concurrency: 2,
  reporters: ['clear-text', 'json', 'ud-evidence'],
  jsonReporter: { fileName: 'reports/mutation/mutation.json' },
  thresholds: { high: 100, low: 100, break: 100 },
};
