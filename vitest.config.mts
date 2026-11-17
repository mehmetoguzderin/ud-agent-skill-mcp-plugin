import { configDefaults, defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    // Module transforms are disposable; retaining one entry per test run made
    // the dependency tree grow and copied that cache into later QA jobs.
    fsModuleCache: false,
    // Bound aggregate test memory on a 16 GiB development Mac as well as each worker.
    maxWorkers: 2,
    // Native Windows guard/process fixtures need more than the 5 s unit default.
    testTimeout: process.platform === 'win32' ? 60_000 : 5_000,
    // Memory budget: no test may need more than 2 GB. Each worker gets a 1 GiB
    // V8 heap, so an over-budget test fails loudly (heap out of memory) on every
    // platform instead of only on small hosts; worker RSS stays well below 2 GB.
    execArgv: ['--max-old-space-size=1024'],
    setupFiles: ['./tests/mutation/vitest-setup.ts', './tests/mutation/stryker-evidence.mjs'],
    // A failed mutation run can leave source copies behind. They are evidence,
    // not additional test suites to discover in the working tree.
    exclude: [...configDefaults.exclude, '**/.stryker-tmp/**', '**/.artifacts/**', '**/target/**'],
  },
});
