import { main } from './cli.js';

try {
  process.exitCode = await main(process.argv.slice(2));
} catch (error: unknown) {
  const message = error instanceof Error ? error.message : 'Unknown startup error.';
  process.stderr.write(`ud-agent: ${message}\n`);
  process.exitCode = 1;
}
