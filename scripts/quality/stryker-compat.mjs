/** Scope the legacy TS compiler API to Stryker's config preprocessor only.
 * TypeScript 7 remains the project compiler and the runtime resolution for all
 * other imports. Stryker 10 imports the removed parser API undeclared.
 */
import { registerHooks } from 'node:module';
import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';

const require = createRequire(import.meta.url);
const packageInfo = require('typescript-compat/package.json');
if (packageInfo.version !== '6.0.3') throw new Error('Stryker requires the locked TypeScript 6.0.3 compatibility API.');
const compat = require('typescript-compat');
if (typeof compat.parseConfigFileTextToJson !== 'function' || typeof compat.resolveProjectReferencePath !== 'function') {
  throw new Error('The locked TypeScript compatibility package lacks Stryker’s required APIs.');
}
const compatUrl = pathToFileURL(require.resolve('typescript-compat')).href;
registerHooks({
  resolve(specifier, context, nextResolve) {
    if (specifier === 'typescript' && context.parentURL?.replaceAll('\\\\', '/').endsWith('/@stryker-mutator/core/dist/src/sandbox/ts-config-preprocessor.js')) {
      return nextResolve(compatUrl, context);
    }
    return nextResolve(specifier, context);
  },
});
