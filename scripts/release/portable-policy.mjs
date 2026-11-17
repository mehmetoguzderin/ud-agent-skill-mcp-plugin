/** Release tooling uses the coordinator's exact frozen Unicode16 path policy. */
// Node24/26 natively load the authored TypeScript module. A computed URL keeps
// release JS type checking independent of TypeScript's emit-extension setting.
const policy = await import(new URL('../../packages/workspace/src/portable-path.ts', import.meta.url).href);
export const portablePathKey = policy.portablePathKey;
export const validPortablePath = policy.validPortablePath;
