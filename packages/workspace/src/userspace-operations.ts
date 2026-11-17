import operationNames from '../../../workers/ud/src/ud_agent/userspace_operations.json' with { type: 'json' };

/** Trusted built-ins run on confined snapshot bytes and return broker intents. */
export const USERSPACE_BUILTIN_OPERATIONS: readonly string[] = Object.freeze([...operationNames]);
/** Historical export retained for coordinator compatibility. */
export const USERSPACE_READ_ONLY_OPERATIONS = USERSPACE_BUILTIN_OPERATIONS;
