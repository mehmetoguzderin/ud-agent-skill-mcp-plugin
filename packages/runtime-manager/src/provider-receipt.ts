import { Ajv2020 } from 'ajv/dist/2020.js';
import schema from '../../../contracts/schema/runtime-lock.schema.json' with { type: 'json' };
import type { Host } from './profiles.js';

const validate = new Ajv2020({ strict: true, allErrors: true }).compile({ $schema: schema.$schema, $defs: schema.$defs, ...schema.properties.provider_receipts });

/** Validate only provider records; legacy locks without these remain readable. */
export function validateProviderReceipt(engine: 'apple-container' | 'lima-nerdctl' | 'wslc', host: Host, value: unknown): asserts value is Record<string, unknown> {
  if (!validate({ [`${engine}/${host.platform}/${host.arch}`]: value })) throw new Error(`PROVIDER_RECEIPT_INVALID: ${validate.errors?.map(error => `${error.instancePath} ${error.message}`).join('; ')}`);
  if (engine === 'lima-nerdctl' && (value as Record<string, unknown>).architecture !== (host.arch === 'x64' ? 'amd64' : 'arm64')) throw new Error('PROVIDER_RECEIPT_ARCHITECTURE_MISMATCH');
}
