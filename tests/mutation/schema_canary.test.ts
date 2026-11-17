import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import Ajv2020 from 'ajv/dist/2020.js';

describe('environment schema fault canary', () => {
  it('rejects unexpected fields and invalid runtime selections', () => {
    const schema = JSON.parse(readFileSync('contracts/schema/operations/check_ud_environment.input.schema.json', 'utf8')) as object;
    const validate = new Ajv2020({ strict: false }).compile(schema);
    expect(validate({})).toBe(true);
    expect(validate({ unexpected: true })).toBe(false);
    expect(validate({ engine: 'arbitrary-command' })).toBe(false);
  });
});
