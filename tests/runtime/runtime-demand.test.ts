import { expect, it } from 'vitest';
import { runtimeCatalog } from '../../packages/runtime-manager/src/runtime-demand.js';

it('selects core for the exact static document request while preserving the published catalog and browser capabilities', () => {
  const catalog = Object.freeze([
    Object.freeze({ name: 'validation_report', runtime_pack: 'core' }),
    Object.freeze({ name: 'documentation_preview', runtime_pack: 'render' }),
    Object.freeze({ name: 'guideline_example_preview', runtime_pack: 'render' }),
    Object.freeze({ name: 'sentence_render', runtime_pack: 'render' }),
    Object.freeze({ name: 'another_renderer', runtime_pack: 'render' }),
  ]);
  expect(runtimeCatalog(catalog)).toEqual(catalog);
  for (const operation of ['documentation_preview', 'guideline_example_preview']) {
    expect(runtimeCatalog(catalog, { operation, arguments: {} }).map(item => item.runtime_pack)).toEqual(catalog.map(item => item.name === operation ? 'core' : item.runtime_pack));
  }
  for (const output_format of ['svg', 'html']) expect(runtimeCatalog(catalog, { operation: 'sentence_render', arguments: { output_format } }).map(item => item.runtime_pack)).toEqual(['core', 'render', 'render', 'core', 'render']);
  for (const output_format of ['png', 'pdf', 'SVG', '', null, undefined, 1, ['svg']]) expect(runtimeCatalog(catalog, { operation: 'sentence_render', arguments: { output_format } })).toEqual(catalog);
  expect(runtimeCatalog(catalog, { operation: 'another_renderer', arguments: { output_format: 'svg' } })).toEqual(catalog);
  expect(runtimeCatalog(catalog, { operation: 'validation_report', arguments: {} })).toEqual(catalog);
  expect(catalog.map(item => item.runtime_pack)).toEqual(['core', 'render', 'render', 'render', 'render']);
});
