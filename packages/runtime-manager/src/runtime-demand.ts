export type OperationDemand = { operation: string; arguments: Record<string, unknown> };

/** Static documents use the core worker; browser exports retain the render pack. */
export function runtimeCatalog<T extends { name: string; runtime_pack: string }>(catalog: readonly T[], demand?: OperationDemand): T[] {
  return catalog.map(tool => {
    if (tool.runtime_pack !== 'render' || tool.name !== demand?.operation) return tool;
    const browserFree = tool.name === 'documentation_preview' || tool.name === 'guideline_example_preview'
      || tool.name === 'sentence_render' && ['svg', 'html'].includes(demand.arguments.output_format as string);
    return browserFree ? { ...tool, runtime_pack: 'core' } : tool;
  });
}
