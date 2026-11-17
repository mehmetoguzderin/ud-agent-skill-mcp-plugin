/** MIT. Bounded Responses namespace validation. Never changes a native request. */
const object = value => value && typeof value === 'object' && !Array.isArray(value);
const fail = code => { throw Object.assign(new Error(code), { code }); };
const name = value => typeof value === 'string' && /^[A-Za-z0-9_-]{1,64}$/.test(value);
const keys = (value, allowed) => Object.keys(value).every(key => allowed.includes(key));
const FUNCTION_KEYS = ['type', 'name', 'description', 'parameters', 'strict', 'defer_loading', 'allowed_callers'];
const CUSTOM_KEYS = ['type', 'name', 'description', 'format', 'defer_loading', 'allowed_callers'];

/** Same selector as translation.py: both counting and generation use to_chat. */
export function needsResponsesTranslation(body) {
  return Array.isArray(body.tools) && body.tools.some(tool => ['custom', 'namespace'].includes(tool?.type)) ||
    Array.isArray(body.input) && body.input.some(item => ['custom_tool_call', 'custom_tool_call_output'].includes(item?.type) || Object.hasOwn(item ?? {}, 'namespace'));
}

/** Flatten only for private observation; namespace and original schema survive.
 * Qualified aliases match pinned LiteLLM 1.109.0, with all collisions rejected. */
export function responsesDeclarations(body, { customResponses = false, nativeTools = false } = {}) {
  const tools = body.tools ?? [];
  if (!Array.isArray(tools) || tools.length > 1024) fail('SERVER_TOOL_TYPE_UNSUPPORTED');
  const namespaces = new Set(), identities = new Set(), aliases = new Set(), result = [];
  const nested = tools.some(tool => tool?.type === 'namespace');
  const add = (tool, namespace) => {
    if (!object(tool)) fail('SERVER_TOOL_TYPE_UNSUPPORTED');
    if (namespace === undefined && !nested && nativeTools && ['shell', 'apply_patch'].includes(tool.type)) { result.push(tool); return; }
    if (tool.type !== 'function' && !(customResponses && tool.type === 'custom')) fail('SERVER_TOOL_TYPE_UNSUPPORTED');
    if (!keys(tool, tool.type === 'function' ? FUNCTION_KEYS : CUSTOM_KEYS)) fail('RESPONSES_TOOL_FIELDS_UNSUPPORTED');
    if (!name(tool.name) || tool.description !== undefined && typeof tool.description !== 'string' ||
        tool.type === 'function' && (tool.parameters !== undefined && !object(tool.parameters) || tool.strict !== undefined && typeof tool.strict !== 'boolean') ||
        tool.type === 'custom' && tool.format !== undefined && !object(tool.format) ||
        tool.defer_loading !== undefined && typeof tool.defer_loading !== 'boolean' ||
        tool.allowed_callers !== undefined && (!Array.isArray(tool.allowed_callers) || tool.allowed_callers.some(caller => typeof caller !== 'string'))) fail('RESPONSES_TOOL_IDENTITY_INVALID');
    const identity = JSON.stringify([namespace ?? null, tool.name]), alias = namespace === undefined ? tool.name : namespace + '__' + tool.name;
    if (!name(alias)) fail('RESPONSES_QUALIFIED_NAME_UNSUPPORTED');
    if (identities.has(identity) || aliases.has(alias)) fail('RESPONSES_NAMESPACE_COLLISION');
    identities.add(identity); aliases.add(alias);
    result.push({ ...tool, ...(namespace === undefined ? {} : { namespace }) });
    if (result.length > 1024) fail('SERVER_TOOL_TYPE_UNSUPPORTED');
  };
  for (const tool of tools) {
    if (!object(tool)) fail('SERVER_TOOL_TYPE_UNSUPPORTED');
    if (tool.type !== 'namespace') { add(tool); continue; }
    if (!keys(tool, ['type', 'name', 'description', 'tools'])) fail('RESPONSES_NAMESPACE_FIELDS_UNSUPPORTED');
    if (!name(tool.name) || tool.description !== undefined && typeof tool.description !== 'string' ||
        !Array.isArray(tool.tools) || !tool.tools.length || tool.tools.length > 1024) fail('RESPONSES_NAMESPACE_INVALID');
    if (namespaces.has(tool.name)) fail('RESPONSES_NAMESPACE_COLLISION');
    namespaces.add(tool.name);
    for (const member of tool.tools) add(member, tool.name);
  }
  return result;
}

export function validateResponsesNamespaces(body, options) {
  const declarations = responsesDeclarations(body, options);
  const namespaced = declarations.some(tool => tool.namespace !== undefined);
  const declared = item => declarations.find(tool => tool.name === item.name && (tool.namespace ?? null) === (item.namespace ?? null));
  const validateIdentity = item => {
    if (item.namespace !== undefined && !name(item.namespace)) fail('RESPONSES_NAMESPACE_IDENTITY_INVALID');
    if (namespaced || item.namespace !== undefined) {
      const tool = declared(item), kind = item.type === 'custom_tool_call' || item.type === 'custom' ? 'custom' : 'function';
      if (!tool || tool.type !== kind) fail('RESPONSES_NAMESPACE_IDENTITY_INVALID');
    }
  };
  for (const item of Array.isArray(body.input) ? body.input : []) {
    if (['function_call', 'custom_tool_call'].includes(item?.type)) validateIdentity(item);
    else if (Object.hasOwn(item ?? {}, 'namespace')) fail('RESPONSES_NAMESPACE_IDENTITY_INVALID');
  }
  if (object(body.tool_choice) && (namespaced || Object.hasOwn(body.tool_choice, 'namespace'))) {
    if (!['function', 'custom'].includes(body.tool_choice.type) || !keys(body.tool_choice, ['type', 'name', 'namespace'])) fail('RESPONSES_NAMESPACE_CHOICE_UNSUPPORTED');
    validateIdentity(body.tool_choice);
  }
  return declarations;
}

export function validateResponsesOutput(body, response) {
  const declarations = responsesDeclarations(body, { customResponses: true, nativeTools: true });
  const namespaced = declarations.some(tool => tool.namespace !== undefined);
  for (const item of response.output ?? []) {
    if (!['function_call', 'custom_tool_call'].includes(item.type)) continue;
    if (item.namespace !== undefined && !name(item.namespace)) fail('RESPONSES_NAMESPACE_IDENTITY_INVALID');
    if (namespaced || item.namespace !== undefined) {
      const tool = declarations.find(tool => tool.name === item.name && (tool.namespace ?? null) === (item.namespace ?? null));
      if (!tool || item.type !== (tool.type === 'custom' ? 'custom_tool_call' : 'function_call')) fail('RESPONSES_NAMESPACE_IDENTITY_INVALID');
    }
  }
}
