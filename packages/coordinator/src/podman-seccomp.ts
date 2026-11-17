/** Docker-profile to effective OCI seccomp verification, with no worker capabilities. */
function object(value: unknown): Record<string, unknown> | undefined { return value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : undefined; }
function canonical(value: unknown): string { return JSON.stringify(value, (_key, item: unknown) => item && typeof item === 'object' && !Array.isArray(item) ? Object.fromEntries(Object.entries(item).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0)) : item); }
function version(value: string): number[] | undefined { const match = /^(\d+)\.(\d+)(?:\.(\d+))?/.exec(value); return match ? match.slice(1).map(item => Number(item ?? 0)) : undefined; }
function atLeast(actual: string, required: unknown): boolean { if (typeof required !== 'string') return false; const left = version(actual), right = version(required); if (!left || !right) return false; for (let i = 0; i < 3; i++) { if (left[i]! > right[i]!) return true; if (left[i]! < right[i]!) return false; } return true; }
function strings(value: unknown): value is string[] { return Array.isArray(value) && value.every(item => typeof item === 'string'); }
function applicable(raw: unknown, arch: string, kernel: string, exclude: boolean): boolean | undefined {
  if (raw === undefined) return !exclude;
  const item = object(raw); if (!item || Object.keys(item).some(key => !['caps', 'arches', 'minKernel'].includes(key))) return undefined;
  if (item.caps !== undefined && !strings(item.caps) || item.arches !== undefined && !strings(item.arches)) return undefined;
  if (item.minKernel !== undefined && (exclude || typeof item.minKernel !== 'string' || !version(item.minKernel))) return undefined;
  // libcontainers treats exclusion selectors as disjunctions, inclusions as
  // conjunctions. All capabilities are dropped by the independently checked OCI policy.
  const caps = Array.isArray(item.caps) && item.caps.length > 0;
  const arches = Array.isArray(item.arches) && item.arches.includes(arch);
  const kernelMatches = item.minKernel === undefined || atLeast(kernel, item.minKernel);
  return exclude ? arches : !caps && (item.arches === undefined || arches) && kernelMatches;
}
function ruleKey(item: Record<string, unknown>): string | undefined {
  if (typeof item.action !== 'string' || !item.action.startsWith('SCMP_ACT_') || item.errnoRet !== undefined && (!Number.isSafeInteger(item.errnoRet) || (item.errnoRet as number) < 0 || (item.errnoRet as number) > 65535)) return undefined;
  const args = item.args ?? [];
  if (!Array.isArray(args) || args.some(value => { const arg = object(value); return !arg || Object.keys(arg).some(key => !['index', 'value', 'valueTwo', 'op'].includes(key)) || !Number.isSafeInteger(arg.index) || (arg.index as number) < 0 || (arg.index as number) > 5 || !Number.isSafeInteger(arg.value) || (arg.value as number) < 0 || arg.valueTwo !== undefined && (!Number.isSafeInteger(arg.valueTwo) || (arg.valueTwo as number) < 0) || typeof arg.op !== 'string'; })) return undefined;
  const normalized = args.map(value => { const arg = value as Record<string, unknown>; return { index: arg.index, value: arg.value, valueTwo: arg.valueTwo ?? 0, op: arg.op }; });
  return canonical({ action: item.action, ...(item.errnoRet === undefined ? {} : { errnoRet: item.errnoRet }), args: normalized });
}

/** Missing allow rules are stricter; added or broadened rules are rejected. */
export function verifyPodmanSeccomp(actual: unknown, expected: unknown, arch: string, kernel: string): boolean {
  const policy = object(expected), applied = object(actual);
  if (!policy || !applied || policy.defaultAction !== 'SCMP_ACT_ERRNO' || applied.defaultAction !== policy.defaultAction || (applied.defaultErrnoRet ?? 1) !== (policy.defaultErrnoRet ?? 1)) return false;
  if (Object.keys(applied).some(key => !['defaultAction', 'defaultErrnoRet', 'architectures', 'flags', 'syscalls'].includes(key))) return false;
  if (applied.flags !== undefined && canonical(applied.flags) !== canonical(policy.flags ?? [])) return false;
  const native: Record<string, string> = { amd64: 'SCMP_ARCH_X86_64', arm64: 'SCMP_ARCH_AARCH64' };
  if (!native[arch]) return false;
  let allowedArchitectures: string[];
  if (strings(policy.architectures)) allowedArchitectures = policy.architectures;
  else if (Array.isArray(policy.archMap)) {
    const map = policy.archMap.map(object).find(item => item?.architecture === native[arch]);
    if (!map || !strings(map.subArchitectures)) return false;
    allowedArchitectures = [native[arch]!, ...map.subArchitectures];
  } else allowedArchitectures = [native[arch]!];
  if (!strings(applied.architectures) || !applied.architectures.includes(native[arch]!) || applied.architectures.some(item => !allowedArchitectures.includes(item))) return false;
  if (!Array.isArray(policy.syscalls) || !Array.isArray(applied.syscalls)) return false;
  const permitted = new Map<string, Set<string>>();
  for (const raw of policy.syscalls) {
    const rule = object(raw); if (!rule || !strings(rule.names) || rule.names.length === 0 || Object.keys(rule).some(key => !['names', 'action', 'errnoRet', 'args', 'comment', 'includes', 'excludes'].includes(key))) return false;
    const include = applicable(rule.includes, arch, kernel, false), exclude = applicable(rule.excludes, arch, kernel, true);
    if (include === undefined || exclude === undefined) return false;
    if (!include || exclude) continue;
    const key = ruleKey(rule); if (key === undefined) return false;
    const names = permitted.get(key) ?? new Set<string>(); for (const name of rule.names) names.add(name); permitted.set(key, names);
  }
  for (const raw of applied.syscalls) {
    const rule = object(raw); if (!rule || !strings(rule.names) || rule.names.length === 0 || Object.keys(rule).some(key => !['names', 'action', 'errnoRet', 'args'].includes(key))) return false;
    const key = ruleKey(rule); if (key === undefined || rule.names.some(name => !permitted.get(key)?.has(name))) return false;
  }
  return true;
}
