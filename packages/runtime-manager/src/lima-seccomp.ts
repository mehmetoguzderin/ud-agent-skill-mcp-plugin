/** Project the frozen Moby profile for nonprivileged OCI workers on Linux >=5.13. */
function object(value: unknown): Record<string, unknown> | undefined { return value !== null && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : undefined; }
const keys = (value: Record<string, unknown>, allowed: string[]) => Object.keys(value).every(key => allowed.includes(key));
function list(value: unknown, pattern: RegExp): string[] {
  if (!Array.isArray(value) || value.length === 0 || value.length > 1024 || value.some(item => typeof item !== 'string' || !pattern.test(item)) || new Set(value).size !== value.length) throw new Error('LIMA_SECCOMP_PROFILE_INVALID');
  return value as string[];
}
function filters(value: unknown): { arches?: string[]; caps?: string[]; minKernel?: string } {
  if (value === undefined) return {};
  const item = object(value);
  if (!item || !keys(item, ['arches', 'caps', 'minKernel'])) throw new Error('LIMA_SECCOMP_PROFILE_INVALID');
  if (item.minKernel !== undefined && item.minKernel !== '4.8') throw new Error('LIMA_SECCOMP_KERNEL_FILTER_UNSUPPORTED');
  return { ...(item.arches === undefined ? {} : { arches: list(item.arches, /^[a-z0-9_]+$/) }), ...(item.caps === undefined ? {} : { caps: list(item.caps, /^CAP_[A-Z0-9_]+$/) }), ...(item.minKernel === undefined ? {} : { minKernel: item.minKernel }) };
}

/** Linux worker admission independently requires Landlock (Linux >=5.13). */
export function compileLimaSeccomp(value: unknown, architecture: 'arm64' | 'amd64'): Record<string, unknown> {
  const profile = object(value);
  if (!['arm64', 'amd64'].includes(architecture) || !profile || !keys(profile, ['defaultAction', 'defaultErrnoRet', 'archMap', 'syscalls']) || profile.defaultAction !== 'SCMP_ACT_ERRNO' || !Number.isSafeInteger(profile.defaultErrnoRet) || (profile.defaultErrnoRet as number) < 1 || (profile.defaultErrnoRet as number) > 4095 || !Array.isArray(profile.archMap) || profile.archMap.length > 32 || !Array.isArray(profile.syscalls) || profile.syscalls.length === 0 || profile.syscalls.length > 1024) throw new Error('LIMA_SECCOMP_PROFILE_INVALID');
  const primary = architecture === 'arm64' ? 'SCMP_ARCH_AARCH64' : 'SCMP_ARCH_X86_64';
  const selected: string[][] = [];
  for (const raw of profile.archMap) {
    const entry = object(raw);
    if (!entry || !keys(entry, ['architecture', 'subArchitectures']) || typeof entry.architecture !== 'string' || !/^SCMP_ARCH_[A-Z0-9_]+$/.test(entry.architecture)) throw new Error('LIMA_SECCOMP_PROFILE_INVALID');
    const sub = entry.subArchitectures == null || Array.isArray(entry.subArchitectures) && entry.subArchitectures.length === 0 ? [] : list(entry.subArchitectures, /^SCMP_ARCH_[A-Z0-9_]+$/);
    if (sub.includes(entry.architecture)) throw new Error('LIMA_SECCOMP_PROFILE_INVALID');
    if (entry.architecture === primary) selected.push([primary, ...sub]);
  }
  const compatible = architecture === 'arm64' ? [primary, 'SCMP_ARCH_ARM'] : [primary, 'SCMP_ARCH_X86', 'SCMP_ARCH_X32'];
  if (selected.length !== 1 || JSON.stringify(selected[0]) !== JSON.stringify(compatible)) throw new Error('LIMA_SECCOMP_ARCHITECTURE_INVALID');
  const syscalls: Record<string, unknown>[] = [];
  for (const raw of profile.syscalls) {
    const call = object(raw);
    if (!call || !keys(call, ['names', 'action', 'errnoRet', 'args', 'includes', 'excludes', 'comment']) || !['SCMP_ACT_ALLOW', 'SCMP_ACT_ERRNO'].includes(call.action as string) || call.comment !== undefined && typeof call.comment !== 'string') throw new Error('LIMA_SECCOMP_PROFILE_INVALID');
    const names = list(call.names, /^[a-zA-Z0-9_]+$/), include = filters(call.includes), exclude = filters(call.excludes);
    if (exclude.minKernel !== undefined) throw new Error('LIMA_SECCOMP_KERNEL_FILTER_UNSUPPORTED');
    if (call.errnoRet !== undefined && (!Number.isSafeInteger(call.errnoRet) || (call.errnoRet as number) < 0 || (call.errnoRet as number) > 4095)) throw new Error('LIMA_SECCOMP_PROFILE_INVALID');
    let args: Record<string, unknown>[] | undefined;
    if (call.args !== undefined) {
      if (!Array.isArray(call.args) || call.args.length === 0 || call.args.length > 6) throw new Error('LIMA_SECCOMP_PROFILE_INVALID');
      args = call.args.map(raw => {
        const arg = object(raw);
        if (!arg || !keys(arg, ['index', 'value', 'valueTwo', 'op']) || !Number.isSafeInteger(arg.index) || (arg.index as number) < 0 || (arg.index as number) > 5 || !Number.isSafeInteger(arg.value) || (arg.value as number) < 0 || arg.valueTwo !== undefined && (!Number.isSafeInteger(arg.valueTwo) || (arg.valueTwo as number) < 0) || !['SCMP_CMP_NE', 'SCMP_CMP_LT', 'SCMP_CMP_LE', 'SCMP_CMP_EQ', 'SCMP_CMP_GE', 'SCMP_CMP_GT', 'SCMP_CMP_MASKED_EQ'].includes(arg.op as string)) throw new Error('LIMA_SECCOMP_PROFILE_INVALID');
        // runtime-spec's valueTwo has omitempty; preserve all other exact fields.
        return { index: arg.index, value: arg.value, ...(arg.valueTwo ? { valueTwo: arg.valueTwo } : {}), op: arg.op };
      });
    }
    // No Linux capabilities are present. Architecture names use Go's frozen
    // profile convention (arm64/amd64), not the OCI SCMP_ARCH_* strings.
    if (exclude.arches?.includes(architecture) || include.arches && !include.arches.includes(architecture) || include.caps?.length) continue;
    syscalls.push({ names, action: call.action, ...(call.errnoRet === undefined ? {} : { errnoRet: call.errnoRet }), ...(args ? { args } : {}) });
  }
  if (syscalls.length === 0) throw new Error('LIMA_SECCOMP_PROFILE_INVALID');
  return { defaultAction: profile.defaultAction, defaultErrnoRet: profile.defaultErrnoRet, architectures: compatible, syscalls };
}

/** Object field order is immaterial; syscall, architecture and argument order are exact. */
export function equalLimaSeccomp(left: unknown, right: unknown): boolean {
  const canonical = (value: unknown): string => JSON.stringify(value, (_key, item: unknown) => {
    const record = object(item); return record ? Object.fromEntries(Object.keys(record).sort().map(key => [key, record[key]])) : item;
  });
  return canonical(left) === canonical(right);
}
