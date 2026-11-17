/** Native payloads need their host guard and their same-architecture VM guard. */
import { releasePlatforms } from './host-adapters.mjs';

const hosts = releasePlatforms.map(platform => platform.replace('-', '/'));

export function selectedNativeHelpers(lock, platform) {
  if (platform !== 'all' && !/^(?:darwin|linux|win32)-(?:arm64|x64)$/.test(platform)) throw new Error('Unsupported helper package platform.');
  const selected = platform === 'all' ? hosts : [...new Set([platform.replace('-', '/'), 'linux/' + platform.split('-')[1]])];
  for (const host of selected) if (!lock.native_helpers?.[host]?.guard) throw new Error(`Selected native/guest helper is missing: ${host}`);
  return selected.map(host => ({ platform: host, guard: lock.native_helpers[host].guard }));
}
