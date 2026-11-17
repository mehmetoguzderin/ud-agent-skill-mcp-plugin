/** Explicit storage admission for new scientific studies. MIT. */
import path from 'node:path';
import { reserveStorage, ownedStorageBytes } from '../../scripts/quality/storage-lifecycle.mjs';
import { originalDockerBytes } from '../../scripts/quality/original-storage.mjs';
import { measureOwnedStorage } from './storage-accounting.mjs';
export const SCIENTIFIC_STORAGE_PLANS = Object.freeze({
  iterate: Object.freeze({ scratch_bytes: 32_000_000, output_bytes: 1_600_000_000, profile: 'release', transient_allowance: 10_000_000_000,
    transient_fixture_output_bytes: 1_100_000_000, persistent_evidence_output_bytes: 500_000_000 }),
  'iterate-transfer': Object.freeze({ scratch_bytes: 32_000_000, output_bytes: 1_250_000_000, profile: 'release', transient_allowance: 10_000_000_000,
    transient_fixture_output_bytes: 1_100_000_000, persistent_evidence_output_bytes: 150_000_000 }),
  prepare: Object.freeze({ scratch_bytes: 32_000_000, output_bytes: 800_000_000, profile: 'ordinary' }),
  run: Object.freeze({ scratch_bytes: 32_000_000, output_bytes: 3_000_000_000, profile: 'release', transient_allowance: 10_000_000_000,
    transient_fixture_output_bytes: 2_000_000_000, persistent_evidence_output_bytes: 1_000_000_000 }),
});
const watchedRoots = value => Array.isArray(value) ? value : [value];
const measureWatched = value => ownedStorageBytes(watchedRoots(value));
/** Fixture caches are in repo unit directories, so their peak is admitted as
 * output rather than pretending that it occupies the external scratch tree. */
export function scientificStudyStorage(root, phase, { reserve = reserveStorage, measure = ownedStorageBytes, asyncMeasure = measure === ownedStorageBytes ? measureOwnedStorage : async roots => measure(roots), engine = originalDockerBytes, watchMeasure = measureWatched, asyncWatchMeasure = watchMeasure === measureWatched ? async directory => measureOwnedStorage(watchedRoots(directory)) : async directory => watchMeasure(directory), onCancel = async () => {} } = {}) {
  const plan = SCIENTIFIC_STORAGE_PLANS[phase]; if (!plan) throw new Error('Unknown scientific storage phase.');
  const baseline = measure([root]), external = engine(root);
  const lease = reserve({ root, plannedBytes: plan.scratch_bytes, plannedOutputBytes: plan.output_bytes, profile: plan.profile,
    ...(plan.transient_allowance ? { transientAllowance: plan.transient_allowance } : {}), externalOwnedBytes: external,
    outputParent: root, outputPath: path.join(root, '.artifacts/local-evals'), label: `scientific-study-${phase}`, onCancel });
  let failure, watched, watchedBaseline = 0, cancelling, timer, checking, watching, closed = false;
  function fail(error) { failure ??= error; cancelling ??= Promise.resolve().then(onCancel).then(() => ({ verified: true }), error => ({ verified: false, error })); }
  async function check() {
    if (failure) throw failure;
    if (closed) throw new Error('Study storage is already closed.');
    // Serialize inventories; a concurrent caller awaits the same complete scan.
    checking ??= (async () => {
      const current = await asyncMeasure([root]);
      if (failure) throw failure;
      return lease.check(Math.max(0, current - baseline));
    })().finally(() => { checking = undefined; });
    return checking;
  }
  return { plan, external_owned_bytes: external, admission: lease.admission,
    check,
    watch(directory) {
      watched = directory; watchedBaseline = watchMeasure(directory); clearInterval(timer);
      timer = setInterval(() => {
        if (failure || closed || watching) return;
        watching = (async () => {
          const current = await asyncWatchMeasure(watched);
          if (!closed && !failure) lease.check(Math.max(0, current - watchedBaseline));
        })().catch(fail).finally(() => { watching = undefined; });
      }, 2000);
      timer.unref();
    },
    async cleanup() {
      closed = true; clearInterval(timer);
      await Promise.allSettled([checking, watching]);
      const result = await cancelling; lease.cleanup();
      if (result?.verified === false) throw result.error;
      if (failure) throw failure;
    },
  };
}
