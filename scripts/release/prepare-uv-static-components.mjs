/** Append exact owned-uv CRT declarations, keeping STL attribution separate. */
import { copyFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { verifyWindowsUv } from '../runtime/finalize-windows-uv.mjs';
import { fileReceipt, sha256 } from './candidate.mjs';
import { canonicalJson } from './http-transports.mjs';

export function appendUvStaticComponents(root, baseFile, uvRoot, output) {
  if (existsSync(output)) throw new Error('New six-component declaration output required.');
  const baseBytes = readFileSync(baseFile), base = JSON.parse(baseBytes), uv = verifyWindowsUv(uvRoot);
  if (base.qualification !== 'exact-proprietary-component-declarations-no-publisher-grant' || base.components.length !== 4 || base.components.some(row => row.binary_name === 'uv') || uv.records.length !== 2) throw new Error('Original four-helper and two-target uv declarations required.');
  const components = [...base.components];
  for (const row of uv.records) {
    const platform = row.platform.replace('/', '-'), libraries = row.libraries.map(value => ({ library: value.library, archive_sha256: value.archive.sha256, archive_size_bytes: value.archive.size_bytes, members: value.members }));
    const proprietary = libraries.filter(value => value.library !== 'libcpmt'), stl = libraries.filter(value => value.library === 'libcpmt');
    if (new Set(proprietary.map(value => value.library)).size !== 3 || !['libcmt', 'libucrt', 'libvcruntime'].every(name => proprietary.some(value => value.library === name)) || stl.length !== 1 || stl[0].members.length !== 5) throw new Error('uv CRT/STL static library universe differs from its exact reviewed classification.');
    const relative = `runtime/materials/msvc-link-maps/uv-${sha256(readFileSync(path.join(uvRoot, 'linkage-receipt.json')))}/${platform}-uv.map`; mkdirSync(path.dirname(path.join(root, relative)), { recursive: true });
    if (existsSync(path.join(root, relative)) && fileReceipt(root, relative).sha256 !== row.map.sha256) throw new Error('Retained uv link-map content address conflicts.');
    if (!existsSync(path.join(root, relative))) copyFileSync(path.join(uvRoot, row.map.path), path.join(root, relative));
    if (fileReceipt(root, relative).sha256 !== row.map.sha256) throw new Error('uv link map copy differs.');
    const component = { id: `microsoft-crt-${platform}-uv`, platform: row.platform, binary_name: 'uv', binary_sha256: row.binary.sha256, license: 'LicenseRef-Microsoft-VisualStudio-2026-CRT', classification: 'proprietary-static-object-code', source_availability: 'source-unavailable-proprietary', corresponding_source_review: 'pending-independent-exact-terms-review', publisher_redistribution_authority: 'unverified-external', system_imports: row.imports, static_libraries: proprietary, other_static_components: stl.map(value => ({ id: `microsoft-stl-${platform}-uv`, classification: 'separately-attributed-open-source-static-object-code', license: 'Apache-2.0 WITH LLVM-exception', source_status: 'pending-exact-per-object-source-checksum-join', ...value })), link_map: fileReceipt(root, relative), terms: base.components[0].terms, original_source_build: { source_commit: uv.source_commit, version: uv.version, source_receipt_sha256: uv.source_receipt_sha256, build_receipt_sha256: uv.build_receipt_sha256, linkage_receipt_sha256: sha256(readFileSync(path.join(uvRoot, 'linkage-receipt.json'))), target_execution: false } };
    components.push({ ...component, definition_sha256: sha256(Buffer.from(canonicalJson(component))) });
  }
  const result = { ...base, components, base_helper_declaration_sha256: sha256(baseBytes), scope: 'Six proprietary CRT components only. The ten libcpmt/STL objects are separately classified; source attribution and publisher authority remain separate unresolved gates.' };
  mkdirSync(path.dirname(output), { recursive: true }); writeFileSync(output, JSON.stringify(result, null, 2) + '\n'); return result;
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { const [root, base, uv, output] = process.argv.slice(2); if (!output) throw new Error('Usage: prepare-uv-static-components.mjs ROOT BASE_FOUR_COMPONENTS UV_BUILD NEW_OUTPUT'); const value = appendUvStaticComponents(path.resolve(root), path.resolve(base), path.resolve(uv), path.resolve(output)); console.log(JSON.stringify({ proprietary_components: value.components.length, stl_objects_separately_pending: 10, publisher_authority: 'unverified-external' })); } catch (error) { console.error(error.message); process.exitCode = 1; }
}
