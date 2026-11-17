#!/usr/bin/env node
/** Record exact proprietary static components; never copy SDK/library payloads. */
import { copyFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { archiveObjectBytes, staticCrtObjectMembers, verifyWindowsBootstrapImports } from './windows-linkage.mjs';
import { canonicalJson } from './http-transports.mjs';
import { fileReceipt, sha256, verifyRecordedFile } from './candidate.mjs';

export function preparePublisherComponents(root, crossFile, termsRoot, output) {
  if (existsSync(output)) throw new Error('New publisher component declaration output required.');
  const crossBytes = readFileSync(crossFile), crossSha256 = sha256(crossBytes), cross = JSON.parse(crossBytes), terms = JSON.parse(readFileSync(path.join(termsRoot, 'receipt.json'), 'utf8'));
  if (cross.schema_version !== 1 || terms.qualification !== 'public-original-license-documents-no-acceptance-or-publisher-authority') throw new Error('Exact link and original-term inputs required.');
  const originalTerms = [];
  for (const row of terms.files) for (const item of [row, ...(row.text ? [row.text] : [])]) {
    verifyRecordedFile(termsRoot, { ...item, size: item.size_bytes });
    const relative = 'licenses/vendor/Microsoft-VisualStudio-2026/' + path.basename(item.path), destination = path.join(root, relative); mkdirSync(path.dirname(destination), { recursive: true });
    if (existsSync(destination) && fileReceipt(root, relative).sha256 !== item.sha256) throw new Error('Original vendor terms conflict with existing notice bytes.');
    if (!existsSync(destination)) copyFileSync(path.join(termsRoot, item.path), destination);
    originalTerms.push({ ...fileReceipt(root, relative), url: row.url, ...(item === row ? {} : { transform: row.transform }) });
  }
  const components = [];
  for (const platform of ['win32-arm64', 'win32-x64']) {
    const linkage = cross.windows_linkage?.[platform];
    if (linkage?.profile !== 'static-msvc-crt' || linkage.license !== 'LicenseRef-Microsoft-VisualStudio-2026-CRT' || linkage.publisher_redistribution_authority !== 'unverified-external') throw new Error('Explicit static CRT authority classification required.');
    for (const name of ['ud-agent', 'ud-agent-guard']) {
      const binary = cross.platforms[platform][name], object = linkage.objects[name]; verifyRecordedFile(root, { ...binary, size: fileReceipt(root, binary.path).size }); verifyWindowsBootstrapImports(object.system_imports);
      const map = object.map; verifyRecordedFile(root, { ...map, size: map.size_bytes }); const observed = staticCrtObjectMembers(readFileSync(path.join(root, map.path), 'utf8')), definitions = [];
      for (const library of object.libraries) {
        verifyRecordedFile(root, { ...library.archive, size: library.archive.size_bytes }); const names = observed.filter(row => row.library === library.library).map(row => row.object);
        const members = archiveObjectBytes(readFileSync(path.join(root, library.archive.path)), names).map(row => ({ name: row.member, sha256: sha256(row.bytes), size_bytes: row.bytes.length }));
        if (canonicalJson(members) !== canonicalJson(library.members)) throw new Error('Contributing static object bytes differ from exact link evidence.');
        definitions.push({ library: library.library, archive_sha256: library.archive.sha256, archive_size_bytes: library.archive.size_bytes, members });
      }
      if (definitions.reduce((sum, row) => sum + row.members.length, 0) !== observed.length) throw new Error('Static object inventory is incomplete.');
      const relative = `runtime/materials/msvc-link-maps/${crossSha256}/${platform}-${name}.map`, destination = path.join(root, relative); mkdirSync(path.dirname(destination), { recursive: true });
      if (existsSync(destination) && fileReceipt(root, relative).sha256 !== map.sha256) throw new Error('Retained link-map content address conflicts.');
      if (!existsSync(destination)) copyFileSync(path.join(root, map.path), destination);
      const component = { id: `microsoft-crt-${platform}-${name}`, platform: platform.replace('-', '/'), binary_name: name, binary_sha256: binary.sha256, license: linkage.license, classification: 'proprietary-static-object-code', source_availability: 'source-unavailable-proprietary', corresponding_source_review: 'pending-independent-exact-terms-review', publisher_redistribution_authority: 'unverified-external', system_imports: object.system_imports, static_libraries: definitions, link_map: fileReceipt(root, relative), terms: originalTerms };
      components.push({ ...component, definition_sha256: sha256(Buffer.from(canonicalJson(component))) });
    }
  }
  const result = { schema_version: 1, qualification: 'exact-proprietary-component-declarations-no-publisher-grant', cross_build_receipt_sha256: crossSha256, components, raw_sdk_payloads_redistributed: false, license_acceptance_automation: false };
  mkdirSync(path.dirname(output), { recursive: true }); writeFileSync(output, JSON.stringify(result, null, 2) + '\n'); return result;
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { const [root, cross, terms, output] = process.argv.slice(2); if (!output) throw new Error('Usage: prepare-publisher-components.mjs ROOT CROSS_RECEIPT ORIGINAL_TERMS NEW_OUTPUT'); const result = preparePublisherComponents(path.resolve(root), path.resolve(cross), path.resolve(terms), path.resolve(output)); console.log(JSON.stringify({ components: result.components.length, authority: 'unverified-external' })); } catch (error) { console.error(error.message); process.exitCode = 1; }
}
