#!/usr/bin/env python3
"""Generate an SPDX 2.3 inventory from exact dependency locks and source receipts."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path
import re
import tomllib
from urllib.parse import quote


def generate(root: Path, source: dict, created: str, *, provisional_materials: bool = False) -> dict:
    if not re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", created):
        raise ValueError("SBOM creation time must be an explicit UTC timestamp")
    if not re.fullmatch(r"[a-f0-9]{64}", source.get("sha256", "")) or not source.get("files"):
        raise ValueError("SBOM requires a nonempty source receipt")
    package = json.loads((root / "package.json").read_text())
    packages = []
    relationships = []
    identifiers = {}

    def add(name, version, download="NOASSERTION", license="NOASSERTION", checksums=None, identity=None, purl=None):
        identity = identity or f"{name}@{version}"
        identifier = "SPDXRef-Package-" + hashlib.sha256(identity.encode()).hexdigest()[:24]
        item = {"SPDXID": identifier, "name": name, "versionInfo": str(version), "downloadLocation": download or "NOASSERTION", "filesAnalyzed": False, "licenseConcluded": "NOASSERTION", "licenseDeclared": license or "NOASSERTION", "copyrightText": "NOASSERTION"}
        if checksums:
            item["checksums"] = checksums
        if purl:
            item["externalRefs"] = [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": purl}]
        if identifier in identifiers:
            if identifiers[identifier] != item:
                raise ValueError("inconsistent duplicate SBOM component identity")
            return
        identifiers[identifier] = item
        packages.append(item)
        relationships.append({"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": identifier})

    add(package["name"], package["version"], package.get("repository"), package.get("license"), identity="product")
    lock = json.loads((root / "package-lock.json").read_text())
    for location, item in sorted(lock.get("packages", {}).items()):
        if not location:
            continue
        name = item.get("name") or location.rsplit("node_modules/", 1)[-1]
        checksums = []
        for integrity in item.get("integrity", "").split():
            algorithm, _, encoded = integrity.partition("-")
            if algorithm in ("sha256", "sha512"):
                checksums.append({"algorithm": algorithm.upper(), "checksumValue": base64.b64decode(encoded, validate=True).hex()})
        add(name, item.get("version", "NOASSERTION"), item.get("resolved"), item.get("license"), checksums, identity="npm:" + location)
    uv = tomllib.loads((root / "uv.lock").read_text())
    for item in sorted(uv.get("package", []), key=lambda value: (value["name"], value.get("version", ""))):
        checksums = []
        source_info = item.get("source", {})
        download = source_info.get("git") or source_info.get("registry") or "NOASSERTION"
        for asset in [item.get("sdist", {})] + item.get("wheels", []):
            algorithm, _, value = asset.get("hash", "").partition(":")
            if algorithm == "sha256":
                checksums.append({"algorithm": "SHA256", "checksumValue": value})
        # Each hash identifies an allowed locked distribution, not a claim that
        # all platform-specific wheels are installed in one runtime.
        add(item["name"], item.get("version", "NOASSERTION"), download, checksums=checksums, identity="python:" + item["name"] + ":" + json.dumps(source_info, sort_keys=True))
    cargo = tomllib.loads((root / "Cargo.lock").read_text())
    for item in sorted(cargo.get("package", []), key=lambda value: (value["name"], value["version"])):
        checksums = [{"algorithm": "SHA256", "checksumValue": item["checksum"]}] if "checksum" in item else []
        add(item["name"], item["version"], item.get("source"), checksums=checksums, identity="cargo:" + item["name"] + "@" + item["version"])
    for filename in ("runtime/node-distributions.lock.json", "runtime/perl-deps.lock.json", "runtime/render-deps.lock.json", "runtime/core-image.lock.json", "runtime/ud-sources.lock.json"):
        file = root / filename
        if not file.is_file():
            raise ValueError(f"missing runtime dependency lock: {filename}")
        data = file.read_bytes()
        add(filename, "locked-receipt", "NOASSERTION", checksums=[{"algorithm": "SHA256", "checksumValue": hashlib.sha256(data).hexdigest()}], identity=filename)
        locked = json.loads(data)
        if "debian" in locked:
            for architecture in locked["debian"]["architectures"].values():
                for component in architecture["packages"]:
                    add(component["name"], component["version"], checksums=[{"algorithm": "SHA256", "checksumValue": component["sha256"]}], identity=f"deb:{component['architecture']}:{component['name']}@{component['version']}", purl=f"pkg:deb/debian/{quote(component['name'], safe='')}@{quote(component['version'], safe='')}?arch={component['architecture']}")
        if filename.endswith("ud-sources.lock.json"):
            for component in locked["sources"]:
                add(component["repository"], component["commit"], "https://github.com/" + component["repository"] + "/tree/" + component["commit"], checksums=[{"algorithm": "SHA256", "checksumValue": component["archive_sha256"]}], identity="git:" + component["repository"] + "@" + component["commit"])
    optional_locks = {"runtime/native-perl-source.lock.json", "runtime/native-perl-modules.lock.json", "runtime/userspace-inputs.lock.json"}
    optional_locks.update(path.relative_to(root).as_posix() for path in (root / "runtime").glob("native-browser-*.lock.json"))
    optional_locks.update({"runtime/node-compatibility.lock.json", "runtime/native-decoder.lock.json", "runtime/windows-perl-distributions.lock.json", "runtime/provider-assets.lock.json", "runtime/providers.sources.lock.json", "runtime/lima-inputs.lock.json", "runtime/lima-guest.lock.json"})
    for filename in sorted(optional_locks):
        file = root / filename
        if not file.is_file():
            continue
        data = file.read_bytes()
        locked = json.loads(data)
        add(filename, "locked-receipt", checksums=[{"algorithm": "SHA256", "checksumValue": hashlib.sha256(data).hexdigest()}], identity=filename)
        if "releases" in locked:
            for component in locked["releases"].values():
                declared = {"perl_5": "(Artistic-1.0-Perl OR GPL-1.0-or-later)", "mit": "MIT", "apache_2_0": "Apache-2.0"}
                values = component.get("license", [])
                license = declared.get(values[0], "NOASSERTION") if len(values) == 1 else "NOASSERTION"
                add(component["distribution"], component["version"], component["url"], license, [{"algorithm": "SHA256", "checksumValue": component["sha256"]}], identity="cpan:" + component["name"])
        elif filename.endswith("native-perl-source.lock.json"):
            add("perl", locked["version"], locked["url"], "(Artistic-1.0-Perl OR GPL-1.0-or-later)", [{"algorithm": "SHA256", "checksumValue": locked["sha256"]}], identity="native-perl:" + locked["name"])
        elif "/native-browser-" in filename:
            browser = locked.get("archive", locked)
            add("Microsoft Edge" if locked.get("provider") == "microsoft-edge" else "Chrome headless shell", locked["version"], browser["url"], checksums=[{"algorithm": "SHA256", "checksumValue": browser["sha256"]}], identity="native-browser:" + locked["platform"])
        elif filename.endswith("native-decoder.lock.json"):
            for name, fingerprint in locked["license_receipts"].items():
                if hashlib.sha256((root / name).read_bytes()).hexdigest() != fingerprint:
                    raise ValueError("native decoder notice differs from its exact source receipt")
            add(locked["name"], locked["version"], locked["source"]["url"], locked["license"], [{"algorithm": "SHA256", "checksumValue": locked["source"]["sha256"]}], identity="native-decoder:source:" + locked["source"]["commit"])
            add(locked["name"] + " ARM64 executable", locked["version"], license=locked["license"], checksums=[{"algorithm": "SHA256", "checksumValue": locked["program"]["sha256"]}], identity="native-decoder:windows-arm64")
        elif filename.endswith("providers.sources.lock.json"):
            for component in locked["sources"]:
                add(component["project"], component["commit"], "https://github.com/" + component["project"] + "/tree/" + component["commit"], component["license"], identity="provider-source:" + component["project"])
        elif filename.endswith("lima-inputs.lock.json"):
            for component in locked["assets"]:
                # nerdctl-full contains independently licensed executables,
                # including runc linked with LGPL libseccomp. Its top-level
                # project's Apache license cannot describe that whole archive.
                declared = "Apache-2.0" if component["name"].startswith("lima-") else "NOASSERTION"
                add(component["name"], "2.3.0" if component["name"].startswith("lima-") else "2.4.2", component["url"], declared, [{"algorithm": "SHA256", "checksumValue": component["sha256"]}], identity="lima-release-asset:" + component["name"])
            for name, component in locked["sources"].items():
                add(name + " release source", component["commit"], component["source_url"], "Apache-2.0", identity="lima-release-source:" + name)
        elif filename.endswith("lima-guest.lock.json"):
            for architecture, component in locked["images"].items():
                add("Ubuntu Lima guest " + architecture, locked["distribution"], component["url"], checksums=[{"algorithm": "SHA256", "checksumValue": component["sha256"].removeprefix("sha256:")}], identity="lima-guest-image:" + architecture)
                manifest_file = root / "runtime/materials/lima-ubuntu" / (architecture + ".manifest")
                manifest_bytes = manifest_file.read_bytes()
                if len(manifest_bytes) != component["manifest"]["size_bytes"] or hashlib.sha256(manifest_bytes).hexdigest() != component["manifest"]["sha256"].removeprefix("sha256:"):
                    raise ValueError("Lima guest publisher package inventory differs from its lock")
                installed = {}
                for line in manifest_bytes.decode("utf-8", errors="strict").splitlines():
                    parts = line.split("\t")
                    if len(parts) != 2 or not all(parts) or parts[0] in installed:
                        raise ValueError("Lima guest publisher package inventory has an invalid or duplicate row")
                    name, version = parts
                    name = name.removesuffix(":" + architecture)
                    if name in installed:
                        raise ValueError("Lima guest package architecture aliases collide")
                    installed[name] = version
                    add(name, version, identity="lima-guest-preinstalled:" + architecture + ":" + name, purl="pkg:deb/ubuntu/" + quote(name, safe='') + "@" + quote(version, safe='') + "?arch=" + architecture)
                for name, version in component["installed_dependencies"].items():
                    if installed.get(name) != version:
                        raise ValueError("Lima guest prerequisites differ from the exact publisher inventory")
            for architecture, components in locked["packages"].items():
                for component in components:
                    add(component["name"], component["version"], component["url"], checksums=[{"algorithm": "SHA256", "checksumValue": component["sha256"].removeprefix("sha256:")}], identity="lima-guest-package:" + architecture + ":" + component["name"])
        elif filename.endswith("provider-assets.lock.json"):
            for name, component in locked.get("downloads", {}).items():
                add(name, "locked-provider-asset", component["url"], checksums=[{"algorithm": "SHA256", "checksumValue": component["sha256"].removeprefix("sha256:")}], identity="provider-asset:" + name)
    policy_file = root / "runtime/policies/render-seccomp.provenance.json"
    if policy_file.is_file():
        provenance = json.loads(policy_file.read_text())
        policy = root / "runtime/policies/render-seccomp.json"
        license = root / "licenses/Moby-Apache-2.0.txt"
        if hashlib.sha256(policy.read_bytes()).hexdigest() != provenance["sha256"] or not license.is_file():
            raise ValueError("Moby policy or license differs from its provenance")
        add("Moby profiles render seccomp derivative", provenance["commit"], provenance["upstream"] + "/tree/" + provenance["commit"], provenance["license"], [{"algorithm": "SHA256", "checksumValue": provenance["sha256"]}], identity="moby-render-seccomp")
        identifiers["SPDXRef-Package-" + hashlib.sha256(b"moby-render-seccomp").hexdigest()[:24]]["annotations"] = [{"annotationType": "OTHER", "annotator": "Tool: ud-agent-source-lock-sbom-1", "annotationDate": created, "comment": "Local modifications: " + "; ".join(provenance["modifications"]) + ". Full license: licenses/Moby-Apache-2.0.txt; attribution: NOTICE."}]
    material_lock = root / "runtime/source-materials.lock.json"
    if provisional_materials:
        product_id = "SPDXRef-Package-" + hashlib.sha256(b"product").hexdigest()[:24]
        identifiers[product_id]["annotations"] = [{"annotationType": "OTHER", "annotator": "Tool: ud-agent-source-lock-sbom-1", "annotationDate": created, "comment": "Provisional material phase: exact corresponding-source materials have not yet been selected from the actual shipped component report. Source file inventory is retained; no source-index or source-shard package is asserted. This SBOM does not authorize production promotion."}]
    elif any(item["path"] == "runtime/source-materials.lock.json" for item in source["files"]):
        if not material_lock.is_file():
            raise ValueError("source material SBOM lock is missing from its bound source tree")
        closure = json.loads(material_lock.read_bytes())
        descriptor = closure.get("index", {})
        relative = descriptor.get("path", "")
        if closure.get("schema_version") != 1 or not relative or relative.startswith("/") or "\\" in relative or any(part in ("", ".", "..") for part in relative.split("/")):
            raise ValueError("source material SBOM lock has an unsafe index path")
        file = root
        for part in relative.split("/"):
            file = file / part
            if file.is_symlink():
                raise ValueError("source material SBOM index contains a link")
        data = file.read_bytes()
        if len(data) > 16 * 1024**2 or len(data) != descriptor.get("size") or hashlib.sha256(data).hexdigest() != descriptor.get("sha256"):
            raise ValueError("source material SBOM index differs from its frozen receipt")
        index = json.loads(data)
        if not isinstance(index.get("complete_product_coverage"), bool) or len(index.get("parts", [])) != len(closure.get("parts", [])):
            raise ValueError("source material SBOM index is incomplete")
        objects = [("corresponding-source-index", descriptor)]
        for expected, actual in zip(index["parts"], closure["parts"], strict=True):
            if any(actual.get(key) != expected.get(key) for key in ("id", "sha256", "size")) or Path(actual["path"]).name != expected["path"]:
                raise ValueError("source material SBOM shards differ from their ordered index")
            objects.append((actual["id"], actual))
        for identity, item in objects:
            add("Corresponding source " + identity, "locked-archive", "https://github.com/mehmetoguzderin/ud-agent-skill-mcp-plugin/releases/download/v" + package["version"] + "/" + Path(item["path"]).name, checksums=[{"algorithm": "SHA256", "checksumValue": item["sha256"]}], identity="source-material:" + identity)
        product_id = "SPDXRef-Package-" + hashlib.sha256(b"product").hexdigest()[:24]
        identifiers[product_id]["annotations"] = [{"annotationType": "OTHER", "annotator": "Tool: ud-agent-source-lock-sbom-1", "annotationDate": created, "comment": "Corresponding-source index SHA256=" + descriptor["sha256"] + "; stream SHA256=" + index["stream_sha256"] + "; complete_product_coverage=" + str(index["complete_product_coverage"]).lower() + ". Partial source inputs do not authorize production promotion. Original per-component notices and source receipts are retained in the closed archive."}]
    files = [{"SPDXID": "SPDXRef-File-" + hashlib.sha256(item["path"].encode()).hexdigest()[:24], "fileName": "./" + item["path"], "checksums": [{"algorithm": "SHA256", "checksumValue": item["sha256"]}], "licenseConcluded": "NOASSERTION", "copyrightText": "NOASSERTION"} for item in source["files"]]
    extracted = []
    proprietary = root / 'runtime/materials/msvc-static-components.lock.json'
    if proprietary.is_file():
        declaration = json.loads(proprietary.read_bytes()); terms = {}; component_ids = set()
        if declaration.get('schema_version') != 1 or declaration.get('qualification') != 'exact-proprietary-component-declarations-no-publisher-grant' or declaration.get('raw_sdk_payloads_redistributed') is not False or not declaration.get('components'):
            raise ValueError('exact proprietary static-component declaration is missing')
        for component in declaration['components']:
            definition = {key: value for key, value in component.items() if key != 'definition_sha256'}
            if component['id'] in component_ids or hashlib.sha256(json.dumps(definition, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest() != component['definition_sha256'] or component.get('license') != 'LicenseRef-Microsoft-VisualStudio-2026-CRT' or component.get('publisher_redistribution_authority') != 'unverified-external':
                raise ValueError('proprietary static-component identity or classification differs')
            component_ids.add(component['id'])
            for term in component['terms']:
                name = term['path']
                if not name.startswith('licenses/vendor/Microsoft-VisualStudio-2026/') or '..' in Path(name).parts or '\\' in name: raise ValueError('unsafe original proprietary terms path')
                file = root / name
                if file.is_symlink() or not file.is_file() or file.stat().st_size != term['size'] or hashlib.sha256(file.read_bytes()).hexdigest() != term['sha256']: raise ValueError('original proprietary terms differ from the component declaration')
                terms[name] = term
            identity = 'proprietary-static-component:' + component['id']
            add(component['id'], 'exact-static-object-inventory', license=component['license'], checksums=[{'algorithm': 'SHA256', 'checksumValue': component['binary_sha256']}], identity=identity)
            item = identifiers['SPDXRef-Package-' + hashlib.sha256(identity.encode()).hexdigest()[:24]]
            item['sourceInfo'] = 'Proprietary static object code; source unavailable. Exact contributing library/object hashes are retained in runtime/materials/msvc-static-components.lock.json. Microsoft SDK/library payloads are not redistributed in corresponding-source archives.'
            item['annotations'] = [{'annotationType': 'OTHER', 'annotator': 'Tool: ud-agent-source-lock-sbom-1', 'annotationDate': created, 'comment': 'Component definition SHA256=' + component['definition_sha256'] + '; publisher_redistribution_authority=unverified-external. Source-duty review is separate and does not grant publisher rights. Original terms: ' + ', '.join(sorted(term['path'] for term in component['terms']))}]
            for other in component.get('other_static_components', []):
                if other.get('license') != 'Apache-2.0 WITH LLVM-exception' or not other.get('members') or other['id'] in component_ids: raise ValueError('separate STL component declaration is incomplete or duplicate')
                component_ids.add(other['id']); identity = 'separate-open-source-static-component:' + other['id']
                add(other['id'], 'exact-static-object-inventory', license=other['license'], checksums=[{'algorithm': 'SHA256', 'checksumValue': other['archive_sha256']}], identity=identity)
                described = identifiers['SPDXRef-Package-' + hashlib.sha256(identity.encode()).hexdigest()[:24]]
                described['sourceInfo'] = 'Separately attributed Microsoft STL objects; exact archive/member hashes retained. Per-object source status: ' + other['source_status'] + '. Original proprietary SDK/header inputs and publisher authority remain separate.'
                described['annotations'] = [{'annotationType': 'OTHER', 'annotator': 'Tool: ud-agent-source-lock-sbom-1', 'annotationDate': created, 'comment': 'Contributing objects: ' + ', '.join(row['sha256'] for row in other['members']) + '; this open-source declaration does not cover proprietary CRT objects or infer publisher entitlement.'}]
        texts = [name + '\n' + (root / name).read_text(encoding='utf-8') for name in sorted(terms) if name.endswith('.txt')]
        if not texts: raise ValueError('original proprietary license text is missing')
        extracted.append({'licenseId': 'LicenseRef-Microsoft-VisualStudio-2026-CRT', 'name': 'Microsoft Visual Studio 2026 CRT original conditional terms; publisher authority unresolved', 'extractedText': '\n\n'.join(texts), 'seeAlsos': sorted({row['url'] for row in terms.values() if row.get('url')})})
    if any("LicenseRef-Public-Domain" in item["licenseDeclared"] for item in packages):
        text = (root / "licenses/7zip-License.txt").read_text()
        line = next(line.strip() for line in text.splitlines() if '"public domain" status is stated in source file' in line)
        extracted.append({"licenseId": "LicenseRef-Public-Domain", "name": "7-Zip source files explicitly marked public domain", "extractedText": line, "seeAlsos": ["https://7-zip.org/license.txt"]})
    return {"spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT", "name": package["name"] + "-" + package["version"], "documentNamespace": "https://github.com/mehmetoguzderin/ud-agent-skill-mcp-plugin/sbom/" + source["sha256"], "creationInfo": {"created": created, "creators": ["Tool: ud-agent-source-lock-sbom-1"]}, "packages": packages, "files": files, "relationships": relationships, **({"hasExtractedLicensingInfos": extracted} if extracted else {})}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--source-receipt", type=Path, required=True)
    parser.add_argument("--created", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--provisional-materials", action="store_true", help="Record pending material selection without asserting a corresponding-source index or shard package")
    args = parser.parse_args()
    data = generate(args.root, json.loads(args.source_receipt.read_text()), args.created, provisional_materials=args.provisional_materials)
    with args.output.open("x", encoding="utf-8") as target:
        json.dump(data, target, indent=2)
        target.write("\n")


if __name__ == "__main__":
    main()
