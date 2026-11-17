#!/usr/bin/env python3
"""Derive the Microsoft component declaration from complete actual Perl bytes.

The declaration covers attribution and original terms only. It neither grants
publisher rights nor asserts that Windows workflows have executed.
"""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import xml.etree.ElementTree as ET
import zipfile

ROOT=Path(__file__).resolve().parents[2]
SPEC=importlib.util.spec_from_file_location('ud_perl_shards',ROOT/'scripts/release/shard-windows-perl-components.py');SHARDS=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(SHARDS)


def fingerprint(path):return SHARDS.INPUTS.fingerprint(path)
def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':')).encode()


def verify_original_paragraphs(docx,text):
    with zipfile.ZipFile(docx) as source:
        names=source.namelist()
        if names.count('word/document.xml')!=1:raise ValueError('Original terms have missing or duplicate document XML')
        root=ET.fromstring(source.read('word/document.xml'))
    ns={'w':'http://schemas.openxmlformats.org/wordprocessingml/2006/main'}
    extracted='\n'.join(''.join(node.text or '' for node in paragraph.findall('.//w:t',ns))for paragraph in root.findall('.//w:p',ns))+'\n'
    if text.read_text()!=extracted:raise ValueError('Extracted terms differ from original DOCX')


def supplier_family(library,architecture):
    if architecture not in('arm64','x64'):raise ValueError('Unknown Windows Perl architecture')
    name='ARM64'if architecture=='arm64'else'x64'
    msvc=r'[A-Za-z]:\\Program Files(?: \(x86\))?\\Microsoft Visual Studio\\2022\\(?:BuildTools|Enterprise)\\VC\\Tools\\MSVC\\14\.44\.35207\\lib\\'+name+r'\\(?:msvcrt\.lib|vcruntime\.lib|oldnames\.lib|delayimp\.lib|setargv\.obj)'
    if re.fullmatch(msvc,library,re.I):return 'msvc-2022-14.44.35207'
    sdk=r'[A-Za-z]:\\Program Files \(x86\)\\Windows Kits\\10\\lib\\10\.0\.26100\.0\\(ucrt|um)\\'+architecture+r'\\[A-Za-z0-9_]+\.lib'
    match=re.fullmatch(sdk,library,re.I)
    if match:return 'windows-sdk-10.0.26100.0-'+match[1].lower()
    raise ValueError('Supplier compiland lacks an exact reviewed compiler-library family: '+library)


def authored_family(library,architecture):
    target='aarch64'if architecture=='arm64'else'x86_64'
    name=library['library'];path=library['archive']['path']
    if name=='perl544':return None
    if name in('msvcrt','vcruntime')and path==f'.artifacts/xwin-cache/xwin/crt/lib/{target}/{name}.lib':return 'msvc-2026-14.51.36244'
    if name=='ucrt'and path==f'.artifacts/xwin-cache/xwin/sdk/lib/ucrt/{target}/ucrt.lib':return 'windows-sdk-xwin-version-unverified-ucrt'
    if name in('kernel32','odbccp32')and path==f'.artifacts/xwin-cache/xwin/sdk/lib/um/{target}/{name}.lib':return 'windows-sdk-xwin-version-unverified-um'
    raise ValueError('Authored XS library lacks an exact reviewed compiler-library family')


def supplier_contribution(item):
    """Separate PDB import modules and unlinked modules from actual objects.

    An import module describes a DLL dependency, not the DLL's implementation.
    Source and license status of object bytes must be established independently.
    """
    name=item['object'].replace('\\','/').rsplit('/',1)[-1]
    if not item['contributions']:
        return 'no-recorded-image-contribution'
    if name.lower().startswith('import:') or name.lower().endswith('.dll'):
        return 'import-metadata'
    return 'linked-object'


def authored_contributions(item):
    groups={}
    for member in item['members']:
        if member['member_kind']=='short-COFF-import':kind='import-metadata'
        elif member['member_kind']=='COFF-object':kind='linked-object'
        else:raise ValueError('Unknown authored COFF member kind')
        groups.setdefault(kind,[]).append(member)
    if not groups:raise ValueError('Contributing authored library has no members')
    return groups


def derive(document,load_parts):
    components=[];binary_joins=[]
    if [row['platform']for row in document['records']]!=['win32/arm64','win32/x64']:raise ValueError('Both frozen Windows Perl platforms are required')
    for record in document['records']:
        architecture=record['platform'].split('/')[1];pdbs={row['path']:row for row in record['pdbs']};seen=set()
        for binary in record['binaries']:
            path=binary['path']
            if path in seen:raise ValueError('Duplicate shipped Perl PE')
            seen.add(path);groups={}
            if binary['origin']=='supplier':
                if binary['pdb_path']not in pdbs:raise ValueError('Supplier binary lacks original matching PDB')
                for item in load_parts(binary['runtime_compilands']):groups.setdefault((supplier_family(item['library'],architecture),supplier_contribution(item)),[]).append(item)
                kind='original-PDB-module-and-linked-image-contribution'
            elif binary['origin']=='authored-reproduced-XS':
                for item in binary['libraries']:
                    family=authored_family(item,architecture)
                    if family:
                        for kind,members in authored_contributions(item).items():groups.setdefault((family,kind),[]).append({**item,'members':members})
                kind='byte-equal-reproduction-and-exact-COFF-map-members'
            else:raise ValueError('Unknown Perl PE origin')
            if not groups:raise ValueError('A shipped Perl PE has no bound component classification')
            ids=[]
            for (family,contribution),items in sorted(groups.items()):
                ident='windows-perl-'+architecture+'-'+hashlib.sha256((path+'\0'+family+'\0'+contribution).encode()).hexdigest()[:24];ids.append(ident)
                row={'id':ident,'platform':record['platform'],'binary_path':path,'binary_sha256':binary['sha256'],'binary_size_bytes':binary['size_bytes'],'family':family,'classification':contribution,'source_availability':'unresolved-needs-exact-source-and-notices' if contribution=='linked-object' else 'not-a-linked-source-object','attribution':{'kind':kind,'items':len(items),'canonical_sha256':hashlib.sha256(canonical(items)).hexdigest()},'corresponding_source_review':'pending-independent-exact-terms-review','publisher_redistribution_authority':'unverified-external'}
                if binary['origin']=='supplier':
                    row['attribution'].update({'pdb_path':binary['pdb_path'],'pdb_sha256':pdbs[binary['pdb_path']]['sha256'],'debug_identity':binary['debug_identity'],'module_ids':[item['id']for item in items]})
                    if family.startswith('msvc-2022-'):
                        editions={re.search(r'Microsoft Visual Studio\\2022\\(BuildTools|Enterprise)\\',item['library'],re.I).group(1).lower()for item in items}
                        if len(editions)!=1:raise ValueError('Supplier compiler edition is ambiguous')
                        row['supplier_compiler_edition']=editions.pop()
                else:row['attribution']['archives']=[{'library':item['library'],'archive':item['archive'],'members':[{key:member[key]for key in('name','archive_header_offset','sha256','size_bytes','member_kind')}for member in item['members']]}for item in items]
                components.append(row)
            binary_joins.append({'platform':record['platform'],'path':path,'sha256':binary['sha256'],'size_bytes':binary['size_bytes'],'origin':binary['origin'],'component_ids':ids})
    return components,binary_joins


def generate(index_path):
    for base in (ROOT/'licenses/vendor/Microsoft-VisualStudio-2022/community', ROOT/'.artifacts/source-materials-data/microsoft-vs2022-review/build-tools', ROOT/'.artifacts/source-materials-data/microsoft-vs2022-review/enterprise'):
        verify_original_paragraphs(base.with_suffix('.docx'),base.with_suffix('.txt'))
    proof=SHARDS.verify(index_path);index=json.loads(index_path.read_bytes());document=index['document']
    def load_parts(value):
        rows=[]
        for part in value['parts']:
            path=index_path.parent/part['path']
            if fingerprint(path)!={key:part[key]for key in('sha256','size_bytes')}:raise ValueError('Attribution part changed')
            rows.extend(json.loads(path.read_bytes()))
        if len(rows)!=value['count']:raise ValueError('Complete compiland count changed')
        return rows
    components,binary_joins=derive(document,load_parts)
    groups={
      'msvc-2022':['licenses/vendor/Microsoft-VisualStudio-2022/community.docx','licenses/vendor/Microsoft-VisualStudio-2022/community.txt','licenses/vendor/Microsoft-VisualStudio-2022/redistribution.html'],
      'msvc-2022-buildtools':['.artifacts/source-materials-data/microsoft-vs2022-review/build-tools.docx','.artifacts/source-materials-data/microsoft-vs2022-review/build-tools.txt','licenses/vendor/Microsoft-VisualStudio-2022/redistribution.html'],
      'msvc-2022-enterprise':['.artifacts/source-materials-data/microsoft-vs2022-review/enterprise.docx','.artifacts/source-materials-data/microsoft-vs2022-review/enterprise.txt','licenses/vendor/Microsoft-VisualStudio-2022/redistribution.html'],
      'msvc-2026':['licenses/vendor/Microsoft-VisualStudio-2026/community.docx','licenses/vendor/Microsoft-VisualStudio-2026/community.txt','licenses/vendor/Microsoft-VisualStudio-2026/build-tools.docx','licenses/vendor/Microsoft-VisualStudio-2026/build-tools.txt','licenses/vendor/Microsoft-VisualStudio-2026/redistribution.html'],
      'windows-sdk':['licenses/vendor/Microsoft-Windows-SDK/sdk-license.txt','licenses/vendor/Microsoft-Windows-SDK/sdk-redist.html']}
    originals={'licenses/vendor/Microsoft-Windows-SDK/sdk-license.txt':'https://raw.githubusercontent.com/microsoft/win32metadata/bd964b20fd0996865afd827ba0d6e712f69712a6/licenses/sdk_license.txt','licenses/vendor/Microsoft-Windows-SDK/sdk-redist.html':'https://learn.microsoft.com/en-us/legal/windows-sdk/redist','licenses/vendor/Microsoft-VisualStudio-2022/community.docx':'https://visualstudio.microsoft.com/wp-content/uploads/2021/11/Visual-Studio-2022-Community-License-EN.docx','.artifacts/source-materials-data/microsoft-vs2022-review/build-tools.docx':'https://visualstudio.microsoft.com/wp-content/uploads/2024/03/Visual-Studio-2022-Diagnostic-Build-Tools-Agent-License_Update-March-2024_EN.docx','.artifacts/source-materials-data/microsoft-vs2022-review/enterprise.docx':'https://visualstudio.microsoft.com/wp-content/uploads/2021/11/Visual-Studio-2022-Enterprise-Professional-License-EN.docx','licenses/vendor/Microsoft-VisualStudio-2022/community.txt':'derived-from-bound-original-DOCX-word/document.xml-paragraph-text','.artifacts/source-materials-data/microsoft-vs2022-review/build-tools.txt':'derived-from-bound-original-DOCX-word/document.xml-paragraph-text','.artifacts/source-materials-data/microsoft-vs2022-review/enterprise.txt':'derived-from-bound-original-DOCX-word/document.xml-paragraph-text','licenses/vendor/Microsoft-VisualStudio-2022/redistribution.html':'https://learn.microsoft.com/en-us/visualstudio/releases/2022/redistribution'}
    terms={name:[{'path':path,**fingerprint(ROOT/path),**({'source':originals[path]}if path in originals else{})}for path in paths]for name,paths in groups.items()}
    for component in components:
        component['terms_group']='windows-sdk'if component['family'].startswith('windows-sdk-')else'msvc-2022-'+component['supplier_compiler_edition']if component['family'].startswith('msvc-2022-')else'msvc-2026'
        component['definition_sha256']=hashlib.sha256(canonical(component)).hexdigest()
    if SHARDS.verify(index_path)!=proof:raise ValueError('Bound attribution changed during declaration')
    return {'schema_version':2,'qualification':'exact-Windows-Perl-Microsoft-component-declarations-no-publisher-grant','attribution_index':{'path':str(index_path.relative_to(ROOT)),**proof['index'],'parts':proof['parts'],'total_part_bytes':proof['total_part_bytes'],'source_receipt':proof['source_receipt']},'binary_joins':binary_joins,'components':components,'terms':terms,'xwin_sdk_provenance':{'path':'.artifacts/xwin-cache/xwin/DONE',**fingerprint(ROOT/'.artifacts/xwin-cache/xwin/DONE'),'status':'package-manifest-listed-library-to-package-join-unverified'},'unresolved_original_terms':{'msvc-2022-buildtools':{'reference':'https://visualstudio.microsoft.com/license-terms/vs2022-ga-diagnosticbuildtools/','original_docx':'https://visualstudio.microsoft.com/wp-content/uploads/2024/03/Visual-Studio-2022-Diagnostic-Build-Tools-Agent-License_Update-March-2024_EN.docx','status':'original-docx-bound-supplier-applicability-unverified'},'msvc-2022-enterprise':{'reference':'https://visualstudio.microsoft.com/license-terms/vs2022-ga-proenterprise/','original_docx':'https://visualstudio.microsoft.com/wp-content/uploads/2021/11/Visual-Studio-2022-Enterprise-Professional-License-EN.docx','status':'original-docx-bound-supplier-applicability-unverified'},'windows-sdk-10.0.26100.0':{'reference':'https://learn.microsoft.com/en-us/legal/windows-sdk/redist','status':'exact-supplier-sdk-installation-terms-not-yet-bound'},'windows-sdk-local-xwin':{'reference':'https://learn.microsoft.com/en-us/legal/windows-sdk/redist','status':'SDK-library-version-and-exact-installation-terms-not-yet-bound'}},'review_scope':['These declarations classify Microsoft compiler/library inputs identified by exact original PDBs and exact reproduced XS library members.','Import metadata and modules with no recorded contribution are distinct from linked objects; these declarations do not prove object licensing or source availability.','Edition-specific 2022 original terms are local review inputs only; supplier license acceptance and exact applicability remain unverified.','The public original SDK terms and redistributable list require independent source-duty review; they do not prove any publisher has accepted a license or satisfies its conditions.','Supplier original COFF archive-member bytes are not reconstructed from linked PDB contribution ranges.','Perl and CPAN corresponding-source/license closure is a separate family; this declaration makes no broad Perl source-coverage claim.','No raw Microsoft library/header payload is included in these declarations.'],'publisher_redistribution_authority':'unverified-external','native_execution':'pending-native','generators':{name:fingerprint(ROOT/name)for name in('scripts/release/declare-windows-perl-components.py','scripts/release/shard-windows-perl-components.py','scripts/release/windows-perl-components.py','scripts/release/node-windows-components.py')}}

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--index',type=Path,required=True);parser.add_argument('--output',type=Path);parser.add_argument('--verify',type=Path);args=parser.parse_args()
    if (args.output is None)==(args.verify is None):parser.error('Use exactly one of --output or --verify')
    result=generate(args.index.resolve())
    if args.verify:
        if json.loads(args.verify.read_bytes())!=result:raise ValueError('Frozen Windows Perl component declaration is stale')
        print(json.dumps({'status':'verified','binary_joins':len(result['binary_joins']),'components':len(result['components'])}))
    else:
        if args.output.exists():raise ValueError('A new declaration output is required')
        args.output.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({'binary_joins':len(result['binary_joins']),'components':len(result['components'])}))
