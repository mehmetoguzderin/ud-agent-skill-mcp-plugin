"""Exact vendor/source joins; source declarations never replace byte checks."""
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
import zipfile

MODULE = Path(__file__).resolve().parents[3] / 'scripts/release/provider-binary-joins.py'
spec = importlib.util.spec_from_file_location('provider_binary_joins', MODULE)
joins = importlib.util.module_from_spec(spec)
spec.loader.exec_module(joins)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def asset(root, name, data):
    file = root / name
    file.parent.mkdir(parents=True, exist_ok=True)
    file.write_bytes(data)
    return {'path': name, 'sha256': digest(data), 'size_bytes': len(data)}


def source(root, name, commit, members):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w:gz') as archive:
        for name_in_tar, data in members.items():
            info = tarfile.TarInfo('project-' + commit + '/' + name_in_tar)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    row = asset(root, 'sources/' + name.replace('/', '-') + '.tar.gz', output.getvalue())
    return {**row, 'name': name, 'version': commit, 'notices': []}


class ProviderBinaryJoinTests(unittest.TestCase):
    def test_sdk_license_declaration_and_closed_member_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            file = Path(directory, 'sdk.zip')
            def write(license='MIT', duplicate=False):
                with zipfile.ZipFile(file, 'w') as archive:
                    archive.writestr('Microsoft.WSL.Containers.nuspec', f'<package><metadata><id>Microsoft.WSL.Containers</id><version>3.0.3</version><license type="expression">{license}</license><repository url="https://github.com/microsoft/WSL"/></metadata></package>')
                    for name in ['NOTICE.txt', 'include/wslcsdk.h', 'runtimes/win-arm64/native/wslcsdk.dll', 'runtimes/win-x64/native/wslcsdk.dll']:
                        archive.writestr(name, b'exact')
                    if duplicate:
                        archive.writestr('NOTICE.txt', b'substitute')
            write()
            result = joins.sdk_declarations(file, '3.0.3')
            self.assertEqual(result['include/wslcsdk.h']['sha256'], digest(b'exact'))
            write('proprietary')
            with self.assertRaisesRegex(ValueError, 'license/project/version'):
                joins.sdk_declarations(file, '3.0.3')
            write(duplicate=True)
            with self.assertRaisesRegex(ValueError, 'duplicate'):
                joins.sdk_declarations(file, '3.0.3')

    def test_bound_materials_and_source_member_duplicates_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            row = asset(root, 'source', b'original')
            self.assertEqual(joins.checked(root, row), root / 'source')
            for unsafe in ['../source', '/source', 'a\\source', 'C:source', 'a//source', './source']:
                with self.assertRaisesRegex(ValueError, 'Unsafe'):
                    joins.safe(root, unsafe)
            (root / 'source').write_bytes(b'changed!')
            with self.assertRaisesRegex(ValueError, 'identity/hash'):
                joins.checked(root, row)
            archive = root / 'duplicate.tar'
            with tarfile.open(archive, 'w') as tar:
                for name in ['one/LICENSE', 'two/LICENSE']:
                    member = tarfile.TarInfo(name); member.size = 1; tar.addfile(member, io.BytesIO(b'a'))
            with self.assertRaisesRegex(ValueError, 'duplicate'):
                joins.source_members(archive, ['LICENSE'])

    def test_all_shipped_profiles_join_exact_release_sources_and_explicit_crlf_transform(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory); provider = base/'provider'; sources = base/'sources'; cache = base/'cache'; kernel = base/'kernel'; extracted = base/'extracted'
            for root in [provider, sources, cache, kernel, extracted]:
                root.mkdir()
            apple_commit, init_commit, wsl_commit = 'a'*40, 'b'*40, 'c'*40
            header, notice, license = b'header\ncontract\n', b'notice\nterms\n', b'MIT License\n'
            source_rows = [source(sources, 'apple/container', apple_commit, {'LICENSE': b'Apache License\n', 'NOTICE.md': b'Apple notices\n'}), source(sources, 'apple/containerization', init_commit, {'LICENSE': b'Apache License\n'}), source(sources, 'microsoft/WSL', wsl_commit, {'LICENSE': license, 'NOTICE.txt': notice, 'src/windows/wslc/CMakeLists.txt': b'add_executable(wslc)\n', 'src/windows/WslcSDK/CMakeLists.txt': b'add_library(wslcsdk)\n', 'src/windows/WslcSDK/wslcsdk.h': header, 'nuget/Microsoft.WSL.Containers.nuspec.in': b'<license>MIT</license>'})]
            (sources/'receipt.json').write_text(json.dumps({'schema_version':1,'files':source_rows}))
            with zipfile.ZipFile(cache/'sdk.nupkg','w') as sdk:
                sdk.writestr('Microsoft.WSL.Containers.nuspec','<package><metadata><id>Microsoft.WSL.Containers</id><version>3.0.3</version><license type="expression">MIT</license><repository url="https://github.com/microsoft/WSL"/></metadata></package>')
                sdk.writestr('NOTICE.txt',notice.replace(b'\n',b'\r\n')); sdk.writestr('include/wslcsdk.h',header.replace(b'\n',b'\r\n'))
                for arch in ['arm64','x64']:sdk.writestr(f'runtimes/win-{arch}/native/wslcsdk.dll',('sdk-'+arch).encode())
            downloads={}
            for name in ['apple.pkg','apple-LICENSE.txt','apple-NOTICE.md','wsl-LICENSE.txt','arm64.msi','x64.msi','kernel.tar']:
                downloads[name]=asset(cache,name,name.encode())
            downloads['sdk.nupkg']={'path':'sdk.nupkg','sha256':digest((cache/'sdk.nupkg').read_bytes()),'size_bytes':(cache/'sdk.nupkg').stat().st_size}
            lock={'schema_version':1,'apple_container':{'source_commit':apple_commit,'package':'apple.pkg','kernel':{'archive':'kernel.tar','member':'kernel'},'init_image':{'version':'test'}},'wslc':{'source_commit':'d'*40,'version':'3.0.3','sdk':'sdk.nupkg','architectures':{arch:{'installer':arch+'.msi'}for arch in ['arm64','x64']}},'downloads':downloads}
            binary={'sources':[{'repository':'microsoft/WSL','role':'binary-release-source','commit':wsl_commit},{'repository':'apple/containerization','role':'binary-init-release-source','commit':init_commit}]}
            files=[]; records={}; apple='runtime/providers/apple-container/darwin-arm64/'
            def shipped(name,data):
                row=asset(provider,name,data);row['sha256']='sha256:'+row['sha256'];files.append(row);return row
            apple_files=[shipped(apple+'bin/container',b'Apple CLI'),shipped(apple+'kernel/vmlinux',b'kernel'),shipped(apple+'linux-GPL-2.0.txt',b'GPL'),shipped('runtime/images/init-linux-arm64.tar',b'init')]
            records['apple-container/darwin/arm64']={'lazy_assets':{'files':apple_files},'init_image':{'transport_sha256':apple_files[-1]['sha256'],'transport_size_bytes':4}}
            with zipfile.ZipFile(cache/'sdk.nupkg') as sdk:
                for arch in ['arm64','x64']:
                    prefix=f'runtime/providers/wslc/win32-{arch}/'; selected=[]
                    for name,data in [('bin/wslc.exe',('cli-'+arch).encode()),('bin/wslcsdk.dll',sdk.read(f'runtimes/win-{arch}/native/wslcsdk.dll')),('include/wslcsdk.h',sdk.read('include/wslcsdk.h')),('NOTICE.txt',sdk.read('NOTICE.txt')),('WSL-NOTICE.txt',sdk.read('NOTICE.txt')),('LICENSE.txt',license)]:selected.append(shipped(prefix+name,data))
                    asset(extracted/f'wsl-{arch}-extracted','PFiles64/WSL/wslc.exe',('cli-'+arch).encode());asset(extracted/f'wsl-{arch}-extracted','PFiles64/WSL/NOTICE.txt',sdk.read('NOTICE.txt'));records[f'wslc/win32/{arch}']={'lazy_assets':{'files':selected}}
            (provider/'provider-receipts.json').write_text(json.dumps({'schema_version':1,'files':files}))
            kernel_receipt={'qualification':'pinned-apple-kernel-corresponding-source-inputs','status':'passed','kernel_sha256':'sha256:'+digest(b'kernel')}
            for key in ['kernel_source','kernel_config','kata_source']:kernel_receipt[key]=asset(kernel,key,key.encode())
            (kernel/'receipt.json').write_text(json.dumps(kernel_receipt))
            result=joins.collect(provider,sources,cache,{'provider_receipts':records},lock,extracted_root=extracted,binary_sources=binary,kernel_source_root=kernel)
            self.assertEqual(len(result['joins']),16)
            wsl=next(row for row in result['joins']if row['shipped']['path'].endswith('win32-arm64/bin/wslcsdk.dll'))
            self.assertEqual(wsl['source_commit'],wsl_commit)
            self.assertEqual(wsl['header_transform']['kind'],'LF-to-CRLF-only')
            self.assertEqual(wsl['header_transform']['source_sha256'],digest(header))
            self.assertEqual(wsl['header_transform']['distributed_sha256'],digest(header.replace(b'\n',b'\r\n')))
            changed=copy.deepcopy(records);changed['wslc/win32/x64']['lazy_assets']['files'][0]['sha256']='sha256:'+'0'*64
            with self.assertRaisesRegex(ValueError,'inventory differs'):
                joins.collect(provider,sources,cache,{'provider_receipts':changed},lock,extracted_root=extracted,binary_sources=binary,kernel_source_root=kernel)
            (provider/(apple+'bin/container')).write_bytes(b'changed!!')
            with self.assertRaisesRegex(ValueError,'identity/hash'):
                joins.collect(provider,sources,cache,{'provider_receipts':records},lock,extracted_root=extracted,binary_sources=binary,kernel_source_root=kernel)

class WslSourceRoles(unittest.TestCase):
    def test_binary_release_and_maintained_head_have_distinct_truthful_roles(self):
        root=Path(__file__).resolve().parents[3]
        lock=json.loads((root/'runtime/provider-assets.lock.json').read_text())['wslc']
        sources=json.loads((root/'runtime/materials/provider-binary-sources.lock.json').read_text())['sources']
        release=next(row for row in sources if row['repository']=='microsoft/WSL')
        self.assertEqual(lock['source_commit'],release['commit'])
        self.assertEqual(lock['source_commit'],'15ea3b3846c5f18318722d1381186b2ff6ed72eb')
        self.assertEqual(lock['maintained_source_commit'],'19cd15ea579fe09e29fcef8d9b947a588da3a765')
        self.assertEqual(lock['source_role'],'binary-release-tag')
        self.assertEqual(lock['maintained_source_role'],'independent-maintained-source-input')

if __name__=='__main__':unittest.main()
