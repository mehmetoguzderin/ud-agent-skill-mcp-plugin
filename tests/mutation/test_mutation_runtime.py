import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shlex
import struct
import subprocess
import sys
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('ud_mutation_runtime_test', ROOT / 'scripts/quality/prepare-mutation-runtime.py')
runtime = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runtime)


class MutationRuntimeTests(unittest.TestCase):
    def test_ci_transient_allowance_reaches_only_the_outer_supervisor_when_explicit(self):
        assets=ROOT/'.artifacts/cli-fixture';output=ROOT/'.artifacts/cli-context';node=str(ROOT/'fixture-node')
        for operation,mode in [('--ensure-ci','ensure'),('--load-ci-image','load'),('--ensure-ci-provider','provider')]:
            for allowance in (None,1,8_000_000_000,12_000_000_000):
                with self.subTest(operation=operation,allowance=allowance):
                    options=[] if allowance is None else ['--transient-bytes',str(allowance)]
                    argv=['prepare-mutation-runtime.py',operation,'--asset-root',str(assets),'--output',str(output),'--download',*options]
                    with patch.object(sys,'argv',argv),patch.object(runtime.shutil,'which',return_value=node),patch.object(runtime.subprocess,'run',return_value=SimpleNamespace(returncode=7)) as run:
                        with self.assertRaises(SystemExit) as result:runtime.main()
                    self.assertEqual(result.exception.code,7)
                    run.assert_called_once_with([node,str(ROOT/'scripts/quality/mutation-sdk-storage.mjs'),mode,sys.executable,str(assets.resolve()),str(output.resolve()),'true','',*options],cwd=ROOT)

    def test_ci_transient_allowance_rejects_invalid_bounds_and_scope_before_execution(self):
        invalid=[['--ensure-ci','--transient-bytes',value] for value in ('0','-1','12000000001','1.5','nan')]
        invalid += [arguments+['--transient-bytes','8000000000'] for arguments in [[],['--output','fixture'],['--ci-cache-key'],['--ensure-ci','--sdk-storage-worker'],['--load-ci-image','--sdk-storage-worker'],['--ensure-ci-provider','--sdk-storage-worker'],['--ensure-ci','--load-ci-image'],['--ci-cache-key','--ensure-ci']]]
        for arguments in invalid:
            with self.subTest(arguments=arguments),patch.object(sys,'argv',['prepare-mutation-runtime.py',*arguments]),patch.object(sys,'stderr',io.StringIO()) as error,patch.object(runtime.subprocess,'run') as run,patch.object(runtime,'prepare') as prepare,patch.object(runtime.importlib.util,'spec_from_file_location') as load:
                with self.assertRaises(SystemExit) as result:runtime.main()
                self.assertEqual(result.exception.code,2);self.assertIn('--transient-bytes',error.getvalue())
                run.assert_not_called();prepare.assert_not_called();load.assert_not_called()

    def context(self, output, *, with_git=False):
        output.mkdir()
        for name in [*runtime.CONTEXT_TREES,*(['git'] if with_git else [])]:
            tree=output/name;tree.mkdir();(tree/'original').write_bytes((name+' original SDK bytes\n').encode()*1024);(tree/'original').chmod(0o555 if name in ('uv','node','rust','git') else 0o444)
        for name in [*runtime.CONTEXT_FILES,'native-guard',*(['git-input-receipt.json'] if with_git else [])]:(output/name).write_bytes((name+'\n').encode())
        return output

    def test_compact_context_preserves_closed_bytes_modes_links_and_retires_expanded_inputs(self):
        for with_git in (False,True):
            with self.subTest(with_git=with_git),tempfile.TemporaryDirectory() as temporary:
                root=Path(temporary);output=self.context(root/'context',with_git=with_git)
                (output/'node_modules/alias').symlink_to('original')
                original={file.relative_to(output).as_posix():(file.read_bytes(),file.stat().st_mode&0o777) for file in output.rglob('*') if file.is_file() and not file.is_symlink()}
                receipt=(output/'input-receipt.json').read_bytes();payload=runtime.compact_context(output,with_git=with_git)
                self.assertEqual({file.name for file in output.iterdir()},{'sdk-inputs.tar.xz','input-receipt.json'})
                self.assertEqual((output/'input-receipt.json').read_bytes(),receipt);self.assertEqual(payload['sha256'],runtime.digest(output/payload['path']))
                self.assertEqual((output/payload['path']).read_bytes()[:6],b'\xfd7zXZ\x00')
                self.assertEqual(payload['input_bytes'],sum(len(body) for body,_ in original.values()))
                self.assertEqual(payload['entry_bytes'],{name:sum(len(body) for path,(body,_) in original.items() if path==name or path.startswith(name+'/')) for name in payload['entry_bytes']})
                self.assertLess(payload['size_bytes'],sum(len(body) for body,_ in original.values())//4)
                destinations={'private-perl':'opt/ud-agent/perl','upstream':'opt/ud-agent/upstream','uv':'opt/mutation/bin','native-guard':'opt/mutation/bin/ud-agent-guard'}
                expected={}
                with tarfile.open(output/payload['path'],'r:xz') as packed:
                    members=packed.getmembers();self.assertEqual(len(members),len({member.name for member in members}))
                    for name,(body,mode) in original.items():
                        first,*rest=name.split('/');destination=destinations.get(first,'opt/mutation/'+first)+('/'+'/'.join(rest) if rest else '')
                        member=packed.getmember(destination)
                        expected[destination]=(body,mode)
                        self.assertEqual(packed.extractfile(member).read(),body);self.assertEqual(member.mode,mode)
                        self.assertEqual((member.uid,member.gid,member.uname,member.gname),(0,0,'',''))
                    self.assertEqual(packed.getmember('opt/mutation/node_modules/alias').linkname,'original')
                unpacked=root/'unpacked'
                text=runtime.runtime_containerfile('fixture',{'installed_path':'fixture','upstream_source':{'sha256':'b'*64}},None,payload)
                command=shlex.split(next(line for line in text.splitlines() if line.startswith('RUN ')).split(' && ',1)[0])
                self.assertEqual(command[2:4],['python3','-c'])
                extract=command[4].replace('"/sdk-inputs.tar.xz"',json.dumps(str(output/payload['path']))).replace('.extractall("/",','.extractall('+json.dumps(str(unpacked))+',')
                subprocess.run([sys.executable,'-c',extract],check=True,capture_output=True,timeout=10)
                restored_alias=unpacked/'opt/mutation/node_modules/alias'
                self.assertTrue(restored_alias.is_symlink());self.assertEqual(os.readlink(restored_alias),'original')
                self.assertEqual(restored_alias.read_bytes(),original['node_modules/original'][0])
                for name,(body,mode) in expected.items():
                    restored=unpacked/name
                    self.assertFalse(restored.is_symlink());self.assertEqual(restored.read_bytes(),body)
                    self.assertEqual(restored.stat().st_mode&0o777,mode)
                changed=output/payload['path'];changed.chmod(0o600)
                with changed.open('ab') as stream:stream.write(b'changed transported payload')
                rejected=root/'rejected';invalid=extract.replace(json.dumps(str(unpacked)),json.dumps(str(rejected)))
                result=subprocess.run([sys.executable,'-c',invalid],capture_output=True,timeout=10)
                self.assertNotEqual(result.returncode,0);self.assertIn(b'AssertionError',result.stderr);self.assertFalse(rejected.exists())

    def test_compact_context_rejects_unlisted_roots_and_escaping_links_before_retirement(self):
        for case in ('unlisted','absolute-link','escaping-link','hard-link'):
            with self.subTest(case=case),tempfile.TemporaryDirectory() as temporary:
                root=Path(temporary);output=self.context(root/'context');original=(output/'rust/original').read_bytes()
                if case=='unlisted':(output/'unlisted').write_text('foreign')
                elif case=='hard-link':os.link(output/'rust/original',output/'rust/hard')
                else:(output/'node_modules/alias').symlink_to('/outside' if case=='absolute-link' else '../../outside')
                with self.assertRaisesRegex(ValueError,'SDK compact'):runtime.compact_context(output,with_git=False)
                self.assertEqual((output/'rust/original').read_bytes(),original);self.assertFalse((output/'sdk-inputs.tar.xz').exists())

    def test_runtime_container_uses_one_verified_readonly_payload_mount_without_input_layers(self):
        projection={'installed_path':'python/lib/python3.14/site-packages/mutmut/mutation/trampoline.py','upstream_source':{'sha256':'b'*64}}
        payload={'path':'sdk-inputs.tar.xz','sha256':'a'*64}
        for git in (None,{'version':'original'}):
            text=runtime.runtime_containerfile('provider@sha256:'+'c'*64,projection,git,payload)
            instructions=text.splitlines();run=next(line for line in instructions if line.startswith('RUN '))
            self.assertEqual(sum(line.startswith('RUN ') for line in instructions),1);self.assertFalse(any(line.startswith(('COPY ','ADD ')) for line in instructions))
            self.assertTrue(run.startswith('RUN --mount=type=bind,source=sdk-inputs.tar.xz,target=/sdk-inputs.tar.xz,readonly '))
            self.assertIn('"a'+'a'*63+'"',run);self.assertIn('--no-cache --system',run);self.assertIn('--no-index --no-deps --require-hashes',run)
            self.assertIn(projection['installed_path'],run);self.assertIn('/opt/mutation/rust/bin/cargo-mutants mutants --version',run)
            self.assertEqual('/opt/mutation/bin/git --version' in run,git is not None)
            self.assertEqual(shlex.split(run.rsplit(' && ',1)[1]),['find','/opt/mutation','(','-type','f','-o','-type','d',')','-perm','/222','-exec','chmod','a-w','{}','+'])

    def test_sdk_subprocess_keeps_success_output_and_surfaces_bounded_failure_tails(self):
        result=runtime.sdk_node_command([sys.executable,'-c','print("original SDK success")'],timeout=10)
        self.assertEqual(result.stdout,b'original SDK success'+os.linesep.encode())
        command=[sys.executable,'-c','import sys;sys.stdout.write("hidden-start-out"+"x"*9000+"out-tail");sys.stderr.write("hidden-start-err"+"y"*9000+"err-tail");sys.exit(7)']
        with self.assertRaisesRegex(ValueError,'exited 7') as raised:runtime.sdk_node_command(command,timeout=10)
        diagnostic=str(raised.exception)
        self.assertIn('out-tail',diagnostic);self.assertIn('err-tail',diagnostic)
        # The command is identified separately; captured stream prefixes are clipped.
        self.assertNotIn('hidden-start-out',diagnostic.split('\nstdout ',1)[1]);self.assertNotIn('hidden-start-err',diagnostic.split('\nstderr ',1)[1])
        self.assertLess(len(diagnostic),17000)

    def test_sdk_subprocess_timeout_keeps_available_stderr_without_accepting_a_result(self):
        with patch.object(runtime.subprocess,'run',side_effect=subprocess.TimeoutExpired(['node','fixture.mjs'],3,output=b'partial output',stderr=b'last SDK operation')):
            with self.assertRaisesRegex(ValueError,'timed out after 3 seconds') as raised:runtime.sdk_node_command(['node','fixture.mjs'],timeout=3)
        self.assertIn('partial output',str(raised.exception));self.assertIn('last SDK operation',str(raised.exception))

    def test_download_failures_do_not_poison_the_hash_locked_cache(self):
        class Interrupted(io.BytesIO):
            def read(self, size=-1):
                if self.tell(): raise OSError('connection interrupted')
                return super().read(2)

        with tempfile.TemporaryDirectory() as temporary:
            cache=Path(temporary);content=b'locked bytes';expected=hashlib.sha256(content).hexdigest()
            item={'sha256':expected,'size_bytes':len(content),'url':'https://fixture.invalid/original'}
            for body,error in [(Interrupted(content),OSError),(io.BytesIO(b'bad'),ValueError),(io.BytesIO(content+b'extra'),ValueError)]:
                with self.subTest(error=error),patch.object(runtime,'urlopen',return_value=body):
                    with self.assertRaises(error):runtime.acquire(item,cache,True)
                    self.assertEqual(list(cache.iterdir()),[])
            with patch.object(runtime,'urlopen',return_value=io.BytesIO(content)):
                self.assertEqual(runtime.acquire(item,cache,True).read_bytes(),content)
            (cache/expected).write_bytes(b'corrupt previous bytes')
            with patch.object(runtime,'urlopen',side_effect=AssertionError('existing corrupt input must not be replaced')):
                with self.assertRaisesRegex(ValueError,'integrity'):runtime.acquire(item,cache,True)
            self.assertEqual((cache/expected).read_bytes(),b'corrupt previous bytes')

    def uv_archive(self, directory, *, machine=183, extra=None, link=False):
        archive=directory/'uv.tar.gz';header=bytearray(64);header[:6]=b'\x7fELF\x02\x01';struct.pack_into('<H',header,18,machine)
        with tarfile.open(archive,'w:gz') as output:
            root=tarfile.TarInfo('uv-aarch64-unknown-linux-gnu');root.type=tarfile.DIRTYPE;output.addfile(root)
            for name in ('uv','uvx'):
                member=tarfile.TarInfo('uv-aarch64-unknown-linux-gnu/'+name)
                if link and name=='uv': member.type=tarfile.SYMTYPE;member.linkname='/outside';output.addfile(member)
                else: member.size=len(header);output.addfile(member,io.BytesIO(header))
            if extra:
                member=tarfile.TarInfo(extra);member.size=1;output.addfile(member,io.BytesIO(b'x'))
        item={'filename':'uv-aarch64-unknown-linux-gnu.tar.gz','sha256':'sha256:'+runtime.digest(archive),'size':archive.stat().st_size,'url':'https://fixture.invalid/download/0.13.7/uv-aarch64-unknown-linux-gnu.tar.gz'}
        return archive,item

    def test_uv_sdk_is_exact_native_closed_and_read_only(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);archive,item=self.uv_archive(root);output=root/'sdk'
            chmod=Path.chmod
            with patch.object(Path,'chmod',autospec=True,side_effect=chmod) as requested_mode:
                receipt=runtime.copy_uv(archive,item,'0.13.7',output)
            self.assertEqual(receipt['version'],'0.13.7');self.assertEqual([row['path'] for row in receipt['files']],['bin/uv','bin/uvx'])
            for row in receipt['files']:
                file=output/Path(row['path']).name;self.assertEqual(runtime.digest(file),row['sha256'])
                requested_mode.assert_any_call(file,0o555)
                # Windows exposes read-only status, not POSIX executable bits.
                if os.name=='nt':self.assertEqual(file.stat().st_mode&0o222,0);self.assertTrue(file.stat().st_mode&0o400)
                else:self.assertEqual(file.stat().st_mode&0o777,0o555)

    def test_uv_sdk_refuses_changed_archive_wrong_architecture_links_and_foreign_members(self):
        for case in ('digest','size','version','architecture','link','extra','escape'):
            with self.subTest(case=case),tempfile.TemporaryDirectory() as temporary:
                root=Path(temporary);archive,item=self.uv_archive(root,machine=62 if case=='architecture' else 183,link=case=='link',extra='../outside' if case=='escape' else 'foreign' if case=='extra' else None)
                if case=='digest':item['sha256']='sha256:'+'0'*64
                if case=='size':item['size']+=1
                with self.assertRaises(ValueError):runtime.copy_uv(archive,item,'0.13.6' if case=='version' else '0.13.7',root/'sdk')
                self.assertFalse((root/'sdk').exists());self.assertFalse((root/'outside').exists())

    def test_rust_assertion_parser_requires_complete_current_sources_and_one_binary(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);prefix='scripts/quality/rust-assertion-parser/';inventory={}
            for name,content in [('Cargo.toml',b'[package]\nname="fixture"\n'),('Cargo.lock',b'version=4\n'),('src/main.rs',b'mod cfg_regions; fn main(){}\n'),('src/cfg_regions.rs',b'pub fn regions() {}\n')]:
                file=root/prefix/name;file.parent.mkdir(parents=True,exist_ok=True);file.write_bytes(content);inventory[prefix+name]=hashlib.sha256(content).hexdigest()
            receipt={'assertion_parser':{'schema_version':1,'source_inventory':inventory},'files':[{'path':'bin/ud-rust-assertion-parser'}]}
            runtime.verify_assertion_parser_source(receipt,root)
            integration=root/prefix/'tests/protocol.rs';integration.parent.mkdir();integration.write_text('#[test] fn separate_workspace_case(){}\n')
            runtime.verify_assertion_parser_source(receipt,root)
            for changed in [{**receipt,'assertion_parser':{'schema_version':1,'source_inventory':{name:value for name,value in inventory.items()if not name.endswith('/cfg_regions.rs')}}},{**receipt,'files':[]},{**receipt,'files':receipt['files']*2},{**receipt,'assertion_parser':{'schema_version':1,'source_inventory':{prefix+'src/main.rs':inventory[prefix+'src/main.rs']}}}]:
                with self.assertRaises(ValueError):runtime.verify_assertion_parser_source(changed,root)
            (root/prefix/'src/main.rs').write_bytes(b'fn main(){panic!("changed")}\n')
            with self.assertRaisesRegex(ValueError,'source differs'):runtime.verify_assertion_parser_source(receipt,root)

    def source(self, directory):
        source = directory / 'parser'
        (source / 'lib/perl5').mkdir(parents=True)
        content = b'package PPI; our $VERSION="1.291"; 1;\n'
        (source / 'lib/perl5/PPI.pm').write_bytes(content)
        lock = json.loads((ROOT / 'quality/perl-parser.lock.json').read_text())
        receipt = {'lock_sha256': hashlib.sha256(json.dumps(lock, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest(),
                   'parser_release': 'PPI-1.291', 'perl_version': 'v5.44.0',
                   'files': [{'path': 'lib/perl5/PPI.pm', 'sha256': hashlib.sha256(content).hexdigest(), 'size': len(content)}]}
        (source / 'parser-receipt.json').write_text(json.dumps(receipt))
        return source, receipt

    def test_parser_context_copy_preserves_exact_closed_inventory(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            source, receipt = self.source(directory)
            output = directory / 'output'
            observed = runtime.copy_parser(source, output)
            self.assertEqual(observed['files'], 1)
            self.assertEqual(observed['lock_sha256'], receipt['lock_sha256'])
            self.assertEqual((output / 'lib/perl5/PPI.pm').read_bytes(), (source / 'lib/perl5/PPI.pm').read_bytes())
            self.assertEqual((output / 'parser-receipt.json').read_bytes(), (source / 'parser-receipt.json').read_bytes())

    def test_parser_context_rejects_damage_unlisted_members_links_and_duplicate_paths(self):
        for case in ['damage', 'unlisted', 'link', 'duplicate', 'escape', 'wrong-abi']:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                source, receipt = self.source(directory)
                if case == 'damage':
                    (source / 'lib/perl5/PPI.pm').write_bytes(b'damaged')
                elif case == 'unlisted':
                    (source / 'extra').write_bytes(b'extra')
                elif case == 'link':
                    target = source / 'lib/perl5/PPI.pm'
                    target.unlink()
                    target.symlink_to(source / 'parser-receipt.json')
                elif case == 'duplicate':
                    receipt['files'].append(receipt['files'][0])
                elif case == 'escape':
                    receipt['files'][0]['path'] = '../outside'
                else:
                    receipt['perl_version'] = 'v5.34.0'
                (source / 'parser-receipt.json').write_text(json.dumps(receipt))
                with self.assertRaises(ValueError):
                    runtime.copy_parser(source, directory / 'output')
