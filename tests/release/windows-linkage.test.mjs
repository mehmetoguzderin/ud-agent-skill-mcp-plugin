import { test } from 'vitest';
import assert from 'node:assert/strict';
import { OPEN_WINDOWS_PROFILE, OPEN_WINDOWS_TARGETS, verifyOpenWindowsMap, windowsStaticArguments, verifyWindowsBootstrapImports, staticCrtObjectMembers } from '../../scripts/release/windows-linkage.mjs';
test('both retained Windows tuples cross-link static CRT with separate exact map identities',()=>{
  for(const target of ['aarch64-pc-windows-msvc','x86_64-pc-windows-msvc'])for(const binary of ['ud-agent','ud-agent-guard']){const original=['xwin','build','--locked','--offline','--release','--target',target],map='/owned/'+target+'-'+binary+'.map',actual=windowsStaticArguments(original,target,binary,map);assert.deepEqual(actual,['xwin','rustc',...original.slice(2),'--config',`target.${target}.rustflags=["-C","target-feature=+crt-static"]`,'--bin',binary,'--','-C','link-arg=/DEBUG:NONE','-C','link-arg=/Brepro','-C','link-arg=/MAP:'+map]);assert.deepEqual(original,['xwin','build','--locked','--offline','--release','--target',target]);}
  for(const change of [args=>args.filter(value=>value!=='--offline'),args=>args.filter(value=>value!=='--release')])assert.throws(()=>windowsStaticArguments(change(['xwin','build','--locked','--offline','--release','--target','aarch64-pc-windows-msvc']),'aarch64-pc-windows-msvc','ud-agent','/map'));
});
test('bootstrap verification rejects private or debug VC runtime dependencies',()=>{
  assert.deepEqual(verifyWindowsBootstrapImports(['kernel32.dll','ntdll.dll']),{profile:'static-msvc-crt',private_crt_dlls:[],system_imports:['kernel32.dll','ntdll.dll']});
  for(const imports of [[],['vcruntime140.dll'],['vcruntime140_1.dll'],['msvcp140.dll'],['concrt140.dll'],['ucrtbased.dll'],['kernel32.dll','kernel32.dll'],['../kernel32.dll'],['foreign.dll']])assert.throws(()=>verifyWindowsBootstrapImports(imports));
});
test('open-toolchain Windows helpers bind system UCRT and pinned MinGW startup on each architecture', () => {
  const imports = ['api-ms-win-crt-runtime-l1-1-0.dll', 'kernel32.dll', 'winhttp.dll'];
  assert.deepEqual(verifyWindowsBootstrapImports(imports, OPEN_WINDOWS_PROFILE), {
    profile: OPEN_WINDOWS_PROFILE, private_crt_dlls: [], system_imports: imports,
  });
  for (const dll of ['libunwind.dll', 'libwinpthread-1.dll', 'vcruntime140.dll', 'ucrtbased.dll']) {
    assert.throws(() => verifyWindowsBootstrapImports([...imports, dll], OPEN_WINDOWS_PROFILE));
  }
  assert.throws(() => verifyWindowsBootstrapImports(imports.slice(1), OPEN_WINDOWS_PROFILE), /system UCRT/);
  assert.throws(() => verifyWindowsBootstrapImports(imports));
  for (const target of Object.values(OPEN_WINDOWS_TARGETS)) {
    const architecture = target.split('-')[0];
    const map = '00000100 00000001 4 llvm-mingw/' + architecture + '-w64-mingw32/lib/crt2.o:(.text)';
    assert.doesNotThrow(() => verifyOpenWindowsMap(map, 'llvm-mingw', target));
    assert.throws(() => verifyOpenWindowsMap(map.replace('llvm-mingw/', 'other/'), 'llvm-mingw', target), /startup/);
    assert.throws(() => verifyOpenWindowsMap(map + '\nlibcmt.lib:member', 'llvm-mingw', target), /Microsoft static/);
  }
});
test('static object inventory is exact and refuses dynamic/import-profile maps',()=>{
  const text=' 0001:00000000 symbol 0000000140000000 libcmt:D:\\crt\\exe_main.obj\n 0001:00000001 a 0000000140000001 libvcruntime:D:\\crt\\handlers.obj\n 0001:00000002 b 0000000140000002 libucrt:D:\\ucrt\\stdio.obj\n 0001:00000000 alias 0000000140000000 libcmt:D:\\crt\\exe_main.obj\n';
  assert.deepEqual(staticCrtObjectMembers(text),[{library:'libcmt',object:'D:\\crt\\exe_main.obj'},{library:'libucrt',object:'D:\\ucrt\\stdio.obj'},{library:'libvcruntime',object:'D:\\crt\\handlers.obj'}]);assert.throws(()=>staticCrtObjectMembers('none'));assert.throws(()=>staticCrtObjectMembers(text+' 0001:0 c 1400000000 msvcrt:D:\\crt\\dynamic.obj\n'));
});

test('contributing object bytes come from exact bounded COFF archive members',async()=>{
  const {archiveObjectBytes}=await import('../../scripts/release/windows-linkage.mjs');
  const member=(name,data)=>Buffer.concat([Buffer.from(name.padEnd(16)+'0'.padEnd(12)+'0'.padEnd(6)+'0'.padEnd(6)+'100644'.padEnd(8)+String(data.length).padEnd(10)+'`\n'),data,...(data.length%2?[Buffer.from('\n')]:[])]);
  const name='D:\\crt\\startup.obj',table=Buffer.from(name+'\0'),object=Buffer.from('actual object'),archive=Buffer.concat([Buffer.from('!<arch>\n'),member('//',table),member('/0',object)]);
  assert.deepEqual(archiveObjectBytes(archive,[name]),[{member:name,bytes:object}]);
  assert.throws(()=>archiveObjectBytes(archive,[name,name.toUpperCase()]));assert.throws(()=>archiveObjectBytes(archive,['absent.obj']));assert.throws(()=>archiveObjectBytes(archive.subarray(0,-1),[name]));
  assert.throws(()=>archiveObjectBytes(Buffer.concat([archive,member('/0',object)]),[name]),/ambiguous/);
  const broken=Buffer.from(archive);broken.write('99999999  ',8+48);assert.throws(()=>archiveObjectBytes(broken,[name]));
});
