/** Windows helper bootstrap closure. Cross-linking never executes target code. */
import assert from 'node:assert/strict';
export const OPEN_WINDOWS_PROFILE = 'llvm-mingw-ucrt';
export const OPEN_WINDOWS_TARGETS = Object.freeze({
  'win32-arm64': 'aarch64-pc-windows-gnullvm',
  'win32-x64': 'x86_64-pc-windows-gnullvm',
});

export function windowsStaticArguments(args,target,binary,map){
  assert.ok(['aarch64-pc-windows-msvc','x86_64-pc-windows-msvc'].includes(target));assert.ok(['ud-agent','ud-agent-guard'].includes(binary));
  assert.equal(args[0],'xwin');assert.equal(args[1],'build');assert.ok(args.includes('--locked')&&args.includes('--offline')&&args.includes('--release')&&args[args.indexOf('--target')+1]===target);assert.ok(typeof map==='string'&&map.length>0&&!/[\0\r\n]/.test(map));
  return['xwin','rustc',...args.slice(2),'--config',`target.${target}.rustflags=["-C","target-feature=+crt-static"]`,'--bin',binary,'--','-C','link-arg=/DEBUG:NONE','-C','link-arg=/Brepro','-C','link-arg=/MAP:'+map];
}
export function verifyWindowsBootstrapImports(imports, profile = 'static-msvc-crt'){
  assert.ok(['static-msvc-crt', OPEN_WINDOWS_PROFILE].includes(profile), 'Unknown Windows helper linkage');
  assert.ok(Array.isArray(imports)&&imports.length>0&&new Set(imports).size===imports.length);
  const systemUcrt = /^(?:ucrtbase|api-ms-win-crt-[a-z0-9-]+)\.dll$/;
  for(const name of imports){
    assert.match(name,/^[a-z0-9_.-]+\.dll$/);
    assert.ok(!/^(?:vcruntime|msvcp|concrt|vcomp|msvcr)[0-9_a-z]*\.dll$/.test(name),'Windows launcher/helper still requires a private VC runtime DLL: '+name);
    assert.ok(!/^(?:ucrtbased|vcruntime[0-9_]*d|msvcp[0-9_]*d)\.dll$/.test(name),'Debug CRT cannot be a shipped prerequisite');
    const system = /^(?:api-ms-win-core-[a-z0-9-]+|kernel32|ntdll|advapi32|combase|ktmw32|ole32)\.dll$/.test(name);
    const openSystem = profile === OPEN_WINDOWS_PROFILE && (systemUcrt.test(name) || ['shell32.dll', 'winhttp.dll'].includes(name));
    assert.ok(system || openSystem,'Unclassified native helper DLL dependency: '+name);
  }
  if (profile === OPEN_WINDOWS_PROFILE) assert.ok(imports.some(name => systemUcrt.test(name)), 'Windows open-toolchain build does not use the system UCRT');
  return{profile,private_crt_dlls:[],system_imports:imports};
}

export function verifyOpenWindowsMap(text, toolchain, target) {
  assert.ok(Object.values(OPEN_WINDOWS_TARGETS).includes(target));
  assert.ok(!/\b(?:libcmt|libcpmt|libvcruntime|libucrt|vcruntime|msvcprt)\.lib\b/i.test(text), 'Unexpected Microsoft static library in open Windows link map');
  const startup = `${toolchain}/${target.split('-')[0]}-w64-mingw32/lib/crt2.o:(`;
  assert.ok(text.includes(startup), 'Windows link map is missing pinned MinGW startup code');
}
export function staticCrtObjectMembers(text){
  assert.equal(typeof text,'string');const objects=new Map();
  for(const line of text.split(/\r?\n/)){const match=/\s((?:libcmt|libucrt|libvcruntime|msvcrt|vcruntime|ucrt|libcpmt|msvcprt|oldnames|legacy_stdio_definitions)):(.+\.obj)\s*$/i.exec(line);if(match){const library=match[1].toLowerCase(),object=match[2];assert.ok(!/[\0\r\n]/.test(object));objects.set(library+'\0'+object,{library,object});}}
  assert.ok(objects.size>0,'Link map does not identify any CRT startup/runtime object members');
  const rows=[...objects.values()].sort((a,b)=>a.library<b.library?-1:a.library>b.library?1:a.object<b.object?-1:a.object>b.object?1:0);
  assert.ok(rows.some(row=>row.library==='libcmt'),'Static CRT startup library was not identified');
  assert.ok(!rows.some(row=>['msvcrt','vcruntime','ucrt','msvcprt'].includes(row.library)),'Dynamic CRT object/import profile remains in the static helper map');return rows;
}

/** Parse only data from COFF archives; member paths are labels, never host paths. */
export function archiveObjectBytes(bytes,names){
  assert.ok(Buffer.isBuffer(bytes)&&bytes.length<=256*1024**2&&bytes.subarray(0,8).toString()==='!<arch>\n','Invalid bounded COFF library');assert.ok(Array.isArray(names)&&names.length>0&&new Set(names.map(name=>name.toLowerCase())).size===names.length);
  const raw=[];let offset=8,table;
  while(offset<bytes.length){assert.ok(offset+60<=bytes.length,'Truncated COFF archive header');const header=bytes.subarray(offset,offset+60);assert.equal(header.subarray(58,60).toString(),'`\n');const sizeText=header.subarray(48,58).toString().trim();assert.match(sizeText,/^[0-9]+$/);const size=Number(sizeText);assert.ok(Number.isSafeInteger(size)&&size<=64*1024**2&&offset+60+size<=bytes.length,'Truncated/oversized COFF archive member');const name=header.subarray(0,16).toString().trim(),data=bytes.subarray(offset+60,offset+60+size);if(name==='//'){assert.equal(table,undefined,'Duplicate COFF long-name table');table=data;}else raw.push({name,data});offset+=60+size;if(size%2){assert.ok(offset<bytes.length&&bytes[offset]===10,'Invalid COFF archive padding');offset++;}}
  assert.equal(offset,bytes.length);const found=new Map(names.map(name=>[name.toLowerCase(),[]]));
  for(const entry of raw){let name=entry.name;if(/^\/[0-9]+$/.test(name)){const start=Number(name.slice(1));assert.ok(table&&Number.isSafeInteger(start)&&start<table.length,'Invalid COFF long-name reference');const zero=table.indexOf(0,start),newline=table.indexOf('\n',start),end=zero<0?newline:newline<0?zero:Math.min(zero,newline);assert.ok(end>=start,'Unterminated COFF long name');name=table.subarray(start,end).toString('utf8').replace(/\/$/,'');}else name=name.replace(/\/$/,'');const selected=found.get(name.toLowerCase());if(selected)selected.push({member:name,bytes:entry.data});}
  return names.map(name=>{const matches=found.get(name.toLowerCase());assert.equal(matches.length,1,'Contributing CRT object is missing or ambiguous in its exact library: '+name);return matches[0];});
}
