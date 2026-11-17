/** Select only the native host closure, or lazy universal npm metadata. */
export function selectedUserspaceFiles(manifest, target = 'all') {
  const host=target==='all'?undefined:target.replace(/^(darwin|linux|win32)-/,'$1/');
  if(host!==undefined&&!Object.hasOwn(manifest.platforms??{},host))throw new Error('Userspace target is absent from its manifest.');
  const selected=host===undefined?Object.entries(manifest.platforms??{}):[[host,manifest.platforms[host]]];
  if(!selected.length)throw new Error('Userspace platform inventory is empty.');
  const result=new Map();
  for(const[name,platform]of selected){
    if(!Array.isArray(platform.files)||!platform.files.length)throw new Error('Userspace platform has no file inventory.');
    // A universal npm coordinator does not install any userspace core before
    // OCI selection. Its exact chosen host payload is acquired on demand.
    if(host===undefined){if(!platform.lazy_core)throw new Error(`Universal npm requires a verified lazy core transport for ${name}.`);continue;}
    for(const item of platform.files){if(!item||typeof item.path!=='string'||typeof item.sha256!=='string'||!Number.isSafeInteger(item.size)||item.size<0)throw new Error('Userspace file receipt is malformed.');const prior=result.get(item.path);if(prior&&(prior.sha256!==item.sha256||prior.size!==item.size))throw new Error('Userspace platform assets conflict.');result.set(item.path,item);}
  }
  return [...result.values()].sort((left,right)=>left.path.localeCompare(right.path));
}
