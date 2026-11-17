/** Explicit host-only source derivation of the immutable image loader.
 * No production fallback or /opt write is introduced. Actual /opt admission
 * remains a separate protected OCI acceptance check.
 */
import {createHash}from'node:crypto';import{createRequire}from'node:module';import{mkdirSync,readFileSync,writeFileSync,symlinkSync,chmodSync}from'node:fs';import path from'node:path';
const sha=value=>createHash('sha256').update(value).digest('hex');
export function prepareNativeAssertionFixture(root){
 const runtime=path.join(root,'native-assertion-runtime'),harness=path.join(runtime,'harness'),require=createRequire(import.meta.url);mkdirSync(harness,{recursive:true,mode:0o700});
 symlinkSync(path.dirname(path.dirname(require.resolve('vitest/package.json'))),path.join(runtime,'node_modules'),'dir');
 const derivations=[];for(const name of ['stryker-assertions.mjs','stryker-assertion-sdk.mjs','stryker-opacity.mjs','stryker-native-assertions.cjs','stryker-assertion-setup.mjs']){
  const original=readFileSync(path.resolve('scripts/quality',name));let derived=original;
  if(name==='stryker-native-assertions.cjs'){
   const text=original.toString();if(text.split("const ROOT='/opt/mutation/harness';").length!==2||text.split('const OWNER=0n;').length!==2)throw Error('Native loader test derivation source changed.');
   derived=Buffer.from(text.replace("const ROOT='/opt/mutation/harness';",'const ROOT='+JSON.stringify(harness)+';').replace('const OWNER=0n;','const OWNER='+String(process.getuid?.()??0)+'n;'));
  }else if(name==='stryker-assertion-setup.mjs'){
   const from="'/opt/mutation/harness/stryker-native-assertions.cjs'";if(original.toString().split(from).length!==2)throw Error('Native setup test derivation source changed.');derived=Buffer.from(original.toString().replace(from,JSON.stringify(path.join(harness,'stryker-native-assertions.cjs'))));
  }
  writeFileSync(path.join(harness,name),derived,{flag:'wx',mode:0o444});derivations.push({path:name,original_sha256:sha(original),derived_sha256:sha(derived),test_only:!derived.equals(original)});
 }
 writeFileSync(path.join(runtime,'input-receipt.json'),JSON.stringify({qualification:'explicit-owned-host-test-derivation-not-OCI-authority',harness:derivations.map(row=>({path:row.path,sha256:row.derived_sha256}))}),{flag:'wx',mode:0o444});
 return{runtime,harness,setup:path.join(harness,'stryker-assertion-setup.mjs'),loader:path.join(harness,'stryker-native-assertions.cjs'),captureModule:path.join(harness,'stryker-assertions.mjs'),derivations};
}
