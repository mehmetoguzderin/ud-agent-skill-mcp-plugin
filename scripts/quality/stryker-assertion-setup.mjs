/** Fixed read-only setup runs before project tests and captures pre-rewrite errors. */
import { createRequire } from 'node:module';
const { exportCompiledSources, installStrykerAssertionCapture } = await createRequire(import.meta.url)('/opt/mutation/harness/stryker-native-assertions.cjs');
import { aroundAll, aroundEach, inject } from 'vitest';
import path from 'node:path';
import { createSubprocessOpacityRecorder, installSubprocessOpacityCapture } from './stryker-opacity.mjs';
const context=inject('ud_agent_assertion_context_v1');
if(context?.schema_version!==1||context.source_root!==process.cwd()||!context.source_inventory||!['dry-run','selection-baseline','mutant'].includes(context.kind))throw new Error('Fixed assertion setup has no controller-bound original source inventory.');
await installStrykerAssertionCapture({sourceRoot:context.source_root,sourceInventory:context.source_inventory});
const recorder=createSubprocessOpacityRecorder(),opacity=installSubprocessOpacityCapture(recorder);
aroundEach(async (runTest, { task }) => {
  if(task.concurrent===true)recorder.markNativeUncertainty('concurrent-test-attribution');
  return opacity.runScope({kind:'case',id:task.id},runTest);
});
aroundAll(async (runSuite, {}, suite) => {
  const file=suite.file??suite,filename=file.filepath,relative=typeof filename==='string'?path.relative(process.cwd(),filename).split(path.sep).join('/'):null;
  const scope=relative?.startsWith('tests/')&&!relative.split('/').some(part=>!part||part==='.'||part==='..')?{kind:'file',path:relative}:{kind:'global'};
  try{return await opacity.runScope(scope,runSuite);}finally{
    if(suite===file){
      try{
        file.meta.ud_agent_subprocess_opacity_v1=opacity.snapshot();
        file.meta.ud_agent_compiled_sources_v1=exportCompiledSources({includeSources:context.kind==='dry-run',sourceRoot:context.source_root,sourceInventory:context.source_inventory});
      }finally{opacity.restore();}
    }
  }
});
