/** Copy sealed inputs into a caller-created private temporary fixture only. */
import { chmodSync, constants, copyFileSync, existsSync, lstatSync, mkdirSync, realpathSync, readdirSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';

export function writableFixtureCopy(source, destination, fixtureRoot) {
  // Promise-based realpath uses the native canonicalizer. Use the same one
  // here so Windows short names (RUNNER~1) and expanded caller paths agree.
  const temporary = realpathSync.native(os.tmpdir()), root = realpathSync.native(fixtureRoot), lexicalRoot = path.resolve(fixtureRoot);
  const rootInfo = lstatSync(root), rootRelative = path.relative(temporary, root), relative = path.relative(lexicalRoot, path.resolve(destination));
  if (!rootRelative || path.isAbsolute(rootRelative) || rootRelative.split(path.sep).includes('..') || rootInfo.isSymbolicLink() || !rootInfo.isDirectory() || typeof process.getuid === 'function' && rootInfo.uid !== process.getuid() || !relative || path.isAbsolute(relative) || relative.split(path.sep).includes('..')) throw new Error('Writable fixture copy requires an owned child of TMPDIR.');
  const identity = `${rootInfo.dev}:${rootInfo.ino}`;
  const checkRoot = () => { const info=lstatSync(root); if(!info.isDirectory()||info.isSymbolicLink()||`${info.dev}:${info.ino}`!==identity)throw new Error('Writable fixture root changed.'); };
  let count = 0;
  const target = path.join(root, relative);
  const inputRoot=path.resolve(source), intoSource=path.relative(inputRoot,target);
  if(lstatSync(inputRoot).isDirectory()&&(!intoSource||!path.isAbsolute(intoSource)&&!intoSource.split(path.sep).includes('..')))throw new Error('Writable fixture destination cannot be inside its source.');
  let parent = root;
  for (const part of relative.split(path.sep).slice(0,-1)) {
    parent=path.join(parent,part);
    if(!existsSync(parent))mkdirSync(parent,{mode:0o700});
    const info=lstatSync(parent);if(!info.isDirectory()||info.isSymbolicLink()||typeof process.getuid==='function'&&info.uid!==process.getuid())throw new Error('Writable fixture destination parent is unsafe.');
  }
  if(existsSync(target))throw new Error('Writable fixture destination already exists.');
  const copy = (input, output) => {
    checkRoot();if(++count>100000)throw new Error('Writable fixture inventory exceeds its bound.');
    const info=lstatSync(input);if(info.isSymbolicLink())throw new Error('Writable fixture source contains a symlink.');
    if(info.isDirectory()){mkdirSync(output,{mode:0o700});for(const name of readdirSync(input))copy(path.join(input,name),path.join(output,name));}
    else if(info.isFile()&&info.size<=256*1024*1024){copyFileSync(input,output,constants.COPYFILE_EXCL);chmodSync(output,0o600|(info.mode&0o111?0o100:0));}
    else throw new Error('Writable fixture source is not a bounded ordinary file.');
  };
  copy(path.resolve(source),target);checkRoot();
}
