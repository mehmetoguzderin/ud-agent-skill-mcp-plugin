'use strict';
/** Fixed native Node loader. Vite's transformed module cache must never own
 * the capture maps used by the frozen SDK recorder and serializer. */
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),{pathToFileURL}=require('node:url');
const ROOT='/opt/mutation/harness';
const OWNER=0n;
if(__dirname!==ROOT||fs.realpathSync(ROOT)!==ROOT)throw new Error('Native assertion loader is outside its immutable runtime.');
const directory=fs.lstatSync(ROOT,{bigint:true});if(!directory.isDirectory()||directory.isSymbolicLink()||directory.uid!==OWNER||(directory.mode&0o022n)!==0n)throw new Error('Native assertion loader directory is not immutable authority.');
function read(filename,limit){const fd=fs.openSync(filename,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);try{const before=fs.fstatSync(fd,{bigint:true}),named=fs.lstatSync(filename,{bigint:true});if(!before.isFile()||before.uid!==OWNER||before.nlink!==1n||(before.mode&0o222n)!==0n||before.size>BigInt(limit)||named.isSymbolicLink()||named.dev!==before.dev||named.ino!==before.ino)throw new Error('Native assertion source is not an immutable ordinary file.');const bytes=fs.readFileSync(fd),after=fs.fstatSync(fd,{bigint:true});if(before.size!==after.size||before.mtimeNs!==after.mtimeNs||before.ctimeNs!==after.ctimeNs||BigInt(bytes.length)!==before.size)throw new Error('Native assertion source changed during verification.');return bytes;}finally{fs.closeSync(fd);}}
const receipt=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(read(path.join(path.dirname(ROOT),'input-receipt.json'),16*1024**2))),matches=Array.isArray(receipt.harness)?receipt.harness.filter(item=>item.path==='stryker-assertions.mjs'):[];
if(matches.length!==1||!/^[a-f0-9]{64}$/.test(matches[0].sha256??''))throw new Error('Native assertion source has no unique immutable harness receipt.');
const filename=ROOT+'/stryker-assertions.mjs',bytes=read(filename,16*1024**2);
if(crypto.createHash('sha256').update(bytes).digest('hex')!==matches[0].sha256)throw new Error('Native assertion source differs from its immutable receipt.');
module.exports=import(pathToFileURL(filename).href);
