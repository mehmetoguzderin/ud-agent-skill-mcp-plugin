/** Equivalent exceptions require an exact independently reviewed definition. */
import {createHash}from'node:crypto';import{canonicalJson}from'../release/http-transports.mjs';
const sha=value=>createHash('sha256').update(value).digest('hex');
export function reviewedEquivalent({exceptions,used,tool,id,file,hashes,definition,readReview}){
 const fingerprint=definition?sha(canonicalJson(definition)):undefined;
 const item=exceptions.find(entry=>entry.tool===tool&&entry.file===file&&entry.definition_sha256===fingerprint);
 if(!item||item.file!==file||hashes[file]!==item.source_sha256||!definition||sha(canonicalJson(definition))!==item.definition_sha256||item.author===item.reviewed_by||typeof item.proof!=='string'||item.proof.length<40||typeof item.review?.path!=='string'||!item.review.path.startsWith('quality/reviews/')||item.review.path.split('/').some(part=>['','.','..'].includes(part))||hashes[item.review.path]!==item.review.sha256||typeof readReview!=='function')return false;
 try{const bytes=readReview(item.review.path);if(sha(bytes)!==item.review.sha256)return false;const review=JSON.parse(bytes.toString('utf8'));const exact=review.reviews?.find(entry=>entry.id===item.id);if(review.reviewer!==item.reviewed_by||exact?.equivalent!==true||exact.source_sha256!==item.source_sha256||exact.definition_sha256!==item.definition_sha256||exact.reason!==item.proof||canonicalJson(exact.definition)!==canonicalJson(definition))return false;}catch{return false;}
 used.add(`${tool}\0${item.id}`);return true;
}
