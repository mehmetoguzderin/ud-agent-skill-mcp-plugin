/** Private MiniCPM generation attribution. No model imports or inference. MIT. */
import { execFileSync } from 'node:child_process';

// Python owns the server's canonical JSON representation and its integer
// nanosecond timestamps. Do not approximate either with JavaScript numbers.
const COLLECT = String.raw`
import hashlib,json,math,os,re,stat,sys

def unique_pairs(pairs):
    result={}
    for key,value in pairs:
        if key in result: raise ValueError('DUPLICATE_JSON_KEY')
        result[key]=value
    return result

def reject_constant(_value): raise ValueError('NONFINITE_JSON')
def parse(value): return json.loads(value,object_pairs_hook=unique_pairs,parse_constant=reject_constant)
def integer(value): return isinstance(value,int) and not isinstance(value,bool)
def canonical(value): return json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def unknown(request,reason,**extra):
    return {'type':'backend_generation_observation','request_id':request.get('id'),'status':'unknown','reason':reason,**extra}
def safe_failure(value):
    if value is None: return None
    # Preserve parser/error codes, not arbitrary generated strings or secrets.
    if isinstance(value,str) and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*:[A-Z][A-Z0-9_]{0,179}',value): return value
    return '[private failure detail retained in receipt]'

payload=parse(sys.stdin.read())
requests=payload['requests']
window=payload['window']
try:
    start,end=int(window['started_at_ns']),int(window['ended_before_ns'])
    if start<0 or end<=start: raise ValueError()
    model=payload['model_path']
    directory=payload['directory']
    if not isinstance(model,str) or not model or not isinstance(directory,str) or not os.path.isabs(directory): raise ValueError()
except (KeyError,TypeError,ValueError):
    print(json.dumps({'status':'unknown','observations':[unknown(r,'GENERATION_BINDING_INVALID') for r in requests],'receipts':[]}));sys.exit(0)

receipts=[];scan_error=None
try:
    directory_info=os.lstat(directory)
    if not stat.S_ISDIR(directory_info.st_mode) or directory_info.st_uid!=os.getuid() or directory_info.st_mode&0o077 or os.path.realpath(directory)!=directory:
        raise ValueError('PRIVATE_GENERATION_DIRECTORY_UNTRUSTED')
    entries=list(os.scandir(directory))
    if len(entries)>10000: raise ValueError('PRIVATE_GENERATION_DIRECTORY_TOO_LARGE')
    for entry in entries:
        if not entry.name.endswith('.json'): continue
        if not re.fullmatch(r'[a-f0-9]{32}\.json',entry.name): raise ValueError('PRIVATE_GENERATION_RECEIPT_NAME_INVALID')
        filename=os.path.join(directory,entry.name)
        descriptor=os.open(filename,os.O_RDONLY|os.O_NOFOLLOW)
        try:
            before=os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode) or before.st_uid!=os.getuid() or before.st_mode&0o077 or before.st_nlink!=1 or not 0<before.st_size<=2*1024*1024:
                raise ValueError('PRIVATE_GENERATION_RECEIPT_UNTRUSTED')
            chunks=[];total=0
            while True:
                chunk=os.read(descriptor,65536)
                if not chunk: break
                total+=len(chunk)
                if total>2*1024*1024: raise ValueError('PRIVATE_GENERATION_RECEIPT_TOO_LARGE')
                chunks.append(chunk)
            after=os.fstat(descriptor)
            if (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns):
                raise ValueError('PRIVATE_GENERATION_RECEIPT_CHANGED')
            # Confirm that the path still designates the owned file we opened.
            current=os.lstat(filename)
            if not stat.S_ISREG(current.st_mode) or (before.st_dev,before.st_ino)!=(current.st_dev,current.st_ino):
                raise ValueError('PRIVATE_GENERATION_RECEIPT_CHANGED')
        finally: os.close(descriptor)
        raw=b''.join(chunks);record=parse(raw)
        if not isinstance(record,dict) or record.get('schema_version')!=1:
            raise ValueError('PRIVATE_GENERATION_RECEIPT_SCHEMA_INVALID')
        for name in ('started_at_ns','recorded_at_ns','seed','prompt_tokens','completion_tokens','maximum_tokens'):
            if not integer(record.get(name)): raise ValueError('PRIVATE_GENERATION_RECEIPT_SCHEMA_INVALID')
        ids=record.get('token_ids')
        if (not isinstance(ids,list) or len(ids)!=record['completion_tokens'] or any(not integer(token) or not 0<=token<=0x7fffffff for token in ids)
            or not 0<=record['completion_tokens']<=record['maximum_tokens']<=512 or record['maximum_tokens']<1
            or record['prompt_tokens']<0 or not 0<=record['seed']<=0xffffffff
            or record['started_at_ns']<0 or record['recorded_at_ns']<record['started_at_ns']
            or not isinstance(record.get('request_sha256'),str) or not re.fullmatch(r'[a-f0-9]{64}',record['request_sha256'])
            or not isinstance(record.get('model'),str) or not isinstance(record.get('text'),str)
            or record.get('termination') not in ('eos','length','stopped','cancelled','deadline')
            or record.get('parser_status') not in ('accepted','rejected','not_attempted') or not isinstance(record.get('dispatch_eligible'),bool)):
            raise ValueError('PRIVATE_GENERATION_RECEIPT_SCHEMA_INVALID')
        if (record['parser_status']!='accepted' and (record['dispatch_eligible'] or not isinstance(record.get('failure'),str))
            or record['parser_status']=='not_attempted' and record['termination'] not in ('cancelled','deadline')
            or record['termination'] in ('cancelled','deadline') and record['dispatch_eligible']):
            raise ValueError('PRIVATE_GENERATION_RECEIPT_SCHEMA_INVALID')
        receipts.append({'path':filename,'sha256':hashlib.sha256(raw).hexdigest(),'record':record})
except FileNotFoundError: scan_error='PRIVATE_GENERATION_DIRECTORY_OR_RECEIPT_MISSING'
except (OSError,TypeError,ValueError,UnicodeError): scan_error='PRIVATE_GENERATION_RECEIPT_UNTRUSTED_OR_INVALID'

hashes={}
for request in requests:
    try:
        body=request['body']
        request['canonical_sha256']=hashlib.sha256(canonical(body)).hexdigest()
        hashes[request['canonical_sha256']]=hashes.get(request['canonical_sha256'],0)+1
    except (KeyError,TypeError,ValueError,UnicodeError): pass

observations=[];linked=[]
for request in requests:
    identity=request.get('canonical_sha256')
    if request.get('reason'):
        observations.append(unknown(request,request['reason']));continue
    if scan_error:
        observations.append(unknown(request,scan_error,**({'request_sha256':identity} if identity else {})));continue
    try:
        body=request['body'];seed=body.get('seed',17);limits=[body[key] for key in ('max_tokens','max_completion_tokens') if key in body]
        maximum=limits[0] if limits else 512
        if (not isinstance(body,dict) or body.get('model')!=model or not isinstance(body.get('messages'),list)
            or not integer(seed) or not 0<=seed<=0xffffffff or not integer(maximum) or not 1<=maximum<=512
            or len(set(limits))>1 or not integer(request.get('prompt_tokens')) or request['prompt_tokens']<0 or identity is None):
            raise ValueError()
    except (AttributeError,KeyError,TypeError,ValueError):
        observations.append(unknown(request,'GENERATION_REQUEST_BINDING_INVALID'));continue
    if hashes[identity]!=1:
        observations.append(unknown(request,'GENERATION_REQUEST_HASH_AMBIGUOUS',request_sha256=identity));continue
    same_hash=[item for item in receipts if item['record']['request_sha256']==identity]
    matches=[item for item in same_hash if start<=item['record']['started_at_ns']<=item['record']['recorded_at_ns']<end]
    if len(matches)!=1:
        reason='GENERATION_RECEIPT_AMBIGUOUS' if len(matches)>1 else 'GENERATION_RECEIPT_OUTSIDE_UNIT_WINDOW' if same_hash else 'GENERATION_RECEIPT_MISSING'
        observations.append(unknown(request,reason,request_sha256=identity));continue
    receipt=matches[0];record=receipt['record']
    if record['model']!=model or record['seed']!=seed or record['prompt_tokens']!=request['prompt_tokens'] or record['maximum_tokens']!=maximum:
        observations.append(unknown(request,'GENERATION_RECEIPT_BINDING_MISMATCH',request_sha256=identity));continue
    link={'path':receipt['path'],'sha256':receipt['sha256']}
    observations.append({'type':'backend_generation_observation','request_id':request['id'],'status':'observed',
        'method':'private-minicpm-generation-receipt-v1','request_sha256':identity,'receipt':link,
        'generated_tokens':record['completion_tokens'],'maximum_tokens':record['maximum_tokens'],
        'prompt_tokens':record['prompt_tokens'],'seed':record['seed'],'termination':record['termination'],
        'parser_status':record['parser_status'],'dispatch_eligible':record['dispatch_eligible'],
        'failure':safe_failure(record.get('failure')),'started_at_ns':str(record['started_at_ns']),
        'recorded_at_ns':str(record['recorded_at_ns'])})
    linked.append(link)
status='not_requested' if not observations else 'observed' if all(item['status']=='observed' for item in observations) else 'unknown'
print(json.dumps({'status':status,'observations':observations,'receipts':linked},allow_nan=False))
`;

const object = value => value && typeof value === 'object' && !Array.isArray(value);
const unknown = (id, reason) => ({ type: 'backend_generation_observation', request_id: id, status: 'unknown', reason });

function requestsFromEvents(events) {
  return events.filter(event => event?.type === 'upstream_request').map(event => {
    const id = event.id;
    if (typeof id !== 'string' || !id || events.filter(other => other?.type === 'upstream_request' && other.id === id).length !== 1) return { id, reason: 'GENERATION_REQUEST_ID_AMBIGUOUS' };
    const translations = events.filter(other => other?.type === 'translation_request' && other.id === id);
    const counts = events.filter(other => other?.type === 'token_accounting' && other.id === id);
    if (translations.length > 1) return { id, reason: 'GENERATION_BACKEND_REQUEST_AMBIGUOUS' };
    const body = translations.length ? translations[0].backend : event.protocol === 'chat' ? event.body : undefined;
    if (!object(body) || !Array.isArray(body.messages)) return { id, reason: 'GENERATION_BACKEND_CHAT_REQUEST_MISSING' };
    if (counts.length !== 1 || counts[0].tokens?.trusted !== true || !Number.isSafeInteger(counts[0].tokens.inputTokens)) return { id, reason: 'GENERATION_PROMPT_COUNT_UNVERIFIED' };
    return { id, body, prompt_tokens: counts[0].tokens.inputTokens };
  });
}

/** Returned summaries are engine evidence only; never add them to agent input.
 * Conservatively exclude the uncertain boundary milliseconds: Date.now() does
 * not locate a unit's start/end within that millisecond. Boundary matches stay
 * unknown instead of attributing a preceding or following unit's generation. */
export async function collectGenerationEvidence({ events, evidenceDirectory, modelPath, startedAtMs, endedAtMs, python = 'python3' }) {
  if (!Array.isArray(events)) throw new Error('GENERATION_EVENTS_REQUIRED');
  const requests = requestsFromEvents(events);
  if (!requests.length) return { status: 'not_requested', observations: [], receipts: [] };
  const unknownAll = reason => ({ status: 'unknown', observations: requests.map(request => unknown(request.id, reason)), receipts: [] });
  if (!['linux', 'darwin'].includes(process.platform)) return unknownAll('GENERATION_PLATFORM_UNSUPPORTED');
  if (![startedAtMs, endedAtMs].every(value => Number.isSafeInteger(value) && value >= 0) || endedAtMs - startedAtMs < 2 || requests.length > 10) return unknownAll('GENERATION_UNIT_WINDOW_INVALID');
  const input = JSON.stringify({ requests, directory: evidenceDirectory, model_path: modelPath,
    window: { started_at_ns: String((BigInt(startedAtMs) + 1n) * 1_000_000n), ended_before_ns: String(BigInt(endedAtMs) * 1_000_000n) } });
  if (Buffer.byteLength(input) > 16 * 1024 * 1024) return unknownAll('GENERATION_INPUT_TOO_LARGE');
  try {
    const result = JSON.parse(execFileSync(python, ['-I', '-B', '-c', COLLECT], { input, encoding: 'utf8', timeout: 10_000, maxBuffer: 2 * 1024 * 1024, windowsHide: true }));
    if (!['observed', 'unknown', 'not_requested'].includes(result.status) || !Array.isArray(result.observations) || result.observations.length !== requests.length || !Array.isArray(result.receipts)) return unknownAll('GENERATION_COLLECTOR_OUTPUT_INVALID');
    return result;
  } catch {
    return unknownAll('GENERATION_COLLECTOR_UNAVAILABLE');
  }
}

/** Partial observations must not become a fabricated zero or complete usage. */
export function summarizeGenerationEvidence(result) {
  const rows = result?.observations ?? [], observed = rows.filter(row => row.status === 'observed');
  return { status: result?.status ?? 'unknown', requests: rows.length, observed_requests: observed.length, unknown_requests: rows.length - observed.length,
    generated_tokens: result?.status === 'observed' && observed.length ? observed.reduce((sum, row) => sum + row.generated_tokens, 0) : null,
    known_generated_tokens: observed.length ? observed.reduce((sum, row) => sum + row.generated_tokens, 0) : null,
    parser_rejections: observed.length ? observed.filter(row => row.parser_status === 'rejected').length : null,
    termination_counts: observed.length ? observed.reduce((counts, row) => { counts[row.termination] = (counts[row.termination] ?? 0) + 1; return counts; }, {}) : null };
}
