"""Bounded ELF64 dependency inspection; no external ELF tool or ambient lookup."""
import struct


def inspect(data):
    if len(data)<64 or data[:6]!=b'\x7fELF\x02\x01':raise ValueError('expected little-endian ELF64')
    machine=struct.unpack_from('<H',data,18)[0]
    offset=struct.unpack_from('<Q',data,32)[0];size,count=struct.unpack_from('<HH',data,54)
    if size!=56 or not 1<=count<=256 or offset+size*count>len(data):raise ValueError('invalid ELF program headers')
    loads=[];dynamic=None;interpreter=None
    for index in range(count):
        kind,flags,file_offset,address,physical,file_size,memory_size,alignment=struct.unpack_from('<IIQQQQQQ',data,offset+index*size)
        if file_offset+file_size>len(data):raise ValueError('ELF segment exceeds file')
        if kind==1:loads.append((address,file_offset,file_size))
        if kind==2:
            if dynamic is not None or file_size%16:raise ValueError('invalid ELF dynamic segment')
            dynamic=(file_offset,file_size)
        if kind==3:
            if interpreter is not None or not 1<=file_size<=4096:raise ValueError('invalid ELF interpreter')
            raw=data[file_offset:file_offset+file_size]
            if raw[-1:]!=b'\0' or b'\0' in raw[:-1]:raise ValueError('invalid ELF interpreter string')
            interpreter=raw[:-1].decode('ascii')
    needed=[];paths=[];strings=None;string_size=None
    if dynamic:
        entries=[]
        for cursor in range(dynamic[0],dynamic[0]+dynamic[1],16):
            kind,value=struct.unpack_from('<qQ',data,cursor)
            if kind==0:break
            entries.append((kind,value))
            if kind==5:strings=value
            if kind==10:string_size=value
        if strings is None or string_size is None or string_size>16*1024*1024:raise ValueError('ELF dynamic strings are unavailable')
        mapped=[file_offset+strings-address for address,file_offset,length in loads if address<=strings and strings+string_size<=address+length]
        if len(mapped)!=1:raise ValueError('ELF dynamic strings are not uniquely mapped')
        table=data[mapped[0]:mapped[0]+string_size]
        for kind,value in entries:
            if kind not in (1,15,29):continue
            if value>=len(table):raise ValueError('ELF dynamic string exceeds bounds')
            end=table.find(b'\0',value)
            if end<0:raise ValueError('ELF dynamic string is unterminated')
            text=table[value:end].decode('ascii')
            (needed if kind==1 else paths).append(text)
    return {'machine':machine,'interpreter':interpreter,'needed':needed,'search_paths':paths}


def without_search_paths(data):
    """Remove only RPATH/RUNPATH dynamic entries without resizing an ELF file.

    Build-prefix paths are unsuitable for a relocatable private runtime. Keep
    every other dynamic entry byte-for-byte and leave unused string bytes
    untouched; closure admission subsequently resolves all DT_NEEDED names.
    """
    before=inspect(data)
    if not before['search_paths']:
        return data
    result=bytearray(data)
    offset=struct.unpack_from('<Q',data,32)[0]
    size,count=struct.unpack_from('<HH',data,54)
    for index in range(count):
        kind,_,file_offset,_,_,file_size,_,_=struct.unpack_from('<IIQQQQQQ',data,offset+index*size)
        if kind!=2:
            continue
        kept=[]
        for cursor in range(file_offset,file_offset+file_size,16):
            tag,_=struct.unpack_from('<qQ',data,cursor)
            if tag==0:
                break
            if tag not in (15,29):
                kept.append(data[cursor:cursor+16])
        replacement=b''.join(kept)
        result[file_offset:file_offset+file_size]=replacement+b'\0'*(file_size-len(replacement))
    after=inspect(result)
    if after!={**before,'search_paths':[]} or len(result)!=len(data):
        raise ValueError('ELF search-path removal changed its dependency contract')
    return bytes(result)


def with_interpreter(data,interpreter):
    """Append one bounded PT_INTERP pathname without moving executable segments."""
    if not isinstance(interpreter,str) or not interpreter.startswith('/') or '\0' in interpreter or '..' in interpreter.split('/'):
        raise ValueError('ELF interpreter must be a confined absolute pathname')
    encoded=interpreter.encode('utf-8')+b'\0'
    if len(encoded)>4096:raise ValueError('ELF interpreter exceeds kernel pathname limit')
    before=inspect(data)
    if before['interpreter'] is None:raise ValueError('ELF executable has no interpreter')
    result=bytearray(data)
    offset=struct.unpack_from('<Q',data,32)[0];size,count=struct.unpack_from('<HH',data,54)
    for index in range(count):
        cursor=offset+index*size
        if struct.unpack_from('<I',data,cursor)[0]==3:
            struct.pack_into('<Q',result,cursor+8,len(data))
            struct.pack_into('<QQ',result,cursor+32,len(encoded),len(encoded))
            break
    result+=encoded
    after=inspect(result)
    if after!={**before,'interpreter':interpreter}:raise ValueError('ELF interpreter rewrite changed its dependency contract')
    return bytes(result)
