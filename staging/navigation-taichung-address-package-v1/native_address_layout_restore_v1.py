#!/usr/bin/env python3
"""Portable read-only recipe for reconstructing the stock AP from an update.

The recipe stores metadata, the original small L3 table and allocation tails.
All unchanged map contents come from the candidate; it stores no full backup.
"""
import gzip
import hashlib
import json
import struct

BLOCK = 4096
NAMES = {'00004171.MD2','00004171.MDR','00004171.SRT','I053061A.GMP','I053061A.SRT','MAPSOURC.MPS'}


def require(value, message):
    if not value: raise ValueError(message)


def layout(stream, file_size):
    stream.seek(0); header = stream.read(4096)
    require(len(header)==4096 and header[0]==0 and header[16:23]==b'DSKIMG\0', 'Invalid IMG header')
    require((header[97],header[98],header[64])==(9,3,8), 'Only exact stock 4K allocation supported')
    row=stream.read(512)
    require(len(row)==512 and row[0]==1 and row[16]==3,'Missing root FAT row')
    end=struct.unpack_from('<I',row,12)[0]
    require(4608<=end<=1024*1024 and end%BLOCK==0 and end<=file_size,'Invalid directory span')
    prefix=header+row+stream.read(end-4608)
    require(len(prefix)==end,'Truncated metadata')
    entries={}; used=set(range(end//BLOCK))
    for at in range(4608,end,512):
        r=prefix[at:at+512]
        if r[0]==0:continue
        require(r[0]==1 and r[16]!=3,'Unexpected FAT record')
        name=r[1:9].decode('ascii').rstrip()+'.'+r[9:12].decode('ascii').rstrip()
        require(name in NAMES,'Unexpected stock component')
        size=struct.unpack_from('<I',r,12)[0];part=struct.unpack_from('<H',r,17)[0]
        item=entries.setdefault(name,dict(size=size,blocks=[],parts=0))
        require(part==item['parts'] and (part==0 or size==0),'Component continuation mismatch')
        item['parts']+=1
        slots=struct.unpack_from('<240H',r,32); trailing=False
        for b in slots:
            if b==65535:trailing=True;continue
            require(not trailing and b not in used and (b+1)*BLOCK<=file_size,'Allocation alias/bounds error')
            used.add(b);item['blocks'].append(b)
    require(set(entries)==NAMES,'Incomplete six-component IMG')
    for item in entries.values(): require(len(item['blocks'])==(item['size']+BLOCK-1)//BLOCK,'Allocation count mismatch')
    require(file_size%BLOCK==0,'Unexpected partial final block')
    return dict(prefix=prefix,components=entries,unused_blocks=sorted(set(range(end//BLOCK,file_size//BLOCK))-used))


def logical_read(stream, component, offset, length):
    require(type(offset) is int and type(length) is int and offset>=0 and length>=0 and offset+length<=component['size'], 'Logical range outside component')
    result=[]
    while length:
        index,inside=divmod(offset,BLOCK); count=min(length,BLOCK-inside)
        stream.seek(component['blocks'][index]*BLOCK+inside);raw=stream.read(count)
        require(len(raw)==count,'Truncated logical data')
        result.append(raw);offset+=count;length-=count
    return b''.join(result)


def read_recipe(path):
    with gzip.open(path,'rb') as f: raw=f.read(8*1024*1024+1)
    require(len(raw)<=8*1024*1024,'Recipe JSON exceeds bound')
    recipe=json.loads(raw)
    require(recipe['schema']=='garmin-native-layout-restore/v1','Unsupported recipe')
    return recipe


def restored_blocks(candidate_stream, recipe):
    """Yield the exact original physical file in order; no output is written."""
    require(recipe['schema']=='garmin-native-layout-restore/v1','Unsupported recipe')
    candidate_stream.seek(0,2); size=candidate_stream.tell()
    require(size==recipe['candidate_bytes'],'Candidate size mismatch')
    current=layout(candidate_stream,size)
    expected=recipe['candidate_components']
    require(current['components']==expected,'Candidate FAT differs from bound recipe')
    prefix=bytes.fromhex(recipe['original_prefix_hex'])
    require(len(prefix)==recipe['original_metadata_bytes'],'Original prefix length mismatch')
    components=recipe['original_components']; owners={}
    for name,item in components.items():
        for index,block in enumerate(item['blocks']):
            require(block not in owners,'Original allocation alias');owners[block]=(name,index)
    ranges=recipe['MDR_ranges']; orig_mdr_size=components['00004171.MDR']['size']
    require(sum(r['length']for r in ranges)==orig_mdr_size,'MDR recipe does not cover original')
    def original_component(name,offset,length):
        if name!='00004171.MDR':return logical_read(candidate_stream,current['components'][name],offset,length)
        output=[]; position=0; remaining=length
        for r in ranges:
            stop=position+r['length']
            if offset<stop and remaining:
                inside=offset-position; count=min(remaining,stop-offset)
                if 'original_hex'in r:
                    raw=bytes.fromhex(r['original_hex']);require(len(raw)==r['length'],'Stored range size mismatch')
                    part=raw[inside:inside+count]
                else:part=logical_read(candidate_stream,current['components'][name],r['candidate_offset']+inside,count)
                output.append(part);offset+=count;remaining-=count
            position=stop
        require(remaining==0,'Incomplete MDR reconstruction');return b''.join(output)
    require(recipe['original_bytes']%BLOCK==0,'Original size misaligned')
    for block in range(recipe['original_bytes']//BLOCK):
        if block*BLOCK<len(prefix):raw=prefix[block*BLOCK:(block+1)*BLOCK]
        elif block in owners:
            name,index=owners[block];item=components[name];offset=index*BLOCK
            count=min(BLOCK,item['size']-offset)
            raw=original_component(name,offset,count)
            if count<BLOCK:raw+=bytes.fromhex(recipe['original_tail_hex'][name])
        else:raw=bytes.fromhex(recipe['original_unused_blocks_hex'][str(block)])
        require(len(raw)==BLOCK,'Original block reconstruction has wrong length')
        yield raw


def reconstructed_hash(candidate_stream, recipe):
    digest=hashlib.sha256()
    for block in restored_blocks(candidate_stream,recipe):digest.update(block)
    return digest.hexdigest()
