#!/usr/bin/env python3
"""Offline exact AP4K to AP8K streaming container primitive.

Only allocation/container geometry changes. MDR internals are caller-owned.
The six known AP names are fixed. No CLI, default output, firmware/USB access,
map compilation, header-checksum acceptance, or full-update claim is provided.
"""
from dataclasses import dataclass
import hashlib
import importlib.util
import os
from pathlib import Path
import struct
import sys
from collections.abc import Mapping
from typing import Callable, Iterable

ROOT = Path(__file__).resolve().parents[2]
BASE = ROOT/'staging/navigation-native-general-writer-v1/native_ap_writer.py'
_spec = importlib.util.spec_from_file_location('_frozen_ap4k_container_only', BASE)
_base = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = _base
_spec.loader.exec_module(_base)
# Reuse only the previously tested container parser. Never call its withdrawn
# L3 encoding or table functions; this module does not know MDR table offsets.
AP_NAMES = _base.AP_NAMES
SOURCE_BLOCK = 4096
BLOCK = 8192
CAPACITY = 268435456
MDR = '00004171.MDR'
ROW = 512


def need(ok, message):
    if not ok: raise ValueError(message)


def finite(v, label, low=0, high=0xffffffff):
    need(type(v) is int and low <= v <= high, label+' outside finite range')
    return v


def align(v, n): return (v+n-1)//n*n


def nonallocation_metadata(row):
    """Status/name/flag and unknown13 bytes; omit size/part/allocation table."""
    need(len(row)==ROW, 'Invalid row length')
    return row[:12]+row[16:17]+row[19:32]


class Source4K(_base.StreamIMG):
    def __init__(self, stream):
        super().__init__(stream, required_names=AP_NAMES)
        h=self.header
        need(h[0x61]==9 and h[0x62]==3, 'Expected exact 9+3 AP4K exponents')
        need(self.directory_start==4096, 'Expected AP directory-start sector8')
        need(struct.unpack_from('<H',h,0x18)[0]==16 and struct.unpack_from('<H',h,0x5f)[0]==16,
             'Expected AP16 sectors/track profile')
        need(struct.unpack_from('<H',h,0x63)[0]==32768 and struct.unpack_from('<I',h,0x1ca)[0]==262144,
             'Expected AP134MiB declared-capacity profile')
        need(self.order==AP_NAMES, 'Expected exact stock six AP component order')
        # Reblocking can reduce continuation count. Distinct unknown metadata
        # in discarded rows would not be preservable: reject instead of lose it.
        for c in self.components.values():
            need(all(nonallocation_metadata(r)==nonallocation_metadata(c.rows[0]) for r in c.rows),
                 'Nonuniform continuation metadata cannot be losslessly reblocked: '+c.name)


@dataclass(frozen=True)
class Replacement:
    size: int
    chunks: Callable[[], Iterable[bytes]]


def replacements_dict(entries):
    if isinstance(entries, Mapping): pairs=list(entries.items())
    else:
        try:pairs=list(entries)
        except TypeError:raise ValueError('Replacement entries must be mapping or name/value pairs')
    result={}
    for pair in pairs:
        need(isinstance(pair,(list,tuple)) and len(pair)==2, 'Invalid replacement pair')
        name,value=pair
        need(name==MDR, 'Only explicit MDR replacement is supported')
        need(name not in result, 'Duplicate MDR replacement')
        need(type(value) is Replacement and callable(value.chunks), 'Invalid replacement supplier')
        finite(value.size, 'MDR replacement size',1)
        result[name]=value
    return result


def plan_repack(source, replacements=()):
    need(type(source) is Source4K, 'Expected validated Source4K')
    values=replacements_dict(replacements)
    sizes={name:values[name].size if name in values else source.components[name].size for name in source.order}
    counts={name:(finite(length,'Component size',1)+BLOCK-1)//BLOCK for name,length in sizes.items()}
    rows=1+sum((n+239)//240 for n in counts.values())
    end=align(max(source.directory_end,source.directory_start+rows*ROW), BLOCK)
    metadata_blocks=end//BLOCK
    need(metadata_blocks<=240, 'Root allocation requires unsupported continuation')
    blocks=metadata_blocks+sum(counts.values())
    need(blocks<=32768 and blocks*BLOCK<=CAPACITY, 'Output exceeds explicit AP8K268MiB profile capacity')
    need(blocks<=65535, 'Block numbers would reach reserved uint16FFFF sentinel')
    allocations={};cursor=metadata_blocks
    for name in source.order:
        allocations[name]=tuple(range(cursor,cursor+counts[name]));cursor+=counts[name]
    return {'sizes':sizes,'counts':counts,'rows':rows,'directory_end':end,'metadata_blocks':metadata_blocks,
            'allocations':allocations,'image_bytes':blocks*BLOCK,'output_declared_capacity':CAPACITY,
            'source_declared_capacity':source.capacity}


def _row(template, name, size, part, blocks, root=False):
    need(len(template)==ROW and 0<len(blocks)<=240, 'Invalid FAT row or block count')
    finite(part,'FAT part',0,65535)
    need(all(type(b) is int and 0<=b<65535 for b in blocks), 'Invalid/reserved uint16 block number')
    row=bytearray(template)
    # Existing exact canonical names and all nonallocation metadata retained.
    expected=(name.split('.')[0].encode().ljust(8,b' ')+name.split('.')[1].encode().ljust(3,b' '))
    need(row[1:12]==expected, 'Template name differs')
    row[0]=1
    struct.pack_into('<I',row,12,size if part==0 else 0)
    struct.pack_into('<H',row,17,part)
    if root:need(row[16]==3,'Root template must retain special flag3')
    struct.pack_into('<240H',row,32,*(list(blocks)+[65535]*(240-len(blocks))))
    return bytes(row)


def _write(stream, raw):
    view=memoryview(raw)
    while view:
        n=stream.write(view)
        need(type(n) is int and 0<n<=len(view), 'Output write stalled/returned invalid count')
        view=view[n:]


def _header(h):
    new=bytearray(h)
    new[0x0f]=0  # Official mkgmap creates zero; real AP checksum rule unknown.
    struct.pack_into('<H',new,0x18,32)
    struct.pack_into('<H',new,0x5f,32)
    new[0x62]=4
    struct.pack_into('<I',new,0x1ca,524288)
    allowed={0x0f,0x18,0x19,0x5f,0x60,0x62,0x1ca,0x1cb,0x1cc,0x1cd}
    need(all(a==b or i in allowed for i,(a,b) in enumerate(zip(h,new))), 'Unexpected header change')
    need(struct.unpack_from('<H',new,0x63)[0]==32768, 'Block capacity count changed')
    return bytes(new)


def repack_stream(source, destination, replacements=()):
    """Return only for a complete stream. Caller cleans partial stream on error.

    Supplier chunks are bounded at1MiB. Untouched components use source4K
    logical reads<=64KiB, stream continuously into allocated8K extents, then
    pad only each component tail with zero. No whole component is retained.
    """
    values=replacements_dict(replacements);plan=plan_repack(source,values)
    need(destination is not source.stream, 'Source/destination stream alias')
    try:
        a,b=os.fstat(source.stream.fileno()),os.fstat(destination.fileno())
        need((a.st_dev,a.st_ino)!=(b.st_dev,b.st_ino), 'Source/destination inode alias')
    except (AttributeError,OSError):pass
    destination.seek(0,2);need(destination.tell()==0, 'Output stream must be new and empty')
    newheader=_header(source.header)
    _write(destination,newheader);_write(destination,source.prefix[512:])
    _write(destination,_row(source.root_row,'.',plan['directory_end'],0,tuple(range(plan['metadata_blocks'])),root=True))
    for name in source.order:
        c=source.components[name];allocated=plan['allocations'][name]
        for part,start in enumerate(range(0,len(allocated),240)):
            _write(destination,_row(c.rows[min(part,len(c.rows)-1)],name,plan['sizes'][name],part,allocated[start:start+240]))
    need(destination.tell()<=plan['directory_end'], 'FAT rows overflow metadata extent')
    _write(destination,bytes(plan['directory_end']-destination.tell()))
    receipts=[]
    for name in source.order:
        expected=plan['sizes'][name]
        chunks=values[name].chunks() if name in values else source.iter_component(name,chunk_bytes=65536)
        count=0;digest=hashlib.sha256();maxchunk=0
        for chunk in chunks:
            need(isinstance(chunk,(bytes,bytearray,memoryview)), 'Supplier chunks must be bytes-like')
            need(chunk and len(chunk)<=1048576, 'Supplier chunk empty or exceeds1MiB bound')
            need(count+len(chunk)<=expected, 'Supplier exceeds declared MDR size')
            _write(destination,chunk);digest.update(chunk);count+=len(chunk);maxchunk=max(maxchunk,len(chunk))
        need(count==expected, 'Supplier ended before declared MDR size')
        padding=(-count)%BLOCK
        if padding:_write(destination,bytes(padding))
        receipts.append({'name':name,'bytes':count,'sha256':digest.hexdigest(),'replacement':name in values,
                         'output_FAT_parts':(plan['counts'][name]+239)//240,'tail_padding_bytes':padding,
                         'max_chunk_bytes':maxchunk,'nonallocation_metadata_preserved':True})
    need(destination.tell()==plan['image_bytes'], 'Output length differs from allocation plan')
    destination.truncate(plan['image_bytes'])
    return {'image_bytes':plan['image_bytes'],'directory_end':plan['directory_end'],'directory_rows':plan['rows'],
            'source_block':SOURCE_BLOCK,'output_block':BLOCK,'output_declared_capacity':CAPACITY,
            'changed_header_byte_offsets':[i for i,(a,b) in enumerate(zip(source.header,newheader)) if a!=b],
            'prefix_512_to_dirStart_unchanged':True,'root_nonallocation_metadata_preserved':True,
            'components':receipts,'header_checksum_rule_known':False,'header_checksum_byte15_set_zero':True,
            'device_acceptance_verified':False,'MDR_internal_offsets_updated_here':False,'full_Taiwan_updated':False}


def repack_new_path(source_path, destination_path, replacements=()):
    source_path,destination_path=Path(source_path),Path(destination_path)
    values=replacements_dict(replacements)
    need(source_path.resolve()!=destination_path.resolve(), 'Duplicate source/destination path')
    need(not destination_path.exists() and not destination_path.is_symlink(), 'Output path already exists or is symlink')
    identity=None
    with source_path.open('rb') as f:
        source=Source4K(f);plan_repack(source,values)
        try:
            with destination_path.open('xb') as out:
                s=os.fstat(out.fileno());identity=(s.st_dev,s.st_ino)
                result=repack_stream(source,out,values);out.flush();os.fsync(out.fileno());return result
        except BaseException:
            if identity is not None:
                try:
                    s=destination_path.lstat()
                    if (s.st_dev,s.st_ino)==identity:destination_path.unlink()
                except FileNotFoundError:pass
            raise
