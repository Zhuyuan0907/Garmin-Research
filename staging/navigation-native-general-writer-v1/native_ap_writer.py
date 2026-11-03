#!/usr/bin/env python3
"""Offline primitives for exact XOR0/4096-byte-block AP containers.

No CLI writes a real IMG. Callers must provide streams and explicit replacement
components. This does not update MDR offsets, JAI, labels or route databases.
"""
from dataclasses import dataclass
import hashlib
from pathlib import Path
import re
import struct
from typing import BinaryIO, Callable, Iterable

BLOCK = 4096
ROW = 512
BLOCKS_PER_ROW = 240
AP_NAMES = ('00004171.MD2','00004171.MDR','00004171.SRT',
            'I053061A.GMP','I053061A.SRT','MAPSOURC.MPS')
NAME_RE = re.compile(r'[A-Z0-9_]{1,8}\.[A-Z0-9_]{3}\Z')


def require(ok,message):
    if not ok: raise ValueError(message)


def integer(value,name,minimum=0,maximum=0xffffffff):
    require(type(value) is int and minimum <= value <= maximum,name+' out of finite range')
    return value


def align(value,unit): return (value+unit-1)//unit*unit


@dataclass(frozen=True)
class SelectedRange:
    one_based_street_ID: int
    first_child: int
    count: int


@dataclass(frozen=True)
class ReencodedL3:
    table: bytes
    old_record_count: int
    old_span_bytes: int
    old_unused_tail_bits: int
    old_unused_tail_value: int
    explicit_changes: tuple[SelectedRange,...]
    # The caller must provide these bytes outside its directory-declared span.
    reader_lookahead: bytes = bytes(4)


def rewrite_l3_width23(old_table, *, record_count=47870, selected_ranges=(), child_table_count=None):
    """111-bit original L3→112-bit width23; preserve every other record bit.

    The original111-bit record is [map1,primary19,first22,count12,flags9,
    coord24,coord24]. The new high first-child bit is bit42. Explicit changes
    name existing1-based street IDs and may alter only first/count. Unused old
    tail bits are preserved in the result metadata, never treated as a record.
    """
    integer(record_count,'record_count',1,0x0fffffff)
    require(isinstance(old_table,(bytes,bytearray,memoryview)),'old_table must be bytes-like')
    required = (record_count*111+7)//8
    require(len(old_table) == required,'Old111-bit source span length differs')
    changes = tuple(selected_ranges)
    seen = set()
    if changes:
        integer(child_table_count,'Explicit child_table_count',1,0x7fffff)
    elif child_table_count is not None:
        integer(child_table_count,'child_table_count',1,0x7fffff)
    for change in changes:
        require(type(change) is SelectedRange,'Only SelectedRange(first,count) changes accepted')
        ID = integer(change.one_based_street_ID,'selected streetID',1,record_count)
        require(ID not in seen,'Duplicate selected streetID')
        seen.add(ID)
        integer(change.first_child,'23-bit first_child',0,0x7fffff)
        integer(change.count,'12-bit child count',0,0xfff)
        if change.count:
            require(change.first_child >= 1 and change.first_child+change.count-1 <= child_table_count,
                    'Selected child range exceeds explicit table count')
        else:
            require(change.first_child == 0,'Empty selected range must have first0')
    selected = {c.one_based_street_ID:c for c in changes}
    output = bytearray(record_count*14)
    low42 = (1<<42)-1
    recordmask = (1<<111)-1
    range_mask = ((1<<35)-1)<<20
    for ordinal in range(record_count):
        bit = ordinal*111
        start,initial = divmod(bit,8)
        length = (initial+111+7)//8
        record = (int.from_bytes(old_table[start:start+length],'little')>>initial)&recordmask
        expanded = (record&low42)|((record>>42)<<43)
        change = selected.get(ordinal+1)
        if change:
            require(((record>>54)&7) == 4,
                    'Selected L4 range requires original next_level4; other child tables remain unchanged')
            expanded = (expanded&~range_mask)|(change.first_child<<20)|(change.count<<43)
        output[ordinal*14:(ordinal+1)*14] = expanded.to_bytes(14,'little')
    used = record_count*111%8
    unused = 0 if used == 0 else 8-used
    tail = 0 if unused == 0 else old_table[-1]>>used
    return ReencodedL3(bytes(output),record_count,required,unused,tail,changes)


@dataclass(frozen=True)
class Component:
    name: str
    size: int
    blocks: tuple[int,...]
    rows: tuple[bytes,...]


class StreamIMG:
    """Validate/read allocation metadata, then stream selected logical ranges.

    Construction reads the small header/FAT only. Entire component data is
    never retained by this reader; every physical read is logged.
    """
    def __init__(self,stream: BinaryIO, *, required_names=AP_NAMES):
        self.stream = stream
        self.read_log = []
        stream.seek(0,2)
        self.size = stream.tell()
        require(self.size > 0 and self.size%BLOCK == 0,'Input IMG must have whole4K blocks')
        self.header = self.physical(0,512,'header')
        h = self.header
        require(h[0] == 0 and h[16:23] == b'DSKIMG\0' and h[65:72] == b'GARMIN\0',
                'Only DSKIMG XOR0 containers supported')
        require(h[510:512] == b'\x55\xaa','Invalid header end marker')
        require((h[97]+h[98]) == 12,'Only4096-byte allocation blocks supported')
        blocks = struct.unpack_from('<H',h,0x63)[0]
        sectors = struct.unpack_from('<I',h,0x1ca)[0]
        require(0 < blocks < 0xffff and sectors > 0,'Unsupported declared-capacity sentinel/zero')
        self.capacity = min(blocks*BLOCK,sectors*512)
        require(self.size <= self.capacity,'Input exceeds its original declared container capacity')
        self.directory_start = h[0x40]*512
        require(512 <= self.directory_start < self.size,'Invalid directory-start sector')
        self.prefix = h+self.physical(512,self.directory_start-512,'metadata_prefix')
        self.root_row = self.physical(self.directory_start,512,'root_directory_entry')
        root = self.root_row
        require(root[0] == 1 and root[16] == 3 and root[1:12] == b' '*11,
                'Unsupported metadata directory row')
        require(struct.unpack_from('<H',root,17)[0] == 0,'Multiple root continuation rows unsupported')
        self.directory_end = struct.unpack_from('<I',root,12)[0]
        require(self.directory_start+512 <= self.directory_end <= self.size and self.directory_end%512 == 0,
                'Invalid root directory extent')
        directory = root+self.physical(self.directory_start+512,self.directory_end-self.directory_start-512,'directory_rows')
        root_blocks = self._blocks(root)
        self.metadata_blocks = tuple(range((self.directory_end+BLOCK-1)//BLOCK))
        require(root_blocks == self.metadata_blocks,'Root allocation must cover header/directory extent exactly')
        owner = {b:'<metadata>' for b in root_blocks}
        parts = {}
        order = []
        current = None
        for offset in range(512,len(directory),512):
            row = directory[offset:offset+512]
            if row[0] == 0:
                require(row == bytes(512),'Nonzero unused directory rows unsupported')
                continue
            require(row[0] == 1 and row[16] != 3,'Unexpected directory marker/root continuation')
            name = row[1:9].decode('ascii').rstrip(' ')+'.'+row[9:12].decode('ascii').rstrip(' ')
            require(NAME_RE.fullmatch(name) is not None,'Invalid/noncanonical component path')
            part = struct.unpack_from('<H',row,17)[0]
            length = struct.unpack_from('<I',row,12)[0]
            if part == 0:
                require(name not in parts,'Duplicate component path')
                require(length > 0,'Empty components unsupported')
                parts[name] = dict(size=length,rows=[],blocks=[])
                order.append(name)
                current = name
            require(name == current and part == len(parts[name]['rows']),'Unordered/duplicate FAT continuation')
            require(part == 0 or length == 0,'Continuation row has nonzero logical size')
            allocated = self._blocks(row)
            require(allocated,'Empty FAT continuation unsupported')
            for block in allocated:
                require(block not in owner,'Repeated/overlapping allocated block')
                owner[block] = name
            parts[name]['blocks'].extend(allocated)
            parts[name]['rows'].append(row)
        require(len(order) == len(set(required_names)) and set(order) == set(required_names),
                'Expected exact six AP component paths')
        self.order = tuple(order)
        self.components = {}
        for name in order:
            item = parts[name]
            require(len(item['blocks']) == (item['size']+BLOCK-1)//BLOCK,'Component block count differs from size')
            require(len(item['rows']) == (len(item['blocks'])+239)//240,'Component FAT row count differs')
            self.components[name] = Component(name,item['size'],tuple(item['blocks']),tuple(item['rows']))

    def _blocks(self,row):
        blocks,padding = [],False
        for block in struct.unpack_from('<240H',row,32):
            if block == 0xffff: padding = True
            else:
                require(not padding,'Allocated block afterFFFF padding')
                require(block < self.size//BLOCK,'Allocated block outside input file')
                blocks.append(block)
        return tuple(blocks)

    def physical(self,offset,length,purpose):
        require(0 <= offset <= offset+length <= self.size,'Read outside physical IMG')
        self.stream.seek(offset)
        raw = self.stream.read(length)
        require(len(raw) == length,'Short physical IMG read')
        self.read_log.append(dict(offset=offset,bytes=length,purpose=purpose))
        return raw

    def iter_component(self,name, *, offset=0,length=None,chunk_bytes=65536):
        require(name in self.components,'Unknown component path')
        c = self.components[name]
        length = c.size-offset if length is None else length
        integer(offset,'Logical offset')
        integer(length,'Logical length')
        integer(chunk_bytes,'Chunk size',1,1024*1024)
        require(offset+length <= c.size,'Read outside logical component')
        cursor = offset
        pending = bytearray()
        while cursor < offset+length:
            index,within = divmod(cursor,BLOCK)
            count = min(offset+length-cursor,BLOCK-within,chunk_bytes-len(pending))
            pending.extend(self.physical(c.blocks[index]*BLOCK+within,count,'logical:'+name))
            cursor += count
            if len(pending) == chunk_bytes:
                yield bytes(pending)
                pending.clear()
        if pending: yield bytes(pending)


@dataclass(frozen=True)
class Replacement:
    size: int
    chunks: Callable[[],Iterable[bytes]]

    @classmethod
    def from_bytes(cls,data):
        require(isinstance(data,bytes),'Replacement data must be immutable bytes')
        return cls(len(data),lambda:iter((data,)))


def plan_repack(source:StreamIMG,replacement_sizes):
    require(set(replacement_sizes) <= set(source.order),'Unknown/duplicate replacement path')
    sizes = {name:replacement_sizes.get(name,source.components[name].size) for name in source.order}
    for name,length in sizes.items():integer(length,'Component size:'+name,1)
    counts = {name:(length+BLOCK-1)//BLOCK for name,length in sizes.items()}
    rows = 1+sum((n+239)//240 for n in counts.values())
    end = align(max(source.directory_end,source.directory_start+rows*512),BLOCK)
    metadata_blocks = end//BLOCK
    require(metadata_blocks <= 240,'Root directory requires unsupported continuation')
    total_blocks = metadata_blocks+sum(counts.values())
    image_bytes = total_blocks*BLOCK
    require(total_blocks <= 65535 and image_bytes <= source.capacity,
            'Output exceeds original declared container capacity; geometry expansion not implemented')
    allocations = {}
    cursor = metadata_blocks
    for name in source.order:
        allocations[name] = tuple(range(cursor,cursor+counts[name]))
        cursor += counts[name]
    return dict(sizes=sizes,counts=counts,rows=rows,directory_end=end,metadata_blocks=metadata_blocks,
                allocations=allocations,image_bytes=image_bytes,original_declared_capacity=source.capacity)


def _write(stream,data):
    view = memoryview(data)
    while view:
        written = stream.write(view)
        require(type(written) is int and 0 < written <= len(view),'Short/invalid output write')
        view = view[written:]


def _dir_row(template,name,length,part,blocks,flag=None):
    row = bytearray(template)
    require(len(row) == 512 and len(blocks) <= 240,'Invalid directory template/table')
    base,ext = name.split('.')
    row[0] = 1
    row[1:9] = base.encode('ascii').ljust(8,b' ')
    row[9:12] = ext.encode('ascii').ljust(3,b' ')
    struct.pack_into('<I',row,12,length if part == 0 else 0)
    if flag is not None:row[16] = flag
    struct.pack_into('<H',row,17,part)
    struct.pack_into('<240H',row,32,*(list(blocks)+[65535]*(240-len(blocks))))
    return bytes(row)


def repack_stream(source:StreamIMG,destination:BinaryIO,replacements):
    """Stream a newly allocated container; preserve untouched logical contents.

    Caller owns destination cleanup if a replacement fails/shortens. Complete
    containers are accepted only after successful return. The original header
    capacity/geometry and prefix bytes are kept exactly. No original path can
    be mutated through this API; destination must be distinct and empty.
    """
    require(destination is not source.stream,'Source/destination stream alias')
    try:
        import os
        a,b = os.fstat(source.stream.fileno()),os.fstat(destination.fileno())
        require((a.st_dev,a.st_ino) != (b.st_dev,b.st_ino),'Source/destination inode alias')
    except (AttributeError,OSError):pass
    require(all(type(r) is Replacement and callable(r.chunks) for r in replacements.values()),'Invalid replacement source')
    plan = plan_repack(source,{k:v.size for k,v in replacements.items()})
    destination.seek(0,2)
    require(destination.tell() == 0,'Destination must be a new empty stream')
    _write(destination,source.prefix)
    root = _dir_row(source.root_row,'.',plan['directory_end'],0,tuple(range(plan['metadata_blocks'])),flag=3)
    _write(destination,root)
    for name in source.order:
        c = source.components[name]
        allocated = plan['allocations'][name]
        for part,first in enumerate(range(0,len(allocated),240)):
            template = c.rows[min(part,len(c.rows)-1)]
            _write(destination,_dir_row(template,name,plan['sizes'][name],part,allocated[first:first+240]))
    _write(destination,bytes(plan['directory_end']-destination.tell()))
    receipts = []
    for name in source.order:
        expected = plan['sizes'][name]
        chunks = replacements[name].chunks() if name in replacements else source.iter_component(name)
        digest,count = hashlib.sha256(),0
        for chunk in chunks:
            require(isinstance(chunk,(bytes,bytearray,memoryview)) and len(chunk) > 0,'Replacement must yield nonempty byte chunks')
            require(count+len(chunk) <= expected,'Replacement exceeds declared size')
            _write(destination,chunk)
            digest.update(chunk)
            count += len(chunk)
        require(count == expected,'Replacement ended before declared size')
        padding = (-count)%BLOCK
        if padding:_write(destination,bytes(padding))
        receipts.append(dict(name=name,bytes=count,sha256=digest.hexdigest(),replaced=name in replacements,
                             parts=(len(plan['allocations'][name])+239)//240,tail_padding_bytes=padding))
    require(destination.tell() == plan['image_bytes'],'Output allocation length differs')
    destination.truncate(plan['image_bytes'])
    return dict(image_bytes=plan['image_bytes'],directory_end=plan['directory_end'],directory_rows=plan['rows'],
                original_declared_capacity=plan['original_declared_capacity'],header_prefix_unchanged=True,
                new_part_metadata_template='samepart if present, otherwise last original continuation',components=receipts)


def repack_new_path(source_path,destination_path,replacements):
    """Explicit new-path wrapper; source must already have been backed up.

    This module has no CLI/default output path. Existing destinations or any
    destination sharing the source inode are rejected before opening for write.
    """
    source_path,destination_path = Path(source_path),Path(destination_path)
    require(source_path.resolve() != destination_path.resolve(),'Duplicate source/destination path')
    require(not destination_path.exists(),'Destination path must not already exist')
    with source_path.open('rb') as source_file:
        source = StreamIMG(source_file)
        plan_repack(source,{k:v.size for k,v in replacements.items()})
        created_identity = None
        try:
            import os
            with destination_path.open('xb') as output:
                s = os.fstat(output.fileno())
                created_identity = (s.st_dev,s.st_ino)
                return repack_stream(source,output,replacements)
        except BaseException:
            # This exclusively created path is not a completed candidate.
            if created_identity is not None:
                try:
                    s = destination_path.lstat()
                    if (s.st_dev,s.st_ino) == created_identity:
                        destination_path.unlink()
                except FileNotFoundError:pass
            raise
