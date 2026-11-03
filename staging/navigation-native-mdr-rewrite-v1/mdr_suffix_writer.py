#!/usr/bin/env python3
"""Stock-profile MDR append/widen primitive; no default output or device CLI."""
from dataclasses import dataclass
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import sys
from typing import Callable, Iterable

ROOT = Path('/root/garmin')
SEALED_WRITER = ROOT/'staging/navigation-native-general-writer-v1/native_ap_writer.py'
SEALED_SHA = 'cb190d5f3c70f0e81e9d49808dff044e4717b5061f749e7720af56aee39b0cf8'
CORRECTED_PROOF = ROOT/'staging/navigation-native-general-writer-corrected-source-v2/corrected-original-L3-writer-source-proof-v2.json'
CORRECTED_SHA = '24de01f169b8933d93fb1e7381d700eb3877925d1b333859616af4f72807d3df'
if hashlib.sha256(SEALED_WRITER.read_bytes()).hexdigest() != SEALED_SHA:
    raise ValueError('Requires unchanged sealed AP primitive')
_proof_bytes = CORRECTED_PROOF.read_bytes()
if hashlib.sha256(_proof_bytes).hexdigest() != CORRECTED_SHA:
    raise ValueError('Requires unchanged corrected original source proof')
_stock_binding = json.loads(_proof_bytes)['source']
_name = 'garmin_sealed_ap_primitive_v1'
if _name not in sys.modules:
    _spec = importlib.util.spec_from_file_location(_name,SEALED_WRITER)
    _module = importlib.util.module_from_spec(_spec)
    sys.modules[_name] = _module
    _spec.loader.exec_module(_module)
core = sys.modules[_name]
SelectedRange = core.SelectedRange

PROFILE = [
    (122,[16,9,24,19,1,10,0,0],[1,1]),
    (122,[16,9,24,19,1,10,0,0],[1,1]),
    (111,[22,9,24,19,1,12,0,0],[1,0]),
    (128,[22,9,24,19,1,10,0,0],[1,1]),
    (126,[21,9,24,19,1,9,0,0],[1,1]),
    (68,[0,0,24,19,1,0,0,0],[1,0]),
]
STOCK_COUNTS = [22,343,47870,2133948,2341096,1973316]
ORIGINAL_CAPACITY = 134217728


def need(ok,message):
    if not ok:raise ValueError(message)


def uint(value,name,maximum=0xffffffff):
    need(type(value) is int and 0 <= value <= maximum,name+' outside finite unsigned range')
    return value


def bounded_chunk(raw,context):
    need(isinstance(raw,(bytes,bytearray,memoryview)),context+' chunk must contain bytes')
    length = raw.nbytes if isinstance(raw,memoryview) else len(raw)
    need(0 < length <= 65536,context+' chunk must be nonempty bytes, at most64KiB')
    return bytes(raw)


@dataclass(frozen=True)
class MDRSource:
    size: int
    read_range: Callable[[int,int],bytes]
    range_supplier: Callable[[int,int],Iterable[bytes]]
    unchanged: Callable[[],bool] = lambda:True
    capacity_plan: Callable[[int],dict] | None = None

    @classmethod
    def from_container(cls,container):
        c = container.components['00004171.MDR']
        s = os.fstat(container.stream.fileno())
        identity = (s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
        def unchanged():
            t = os.fstat(container.stream.fileno())
            return identity == (t.st_dev,t.st_ino,t.st_size,t.st_mtime_ns,t.st_ctime_ns)
        def read(offset,length):
            return b''.join(container.iter_component(c.name,offset=offset,length=length))
        def chunks(offset,length):
            return container.iter_component(c.name,offset=offset,length=length)
        def capacity(length):
            return core.plan_repack(container,{c.name:length})
        return cls(c.size,read,chunks,unchanged,capacity)

    def exact(self,offset,length):
        uint(offset,'sourceoffset');uint(length,'sourcelength')
        need(offset+length <= self.size,'Source range exceeds declared MDR component')
        data = self.read_range(offset,length)
        need(isinstance(data,bytes) and len(data) == length,'Source callback returned wrong byte type/count')
        return data

    def chunks(self,offset,length):
        uint(offset,'sourceoffset');uint(length,'sourcelength')
        need(offset+length <= self.size,'Source range exceeds declared MDR component')
        result = self.range_supplier(offset,length)
        need(not isinstance(result,(bytes,bytearray,str)),'Source supplier must return an iterable of chunks')
        count = 0
        for raw in result:
            chunk = bounded_chunk(raw,'Source')
            need(count+len(chunk) <= length,'Source supplier exceeds declared range')
            count += len(chunk)
            yield chunk
        need(count == length,'Source supplier truncated declared range')


@dataclass(frozen=True)
class MDRPlan:
    source: MDRSource
    header: bytes
    directory: bytes
    table: bytes
    table_lookahead: bytes
    old_tables: tuple[dict,...]
    new_tables: tuple[dict,...]
    original_directory_start: int
    new_directory_start: int
    size: int
    append_count: int
    append_supplier: Callable[[],Iterable[bytes]]
    selected_ranges: tuple
    report: dict

    def _appended_chunks(self):
        result = self.append_supplier()
        need(not isinstance(result,(bytes,bytearray,str)),'Append supplier must yield byte chunks')
        expected = self.append_count*16
        total,pending,records = 0,b'',0
        for raw in result:
            chunk = bounded_chunk(raw,'Append')
            need(total+len(chunk) <= expected,'Append stream exceeds explicit record count')
            total += len(chunk)
            joined = pending+chunk
            complete = len(joined)//16*16
            for at in range(0,complete,16):
                need(joined[at]&1 == 1,'Appended record requires existing AP mapordinal1')
                records += 1
            pending = joined[complete:]
            yield chunk
        need(total == expected and not pending and records == self.append_count,
             'Append stream truncated or does not contain exact16-byte records')

    def chunks(self):
        """Yield a full replacement MDR stream, never an IMG container.

        L3 is followed immediately by real L2 bytes; no lookahead insertion.
        Failed/partial streams cannot be treated as completed replacements.
        """
        need(self.source.unchanged() is True,'MDR source changed since planning')
        old4,old2 = self.old_tables[3],self.old_tables[1]
        yield self.header
        yield from self.source.chunks(772,old4['start']+old4['bytes']-772)
        yield from self._appended_chunks()
        for offset in range(0,len(self.table),65536):yield self.table[offset:offset+65536]
        prefix = bytearray()
        for chunk in self.source.chunks(old2['start'],self.original_directory_start-old2['start']):
            if len(prefix) < 4:
                prefix.extend(chunk[:4-len(prefix)])
                if len(prefix) == 4:need(bytes(prefix) == self.table_lookahead,'L2 lookahead changed after planning')
            yield chunk
        need(bytes(prefix) == self.table_lookahead,'Missing actual L2 lookahead')
        yield self.directory
        need(self.source.unchanged() is True,'MDR source changed during streaming')

    def replacement(self):
        return core.Replacement(self.size,self.chunks)


def _decoded(raw):
    start,size,stride,w,x = struct.unpack('<5I',raw)
    need(stride > 0,'Zero directory stride')
    widths = [(w>>18)&63,(w>>24)&63,(w>>12)&63,(w>>6)&63,w&63,x&63,(x>>11)&63,(x>>17)&63]
    flags = [(w>>30)&1,(w>>31)&1]
    return dict(start=start,bytes=size,stride=stride,count=size*8//stride,widths=widths,flags=flags)


def plan_mdr_rewrite(source, *, new_l4_count, new_l4_supplier, selected_ranges=(), synthetic_fixture=False):
    """Derive/validate original source profile, then plan append+widen suffix.

    Production inputs must match the original stock counts/size and profile.
    The explicitly marked small-fixture mode permits counts≤16 for tests only.
    """
    need(type(source) is MDRSource,'Requires explicit MDRSource callbacks')
    need(callable(source.read_range) and callable(source.range_supplier) and callable(source.unchanged),
         'Requires callable bounded/streamed source callbacks')
    need(source.capacity_plan is None or callable(source.capacity_plan),'Capacity planner must be callable')
    uint(source.size,'MDR component size')
    uint(new_l4_count,'newL4count',0x7fffff)
    need(callable(new_l4_supplier),'Append supplier must be callable')
    need(type(synthetic_fixture) is bool,'Synthetic fixture marker must be bool')
    need(source.unchanged() is True,'Source changed before planning')
    header = bytearray(source.exact(0,772))
    need(struct.unpack_from('<H',header)[0] == 772 and header[2:12] == b'GARMIN MDR',
         'Only original772-byte MDR header supported')
    dstart,dbytes,itembytes,dflags = struct.unpack_from('<4I',header,600)
    need((dbytes,itembytes,dflags) == (120,20,1),'Only original six-entry20-byte descriptor supported')
    need(dstart+120 == source.size,'Directory must end exactly at MDR component EOF')
    directory = bytearray(source.exact(dstart,120))
    tables = [_decoded(directory[i*20:(i+1)*20]) for i in range(6)]
    for index,(table,(stride,widths,flags)) in enumerate(zip(tables,PROFILE)):
        need((table['stride'],table['widths'],table['flags']) == (stride,widths,flags),
             'Source is not stock original profile at level'+str(index+1))
        need(table['count'] > 0 and table['bytes'] > 0,'Empty original table unsupported')
        need(table['bytes'] == (table['count']*table['stride']+7)//8,'Directory contains extra nonrecord bytes')
        need(772 <= table['start'] < table['start']+table['bytes'] <= dstart,'Table outside original suffix')
    sequence = [tables[i] for i in [5,4,3,2,1,0]]
    for a,b in zip(sequence,sequence[1:]):
        need(a['start']+a['bytes'] == b['start'],'Original physical table sequence/gap is unsupported')
    need(tables[0]['start']+tables[0]['bytes'] == dstart,'Level1 does not end at directory')
    if synthetic_fixture:
        need(source.size <= 16384 and all(t['count'] <= 16 for t in tables),'Synthetic mode limited to small fixtures')
    else:
        need(source.size == 92653600 and [t['count'] for t in tables] == STOCK_COUNTS,
             'Production source must be exact original stock-count profile, not a prior candidate')
        need(bytes(directory).hex() == _stock_binding['directory_hex'],
             'Production directory differs from sealed corrected original source')
        need(callable(source.capacity_plan),'Production requires container capacity planner')
    new_l4_total = tables[3]['count']+new_l4_count
    need(new_l4_total <= 0x7fffff,'NewL4 range exceeds23-bit first-child profile')
    l3bytes = tables[2]['count']*14
    addedbytes = new_l4_count*16
    delta = addedbytes+l3bytes-tables[2]['bytes']
    size = source.size+delta
    uint(size,'NewMDR logical size')
    capacity = source.capacity_plan(size) if source.capacity_plan else None
    if source.capacity_plan:
        need(isinstance(capacity,dict),'Capacity callback must return its validated plan')
        uint(capacity.get('image_bytes'),'Planned IMG size')
        uint(capacity.get('original_declared_capacity'),'Original container capacity')
        need(0 < capacity['image_bytes'] <= capacity['original_declared_capacity'],
             'Planned IMG exceeds declared container capacity')
        if not synthetic_fixture:
            need(capacity['original_declared_capacity'] == ORIGINAL_CAPACITY,
                 'Production requires original AP declared capacity')
    selected = tuple(selected_ranges)
    # One bounded L3 read: no old full-table preservation suite is replayed.
    old_l3 = source.exact(tables[2]['start'],tables[2]['bytes'])
    if not synthetic_fixture:
        need(hashlib.sha256(old_l3).hexdigest() == _stock_binding['correct_table_sha256'],
             'Production L3 differs from sealed corrected original source')
    for change in selected:
        need(type(change) is SelectedRange,'Requires explicit sealed SelectedRange')
        uint(change.one_based_street_ID,'StreetID',tables[2]['count'])
        need(change.one_based_street_ID > 0,'StreetID must be one-based')
        at = (change.one_based_street_ID-1)*111
        byte,initial = divmod(at,8)
        record = int.from_bytes(old_l3[byte:byte+(initial+111+7)//8],'little')>>initial
        first,count = (record>>20)&0x3fffff,(record>>42)&0xfff
        need((record>>54)&7 == 4 and first >= 1 and count >= 1 and first+count-1 <= tables[3]['count'],
             'Selected source street requires original valid nonempty next_level4 range')
    converted = core.rewrite_l3_width23(old_l3,record_count=tables[2]['count'],
        selected_ranges=selected,child_table_count=new_l4_total)
    need(converted.old_unused_tail_value == 0,'Original L3 unused tail must be zero; unknown nonzero tail unsupported')
    lookahead = source.exact(tables[1]['start'],4)
    old_directory = bytes(directory)
    struct.pack_into('<I',header,600,dstart+delta)
    struct.pack_into('<I',directory,3*20+4,tables[3]['bytes']+addedbytes)
    struct.pack_into('<3I',directory,2*20,tables[2]['start']+addedbytes,l3bytes,112)
    w = struct.unpack_from('<I',directory,2*20+12)[0]
    struct.pack_into('<I',directory,2*20+12,(w&~(63<<18))|(23<<18))
    for level in [0,1]:struct.pack_into('<I',directory,level*20,tables[level]['start']+delta)
    newtables = tuple(_decoded(directory[i*20:(i+1)*20]) for i in range(6))
    need(newtables[3]['start']+newtables[3]['bytes'] == newtables[2]['start'],'PlannedL4/L3 adjacency differs')
    need(newtables[2]['start']+newtables[2]['bytes'] == newtables[1]['start'],'Planned L3/L2 adjacency differs')
    need(newtables[1]['start']+newtables[1]['bytes'] == newtables[0]['start'] and
         newtables[0]['start']+newtables[0]['bytes'] == dstart+delta,'Planned tail adjacency differs')
    report = dict(original_size=source.size,new_size=size,delta=delta,old_directory_start=dstart,new_directory_start=dstart+delta,
        original_tables=tables,new_tables=newtables,new_l4_count=new_l4_count,appended_bytes=addedbytes,
        L3_original_bytes=tables[2]['bytes'],L3_new_bytes=l3bytes,L3_growth=l3bytes-tables[2]['bytes'],
        original_L3_sha256=hashlib.sha256(old_l3).hexdigest(),new_L3_sha256=hashlib.sha256(converted.table).hexdigest(),
        original_L3_unused_tail_bits=converted.old_unused_tail_bits,original_L3_unused_tail_value=converted.old_unused_tail_value,
        lookahead_is_actual_L2_bytes=True,actual_L2_lookahead_hex=lookahead.hex(),lookahead_insertion_bytes=0,
        preserved_directory_level5_level6=old_directory[80:120] == directory[80:120],
        selected_ranges=[dict(one_based_ID=c.one_based_street_ID,first=c.first_child,count=c.count)for c in selected],
        capacity_plan=None if capacity is None else dict(image_bytes=capacity['image_bytes'],original_declared_capacity=capacity['original_declared_capacity']),
        corrected_original_source_proof=dict(path=str(CORRECTED_PROOF.relative_to(ROOT)),sha256=CORRECTED_SHA),
        sealed_AP_primitive=dict(path=str(SEALED_WRITER.relative_to(ROOT)),sha256=SEALED_SHA),
        synthetic_fixture=synthetic_fixture,complete_new_street_or_JAI_writer=False)
    need(source.unchanged() is True,'Source changed during planning')
    return MDRPlan(source,bytes(header),bytes(directory),converted.table,lookahead,tuple(tables),newtables,
                   dstart,dstart+delta,size,new_l4_count,new_l4_supplier,selected,report)
