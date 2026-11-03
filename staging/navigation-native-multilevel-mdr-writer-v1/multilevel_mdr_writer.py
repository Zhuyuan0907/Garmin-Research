#!/usr/bin/env python3
"""Stock MDR multilevel packed append; capacity is an explicit separate adapter."""
from dataclasses import dataclass
import hashlib
import importlib.util
import os
from pathlib import Path
import struct
import sys
from typing import Callable, Iterable

ROOT=Path('/root/garmin')
SINGLE_PATH=ROOT/'staging/navigation-native-mdr-rewrite-v1/mdr_suffix_writer.py'
SINGLE_SHA='f61c347fea346e5655e1ae83bc1c493ae2095b9b3e2e4ba85e6ba898a8204408'
EIGHT_PATH=ROOT/'staging/navigation-native-img-8k-writer-v1/ap_8k_writer.py'
EIGHT_SHA='f4c870f2494d82f93a64f3de70b215c3ae38a85263f977016093c2fef46c1716'


def imported(path,expected,name):
    if hashlib.sha256(path.read_bytes()).hexdigest()!=expected:raise ValueError('Sealed dependency changed:'+str(path))
    if name not in sys.modules:
        spec=importlib.util.spec_from_file_location(name,path)
        module=importlib.util.module_from_spec(spec);sys.modules[name]=module;spec.loader.exec_module(module)
    return sys.modules[name]


single=imported(SINGLE_PATH,SINGLE_SHA,'sealed_singlelevel_MDR_v1')
core=single.core
MDRSource=single.MDRSource
need,uint,bounded_chunk=single.need,single.uint,single.bounded_chunk
STRIDES={4:128,5:126,6:68}


def pack_records(level,records,record_count):
    """Pack individually padded records into one continuous table bitstream.

    Each input row contains exactly ceil(stride/8) bytes with zero unused bits.
    Only the last output byte has padding; there is no per-record output pad.
    """
    need(type(level)is int and level in STRIDES,'Append level must be4/5/6')
    uint(record_count,'Append record count',0x7fffff)
    width=STRIDES[level];rowbytes=(width+7)//8
    buffer,accumulator,bits,count=bytearray(),0,0,0
    for row in records:
        need(isinstance(row,(bytes,bytearray,memoryview)),'Record supplier must yield bytes-like records')
        length=row.nbytes if isinstance(row,memoryview)else len(row)
        need(length==rowbytes,'Individual record padded byte length differs from declared level')
        need(count<record_count,'Individual record supplier exceeds explicit count')
        value=int.from_bytes(row,'little')
        need(value>>width==0,'Individual record contains nonzero unused high bits')
        need(value&1==1,'Individual record requires original AP mapordinal1')
        accumulator|=value<<bits;bits+=width;count+=1
        while bits>=8:
            buffer.append(accumulator&255);accumulator>>=8;bits-=8
            if len(buffer)==65536:yield bytes(buffer);buffer.clear()
    need(count==record_count,'Individual record supplier truncated explicit count')
    if bits:buffer.append(accumulator)
    if buffer:yield bytes(buffer)


@dataclass(frozen=True)
class PackedAppend:
    level: int
    record_count: int
    bit_length: int
    supplier: Callable[[],Iterable[bytes]]

    @classmethod
    def from_records(cls,level,record_count,supplier):
        need(type(level)is int and level in STRIDES,'Append level must be4/5/6')
        uint(record_count,'Append record count',0x7fffff);need(callable(supplier),'Individual record supplier must be callable')
        return cls(level,record_count,record_count*STRIDES[level],lambda:pack_records(level,supplier(),record_count))

    @classmethod
    def empty(cls,level):return cls.from_records(level,0,lambda:iter(()))

    @property
    def byte_length(self):return (self.bit_length+7)//8

    def validate(self):
        need(type(self.level)is int and self.level in STRIDES,'Append level must be4/5/6')
        uint(self.record_count,'Append record count',0x7fffff);uint(self.bit_length,'Append bit length')
        need(self.bit_length==self.record_count*STRIDES[self.level],'Explicit bit length differs from count times stride')
        need(callable(self.supplier),'Packed append supplier must be callable')

    def chunks(self):
        self.validate();result=self.supplier()
        need(not isinstance(result,(bytes,bytearray,memoryview,str)),'Packed supplier must return an iterable of chunks')
        total,ordinal=0,0;stride=STRIDES[self.level]
        for raw in result:
            data=bounded_chunk(raw,'Packed append')
            need(total+len(data)<=self.byte_length,'Packed append exceeds declared byte/bit count')
            begin,end=total*8,(total+len(data))*8
            while ordinal<self.record_count and ordinal*stride<end:
                relative=ordinal*stride-begin
                need(relative>=0 and (data[relative//8]>>(relative%8))&1==1,'Packed record mapordinal1 missing')
                ordinal+=1
            total+=len(data)
            if total==self.byte_length and self.bit_length%8:
                need(data[-1]>>(self.bit_length%8)==0,'Packed stream contains nonzero unused final bits')
            yield data
        need(total==self.byte_length and ordinal==self.record_count,'Packed append truncated declared records/bits')


@dataclass(frozen=True)
class SelectedRange:
    one_based_street_ID: int
    first_child: int
    count: int
    next_level: int
    original_flags: int


@dataclass(frozen=True)
class ContainerAdapter:
    kind: str
    image: object
    mdr_source: MDRSource

    @classmethod
    def original_4k(cls,image):
        need(type(image)is core.StreamIMG,'4K adapter requires this module core.StreamIMG')
        need(image.capacity==134217728,'4K adapter requires original declared capacity')
        return cls('original4K',image,MDRSource.from_container(image))

    @classmethod
    def explicit_8k(cls,image):
        eight=imported(EIGHT_PATH,EIGHT_SHA,'sealed_explicit_8K_container_v1')
        need(type(image)is eight.Source4K,'8K adapter requires this module eight().Source4K')
        return cls('explicit8K',image,MDRSource.from_container(image))

    def bind(self,plan):
        need(type(plan)is MDRPlan and plan.source is self.mdr_source,'Container adapter must bind its own original MDRSource')
        if self.kind=='original4K':
            need(type(self.image)is core.StreamIMG,'4K adapter source type differs')
            replacement=core.Replacement(plan.size,plan.chunks)
            capacity=core.plan_repack(self.image,{'00004171.MDR':plan.size})
            return BoundMDR(plan,self,replacement,capacity)
        need(self.kind=='explicit8K','Unknown container adapter')
        eight=imported(EIGHT_PATH,EIGHT_SHA,'sealed_explicit_8K_container_v1')
        need(type(self.image)is eight.Source4K,'8K adapter source type differs')
        replacement=eight.Replacement(plan.size,plan.chunks)
        capacity=eight.plan_repack(self.image,{'00004171.MDR':replacement})
        return BoundMDR(plan,self,replacement,capacity)


def eight():return imported(EIGHT_PATH,EIGHT_SHA,'sealed_explicit_8K_container_v1')


@dataclass(frozen=True)
class BoundMDR:
    plan: object
    adapter: ContainerAdapter
    replacement: object
    capacity_plan: dict

    def repack_stream(self,destination):
        module=core if self.adapter.kind=='original4K'else eight()
        return module.repack_stream(self.adapter.image,destination,{'00004171.MDR':self.replacement})


@dataclass(frozen=True)
class MDRPlan:
    source: MDRSource
    header: bytes
    directory: bytes
    L3: bytes
    L2_lookahead: bytes
    old_tables: tuple
    new_tables: tuple
    appends: tuple
    size: int
    old_directory_start: int
    new_directory_start: int
    report: dict

    def chunks(self):
        need(self.source.unchanged()is True,'Source changed since multilevel planning')
        yield self.header
        prefix=self.old_tables[5]['start']-772
        if prefix:yield from self.source.chunks(772,prefix)
        for level,spec in zip([6,5,4],self.appends):
            table=self.old_tables[level-1]
            yield from self.source.chunks(table['start'],table['bytes'])
            yield from spec.chunks()
        for at in range(0,len(self.L3),65536):yield self.L3[at:at+65536]
        start=self.old_tables[1]['start'];first=bytearray()
        for data in self.source.chunks(start,self.old_directory_start-start):
            if len(first)<4:
                first.extend(data[:4-len(first)])
                if len(first)==4:need(bytes(first)==self.L2_lookahead,'Actual L2 lookahead changed')
            yield data
        need(bytes(first)==self.L2_lookahead,'Actual L2 lookahead missing')
        yield self.directory
        need(self.source.unchanged()is True,'Source changed during multilevel streaming')

    def bind_container(self,adapter):
        need(type(adapter)is ContainerAdapter,'Requires explicit container adapter')
        return adapter.bind(self)


def plan_multilevel_mdr(source,*,appends,selected_ranges=(),synthetic_fixture=False):
    """Prepare MDR semantics only. No capacity fallback or supplier consumption.

    appends requires explicit PackedAppend for each level4/5/6, including zero.
    Container capacity is checked independently by plan.bind_container(adapter).
    """
    need(type(source)is MDRSource,'Requires sealed bounded/streaming MDRSource')
    need(callable(source.read_range)and callable(source.range_supplier)and callable(source.unchanged),'Invalid source callbacks')
    uint(source.size,'MDR source size');need(type(synthetic_fixture)is bool,'Fixture marker must be bool')
    need(source.unchanged()is True,'Source changed before multilevel planning')
    need(isinstance(appends,dict)and set(appends)=={4,5,6},'Explicit append declarations for all levels4/5/6 required')
    for level,spec in appends.items():
        need(type(level)is int,'Append mapping keys must be integer levels')
        need(type(spec)is PackedAppend and spec.level==level,'Packed append level/key or type differs');spec.validate()
    header=bytearray(source.exact(0,772))
    need(struct.unpack_from('<H',header)[0]==772 and header[2:12]==b'GARMIN MDR','Only original772-byte header supported')
    dstart,dbytes,itembytes,dflags=struct.unpack_from('<4I',header,600)
    need((dbytes,itembytes,dflags)==(120,20,1)and dstart+120==source.size,'Original six-entry descriptor/EOF differs')
    directory=bytearray(source.exact(dstart,120));tables=[single._decoded(directory[i*20:i*20+20])for i in range(6)]
    for index,(table,profile)in enumerate(zip(tables,single.PROFILE)):
        need((table['stride'],table['widths'],table['flags'])==profile,'Original profile differs at level'+str(index+1))
        need(table['count']>0 and table['bytes']==(table['count']*table['stride']+7)//8,'Original span contains extra records/padding')
        need(772<=table['start']<table['start']+table['bytes']<=dstart,'Original table outside suffix')
    order=[tables[i]for i in [5,4,3,2,1,0]]
    need(all(a['start']+a['bytes']==b['start']for a,b in zip(order,order[1:]))and
         tables[0]['start']+tables[0]['bytes']==dstart,'Original physical6/5/4/3/2/1 sequence differs')
    need(all(tables[level-1]['count']*STRIDES[level]%8==0 for level in [6,5,4]),
         'Only byte-aligned original level6/5/4 endings supported')
    if synthetic_fixture:
        need(source.size<=16384 and all(t['count']<=16 for t in tables),'Only small synthetic original fixtures supported')
    else:
        need(source.size==92653600 and [t['count']for t in tables]==single.STOCK_COUNTS and
             bytes(directory).hex()==single._stock_binding['directory_hex'],'Not sealed corrected original stock directory')
    new=[dict(t)for t in tables]
    for level in [6,5,4]:
        spec=appends[level];table=new[level-1];table['count']+=spec.record_count
        need(table['count']<=0x7fffff,'Corresponding child table exceeds common23-bit first profile')
        table['bytes']=(table['count']*table['stride']+7)//8
    new[2]['bytes']=new[2]['count']*14;new[2]['stride']=112;new[2]['widths']=[23,*new[2]['widths'][1:]]
    cursor=tables[5]['start']
    for level in [6,5,4,3,2,1]:new[level-1]['start']=cursor;cursor+=new[level-1]['bytes']
    size=cursor+120;uint(size,'New MDR logical size')
    old_L3=source.exact(tables[2]['start'],tables[2]['bytes'])
    if not synthetic_fixture:need(hashlib.sha256(old_L3).hexdigest()==single._stock_binding['correct_table_sha256'],'Not sealed corrected original L3')
    selected=tuple(selected_ranges);seen=set();changes=[]
    for change in selected:
        need(type(change)is SelectedRange,'Requires explicit multilevel SelectedRange with original flags')
        ID=uint(change.one_based_street_ID,'Selected StreetID',tables[2]['count']);need(ID>0 and ID not in seen,'Duplicate/zero selected StreetID');seen.add(ID)
        need(type(change.next_level)is int and change.next_level in [4,5,6],'Selected nextlevel must remain4/5/6')
        uint(change.original_flags,'Expected original flags',511)
        bit=(ID-1)*111;at,initial=divmod(bit,8)
        record=(int.from_bytes(old_L3[at:at+(initial+118)//8],'little')>>initial)&((1<<111)-1)
        oldfirst,oldcount,flags=(record>>20)&0x3fffff,(record>>42)&0xfff,(record>>54)&511
        need(flags==change.original_flags and flags&7==change.next_level,'Selected original flags/nextlevel differ; branch conversion forbidden')
        limit=tables[change.next_level-1]['count']
        need(oldfirst>=1 and oldcount>=1 and oldfirst+oldcount-1<=limit,'Selected original corresponding-table range invalid')
        uint(change.first_child,'Selected firstchild23',0x7fffff);uint(change.count,'Selected count12',0xfff)
        limit=new[change.next_level-1]['count']
        need((change.count==0 and change.first_child==0)or(change.count>0 and change.first_child>=1 and
             change.first_child+change.count-1<=limit),'Selected range exceeds actual corresponding table count')
        changes.append(dict(ID=ID,next_level=change.next_level,original_flags=flags,original_first=oldfirst,original_count=oldcount,
            first=change.first_child,count=change.count,corresponding_new_table_count=limit))
    # Reuse the sealed pure insertion exactly once, with no next4-only edits.
    widened=core.rewrite_l3_width23(old_L3,record_count=tables[2]['count'])
    need(widened.old_unused_tail_value==0,'Unknown nonzero original L3 unused tail unsupported')
    L3=bytearray(widened.table);range_mask=((1<<35)-1)<<20
    for c in selected:
        at=(c.one_based_street_ID-1)*14;record=int.from_bytes(L3[at:at+14],'little')
        altered=(record&~range_mask)|(c.first_child<<20)|(c.count<<43)
        need((record&~range_mask)==(altered&~range_mask),'Non-range L3 bit changed')
        L3[at:at+14]=altered.to_bytes(14,'little')
    lookahead=source.exact(tables[1]['start'],4)
    struct.pack_into('<I',header,600,cursor)
    for index,table in enumerate(new):
        struct.pack_into('<3I',directory,index*20,table['start'],table['bytes'],table['stride'])
    w=struct.unpack_from('<I',directory,52)[0];struct.pack_into('<I',directory,52,(w&~(63<<18))|(23<<18))
    decoded=tuple(single._decoded(directory[i*20:i*20+20])for i in range(6))
    need(all(t['count']==n['count']for t,n in zip(decoded,new)),'Rebuilt directory span/count differs')
    report=dict(original_size=source.size,new_size=size,delta=size-source.size,old_directory_start=dstart,new_directory_start=cursor,
        original_tables=tables,new_tables=decoded,appends=[dict(level=level,records=appends[level].record_count,
            valid_bits=appends[level].bit_length,packed_bytes=appends[level].byte_length,
            final_unused_bits=appends[level].byte_length*8-appends[level].bit_length)for level in [6,5,4]],
        selected_ranges=changes,L3_growth=len(L3)-len(old_L3),L3_w0=23,L3_stride=112,
        original_L3_sha256=hashlib.sha256(old_L3).hexdigest(),new_L3_sha256=hashlib.sha256(L3).hexdigest(),
        original_L3_unused_tail_bits=widened.old_unused_tail_bits,original_L3_unused_tail_value=widened.old_unused_tail_value,
        raw_parent_flags_and_nextlevels_preserved=True,level5_level4_child_fields_not_widened=True,
        actual_L2_lookahead_hex=lookahead.hex(),inserted_lookahead_bytes=0,capacity_checked_here=False,
        capacity_must_be_explicitly_bound_before_IMG_output=True,synthetic_fixture=synthetic_fixture,
        original_bit_insertion_dependency_sha256=single.SEALED_SHA,corrected_source_proof_sha256=single.CORRECTED_SHA,
        flag8_or13_semantics_established=False,new_streets_JAI_or_full_country_update=False)
    need(source.unchanged()is True,'Source changed during multilevel planning')
    return MDRPlan(source,bytes(header),bytes(directory),bytes(L3),lookahead,tuple(tables),decoded,
        tuple(appends[level]for level in [6,5,4]),size,dstart,cursor,report)
