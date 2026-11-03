#!/usr/bin/env python3
"""Current v2 MDR COW suffix API. No CLI, default output, or device operation.

The append producer owns copied-parent range edits. This writer preserves
every current lower-table significant bit and patches only explicit L3 ranges.
Container expansion requires a separate, explicitly bound AP8K adapter.
"""
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
EIGHT_PATH = ROOT/'staging/navigation-native-img-8k-writer-v1/ap_8k_writer.py'
EIGHT_SHA = 'f4c870f2494d82f93a64f3de70b215c3ae38a85263f977016093c2fef46c1716'
BASE_SHA = 'cb190d5f3c70f0e81e9d49808dff044e4717b5061f749e7720af56aee39b0cf8'
V2 = ROOT/'staging/navigation-country-native-candidate-v2'
V2_SEAL_SHA = '659ae2d149b45098542fd90cd0a3000e74e3c9e2d76077f4d1ecdbbeec022766'
V2_SHA = '925a515b668f3878ef0acea3e1c79188c15216f1af7f039c0e426942907ebefb'
V2_BYTES = 128356352
V2_MDR_BYTES = 124255307
V2_L3_SHA = '2cd4c24f263cb6df6c863d1113992f3959090c1d99ebf26159288109b1d9ad21'
STRIDES = {4:128, 5:126, 6:68}
PROFILE = (
    (122, (16,9,24,19,1,10,0,0), (1,1)),
    (122, (16,9,24,19,1,10,0,0), (1,1)),
    (112, (23,9,24,19,1,12,0,0), (1,0)),
    (128, (22,9,24,19,1,10,0,0), (1,1)),
    (126, (21,9,24,19,1,9,0,0), (1,1)),
    (68, (0,0,24,19,1,0,0,0), (1,0)),
)
CURRENT_COUNTS = (22,343,47870,3781594,2667573,1984066)
CURRENT_DIR_HEX = (
    '83fa6707500100007a000000c18441c90a000000'
    '14e667076f1400007a000000c18441c90a000000'
    '30ac5d07e4390a0070000000c1845d490c000000'
    '906ec203a03d9b0380000000c18459c90a000000'
    '4d584101431681027e000000c18455c909000000'
    '1c0340003155010144000000c184014000000000'
)


def need(ok, message):
    if not ok:
        raise ValueError(message)


def uint(value, label, maximum=0xffffffff):
    need(type(value) is int and 0 <= value <= maximum, label+' outside finite unsigned range')
    return value


def chunk(raw, label):
    need(isinstance(raw, (bytes,bytearray,memoryview)), label+' must contain bytes')
    raw = bytes(raw)
    need(0 < len(raw) <= 65536, label+' must be nonempty and <=64KiB')
    return raw


def eight():
    need(hashlib.sha256(EIGHT_PATH.read_bytes()).hexdigest() == EIGHT_SHA, 'Sealed AP8K dependency changed')
    base = ROOT/'staging/navigation-native-general-writer-v1/native_ap_writer.py'
    need(hashlib.sha256(base.read_bytes()).hexdigest() == BASE_SHA, 'Sealed container parser dependency changed')
    name = 'current_cow_sealed_AP8K_v1'
    if name not in sys.modules:
        spec = importlib.util.spec_from_file_location(name, EIGHT_PATH)
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
    return sys.modules[name]


def stat_tuple(stream):
    s = os.fstat(stream.fileno())
    return (s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)


@dataclass(frozen=True)
class CurrentMDRSource:
    size: int
    read_range: Callable[[int,int],bytes]
    range_supplier: Callable[[int,int],Iterable[bytes]]
    unchanged: Callable[[],bool] = lambda: True
    source_binding: str = 'explicit_small_fixture'

    @classmethod
    def from_container(cls, image, *, synthetic_fixture=False):
        need(type(image) is eight().Source4K, 'Requires sealed Source4K parser instance')
        need(type(synthetic_fixture) is bool, 'Fixture marker must be bool')
        if synthetic_fixture:
            need(image.size <= 262144, 'Container fixture exceeds256KiB')
            snapshot = None
            try:
                snapshot = stat_tuple(image.stream)
            except (AttributeError,OSError):
                pass
            unchanged = (lambda: stat_tuple(image.stream) == snapshot) if snapshot else (lambda: True)
            binding = 'explicit_small_fixture'
        else:
            seal_bytes = (V2/'sealed-files.json').read_bytes()
            need(hashlib.sha256(seal_bytes).hexdigest() == V2_SEAL_SHA, 'Current v2 seal differs')
            seal = json.loads(seal_bytes)
            pin = next(row for row in seal['files'] if row['path'] == str((V2/'gmapprom1.img').relative_to(ROOT)))
            need(pin['bytes'] == V2_BYTES and pin['sha256'] == V2_SHA, 'Current v2 inherited hash binding differs')
            need(Path(image.stream.name).resolve() == (V2/'gmapprom1.img').resolve(), 'Only exact current v2 source path supported')
            snapshot = stat_tuple(image.stream)
            # Root-created hardlinks may legitimately change ctime since sealing;
            # retain exact dev/inode/size/mtime and capture current ctime for use.
            need(snapshot[:4] == tuple(pin['stat_at_seal'][:4]), 'Current source dev/inode/size/mtime differs from seal')
            need(image.size == V2_BYTES and image.components['00004171.MDR'].size == V2_MDR_BYTES,
                 'Current image or MDR logical size differs')
            unchanged = lambda: stat_tuple(image.stream) == snapshot
            binding = V2_SHA
        name = '00004171.MDR'
        return cls(image.components[name].size,
            lambda at,n: b''.join(image.iter_component(name,offset=at,length=n,chunk_bytes=65536)),
            lambda at,n: image.iter_component(name,offset=at,length=n,chunk_bytes=65536), unchanged, binding)

    def exact(self, at, n):
        uint(at,'Source offset');uint(n,'Source read bytes',65536)
        need(at+n <= self.size, 'Source range exceeds MDR EOF')
        raw = self.read_range(at,n)
        need(type(raw) is bytes and len(raw) == n, 'Source read callback returned wrong type/length')
        return raw

    def chunks(self, at, n):
        uint(at,'Source offset');uint(n,'Source span bytes')
        need(at+n <= self.size, 'Source span exceeds MDR EOF')
        result = self.range_supplier(at,n)
        need(not isinstance(result,(bytes,bytearray,memoryview,str)), 'Source supplier must return chunk iterable')
        total = 0
        for raw in result:
            raw = chunk(raw,'Source chunk');total += len(raw)
            need(total <= n, 'Source span supplier exceeds declared bytes')
            yield raw
        need(total == n, 'Source span supplier truncated')


def bit_splice(segments):
    """Each segment is (valid_bit_length, chunk supplier); one final padding.

    The supplier includes ceil(valid_bits/8) bytes. Discard only zero high final
    padding, carrying the valid bits directly into the following segment.
    """
    carry = pending = 0
    for bits,supplier in segments:
        uint(bits,'Segment significant bits',0x7fffffffffffffff)
        need(callable(supplier), 'Segment supplier must be callable')
        expected = (bits+7)//8;total = 0;remaining = bits
        result = supplier()
        need(not isinstance(result,(bytes,bytearray,memoryview,str)), 'Segment supplier must yield chunks')
        for raw in result:
            raw = chunk(raw,'Bit segment');total += len(raw)
            need(total <= expected, 'Bit segment supplier exceeds declaration')
            valid = min(remaining,len(raw)*8);value = int.from_bytes(raw,'little')
            need(value >> valid == 0, 'Nonzero unused segment final padding')
            combined = carry | (value << pending);available = pending+valid
            whole = available//8;wire = combined.to_bytes((available+7)//8,'little')
            if whole:
                yield wire[:whole]
            pending = available%8;carry = combined >> (whole*8);remaining -= valid
        need(total == expected and remaining == 0, 'Bit segment supplier truncated')
    if pending:
        yield bytes([carry])


def pack_records(level, records, count):
    need(type(level) is int and level in STRIDES, 'Record level must be4/5/6')
    uint(count,'Record count',0x7fffff)
    width = STRIDES[level];rowbytes = (width+7)//8
    accumulator = pending = seen = 0;buffer = bytearray()
    for raw in records:
        need(isinstance(raw,(bytes,bytearray,memoryview)) and len(raw) == rowbytes, 'Individual record byte length differs')
        value = int.from_bytes(raw,'little')
        need(value >> width == 0 and value & 1 == 1, 'Individual record padding/mapordinal1 differs')
        seen += 1;need(seen <= count, 'Individual supplier exceeds count')
        accumulator |= value << pending;pending += width
        while pending >= 8:
            buffer.append(accumulator & 255);accumulator >>= 8;pending -= 8
            if len(buffer) == 65536:
                yield bytes(buffer);buffer.clear()
    need(seen == count, 'Individual supplier truncated')
    if pending:
        buffer.append(accumulator)
    if buffer:
        yield bytes(buffer)


@dataclass(frozen=True)
class PackedAppend:
    level: int
    record_count: int
    bit_length: int
    supplier: Callable[[],Iterable[bytes]]

    @classmethod
    def from_records(cls,level,record_count,supplier):
        need(callable(supplier), 'Record supplier must be callable')
        need(type(level) is int and level in STRIDES, 'Append level must be4/5/6')
        return cls(level,record_count,record_count*STRIDES[level],lambda: pack_records(level,supplier(),record_count))

    @classmethod
    def empty(cls,level):
        return cls.from_records(level,0,lambda: iter(()))

    def validate(self):
        need(type(self.level) is int and self.level in STRIDES, 'Append level must be4/5/6')
        uint(self.record_count,'Append count',0x7fffff);uint(self.bit_length,'Append bit length')
        need(self.bit_length == self.record_count*STRIDES[self.level] and callable(self.supplier), 'Append count/stride/supplier differs')

    @property
    def byte_length(self):
        return (self.bit_length+7)//8

    def chunks(self):
        self.validate();result = self.supplier()
        need(not isinstance(result,(bytes,bytearray,memoryview,str)), 'Append supplier must return chunk iterable')
        total = ordinal = 0;stride = STRIDES[self.level]
        for raw in result:
            raw = chunk(raw,'Append chunk');begin,end = total*8,(total+len(raw))*8
            need(total+len(raw) <= self.byte_length, 'Append supplier exceeds explicit span')
            while ordinal < self.record_count and ordinal*stride < end:
                relative = ordinal*stride-begin
                need(relative >= 0 and (raw[relative//8] >> (relative%8)) & 1 == 1, 'Append record mapordinal1 differs')
                ordinal += 1
            total += len(raw)
            if total == self.byte_length and self.bit_length%8:
                need(raw[-1] >> (self.bit_length%8) == 0, 'Append unused final bits are nonzero')
            yield raw
        need(total == self.byte_length and ordinal == self.record_count, 'Append supplier truncated count/span')


@dataclass(frozen=True)
class SelectedRange:
    one_based_street_ID: int
    first_child: int
    count: int
    next_level: int
    original_flags: int


def decode_descriptor(raw):
    need(type(raw) is bytes and len(raw) == 20, 'Table descriptor length differs')
    start,size,stride,w,x = struct.unpack('<5I',raw)
    need(stride > 0, 'Zero record stride')
    return dict(start=start,bytes=size,stride=stride,count=size*8//stride,
        widths=[(w>>18)&63,(w>>24)&63,(w>>12)&63,(w>>6)&63,w&63,x&63,(x>>11)&63,(x>>17)&63],
        flags=[(w>>30)&1,(w>>31)&1])


@dataclass(frozen=True)
class CurrentMDRPlan:
    source: CurrentMDRSource
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
        need(self.source.unchanged() is True, 'Current source changed since planning')
        yield self.header
        if self.old_tables[5]['start'] > 772:
            yield from self.source.chunks(772,self.old_tables[5]['start']-772)
        for level,spec in zip((6,5,4),self.appends):
            old = self.old_tables[level-1]
            yield from bit_splice(((old['count']*old['stride'],lambda old=old:self.source.chunks(old['start'],old['bytes'])),
                                  (spec.bit_length,spec.chunks)))
        for at in range(0,len(self.L3),65536):
            yield self.L3[at:at+65536]
        prefix = bytearray();old2 = self.old_tables[1]
        for raw in self.source.chunks(old2['start'],self.old_directory_start-old2['start']):
            if len(prefix) < 4:
                prefix.extend(raw[:4-len(prefix)])
                if len(prefix) == 4:
                    need(bytes(prefix) == self.L2_lookahead, 'Actual L2 lookahead changed')
            yield raw
        need(bytes(prefix) == self.L2_lookahead, 'Actual L2 lookahead missing')
        yield self.directory
        need(self.source.unchanged() is True, 'Current source changed during suffix streaming')

    def bind_container(self,adapter):
        need(type(adapter) is Explicit8KAdapter and adapter.source is self.source, 'Plan requires its own explicit8K adapter')
        replacement = eight().Replacement(self.size,self.chunks)
        capacity = eight().plan_repack(adapter.image,{'00004171.MDR':replacement})
        return BoundCurrentMDR(self,adapter,replacement,capacity)


@dataclass(frozen=True)
class Explicit8KAdapter:
    image: object
    source: CurrentMDRSource

    @classmethod
    def from_container(cls,image,*,synthetic_fixture=False):
        return cls(image,CurrentMDRSource.from_container(image,synthetic_fixture=synthetic_fixture))


@dataclass(frozen=True)
class BoundCurrentMDR:
    plan: CurrentMDRPlan
    adapter: Explicit8KAdapter
    replacement: object
    capacity_plan: dict

    def repack_stream(self,destination):
        need(self.plan.source.unchanged() is True, 'Source changed before AP8K packaging')
        receipt = eight().repack_stream(self.adapter.image,destination,{'00004171.MDR':self.replacement})
        need(self.plan.source.unchanged() is True, 'Source changed during AP8K packaging')
        return receipt


def plan_current_mdr(source,*,appends,selected_ranges=(),synthetic_fixture=False):
    """Plan current112-bit L3/unchanged lower widths, never consume appends.

    Source lower significant prefixes remain recoverable at count*stride bits;
    only their final padding may be replaced when the append begins mid-byte.
    Copied-parent links and leaf encoding are producer-owned and not inferred.
    """
    need(type(source) is CurrentMDRSource, 'Requires CurrentMDRSource callbacks')
    need(type(synthetic_fixture) is bool, 'Fixture marker must be bool')
    need(callable(source.read_range) and callable(source.range_supplier) and callable(source.unchanged), 'Source callbacks differ')
    uint(source.size,'Current MDR size');need(source.unchanged() is True, 'Source changed before plan')
    need(isinstance(appends,dict) and set(appends) == {4,5,6}, 'Explicit append mapping4/5/6 required')
    for level,spec in appends.items():
        need(type(level) is int and type(spec) is PackedAppend and spec.level == level, 'Append key/type/level differs')
        spec.validate()
    header = bytearray(source.exact(0,772))
    need(struct.unpack_from('<H',header)[0] == 772 and header[2:12] == b'GARMIN MDR', 'Current MDR772 signature differs')
    dstart,dbytes,itembytes,dflags = struct.unpack_from('<4I',header,600)
    need((dbytes,itembytes,dflags) == (120,20,1) and dstart+120 == source.size, 'Current directory descriptor/EOF differs')
    directory = bytearray(source.exact(dstart,120))
    tables = [decode_descriptor(bytes(directory[i*20:(i+1)*20])) for i in range(6)]
    for i,(table,profile) in enumerate(zip(tables,PROFILE)):
        need((table['stride'],tuple(table['widths']),tuple(table['flags'])) == profile, 'Current profile differs at level'+str(i+1))
        need(table['count'] > 0 and table['bytes'] == (table['count']*table['stride']+7)//8, 'Current minimal table span/count differs')
        need(772 <= table['start'] < table['start']+table['bytes'] <= dstart, 'Current table outside suffix')
    physical = [tables[i] for i in (5,4,3,2,1,0)]
    need(all(a['start']+a['bytes'] == b['start'] for a,b in zip(physical,physical[1:])) and
         tables[0]['start']+tables[0]['bytes'] == dstart, 'Current physical6/5/4/3/2/1 layout differs')
    if synthetic_fixture:
        need(source.source_binding == 'explicit_small_fixture' and source.size <= 16384 and all(t['count'] <= 16 for t in tables),
             'Only explicit small current-profile fixtures supported')
    else:
        need(source.source_binding == V2_SHA and source.size == V2_MDR_BYTES and tuple(t['count'] for t in tables) == CURRENT_COUNTS,
             'Only sealed exact current v2 profile supported')
        need(directory.hex() == CURRENT_DIR_HEX, 'Current directory differs from sealed actual v2')
    for level in (6,5,4):
        table = tables[level-1];valid = table['count']*table['stride'];tail = valid%8
        if tail:
            need(source.exact(table['start']+table['bytes']-1,1)[0] >> tail == 0, 'Current unused lower-table padding nonzero')
    new = [dict(t) for t in tables]
    for level,limit in ((4,0x7fffff),(5,0x3fffff),(6,0x1fffff)):
        t = new[level-1];t['count'] += appends[level].record_count
        need(t['count'] <= limit, 'New table exceeds unchanged incoming first-field width at level'+str(level))
        t['bytes'] = (t['count']*t['stride']+7)//8
    cursor = tables[5]['start']
    for level in (6,5,4,3,2,1):
        new[level-1]['start'] = cursor;cursor += new[level-1]['bytes']
    size = uint(cursor+120,'New current MDR size')
    need(tables[2]['bytes'] <= 1048576, 'Current L3 retained buffer exceeds1MiB')
    old_L3 = b''.join(source.chunks(tables[2]['start'],tables[2]['bytes']))
    old_L3_sha = hashlib.sha256(old_L3).hexdigest()
    if not synthetic_fixture:
        need(old_L3_sha == V2_L3_SHA, 'Actual current L3 hash differs from completed v2 readback')
    L3 = bytearray(old_L3);seen = set();changes = [];new_intervals = {4:[],5:[],6:[]}
    selected = tuple(selected_ranges)
    range_mask = ((1<<35)-1)<<20
    for change in selected:
        need(type(change) is SelectedRange, 'Requires explicit SelectedRange')
        ID = uint(change.one_based_street_ID,'Selected StreetID',tables[2]['count'])
        need(ID > 0 and ID not in seen, 'Duplicate/zero selected StreetID');seen.add(ID)
        need(type(change.next_level) is int and change.next_level in STRIDES, 'Selected next level must be4/5/6')
        uint(change.original_flags,'Original raw flags',511)
        at = (ID-1)*14;value = int.from_bytes(old_L3[at:at+14],'little')
        first,count,flags = (value>>20)&0x7fffff,(value>>43)&0xfff,(value>>55)&511
        need(flags == change.original_flags and flags&7 == change.next_level, 'Selected raw flags/branch differ; conversion forbidden')
        old_limit = tables[change.next_level-1]['count']
        need(first >= 1 and count >= 1 and first+count-1 <= old_limit, 'Selected current old range invalid')
        uint(change.first_child,'New L3 first23',0x7fffff);uint(change.count,'New L3 count12',0xfff)
        need(change.count > 0 and change.first_child > old_limit and
             change.first_child+change.count-1 <= new[change.next_level-1]['count'], 'COW root must target complete appended corresponding-table range')
        new_intervals[change.next_level].append((change.first_child,change.first_child+change.count-1))
        altered = (value & ~range_mask) | change.first_child<<20 | change.count<<43
        need((value & ~range_mask) == (altered & ~range_mask), 'Non-range L3 field changed')
        L3[at:at+14] = altered.to_bytes(14,'little')
        changes.append(dict(ID=ID,next_level=change.next_level,original_flags=flags,original_first=first,original_count=count,
                            first=change.first_child,count=change.count))
    for intervals in new_intervals.values():
        intervals.sort()
        need(all(a[1] < b[0] for a,b in zip(intervals,intervals[1:])), 'Selected COW output ranges overlap/alias')
    lookahead = source.exact(tables[1]['start'],4)
    struct.pack_into('<I',header,600,cursor)
    for i,t in enumerate(new):
        # Preserve stride and both complete descriptor bitfields byte-verbatim.
        struct.pack_into('<2I',directory,i*20,t['start'],t['bytes'])
    decoded = tuple(decode_descriptor(bytes(directory[i*20:(i+1)*20])) for i in range(6))
    need(all(t['count'] == n['count'] for t,n in zip(decoded,new)), 'Rebuilt counts differ')
    report = dict(schema='current-profile-cow-MDR-plan/v1',source_binding=source.source_binding,
        original_size=source.size,new_size=size,old_directory_start=dstart,new_directory_start=cursor,
        original_tables=tables,new_tables=decoded,selected_ranges=changes,
        appends=[dict(level=level,records=appends[level].record_count,valid_bits=appends[level].bit_length,
                      packed_bytes=appends[level].byte_length) for level in (6,5,4)],
        L3_stride=112,L3_first_width=23,L3_growth=0,original_L3_sha256=old_L3_sha,new_L3_sha256=hashlib.sha256(L3).hexdigest(),
        original_lower_significant_bit_prefixes_preserved=True,source_final_padding_discarded_only_when_zero=True,
        lower_record_widths_expanded=False,copied_parent_links_are_append_producer_owned=True,
        L3_only_selected_first_count_modified=True,unknown_prefix_L2_L1_and_descriptor_bitfields_preserved=True,
        actual_L2_lookahead_hex=lookahead.hex(),inserted_lookahead_bytes=0,
        capacity_checked_here=False,explicit8K_binding_required_before_container_output=True,
        synthetic_fixture=synthetic_fixture,native_comparator_or_CPU_verified=False,device_acceptance_verified=False)
    need(source.unchanged() is True, 'Source changed during current plan')
    return CurrentMDRPlan(source,bytes(header),bytes(directory),bytes(L3),lookahead,tuple(tables),decoded,
                          tuple(appends[level] for level in (6,5,4)),size,dstart,cursor,report)
