#!/usr/bin/env python3
"""Focused primitive tests; exactly one original664197B L3 read/conversion.

Synthetic containers are about1MiB, kept in memory. No original full-container
copy/repack, guest CPU suite, device, installation or external-service actions.
"""
import datetime
import hashlib
import io
import json
from pathlib import Path
import resource
import struct
import sys
import tempfile

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0,str(HERE))
from native_ap_writer import (AP_NAMES,BLOCK,StreamIMG,Replacement,SelectedRange,
    rewrite_l3_width23,plan_repack,repack_stream,repack_new_path)


def sha(raw):return hashlib.sha256(raw).hexdigest()


def need(ok,message):
    if not ok:raise AssertionError(message)


def fixture_row(name,size,blocks,part=0,flag=0,tag=0):
    base,ext = name.split('.')
    row = bytearray(512)
    row[0] = 1
    row[1:9] = base.encode().ljust(8,b' ')
    row[9:12] = ext.encode().ljust(3,b' ')
    struct.pack_into('<I',row,12,size if part == 0 else 0)
    row[16] = flag
    struct.pack_into('<H',row,17,part)
    row[19:32] = bytes([tag])*13
    struct.pack_into('<240H',row,32,*(blocks+[65535]*(240-len(blocks))))
    return row


def synthetic_container(stock_header):
    h = bytearray(stock_header)
    h[64] = 1
    sizes = [17,240*4096-3,37,8193,53,11]
    payloads = {name:bytes([65+i])*size for i,(name,size) in enumerate(zip(AP_NAMES,sizes))}
    rows = []
    cursor = 1
    for i,name in enumerate(AP_NAMES):
        length = sizes[i]
        count = (length+4095)//4096
        blocks = list(range(cursor,cursor+count))
        rows.append(fixture_row(name,length,blocks,tag=33+i))
        cursor += count
    root = fixture_row('.',4096,[0],flag=3,tag=77)
    out = bytearray(h+root+b''.join(rows))
    need(len(out) == 4096,'Fixture metadata must end at4K')
    for name in AP_NAMES:
        data = payloads[name]
        out.extend(data)
        out.extend(bytes([0xee])*((-len(data))%4096))
    return bytes(out),payloads


def independent_container_read(raw):
    """Small-fixture verifier derived directly from local format references.

    It does not import/use the primitive's StreamIMG parser or allocation plan.
    """
    first = raw[64]*512
    end = struct.unpack_from('<I',raw,first+12)[0]
    need(end%BLOCK == 0,'Output directory growth is not4K aligned')
    rootblocks = [b for b in struct.unpack_from('<240H',raw,first+32) if b != 65535]
    need(rootblocks == list(range(end//BLOCK)),'Output root allocation mismatch')
    owner = set(rootblocks)
    files = {}
    for offset in range(first+512,end,512):
        row = raw[offset:offset+512]
        if row[0] == 0:
            need(row == bytes(512),'Output inactive row not zero');continue
        name = row[1:9].decode().rstrip()+'.'+row[9:12].decode().rstrip()
        length = struct.unpack_from('<I',row,12)[0]
        part = struct.unpack_from('<H',row,17)[0]
        if part == 0:
            need(name not in files,'Output duplicate path')
            files[name] = dict(size=length,blocks=[],rows=[])
        else:need(length == 0,'Output continuation size not0')
        c = files[name]
        need(part == len(c['rows']),'Output part sequence differs')
        table = struct.unpack_from('<240H',row,32)
        blocks = [b for b in table if b != 65535]
        need(table[:len(blocks)] == tuple(blocks) and all(b == 65535 for b in table[len(blocks):]),'Output FAT padding differs')
        for b in blocks:
            need(b not in owner and (b+1)*BLOCK <= len(raw),'Output overlap/outside block')
            owner.add(b)
        c['blocks'].extend(blocks);c['rows'].append(row)
    for c in files.values():
        need(len(c['blocks']) == (c['size']+4095)//4096,'Output block count differs')
        allocated = b''.join(raw[b*4096:(b+1)*4096] for b in c['blocks'])
        c['payload'] = allocated[:c['size']]
        need(allocated[c['size']:] == bytes(len(allocated)-c['size']),'Output component tail padding not zero')
    return end,files


def old_records(fields,tail_value=0):
    bits,position = 0,0
    for row in fields:
        for value,width in zip(row,[1,19,22,12,9,24,24]):
            need(0 <= value < 1<<width,'Fixture field overflow')
            bits |= value<<position;position += width
    extra = (-position)%8
    need(0 <= tail_value < 1<<extra if extra else tail_value == 0,'Fixture tail overflow')
    bits |= tail_value<<position
    return bits.to_bytes((position+7)//8,'little')


def reference_fields(raw,ID,width):
    start = (ID-1)*(89+width)
    fields = []
    # Independent bit-by-bit extraction, with no record integer/insertion.
    for n in [1,19,width,12,9,24,24]:
        value = 0
        for bit in range(n):value |= ((raw[(start+bit)//8]>>((start+bit)%8))&1)<<bit
        fields.append(value);start += n
    return fields


def main():
    output = HERE/'general-writer-focused-proof-v1.json'
    need(not output.exists(),'Refuse overwrite terminal proof/test scope')
    guards = []
    def rejected(name,func):
        try:func()
        except (ValueError,FileExistsError) as exc:guards.append(dict(name=name,rejected=True,exception=str(exc)))
        else:raise AssertionError('Missing rejection: '+name)
    # Only this reader instance reads original header/FAT and later L3 span.
    source_path = ROOT/'backups/20261002T154458Z/files/.System/gmapprom1.img'
    before = source_path.stat()
    identity = [before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns]
    with source_path.open('rb') as source_file:
        original = StreamIMG(source_file)
        need(original.size == 96739328 and original.capacity == 134217728,'Exact originalAP size/capacity differs')
        fixture,payloads = synthetic_container(original.header)
        replacement_data = b'R'*(241*4096-7)
        chunks_called = []
        def chunks():
            for p in range(0,len(replacement_data),4093):
                chunk = replacement_data[p:p+4093]
                chunks_called.append(len(chunk));yield chunk
        small_source = StreamIMG(io.BytesIO(fixture))
        out = io.BytesIO()
        repack_receipt = repack_stream(small_source,out,{'00004171.MDR':Replacement(len(replacement_data),chunks)})
        rebuilt = out.getvalue()
        end,parsed = independent_container_read(rebuilt)
        need(end == 8192 and small_source.directory_end == 4096,'240→241 FAT growth did not grow directory4K')
        need(rebuilt[:512] == fixture[:512],'Global header/geometry metadata changed')
        need(rebuilt[512+19:512+32] == fixture[512+19:512+32],'Root reserved metadata changed')
        for name in AP_NAMES:
            expected = replacement_data if name == '00004171.MDR' else payloads[name]
            need(parsed[name]['payload'] == expected,'Logical component bytes differ:'+name)
            for part,row in enumerate(parsed[name]['rows']):
                template = small_source.components[name].rows[min(part,len(small_source.components[name].rows)-1)]
                need(row[16] == template[16] and row[19:32] == template[19:32],'Component metadata template differs')
        need(len(parsed['00004171.MDR']['rows']) == 2 and len(parsed['00004171.MDR']['blocks']) == 241,'FAT continuation not exercised')
        need(sum(chunks_called) == len(replacement_data) and max(chunks_called) == 4093,'Streaming replacement not exercised')
        StreamIMG(io.BytesIO(rebuilt))
        def mutated(offset,value):
            raw = bytearray(fixture);raw[offset:offset+len(value)] = value
            return StreamIMG(io.BytesIO(raw))
        rejected('duplicate_allocated_block',lambda:mutated(1536+32,struct.pack('<H',1)))
        rejected('duplicate_component_path',lambda:mutated(1536+1,b'00004171MD2'))
        rejected('noncanonical_component_path',lambda:mutated(1024+1,b'../evil '))
        rejected('allocation_after_padding',lambda:mutated(1536+34,b'\xff\xff'))
        rejected('unsupported_XOR',lambda:mutated(0,b'\x69'))
        rejected('unsupported_block_width',lambda:mutated(98,b'\x04'))
        rejected('continuation_size_or_part',lambda:mutated(1536+17,b'\x01\x00'))
        rejected('unknown_replacement_path',lambda:plan_repack(small_source,{'NEW.MDR':1}))
        rejected('component_u32_overflow',lambda:plan_repack(small_source,{'00004171.MDR':1<<32}))
        rejected('original_capacity_exceeded',lambda:plan_repack(small_source,{'00004171.MDR':134217728}))
        rejected('destination_stream_alias',lambda:repack_stream(small_source,small_source.stream,{}))
        untouched = io.BytesIO(b'unchanged')
        rejected('nonempty_destination',lambda:repack_stream(small_source,untouched,{}))
        need(untouched.getvalue() == b'unchanged','Guard mutated existing output')
        rejected('short_replacement_stream',lambda:repack_stream(small_source,io.BytesIO(),{'00004171.MDR':Replacement(2,lambda:iter((b'a',)))}))
        rejected('long_replacement_stream',lambda:repack_stream(small_source,io.BytesIO(),{'00004171.MDR':Replacement(1,lambda:iter((b'ab',)))}))
        with tempfile.TemporaryDirectory(dir=HERE,prefix='small-fixture-') as td:
            p = Path(td)/'source.img';p.write_bytes(fixture)
            rejected('duplicate_output_path',lambda:repack_new_path(p,p,{}))
            existing = Path(td)/'existing.img';existing.write_bytes(b'existing')
            rejected('existing_output_path',lambda:repack_new_path(p,existing,{}))
            need(existing.read_bytes() == b'existing','Existing path guard mutated data')
            fail = Path(td)/'short.img'
            rejected('exclusive_output_cleanup',lambda:repack_new_path(p,fail,{'00004171.MDR':Replacement(2,lambda:iter((b'a',)))}))
            need(not fail.exists(),'Incomplete exclusively-created output survived')
        fields = [[1,206,100,93,4,1124821,5624199],[1,123,500,2,5,1111111,5555555],
                  [1,524287,700,3,14,2222222,6666666],[1,0,0,0,8,0xffffff,0xffffff]]
        synthetic_table = old_records(fields,tail_value=11)
        widened = rewrite_l3_width23(synthetic_table,record_count=4,
            selected_ranges=[SelectedRange(1,4267896,93)],child_table_count=4267988)
        need(widened.old_unused_tail_bits == 4 and widened.old_unused_tail_value == 11,'Unused tail bits not preserved in metadata')
        need(widened.reader_lookahead == bytes(4) and len(widened.table) == 56,'Lookahead leaked into declared table span')
        for ID,expected in enumerate(fields,1):
            expected = expected.copy()
            if ID == 1:expected[2:4] = [4267896,93]
            need(reference_fields(widened.table,ID,23) == expected,'Selected change modified another field/ID')
        rejected('source_span_width_mismatch',lambda:rewrite_l3_width23(synthetic_table[:-1],record_count=4))
        rejected('record_count_type',lambda:rewrite_l3_width23(synthetic_table,record_count=True))
        rejected('duplicate_selected_ID',lambda:rewrite_l3_width23(synthetic_table,record_count=4,selected_ranges=[SelectedRange(1,1,1),SelectedRange(1,1,1)],child_table_count=10))
        rejected('selected_ID_outside_table',lambda:rewrite_l3_width23(synthetic_table,record_count=4,selected_ranges=[SelectedRange(5,1,1)],child_table_count=10))
        rejected('first_width23_overflow',lambda:rewrite_l3_width23(synthetic_table,record_count=4,selected_ranges=[SelectedRange(1,8388608,1)],child_table_count=8388607))
        rejected('count_width12_overflow',lambda:rewrite_l3_width23(synthetic_table,record_count=4,selected_ranges=[SelectedRange(1,1,4096)],child_table_count=8388607))
        rejected('selected_range_outside_explicit_child_table',lambda:rewrite_l3_width23(synthetic_table,record_count=4,selected_ranges=[SelectedRange(1,9,2)],child_table_count=9))
        rejected('missing_explicit_child_table_count',lambda:rewrite_l3_width23(synthetic_table,record_count=4,selected_ranges=[SelectedRange(1,1,1)]))
        rejected('selected_next5_not_L4',lambda:rewrite_l3_width23(synthetic_table,record_count=4,selected_ranges=[SelectedRange(2,1,1)],child_table_count=10))
        # Sole original source L3 span read and sole full-table conversion.
        source = b''.join(original.iter_component('00004171.MDR',offset=91985204,length=664197))
        converted = rewrite_l3_width23(source)
        need(len(converted.table) == 670180 and converted.old_unused_tail_bits == 6,'Full original L3 span sizes differ')
        old_fields,new_fields = hashlib.sha256(),hashlib.sha256()
        levels = {}
        for ID in range(1,47871):
            a = reference_fields(source,ID,22)
            b = reference_fields(converted.table,ID,23)
            need(a == b,'Original L3 field/ID changed:'+str(ID))
            old_fields.update(struct.pack('<7I',*a));new_fields.update(struct.pack('<7I',*b))
            level = a[4]&7
            levels[level] = levels.get(level,0)+1
        need(old_fields.digest() == new_fields.digest(),'Independent per-field digest differs')
        after = source_path.stat()
        need(identity == [after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns],'Original AP changed during bounded read')
        original_log = original.read_log
    references = []
    for name in ['sources/maps/format-reference/ImgHeader.java','sources/maps/format-reference/Dirent.java',
                 'sources/maps/format-reference/Directory.java','scripts/verify_garmin_map.py']:
        p = ROOT/name;references.append(dict(path=name,sha256=sha(p.read_bytes()),role='local primary format/verifier reference; no old suite run'))
    result = dict(schema='native-AP-general-writer-primitives/v1',created_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        source_sha256=sha((HERE/'native_ap_writer.py').read_bytes()),test_source_sha256=sha(Path(__file__).read_bytes()),
        all_focused_checks_passed=True,references=references,
        streaming_container=dict(synthetic_only=True,input_bytes=len(fixture),output_bytes=len(rebuilt),
            MDR_original_blocks=240,MDR_new_blocks=241,MDR_new_FAT_parts=2,
            old_directory_end=4096,new_directory_end=end,header_prefix_bytes_preserved=512,
            six_component_logical_bytes_checked=True,other5_components_verbatim=True,
            independent_allocation_and_tail_padding_checks=True,stream_chunk_bytes_max=max(chunks_called),receipt=repack_receipt),
        explicit_selected_range=dict(synthetic_street_ID=1,first=4267896,count=93,other_fields_and_IDs_preserved=True,
            next5_and_next6_fields_preserved=True,next5_L4_range_mutation_rejected=True,old_unused_tail_bits=4,old_unused_tail_value=11),
        original_L3=dict(path=str(source_path.relative_to(ROOT)),map_bytes=before.st_size,map_stat_unchanged=True,
            component='00004171.MDR',offset=91985204,source_span_bytes=664197,source_span_sha256=sha(source),
            records=47870,original_record_bits=111,new_record_bits=112,new_span_bytes=670180,new_span_sha256=sha(converted.table),
            new_span_binary_saved=False,full_table_writer_invocations=1,per_record_fields_independently_equal=47870,
            original_fields_digest=old_fields.hexdigest(),converted_fields_digest=new_fields.hexdigest(),
            old_unused_tail_bits=converted.old_unused_tail_bits,old_unused_tail_value=converted.old_unused_tail_value,
            unused_tail_preserved_as_explicit_metadata=True,reader_lookahead_bytes=4,lookahead_inside_declared_span=False,
            low3_child_level_classification=levels,all_original_flags_and_counts_and_refs_and_coordinates_preserved=True,
            selected_original_table_changes=0),
        original_map_read_log=original_log,original_map_total_bytes_read=sum(r['bytes']for r in original_log),
        guards=guards,guard_count=len(guards),actual_process_peak_RSS_KiB=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
        guest_CPU_or_old_guest_suite_executed=False,original_full_IMG_or_MAIN_read_or_hash=False,
        original_full_IMG_repacked_or_copied=False,device_IO=False,canonical_ZIP_or_installation_mutation=False,
        complete_Taiwan_update=False,installable=False,
        limits=['These are offline writer primitives, not an assembled update or proven device-compatible nationwide package.',
            'L3 widening preserves all child-level flags, including5/6; initial selected L4 range mutation is explicitly limited to original next_level4 with a supplied child table count.',
            'Oldunused6bits have no new-span location after byte alignment; their value is retained in result metadata, never silently treated as records. Four lookahead bytes are separate.',
            'Container repacking preserves original header/geometry capacity and metadata templates; outputs beyond original134217728-byte declared capacity are refused, not called a platform limit.',
            'MDR header span/pointer relocation, additional L4/5/6 records, new label allocation, JAI/DB/route relationships and complete native search acceptance must be integrated separately.',
            'New continuation metadata uses the last existing component-row template. Unknown header checksums, geometry expansion and broader IMG variants are unproven.',
            'Stream API may leave an incomplete caller-owned destination on failure; new-path wrapper removes only its own exclusively-created inode. No default real-map output path exists.'])
    output.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(dict(output=str(output.relative_to(ROOT)),proof_sha256=sha(output.read_bytes()),all_passed=True,
        original_records=47870,new_table_bytes=670180,guards=len(guards),next_levels=levels,peak_RSS_KiB=result['actual_process_peak_RSS_KiB']),ensure_ascii=False))


if __name__ == '__main__':main()
