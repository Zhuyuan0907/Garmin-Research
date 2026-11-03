#!/usr/bin/env python3
"""New small suffix/integration cases, plus one bounded original selected plan.

Never emits a real MDR/IMG; never repeats the closed original field suite.
"""
import datetime
import hashlib
import io
import json
from pathlib import Path
import struct
import sys

sys.dont_write_bytecode = True
import mdr_suffix_writer as writer

HERE = Path(__file__).resolve().parent
ROOT = writer.ROOT


def need(ok,message):
    if not ok:raise AssertionError(message)


def sha(raw):return hashlib.sha256(raw).hexdigest()


def serialize(values,widths):
    position,value = 0,0
    for part,width in zip(values,widths):
        need(0 <= part < (1<<width),'Fixture field exceeds its stated width')
        value |= part<<position
        position += width
    return value,position


def fields(raw,ID,firstwidth):
    position = (ID-1)*(89+firstwidth)
    values = []
    for width in [1,19,firstwidth,12,9,24,24]:
        value = 0
        for bit in range(width):
            value |= ((raw[(position+bit)//8]>>((position+bit)%8))&1)<<bit
        values.append(value)
        position += width
    return values


def fragment(raw,sizes=(3,11,2,17,7)):
    cursor,index = 0,0
    while cursor < len(raw):
        count = sizes[index%len(sizes)]
        yield raw[cursor:cursor+count]
        cursor += count
        index += 1


def fixture():
    # Independent fixture layout: nine111-bit records occupy125 bytes.
    counts = [2,3,9,4,2,2]
    specs = [
        (122,[16,9,24,19,1,10,0,0],[1,1]),
        (122,[16,9,24,19,1,10,0,0],[1,1]),
        (111,[22,9,24,19,1,12,0,0],[1,0]),
        (128,[22,9,24,19,1,10,0,0],[1,1]),
        (126,[21,9,24,19,1,9,0,0],[1,1]),
        (68,[0,0,24,19,1,0,0,0],[1,0]),
    ]
    rows = [
        [1,101,1,2,4,100001,200001],
        [1,102,1,1,5|8,100002,200002],
        [1,103,1,1,6|0x100,100003,200003],
    ]+[[1,104+i,3,2,4|(i<<3),100004+i,200004+i]for i in range(6)]
    packed = sum(serialize(row,[1,19,22,12,9,24,24])[0]<<(i*111)for i,row in enumerate(rows))
    l3 = packed.to_bytes(125,'little')
    l4rows = [serialize([1,31+i,10+i,2+i,(5,6,8,0)[i],300+i,400+i,0x7ffff],
                        [1,19,22,10,9,24,24,19])[0].to_bytes(16,'little')for i in range(4)]
    bodies = {}
    for level,(bits,_,_) in enumerate(specs,1):
        length = (counts[level-1]*bits+7)//8
        bodies[level] = bytes((level*19+i*7)&255 for i in range(length))
    bodies[3] = l3
    bodies[4] = b''.join(l4rows)
    bodies[2] = bytes.fromhex('deadbeef')+bodies[2][4:]
    raw = bytearray((i*29+71)&255 for i in range(900))
    struct.pack_into('<H',raw,0,772)
    raw[2:12] = b'GARMIN MDR'
    starts = {}
    for level in [6,5,4,3,2,1]:
        starts[level] = len(raw)
        raw.extend(bodies[level])
    directory_start = len(raw)
    struct.pack_into('<4I',raw,600,directory_start,120,20,1)
    directory = bytearray()
    for level,(stride,widths,flags) in enumerate(specs,1):
        w0,w1,w2,w3,w4,w5,w6,w7 = widths
        w = w4|(w3<<6)|(w2<<12)|(w0<<18)|(w1<<24)|(flags[0]<<30)|(flags[1]<<31)
        x = w5|(w6<<11)|(w7<<17)|(0x15<<6)|(0xa5<<23) # Unknown/reserved bits.
        directory.extend(struct.pack('<5I',starts[level],len(bodies[level]),stride,w,x))
    raw.extend(directory)
    added = l4rows[:2]+[serialize([1,500,0,0,0,600,700,0x7ffff],
                                [1,19,22,10,9,24,24,19])[0].to_bytes(16,'little')]
    return dict(raw=bytes(raw),starts=starts,bodies=bodies,rows=rows,counts=counts,
                directory_start=directory_start,added=b''.join(added))


def source_for(raw, *, source_chunks=None,read=None,unchanged=lambda:True,capacity=None):
    return writer.MDRSource(len(raw),read or (lambda offset,length:bytes(raw[offset:offset+length])),
        source_chunks or (lambda offset,length:fragment(bytes(raw[offset:offset+length]))),unchanged,capacity)


def plan_fixture(f, *, source=None,supplier=None,count=3,selected=None):
    return writer.plan_mdr_rewrite(source or source_for(f['raw']),new_l4_count=count,
        new_l4_supplier=supplier or (lambda:fragment(f['added'],(7,2,19,1))),
        selected_ranges=(writer.SelectedRange(1,5,3),) if selected is None else selected,
        synthetic_fixture=True)


def directory_expected(f,plan):
    old = f['raw'][f['directory_start']:]
    result = bytearray(old)
    # Expected allowable mutations, independently specified per word.
    changes = {0:plan.report['delta'],20:plan.report['delta'],40:48,44:1,48:1,64:48}
    for at,delta in changes.items():
        struct.pack_into('<I',result,at,struct.unpack_from('<I',old,at)[0]+delta)
    at = 52
    word = struct.unpack_from('<I',old,at)[0]
    struct.pack_into('<I',result,at,(word&~(63<<18))|(23<<18))
    return bytes(result)


def tiny_container(mdr):
    core = writer.core
    contents = {name:bytes((i*13+ord(name[0]))&255 for i in range(27+j*3))
                for j,name in enumerate(core.AP_NAMES)}
    contents['00004171.MDR'] = mdr
    prefix = bytearray(4096)
    prefix[16:23] = b'DSKIMG\0';prefix[65:72] = b'GARMIN\0'
    prefix[0x40] = 8;prefix[97] = 9;prefix[98] = 3
    struct.pack_into('<H',prefix,0x63,32768)
    struct.pack_into('<I',prefix,0x1ca,262144)
    prefix[510:512] = b'\x55\xaa';prefix[700:709] = b'untouched'
    def row(name,size,blocks,root=False):
        value = bytearray(512)
        value[0] = 1
        value[1:12] = b' '*11 if root else name.split('.')[0].encode().ljust(8,b' ')+name.split('.')[1].encode()
        struct.pack_into('<I',value,12,size)
        value[16] = 3 if root else 0
        value[19:32] = b'metadata keep'
        struct.pack_into('<240H',value,32,*(blocks+[65535]*(240-len(blocks))))
        return bytes(value)
    directory = row('',8192,[0,1],True)
    for index,name in enumerate(core.AP_NAMES,2):directory += row(name,len(contents[name]),[index])
    directory += bytes(4096-len(directory))
    body = b''.join(contents[name]+bytes((-len(contents[name]))%4096)for name in core.AP_NAMES)
    return bytes(prefix)+directory+body,contents


def synthetic_success():
    f = fixture()
    plan = plan_fixture(f)
    result = b''.join(plan.chunks())
    need(len(result) == plan.size == len(f['raw'])+49,'Synthetic append+widen exact EOF differs')
    old4end = f['starts'][4]+len(f['bodies'][4])
    need(result[:600] == f['raw'][:600] and result[604:old4end] == f['raw'][604:old4end],
         'Header unknown bytes/prefix/original level6/5/4 changed')
    need(result[old4end:old4end+48] == f['added'],'Added records changed while crossing chunks')
    new3,new2,new1 = plan.new_tables[2],plan.new_tables[1],plan.new_tables[0]
    need(result[new3['start']:new3['start']+new3['bytes']] == plan.table,'Declared new L3 span differs')
    need(result[new2['start']:new2['start']+new2['bytes']] == f['bodies'][2] and
         result[new1['start']:new1['start']+new1['bytes']] == f['bodies'][1],'L2/L1 body preservation differs')
    need(result[new3['start']+new3['bytes']:new3['start']+new3['bytes']+4] == bytes.fromhex('deadbeef'),
         'L3 lookahead is not exactly following real L2 bytes')
    need(result[plan.new_directory_start:] == directory_expected(f,plan),'Unexpected directory-bit mutation')
    need(struct.unpack_from('<4I',result,600) == (f['directory_start']+49,120,20,1),'Header descriptor changed elsewhere')
    controls = []
    for ID,original in enumerate(f['rows'],1):
        actual = fields(plan.table,ID,23)
        expected = list(original)
        if ID == 1:expected[2:4] = [5,3]
        need(actual == expected,'Small-fixture L3 field preservation/selection differs')
        controls.append(dict(ID=ID,before=original,after=actual))
    # A normal zero-append conversion is also a complete suffix stream.
    empty = writer.plan_mdr_rewrite(source_for(f['raw']),new_l4_count=0,new_l4_supplier=lambda:iter(()),synthetic_fixture=True)
    emptyraw = b''.join(empty.chunks())
    need(empty.size == len(f['raw'])+1 and emptyraw[empty.new_tables[1]['start']:
         empty.new_tables[1]['start']+4] == bytes.fromhex('deadbeef'),'Zero-append widen boundary differs')
    # A new small integration case only: the suffix Replacement feeds the
    # sealed repacker; this is not the closed 240-block/container control suite.
    original,contents = tiny_container(f['raw'])
    image = writer.core.StreamIMG(io.BytesIO(original))
    source = source_for(f['raw'],capacity=lambda size:writer.core.plan_repack(image,{'00004171.MDR':size}))
    integrated_plan = plan_fixture(f,source=source)
    destination = io.BytesIO()
    receipt = writer.core.repack_stream(image,destination,{'00004171.MDR':integrated_plan.replacement()})
    rebuilt = writer.core.StreamIMG(io.BytesIO(destination.getvalue()))
    for name in image.order:
        content = b''.join(rebuilt.iter_component(name))
        need(content == (result if name == '00004171.MDR' else contents[name]),'Synthetic integrated component differs')
    need(receipt['original_declared_capacity'] == 134217728,'Original-capacity byte units differ')
    return dict(all_passed=True,fixture_bytes=len(f['raw']),output_bytes=len(result),
        output_sha256=sha(result),source_stream_chunk_sizes=[3,11,2,17,7],append_chunk_sizes=[7,2,19,1],
        appended_records=3,L3_original_span=125,L3_new_span=126,L3_growth=1,
        selected_field_checks=controls,all_other_prefix_header_directory_and_L2_L1_bytes_checked=True,
        actual_L2_lookahead_hex='deadbeef',inserted_lookahead_bytes=0,zero_append_complete_stream_checked=True,
        integration=dict(synthetic_IMG_bytes=len(original),output_IMG_bytes=len(destination.getvalue()),
            suffix_replacement_fed_to_sealed_repack_stream=True,six_logical_components_checked=True,receipt=receipt))


def negative_cases():
    f = fixture();cases = []
    def rejected(name,call,fragment='',kind=ValueError):
        try:call()
        except kind as exc:
            need(fragment in str(exc),'Unexpected rejection for '+name+': '+str(exc))
            cases.append(dict(name=name,rejected=True,exception=type(exc).__name__,message=str(exc)))
        else:raise AssertionError('Guard failed: '+name)
    def modified(at,value,fmt='<I'):
        raw = bytearray(f['raw']);struct.pack_into(fmt,raw,at,value);return source_for(bytes(raw))
    rejected('header_size',lambda:plan_fixture(f,source=modified(0,771,'<H')),'772-byte')
    rejected('directory_descriptor_bytes',lambda:plan_fixture(f,source=modified(604,119)),'descriptor')
    rejected('directory_descriptor_item_size',lambda:plan_fixture(f,source=modified(608,16)),'descriptor')
    rejected('directory_descriptor_flags',lambda:plan_fixture(f,source=modified(612,0)),'descriptor')
    rejected('directory_at_component_EOF',lambda:plan_fixture(f,source=modified(600,f['directory_start']-1)),'EOF')
    rejected('physical_table_gap',lambda:plan_fixture(f,source=modified(f['directory_start']+80,f['starts'][5]-1)),'sequence/gap')
    rejected('candidate_width23_source',lambda:plan_fixture(f,source=modified(f['directory_start']+52,
        (struct.unpack_from('<I',f['raw'],f['directory_start']+52)[0]&~(63<<18))|(23<<18))),'stock original profile')
    rejected('candidate_stride112_source',lambda:plan_fixture(f,source=modified(f['directory_start']+48,112)),'stock original profile')
    tail = bytearray(f['raw']);tail[f['starts'][3]+124] |= 0x80
    rejected('nonzero_unused_L3_tail',lambda:plan_fixture(f,source=source_for(bytes(tail))),'unused tail')
    rejected('selected_original_next5',lambda:plan_fixture(f,selected=(writer.SelectedRange(2,5,3),)),'next_level4')
    invalid = bytearray(f['raw']);bit=f['starts'][3]*8+20
    invalid[bit//8:bit//8+4] = ((int.from_bytes(invalid[bit//8:bit//8+4],'little')&~(0x3fffff<<(bit%8)))|
        (4<<(bit%8))).to_bytes(4,'little')
    rejected('selected_invalid_original_range',lambda:plan_fixture(f,source=source_for(bytes(invalid))),'valid nonempty')
    rejected('append_count_bool',lambda:plan_fixture(f,count=True),'finite unsigned')
    rejected('append_count_negative',lambda:plan_fixture(f,count=-1),'finite unsigned')
    rejected('append_count_uint_overflow',lambda:plan_fixture(f,count=1<<32),'finite unsigned')
    rejected('new_child_profile_overflow',lambda:plan_fixture(f,count=0x7fffff),'23-bit')
    rejected('append_callback_not_callable',lambda:writer.plan_mdr_rewrite(source_for(f['raw']),new_l4_count=3,
        new_l4_supplier=b'bad',synthetic_fixture=True),'callable')
    rejected('short_bounded_read',lambda:plan_fixture(f,source=source_for(f['raw'],
        read=lambda offset,length:f['raw'][offset:offset+length-1])),'byte type/count')
    rejected('wrong_bounded_read_type',lambda:plan_fixture(f,source=source_for(f['raw'],
        read=lambda offset,length:bytearray(f['raw'][offset:offset+length]))),'byte type/count')
    rejected('changed_before_plan',lambda:plan_fixture(f,source=source_for(f['raw'],unchanged=lambda:False)),'changed before')
    reads = []
    def read(offset,length):reads.append([offset,length]);return f['raw'][offset:offset+length]
    def no_capacity(size):raise ValueError('Explicit declared capacity rejected')
    rejected('capacity_rejected_before_L3_read',lambda:plan_fixture(f,source=source_for(f['raw'],read=read,
        capacity=no_capacity)),'capacity rejected')
    need(reads == [[0,772],[f['directory_start'],120]],'Capacity guard consumed L3/append data')
    cases[-1]['bounded_reads_before_rejection'] = reads
    rejected('capacity_callback_missing_plan',lambda:plan_fixture(f,source=source_for(f['raw'],capacity=lambda _:None)),'validated plan')
    rejected('capacity_callback_overflow',lambda:plan_fixture(f,source=source_for(f['raw'],capacity=lambda _:
        dict(image_bytes=134217729,original_declared_capacity=134217728))),'exceeds declared')
    def consumed(**kwargs):return b''.join(plan_fixture(f,**kwargs).chunks())
    rejected('append_truncated_mid_record',lambda:consumed(supplier=lambda:iter([f['added'][:-1]])),'truncated')
    rejected('append_oversized',lambda:consumed(supplier=lambda:iter([f['added']+b'x'])),'exceeds explicit')
    rejected('append_bare_bytes',lambda:consumed(supplier=lambda:f['added']),'yield byte chunks')
    rejected('append_empty_chunk',lambda:consumed(supplier=lambda:iter([b'',f['added']])),'nonempty bytes')
    badmap = bytes([f['added'][0]&~1])+f['added'][1:]
    rejected('append_bad_mapordinal',lambda:consumed(supplier=lambda:iter([badmap])),'mapordinal1')
    rejected('append_oversized_chunk',lambda:consumed(supplier=lambda:iter([bytes(65537)])),'at most64KiB')
    rejected('typed_memoryview_oversized_bytes',lambda:consumed(supplier=lambda:iter([memoryview(bytes(65540)).cast('I')])),'at most64KiB')
    def failed_supplier():
        yield f['added'][:16]
        raise RuntimeError('Supplier deliberately failed midstream')
    rejected('append_callback_failure',lambda:consumed(supplier=failed_supplier),'deliberately failed',RuntimeError)
    rejected('source_supplier_truncated',lambda:consumed(source=source_for(f['raw'],source_chunks=lambda offset,length:
        iter([f['raw'][offset:offset+length-1]]))),'truncated')
    rejected('source_supplier_oversized',lambda:consumed(source=source_for(f['raw'],source_chunks=lambda offset,length:
        iter([f['raw'][offset:offset+length]+b'x']))),'exceeds declared')
    rejected('source_supplier_bare_bytes',lambda:consumed(source=source_for(f['raw'],source_chunks=lambda offset,length:
        f['raw'][offset:offset+length])),'iterable of chunks')
    mutable = bytearray(f['raw']);plan = plan_fixture(f,source=source_for(mutable))
    mutable[f['starts'][2]] ^= 1
    rejected('L2_lookahead_changed_after_plan',lambda:b''.join(plan.chunks()),'lookahead changed')
    state = dict(stable=True)
    def changed_chunks(offset,length):
        yield f['raw'][offset:offset+length]
        state['stable'] = False
    changed = plan_fixture(f,source=source_for(f['raw'],source_chunks=changed_chunks,unchanged=lambda:state['stable']))
    rejected('source_changed_during_stream',lambda:b''.join(changed.chunks()),'changed during streaming')
    # Counting actual bytes of a typed memoryview prevents logical truncation.
    typed = plan_fixture(f,supplier=lambda:iter([memoryview(f['added']).cast('I')]))
    need(b''.join(typed._appended_chunks()) == f['added'],'Typed memoryview byte count differs')
    return dict(all_passed=True,rejection_count=len(cases),cases=cases,typed_memoryview_exact_bytes_checked=True)


def actual_selected_plan():
    source_path = ROOT/'backups/20261002T154458Z/files/.System/gmapprom1.img'
    witness_path = ROOT/'staging/navigation-AP-MinQuan184-witness-v1/stock-MinQuan184-bounded-source-proof-v1.json'
    witness_raw = witness_path.read_bytes()
    need(sha(witness_raw) == '628a5452cfe8c1097a844fe9376d620d7240319fce4488dc7783a37010bf2774','Frozen old84 witness changed')
    witness = json.loads(witness_raw)
    manifest_path = ROOT/'staging/navigation-native-address-supplement-v1/manifest.json'
    manifest_raw = manifest_path.read_bytes()
    manifest = json.loads(manifest_raw)
    rows = [r for r in manifest['records'] if r['oldID'] is not None or r['label'] == '6號']
    old = [r for r in rows if r['oldID'] is not None]
    need(len(rows) == 85 and len(old) == 84,'Cached prototype count differs')
    need([(r['oldID'],r['payload'])for r in old] == [(r['lowID'],r['record_hex'])for r in witness['all84_rows_with_frozen_boundaries']],
         'Cached original84 payload/order differs')
    new = [r for r in rows if r['oldID'] is None]
    need(len(new) == 1 and new[0]['label'] == '6號' and new[0]['primary_ref'] == 23,'Cached existing-reference sample differs')
    cached = b''.join(bytes.fromhex(r['payload'])for r in rows)
    calls = []
    def supplier():
        calls.append('called')
        return fragment(cached,(17,7,31))
    before = source_path.stat()
    with source_path.open('rb') as f:
        image = writer.core.StreamIMG(f)
        source = writer.MDRSource.from_container(image)
        plan = writer.plan_mdr_rewrite(source,new_l4_count=85,new_l4_supplier=supplier,
            selected_ranges=(writer.SelectedRange(16707,2133949,85),))
        need(plan.old_tables[2]['start'] == 91983716 and plan.old_tables[2]['bytes'] == 664197,'Actual stock source derived incorrectly')
        need(plan.size == 92660943 and plan.new_directory_start == 92660823 and
             plan.new_tables[2]['start'] == 91985076 and plan.new_tables[1]['start'] == 92655256 and
             plan.new_tables[0]['start'] == 92660487,'Actual selected plan positions differ')
        selected = fields(plan.table,16707,23)
        need(selected[2:4] == [2133949,85] and selected[4]&7 == 4,'Actual selected range was not reencoded')
        replacement = plan.replacement()
        need(type(replacement) is writer.core.Replacement and replacement.size == plan.size,'Replacement handoff type/size differs')
        need(not calls,'Actual plan consumed append stream/full prefix')
        need(sum(r['bytes']for r in image.read_log) == 722437,'Actual bounded new-scope reads differ')
        read_log = list(image.read_log)
        capacity_plan = writer.core.plan_repack(image,{'00004171.MDR':plan.size})
        # New production plan negative controls: capacity must reject before
        # L3 read; a plausible modified directory must not pass as original.
        prior = len(image.read_log)
        try:writer.plan_mdr_rewrite(source,new_l4_count=3000000,new_l4_supplier=lambda:iter(()))
        except ValueError as exc:
            need('declared container capacity' in str(exc),'Unexpected actual capacity rejection')
            overcap = dict(rejected=True,message=str(exc),new_original_read_log=image.read_log[prior:])
        else:raise AssertionError('Actual original-capacity overflow accepted')
        need(sum(r['bytes']for r in image.read_log[prior:]) == 892,'Capacity rejection read more than MDR metadata')
        extra_control_bytes = sum(r['bytes']for r in image.read_log[prior:])
        need(source.unchanged(),'Actual AP changed')
    after = source_path.stat()
    need((before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns) ==
         (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns),'Actual source stat changed')
    return dict(all_passed=True,source=str(source_path.relative_to(ROOT)),source_size=before.st_size,stat_unchanged=True,
        plan=plan.report,selected_ID16707_after=selected,
        cached_supply=dict(old84_witness_path=str(witness_path.relative_to(ROOT)),old84_witness_sha256=sha(witness_raw),
            new6_manifest_path=str(manifest_path.relative_to(ROOT)),new6_manifest_sha256=sha(manifest_raw),
            cached85_bytes=len(cached),cached85_sha256=sha(cached),all84_original_payloads_and_relative_order_retained=True,
            append_callback_calls=0,actual_plan_only=True),
        replacement_type_checked_without_execution=True,actual_plan_original_read_log=read_log,
        actual_plan_original_bytes_read=722437,actual_capacity_negative=overcap,
        actual_extra_capacity_guard_read_bytes=extra_control_bytes,total_new_scope_original_bytes_read=722437+extra_control_bytes,
        planned_container_bytes=capacity_plan['image_bytes'],original_declared_capacity=capacity_plan['original_declared_capacity'],
        actual_L3_reads=1,actual_width_rewriter_invocations=1,actual_full_MDR_IMG_streams_executed=0,
        previous_all47870_field_suite_or_CPU_suite_replayed=False)


def main():
    output = HERE/'MDR-streaming-suffix-writer-proof-v1.json'
    need(not output.exists(),'Refuse overwrite terminal MDR scope')
    synthetic = synthetic_success()
    negative = negative_cases()
    actual = actual_selected_plan()
    result = dict(schema='native-MDR-streaming-suffix-writer/v1',created_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        source_sha256=sha((HERE/'mdr_suffix_writer.py').read_bytes()),test_sha256=sha(Path(__file__).read_bytes()),
        sealed_AP_primitive=dict(path=str(writer.SEALED_WRITER.relative_to(ROOT)),sha256=writer.SEALED_SHA),
        corrected_original_source=dict(path=str(writer.CORRECTED_PROOF.relative_to(ROOT)),sha256=writer.CORRECTED_SHA),
        synthetic_suffix_and_small_container_integration=synthetic,new_MDR_specific_negative_controls=negative,
        actual_stock_bounded_selected_plan=actual,all_checks_passed=True,
        full_MDR_or_large_IMG_output=False,USB_or_services_or_canonical_or_ZIP_mutated=False,CPU_suite_executed=False,
        complete_Taiwan_address_update=False,installable_candidate=False,
        limits=['Streaming suppliers execute only when callers consume MDRPlan.chunks()/Replacement; incomplete streams are failures.',
            'Only synthetic small-container suffix/repacker integration executed; actual stock test stopped at plan and one selected L3 record.',
            'Original directory/table binding is to corrected-source-v2, never the withdrawn v1 offset.',
            'This appends preencoded L4 bytes and changes selected existing next4 ranges; it does not encode new street hierarchy, JAI, LBL, or routing.',
            'Original AP declared capacity is134217728bytes(128MiB); no container geometry expansion or platform capacity claim.',
            'New house references/coordinates/labels, full candidate/native query, and physical acceptance require the separate integration work.'])
    output.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(dict(output=str(output.relative_to(ROOT)),proof_sha256=sha(output.read_bytes()),all_passed=True,
        synthetic_rejections=negative['rejection_count'],actual_plan_bytes_read=actual['total_new_scope_original_bytes_read'],
        actual_full_stream_executed=False,actual_newMDRsize=actual['plan']['new_size'],
        actual_new_directory=actual['plan']['new_directory_start'],planned_IMG_bytes=actual['planned_container_bytes'])))


if __name__ == '__main__':main()
