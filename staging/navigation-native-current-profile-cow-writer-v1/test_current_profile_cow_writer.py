#!/usr/bin/env python3
"""NEW small current-profile controls, independent bit/FAT readback.

No old test runner, real source IMG, source ledger or device is opened.
"""
from dataclasses import replace
import datetime
import hashlib
import io
import json
from pathlib import Path
import struct
import sys
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0,str(HERE))
import current_profile_cow_writer as w


def check(ok,message):
    if not ok:
        raise AssertionError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def packed(values,width):
    # Independent absolute-position reference, not writer accumulator logic.
    combined = sum(value << (ordinal*width) for ordinal,value in enumerate(values))
    return combined.to_bytes((len(values)*width+7)//8,'little')


def values_at(raw,count,width):
    value = int.from_bytes(raw,'little');mask = (1<<width)-1
    return [(value >> (i*width)) & mask for i in range(count)]


def descriptor(start,count,profile):
    stride,widths,flags = profile
    a = (widths[0]<<18)|(widths[1]<<24)|(widths[2]<<12)|(widths[3]<<6)|widths[4]|flags[0]<<30|flags[1]<<31
    b = widths[5]|widths[6]<<11|widths[7]<<17
    return struct.pack('<5I',start,(count*stride+7)//8,stride,a,b)


def current_mdr():
    counts = [2,3,3,4,5,3]
    values = {}
    for level,(profile,count) in enumerate(zip(w.PROFILE,counts),1):
        width = profile[0]
        values[level] = [((1<<(width-1)) | (0x111+(level*0x101+i)*2)) & ((1<<width)-1) for i in range(count)]
    # Each L3 root has a current valid branch into a different lower table.
    values[3] = [1 | (71+i)<<1 | 1<<20 | 1<<43 | level<<55 | (900+i)<<64 | (1200+i)<<88
                 for i,level in enumerate((4,5,6))]
    # Old lower records include raw13 and ordinary branch/leaf bit patterns.
    values[4][0] = 1 | 123<<1 | 77<<20 | 1<<39 | 1<<61 | 6<<71 | 100<<80 | 200<<104
    values[4][1] = 1 | 321<<1 | 91<<20 | 13<<71 | 101<<80 | 201<<104
    values[5][0] = 1 | 222<<1 | 80<<20 | 1<<39 | 1<<60 | 6<<69 | 300<<78 | 400<<102
    values[5][1] = 1 | 223<<1 | 81<<20 | 13<<69 | 301<<78 | 401<<102
    prefix = bytes((i*31+3)%256 for i in range(1021))
    header = bytearray(772);struct.pack_into('<H',header,0,772);header[2:12] = b'GARMIN MDR'
    header[19:598] = bytes((i*17)%256 for i in range(579))
    cursor = 772+len(prefix);tables = {};suffix = bytearray()
    for level in (6,5,4,3,2,1):
        raw = packed(values[level],w.PROFILE[level-1][0]);tables[level] = {'start':cursor,'bytes':len(raw),'count':counts[level-1]}
        suffix.extend(raw);cursor += len(raw)
    directory = b''.join(descriptor(tables[i]['start'],counts[i-1],w.PROFILE[i-1]) for i in range(1,7))
    struct.pack_into('<4I',header,600,cursor,120,20,1)
    return bytes(header)+prefix+bytes(suffix)+directory,values,tables,prefix


def source_for(raw,unchanged=lambda:True):
    return w.CurrentMDRSource(len(raw),lambda at,n:raw[at:at+n],
        lambda at,n: (raw[i:min(i+7,at+n)] for i in range(at,at+n,7)),unchanged)


def row(name,size,part,blocks,marker,root=False):
    raw = bytearray(512);raw[0] = 1
    a,b = name.split('.');raw[1:9] = a.encode().ljust(8,b' ');raw[9:12] = b.encode().ljust(3,b' ')
    struct.pack_into('<I',raw,12,size if part == 0 else 0);raw[16] = 3 if root else 0
    struct.pack_into('<H',raw,17,part);raw[19:32] = bytes([marker])*13
    struct.pack_into('<240H',raw,32,*(blocks+[65535]*(240-len(blocks))))
    return bytes(raw)


def image_for(mdr):
    cap = json.loads((ROOT/'staging/navigation-img-capacity-header-comparison-v1/stock-header-comparison.json').read_text())
    header = bytes.fromhex(next(x['header_hex'] for x in cap['headers'] if x['source'].endswith('gmapprom1.img')))
    names = w.eight().AP_NAMES
    components = {name:bytes((i*7+j)%256 for i in range(n)) for j,(name,n) in enumerate(zip(names,[17,len(mdr),37,8193,53,11]))}
    components['00004171.MDR'] = mdr
    metadata_blocks = 2;cursor = metadata_blocks;blocks = {}
    for name in names:
        count = (len(components[name])+4095)//4096;blocks[name] = list(range(cursor,cursor+count));cursor += count
        blocks[name].reverse()  # Exercise logical reads across noncontiguous FAT.
    raw = bytearray(cursor*4096);raw[:512] = header
    raw[512:4096] = bytes((i*11)%256 for i in range(3584))
    raw[4096:4608] = row('.',8192,0,[0,1],239,True)
    for i,name in enumerate(names):
        at = 4608+i*512;raw[at:at+512] = row(name,len(components[name]),0,blocks[name],81+i)
        for ordinal,block in enumerate(blocks[name]):
            data = components[name][ordinal*4096:(ordinal+1)*4096]
            raw[block*4096:block*4096+len(data)] = data
    return bytes(raw),components


def independent_image_read(raw):
    # Manual little-endian FAT allocation, no writer/base container parser.
    block = 1 << (raw[97]+raw[98]);start = raw[64]*512
    root = raw[start:start+512];end = int.from_bytes(root[12:16],'little')
    check(end%block == 0,'Independent directory alignment')
    roots = [int.from_bytes(root[i:i+2],'little') for i in range(32,512,2)]
    roots = [b for b in roots if b != 65535]
    check(roots == list(range(end//block)),'Independent root allocation')
    owned = set(roots);result = {};metadata = {}
    for at in range(start+512,end,512):
        entry = raw[at:at+512]
        if entry[0] == 0:
            check(entry == bytes(512),'Unused row must be zero');continue
        name = entry[1:9].decode().strip()+'.'+entry[9:12].decode().strip()
        check(entry[0] == 1 and entry[16] != 3 and name not in result,'Independent unique active component')
        check(int.from_bytes(entry[17:19],'little') == 0,'Tiny single-part fixture')
        size = int.from_bytes(entry[12:16],'little');ids = [];padding = False
        for i in range(32,512,2):
            b = int.from_bytes(entry[i:i+2],'little')
            if b == 65535:
                padding = True;continue
            check(not padding and b not in owned and (b+1)*block <= len(raw),'Independent allocation bounds/alias')
            owned.add(b);ids.append(b)
        check(len(ids) == (size+block-1)//block,'Independent allocated component blocks')
        storage = b''.join(raw[b*block:(b+1)*block] for b in ids)
        check(storage[size:] == bytes(len(storage)-size),'Independent zero tail padding')
        result[name] = storage[:size];metadata[name] = entry[:12]+entry[16:17]+entry[19:32]
    check(len(result) == 6 and len(owned)*block == len(raw),'Independent six components and whole allocation')
    return result,metadata,block


def main():
    result_path = HERE/'new-current-profile-controls-proof.json'
    check(not result_path.exists(),'Refuse overwrite completed controls')
    positives = [];guards = []
    def rejected(name,call):
        try:
            call()
        except (ValueError,TypeError,OSError) as error:
            guards.append({'case':name,'rejected':True,'reason':str(error)})
        else:
            raise AssertionError('No rejection: '+name)
    raw,old,tables,prefix = current_mdr();source = source_for(raw)
    # Explicit copied-parent payloads: producer performs these field patches.
    clone4 = (old[4][0] & ~(((1<<32)-1)<<39)) | (6<<39) | (3<<61)
    clone5 = (old[5][0] & ~(((1<<30)-1)<<39)) | (4<<39) | (2<<60)
    appended = {4:[clone4,old[4][1],0x12345|1],5:[clone5,old[5][1],0x23457],6:[0x45679,0x34567]}
    appends = {level:w.PackedAppend.from_records(level,len(values),lambda values=values,level=level:
        iter(value.to_bytes((w.STRIDES[level]+7)//8,'little') for value in values)) for level,values in appended.items()}
    selected = [w.SelectedRange(i,tables[level]['count']+1,len(appended[level]),level,level) for i,level in enumerate((4,5,6),1)]
    plan = w.plan_current_mdr(source,appends=appends,selected_ranges=selected,synthetic_fixture=True)
    actual = b''.join(plan.chunks());check(len(actual) == plan.size,'Full replacement MDR byte length')
    check(actual[:600] == raw[:600] and actual[604:772] == raw[604:772],'Unknown MDR header bytes preserved')
    check(actual[772:772+len(prefix)] == prefix,'Unknown pre-table prefix preserved')
    for level in (6,5,4):
        t = plan.new_tables[level-1];wire = actual[t['start']:t['start']+t['bytes']]
        check(values_at(wire,t['count'],t['stride']) == old[level]+appended[level],'Independent every current+append record'+str(level))
        check(wire == packed(old[level]+appended[level],t['stride']),'Independent tight bytes'+str(level))
        old_bits = tables[level]['count']*w.STRIDES[level]
        check((int.from_bytes(wire,'little') & ((1<<old_bits)-1)) == int.from_bytes(packed(old[level],w.STRIDES[level]),'little'),
              'Current significant prefix preserved'+str(level))
    positives.append({'case':'current_lower_tables_full_significant_prefix_and_appends','old_L5_unused_bits':2,'old_L6_unused_bits':4,
                      'all_old_and_appended_records_checked':sum(len(v) for v in old.values())+sum(len(v) for v in appended.values())})
    check((clone4 ^ old[4][0]) & ~(((1<<32)-1)<<39) == 0,'Producer clone4 only first/count')
    check((clone5 ^ old[5][0]) & ~(((1<<30)-1)<<39) == 0,'Producer clone5 only first/count')
    check(appended[4][1] == old[4][1] and appended[5][1] == old[5][1],'Raw13 records unchanged')
    positives.append({'case':'copied_parent_payloads_and_raw13_verbatim','producer_owned_range_edits':True})
    for change in selected:
        at = plan.new_tables[2]['start']+(change.one_based_street_ID-1)*14
        value = int.from_bytes(actual[at:at+14],'little');oldvalue = old[3][change.one_based_street_ID-1]
        check(((value>>20)&0x7fffff,(value>>43)&0xfff) == (change.first_child,change.count),'Actual L3 new link')
        check((value^oldvalue) & ~(((1<<35)-1)<<20) == 0,'All L3 nonrange significant fields unchanged')
    for level in (2,1):
        new = plan.new_tables[level-1];oldtable = tables[level]
        check(actual[new['start']:new['start']+new['bytes']] == raw[oldtable['start']:oldtable['start']+oldtable['bytes']],
              'L2/L1 complete bytes unchanged')
    for i in range(6):
        check(plan.directory[i*20+8:i*20+20] == raw[-120+i*20+8:len(raw)-120+i*20+20], 'Full stride/descriptor bitfields unchanged')
    positives.append({'case':'three_current_L3_branches_only_first_count_and_real_L2_lookahead','L3_stride':112,'first_width':23})
    # Independent splice reference with irregular chunks and carry every offset.
    for carry in range(8):
        a = (1<<(17+carry))-3;b = (1<<23)-5
        abits,bbits = 17+carry,23
        def supplier(value,bits):
            wire = value.to_bytes((bits+7)//8,'little')
            return lambda:iter(bytes([x]) for x in wire)
        wire = b''.join(w.bit_splice(((abits,supplier(a,abits)),(bbits,supplier(b,bbits)))))
        reference = (a | b<<abits).to_bytes((abits+bbits+7)//8,'little')
        check(wire == reference,'Carry'+str(carry))
    positives.append({'case':'independent_all_eight_bit_carries_one_byte_chunks'})
    a = (1<<524289)-1;b = 7
    big = a.to_bytes((524289+7)//8,'little')
    wire = b''.join(w.bit_splice(((524289,lambda:iter([big[:65536],big[65536:]])),(3,lambda:iter([b'\x07'])))))
    check(wire == (a | b<<524289).to_bytes((524292+7)//8,'little'),'64KiB carry boundary')
    positives.append({'case':'new_64KiB_carry_boundary'})
    image_raw,components = image_for(raw);image = w.eight().Source4K(io.BytesIO(image_raw))
    adapter = w.Explicit8KAdapter.from_container(image,synthetic_fixture=True)
    imageplan = w.plan_current_mdr(adapter.source,appends=appends,selected_ranges=selected,synthetic_fixture=True)
    bound = imageplan.bind_container(adapter);out = io.BytesIO();receipt = bound.repack_stream(out)
    got,metadata,block = independent_image_read(out.getvalue());check(block == 8192,'Explicit8K output')
    for name,component in components.items():
        expected = actual if name == '00004171.MDR' else component
        check(got[name] == expected,'Independent full component readback:'+name)
        original_row = image.components[name].rows[0]
        check(metadata[name] == original_row[:12]+original_row[16:17]+original_row[19:32],'Component metadata preserved:'+name)
    check(out.getvalue()[512:4096] == image_raw[512:4096],'Container prefix512..dirStart unchanged')
    changes = [i for i,(a,b) in enumerate(zip(image_raw[:512],out.getvalue()[:512])) if a != b]
    check(set(changes) <= {15,24,25,95,96,98,458,459,460,461},'Only exact allowed header offsets')
    check(not receipt['header_checksum_rule_known'] and not receipt['device_acceptance_verified'],'Unknown real checksum/device not claimed')
    positives.append({'case':'tiny_current4K_to_explicit8K_full_six_component_FAT_prefix_readback',
                      'source_bytes':len(image_raw),'output_bytes':len(out.getvalue()),'changed_header_byte_offsets':changes})
    # Empty append identity preserves even each lower final zero-padding byte.
    empty = {level:w.PackedAppend.empty(level) for level in (4,5,6)}
    identity = w.plan_current_mdr(source,appends=empty,synthetic_fixture=True)
    check(b''.join(identity.chunks()) == raw,'Current identity MDR unchanged')
    positives.append({'case':'current_profile_zero_append_identity'})
    def fail_supplier():
        raise AssertionError('Plan/capacity must not consume append')
    lazy = {level:w.PackedAppend(level,len(appended[level]),len(appended[level])*w.STRIDES[level],fail_supplier) for level in (4,5,6)}
    lazyplan = w.plan_current_mdr(adapter.source,appends=lazy,selected_ranges=selected,synthetic_fixture=True)
    lazyplan.bind_container(adapter)
    positives.append({'case':'planning_and_capacity_do_not_consume_append_suppliers'})
    # Narrow NEW current-source/stream/profile guards.
    rejected('production_rejects_fixture_profile',lambda:w.plan_current_mdr(source,appends=empty))
    rejected('source_changed_before_plan',lambda:w.plan_current_mdr(source_for(raw,lambda:False),appends=empty,synthetic_fixture=True))
    rejected('missing_level',lambda:w.plan_current_mdr(source,appends={4:appends[4]},synthetic_fixture=True))
    rejected('wrong_append_level',lambda:w.plan_current_mdr(source,appends={**appends,4:appends[5]},synthetic_fixture=True))
    rejected('append_bit_length_differs',lambda:w.plan_current_mdr(source,appends={**appends,5:replace(appends[5],bit_length=1)},synthetic_fixture=True))
    rejected('append_noncallable_supplier',lambda:w.plan_current_mdr(source,appends={**appends,5:replace(appends[5],supplier=None)},synthetic_fixture=True))
    rejected('duplicate_selected_ID',lambda:w.plan_current_mdr(source,appends=appends,selected_ranges=selected+[selected[0]],synthetic_fixture=True))
    rejected('zero_selected_ID',lambda:w.plan_current_mdr(source,appends=appends,selected_ranges=[replace(selected[0],one_based_street_ID=0)],synthetic_fixture=True))
    rejected('selected_branch_conversion',lambda:w.plan_current_mdr(source,appends=appends,selected_ranges=[replace(selected[0],next_level=5)],synthetic_fixture=True))
    rejected('selected_rawflags_conversion',lambda:w.plan_current_mdr(source,appends=appends,selected_ranges=[replace(selected[0],original_flags=12)],synthetic_fixture=True))
    rejected('selected_points_current_prefix',lambda:w.plan_current_mdr(source,appends=appends,selected_ranges=[replace(selected[0],first_child=1)],synthetic_fixture=True))
    rejected('selected_newrange_overrun',lambda:w.plan_current_mdr(source,appends=appends,selected_ranges=[replace(selected[0],count=4)],synthetic_fixture=True))
    rejected('selected_count12_overflow',lambda:w.plan_current_mdr(source,appends=appends,selected_ranges=[replace(selected[0],count=4096)],synthetic_fixture=True))
    rejected('selected_zero_count',lambda:w.plan_current_mdr(source,appends=appends,selected_ranges=[replace(selected[0],count=0)],synthetic_fixture=True))
    def mutate(at,replacement):
        changed = bytearray(raw);changed[at:at+len(replacement)] = replacement
        return source_for(bytes(changed))
    rejected('wrong_L3_111bit_stock_profile',lambda:w.plan_current_mdr(mutate(len(raw)-120+2*20+8,struct.pack('<I',111)),appends=empty,synthetic_fixture=True))
    rejected('directory_EOF_mismatch',lambda:w.plan_current_mdr(mutate(600,struct.pack('<I',len(raw)-121)),appends=empty,synthetic_fixture=True))
    rejected('nonzero_old_L5_final_padding',lambda:w.plan_current_mdr(mutate(tables[5]['start']+tables[5]['bytes']-1,b'\xc0'),appends=empty,synthetic_fixture=True))
    rejected('nonzero_old_L6_final_padding',lambda:w.plan_current_mdr(mutate(tables[6]['start']+tables[6]['bytes']-1,b'\xf0'),appends=empty,synthetic_fixture=True))
    rejected('source_short_bounded_read',lambda:w.plan_current_mdr(replace(source,read_range=lambda at,n:b'x'),appends=empty,synthetic_fixture=True))
    rejected('source_short_L3_stream',lambda:w.plan_current_mdr(replace(source,range_supplier=lambda at,n:iter([b'x'])),appends=empty,synthetic_fixture=True))
    rejected('source_read_larger64KiB',lambda:source.exact(0,65537))
    for level,limit in ((4,0x7fffff),(5,0x3fffff),(6,0x1fffff)):
        excess = limit-tables[level]['count']+1
        rejected('unchanged_incoming_first_width_overflow_L'+str(level),lambda level=level,excess=excess:
            w.plan_current_mdr(source,appends={**empty,level:w.PackedAppend(level,excess,excess*w.STRIDES[level],lambda:iter(()))},synthetic_fixture=True))
    for name,spec in [('short',w.PackedAppend(5,1,126,lambda:iter([b'\x01']))),
                      ('long',w.PackedAppend(5,1,126,lambda:iter([b'\x01'+bytes(16)]))),
                      ('nonzero_padding',w.PackedAppend(5,1,126,lambda:iter([b'\x01'+bytes(14)+b'\xc0']))),
                      ('mapordinal0',w.PackedAppend(5,1,126,lambda:iter([bytes(16)]))),
                      ('nonbytes',w.PackedAppend(5,1,126,lambda:iter(['wrong']))),
                      ('emptychunk',w.PackedAppend(5,0,0,lambda:iter([b'']))),
                      ('noniterable',w.PackedAppend(5,1,126,lambda:b'\x01'+bytes(15)))]:
        rejected('packed_'+name,lambda spec=spec:b''.join(spec.chunks()))
    rejected('bit_segment_padding',lambda:b''.join(w.bit_splice(((3,lambda:iter([b'\xf7'])),))))
    rejected('bit_segment_short',lambda:b''.join(w.bit_splice(((9,lambda:iter([b'\x01'])),))))
    rejected('bit_segment_long',lambda:b''.join(w.bit_splice(((3,lambda:iter([b'\x07\x00'])),))))
    rejected('wrong_container_binding',lambda:plan.bind_container(adapter))
    rejected('explicit8K_capacity_overflow_before_supplier',lambda:w.eight().plan_repack(image,{'00004171.MDR':w.eight().Replacement(268435456,fail_supplier)}))
    rejected('output_stream_alias',lambda:bound.repack_stream(image.stream))
    rejected('output_existing_bytes',lambda:bound.repack_stream(io.BytesIO(b'existing')))
    source_changed = [False]
    mutable_source = source_for(raw,lambda:not source_changed[0])
    mutable_plan = w.plan_current_mdr(mutable_source,appends=empty,synthetic_fixture=True);source_changed[0] = True
    rejected('source_changed_after_plan',lambda:b''.join(mutable_plan.chunks()))
    result = {'schema':'new-current-profile-cow-writer-controls/v1','created_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'all_assigned_controls_passed':True,'positive_controls':positives,'rejection_controls':guards,
              'positive_count':len(positives),'rejection_count':len(guards),'writer_sha256':sha((HERE/'current_profile_cow_writer.py').read_bytes()),
              'test_source_sha256':sha(Path(__file__).read_bytes()),'old_test_suites_executed':False,'actual_v2_image_read':False,
              'device_IO':False,'large_candidate_or_append_files_produced':False,'native_CPU_verified':False,
              'checksum_or_8K_device_acceptance_verified':False}
    with result_path.open('x') as out:
        json.dump(result,out,indent=2,sort_keys=True);out.write('\n')
    print(json.dumps({'all_assigned_controls_passed':True,'positives':len(positives),'rejections':len(guards)}))


if __name__ == '__main__':
    main()
