#!/usr/bin/env python3
"""Independent new append readback, plus bounded original Kaohsiung windows."""
from collections import Counter
from decimal import Decimal
from fractions import Fraction
import gzip
import hashlib
import importlib.util
import itertools
import json
import mmap
from pathlib import Path
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = Path('/root/garmin')
sys.path.insert(0,str(HERE))
import merge_policy as policy


def need(ok,message):
    if not ok:raise AssertionError(message)


def sha(data):return hashlib.sha256(data).hexdigest()


def field(value,at,width):return (value>>at)&((1<<width)-1)


def record(wire,bit_at,width):
    begin,shift=divmod(bit_at,8)
    end=(bit_at+width+7)//8
    result=0
    for byte in reversed(wire[begin:end]):result=(result<<8)|byte
    return field(result,shift,width)


def significant_hash(values,width):
    digest=hashlib.sha256()
    for value in values:digest.update(value.to_bytes((width+7)//8,'little'))
    return digest.hexdigest()


def tight_group_bytes(values,width):
    # Independent integer assembly only over a bounded single group.
    word=0
    for index,value in enumerate(values):word|=value<<(index*width)
    return word.to_bytes((len(values)*width+7)//8,'little')


def selected_rows(path,expected):
    digest=hashlib.sha256();total=count=0
    with path.open('rb') as stream:
        for line in stream:
            digest.update(line);total+=len(line)
            text=line.strip().rstrip(b',')
            if text in (b'[',b']',b''):continue
            count+=1;yield json.loads(text)
    need(count==expected['rows'] and total==expected['bytes'] and digest.hexdigest()==expected['sha256'],'Selected EOF/hash/count')


def ledger_rows(path,expected):
    with path.open('rb') as stream:compressed=hashlib.file_digest(stream,'sha256').hexdigest()
    digest=hashlib.sha256();count=0
    with gzip.open(path,'rb') as stream:
        for line in stream:
            digest.update(line);count+=1;yield json.loads(line)
    need(count==expected['rows'] and digest.hexdigest()==expected['uncompressed_sha256'] and
         compressed==expected['sha256'] and path.stat().st_size==expected['bytes'],'New ledger EOF/hash/count')


def original_reader():
    source=ROOT/'staging/navigation-taichung-merge-review-v1/review_merge.py'
    raw=source.read_bytes()
    need(sha(raw)=='d7f9669b0abdf4222d24c387b3e8ba1193bb1b53db97d9e94e042ec08de4ce90','Sealed independent original IMG reader')
    spec=importlib.util.spec_from_file_location('kaohsiung_new_independent_IMG_reader',source)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module.IndependentIMG(ROOT/'backups/20261002T154458Z/files/.System/gmapprom1.img')


def main():
    need(not (HERE/'output-readback-proof.json').exists(),'New readback namespace result')
    proof=json.loads((HERE/'proof.json').read_text())
    validator=policy.district_validator()
    streams,maps={},{}
    for level in (4,5,6):
        artifact=proof['artifacts'][f'level{level}'];path=HERE/artifact['path']
        with path.open('rb') as stream:digest=hashlib.file_digest(stream,'sha256').hexdigest()
        need(digest==artifact['sha256'] and path.stat().st_size==artifact['bytes'],'Complete fresh append hash/bytes')
        need(artifact['bit_length']==artifact['record_count']*artifact['record_bits'],'Actual significant bit length')
        stream=path.open('rb');streams[level]=stream
        maps[level]=mmap.mmap(stream.fileno(),0,access=mmap.ACCESS_READ) if artifact['bytes'] else b''
        if artifact['bit_length']%8:need(maps[level][-1]>>(artifact['bit_length']%8)==0,'Only final padding high bits zero')
    # Groupwise zip keeps only one street of selected metadata/new leaves.
    groups=itertools.groupby(ledger_rows(HERE/'new-house-records.jsonl.gz',proof['artifacts']['new_records']),
                             key=lambda row:(row['next_level'],row['nativeStreetID']))
    ranges=selected_rows(HERE/'selected-street-ranges.json',proof['artifacts']['selected_ranges'])
    positions_by_rep={};representatives={};largest={};last={};alignments={};first_counts=Counter();raw13={}
    checked=original_retained=selected_count=0;next_local={4:0,5:0,6:0};selected_ids=set();max_group_leaves=0
    for selected,group_pair in itertools.zip_longest(ranges,groups):
        need(selected is not None and group_pair is not None,'Every selected parent has exactly one new leaf group')
        key,members=group_pair;level,street_id=key;rows=list(members);max_group_leaves=max(max_group_leaves,len(rows))
        need(key==(selected['next_level'],selected['nativeStreetID']),'Selected/new ledger same ordered parent')
        need(selected['city']=='高雄市' and selected['district'] in validator.geometries and selected['district']!='旗津區','Only complete explicit districts')
        need(street_id not in selected_ids,'Selected street unique');selected_ids.add(street_id)
        width=selected['record_bits'];need(width=={4:128,5:126,6:68}[level],'Actual stride')
        need(selected['appended_bit_offset']==next_local[level],'Append group windows densely packed')
        start_count=proof['starting_country_v1_counts'][str(level)]
        need(selected['new_first']==start_count+next_local[level]//width+1,'New low IDs continue frozen country count')
        need(selected['combined_append_bit_offset']==proof['country_v1_append_bit_lengths'][str(level)]+next_local[level],'Cross-version significant bit offset')
        next_local[level]+=selected['new_count']*width
        inserted=set()
        for row in rows:
            need(row['city']=='高雄市' and row['district']==selected['district'] and row['street']==selected['street'],'Every new leaf admin/street witness')
            bit_at=row['appended_bit_offset'];position=(bit_at-selected['appended_bit_offset'])//width
            need(bit_at>=selected['appended_bit_offset'] and (bit_at-selected['appended_bit_offset'])%width==0 and
                 0<=position<selected['new_count'] and position not in inserted,'Leaf exact unique packed position')
            inserted.add(position)
            need(row['new_lowID']==selected['new_first']+position and row['combined_append_bit_offset']==
                 proof['country_v1_append_bit_lengths'][str(level)]+bit_at,'Every low ID/combined bit offset')
            payload=bytes.fromhex(row['payload']);value=int.from_bytes(payload,'little')
            need(value>>width==0 and record(maps[level],bit_at,width)==value,'Actual new leaf packed bytes equal receipt')
            need(field(value,0,1)==1,'Every new leaf mapordinal1')
            if level==4:
                need(field(value,1,19)==524287 and field(value,20,19)==row['primary_ref'],'L4 refs')
                need(field(value,39,22)==field(value,61,10)==field(value,71,9)==0,'L4 child/flags zero')
                raw24=[field(value,80,24),field(value,104,24)]
            elif level==5:
                need(field(value,1,19)==524287 and field(value,20,19)==row['primary_ref'],'L5 refs')
                need(field(value,39,21)==field(value,60,9)==field(value,69,9)==0,'L5 child/flags zero')
                raw24=[field(value,78,24),field(value,102,24)]
            else:
                need(field(value,1,19)==row['primary_ref'],'L6 primary ref')
                raw24=[field(value,20,24),field(value,44,24)]
            need(raw24==row['raw24'],'Independently decoded coordinate field placement')
            source=validator.assess('高雄市',row['district'],*row['coordinate_strings'])
            quantized=policy.quantized_assess(validator,'高雄市',row['district'],raw24)
            need(source['status']==quantized['status']=='inside_verified_district' and
                 source==row['source_district_decision'] and quantized==row['quantized_district_decision'],
                 'Every new source point and exact raw24 point inside same explicit district')
            need(all(member['raw_address'][0]=='高雄市' and member['raw_address'][1]==row['district'] and
                     tuple(map(Decimal,member['coordinate_strings']))==tuple(map(Decimal,row['coordinate_strings']))
                     for member in row['source_members']),'Every coalesced source member exact names and Decimal point')
            need(sorted({node for member in row['source_members'] for node in member['source_ids']})==row['source_ids'] and
                 [member['group_id'] for member in row['source_members']]==row['source_group_ids'],'All provenance members retained')
            checked+=1
        need(len(rows)==selected['new_integer_house_count'],'Every expected new integer leaf in group')
        actual=[record(maps[level],selected['appended_bit_offset']+index*width,width) for index in range(selected['new_count'])]
        retained=[value for index,value in enumerate(actual) if index not in inserted]
        need(len(retained)==selected['original_count'] and significant_hash(retained,width)==selected['original_significant_records_sha256'],
             'Every selected group original significant hash/order preserved')
        need(significant_hash(actual,width)==selected['new_significant_records_sha256'] and
             sha(tight_group_bytes(actual,width))==selected['new_group_tight_packed_sha256'],'Every new group significant/tight hash')
        original_retained+=len(retained);selected_count+=1
        take=first_counts[level]<2;first_counts[level]+=1
        shift_key=(level,selected['appended_bit_offset']%8)
        if shift_key not in alignments:alignments[shift_key]=selected;take=True
        if selected['original_flags']==13 and level not in raw13:raw13[level]=selected;take=True
        if take:
            representatives[key]=selected;positions_by_rep[key]=inserted
        if level not in largest or selected['new_count']>largest[level][0]['new_count']:
            largest[level]=(selected,inserted)
        last[level]=(selected,inserted)
    for selected,inserted in list(largest.values())+list(last.values()):
        key=(selected['next_level'],selected['nativeStreetID']);representatives[key]=selected;positions_by_rep[key]=inserted
    need(checked==proof['artifacts']['new_records']['rows'] and selected_count==proof['artifacts']['selected_ranges']['rows'],'Actual complete leaf/range totals')
    need(original_retained==proof['counts']['cloned_original_records'],'All original cloned output count')
    for level in (4,5,6):need(next_local[level]==proof['artifacts'][f'level{level}']['bit_length'],'All append bits covered by groups')
    image=original_reader();actual_original=[]
    table={4:57840548,5:20968286,6:4195100}
    for key,selected in sorted(representatives.items()):
        level,street_id=key;width=selected['record_bits']
        at,shift=divmod((selected['original_first']-1)*width,8)
        body=image.get('00004171.MDR',table[level]+at,(shift+selected['original_count']*width+7)//8)
        old=[record(body,shift+index*width,width) for index in range(selected['original_count'])]
        actual=[record(maps[level],selected['appended_bit_offset']+index*width,width) for index in range(selected['new_count'])]
        retained=[v for index,v in enumerate(actual) if index not in positions_by_rep[key]]
        need(old==retained and sha(body)==selected['original_source_window_sha256'],'Actual representative original bits/relative order and window hash')
        old_raw13=sum(field(v,71 if level==4 else 69,9)==13 for v in old) if level!=6 else 0
        actual_original.append(dict(next_level=level,nativeStreetID=street_id,district=selected['district'],street=selected['street'],
            original_count=len(old),new_count=len(actual),original_flags=selected['original_flags'],raw13_original_records=old_raw13,
            actual_original_bits_order_equal=True,output_initial_bit_shift=selected['appended_bit_offset']%8))
    image.close()
    original_bytes=sum(r['bytes'] for r in image.read_log)
    need(original_bytes<500000,'Bounded representative original read budget')
    # Stream frozen country selections again only to prove disjoint IDs; no
    # country v1 groups/append/comparator or old test suite is rerun.
    intersection=set();country_count=0
    for row in selected_rows(ROOT/'staging/navigation-country-native-house-merge-v1/selected-street-ranges.json',
                             {'rows':15679,'bytes':14628154,'sha256':'dd42c0e57c96f61ed6d93f0309b4fdd5ae6c98652a937163fd61f494b8e7bbaa'}):
        country_count+=1
        if row['nativeStreetID'] in selected_ids:intersection.add(row['nativeStreetID'])
    need(not intersection,'Independent country v1 selected intersection empty')
    for wire in maps.values():
        if hasattr(wire,'close'):wire.close()
    for stream in streams.values():stream.close()
    result=dict(schema='kaohsiung-new-append-readback/v1',all_assigned_readbacks_passed=True,
        every_new_leaf_checked=checked,every_selected_group_checked=selected_count,
        original_cloned_output_records_significant_hashes_checked=original_retained,
        every_new_source_and_exact_raw24_point_in_same_verified_district=True,
        complete_append_selected_and_ledger_hashes_checked=True,country_v1_selected_ids_checked=country_count,
        country_v1_selected_intersection_count=0,representative_actual_original_groups=actual_original,
        actual_original_records_directly_compared=sum(r['original_count'] for r in actual_original),
        actual_original_map_bytes_read=original_bytes,max_new_leaves_per_group=max_group_leaves,
        actual_original_reader_log=image.read_log,
        limits=['Direct original-map byte comparison is bounded to representatives; all group preservation also uses producer original-window/significant hashes.',
                'Source ready input hashes/provenance bind the single producer pass; ready inputs are not reopened by this readback.',
                'No IMG/container splice, native frontend/query, UI or hardware acceptance proof.'],
        device_IO=False,new_IMG_created=False,old_country_controls_rerun=False,
        source_script_sha256=sha(Path(__file__).read_bytes()))
    with (HERE/'output-readback-proof.json').open('x') as stream:
        json.dump(result,stream,ensure_ascii=False,sort_keys=True,separators=(',',':'));stream.write('\n')
    print(json.dumps(dict(all_assigned_readbacks_passed=True,new_leaves=checked,selected_groups=selected_count,
        representative_groups=len(actual_original),actual_original_bytes=original_bytes,selected_intersection=0),ensure_ascii=False))


if __name__=='__main__':main()
