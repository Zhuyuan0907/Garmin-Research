#!/usr/bin/env python3
"""Actual original-record merge appends, without a new IMG or device operation."""
from collections import Counter,defaultdict
from datetime import datetime,timezone
from functools import lru_cache
import gzip
import hashlib
import importlib.util
import itertools
import json
from pathlib import Path
import re
import resource
import struct
import sys
import time

sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
ROOT=Path('/root/garmin')
sys.path.insert(0,str(HERE))
import flat_merge_policy as policy
PREFLIGHT_SHA='0216fc4f4ab35e89caf03e73013b5cb6b4646a0cec320911904b1fe8ef76fb05'


def sha(payload):return hashlib.sha256(payload).hexdigest()


def signature(path):
    x=path.stat();return [x.st_dev,x.st_ino,x.st_size,x.st_mtime_ns,x.st_ctime_ns]


def verified_module(path,digest,name):
    before=signature(path);payload=path.read_bytes()
    if sha(payload)!=digest or signature(path)!=before:raise ValueError('Unverified reusable code '+str(path))
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);sys.modules[name]=module;spec.loader.exec_module(module)
    return module


def main():
    started=datetime.now(timezone.utc).isoformat()
    raw=(HERE/'preflight.json').read_bytes();assert sha(raw)==PREFLIGHT_SHA
    meta=json.loads(raw);assert meta['metadata_checks_passed']
    for binding in meta['input_receipts']:
        assert signature(ROOT/binding['path'])==binding['stat_after'],binding['path']
    code={r['path']:r for r in meta['code_bindings']}
    helper_path='staging/navigation-country-native-house-merge-v1/prepare_country_house_merge.py'
    base=verified_module(ROOT/helper_path,code[helper_path]['sha256'],'flat_city_reused_country_helpers_only')
    base.OUT=HERE;base.INPUTS=[];need=base.need
    need(not (HERE/'proof.json').exists() and not (HERE/'appended-level4.bin').exists(),'New append namespace only')
    native_payload=(HERE/'native-flat-roster.json').read_bytes();binding=meta['native_flat_roster_file']
    need(len(native_payload)==binding['bytes'] and sha(native_payload)==binding['sha256'],'Frozen preflight native roster')
    native={r['low28_id']:r for r in json.loads(native_payload)}
    cardinality=Counter((policy.norm(r['city']),policy.norm(r['street'])) for r in native.values())
    API_binding=meta['geometry_API_binding']
    validator=verified_module(ROOT/API_binding['path'],API_binding['sha256'],'flat_city_frozen_source_district_API').SourceDistrictMembership()
    starts={int(k):v for k,v in meta['sealed_start_counts'].items()}
    need(starts=={4:3642683,5:2659853,6:1984052},'Explicit immutable base counts')
    selected=base.JsonArray('selected-street-ranges.json')
    ledger=base.JsonLines('new-house-records.jsonl.gz')
    held=base.JsonLines('held-street-groups.jsonl.gz')
    rejected=base.JsonLines('rejected-new-house-targets.jsonl.gz')
    readlog=base.JsonLines('original-map-read-log.jsonl.gz')
    appended={level:base.BitAppend(base.OutputHash(HERE/f'appended-level{level}.bin'),width) for level,width in base.STRIDES.items()}
    totals=Counter();by_level={};by_city=defaultdict(Counter);by_district=defaultdict(Counter)
    selected_ids=set();seen_groups=set();seen_source_ids=set();seen_streets=set()
    max_rows=max_old=map_bytes=map_reads=0
    input_receipts=[];runtime=[];last_update=time.monotonic()
    before_ap=signature(base.AP)
    core=verified_module(base.CORE,base.CORE_SHA,'flat_city_original_StreamIMG_reader_only')

    def source_rows(expected,level):
        path=ROOT/expected['path'];before=signature(path)
        need(before[2]==expected['bytes'],'Ready sealed byte count')
        previous=None;count=0;plain=hashlib.sha256()
        with path.open('rb') as raw:
            reader=base.HashReader(raw)
            with gzip.GzipFile(fileobj=reader) as stream:
                for line in stream:
                    plain.update(line);count+=1;row=json.loads(line)
                    key=(row['native_street_record'],row['house_label'],row['group_id'])
                    need(previous is None or previous<key,'Complete directcity input ordering');previous=key
                    need(row['native_city'] in policy.CITIES and row['native_district'] is None and
                         row['old_next_level']==level and row['old_child_level_and_flags']&7==level,
                         'Direct city/null native district/next level witness')
                    need(row['native_match_scope']=='direct_city_street_district_unverified' and row['district_verified'] is False
                         and row['native_merge_eligible'] is False,'Original directcity hold policy retained')
                    need(type(row['group_id'])is int and row['group_id']>0 and row['group_id'] not in seen_groups,'Source groups positive and globally unique')
                    ids=row['source_ids'];need(isinstance(ids,list) and ids and len(ids)==row['source_node_count'] and
                         all(type(i)is int and i>0 for i in ids) and len(ids)==len(set(ids)) and not seen_source_ids.intersection(ids),
                         'Every source node ID positive and globally unreused')
                    seen_groups.add(row['group_id']);seen_source_ids.update(ids)
                    yield row
            need(reader.bytes==before[2] and reader.digest.hexdigest()==expected['sha256'] and
                 plain.hexdigest()==expected['uncompressed_sha256'],'Ready compressed/plain EOF/hash')
        need(count==expected['rows'] and signature(path)==before,'Complete directcity count and immutable source')
        input_receipts.append({'path':expected['path'],'bytes':reader.bytes,'sha256':reader.digest.hexdigest(),
            'uncompressed_sha256':plain.hexdigest(),'rows':count,'gzip_EOF_validated':True,
            'stat_before':before,'stat_after':signature(path),'stat_unchanged':True,'compressed_content_passes':1})

    with base.AP.open('rb') as source:
        image=core.StreamIMG(source)
        def flush_reads():
            nonlocal map_bytes,map_reads
            for row in image.read_log:readlog.write(row);map_bytes+=row['bytes'];map_reads+=1
            image.read_log.clear()
        def read(name,offset,count):return b''.join(image.iter_component(name,offset=offset,length=count))
        header=read('00004171.MDR',0,772)
        descriptor=struct.unpack_from('<4I',header,600)
        need(descriptor==(92653480,120,20,1),'Actual original directory descriptor, not candidate offsets')
        directory=read('00004171.MDR',descriptor[0],descriptor[1])
        tables={level:struct.unpack_from('<5I',directory,(level-1)*20) for level in range(1,7)}
        need(tables[3][:3]==(91983716,664197,111),'Actual original L3 profile')
        for level in base.STRIDES:
            need(tables[level][:3]==base.DESCRIPTORS[level] and tables[level][1]*8==base.TOTALS[level]*base.STRIDES[level],
                 'Actual original lower table profiles')
        LBL=read('I053061A.GMP',874,176)
        need(LBL[2:12]==b'GARMIN LBL' and struct.unpack_from('<II',LBL,21)==(6566,3805432)
             and LBL[29:31]==bytes([3,10]) and struct.unpack_from('<H',LBL,170)[0]==950,'Actual stock CP950 label pool profile')
        pool=read('I053061A.GMP',6566,3805432)
        @lru_cache(maxsize=65536)
        def label(ref):
            if type(ref)is not int or not 0<=ref<524287 or ref*8>=len(pool):return None
            at=ref*8;end=pool.find(b'\0',at,min(len(pool),at+512))
            if end<0:return None
            try:return pool[at:end].decode('cp950',errors='strict')
            except UnicodeDecodeError:return None
        flush_reads()
        for level in (4,5,6):
            counts=by_level[level]=Counter();output=appended[level];width=base.STRIDES[level]
            expected=meta['join_direct_ready_bindings'][str(level)]
            for street_id,group in itertools.groupby(source_rows(expected,level),key=lambda row:row['nativeStreetID']):
                rows=list(group);witness=rows[0];stock=native.get(street_id);city=witness['native_city']
                max_rows=max(max_rows,len(rows));counts['directcity_source_groups']+=len(rows)
                by_city[city]['source_groups']+=len(rows)
                need(street_id not in seen_streets,'Native street source group occurs in exactly one level')
                seen_streets.add(street_id)
                first,count,flags=[witness[k] for k in ('old_child_first','old_child_count','old_child_level_and_flags')]
                source_districts=sorted({row['raw_address'][1] for row in rows})
                def hold(reason,**extra):
                    counts['held_streets_'+reason]+=1;counts['held_source_groups_'+reason]+=len(rows)
                    by_city[city]['held_streets_'+reason]+=1
                    held.write({'nativeStreetID':street_id,'native_street_record':witness['native_street_record'],
                        'city':city,'district':None,'street':witness['native_street'],'next_level':level,
                        'original_first':first,'original_count':count,'original_flags':flags,
                        'source_groups':len(rows),'declared_source_districts':source_districts,
                        'reason':reason,'native_district_verified':False,**extra})
                unique=stock is not None and cardinality[(policy.norm(stock['city']),policy.norm(stock['street']))]==1
                if not all(policy.exact_native_witness(row,stock,unique) for row in rows):
                    hold('nonunique_native_city_street_or_original_witness_mismatch');continue
                if flags not in (4,5,6):hold('unproved_original_parent_flags');continue
                if not(1<=street_id<=47870 and 0<count<=4095 and 1<=first<=first+count-1<=base.TOTALS[level]):
                    hold('original_group_bounds_unproved');continue
                parent_at,parent_shift=divmod((street_id-1)*111,8)
                parent=int.from_bytes(read('00004171.MDR',tables[3][0]+parent_at,16),'little')>>parent_shift
                need(((parent>>20)&((1<<22)-1),(parent>>42)&4095,(parent>>54)&511)==(first,count,flags),'Actual original parent matches decoded roster')
                start,shift=divmod((first-1)*width,8)
                body=read('00004171.MDR',tables[level][0]+start,(shift+count*width+7)//8)
                old=base.unpack(body,shift,count,width);max_old=max(max_old,count)
                names=[label((value>>(1 if level==6 else 20))&524287) for value in old]
                if any(name is None for name in names):hold('unreadable_original_label');flush_reads();continue
                anchors=[int(m.group()) for name in names if (m:=re.match(r'^[0-9]+',name))]
                if not anchors or anchors!=sorted(anchors):hold('unproved_original_numeric_order');flush_reads();continue
                original_names=set(names);ordinal_one=all(value&1==1 for value in old);additions=[]
                for house,members_group in itertools.groupby(rows,key=lambda row:row['house_label']):
                    members=list(members_group);counts['source_distinct_native_street_house_targets']+=1
                    match=base.INTEGER.fullmatch(house)
                    if not match:
                        counts['subnumber_or_other_targets_deferred']+=1
                        counts['subnumber_or_other_source_groups_deferred']+=len(members);continue
                    counts['positive_integer_source_groups']+=len(members)
                    if house in original_names:
                        counts['original_exact_integer_targets_unchanged']+=1
                        counts['source_integer_groups_already_original']+=len(members);continue
                    decision=policy.target_eligibility(members,stock,validator,label,ordinal_one,base.quantize_point24)
                    if not decision['accepted']:
                        reason=decision['reason'];counts['new_integer_targets_rejected_'+reason]+=1
                        by_city[city]['new_integer_targets_rejected_'+reason]+=1
                        rejected.write({'nativeStreetID':street_id,'next_level':level,'city':city,'district':None,
                            'street':stock['street'],'house_label':house,'source_group_ids':[r['group_id'] for r in members],
                            'source_ids':[i for r in members for i in r['source_ids']],
                            'source_members':[{k:r[k] for k in ('group_id','source_ids','raw_address','coordinate_strings','source_node_count',
                                'separate_floor_unit_source_nodes','embedded_floor_unit_first_source_flag')} for r in members],
                            'reason':reason,'decision':decision,'native_district_verified':False});continue
                    point=members[0]['coordinate_strings'];raw24=decision['raw24'];ref=members[0]['primary_ref']
                    payload=base.encode_record(base.LAYOUTS[level],base.AddressRecord(1,ref,None,0,0,0,*raw24)).payload
                    value=int.from_bytes(payload,'little');need(value>>width==0,'New unused per-record bits zero')
                    provenance=[{k:r[k] for k in ('group_id','source_ids','raw_address','coordinate_strings','source_node_count',
                        'separate_floor_unit_source_nodes','embedded_floor_unit_first_source_flag')} for r in members]
                    additions.append({'label':house,'number':int(match.group(1)),'value':value,'payload':payload.hex(),'raw24':raw24,
                        'primary_ref':ref,'coordinate_strings':point,'source_members':provenance,
                        'source_group_ids':[r['group_id'] for r in members],'source_ids':[i for r in members for i in r['source_ids']],
                        'source_city':decision['source_city'],'source_district':decision['source_district'],
                        'source_member_decisions':decision['pair_decisions'],
                        'source_district_decision':decision['source_decisions'][0],
                        'quantized_district_decision':decision['pair_decisions'][0]})
                    if len(members)>1:counts['coalesced_same_point_same_source_district_targets']+=1;counts['coalesced_extra_source_groups']+=len(members)-1
                if not additions:counts['streets_without_new_eligible_integer']+=1;flush_reads();continue
                if count+len(additions)>4095:hold('merged_parent_count_over_12bit',held_new_targets=len(additions));flush_reads();continue
                relative_first=output.records+1;new_first=starts[level]+relative_first
                if new_first+count+len(additions)-1>0x7fffff:hold('proposed_index_over_current_L3_23bit_profile',held_new_targets=len(additions));flush_reads();continue
                merged,positions,ordered=base.merge_numeric(old,names,additions)
                need(street_id not in selected_ids,'Every selected original street appears once');selected_ids.add(street_id)
                offset=output.bits
                for value in merged:output.add(value)
                used_districts=sorted({r['source_district'] for r in additions})
                selected.write({'nativeStreetID':street_id,'native_street_record':stock['record'],'city':city,'district':None,
                    'street':stock['street'],'next_level':level,'record_bits':width,'original_first':first,'original_count':count,
                    'original_flags':flags,'new_first':new_first,'relative_new_first':relative_first,'new_count':len(merged),
                    'index_base_count_pin':starts[level],'appended_bit_offset':offset,'appended_record_ordinal':offset//width,
                    'new_integer_house_count':len(additions),'declared_source_districts':used_districts,
                    'native_district_record':None,'native_district_verified':False,
                    'original_source_window_sha256':base.sha(body),'original_source_initial_bit_shift':shift,
                    'original_significant_records_sha256':base.record_hash(old,width),
                    'new_significant_records_sha256':base.record_hash(merged,width),
                    'new_group_tight_packed_sha256':base.sha(base.packed(merged,width)),
                    'significant_hash_policy':'Each significant record in ceil(stride/8) LE bytes, per-record unused high bits zero; preserve old relative order.'})
                for row in ordered:
                    position=positions[row['label']];relative_ID=relative_first+position
                    ledger.write({'nativeStreetID':street_id,'next_level':level,'new_lowID':starts[level]+relative_ID,
                        'relative_new_lowID':relative_ID,'index_base_count_pin':starts[level],
                        'appended_bit_offset':offset+position*width,'record_bits':width,'house_label':row['label'],
                        'primary_ref':row['primary_ref'],'source_ids':row['source_ids'],'source_group_ids':row['source_group_ids'],
                        'source_members':row['source_members'],'coordinate_strings':row['coordinate_strings'],'raw24':row['raw24'],
                        'payload':row['payload'],'old_child_first':first,'old_child_count':count,'old_parent_flags':flags,
                        'city':city,'district':None,'street':stock['street'],'source_city':row['source_city'],
                        'source_district':row['source_district'],'native_district_record':None,'native_district_verified':False,
                        'source_district_decision':row['source_district_decision'],
                        'quantized_district_decision':row['quantized_district_decision'],
                        'source_member_decisions':row['source_member_decisions']})
                    by_district[(row['source_city'],row['source_district'])]['new_integer_house_records']+=1
                counts['updated_streets']+=1;counts['new_integer_house_records']+=len(additions)
                counts['cloned_original_records']+=count;counts['appended_records']+=len(merged)
                by_city[city]['updated_streets']+=1;by_city[city]['new_integer_house_records']+=len(additions)
                flush_reads()
                if time.monotonic()-last_update>20:
                    observation={'level':level,'source_groups':counts['directcity_source_groups'],
                        'new_integer_house_records':counts['new_integer_house_records'],'updated_streets':counts['updated_streets'],
                        'max_RSS_KiB':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss}
                    runtime.append(observation);print(json.dumps({'progress':observation},ensure_ascii=False),flush=True);last_update=time.monotonic()
            need(counts['directcity_source_groups']==expected['rows'],'Every ready source group classified')
            totals.update(counts);print(json.dumps({'level_finished':level,'counts':dict(counts)},ensure_ascii=False),flush=True)
        flush_reads()
    need(signature(base.AP)==before_ap,'Original map immutable')
    need(len(seen_groups)==159594,'All three direct-city ready ledgers complete')
    artifacts={f'level{level}':appended[level].finish() for level in (4,5,6)}
    artifacts.update(selected_ranges=selected.close(),new_records=ledger.close(),held=held.close(),rejected_targets=rejected.close(),read_log=readlog.close())
    for binding in meta['input_receipts']:need(signature(ROOT/binding['path'])==binding['stat_after'],'All metadata still immutable')
    final_counts={level:starts[level]+artifacts[f'level{level}']['record_count'] for level in (4,5,6)}
    need(all(final_counts[level]<=meta['conservative_capacity_upper_bounds'][str(level)]['final_count_upper_bound'] for level in (4,5,6)),
         'Actual append bounded by preflight upper estimate')
    source_code_bindings=[{'path':str(path.relative_to(ROOT)),'bytes':path.stat().st_size,'sha256':sha(path.read_bytes())}
                          for path in (Path(__file__),HERE/'flat_merge_policy.py')]
    base.save('proof.json',{'schema':'flat-city-original-native-house-merge-preparation/v1','started_utc':started,
        'finished_utc':datetime.now(timezone.utc).isoformat(),'all_assigned_checks_passed':True,
        'preflight_sha256':PREFLIGHT_SHA,'preflight_input_receipts_inherited':meta['input_receipts'],
        'inputs':input_receipts,'input_address_ready_content_passes_each':1,'source_code_bindings':source_code_bindings,
        'original_counts':base.TOTALS,'starting_country_v1_plus_KH_counts':starts,'proposed_counts':final_counts,
        'strides':base.STRIDES,'counts':dict(totals),'counts_by_level':{k:dict(v) for k,v in by_level.items()},
        'counts_by_city':{k:dict(v) for k,v in by_city.items()},
        'counts_by_source_district':[{'source_city':c,'source_district':d,**dict(v)} for (c,d),v in sorted(by_district.items())],
        'source_groups_positive_unique':len(seen_groups),'source_OSM_IDs_positive_unique':len(seen_source_ids),
        'source_streets_observed':len(seen_streets),'selected_streets_unique':len(selected_ids),
        'native_city_to_street_layout_retained':True,'native_district_records_created':0,'native_district_verified':False,
        'original_map_stat_before':before_ap,'original_map_stat_after':signature(base.AP),'original_map_bytes_read':map_bytes,
        'original_map_read_operations':map_reads,'actual_original_directory_descriptor':list(descriptor),
        'original_label_pool_bytes_read':3805432,'original_label_pool_sha256':sha(pool),
        'max_source_street_rows':max_rows,'max_original_street_records':max_old,'max_RSS_KiB':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
        'runtime_resource_receipts':runtime,'artifacts':artifacts,
        'all_selected_original_significant_bits_relative_order_flags_nested_links_coords_preserved':True,
        'original_exact_house_coords_updated':False,'raw13_or_other_unknown_parent_flags_held':True,
        'new_house_records_positive_ASCII_integer_stock_label_refs_mapordinal1_only':True,
        'source_and_exact_raw24_both_inside_same_literal_declared_source_district':True,
        'global_target_guard_evidence':'Complete ready producer collision flags plus full target member cardinality; conflicting source districts held.',
        'unique_native_city_street_guard_policy':'Complete original four-city roster cardinality under inherited NFKC/outer whitespace/臺→台 policy; no device prefix change.',
        'tight_table_wide_packing_only_final_high_padding':True,
        'rebase_contract':{'local_bits_and_records_immutable':True,'base_counts_are_explicit_pins':starts,
             'new_lowID_formula':'explicit_rebased_base[level] + relative_new_lowID',
             'new_first_formula':'explicit_rebased_base[level] + relative_new_first',
             'may_silently_change_counts_or_bins':False,'splice_requires_significant_bits_not_byte_concat':True,
             'root_possible_L4_base_adjustment':-1},
        'whole_PBF_node_full_group_exact_ready_ledgers_read':False,'whole_IMG_JAI_canonical_ZIP_written':False,
        'device_IO':False,'native_CPU_executed':False,'closed_suites_rerun':False,'full_Taiwan_update_complete':False,
        'limits':['Only sealed coordinate-ready directcity subset; coordinate-review/name/admin/label/unresolved groups remain held upstream.',
            'Source district geography only; original native district record is absent, not invented.',
            'Street/base-number insertion follows the previously sealed host merge; no physical getter/UI/routing acceptance.',
            'Base counts are pinned v1+KH; root must explicitly rebase if excluding its one L4 outlier.']})
    print(json.dumps({'all_assigned_checks_passed':True,'counts':dict(totals),'proposed_counts':final_counts,
        'append_bytes':sum(artifacts[f'level{level}']['bytes'] for level in (4,5,6)),'original_map_bytes_read':map_bytes,
        'proof_sha256':sha((HERE/'proof.json').read_bytes())},ensure_ascii=False),flush=True)


if __name__=='__main__':main()
