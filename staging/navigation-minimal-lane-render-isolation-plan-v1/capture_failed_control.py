#!/usr/bin/env python3
"""Capture-only recovery, retaining first failed clone guard without rerunning it.

Ordinary files only. Preserve unknown old flags/pointers verbatim. No payload
patch, append writer, CPU, MAIN, device, whole IMG hash or original-file mutation.
"""
from pathlib import Path
from datetime import datetime,timezone
from collections import Counter
from decimal import Decimal,ROUND_HALF_UP
import ast
import hashlib
import json
import os
import resource
import struct
import time

ROOT=Path('/root/garmin'); HERE=Path(__file__).resolve().parent
FAILED_SOURCE_SHA='a20877fce09cbfe36f1f5621144f2ade44a031c26e4c6d330d07b2a1b86c4095'
FIRST_RUN_READ_UPPER_BOUND=740000
TOTAL_IMG_LIMIT=1<<20


def save(name,row):
    raw=json.dumps(row,ensure_ascii=False,indent=2).encode()+b'\n'
    with (HERE/name).open('xb') as f:
        f.write(raw); f.flush(); os.fsync(f.fileno())
    return dict(path=str((HERE/name).relative_to(ROOT)),bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())


def main():
    started=datetime.now(timezone.utc).isoformat(); t0=time.monotonic()
    raw=(HERE/'prepare_control.py').read_bytes()
    if hashlib.sha256(raw).hexdigest()!=FAILED_SOURCE_SHA:
        raise ValueError('Failed original source changed')
    parsed=ast.parse(raw.decode()); imports=(ast.FunctionDef,ast.ClassDef)
    names={'need','sha','stat','saved','saved_bytes','bounded_file','load','Budget','Image','Records'}
    nodes=[]
    for n in parsed.body:
        if isinstance(n,imports) and n.name in names: nodes.append(n)
        if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id in {'PROFILES','NAMES','IMAGES'} for t in n.targets): nodes.append(n)
    ns=dict(Path=Path,ast=ast,hashlib=hashlib,json=json,os=os,struct=struct,ROOT=ROOT,HERE=HERE,
            LIMIT=TOTAL_IMG_LIMIT-FIRST_RUN_READ_UPPER_BOUND)
    exec(compile(ast.Module(body=nodes,type_ignores=[]),str(HERE/'prepare_control.py'),'exec'),ns)
    need,sha,stat,load=(ns[k] for k in ('need','sha','stat','load'))
    inputs=[]
    inputs.append(dict(path=str((HERE/'prepare_control.py').relative_to(ROOT)),bytes=len(raw),sha256=FAILED_SOURCE_SHA,
                       use='Reuse unchanged ordinary FILE mapper/classes only; main not executed'))
    need((HERE/'failure.json').exists(),'First actual failure retained')
    failure_raw=(HERE/'failure.json').read_bytes(); failure=json.loads(failure_raw)
    need(failure['error']=='Selected L5 terminal subtree has no nested child pointers/unknown flags','Actual first failure identity')
    readerraw=ns['bounded_file']('staging/navigation-country-native-lane-independent-review-v3/review_actual_v3.py',
        'e4b5cebe1f805e4569929fa43111efd92aed8af560993b619a89c17c8a8acb56',inputs)
    helpers=[n for n in ast.parse(readerraw.decode()).body if isinstance(n,ast.FunctionDef) and n.name in ('extract','decode')]
    need([n.name for n in helpers]==['extract','decode'],'Existing pure ordinary bit helper definitions')
    pure={'need':need}; exec(compile(ast.Module(body=helpers,type_ignores=[]),'<sealed ordinary bit helpers>','exec'),pure)
    cpu_seal=load('staging/navigation-country-native-lane-cpu-v3/sealed-files.json',
        '4dca5ab38bbf621d42d03b9b5f3fd319054cbef3c12ef43ab7ef198ac0bdfcdb',inputs)
    need(cpu_seal['all_assigned_actual_CPU_checks_passed'],'Inherited CPU scope only')
    selection=load('staging/navigation-country-native-lane-cpu-v3/finite-selection.json',
        '7315e1f0ec601a971765f4b3ec8f96656ac3ed291da6a23bf4a8f4a97aeb6ffb',inputs)
    review_seal=load('staging/navigation-country-native-lane-independent-review-v3/sealed-files.json',
        'c091c972bb50a7d0e38c469f21aa02aab21c6394156bcbca0ec4ebeaae2aab99',inputs)
    witness=load('staging/navigation-country-native-lane-independent-review-v3/actual-native-CPU-witnesses.json',
        '7431c5821d1f322d6c7a74c473b3df450fd62dcc785fc3a06e1d7e841d28b59a',inputs)
    need(review_seal['all_assigned_checks_passed'] and witness['source_full_EOF_verified'],'Inherited full readback/provenance scope')
    screens=[]
    for r in selection['new_leaf_samples'][:3]:
        s=r['sample']; m=s['source_members']; reasons=[]
        if any(x['separate_floor_unit_nodes'] for x in m): reasons.append('floor_unit_door_level')
        if any(x['embedded_floor_unit'] for x in m): reasons.append('embedded_floor_unit')
        reasons+=s['source_ready_target']['reasons']
        if any(not x['coordinate_selection_ready'] or x['different_coordinate_nodes'] for x in m): reasons.append('coordinate_not_unique_ready')
        screens.append(dict(new_lowID=s['new_lowID'],raw_address=m[0]['raw_address'],source_ids=s['source_ids'],reasons=reasons))
    candidate=selection['new_leaf_samples'][2]['sample']
    need(candidate['source_ids']==[12084620255] and not screens[2]['reasons'],'Exact clean chosen source')
    need(candidate['house_label']=='2號' and candidate['source_group_ids']==[3508619],'Literal candidate identity')
    target=candidate['source_ready_target']
    need(candidate['source_members']==target['source_members'] and candidate['source_ids']==target['source_ids'],
         'Complete source members from sealed small sample')
    need(sorted({v for m in candidate['source_members'] for v in m['source_ids']})==candidate['source_ids']
         and sum(m['source_node_count'] for m in candidate['source_members'])==candidate['source_node_count'],
         'Complete source union and counts')
    need(all(type(v) is int and v>0 for v in candidate['source_ids']),'Positive source IDs')
    need([int((Decimal(v)*Decimal(1<<24)/Decimal(360)).quantize(Decimal(1),rounding=ROUND_HALF_UP))
          for v in candidate['coordinate_strings']]==candidate['raw24'],'Recorded prototype Decimal quantization')
    matched=[r for r in witness['new_leaf_samples'] if r['sample']['new_lowID']==candidate['new_lowID']]
    need(len(matched)==1 and matched[0]['sample']==candidate,'Exact complete-review source witness')
    path=next(r for r in selection['complete_path_samples'] if r['stock_parent_record']==candidate['stock_parent_record'])
    budget=ns['Budget'](); actual={}; windows={}; images={}
    for name,pin in ns['IMAGES'].items():
        sealed=load(pin['seal'],pin['seal_sha256'],inputs)
        need(sealed['all_assigned_checks_passed'],'Completed frozen candidate source')
        entry=next(r for r in sealed['files'] if r['path']==pin['path'])
        need(entry['sha256']==pin['sha256'] and entry['bytes']==pin['bytes'],'Inherited candidate whole SHA')
        p=ROOT/pin['path']; before=stat(p)
        need([before[k] for k in ('dev','ino','bytes','mtime_ns')]==entry['stat_at_seal'][:4]
             and before['mode']=='0o444','Frozen content inode/size/mtime; release hardlinks fresh ctime')
        with p.open('rb') as f:
            image=ns['Image'](name,f,pin,budget); records=ns['Records'](image,pure['extract'],pure['decode'])
            root=records.record(3,1153)
            need(root['label']=='四川路二段' and root['next_level']==4 and root['raw_flags']==4,'Exact original root')
            siblings=records.group(root); lanes=[r for r in siblings if r['label']=='4巷']
            need(len(lanes)==1,'Unique exact actual lane'); lane=lanes[0]
            expected=path['current_v2_parent_record'] if name=='v2' else path['new_COW_parent_record']
            need(lane['record']==expected and lane['next_level']==5 and lane['raw_flags']==5,'Correct actual lane parent')
            houses=records.group(lane)
            for r in houses:
                r['secondary_label']=records.label(r['secondary_ref'])
            found=[r for r in houses if r['label']=='2號']
            need(len(found)==(0 if name=='v2' else 1),'Actual selected new leaf membership')
            if name=='v3':
                new=found[0]
                need(new['ID']==candidate['new_lowID'] and new['payload']==candidate['payload']
                     and new['primary_ref']==candidate['primary_ref']
                     and [new['raw_location_a'],new['raw_location_b']]==candidate['raw24'],'Actual selected source payload/ref/raw24')
                need(new['raw_flags']==new['next_level']==new['first_child']==new['child_count']==0,'Selected new leaf has no nested branch')
            need(records.label(candidate['primary_ref'])=='2號','Actual v2/v3 existing primary label')
            windows[name]={'root':records.group_windows[root['record']], 'lane':records.group_windows[lane['record']]}
            actual[name]=dict(root=root,lane=lane,root_children=siblings,house_children=houses,selected_house=found,tables=records.tables,
                container=dict(bytes=pin['bytes'],block_bytes=image.block_bytes,capacity=image.capacity,
                    metadata_start=image.directory_start,metadata_end=image.directory_end,
                    used_FAT_rows=image.used_rows,free_FAT_rows=image.free_rows,header_hex=image.header.hex(),header_sha256=sha(image.header),
                    component_sizes={k:v['size'] for k,v in image.components.items()},
                    component_blocks={k:len(v['blocks']) for k,v in image.components.items()},
                    component_parts={k:v['parts'] for k,v in image.components.items()}))
            need(stat(p)==before,'Frozen rb input stat/nlink while handle open')
        need(stat(p)==before,'Frozen input stat/nlink after handle closed')
        images[name]=dict(path=pin['path'],bytes=pin['bytes'],inherited_root_whole_sha256=pin['sha256'],
                          whole_SHA_recomputed=False,stat_before=before,stat_after=stat(p),handle_closed=True)
    v2,v3=actual['v2'],actual['v3']; old=v2['house_children']; full=v3['house_children']; new=v3['selected_house'][0]
    need(len(v2['root_children'])==len(v3['root_children'])==267 and len(old)==4 and len(full)==6,
         'Bounded exact selected group sizes')
    need([r['label'] for r in v2['root_children']]==[r['label'] for r in v3['root_children']],
         'Same sibling labels/relative order')
    old_positions=[]; comparison=[]
    for r in old:
        matches=[s for s in full if (s['primary_ref'],s['secondary_ref'],s['raw_location_a'],s['raw_location_b'],s['raw_flags'])
            ==(r['primary_ref'],r['secondary_ref'],r['raw_location_a'],r['raw_location_b'],r['raw_flags'])]
        need(len(matches)==1,'Unique existing old record counterpart by exact ref/point/flags')
        s=matches[0]; old_positions.append(s['ordinal'])
        comparison.append(dict(v2_record=r['record'],v3_record=s['record'],label=r['label'],v2_raw_flags=r['raw_flags'],
            v3_raw_flags=s['raw_flags'],v2_child_range=[r['next_level'],r['first_child'],r['child_count']],
            v3_child_range=[s['next_level'],s['first_child'],s['child_count']],
            significant_bits_identical=r['payload']==s['payload'],childptr_changed=(r['next_level'],r['first_child'],r['child_count'])
                !=(s['next_level'],s['first_child'],s['child_count'])))
    need(old_positions==sorted(old_positions),'Old records relative order unchanged')
    insertion=sum(i<new['ordinal'] for i in old_positions)
    planned_labels=[r['label'] for r in old]; planned_labels.insert(insertion,'2號')
    # Insertion follows the actual V3 observed ordering; no invented interpretation
    # of old intersections, raw13 or nested branch labels.
    captures={}; artifacts={}
    for name,key in [('v2','root'),('v2','lane')]:
        w=windows[name][key]; fn='v2-'+key+'-raw-window.bin'; art=ns['saved_bytes'](fn,w['raw'])
        captures[name+'_'+key]=dict(**{k:v for k,v in w.items() if k!='raw'},artifact=art)
    w=windows['v3']['lane']; width=126
    val=pure['extract'](w['raw'],w['initial_bit_shift']+new['ordinal']*width,width)
    significant=val.to_bytes(16,'little')
    need(significant.hex()==candidate['payload'],'Extract selected house from cached actual read, no new IMG reads')
    captures['v3_new_2_house']=dict(record=new['record'],ID=new['ID'],significant_bits=126,primary_ref=19,
        initial_bit_shift=new['initial_bit_shift'],table_relative_bit_offset=new['table_relative_bit_offset'],
        logical_MDR_byte_offset=new['logical_MDR_byte_offset'],extracted_from_cached_actual_group=True,
        artifact=ns['saved_bytes']('v3-selected-2-house-significant-bits.bin',significant))
    artifacts['raw_captures']=save('actual-raw-capture-metadata.json',dict(schema='garmin-minimal-control-raw-capture/v1',
        captures=captures,parent_actual_bit_offsets={k:dict(root=v['root'],lane=v['lane']) for k,v in actual.items()},
        no_pointer_patch=True,no_append_payload_or_IMG_produced=True,no_actual_IMG_reread_for_saving=True))
    artifacts['source']=save('selected-control.json',dict(schema='garmin-source-backed-minimal-lane-control/v1',candidate=candidate,
        complete_path=path,screened_candidates=screens,full_source_members=candidate['source_members'],
        inherited_full_source_leaf_ledger_pin=witness['source_new_leaf_ledger_pin'],full_source_ledger_read_this_scope=False,
        source_point_and_raw24_city_geometry_inherited=target['source_geometry_decision']['eligible'] and target['exact_raw24_geometry_decision']['eligible'],
        geometry_scope='complete source city only, not source district polygon',
        source_OSM_address_semantics=True,official_postal_house_verified=False,name_alias_transform_used=False))
    artifacts['actual_records']=save('actual-v2-v3-records.json',actual)
    artifacts['read_receipts']=save('actual-IMG-read-receipts.json',dict(schema='garmin-ordinary-file-capture-read-ledger/v1',
        exact_capture_only_bytes=budget.bytes,exact_capture_only_operations=len(budget.rows),reads=budget.rows,
        first_failed_run_exact_readledger_not_preserved=True,first_failed_run_conservative_upper_bound_bytes=FIRST_RUN_READ_UPPER_BOUND,
        capture_only_read_cap_bytes=TOTAL_IMG_LIMIT-FIRST_RUN_READ_UPPER_BOUND,
        combined_read_upper_bound_bytes=FIRST_RUN_READ_UPPER_BOUND+budget.bytes,combined_read_cap_bytes=TOTAL_IMG_LIMIT,
        first_run_bound_derivation='Per image: metadata<=200000, MDR/GMP/LBL headers1610, root14+label64, L4group<=16368+1023 labels*64, L5group<=16114+1023 labels*64, selected label64; two images <740000. Strict group cap1023 and label cache ensure this bound.'))
    first_v2_l4=v2['tables'][4]['count']+1; first_v2_l5=v2['tables'][5]['count']+1
    after_counts=[v2['tables'][i]['count'] for i in range(1,7)]; after_counts[3]+=267; after_counts[4]+=5
    delta4=267*16; delta5=(after_counts[4]*126+7)//8-v2['tables'][5]['bytes']; delta=delta4+delta5
    c=v2['container']; old_size=c['component_sizes']['00004171.MDR']; new_size=old_size+delta
    blocks_before=c['component_blocks']['00004171.MDR']; blocks_after=(new_size+4095)//4096
    parts_before=c['component_parts']['00004171.MDR']; parts_after=(blocks_after+239)//240
    new_img=c['bytes']+(blocks_after-blocks_before)*4096
    need(first_v2_l4+266<(1<<23) and first_v2_l5<(1<<22) and new_img<=c['capacity']
         and parts_after-parts_before<=c['free_FAT_rows'],'Same actual112-bit/4K capacity arithmetic')
    differences=[]
    for a,b in zip(v2['root_children'],v3['root_children']):
        if (a['next_level'],a['first_child'],a['child_count'])!=(b['next_level'],b['first_child'],b['child_count']):
            differences.append(dict(ordinal=a['ordinal'],label=a['label'],v2_record=a['record'],v3_record=b['record'],
                v2_childrange=[a['next_level'],a['first_child'],a['child_count']],v3_childrange=[b['next_level'],b['first_child'],b['child_count']]))
    plan=dict(schema='garmin-minimal-lane-render-isolation-cow-plan/v1',status='read-plan only, no delta or IMG produced',
        baseline_IMG=images['v2'],baseline_actual_L3_first_width=23,baseline_actual_L3_stride=112,
        selected_root=dict(record=v2['root']['record'],ID=1153,old_first=v2['root']['first_child'],old_count=267),
        clone_from_v2_only=dict(L4_group=captures['v2_root'],L5_group=captures['v2_lane']),
        projected_appends=dict(L4_first=first_v2_l4,L4_count=267,L5_first=first_v2_l5,L5_count=5),
        root_patch=dict(level=3,ID=1153,new_first=first_v2_l4,count=267,preserve_all_other_bits=True),
        selected_lane_patch=dict(source_v2_record=v2['lane']['record'],source_ordinal=v2['lane']['ordinal'],
            projected_new_L4_ID=first_v2_l4+v2['lane']['ordinal'],new_first=first_v2_l5,count=5,raw_flags=5,
            preserve_all_other_bits=True),
        preserved_old_L5_records=comparison,old_relative_order_preserved=True,
        new_2_house=dict(significant_bits=captures['v3_new_2_house'],insert_ordinal=insertion,
                         rawflags=0,no_childptr=True,source_members_artifact=artifacts['source']),
        projected_group_labels=planned_labels,old_unknown_bits_flags_and_lower_pointers_preserved_verbatim=True,
        actual_v3_group_extra_house_excluded='3號',
        v3_direct_subtree_copy=dict(L5_group_first=v3['lane']['first_child'],L5_group_count=6,
            all_zero_flags_or_ptrs=False,not_safe_as_zero_branch_terminal_subtree=True,
            raw_flags=[r['raw_flags'] for r in full],requires_preserve_v2_old_bits_and_ptrs=True,
            existing_record_pointer_differences=comparison),
        v3_root_group_not_to_copy=dict(changed_childptr_count=len(differences),changes=differences,
            explanation='V3 siblings can reference other COW lowergroups. Keep all v2 sibling bytes/pointers except the selected lane range.'),
        table_counts_before=[v2['tables'][i]['count'] for i in range(1,7)],table_counts_projected=after_counts,
        profile_unchanged=True,lower_strides={str(i):v2['tables'][i]['stride'] for i in (3,4,5,6)},
        L5_splice=dict(old_significant_bits=v2['tables'][5]['count']*126,old_unused_pad_bits=(-v2['tables'][5]['count']*126)%8,
            append_significant_bits=5*126,new_unused_pad_bits=(-after_counts[4]*126)%8,byte_prefix_append_not_valid=True),
        arithmetic=dict(L4_growth_bytes=delta4,L5_growth_bytes=delta5,MDR_growth_bytes=delta,MDR_before=old_size,MDR_projected=new_size,
            MDR_4K_blocks_before=blocks_before,MDR_4K_blocks_projected=blocks_after,MDR_FAT_parts_before=parts_before,
            MDR_FAT_parts_projected=parts_after,additional_FAT_rows=parts_after-parts_before,
            metadata_bytes=c['metadata_end'],IMG_before=c['bytes'],IMG_projected=new_img,declared_4K_capacity=c['capacity']),
        exact_v2_4K_header_can_be_preserved_in_future_writer_arithmetic=True,
        header_preservation_not_actual_output_validation=True,existing_GMP_ref=19,actual_existing_GMP_label='2號',
        new_GMP_text_or_JAI_rows_needed=False,
        future_writer_required=['Read only captured original v2 root267 records and L5 old4 significant bits',
            'Preserve all old flags, crossing labels and lower pointers verbatim; do not clone their descendants',
            'Insert source-bound flags0/ref19 2號 significant bits at observed V3 relative insertion ordinal',
            'Append new L5 group at old significant end; consume old2 pad bits and leave new4 pad bits',
            'Clone v2 L4 group267 once and patch only selected 4巷 first/count',
            'Patch existing L3 root1153 first/count, relocate suffix and six DIR starts/MDR DIRheader as needed',
            'Repack same4K header/FAT geometry; preserve five other components and GMP labels byte exact'],
        official_postal_or_renderer_or_device_acceptance_verified=False,full_Taiwan_complete=False)
    artifacts['plan']=save('minimal-cow-plan.json',plan)
    proof=dict(schema='garmin-minimal-lane-capture-and-failed-guard-proof/v1',started_utc=started,
        finished_utc=datetime.now(timezone.utc).isoformat(),all_assigned_capture_and_plan_checks_passed=True,
        first_run_all_guards_passed=False,first_actual_exit_code=1,first_actual_terminal='1fcd04',
        first_actual_failure_retained=dict(path=str((HERE/'failure.json').relative_to(ROOT)),bytes=len(failure_raw),sha256=sha(failure_raw)),
        first_failed_source_sha256=FAILED_SOURCE_SHA,old_guard_modified_or_relaxed=False,
        capture_only_after_explicit_root_authorization=True,failed_all_zero_subtree_assumption_not_reused=True,
        source_inputs=inputs,candidate_input_bindings=images,artifacts=artifacts,
        screened_candidate_count=3,selected_source_ids=candidate['source_ids'],selected_source_group_ids=candidate['source_group_ids'],
        source_OSM_semantics=True,complete_source_IDs_and_members_embedded_in_small_sealed_sample=True,
        inherited_full_new_leaf_ledger_pin=witness['source_new_leaf_ledger_pin'],full_ledger_EOF_SHA_inherited_only=True,
        full_big_source_or_new_leaf_ledger_read=False,PBF_read=False,
        source_geometry_scope='inherited complete city only, not source district polygon',
        source_geometry_reexecuted=False,no_floor_unit_door_level_metadata=True,no_embedded_floor_unit=True,
        no_alias_or_name_transform_applied=True,no_coordinate_conflict_or_firstpoint_selection=True,
        actual_v2_house_exact_membership='absent',actual_v3_house_exact_membership='unique',
        selected_actual_v3_payload_ref_point_equals_sealed_source=True,
        original_v2_old4_records_comparison=comparison,
        all_old4_significant_bits_preserved_in_v3=all(r['significant_bits_identical'] for r in comparison),
        actual_v2_old4_flags=[r['raw_flags'] for r in old],actual_v3_L5_flags=[r['raw_flags'] for r in full],
        selected_source_leaf_flag0=True,selected_house_insertion_ordinal=insertion,
        actual_v2_v3_root_children=267,original_v2_L5_records=4,actual_v3_L5_records=6,
        actual_capture_only_IMG_bytes_read=budget.bytes,actual_capture_only_IMG_read_operations=len(budget.rows),
        first_run_exact_IMG_counter_not_preserved=True,first_run_read_upper_bound=FIRST_RUN_READ_UPPER_BOUND,
        combined_IMG_read_upper_bound=FIRST_RUN_READ_UPPER_BOUND+budget.bytes,combined_IMG_read_cap=TOTAL_IMG_LIMIT,
        capture_only_per_IMG_bytes={name:sum(r['bytes'] for r in budget.rows if r['image']==name) for name in images},
        MAIN_bytes_read=0,CPU_executed=False,guest_audio_native_code_executed=False,physical_device_IO=False,
        whole_IMG_SHA_recomputed=False,new_IMG_or_delta_created=False,pointer_patch_produced=False,
        old_sealed_source_IMG_or_report_or_canonical_modified=False,
        current_UI_renderer_official_postal_house_or_device_acceptance_verified=False,
        full_Taiwan_or_App_complete=False,all_own_and_IMG_handles_closed=True,
        max_RSS_KiB=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,elapsed_seconds_receipt_only=time.monotonic()-t0)
    art=save('proof.json',proof)
    print(json.dumps(dict(all_assigned_capture_and_plan_checks_passed=True,first_failure_retained=True,proof=art,
        exact_capture_IMG_read_bytes=budget.bytes,combined_IMG_read_upper_bound=FIRST_RUN_READ_UPPER_BOUND+budget.bytes,
        old4_flags=[r['raw_flags'] for r in old],old4_labels=[r['label'] for r in old],new_insert_ordinal=insertion,
        actual_v3_root_childptr_changed=len(differences),projected_IMG_bytes=new_img,projected_MDR_growth=delta,
        handles_closed=True),ensure_ascii=False))


if __name__=='__main__':
    main()
