#!/usr/bin/env python3
"""Derive complete future COW paths from sealed current paths and own mappings."""
from pathlib import Path
import importlib.util
import hashlib
import json
import sys

HERE=Path(__file__).resolve().parent
source=HERE/'prepare_lane_cow_appends.py'
spec=importlib.util.spec_from_file_location('sealed_producer_path_IO',source);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
inputs=[];h=m.imported(m.PLAN/'plan_lane_tree_overlay.py',m.HELPER_SHA,'sealed_tree_path_input_IO',inputs)
proof=json.loads((HERE/'proof.json').read_text());need=m.need
need(hashlib.sha256((HERE/'proof.json').read_bytes()).hexdigest()=='1cde367d1d3aba44290b7f44be40c9cb5d04bf911a3e8bd3898e071a1329b4e9','Producer proof binding')
parentmaps={r['current_parent_record']:r for r in h.ledger_input(HERE/'cloned-parent-mappings.jsonl.gz',proof['artifacts']['parent_mappings'],inputs)}
selected={3<<28|r['one_based_street_ID']:r for r in json.loads((HERE/'selected-l3-range-changes.json').read_text())}
need(hashlib.sha256((HERE/'selected-l3-range-changes.json').read_bytes()).hexdigest()==proof['artifacts']['selected_ranges']['sha256'],'Root selected binding')
planraw=m.pinned(m.PLAN/'proof.json','68bdcaeb2dbf0eaa070653bacf63dcb2541edf986dfc2fdba87cfd0a22d35622',inputs);plan=json.loads(planraw)
out=m.Ledger('new-tree-parent-paths.jsonl.gz');paths=edges=0;roots=set();finalparents=set()
for row in h.ledger_input(m.PLAN/'current-path-mappings.jsonl.gz',plan['artifacts']['paths'],inputs):
    steps=row['path'];newsteps=[];links=[]
    for step in steps:
        current=step['current_record'];new=parentmaps[current]['new_parent_record']if current>>28!=3 else current
        newsteps.append(dict(stock_record=step['stock_record'],current_v2_record=current,new_COW_record=new,label=step['label'],raw_flags=step['raw_flags']))
    for parent,child in zip(newsteps,newsteps[1:]):
        current=parent['current_v2_record'];level=child['new_COW_record']>>28;ID=child['new_COW_record']&0xfffffff
        if current>>28==3:
            root=selected[current];first,count,nextlevel,flags=root['first_child'],root['count'],root['next_level'],root['original_flags'];roots.add(current)
        else:
            mapping=parentmaps[current];first,count,nextlevel,flags=mapping['patched_first_child'],mapping['patched_child_count'],mapping['original_fields']['next_level'],mapping['original_fields']['raw_flags']
        need(nextlevel==level and first<=ID<first+count and flags==parent['raw_flags'],'Complete new ancestor path reaches exact copied descendant without flags conversion')
        links.append(dict(parent_new_record=parent['new_COW_record'],next_level=nextlevel,first_child=first,count=count,raw_flags=flags,
                          child_new_record=child['new_COW_record'],child_ordinal=ID-first));edges+=1
    final=newsteps[-1];mapping=parentmaps[final['current_v2_record']];finalparents.add(final['new_COW_record'])
    out.add(dict(stock_parent_record=row['stock_parent_record'],current_v2_parent_record=row['current_parent_record'],new_COW_parent_record=final['new_COW_record'],
                 complete_path=newsteps,ancestor_links=links,new_house_group_first=mapping['patched_first_child'],new_house_group_count=mapping['patched_child_count'],
                 next_leaf_level=mapping['original_fields']['next_level'],full_flags=mapping['original_fields']['raw_flags'],
                 complete_tree_path_metadata_ready=True,actual_full_IMG_readback_pending=True,native_write_ready=False));paths+=1
need(paths==20613 and len(roots)==7650 and len(finalparents)==20613,'Complete unique new path/parent/root closure')
artifact=out.close();result=dict(schema='prepared-COW-complete-path-derivation/v1',all_checks_passed=True,inputs=inputs,artifact=artifact,
    paths=paths,ancestor_links=edges,roots=len(roots),unique_new_parent_records=len(finalparents),current_candidate_not_reopened=True,
    full_IMG_not_written_or_read=True,native_CPU_not_executed=True,native_write_ready=False)
m.saved('new-tree-path-proof.json',result);print(json.dumps(result,ensure_ascii=False))
