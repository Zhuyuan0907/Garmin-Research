#!/usr/bin/env python3
"""Read only own newly produced outputs; do not reopen candidate/inputs."""
from pathlib import Path
from collections import Counter
import gzip
import hashlib
import json

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
proof=json.loads((HERE/'proof.json').read_text());pins=proof['artifacts'];audits=[]


def need(value,message):
    if not value:raise ValueError(message)


def stat(path):
    s=path.stat();return(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)


def rows(pin):
    path=ROOT/pin['path'];need(path.is_relative_to(HERE),'Own output only');before=stat(path)
    raw=hashlib.sha256()
    with path.open('rb')as f:
        for b in iter(lambda:f.read(1<<20),b''):raw.update(b)
    need(before[2]==pin['bytes']and raw.hexdigest()==pin['sha256'],'Fresh output compressed hash')
    count=amount=0;plain=hashlib.sha256()
    with gzip.open(path,'rb')as f:
        for line in f:count+=1;amount+=len(line);plain.update(line);yield json.loads(line)
    need(count==pin['rows']and amount==pin['uncompressed_bytes']and plain.hexdigest()==pin['uncompressed_sha256'],'Fresh output plain hash/rows/EOF')
    need(stat(path)==before,'Own output immutable stat');audits.append(dict(path=pin['path'],rows=count,all_pins_EOF_stat_verified=True))


groups={};clones=Counter();newleaves=Counter();owners={};firstmax=Counter();nextcursor={4:3781595,5:2667574,6:1984067}
for row in rows(pins['closure_groups']):
    c=row['current_group'];key=(c['level'],c['first'],c['count']);need(key not in groups,'Unique exact clone group')
    groups[key]=row;level=key[0];clones[level]+=row['clone_old_records'];newleaves[level]+=row['new_integer_house_targets']
    need(row['clone_old_records']==key[2]and row['planned_new_count']==key[2]+row['new_integer_house_targets'],'Whole current group cloned')
    need(row['new_integer_house_targets']==len(row['inserted_house_numbers'])and row['inserted_house_numbers']==sorted(set(row['inserted_house_numbers'])),
         'Strict integer group insertions')
    need(not row['native_write_ready']and row['unknown_old_child_fields_preserved'],'Planning preserves unknown raw groups')
    for owner in row['current_parent_owners']:
        need(owner not in owners or owners[owner]==key,'One child group per current parent')
        owners[owner]=key;firstmax[owner>>28]=max(firstmax[owner>>28],row['planned_new_first'])
    patchordinals=set()
    for patch in row['proposed_child_patches']:
        ordinal=patch['current_child_ordinal'];need(0<=ordinal<key[2]and ordinal not in patchordinals,'Unique old child patch ordinal')
        patchordinals.add(ordinal);need(patch['current_child_record']==(level<<28|key[1]+ordinal),'Actual current child ID rather than stock ID')
for level in [6,5,4]:
    for key,row in sorted(groups.items()):
        if key[0]!=level:continue
        need(row['planned_new_first']==nextcursor[level],'Continuous per-table append group allocation')
        nextcursor[level]+=row['planned_new_count']
for row in groups.values():
    for patch in row['proposed_child_patches']:
        target=tuple(patch['referenced_group']);need(target in groups and owners[patch['current_child_record']]==target,'Transitive patch reaches exact new child group')
pathplans={};remapped=0
for row in rows(pins['paths']):
    stock=row['stock_parent_record'];need(stock not in pathplans,'One path per stock parent');pathplans[stock]=row
    need(row['path'][0]['current_record']>>28==3 and row['path'][-1]['current_record']==row['current_parent_record'],'Current full path connects root to parent')
    if stock!=row['current_parent_record']:remapped+=1
counts=Counter();flags=Counter();nested=0;example=None
for row in rows(pins['ready_parents']):
    stock=row['stock_parent']['record'];path=pathplans[stock];current=row['current_parent_record'];g=row['current_child_group'];key=(g['level'],g['first'],g['count'])
    need(not row['reasons']and not row['native_write_ready']and not row['current_exact_present_targets'],'Admitted planning absent from actual current groups')
    need(row['current_path']==path['path']and current==path['current_parent_record']and owners[current]==key,'Parent updates current copy and full path')
    actual=groups[key];numbers=[t['number']for t in row['missing_targets']]
    need(numbers==actual['inserted_house_numbers']and len(numbers)==actual['new_integer_house_targets'],'Parent target set matches clone group')
    need(row['planned_group_count']==actual['planned_new_count'],'Parent group count matches allocated group')
    need(set(map(int,row['numeric_insertion_ordinals']))==set(numbers),'Each new integer has insertion ordinal')
    positions=list(row['numeric_insertion_ordinals'].values());need(len(set(positions))==len(positions)and all(0<=x<row['planned_group_count']for x in positions),'Unique valid insertion ordinals')
    for target in row['missing_targets']:
        need(target['house_label']==str(target['number'])+'號'and type(target['primary_ref'])is int and len(target['raw24'])==2,'Source house/reference/raw24 bound')
        need(target['source_ids']==sorted(set(target['source_ids']))and len(target['source_ids'])==target['source_node_count'],'Full source IDs retained')
        counts['source_node_members']+=target['source_node_count']
    counts['ready_parents']+=1;counts['new_integer_targets']+=len(numbers);nested+=row['old_nested_child_count']
    flags.update({int(k):v for k,v in row['old_raw_child_flag_counts'].items()})
    for edge in row['path_edges']:
        edgekey=tuple(edge['child_group']);need(edgekey in groups and owners[edge['parent_record']]==edgekey,'All current ancestors patched through clone group')
        need(any(p['current_child_record']==edge['current_child_record']for p in groups[edgekey]['proposed_child_patches']),'Current parent copy receives transitive range patch')
    if example is None and current!=stock:example=dict(stock_parent_record=stock,current_parent_record=current,path=row['current_path'])
for row in rows(pins['held_parents']):counts['held_parents']+=1
readbytes=ops=0
for row in rows(pins['candidate_reads']):readbytes+=row['bytes'];ops+=1
need(readbytes==proof['candidate_readbytes']and ops==proof['candidate_read_operations'],'Read receipts account for actual bounded IMG reads')
capacitypath=HERE/'capacity-and-width-plan.json';capacityraw=capacitypath.read_bytes();need(hashlib.sha256(capacityraw).hexdigest()==pins['capacity']['sha256'],'Capacity plan hash')
capacity=json.loads(capacityraw)
need({str(k):v for k,v in clones.items()}==proof['admitted_COW_clone_counts']and{str(k):v for k,v in newleaves.items()}==proof['admitted_new_leaf_counts'],'All group clone/new totals independently summed')
need(dict(firstmax)=={int(k):v for k,v in capacity['maximum_new_first_by_parent_level'].items()},'Every actual owner maximum first verified')
need(counts['ready_parents']==20613 and counts['new_integer_targets']==58233 and counts['source_node_members']==111147,'Every ready target and full source member accounted')
for level,end in nextcursor.items():need(end-1==int(capacity['proposed_table_counts'][str(level)]),'Allocation last ID equals final table count')
for variant in capacity['capacity_variants']:
    cursor=int(capacity['current_tables']['6']['start'])
    for level in [6,5,4,3,2,1]:
        t=variant['tables'][str(level)];need(t['start']==cursor and t['bytes']==(t['count']*t['stride']+7)//8,'Minimal bit spans, no stray lookahead/padding table')
        cursor+=t['bytes']
    need(cursor==variant['MDR_directory_start']and cursor+120==variant['MDR_component_bytes'],'DIR EOF physical suffix')
    need(not variant['original4K_fits']and variant['explicit8K_profile_fits']and not variant['explicit8K_on_device_acceptance_proved'],'Capacity distinction retained')
audit=dict(all_own_output_audits_passed=True,audits=audits,independently_summed_counts=dict(counts),clone_counts=dict(clones),
           new_leaf_counts=dict(newleaves),source_to_current_parent_ID_remaps=remapped,old_final_group_raw_flag_counts=dict(flags),
           old_nested_records_in_final_groups=nested,current_copy_example=example,
           original_candidate_or_source_inputs_reopened=False,native_CPU_or_geometry_or_closed_suite_reexecuted=False)
with(HERE/'output-readback-proof.json').open('x')as f:json.dump(audit,f,ensure_ascii=False,indent=2);f.write('\n')
print(json.dumps(audit,ensure_ascii=False))
