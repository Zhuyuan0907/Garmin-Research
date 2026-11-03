#!/usr/bin/env python3
"""Independent output-only structural/provenance/tight-file audit."""
from pathlib import Path
from collections import Counter
import gzip
import hashlib
import json
import mmap

HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[1]
proof=json.loads((HERE/'proof.json').read_text());pins=proof['artifacts'];audits=[];widths={4:128,5:126,6:68};basecounts={4:3781594,5:2667573,6:1984066}


def need(x,message):
    if not x:raise ValueError(message)


def identity(path):
    s=path.stat();return(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)


def readpin(pin):
    p=ROOT/pin['path'];need(p.is_relative_to(HERE),'Own outputs only');before=identity(p);h=hashlib.sha256()
    with p.open('rb')as f:
        for b in iter(lambda:f.read(1<<20),b''):h.update(b)
    need(before[2]==pin['bytes']and h.hexdigest()==pin['sha256'],'Fresh own compressed/file SHA')
    return p,before


def rows(pin):
    p,before=readpin(pin);count=amount=0;h=hashlib.sha256()
    with gzip.open(p,'rb')as f:
        for line in f:count+=1;amount+=len(line);h.update(line);yield json.loads(line)
    need(count==pin['rows']and amount==pin['uncompressed_bytes']and h.hexdigest()==pin['uncompressed_sha256']and identity(p)==before,'Own plain EOF/rows/hash/stat')
    audits.append(dict(path=pin['path'],rows=count,all_pins_EOF_stat_verified=True))


def bitrecord(raw,bit,width):
    byte,shift=divmod(bit,8);span=(shift+width+7)//8;need(byte+span<=len(raw),'Actual tight record bounds')
    return(int.from_bytes(raw[byte:byte+span],'little')>>shift)&((1<<width)-1)


handles={n:(HERE/a['path']).open('rb')for n,a in [(int(k),v)for k,v in proof['append_artifacts'].items()]}
maps={n:mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ)for n,f in handles.items()};groups={};owners={};clonecounts=Counter();newcounts=Counter();cursor=Counter();groupchecks=0
for row in rows(pins['groups']):
    g=row['current_group'];key=(g['level'],g['first'],g['count']);level=key[0];need(key not in groups,'Unique emitted COW group');groups[key]=row
    need(row['appended_bit_offset']==cursor[level]*widths[level]and row['new_first']==basecounts[level]+cursor[level]+1,'Continuous tight groups without byte padding')
    cursor[level]+=row['new_count'];clonecounts[level]+=key[2];newcounts[level]+=row['new_integer_leaf_count']
    inserted=row['inserted_new_ordinals'];need(len(inserted)==row['new_integer_leaf_count']and inserted==sorted(set(inserted)),'Unique actual inserted ordinals')
    need(row['new_count']==key[2]+len(inserted)and row['all_other_old_significant_bits_preserved']and row['old_relative_order_preserved'],'Complete current old records scheduled')
    h=hashlib.sha256()
    for i in range(row['new_count']):h.update(bitrecord(maps[level],row['appended_bit_offset']+i*widths[level],widths[level]).to_bytes((widths[level]+7)//8,'little'))
    need(h.hexdigest()==row['new_significant_records_sha256'],'Every real tight group hash matches output metadata')
    for owner in row['current_parent_owners']:need(owner not in owners,'One emitted group per parent');owners[owner]=key
    groupchecks+=1
parentmaps={};patches=Counter()
for row in rows(pins['parent_mappings']):
    level=row['parent_level'];current=row['current_parent_record'];need(current not in parentmaps,'Unique current cloned parent mapping');parentmaps[current]=row
    value=bitrecord(maps[level],row['appended_bit_offset'],widths[level]);old=int.from_bytes(bytes.fromhex(row['old_payload']),'little');expected=int.from_bytes(bytes.fromhex(row['new_payload']),'little')
    need(value==expected and row['new_parent_record']==(level<<28|row['new_lowID'])and row['appended_bit_offset']==(row['new_lowID']-basecounts[level]-1)*widths[level],'Actual copied parent position/payload')
    firstwidth,countwidth,flagbit=(22,10,71)if level==4 else(21,9,69);first=value>>39&((1<<firstwidth)-1);count=value>>(39+firstwidth)&((1<<countwidth)-1)
    mask=((1<<(firstwidth+countwidth))-1)<<39
    need((value^old)&~mask==0 and int(row['explicit_first_count_mask_hex'],16)==mask and(value>>flagbit&511)==row['original_fields']['raw_flags'],'Independent fixed-profile explicit patch mask preserves every other old bit')
    key=tuple(row['referenced_group']);group=groups[key];need(owners[current]==key and(first,count)==(group['new_first'],group['new_count']),'Actual cloned parent points to exact emitted child group')
    patches[level]+=1
selectedpath,before=readpin(pins['selected_ranges']);selected=json.loads(selectedpath.read_text());classifications=Counter();rootIDs=set()
for row in selected:
    record=3<<28|row['one_based_street_ID'];need(record not in rootIDs,'Unique selected root');rootIDs.add(record);key=tuple(row['group_key']);group=groups[key]
    need(owners[record]==key and(row['first_child'],row['count'])==(group['new_first'],group['new_count'])and row['original_flags']&7==row['next_level']==key[0],'Every root reaches current COW path')
    need(row['first_child']<(1<<23)and row['count']<(1<<12),'Current L3 fields fit')
    classifications['already_selected_v2'if row['was_selected_in_v2']else'previously_stock_range']+=1
need(identity(selectedpath)==before and classifications==Counter(already_selected_v2=6366,previously_stock_range=1284),'All selected/unselected current branches classified')
leafcounts=Counter();fullmembers=0;newIDs=set();sourceorder=None
for row in rows(pins['new_records']):
    level=row['level'];key=(row['stock_parent_record'],row['numeric_house']);need(sourceorder is None or sourceorder<key,'Full new source targets numeric order');sourceorder=key
    value=bitrecord(maps[level],row['appended_bit_offset'],widths[level]);need(value==int.from_bytes(bytes.fromhex(row['payload']),'little'),'Every actual new leaf payload')
    if level==5:reference=value>>20&524287;point=[value>>78&16777215,value>>102&16777215];need(value>>39&((1<<39)-1)==0,'L5 leaf zero first/count/flags')
    else:reference=value>>1&524287;point=[value>>20&16777215,value>>44&16777215]
    need(value&1==1 and(reference,point)==(row['primary_ref'],row['raw24']),'Independent actual leaf ref/point bit extraction')
    identitykey=(level,row['new_lowID']);need(identitykey not in newIDs,'Unique emitted new house ID');newIDs.add(identitykey)
    source=row['source_ready_target'];need(not source['reasons']and not source['native_write_ready']and source['source_geometry_decision']['eligible']and source['exact_raw24_geometry_decision']['eligible'],'Full inherited qualified source/geometry evidence')
    need(source['source_members']==row['source_members']and source['source_ids']==row['source_ids']and source['source_group_ids']==row['source_group_ids']and source['planned_raw24']==row['raw24']and source['selected_coordinate_strings']==row['coordinate_strings'],'Full source-ready provenance unchanged')
    union=sorted({ID for member in row['source_members']for ID in member['source_ids']});need(union==row['source_ids']and len(union)==row['source_node_count'],'Complete actual source ID union')
    parent=parentmaps[row['current_parent_record']];need(parent['new_parent_record']==row['new_parent_record']and parent['patched_first_child']<=row['new_lowID']<parent['patched_first_child']+parent['patched_child_count'],'Every actual new house reachable from actual copied parent')
    leafcounts[level]+=1;fullmembers+=row['source_node_count']
priorcounts=Counter();priorhash=hashlib.sha256()
for row in rows(pins['prior_new_identities']):
    priorhash.update(row['source_content_identity_sha256'].encode()+b'\n')
    if row['status']=='actual_cloned_append_payload_identical':
        level=row['level'];value=bitrecord(maps[level],row['appended_bit_offset'],widths[level]);need(value==int.from_bytes(bytes.fromhex(row['unchanged_payload']),'little'),'Every classified copied prior new leaf remains identical')
        priorcounts['copied_prior_new_leaves']+=1
    else:need(row['actual_full_IMG_prefix_preservation_still_integration_gate'],'Untouched prior prefix gate retained');priorcounts['untouched_current_prefix_prior_new_leaves']+=1
readbytes=readops=0
for row in rows(pins['candidate_reads']):readbytes+=row['bytes'];readops+=1
need(groupchecks==29866 and len(parentmaps)==22216 and len(selected)==7650 and sum(leafcounts.values())==58233 and fullmembers==111147,'All closure/source totals independently verified')
need(dict(priorcounts)==proof['prior_v2_new_leaf_identity_counts']and priorhash.hexdigest()==proof['prior_v2_source_content_identity_digest'],'All130637prior identities classified and digest retained')
for level,mapping in maps.items():
    artifact=proof['append_artifacts'][str(level)];need(hashlib.sha256(mapping).hexdigest()==artifact['sha256']and len(mapping)==artifact['bytes'],'Fresh tight file digest/size')
    need(cursor[level]==artifact['record_count']and artifact['bit_length']==cursor[level]*widths[level],'Actual tight count/bit length')
    tail=artifact['unused_final_high_bits'];need(not tail or mapping[-1]>>(8-tail)==0,'Only terminal padding zero')
    mapping.close();handles[level].close()
need(readbytes==proof['candidate_readbytes']and readops==proof['candidate_read_operations'],'Bounded actual source read receipts accounted')
result=dict(all_own_output_audits_passed=True,ledger_audits=audits,actual_tight_group_hash_checks=groupchecks,
    independently_summed_current_clone_counts=dict(clonecounts),new_leaf_counts=dict(leafcounts),explicit_parent_patch_counts=dict(patches),
    selected_L3_classification=dict(classifications),full_new_source_node_memberships=fullmembers,prior_new_identity_counts=dict(priorcounts),
    original_candidate_source_geometry_or_quantization_reopened=False,native_CPU_or_closed_suite_executed=False,whole_IMG_written=False)
with(HERE/'output-readback-proof.json').open('x')as f:json.dump(result,f,ensure_ascii=False,indent=2);f.write('\n')
print(json.dumps(result))
