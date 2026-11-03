#!/usr/bin/env python3
"""Read-only current-candidate tree closure and capacity planning.

No record encoding, native writer invocation, binary/map/device output or old
test execution. Current IMG is opened only after its root-created file seal.
"""
from pathlib import Path
from datetime import datetime, timezone
from collections import Counter, defaultdict
from bisect import bisect_left
import array
import gzip
import hashlib
import importlib.util
import json
import math
import os
import re
import resource
import struct
import sys
import time

ROOT=Path('/root/garmin')
HERE=Path(__file__).resolve().parent
JOIN=ROOT/'staging/navigation-country-lane-absent-source-join-v1'
BASE=ROOT/'staging/navigation-country-native-candidate-v2'
CORE=ROOT/'staging/navigation-native-general-writer-v1/native_ap_writer.py'
CORE_SHA='cb190d5f3c70f0e81e9d49808dff044e4717b5061f749e7720af56aee39b0cf8'
JOIN_SEAL_SHA='484f1366c2baf96bcd9560028599a62149984b1356ba4ad5c2146f6b17802f95'
BASE_SHA='925a515b668f3878ef0acea3e1c79188c15216f1af7f039c0e426942907ebefb'
EXPECTED_COUNTS=[22,343,47870,3781594,2667573,1984066]
PROFILES=[([16,9,24,19,1,10,0,0],[1,1],122),([16,9,24,19,1,10,0,0],[1,1],122),
          ([23,9,24,19,1,12,0,0],[1,0],112),([22,9,24,19,1,10,0,0],[1,1],128),
          ([21,9,24,19,1,9,0,0],[1,1],126),([0,0,24,19,1,0,0,0],[1,0],68)]
INTEGER=re.compile(r'[1-9][0-9]*號\Z')
BASE_NUMBER=re.compile(r'[0-9]+')
MAX_RSS_KIB=512000


def need(ok,message):
    if not ok:raise ValueError(message)


def sha(data):return hashlib.sha256(data).hexdigest()


def stat(path):
    s=path.stat();return [s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]


def raw_input(path,expected,receipts,maximum=30_000_000):
    before=stat(path);need(before[2]<=maximum,'Small pinned metadata ceiling')
    raw=path.read_bytes();need(stat(path)==before and sha(raw)==expected,'Pinned immutable metadata: '+str(path))
    receipts.append(dict(path=str(path.relative_to(ROOT)),bytes=len(raw),sha256=expected,stat_before=before,stat_after=stat(path)))
    return raw


class HashReader:
    def __init__(self,f):self.f=f;self.hash=hashlib.sha256();self.count=0
    def read(self,n=-1):
        b=self.f.read(n);self.hash.update(b);self.count+=len(b);return b


def ledger_input(path,pin,receipts):
    before=stat(path);plain=hashlib.sha256();rows=amount=0
    with path.open('rb')as f:
        reader=HashReader(f)
        with gzip.GzipFile(fileobj=reader,mode='rb')as z:
            for line in z:
                plain.update(line);amount+=len(line);rows+=1;yield json.loads(line)
    need(rows==pin['rows'] and reader.count==pin['bytes'] and reader.hash.hexdigest()==pin['sha256'],
         'Compressed input rows/bytes/hash/EOF')
    need(plain.hexdigest()==pin['uncompressed_sha256'] and stat(path)==before,'Plain input pin and immutable stat')
    receipts.append(dict(path=str(path.relative_to(ROOT)),rows=rows,bytes=reader.count,sha256=reader.hash.hexdigest(),
        uncompressed_bytes=amount,uncompressed_sha256=plain.hexdigest(),gzip_EOF_verified=True,stat_before=before,stat_after=stat(path)))


class Ledger:
    def __init__(self,name):
        self.path=HERE/name;self.f=self.path.open('xb');self.z=gzip.GzipFile(filename='',fileobj=self.f,mode='wb',mtime=0)
        self.rows=self.amount=0;self.h=hashlib.sha256()
    def add(self,row):
        raw=json.dumps(row,ensure_ascii=False,separators=(',',':')).encode()+b'\n';self.z.write(raw)
        self.h.update(raw);self.amount+=len(raw);self.rows+=1
    def close(self):
        self.z.close();self.f.flush();os.fsync(self.f.fileno());self.f.close()
        return dict(path=str(self.path.relative_to(ROOT)),rows=self.rows,bytes=self.path.stat().st_size,
          sha256=sha(self.path.read_bytes()),uncompressed_sha256=self.h.hexdigest(),uncompressed_bytes=self.amount)


def saved(name,row):
    path=HERE/name
    with path.open('x')as f:json.dump(row,f,ensure_ascii=False,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
    return dict(path=str(path.relative_to(ROOT)),bytes=path.stat().st_size,sha256=sha(path.read_bytes()))


def core_module(receipts):
    raw_input(CORE,CORE_SHA,receipts,50_000)
    spec=importlib.util.spec_from_file_location('sealed_overlay_read_core',CORE)
    m=importlib.util.module_from_spec(spec);sys.modules[spec.name]=m;spec.loader.exec_module(m);return m


def decode(value,table):
    w,f=table['widths'],table['reference_flags'];cursor=0;r={}
    for name,width,enabled,isref in [
        ('mapordinal',w[4],True,False),('secondary_ref',w[3],bool(f[1]),True),
        ('primary_ref',w[3],bool(f[0]),True),('first_child',w[0],bool(w[0]),False),
        ('child_count',w[5],bool(w[5]),False),('raw_flags',w[1],bool(w[1]),False),
        ('raw_location_a',w[2],bool(w[2]),False),('raw_location_b',w[2],bool(w[2]),False)]:
        v=(value>>cursor)&((1<<width)-1)if enabled else None if isref else 0
        r[name]=None if enabled and isref and v==(1<<width)-1 else v;cursor+=width if enabled else 0
    need(cursor==table['stride'],'Complete derived-profile field decode');r['next_level']=r['raw_flags']&7
    return r


def extract(raw,bit,width):
    at,shift=divmod(bit,8);size=(shift+width+7)//8
    need(at+size<=len(raw),'Exact packed window record boundary')
    return (int.from_bytes(raw[at:at+size],'little')>>shift)&((1<<width)-1)


def significant_hash(values,width):
    h=hashlib.sha256()
    for value in values:h.update(value.to_bytes((width+7)//8,'little'))
    return h.hexdigest()


def old_to_current_ordinals(old_count,new_count,inserted):
    need(type(old_count)is int and type(new_count)is int and old_count>=0 and new_count>=old_count,'Explicit cloned counts')
    need(len(inserted)==new_count-old_count and all(type(i)is int and 0<=i<new_count for i in inserted),'Exact inserted ordinal set')
    result=[i for i in range(new_count)if i not in inserted]
    need(len(result)==old_count,'Every old ordinal retained once');return result


def numeric_positions(names,numbers):
    anchors=[int(m.group())for name in names if name is not None and(m:=BASE_NUMBER.match(name))]
    if not anchors or anchors!=sorted(anchors):return None
    need(numbers==sorted(set(numbers)),'Unique ascending new integer houses')
    positions={};index=added=0
    for ordinal,name in enumerate(names):
        match=BASE_NUMBER.match(name)if name is not None else None
        if match:
            while index<len(numbers)and numbers[index]<int(match.group()):
                positions[numbers[index]]=ordinal+added;added+=1;index+=1
    for number in numbers[index:]:positions[number]=len(names)+added;added+=1
    return positions


def intervals_overlap(a,b):return a[0]==b[0]and max(a[1],b[1])<min(a[1]+a[2],b[1]+b[2])


class Tree:
    def __init__(self,image):
        self.image=image;self.groups={};self.record_cache={};self.labels={};self.group_rows=0
        header=self.read('00004171.MDR',0,772)
        need(struct.unpack_from('<H',header)[0]==772 and header[2:12]==b'GARMIN MDR','Actual MDR header')
        dstart,n,s,flags=struct.unpack_from('<4I',header,600)
        need((n,s,flags)==(120,20,1)and dstart+120==image.components['00004171.MDR'].size,'Derived directory/EOF')
        directory=self.read('00004171.MDR',dstart,120);self.tables={}
        for level in range(1,7):
            a,b,stride,w,x=struct.unpack_from('<5I',directory,(level-1)*20)
            widths=[(w>>18)&63,(w>>24)&63,(w>>12)&63,(w>>6)&63,w&63,x&63,(x>>11)&63,(x>>17)&63]
            refs=[w>>30&1,w>>31&1];count=b*8//stride
            need((widths,refs,stride)==PROFILES[level-1]and count==EXPECTED_COUNTS[level-1],'Sealed v2 derived profile/count')
            need(b==(count*stride+7)//8,'Minimal significant table span')
            self.tables[level]=dict(level=level,start=a,bytes=b,stride=stride,count=count,widths=widths,reference_flags=refs,
                directory_raw_hex=directory[(level-1)*20:level*20].hex())
        cursor=self.tables[6]['start']
        for level in [6,5,4,3,2,1]:
            table=self.tables[level];need(table['start']==cursor,'Physical level6→5→4→3→2→1');cursor+=table['bytes']
        need(cursor==dstart,'Derived directory suffix closure');self.directory_start=dstart;self.header_hex=header.hex()
        gmp=self.read('I053061A.GMP',0,57);need(gmp[2:12]==b'GARMIN GMP','Actual GMP header')
        lblstart=struct.unpack_from('<7I',gmp,25)[2];lbl=self.read('I053061A.GMP',lblstart,661)
        self.pool_start,self.pool_size=struct.unpack_from('<II',lbl,21);self.label_shift=lbl[29]
        need(lbl[2:12]==b'GARMIN LBL'and(self.pool_start,self.pool_size,self.label_shift,lbl[30],struct.unpack_from('<H',lbl,170)[0])
             ==(6566,3805432,3,10,950),'Actual GMP/LBL CP950 pool')
        self.L3=self.read('00004171.MDR',self.tables[3]['start'],self.tables[3]['bytes'])
    def read(self,name,start,length):return b''.join(self.image.iter_component(name,offset=start,length=length))
    def label(self,ref):
        if ref is None:return None
        if ref not in self.labels:
            at=ref<<self.label_shift;need(0<=at<self.pool_size,'Actual label bounds')
            raw=self.read('I053061A.GMP',self.pool_start+at,min(64,self.pool_size-at));end=raw.find(b'\0')
            need(end>=0,'Bounded label NUL');self.labels[ref]=raw[:end].decode('cp950',errors='strict')
        return self.labels[ref]
    def record(self,encoded):
        if encoded not in self.record_cache:
            level,ID=encoded>>28,encoded&0xfffffff;table=self.tables[level]
            need(1<=ID<=table['count'],'Actual record ID bounds');bit=(ID-1)*table['stride']
            if level==3:value=extract(self.L3,bit,table['stride'])
            else:
                byte,shift=divmod(bit,8);raw=self.read('00004171.MDR',table['start']+byte,(shift+table['stride']+7)//8)
                value=extract(raw,shift,table['stride'])
            r=decode(value,table);r.update(record=encoded,level=level,ID=ID,value=value,label=self.label(r['primary_ref']))
            self.record_cache[encoded]=r
        return self.record_cache[encoded]
    def group(self,key):
        if key not in self.groups:
            level,first,count=key;table=self.tables[level];need(1<=first and 1<=count<=4095 and first+count-1<=table['count'],'Actual group bounds')
            bit=(first-1)*table['stride'];byte,shift=divmod(bit,8)
            raw=self.read('00004171.MDR',table['start']+byte,(shift+count*table['stride']+7)//8)
            self.groups[key]=dict(raw=raw,shift=shift,count=count,width=table['stride'],window_sha256=sha(raw),
              logical_start=table['start']+byte);self.group_rows+=count
        return self.groups[key]
    def values(self,key):
        g=self.group(key)
        return (extract(g['raw'],g['shift']+i*g['width'],g['width'])for i in range(g['count']))
    def group_key(self,parent):
        nextlevel=parent['next_level'];need(parent['level']<nextlevel<=6,'Actual deeper branch level')
        return(nextlevel,parent['first_child'],parent['child_count'])
    def group_receipt(self,key):
        g=self.group(key);return dict(level=key[0],first=key[1],count=key[2],logical_start=g['logical_start'],
            initial_shift=g['shift'],window_bytes=len(g['raw']),window_sha256=g['window_sha256'],
            significant_records_sha256=significant_hash(self.values(key),g['width']))


def main():
    need(not(HERE/'proof.json').exists(),'New planning scope only');started=datetime.now(timezone.utc).isoformat();t0=time.monotonic();inputs=[]
    seal=json.loads(raw_input(JOIN/'seal.json',JOIN_SEAL_SHA,inputs,50_000));pins={Path(r['path']).name:r for r in seal['artifacts']}
    joined=json.loads(raw_input(JOIN/'proof.json',pins['proof.json']['sha256'],inputs,50_000))
    ready_pin=joined['artifacts']['ready'];summary_pin=joined['artifacts']['ready_parent_summary']
    # A root-created candidate seal is required before even opening the IMG.
    base_seal_path=BASE/'file-seal-v2.json';need(base_seal_path.exists(),'Wait for root v2 seal before candidate reads')
    base_seal_bytes=base_seal_path.read_bytes();base_seal=json.loads(base_seal_bytes)
    # Root seal format is bound and interpreted below; no whole IMG hash pass.
    source_receipt=dict(path=str(base_seal_path.relative_to(ROOT)),bytes=len(base_seal_bytes),sha256=sha(base_seal_bytes))
    inputs.append(source_receipt)
    entries=base_seal.get('files',base_seal.get('artifacts',[]))
    base_pins={Path(x['path']).name:x for x in entries}
    need('proof.json'in base_pins and'gmapprom1.img'in base_pins,'Root candidate seal files')
    need(base_pins['gmapprom1.img']['sha256']==BASE_SHA and base_pins['gmapprom1.img']['bytes']==128356352,'Expected actual v2 image seal')
    base_proof=json.loads(raw_input(BASE/'proof.json',base_pins['proof.json']['sha256'],inputs,100_000))
    need(base_proof['all_assigned_checks_passed']and base_proof['candidate_sha256']==BASE_SHA,'Successful v2 candidate')
    ranges=json.loads(raw_input(BASE/'merged-selected-street-ranges.json',base_proof['merged_selected_ranges']['sha256'],inputs))
    selected={r['nativeStreetID']:r for r in ranges};need(len(selected)==18823,'Unique selected street ranges')
    summaries={};roots=defaultdict(list)
    for row in ledger_input(JOIN/'ready-parent-summary.jsonl.gz',summary_pin,inputs):
        parent=row['actual_parent'];record=parent['record'];need(record not in summaries,'Unique sealed stock parents')
        summaries[record]=row;roots[parent['root_street_record']].append(record)
    need(len(summaries)==20613 and len(roots)==7650,'Exact ready path metadata')
    targets=defaultdict(list);target_total=0;previous=None
    for row in ledger_input(JOIN/'ready-lane-house-targets.jsonl.gz',ready_pin,inputs):
        p=row['actual_parent'];key=(p['record'],row['numeric_house']);need(previous is None or previous<key,'Ready numeric order');previous=key
        need(p==summaries[p['record']]['actual_parent']and row['native_write_ready']is False and not row['reasons']and
             row['planning_eligibility']=='source_join_geometry_ready','Unmodified qualified source planning row')
        targets[p['record']].append(dict(house_label=row['house_label'],number=row['numeric_house'],primary_ref=row['primary_ref'],
             raw24=row['planned_raw24'],coordinate_strings=row['selected_coordinate_strings'],source_group_ids=row['source_group_ids'],
             source_ids=row['source_ids'],source_node_count=row['source_node_count']))
        target_total+=1
    need(target_total==58233,'Qualified planned targets')
    # Candidate provenance only: retain true inserted ordinals for affected roots.
    insertions=defaultdict(set);kept_counts=Counter();last_source=-1
    for row in ledger_input(BASE/'kept-new-house-records.jsonl.gz',base_proof['kept_new_records'],inputs):
        sid=row['nativeStreetID'];r=selected[sid];position=row['new_lowID']-r['new_first']
        need(row['next_level']==r['next_level']and 0<=position<r['new_count'],'Kept leaf exact selected group ordinal')
        kept_counts[sid]+=1
        if(3<<28|sid)in roots:
            need(position not in insertions[sid],'Unique actual new leaf ordinal');insertions[sid].add(position)
    need(all(kept_counts[r['nativeStreetID']]==r['new_integer_house_count']for r in ranges),'Complete kept leaf counts')
    del ranges,kept_counts
    core=core_module(inputs);candidate=BASE/'gmapprom1.img';before=stat(candidate)
    need(before[2]==128356352,'Sealed candidate size without full scan')
    plans=[];mapping_ledger=Ledger('current-path-mappings.jsonl.gz');counts=Counter();held_reasons=Counter();unknowns=Counter()
    group_owners=defaultdict(set);active_groups={};record_to_group={};parent_names={};parent_to_roots=defaultdict(set)
    with candidate.open('rb')as f:
        image=core.StreamIMG(f);tree=Tree(image)
        for root_encoded,parentIDs in sorted(roots.items()):
            root=tree.record(root_encoded);sid=root['ID'];spec=selected.get(sid)
            rootkey=tree.group_key(root);old_positions=None
            if spec:
                need((root['first_child'],root['child_count'],root['next_level'],root['raw_flags'])==
                     (spec['new_first'],spec['new_count'],spec['next_level'],spec['original_flags']),'Actual cloned current L3 fields')
                old_positions=old_to_current_ordinals(spec['original_count'],spec['new_count'],insertions[sid])
                values=list(tree.values(rootkey));need(significant_hash((values[i]for i in old_positions),tree.tables[rootkey[0]]['stride'])==
                    spec['original_significant_records_sha256'],'Actual current old sequence minus true kept new ordinals')
                need(significant_hash(values,tree.tables[rootkey[0]]['stride'])==spec['new_significant_records_sha256'],'Current root group significant hash')
                counts['mapped_selected_L3_roots']+=1
            else:counts['mapped_unselected_L3_roots']+=1
            for stock_parent_ID in parentIDs:
                summary=summaries[stock_parent_ID];witness=summary['actual_parent'];path=witness['path_record_ids'];tokens=witness['path_tokens']
                need(path[0]==root_encoded and path[-1]==stock_parent_ID and len(tokens)==len(path)-1,'Sealed full path closure')
                current=root;steps=[dict(stock_record=root_encoded,current_record=root_encoded,label=root['label'],raw_flags=root['raw_flags'])]
                edges=[];reasons=[]
                for at,stock_encoded in enumerate(path[1:]):
                    child_level,oldID=stock_encoded>>28,stock_encoded&0xfffffff;key=tree.group_key(current)
                    need(key[0]==child_level,'Actual path next table level')
                    if at==0 and spec:
                        oldordinal=oldID-spec['original_first'];need(0<=oldordinal<len(old_positions),'Stock child in original selected range')
                        actualID=spec['new_first']+old_positions[oldordinal]
                    else:
                        need(key[1]<=oldID<key[1]+key[2],'Stock descendant remains in actual current range');actualID=oldID
                    actual_encoded=child_level<<28|actualID;child=tree.record(actual_encoded);stock=tree.record(stock_encoded)
                    need(child['value']==stock['value']and child['label']==tokens[at],'Exact preserved current child bits/token label')
                    if current['raw_flags']not in[4,5,6]:reasons.append('unknown_ancestor_raw_flags_preserved_held');unknowns[current['raw_flags']]+=1
                    edges.append(dict(parent_record=current['record'],parent_level=current['level'],child_group=key,
                                      old_child_record=stock_encoded,current_child_record=actual_encoded,child_ordinal=actualID-key[1]))
                    current=child;steps.append(dict(stock_record=stock_encoded,current_record=actual_encoded,label=child['label'],raw_flags=child['raw_flags']))
                need((current['level'],current['ID']if current['record']==stock_parent_ID else witness['ID'],current['label'],current['raw_flags'],
                     current['next_level'],current['first_child'],current['child_count'])==
                    (witness['level'],witness['ID'],witness['label'],witness['raw_flags'],witness['next_leaf_level'],witness['old_first_child'],witness['old_child_count']),
                     'Actual current final parent matches unchanged stock witness')
                finalkey=tree.group_key(current);names=[];leafmatches=defaultdict(list);oldflags=Counter();nested=0
                for ordinal,value in enumerate(tree.values(finalkey)):
                    child=decode(value,tree.tables[finalkey[0]]);name=tree.label(child['primary_ref']);names.append(name);oldflags[child['raw_flags']]+=1
                    if child['child_count']:nested+=1
                    if not child['child_count']and name is not None:leafmatches[name].append(finalkey[1]+ordinal)
                    if child['mapordinal']!=1:reasons.append('non1_old_mapordinal')
                additions=[];present=[]
                for target in targets[stock_parent_ID]:
                    need(tree.label(target['primary_ref'])==target['house_label'],'Actual candidate existing new house label')
                    matches=leafmatches[target['house_label']]
                    if matches:
                        present.append(dict(**target,current_matching_leaf_IDs=matches));counts['targets_already_in_current_group']+=1
                        if len(matches)>1:reasons.append('duplicate_current_exact_house_leaf')
                    else:additions.append(target)
                positions=numeric_positions(names,[r['number']for r in additions])
                if additions and positions is None:reasons.append('unproved_current_numeric_anchor_order')
                if current['raw_flags']not in[5,6]:reasons.append('unknown_final_parent_raw_flags_preserved_held')
                limit=(1<<tree.tables[current['level']]['widths'][5])-1
                if finalkey[2]+len(additions)>limit:reasons.append('final_parent_child_count_field_overflow')
                reasons=sorted(set(reasons));plan=dict(stock_parent=witness,current_parent_record=current['record'],current_path=steps,
                    path_edges=edges,current_child_group=tree.group_receipt(finalkey),old_raw_child_flag_counts=dict(oldflags),
                    old_nested_child_count=nested,current_exact_present_targets=present,missing_targets=additions,
                    numeric_insertion_ordinals=positions,planned_group_count=finalkey[2]+len(additions),reasons=reasons,
                    planning_eligibility='held'if reasons else'current_tree_group_ready',native_write_ready=False)
                plans.append(plan);mapping_ledger.add(dict(stock_parent_record=stock_parent_ID,current_parent_record=current['record'],path=steps,
                    mapped_through_selected_L3=bool(spec),path_edges=edges,original_parent_witness=witness,reasons=reasons))
                parent_names[current['record']]=(witness['city'],witness['district'],witness['source_full_street']);parent_to_roots[current['record']].add(root_encoded)
                if len(plans)%1000==0:
                    rss=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss;need(rss<=MAX_RSS_KIB,'Actual planner RSS guard')
                    print(json.dumps(dict(paths=len(plans),candidate_readbytes=sum(x['bytes']for x in image.read_log),max_RSS_KiB=rss)),flush=True)
        # Exact final-range aliases require compatible closure identities and insertion plans.
        aliases=defaultdict(list)
        for plan in plans:
            g=plan['current_child_group'];aliases[(g['level'],g['first'],g['count'])].append(plan)
        for key,owners in aliases.items():
            identities={(p['stock_parent']['city'],p['stock_parent']['district'],p['stock_parent']['source_full_street'])for p in owners}
            signatures={json.dumps([(t['number'],t['primary_ref'],t['raw24'],t['coordinate_strings'])for t in p['missing_targets']],sort_keys=True)for p in owners}
            if len(identities)>1 or len(signatures)>1:
                for p in owners:p['reasons']=sorted(set(p['reasons']+['source_street_shared_range_closure_collision']));p['planning_eligibility']='held'
        # A partial overlap is not an exact alias and cannot share a clone plan.
        ordered=sorted(aliases)
        overlapping=set()
        for i,key in enumerate(ordered):
            j=i+1
            while j<len(ordered)and ordered[j][0]==key[0]and ordered[j][1]<key[1]+key[2]:
                if ordered[j]!=key:overlapping.update([key,ordered[j]])
                j+=1
        for key in overlapping:
            for p in aliases[key]:p['reasons']=sorted(set(p['reasons']+['partially_overlapping_final_ranges_held']));p['planning_eligibility']='held'
        # Form copy-on-write closure only from admitted final groups and paths.
        admitted=[p for p in plans if not p['reasons']and p['missing_targets']]
        for plan in admitted:
            g=plan['current_child_group'];key=(g['level'],g['first'],g['count'])
            group=active_groups.setdefault(key,dict(key=key,additions=plan['missing_targets'],owners=set(),patches={},receipt=g))
            group['owners'].add(plan['current_parent_record']);record_to_group[plan['current_parent_record']]=key
        for plan in admitted:
            for edge in reversed(plan['path_edges']):
                key=tuple(edge['child_group']);group=active_groups.setdefault(key,dict(key=key,additions=[],owners=set(),patches={},receipt=tree.group_receipt(key)))
                group['owners'].add(edge['parent_record']);record_to_group[edge['parent_record']]=key
                child=edge['current_child_record'];patch=dict(current_child_record=child,current_child_ordinal=edge['child_ordinal'],
                    referenced_group=record_to_group[child])
                existing=group['patches'].get(child);need(existing is None or existing==patch,'Consistent transitive child patch target')
                group['patches'][child]=patch
        closure_partial_overlaps=[];closure_keys=sorted(active_groups)
        for i,key in enumerate(closure_keys):
            j=i+1
            while j<len(closure_keys)and closure_keys[j][0]==key[0]and closure_keys[j][1]<key[1]+key[2]:
                closure_partial_overlaps.append([key,closure_keys[j]]);j+=1
        # Report all current L3 owners of exact/partial affected root-group ranges.
        root_closure={record:key for record,key in record_to_group.items()if record>>28==3}
        root_ranges=defaultdict(list)
        for sid in range(1,tree.tables[3]['count']+1):
            r=decode(extract(tree.L3,(sid-1)*112,112),tree.tables[3])
            if r['child_count']and r['next_level']in[4,5,6]:root_ranges[(r['next_level'],r['first_child'],r['child_count'])].append(3<<28|sid)
        indexed_ranges={level:sorted((k for k in root_ranges if k[0]==level),key=lambda k:k[1])for level in [4,5,6]}
        range_starts={level:[k[1]for k in rows]for level,rows in indexed_ranges.items()}
        # Prefix maximum endpoints permit bounded backward overlap traversal.
        prefix_ends={}
        for level,rows in indexed_ranges.items():
            ends=[];end=0
            for k in rows:end=max(end,k[1]+k[2]);ends.append(end)
            prefix_ends[level]=ends
        root_alias_receipts=[]
        for record,key in sorted(root_closure.items()):
            others=root_ranges[key]
            level,start,count=key;rows=indexed_ranges[level];cursor=bisect_left(range_starts[level],start+count)-1;partial=[]
            while cursor>=0 and prefix_ends[level][cursor]>start:
                k=rows[cursor]
                if k!=key and intervals_overlap(k,key):partial.append(dict(key=k,owners=root_ranges[k]))
                cursor-=1
            if len(others)>1 or partial:root_alias_receipts.append(dict(record=record,key=key,all_current_L3_exact_owners=others,partial_overlaps=partial))
        new_counts={level:table['count']for level,table in tree.tables.items()};clone_counts=Counter();new_leaf_counts=Counter();first_requirements=Counter();descriptor_blockers=[]
        groupledger=Ledger('transitive-ancestor-groups.jsonl.gz')
        for key,group in sorted(active_groups.items(),key=lambda x:(-x[0][0],x[0][1],x[0][2])):
            level,first,count=key;group['new_first']=new_counts[level]+1;group['new_count']=count+len(group['additions']);new_counts[level]+=group['new_count']
            clone_counts[level]+=count;new_leaf_counts[level]+=len(group['additions'])
        for key,group in sorted(active_groups.items()):
            for owner in group['owners']:
                p=tree.record(owner);width=tree.tables[p['level']]['widths'][0];maxfirst=(1<<width)-1
                first_requirements[p['level']]=max(first_requirements[p['level']],group['new_first'])
                if group['new_first']>maxfirst:descriptor_blockers.append(dict(parent_record=owner,parent_level=p['level'],current_first_width=width,
                    required_first=group['new_first'],minimum_required_width=group['new_first'].bit_length(),child_table_level=key[0]))
                need(group['new_count']<(1<<tree.tables[p['level']]['widths'][5]),'Closure parent count overflow must be held before plan')
            groupledger.add(dict(current_group=group['receipt'],current_parent_owners=sorted(group['owners']),
                clone_old_records=key[2],new_integer_house_targets=len(group['additions']),planned_new_first=group['new_first'],planned_new_count=group['new_count'],
                proposed_child_patches=sorted(group['patches'].values(),key=lambda p:p['current_child_ordinal']),
                inserted_house_numbers=[t['number']for t in group['additions']],unknown_old_child_fields_preserved=True,native_write_ready=False))
        parentsledger=Ledger('planned-parent-groups.jsonl.gz');heldledger=Ledger('held-parent-groups.jsonl.gz')
        for plan in plans:
            if plan['reasons']:
                heldledger.add(plan);counts['held_parent_plans']+=1;counts['held_source_targets']+=len(plan['missing_targets'])
                for reason in plan['reasons']:held_reasons[reason]+=1
            else:
                parentsledger.add(plan);counts['numeric_order_eligible_parent_plans']+=1;counts['numeric_order_eligible_missing_targets']+=len(plan['missing_targets'])
        level_widths={level:list(t['widths'])for level,t in tree.tables.items()}
        for block in descriptor_blockers:level_widths[block['parent_level']][0]=max(level_widths[block['parent_level']][0],block['minimum_required_width'])
        capacity_variants=[]
        for kind,widths in [('current_descriptors',None),('minimum_first_width_expansion',level_widths)]:
            tableplans={};cursor=tree.tables[6]['start']
            for level in [6,5,4,3,2,1]:
                table=tree.tables[level];stride=table['stride']if widths is None else table['stride']+widths[level][0]-table['widths'][0]
                size=(new_counts[level]*stride+7)//8;tableplans[level]=dict(level=level,start=cursor,bytes=size,stride=stride,count=new_counts[level],
                    first_width=table['widths'][0]if widths is None else widths[level][0]);cursor+=size
            mdr_size=cursor+120;blocks={name:(mdr_size if name=='00004171.MDR'else c.size)+4095 for name,c in image.components.items()};blocks={name:n//4096 for name,n in blocks.items()}
            rows=1+sum((n+239)//240 for n in blocks.values());dirend=((max(image.directory_end,image.directory_start+rows*512)+4095)//4096)*4096
            image_bytes=(dirend//4096+sum(blocks.values()))*4096
            eight_blocks={name:((mdr_size if name=='00004171.MDR'else c.size)+8191)//8192 for name,c in image.components.items()}
            eight_rows=1+sum((n+239)//240 for n in eight_blocks.values());eight_dirend=((max(image.directory_end,image.directory_start+eight_rows*512)+8191)//8192)*8192
            eight_bytes=(eight_dirend//8192+sum(eight_blocks.values()))*8192
            capacity_variants.append(dict(variant=kind,semantic_first_widths_valid=kind!='current_descriptors'or not descriptor_blockers,
               tables=tableplans,MDR_directory_start=cursor,MDR_component_bytes=mdr_size,image4K_bytes=image_bytes,
               image4K_FAT_rows=rows,image4K_directory_end=dirend,original4K_capacity=image.capacity,original4K_fits=image_bytes<=image.capacity,
               explicit8K_estimated_bytes=eight_bytes,explicit8K_capacity=268435456,explicit8K_profile_fits=eight_bytes<=268435456,
               explicit8K_on_device_acceptance_proved=False))
        need(stat(candidate)==before,'Actual candidate stat unchanged')
        rss=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss;need(rss<=MAX_RSS_KIB,'Actual planner RSS ceiling')
        read_log=Ledger('candidate-bounded-read-receipts.jsonl.gz')
        for receipt in image.read_log:read_log.add(receipt)
        readbytes=sum(r['bytes']for r in image.read_log);readops=len(image.read_log)
        artifacts=dict(paths=mapping_ledger.close(),ready_parents=parentsledger.close(),held_parents=heldledger.close(),
                       closure_groups=groupledger.close(),candidate_reads=read_log.close())
        capacity=dict(schema='lane-tree-overlay-width-capacity-plan/v1',base_candidate_sha256=BASE_SHA,
            base_candidate_bytes=before[2],current_tables=tree.tables,exact_COW_closure_group_count=len(active_groups),
            clone_counts=dict(clone_counts),new_leaf_counts=dict(new_leaf_counts),proposed_table_counts=new_counts,
            maximum_new_first_by_parent_level=dict(first_requirements),first_descriptor_overflows=descriptor_blockers,
            closure_partial_overlaps=closure_partial_overlaps,current_L3_root_aliases=root_alias_receipts,
            capacity_variants=capacity_variants,native_write_ready=False,
            required_new_primitive='Current width23-profile copy-on-write MDR descriptor and ancestor writer; existing sealed writer accepts only stock original and L3 changes.',
            rollback_requirement='Streaming significant-bit inverse reencode for any widened L4/L5 table, restoring original descriptors and all stock fields; old byte-prefix truncation rollback invalid if lower first width changes.',
            closure_ownership_scope='Every admitted exact source path and its current ancestor groups; all L3 exact/partial range owners checked. Unvisited lower-level global aliases remain external old views under copy-on-write, without inferred source-name equivalence.',
            old_records_reordered=False,old_unknown_flags_converted=False,global_native_comparator_validated=False)
        artifacts['capacity']=saved('capacity-and-width-plan.json',capacity)
        proof=dict(schema='current-native-lane-tree-overlay-feasibility/v1',started_utc=started,finished_utc=datetime.now(timezone.utc).isoformat(),
            script_sha256=sha(Path(__file__).read_bytes()),assigned_input_targets=target_total,
            assigned_stock_parent_count=len(summaries),assigned_root_street_count=len(roots),counts=dict(counts),
            held_reason_parent_counts=dict(held_reasons),unknown_ancestor_flags=dict(unknowns),
            admitted_COW_clone_counts=dict(clone_counts),admitted_new_leaf_counts=dict(new_leaf_counts),proposed_table_counts=new_counts,
            base_candidate_seal=source_receipt,base_candidate_sha256=BASE_SHA,base_candidate_stat_before=before,base_candidate_stat_after=stat(candidate),
            inherited_whole_candidate_SHA_not_recomputed=True,all_new_bounded_candidate_record_reads_actual=True,candidate_readbytes=readbytes,
            candidate_read_operations=readops,unique_bounded_groups=len(tree.groups),bounded_group_record_count=tree.group_rows,
            actual_label_references=len(tree.labels),max_RSS_KiB=rss,max_RSS_limit_KiB=MAX_RSS_KIB,inputs=inputs,artifacts=artifacts,
            closure_partial_overlaps=len(closure_partial_overlaps),root_range_alias_receipts=len(root_alias_receipts),
            native_write_ready=False,all_assigned_checks_passed=True,unknown_flag_policy_invented=False,
            native_CPU_or_UI_or_device_executed=False,binaries_IMG_ZIP_USB_canonical_or_prior_files_modified=False,
            PBF_or_full_source_or_source_ready_ledgers_accessed=False,closed_suites_replayed=False,
            full_native_address_update_complete=False,elapsed_seconds_receipt_only=time.monotonic()-t0,
            limits=['This is conditional host feasibility and actual current-path planning, not encoded records or native writer readiness.',
                'Numeric insertion is host base-number interleave; original complete comparator/prefix query remains unproved.',
                'Old nonnumeric/nested/unknown child fields are preserved; unproved ancestor flag branches or conflicting/overlapping final ownership are held.',
                'Copy-on-write retains unvisited old alias views; no full lower-level global owner scan or name inference.',
                'New current-profile descriptor/tree writer, rollback correctness, native consumer acceptance and capacity/device validation remain necessary.'])
        saved('proof.json',proof)
        receipt=dict(exit_status=0,counts=dict(counts),clone_counts=dict(clone_counts),new_leaf_counts=dict(new_leaf_counts),
            candidate_readbytes=readbytes,candidate_read_operations=readops,max_RSS_KiB=rss,source_sha256=sha(Path(__file__).read_bytes()),
            proof_sha256=sha((HERE/'proof.json').read_bytes()),native_write_ready=False)
        saved('execution-receipt.json',receipt);print(json.dumps(receipt),flush=True)


if __name__=='__main__':main()
