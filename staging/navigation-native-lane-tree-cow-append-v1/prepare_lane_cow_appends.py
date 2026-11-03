#!/usr/bin/env python3
"""Produce bound current-profile COW append data only, never an IMG.

Old lower records are copied as significant bits with explicit first/count
patches only. No native CPU, device, source-group/PBF or geometry execution.
"""
from pathlib import Path
from datetime import datetime,timezone
from collections import Counter,defaultdict
from bisect import bisect_right
import gzip
import hashlib
import importlib.util
import json
import mmap
import os
import resource
import sys
import time

ROOT=Path('/root/garmin');HERE=Path(__file__).resolve().parent
PLAN=ROOT/'staging/navigation-native-lane-tree-overlay-plan-v1'
JOIN=ROOT/'staging/navigation-country-lane-absent-source-join-v1'
BASE=ROOT/'staging/navigation-country-native-candidate-v2'
PLAN_SEAL_SHA='9cf478a98b09473fa3308ba0cf76a37ed5d700609ac039f6c110c7561bad465a'
HELPER_SHA='8178f9b50e5958265d6eba26561669e5b0bc486797295e5023e05af0fda1ccf9'
JOIN_SEAL_SHA='484f1366c2baf96bcd9560028599a62149984b1356ba4ad5c2146f6b17802f95'
BASE_SEAL_SHA='659ae2d149b45098542fd90cd0a3000e74e3c9e2d76077f4d1ecdbbeec022766'
CODEC_SHA='8dfec0a03795e29fc223fbd06f0418536b6f3969024083b5023e25620319eb33'
MAX_RSS_KIB=512000
STRIDES={4:128,5:126,6:68}


def need(ok,message):
    if not ok:raise ValueError(message)


def sha(raw):return hashlib.sha256(raw).hexdigest()


def stat(path):
    s=path.stat();return[s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]


def pinned(path,digest,inputs,maximum=200000):
    before=stat(path);need(before[2]<=maximum,'Pinned small source ceiling');raw=path.read_bytes()
    need(sha(raw)==digest and stat(path)==before,'Sealed small input immutable')
    inputs.append(dict(path=str(path.relative_to(ROOT)),bytes=len(raw),sha256=digest,stat_before=before,stat_after=stat(path)))
    return raw


def imported(path,digest,name,inputs):
    pinned(path,digest,inputs);spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec)
    sys.modules[name]=m;spec.loader.exec_module(m);return m


def saved(name,row):
    path=HERE/name
    with path.open('x')as f:json.dump(row,f,ensure_ascii=False,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
    return dict(path=str(path.relative_to(ROOT)),bytes=path.stat().st_size,sha256=sha(path.read_bytes()))


class Ledger:
    def __init__(self,name):
        self.path=HERE/name;self.f=self.path.open('xb');self.z=gzip.GzipFile(filename='',fileobj=self.f,mode='wb',mtime=0)
        self.rows=self.amount=0;self.h=hashlib.sha256()
    def add(self,row):
        raw=json.dumps(row,ensure_ascii=False,separators=(',',':')).encode()+b'\n';self.z.write(raw);self.h.update(raw);self.rows+=1;self.amount+=len(raw)
    def close(self):
        self.z.close();self.f.flush();os.fsync(self.f.fileno());self.f.close()
        return dict(path=str(self.path.relative_to(ROOT)),rows=self.rows,bytes=self.path.stat().st_size,sha256=sha(self.path.read_bytes()),
            uncompressed_sha256=self.h.hexdigest(),uncompressed_bytes=self.amount)


class TightWriter:
    """Persistent LSB-first bit carry across records and group boundaries."""
    def __init__(self,path,width):
        need(width in STRIDES.values(),'Known lower stride');self.path=path;self.width=width;self.f=path.open('xb')
        self.acc=self.pending=self.records=self.bytes=0;self.buffer=bytearray();self.h=hashlib.sha256()
    def flush(self):
        if self.buffer:
            data=bytes(self.buffer);need(self.f.write(data)==len(data),'Full tight write');self.h.update(data);self.bytes+=len(data);self.buffer.clear()
    def add(self,value):
        need(type(value)is int and 0<=value<(1<<self.width),'Explicit bounded significant record value')
        self.acc|=value<<self.pending;bits=self.pending+self.width;whole=bits//8
        raw=self.acc.to_bytes((bits+7)//8,'little');self.buffer.extend(raw[:whole]);self.acc>>=whole*8;self.pending=bits%8;self.records+=1
        if len(self.buffer)>=65536:self.flush()
    def close(self):
        if self.pending:self.buffer.append(self.acc)
        self.flush();self.f.flush();os.fsync(self.f.fileno());self.f.close();bits=self.records*self.width
        need(self.bytes==(bits+7)//8,'Tight declared byte length')
        return dict(path=self.path.name,record_count=self.records,record_bits=self.width,bit_length=bits,bytes=self.bytes,
            sha256=self.h.hexdigest(),unused_final_high_bits=(-bits)%8,final_unused_bits_zero=True)


def range_mask(table):
    w,f=table['widths'],table['reference_flags'];firstat=w[4]+sum(f)*w[3];countat=firstat+w[0]
    return firstat,countat,((1<<(w[0]+w[5]))-1)<<firstat


def patch_range(value,table,first,count,nextlevel,expected_flags,decode):
    r=decode(value,table);need(r['raw_flags']==expected_flags and r['next_level']==nextlevel,'Patch expected whole rawflags/nextlevel')
    w=table['widths'];need(type(first)is int and 1<=first<(1<<w[0])and type(count)is int and 1<=count<(1<<w[5]),'Explicit child first/count fit unchanged widths')
    a,b,mask=range_mask(table);result=(value&~mask)|(first<<a)|(count<<b)
    need((result^value)&~mask==0,'Only child first/count patch bits')
    return result,mask


def old_to_new_ordinal(oldordinal,insertions):
    need(type(oldordinal)is int and oldordinal>=0,'Explicit old ordinal');result=oldordinal
    for pos in sorted(insertions):
        if pos<=result:result+=1
        else:break
    return result


def source_content_identity(row):
    # Structural location fields are explicitly represented separately.
    ignored={'new_lowID','appended_bit_offset','v2_combined_append_bit_offset'}
    return {k:v for k,v in row.items()if k not in ignored}


def main():
    need(not(HERE/'proof.json').exists(),'New isolated append scope only');t0=time.monotonic();started=datetime.now(timezone.utc).isoformat();inputs=[]
    h=imported(PLAN/'plan_lane_tree_overlay.py',HELPER_SHA,'sealed_current_overlay_reader',inputs)
    codec=imported(ROOT/'scripts/native_address_records.py',CODEC_SHA,'sealed_lower_record_codec',inputs)
    ps=json.loads(pinned(PLAN/'seal.json',PLAN_SEAL_SHA,inputs));pp={Path(r['path']).name:r for r in ps['files']}
    plan=json.loads(pinned(PLAN/'proof.json',pp['proof.json']['sha256'],inputs));capacity=json.loads(pinned(PLAN/'capacity-and-width-plan.json',pp['capacity-and-width-plan.json']['sha256'],inputs))
    js=json.loads(pinned(JOIN/'seal.json',JOIN_SEAL_SHA,inputs));jp={Path(r['path']).name:r for r in js['artifacts']}
    join=json.loads(pinned(JOIN/'proof.json',jp['proof.json']['sha256'],inputs))
    bs=json.loads(pinned(BASE/'sealed-files.json',BASE_SEAL_SHA,inputs));bp={Path(r['path']).name:r for r in bs['files']}
    base=json.loads(pinned(BASE/'proof.json',bp['proof.json']['sha256'],inputs));candidate=BASE/'gmapprom1.img';before=stat(candidate)
    sealed=bp['gmapprom1.img']['stat_at_seal'];need(before[:4]==sealed[:4],'Sealed image content/inode/mtime identity; ctime may change by root authorized hardlink')
    groups={};owner_group={}
    for row in h.ledger_input(PLAN/'transitive-ancestor-groups.jsonl.gz',plan['artifacts']['closure_groups'],inputs):
        g=row['current_group'];key=(g['level'],g['first'],g['count']);need(key not in groups,'Unique exact COW group')
        groups[key]=row
        for owner in row['current_parent_owners']:need(owner not in owner_group,'One actual child group per parent');owner_group[owner]=key
    source_targets={};parent_context={};group_target={};needed_count=0
    for row in h.ledger_input(PLAN/'planned-parent-groups.jsonl.gz',plan['artifacts']['ready_parents'],inputs):
        p=row['stock_parent'];g=row['current_child_group'];key=(g['level'],g['first'],g['count']);need(not row['reasons']and not row['current_exact_present_targets'],'Only closed admitted plans')
        context=dict(stock_parent=p,current_parent_record=row['current_parent_record'],current_path=row['current_path'],group_key=key,
            numeric_insertion_ordinals={int(k):v for k,v in row['numeric_insertion_ordinals'].items()})
        parent_context[p['record']]=context;need(key not in group_target,'No actual final aliases in sealed plan');group_target[key]=context
        for target in row['missing_targets']:
            keytarget=(p['record'],target['number']);need(keytarget not in source_targets,'Unique exact source target');source_targets[keytarget]=target
            needed_count+=1
    need(len(groups)==29866 and len(parent_context)==20613 and needed_count==58233,'Inherited plan counts independently parsed')
    appends={};group_ledger=Ledger('emitted-cow-groups.jsonl.gz');parent_ledger=Ledger('cloned-parent-mappings.jsonl.gz')
    new_positions={};patched_parent_mappings={};selected=[];counts=Counter();raw_flags=Counter();group_start_shifts=defaultdict(Counter)
    with candidate.open('rb')as f:
        image=h.core_module(inputs).StreamIMG(f);tree=h.Tree(image)
        layouts={level:codec.RecordLayout(tuple(tree.tables[level]['widths']),tuple(tree.tables[level]['reference_flags']),STRIDES[level])for level in [4,5,6]}
        writers={level:TightWriter(HERE/('appended-level'+str(level)+'.bin'),STRIDES[level])for level in [4,5,6]}
        for key,row in sorted(groups.items(),key=lambda x:(-x[0][0],x[1]['planned_new_first'])):
            level,currentfirst,currentcount=key;table=tree.tables[level];writer=writers[level];bit=writer.records*STRIDES[level]
            need(row['planned_new_first']==table['count']+writer.records+1,'Exact append first from actual source table count')
            need(tree.group_receipt(key)==row['current_group'],'Actual current group window/significant bits match sealed plan')
            old=list(tree.values(key));targets=group_target.get(key);inserts={};patches={p['current_child_ordinal']:p for p in row['proposed_child_patches']}
            if targets:
                stock=targets['stock_parent']['record']
                for number,pos in targets['numeric_insertion_ordinals'].items():
                    target=source_targets[(stock,number)];need(tree.label(target['primary_ref'])==target['house_label'],'Actual numeric textref identity')
                    r=codec.AddressRecord(1,target['primary_ref'],None,0,0,0,*target['raw24']);payload=codec.encode_record(layouts[level],r).payload
                    value=int.from_bytes(payload,'little');decoded=h.decode(value,table)
                    need(decoded['primary_ref']==target['primary_ref']and[decoded['raw_location_a'],decoded['raw_location_b']]==target['raw24']and
                         decoded['child_count']==0 and decoded['first_child']==0 and decoded['raw_flags']==0,'Encoded explicit leaf fields verified')
                    need(pos not in inserts and 0<=pos<row['planned_new_count'],'Unique new merged ordinal');inserts[pos]=value
                    newID=row['planned_new_first']+pos;new_positions[(stock,number)]=dict(level=level,new_lowID=newID,group_key=key,
                        group_first=row['planned_new_first'],group_count=row['planned_new_count'],group_ordinal=pos,
                        appended_bit_offset=(newID-table['count']-1)*STRIDES[level],payload=payload.hex(),current_parent_record=targets['current_parent_record'])
                    counts['new_integer_leaf_level'+str(level)]+=1
            need(len(inserts)==row['new_integer_house_targets'],'Exact bound inserted target count')
            oldordinal=0;afterhash=hashlib.sha256();patch_count=0
            for newordinal in range(row['planned_new_count']):
                if newordinal in inserts:value=inserts[newordinal]
                else:
                    value=original=old[oldordinal];decoded=h.decode(original,table);raw_flags[decoded['raw_flags']]+=1
                    if oldordinal in patches:
                        patch=patches[oldordinal];targetgroup=groups[tuple(patch['referenced_group'])];currentrecord=level<<28|currentfirst+oldordinal
                        need(currentrecord==patch['current_child_record']and owner_group[currentrecord]==tuple(patch['referenced_group']),'Patch actual current copied parent')
                        value,mask=patch_range(original,table,targetgroup['planned_new_first'],targetgroup['planned_new_count'],
                            patch['referenced_group'][0],decoded['raw_flags'],h.decode)
                        newID=row['planned_new_first']+newordinal;mapping=dict(current_parent_record=currentrecord,new_parent_record=level<<28|newID,
                            parent_level=level,new_lowID=newID,original_group_key=key,old_group_ordinal=oldordinal,new_group_ordinal=newordinal,
                            new_parent_group_first=row['planned_new_first'],appended_bit_offset=(newID-table['count']-1)*STRIDES[level],
                            old_payload=original.to_bytes((STRIDES[level]+7)//8,'little').hex(),new_payload=value.to_bytes((STRIDES[level]+7)//8,'little').hex(),
                            explicit_first_count_mask_hex=hex(mask),original_fields=decoded,patched_first_child=targetgroup['planned_new_first'],
                            patched_child_count=targetgroup['planned_new_count'],referenced_group=list(patch['referenced_group']),raw_flags_preserved=True)
                        need(currentrecord not in patched_parent_mappings,'Each actual parent copied/patched once');patched_parent_mappings[currentrecord]=mapping
                        parent_ledger.add(mapping);patch_count+=1;counts['explicit_lower_parent_patches']+=1
                    else:need(value==original,'Unpatched entire significant record copy')
                    oldordinal+=1;counts['current_old_records_cloned_level'+str(level)]+=1
                writer.add(value);afterhash.update(value.to_bytes((STRIDES[level]+7)//8,'little'))
            need(oldordinal==currentcount and patch_count==len(patches),'Every current old row and explicit patch emitted once')
            group_start_shifts[level][bit%8]+=1
            group_ledger.add(dict(current_group=row['current_group'],new_first=row['planned_new_first'],new_count=row['planned_new_count'],
                appended_bit_offset=bit,append_initial_bit_shift=bit%8,record_bits=STRIDES[level],new_significant_records_sha256=afterhash.hexdigest(),
                source_significant_records_sha256=row['current_group']['significant_records_sha256'],explicit_patch_count=patch_count,
                new_integer_leaf_count=len(inserts),inserted_new_ordinals=sorted(inserts),all_other_old_significant_bits_preserved=True,
                old_relative_order_preserved=True,current_parent_owners=row['current_parent_owners']))
            counts['groups_emitted']+=1
            if counts['groups_emitted']%2500==0:
                rss=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss;need(rss<=MAX_RSS_KIB,'Actual producer memory guard')
                print(json.dumps(dict(groups=counts['groups_emitted'],counts=dict(counts),max_RSS_KiB=rss)),flush=True)
        for level,writer in writers.items():appends[level]=writer.close()
        need(len(new_positions)==58233 and len(patched_parent_mappings)==22216,'Actual encoded target/parent closure counts')
        for currentrecord,key in sorted(owner_group.items()):
            if currentrecord>>28!=3:continue
            r=tree.record(currentrecord);group=groups[key]
            need(r['raw_flags']in[4,5,6]and r['next_level']==key[0]and(r['first_child'],r['child_count'])==key[1:],'Actual current L3 branch and whole flags')
            selected.append(dict(one_based_street_ID=r['ID'],first_child=group['planned_new_first'],count=group['planned_new_count'],
                next_level=r['next_level'],original_flags=r['raw_flags'],current_first_child=r['first_child'],current_count=r['child_count'],
                was_selected_in_v2=r['first_child']>{4:2133948,5:2341096,6:1973316}[r['next_level']],group_key=list(key)))
        classifications=Counter('already_selected_v2'if r['was_selected_in_v2']else'previously_stock_range'for r in selected)
        need(len(selected)==7650 and classifications==Counter(already_selected_v2=6366,previously_stock_range=1284),'All affected current L3 branches included')
        for context in parent_context.values():
            current=context['current_parent_record'];need(current in patched_parent_mappings,'Every house parent current copied node patched')
            mapping=patched_parent_mappings[current];group=groups[context['group_key']]
            need(mapping['patched_first_child']==group['planned_new_first']and mapping['patched_child_count']==group['planned_new_count'],'Real copied house parent reaches exact appended group')
        # Read all three real tight files once through actual file-backed bits.
        handles={level:(HERE/artifact['path']).open('rb')for level,artifact in appends.items()};maps={level:mmap.mmap(handle.fileno(),0,access=mmap.ACCESS_READ)for level,handle in handles.items()}
        actual_readback=Counter();patched_fields=Counter()
        for key,row in sorted(groups.items()):
            level=key[0];table=tree.tables[level];width=STRIDES[level];offset=(row['planned_new_first']-table['count']-1)*width
            emitted=[h.extract(maps[level],offset+i*width,width)for i in range(row['planned_new_count'])];old=list(tree.values(key));context=group_target.get(key)
            inserted=set(context['numeric_insertion_ordinals'].values())if context else set();retained=[value for i,value in enumerate(emitted)if i not in inserted]
            need(len(retained)==len(old),'Actual tight output old sequence count')
            patchdict={p['current_child_ordinal']:p for p in row['proposed_child_patches']}
            for ordinal,(beforevalue,aftervalue)in enumerate(zip(old,retained)):
                if ordinal in patchdict:
                    patch=patchdict[ordinal];referenced=groups[tuple(patch['referenced_group'])];decoded=h.decode(beforevalue,table)
                    expected,mask=patch_range(beforevalue,table,referenced['planned_new_first'],referenced['planned_new_count'],patch['referenced_group'][0],decoded['raw_flags'],h.decode)
                    need(aftervalue==expected and(aftervalue^beforevalue)&~mask==0,'Actual output only explicit pointer/count changes')
                    patched_fields[level]+=1
                else:need(beforevalue==aftervalue,'Actual tight output current prior significant bits and relative order retained')
                actual_readback[level]+=1
        for position in new_positions.values():
            level=position['level'];value=h.extract(maps[level],position['appended_bit_offset'],STRIDES[level])
            need(value==int.from_bytes(bytes.fromhex(position['payload']),'little'),'Every actual output new leaf exact payload')
        prior_ledger=Ledger('prior-v2-new-leaf-identity-status.jsonl.gz');prior_counts=Counter();source_identity_hash=hashlib.sha256()
        intervals={level:sorted(k for k in groups if k[0]==level)for level in [4,5,6]};starts={level:[k[1]for k in keys]for level,keys in intervals.items()}
        for row in h.ledger_input(BASE/'kept-new-house-records.jsonl.gz',base['kept_new_records'],inputs):
            level,ID=row['next_level'],row['new_lowID'];i=bisect_right(starts[level],ID)-1;key=intervals[level][i]if i>=0 else None
            copied=key is not None and key[1]<=ID<key[1]+key[2];identity=sha(json.dumps(source_content_identity(row),ensure_ascii=False,sort_keys=True,separators=(',',':')).encode())
            source_identity_hash.update(identity.encode()+b'\n');item=dict(level=level,current_lowID=ID,unchanged_payload=row['payload'],source_content_identity_sha256=identity)
            if copied:
                group=groups[key];ordinal=ID-key[1];context=group_target.get(key);inserts=context['numeric_insertion_ordinals'].values()if context else[]
                newordinal=old_to_new_ordinal(ordinal,inserts);newID=group['planned_new_first']+newordinal;offset=(newID-tree.tables[level]['count']-1)*STRIDES[level]
                sourcegroup=tree.group(key);sourcevalue=h.extract(sourcegroup['raw'],sourcegroup['shift']+ordinal*STRIDES[level],STRIDES[level])
                actualvalue=h.extract(maps[level],offset,STRIDES[level]);expected=int.from_bytes(bytes.fromhex(row['payload']),'little')
                need(sourcevalue==actualvalue==expected,'Every prior new leaf in COW closure remains identical in actual append')
                item.update(status='actual_cloned_append_payload_identical',cloned_lowID=newID,appended_bit_offset=offset);prior_counts['copied_prior_new_leaves']+=1
            else:
                item.update(status='outside_COW_closure_remains_in_bound_current_prefix',actual_full_IMG_prefix_preservation_still_integration_gate=True)
                prior_counts['untouched_current_prefix_prior_new_leaves']+=1
            prior_ledger.add(item)
        need(sum(prior_counts.values())==130637,'All prior new-leaf identities classified once')
        leaf_ledger=Ledger('new-lane-house-records.jsonl.gz');full_members=0;seen=0
        for ready in h.ledger_input(JOIN/'ready-lane-house-targets.jsonl.gz',join['artifacts']['ready'],inputs):
            key=(ready['actual_parent']['record'],ready['numeric_house']);target=source_targets.pop(key);position=new_positions[key]
            need((ready['house_label'],ready['primary_ref'],ready['planned_raw24'],ready['source_ids'],ready['source_group_ids'],ready['source_node_count'])==
                 (target['house_label'],target['primary_ref'],target['raw24'],target['source_ids'],target['source_group_ids'],target['source_node_count']),
                 'New payload exact full sealed source provenance values')
            mapping=patched_parent_mappings[position['current_parent_record']]
            need(mapping['patched_first_child']<=position['new_lowID']<mapping['patched_first_child']+mapping['patched_child_count']and
                 mapping['original_fields']['next_level']==position['level'],'Actual copied parent pointer reaches new leaf ID')
            leaf_ledger.add(dict(**position,house_label=ready['house_label'],numeric_house=ready['numeric_house'],primary_ref=ready['primary_ref'],
                raw24=ready['planned_raw24'],coordinate_strings=ready['selected_coordinate_strings'],source_ids=ready['source_ids'],
                source_group_ids=ready['source_group_ids'],source_node_count=ready['source_node_count'],source_members=ready['source_members'],
                source_ready_target=ready,stock_parent_record=ready['actual_parent']['record'],new_parent_record=mapping['new_parent_record'],
                native_write_ready=False,geometry_reexecuted=False,quantization_reexecuted=False))
            seen+=1;full_members+=ready['source_node_count']
        need(not source_targets and seen==58233 and full_members==111147,'All new leaves complete actual source membership')
        for level,mapfile in maps.items():
            artifact=appends[level];need(sha(mapfile)==artifact['sha256'],'Fresh actual full tight append SHA')
            need(not artifact['unused_final_high_bits']or mapfile[-1]>>(8-artifact['unused_final_high_bits'])==0,'Only final high padding zero')
            mapfile.close();handles[level].close()
        need(stat(candidate)==before,'Actual candidate immutable during bounded reads')
        readledger=Ledger('candidate-bounded-read-receipts.jsonl.gz')
        for row in image.read_log:readledger.add(row)
        readbytes=sum(r['bytes']for r in image.read_log);readops=len(image.read_log)
        artifacts=dict(groups=group_ledger.close(),parent_mappings=parent_ledger.close(),new_records=leaf_ledger.close(),prior_new_identities=prior_ledger.close(),
            candidate_reads=readledger.close(),selected_ranges=saved('selected-l3-range-changes.json',selected),
            appends=saved('appends.json',{str(k):v for k,v in appends.items()}))
        derived={level:tree.tables[level]['count']+artifact['record_count']for level,artifact in appends.items()}
        need(all(derived[level]==capacity['proposed_table_counts'][str(level)]for level in [4,5,6]),
             'Exact final table counts derived from source and encoded appends')
        rss=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss;need(rss<=MAX_RSS_KIB,'Actual producer memory guard')
        proof=dict(schema='current-native-lane-tree-COW-appends/v1',started_utc=started,finished_utc=datetime.now(timezone.utc).isoformat(),
            script_sha256=sha(Path(__file__).read_bytes()),all_assigned_checks_passed=True,inputs=inputs,artifacts=artifacts,append_artifacts={str(k):v for k,v in appends.items()},
            counts=dict(counts),selected_L3_changes=len(selected),selected_L3_classification=dict(classifications),new_integer_house_records=seen,
            full_new_source_node_memberships=full_members,explicit_lower_parent_mappings=len(patched_parent_mappings),
            final_table_counts=derived,lower_profiles_unchanged=True,current_source_L5_unused_tail_bits=2,
            independent_append_group_start_bit_shifts={str(k):dict(v)for k,v in group_start_shifts.items()},all_old_relative_order_preserved=True,
            actual_readback_current_old_records_by_level=dict(actual_readback),actual_readback_explicit_pointer_patches_by_level=dict(patched_fields),
            cloned_old_raw_flag_counts=dict(raw_flags),prior_v2_new_leaf_identity_counts=dict(prior_counts),prior_v2_source_content_identity_digest=source_identity_hash.hexdigest(),
            entire_current_prefix_is_future_IMG_writer_gate=True,source_candidate_SHA=base['candidate_sha256'],source_candidate_stat_before=before,source_candidate_stat_after=stat(candidate),
            source_candidate_ctime_diff_from_root_seal_due_authorized_hardlink=before[4]!=sealed[4],whole_candidate_hash_not_repeated=True,
            candidate_readbytes=readbytes,candidate_read_operations=readops,max_RSS_KiB=rss,unchanged_RSS_guard_KiB=MAX_RSS_KIB,
            lower_original_fields_except_explicit_first_count_patches_preserved=True,all_actual_new_leaf_payload_ref_coordinates_verified=True,
            all_actual_cloned_parent_links_reach_expected_new_groups=True,stock_only_parent_patches_used=False,
            native_write_ready=False,whole_IMG_written=False,PBF_prepared_source_or_exact_ready_ledgers_reopened=False,
            geometry_or_quantization_reexecuted=False,native_CPU_UI_device_or_closed_suites_executed=False,
            USB_ZIP_canonical_or_prior_frozen_files_modified=False,full_native_address_update_complete=False,
            elapsed_seconds_receipt_only=time.monotonic()-t0,
            limits=['This is actual append preparation and file readback, not a whole image or installed update.',
                'Entire v2 prefix/all prior leaf preservation in an assembled IMG still requires current-profile writer/full integration readback.',
                'Prior new leaves copied within this closure are byte-identical; outside leaves stay in bound current base pending that prefix gate.',
                'Native complete comparator/query/UI/routing, 8K device acceptance and exact rollback remain unproved.'])
        saved('proof.json',proof);receipt=dict(exit_status=0,counts=dict(counts),appends={str(k):v for k,v in appends.items()},selected_L3_changes=len(selected),
            final_table_counts=derived,prior_new_leaf_identity_counts=dict(prior_counts),candidate_readbytes=readbytes,candidate_read_operations=readops,
            max_RSS_KiB=rss,source_sha256=proof['script_sha256'],proof_sha256=sha((HERE/'proof.json').read_bytes()),image_handle_closed=True)
        saved('execution-receipt.json',receipt);print(json.dumps(receipt),flush=True)


if __name__=='__main__':main()
