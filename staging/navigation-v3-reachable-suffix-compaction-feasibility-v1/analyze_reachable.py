#!/usr/bin/env python3
"""Single actual MDR stream; bounded field arrays, reachability and arithmetic.

No image output, firmware/guest execution, source ledger, labels or device I/O.
Original stock IDs remain fixed. All47870 original L3 records are roots.
"""
from pathlib import Path
from datetime import datetime,timezone
from array import array
from collections import Counter
import ast
import hashlib
import json
import os
import resource
import struct
import sys
import time

ROOT=Path('/root/garmin'); HERE=Path(__file__).resolve().parent
IMG_CAP=160000000; RSS_CAP_KIB=384*1024; SUMMARY_CAP=1<<20
RANGE_CAP=2000000
CANDIDATE='staging/navigation-country-native-lane-candidate-v3/gmapprom1.img'
CANDIDATE_SHA='1f468eb78cc1268951873c82ffce4abe3292dcece69c0eee405c5d7aca3cc360'
READER='staging/navigation-minimal-lane-render-isolation-plan-v1/prepare_control.py'
READER_SHA='a20877fce09cbfe36f1f5621144f2ade44a031c26e4c6d330d07b2a1b86c4095'
KNOWN_RAW_FLAGS={0,4,5,6,8,12,13,14}


def need(condition,message):
    if not condition: raise ValueError(message)


def sha(raw): return hashlib.sha256(raw).hexdigest()


def stat(path):
    s=path.stat()
    return dict(dev=s.st_dev,ino=s.st_ino,bytes=s.st_size,mtime_ns=s.st_mtime_ns,
                ctime_ns=s.st_ctime_ns,nlink=s.st_nlink,mode=oct(s.st_mode&0o777))


def rss():
    value=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    need(value<=RSS_CAP_KIB,'Bounded RSS guard')
    return value


def write(name,row):
    raw=json.dumps(row,ensure_ascii=False,indent=2).encode()+b'\n'
    need(len(raw)<=SUMMARY_CAP,'One bounded summary artifact')
    with (HERE/name).open('xb') as f:
        f.write(raw); f.flush(); os.fsync(f.fileno())
    return dict(path=str((HERE/name).relative_to(ROOT)),bytes=len(raw),sha256=sha(raw))


def load(path,pin,inputs,maximum=200000):
    p=ROOT/path; before=stat(p); need(before['bytes']<=maximum,'Small sealed input bound')
    with p.open('rb') as f:
        raw=f.read(maximum+1); need(f.read(1)==b'','Small input EOF')
    need(sha(raw)==pin and stat(p)==before,'Small source SHA/stat pin')
    inputs.append(dict(path=path,bytes=len(raw),sha256=pin,stat_before=before,stat_after=stat(p)))
    return json.loads(raw)


class ReadBudget:
    """Rolling receipt, not an unbounded physical-read list."""
    def __init__(self):
        self.bytes=0; self.ops=0; self.h=hashlib.sha256(); self.first=[]; self.last=[]
        self.by_purpose=Counter(); self.min_offset=None; self.max_end=0
    def read(self,image,at,size,purpose):
        need(0<=at<=at+size<=image.size and self.bytes+size<=IMG_CAP,'Hard total actual IMG read cap')
        image.f.seek(at); raw=image.f.read(size); need(len(raw)==size,'Complete actual read')
        row=dict(ordinal=self.ops,physical_offset=at,bytes=size,sha256=sha(raw),purpose=purpose)
        receipt=json.dumps(row,separators=(',',':'),sort_keys=True).encode()+b'\n'
        self.h.update(receipt); self.bytes+=size; self.ops+=1
        if len(self.first)<8:self.first.append(row)
        self.last.append(row)
        if len(self.last)>8:self.last.pop(0)
        self.by_purpose[purpose.split(';')[0]]+=size
        self.min_offset=at if self.min_offset is None else min(self.min_offset,at); self.max_end=max(self.max_end,at+size)
        return raw


def allocate_fields(count):
    return dict(first=array('I',[0])*(count+1),count=array('H',[0])*(count+1),flags=array('H',[0])*(count+1))


def stream_actual(image,tables,pin):
    fields={level:allocate_fields(tables[level]['count']) for level in (3,4,5)}
    fixed_bytes=sum(a.itemsize*len(a) for f in fields.values() for a in f.values())
    print(json.dumps(dict(stage='allocated bounded field arrays',bytes=fixed_bytes,RSS_KiB=rss())),flush=True)
    cursor=0; allhash=hashlib.sha256(); streamed_bytes=0; receipts=[]; header=None
    def chunks(start,total,chunk_bytes,purpose):
        nonlocal cursor,streamed_bytes,header
        need(start==cursor,'Single monotonic MDR pass without overlap')
        at=start; end=start+total
        while at<end:
            n=min(chunk_bytes,end-at); raw=image.logical('00004171.MDR',at,n,purpose)
            if at==0:header=raw[:772]
            allhash.update(raw); streamed_bytes+=len(raw); cursor+=len(raw); at+=len(raw)
            yield raw
    prefix_hash=hashlib.sha256()
    for raw in chunks(0,tables[6]['start'],1<<20,'single MDR unchanged prefix'):prefix_hash.update(raw)
    need(header is not None and len(header)==772 and struct.unpack_from('<H',header)[0]==772
         and header[2:12]==b'GARMIN MDR','Actual streamed MDR header')
    need(struct.unpack_from('<4I',header,600)==(149220236,120,20,1),'Actual streamed six DIR header')
    receipts.append(dict(segment='unchanged prefix',bytes=tables[6]['start'],sha256=prefix_hash.hexdigest()))
    map_counts={}; flag_counts={}; padding={}
    for level in (6,5,4,3,2,1):
        t=tables[level]; width=t['stride']; digest=hashlib.sha256(); maps=Counter(); flags=Counter(); number=0
        record_chunk=65536; chunk_bytes=record_chunk*width//8
        for raw in chunks(t['start'],t['bytes'],chunk_bytes,'single MDR L'+str(level)):
            digest.update(raw)
            n=min(record_chunk,t['count']-number)
            if level==4:
                need(len(raw)==n*16,'Aligned actual L4 record chunk')
                f=fields[4]; ID=number+1
                for lo,hi in struct.iter_unpack('<QQ',raw):
                    f['first'][ID]=(lo>>39)&((1<<22)-1)
                    f['count'][ID]=((lo>>61)|(hi<<3))&1023
                    flag=(hi>>7)&511; f['flags'][ID]=flag; flags[flag]+=1; maps[lo&1]+=1; ID+=1
            elif level==5:
                f=fields[5]; ID=number+1
                for k in range(n):
                    byte,shift=divmod(k*126,8); value=int.from_bytes(raw[byte:byte+11],'little')>>shift
                    f['first'][ID]=(value>>39)&((1<<21)-1)
                    f['count'][ID]=(value>>60)&511
                    flag=(value>>69)&511; f['flags'][ID]=flag; flags[flag]+=1; maps[value&1]+=1; ID+=1
            elif level==3:
                f=fields[3]; ID=number+1
                for k in range(n):
                    value=int.from_bytes(raw[k*14:k*14+14],'little')
                    f['first'][ID]=(value>>20)&((1<<23)-1)
                    f['count'][ID]=(value>>43)&4095
                    flag=(value>>55)&511; f['flags'][ID]=flag; flags[flag]+=1; maps[value&1]+=1; ID+=1
            elif level==6:
                for k in range(n):
                    byte,shift=divmod(k*68,8); maps[(raw[byte]>>shift)&1]+=1
            number+=n
            if number==t['count']:
                pad=(-t['count']*width)%8
                need(not pad or raw[-1]>>(8-pad)==0,'Actual final table padding zero')
                padding[level]=pad
            rss()
        need(number==t['count'],'All actual table records streamed exactly')
        receipts.append(dict(segment='table',level=level,start=t['start'],bytes=t['bytes'],record_count=number,
                             stride_bits=width,sha256=digest.hexdigest(),final_padding_bits=padding[level]))
        map_counts[level]=dict(maps); flag_counts[level]=dict(flags)
        print(json.dumps(dict(stage='single actual table complete',level=level,records=number,bytes=t['bytes'],
                             rawflags=dict(flags),RSS_KiB=rss()),ensure_ascii=False),flush=True)
    directory=b''.join(chunks(cursor,120,120,'single MDR DIR'))
    need(directory.hex()==pin['actual_DIR_hex'],'Actual streamed DIR equals frozen directory ABI witness')
    need(cursor==149220356 and streamed_bytes==149220356,'One full MDR stream exact EOF')
    need(allhash.hexdigest()==pin['actual_MDR_SHA'],'Actual component stream matches producer complete-readback hash')
    receipts.append(dict(segment='DIR',start=149220236,bytes=120,sha256=sha(directory)))
    return fields,dict(streamed_bytes=streamed_bytes,actual_MDR_SHA256=allhash.hexdigest(),segments=receipts,
                     mapordinal_counts=map_counts,raw_flag_counts=flag_counts,final_padding_bits=padding,
                     fixed_field_arrays_bytes=fixed_bytes,whole_IMG_hash_computed=False)


def prefix_mask(count,kept):
    bits=bytearray((count+7)//8); whole,remainder=divmod(kept,8)
    bits[:whole]=b'\xff'*whole
    if remainder:bits[whole]=(1<<remainder)-1
    return bits


def fill_all(bits,count):
    bits[:]=b'\xff'*len(bits)
    if count%8:bits[-1]=(1<<(count%8))-1


def mark(bits,first,count):
    a,b=first-1,first-1+count; left,right=a//8,b//8
    if left==right:
        bits[left]|=((1<<count)-1)<<(a%8); return
    bits[left]|=(255<<(a%8))&255
    if right-left>1:bits[left+1:right]=b'\xff'*(right-left-1)
    if b%8:bits[right]|=(1<<(b%8))-1


def contains(bits,ID):return bool(bits[(ID-1)//8]&(1<<((ID-1)%8)))


def make_rank(bits):
    out=array('I',[0]); amount=0
    for v in bits:amount+=v.bit_count(); out.append(amount)
    return out


def mapped_ID(bits,rank,ID):
    byte,bit=divmod(ID-1,8)
    need(bits[byte]&(1<<bit),'Map only retained IDs')
    return rank[byte]+(bits[byte]&((1<<(bit+1))-1)).bit_count()


def analyze(name,prefixes,fields,tables,container):
    counts={i:tables[i]['count'] for i in (4,5,6)}
    keep={i:prefix_mask(counts[i],prefixes[i]) for i in counts}
    ranges={i:array('Q') for i in counts}; occurrences=Counter(); rawflags=Counter(); anomalies=Counter()
    anomaly_samples=[]; unknown_flags=Counter(); inactive=Counter(); active=Counter(); force_all=False; alias_complete=True
    def anomaly(kind,level,ID,first,n,flags):
        nonlocal force_all
        anomalies[kind]+=1
        if len(anomaly_samples)<20:anomaly_samples.append(dict(kind=kind,source_level=level,source_ID=ID,
            first=first,count=n,raw_flags=flags))
        # An uninterpreted/invalid child encoding is not permission to drop data.
        # Retain every lower suffix, so feasibility remains conservative.
        if not force_all:
            for target in keep:fill_all(keep[target],counts[target])
            force_all=True
    def edge(level,ID):
        nonlocal alias_complete
        f=fields[level]; first=f['first'][ID]; n=f['count'][ID]; flags=f['flags'][ID]; target=flags&7
        rawflags[str(level)+':'+str(flags)]+=1
        if flags not in KNOWN_RAW_FLAGS:
            unknown_flags[str(level)+':'+str(flags)]+=1
            anomaly('unclassified_raw_flag_conservative_all_suffix',level,ID,first,n,flags)
        if n==0 and first==0:
            if target not in (0,4,5,6):anomaly('invalid_empty_next_level',level,ID,first,n,flags)
            return
        if target not in counts or target<=level:
            anomaly('invalid_or_nonforward_next_level',level,ID,first,n,flags); return
        if n==0:
            anomaly('nonzero_first_with_zero_count',level,ID,first,n,flags); return
        if not(1<=first<=first+n-1<=counts[target]):
            anomaly('out_of_bounds_child_range',level,ID,first,n,flags); return
        mark(keep[target],first,n); occurrences[target]+=1
        if len(ranges[target])<RANGE_CAP:ranges[target].append((first<<12)|n)
        else:alias_complete=False
    for ID in range(1,tables[3]['count']+1):edge(3,ID)
    for level in (4,5):
        for ID in range(1,counts[level]+1):
            if contains(keep[level],ID):edge(level,ID); active[level]+=1
            else:inactive[level]+=1
        print(json.dumps(dict(stage='RAM-only reachability',plan=name,source_level=level,retained=active[level],
            skipped=inactive[level],unknown_flags=dict(unknown_flags),anomalies=dict(anomalies),RSS_KiB=rss())),flush=True)
    retained={i:sum(v.bit_count() for v in keep[i]) for i in counts}
    post={i:retained[i]-prefixes[i] for i in counts}; removable={i:counts[i]-retained[i] for i in counts}
    ranks={i:make_rank(keep[i]) for i in counts}; relation_stats={}; per_parent_remap=Counter(); roots_changed=0
    for level in (3,4,5):
        f=fields[level]
        for ID in range(1,tables[level]['count']+1):
            if level!=3 and not contains(keep[level],ID):continue
            first,n,flag=f['first'][ID],f['count'][ID],f['flags'][ID]; target=flag&7
            if n and target in counts and target>level and 1<=first<=first+n-1<=counts[target]:
                moved=mapped_ID(keep[target],ranks[target],first)!=first
                if moved:per_parent_remap[str(level)+'→'+str(target)]+=1
                if level==3 and moved:roots_changed+=1
    for target in (4,5,6):
        values=sorted(ranges[target]); unique=duplicate=overlap=components=changed_groups=0
        max_end=0; previous=None; partial_samples=[]; group_samples=[]; contiguity_fail=0; aliased_parents=0
        for code in values:
            first,n=code>>12,code&4095
            if code==previous:duplicate+=1; aliased_parents+=1;continue
            previous=code; unique+=1; end=first+n-1
            if first<=max_end:
                overlap+=1
                if len(partial_samples)<10:partial_samples.append(dict(first=first,count=n,previous_union_end=max_end))
            else:components+=1
            max_end=max(max_end,end)
            newfirst=mapped_ID(keep[target],ranks[target],first); newlast=mapped_ID(keep[target],ranks[target],end)
            if newlast-newfirst!=n-1:contiguity_fail+=1
            if newfirst!=first:
                changed_groups+=1
                if len(group_samples)<10:group_samples.append(dict(old_first=first,count=n,new_first=newfirst))
        relation_stats[target]=dict(retained_parent_child_ranges=occurrences[target],bounded_ranges_stored=len(ranges[target]),
            exact_unique_first_count_groups=unique,duplicate_first_count_references=duplicate,
            distinct_overlapping_intervals=overlap,connected_interval_union_clusters=components,
            unique_groups_needing_first_pointer_remap=changed_groups,contiguity_failures=contiguity_fail,
            partial_overlap_samples=partial_samples,first_remap_samples=group_samples,
            range_alias_analysis_complete=alias_complete)
        del values
    need(all(r['contiguity_failures']==0 for r in relation_stats.values()),'Every retained valid range maps to contiguous dense IDs')
    lower_IDs_changed={}
    for level in counts:
        changed=0
        for ID in range(prefixes[level]+1,counts[level]+1):
            if contains(keep[level],ID) and mapped_ID(keep[level],ranks[level],ID)!=ID:changed+=1
        lower_IDs_changed[level]=changed
    # Same widths and table packing; the old non-table prefix and upper tables
    # remain present. Directory first/count fields would need mapped pointers.
    sizes={i:(retained[i]*tables[i]['stride']+7)//8 for i in counts}
    new_mdr=container['MDR_bytes']-sum(tables[i]['bytes'] for i in counts)+sum(sizes.values())
    comp4k={name:(size+4095)//4096 for name,size in container['component_sizes'].items()}
    comp4k['00004171.MDR']=(new_mdr+4095)//4096
    parts={name:(blocks+239)//240 for name,blocks in comp4k.items()}
    row_count=1+sum(parts.values()); metadata_min=(4096+row_count*512+4095)//4096*4096
    metadata_conservative=max(73728,metadata_min)
    image_min=metadata_min+sum(comp4k.values())*4096
    image_conservative=metadata_conservative+sum(comp4k.values())*4096
    capacity=134217728
    widths_ok=(retained[4]<(1<<23) and retained[5]<(1<<22) and retained[6]<(1<<21))
    stats=dict(plan=name,preserved_lower_prefix_counts=prefixes,all_L3_roots=47870,
        current_lower_counts=counts,retained_total_lower_counts=retained,
        additional_retained_postprefix_records=post,structurally_unreferenced_postprefix_records=removable,
        raw_flag_counts_of_retained_pointer_sources=dict(rawflags),unknown_raw_flag_counts=dict(unknown_flags),
        invalid_or_unclassified_child_encoding_counts=dict(anomalies),anomaly_samples=anomaly_samples,
        any_unknown_or_invalid_encoding_forced_all_lower_suffix_retention=force_all,
        pointer_relation_reachability_complete=not anomalies,
        nonforward_dependency_fixpoint_not_needed=not force_all,
        range_alias_analysis=relation_stats,range_alias_analysis_complete=alias_complete,
        parent_records_needing_pointer_remap_by_source_target=dict(per_parent_remap),
        total_parent_first_fields_needing_remap=sum(per_parent_remap.values()),
        L3_roots_needing_first_pointer_remap=roots_changed,lower_retained_records_whose_lowID_would_change=lower_IDs_changed,
        original_prefix_IDs_unchanged=True,L3_IDs_and_JAI_record_keys_unchanged=True,
        GMP_or_other_five_components_changed=False,unknown_flag_bits_or_records_not_normalized=True,
        referenced_range_contiguity_preserved=True,overlapping_group_aliases_preserved_by_same_order_dense_mapping=True,
        arithmetic=dict(lower_table_bytes_after=sizes,MDR_bytes_after=new_mdr,MDR_bytes_removed=container['MDR_bytes']-new_mdr,
            component_4K_block_counts=comp4k,FAT_component_part_counts=parts,root_plus_component_FAT_rows=row_count,
            minimal_4K_metadata_bytes=metadata_min,conservative_4K_metadata_bytes=metadata_conservative,
            projected_minimum_4K_IMG_bytes=image_min,projected_conservative_4K_IMG_bytes=image_conservative,
            declared_original_4K_capacity=capacity,capacity_margin_conservative=capacity-image_conservative,
            fits_4K_capacity_arithmetic=image_conservative<=capacity,same_field_width_capacity_valid=widths_ok),
        caveats=['All current active first/count relations are examined, not all external lower-record ID consumers.',
            'Other MDR non-table prefix or external components may contain lower IDs; their relocation ABI is unknown.',
            'L3 JAI IDs stay fixed but native caches/query vectors may retain L4/L5/L6 IDs; no live/UI continuity is proved.',
            'Unknown high flags8/12/13/14 are retained verbatim with their full referenced ranges, not given invented meanings.',
            'Arithmetic feasibility does not prove safe compact IMG construction, original checksum or physical acceptance.'],
        native_context_renderer_UI_or_install_ready=False,RSS_KiB=rss())
    print(json.dumps(dict(stage='feasibility plan complete',plan=name,retained=retained,removed=removable,
        projected_IMG=image_conservative,fits=image_conservative<=capacity,anomalies=dict(anomalies),RSS_KiB=rss())),flush=True)
    return stats


def main():
    need(not (HERE/'proof.json').exists(),'New finite namespace')
    need(array('I').itemsize==4 and array('H').itemsize==2 and array('Q').itemsize==8,'Fixed native array widths')
    started=datetime.now(timezone.utc).isoformat(); t0=time.monotonic(); inputs=[]
    original=load('staging/navigation-country-native-house-merge-v1/proof.json',
        'bfc55b01f1f567cbad495ba3e35301d358cf54d1fdddea9fe1b8a9e6c8412a41',inputs)
    stock={int(k):v for k,v in original['original_counts'].items()}
    need(stock=={4:2133948,5:2341096,6:1973316},'Pinned original stock counts')
    facts=load('staging/navigation-native-L3-width-policy-static-v1/candidate-layout-and-CPU-facts.json',
        '3305e1aa1019c1920fee5e8993936d21aa0fe0ebb79d745a624ae900978868e9',inputs)
    base=load('staging/navigation-country-native-lane-candidate-v3/proof.json',
        'b5baf538981a60aceb2b8cbb2c31ce3e8159363a719909791e31ef0ca0cb58d0',inputs)
    sealed=load('staging/navigation-country-native-lane-candidate-v3/sealed-files.json',
        'dfc47744887137f944d710dffeb5ea6f6821c24eb8abbeb522cb406576754335',inputs)
    producer=load('staging/navigation-native-lane-tree-cow-append-v1/proof.json',
        '1cde367d1d3aba44290b7f44be40c9cb5d04bf911a3e8bd3898e071a1329b4e9',inputs)
    need(base['all_assigned_checks_passed'] and sealed['all_assigned_checks_passed'] and producer['all_assigned_checks_passed'],
         'Closed producer and actual v3 composition scope pins')
    need(all(r['all_significant_bits_identical'] for r in base['lower_prefix_significant_bit_checks'])
         and all(r['matches_sealed_producer_stream'] for r in base['actual_append_extraction_checks'])
         and producer['all_old_relative_order_preserved'] and producer['lower_original_fields_except_explicit_first_count_patches_preserved'],
         'Inherited v2 old-field/relative order/leaf retention and actual COW assembly gates')
    raw=(ROOT/READER).read_bytes(); need(sha(raw)==READER_SHA,'Sealed ordinary mapper source identity')
    inputs.append(dict(path=READER,bytes=len(raw),sha256=READER_SHA,use='AST reuse only Image allocation parser; old main not executed'))
    tree=ast.parse(raw.decode()); n=next(n for n in tree.body if isinstance(n,ast.ClassDef) and n.name=='Image')
    names=next(n for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='NAMES' for t in n.targets))
    env=dict(need=need,struct=struct)
    exec(compile(ast.Module(body=[names,n],type_ignores=[]),READER,'exec'),env)
    profile=facts['profiles']['lane_v3']; tables={r['level']:dict(r,stride=r['stride_bits']) for r in profile['tables']}
    need(tables[3]['count']==47870 and tables[3]['widths'][0]==23 and tables[3]['stride']==112,'Actual23/112 pinned profile')
    need([tables[i]['stride'] for i in (4,5,6)]==[128,126,68],'Current lower packing unchanged')
    component=next(r for r in base['complete_actual_component_checks'] if r['name']=='00004171.MDR')
    stream_pin=dict(actual_DIR_hex=profile['directory_source']['hex'],actual_MDR_SHA=component['sha256'])
    imagepin=dict(bytes=153346048,block_bytes=8192)
    imgrow=next(r for r in sealed['files'] if r['path']==CANDIDATE)
    p=ROOT/CANDIDATE; before=stat(p)
    need(imgrow['sha256']==CANDIDATE_SHA and [before[k] for k in ('dev','ino','bytes','mtime_ns')]==imgrow['stat_at_seal'][:4]
         and before['mode']=='0o444','Original immutable v3 content inode/size/mtime; fresh released hardlinks stat')
    budget=ReadBudget()
    with p.open('rb') as f:
        image=env['Image']('v3',f,imagepin,budget)
        need(image.components['00004171.MDR']['size']==149220356,'Actual FAT MDR size')
        need({r['name']:r['bytes'] for r in base['complete_actual_component_checks']}==
             {k:v['size'] for k,v in image.components.items()},'All actual six component sizes')
        fields,stream=stream_actual(image,tables,stream_pin)
        container=dict(MDR_bytes=149220356,component_sizes={k:v['size'] for k,v in image.components.items()},
            current_block_bytes=8192,current_metadata_end=image.directory_end)
        need(stat(p)==before,'Source stat/nlink stable through stream')
    need(stat(p)==before,'Source stat/nlink stable after rb handle closed')
    receipt=write('actual-stream-read-receipts.json',dict(schema='garmin-single-MDR-stream-rolling-receipt/v1',
        image_bytes_read=budget.bytes,read_operation_count=budget.ops,read_cap_bytes=IMG_CAP,
        rolling_all_physical_read_receipts_sha256=budget.h.hexdigest(),rolling_receipt_format='canonical sorted compact JSON plus LF',
        first_bounded_reads=budget.first,last_bounded_reads=budget.last,bytes_by_purpose=dict(budget.by_purpose),
        stream=stream,source_stat_before=before,source_stat_after=stat(p),source_handle_closed=True,
        full_tables_or_full_read_ledger_not_written=True,whole_IMG_hash_recomputed=False))
    # No source IMG is open during reachability/rank/alias analyses.
    stock_result=analyze('retain_all_stock_lower_prefixes_plus_all_L3_active_tree',stock,fields,tables,container)
    v2_prefixes={r['level']:r['count'] for r in facts['profiles']['country_v2']['tables'] if r['level'] in (4,5,6)}
    v2_result=analyze('retain_all_current_v2_lower_prefixes_plus_all_L3_active_tree',v2_prefixes,fields,tables,container)
    need(stat(p)==before,'Source inode/stat/nlink still stable at scope completion')
    preservation=dict(whole_original_stock_lower_IDs_and_records_retained=True,all_original_47870_L3_roots_retained=True,
        unchanged_original_L3IDs_and_JAI_keys=True,
        current_v2_prior_new_leaves_retention_inherited_counts=producer['prior_v2_new_leaf_identity_counts'],
        current_v2_prior_source_identity_digest_inherited=producer['prior_v2_source_content_identity_digest'],
        current_v2_current_children_old_relative_order_and_fields_except_explicit_childpatches_inherited=True,
        current_v3_active_parent_first_count_closure_actually_analyzed=True,
        original_non_table_MDR_prefix_and_all_five_other_components_retained_in_arithmetic=True,
        lower_ID_external_references_proven_absent=False,official_or_physical_or_renderer_acceptance_verified=False,
        scope_does_not_prove_uninterrupted_search_UI_or_all_possible_external_record_consumers=True)
    results=write('feasibility-summary.json',dict(schema='garmin-v3-reachable-suffix-compaction-feasibility/v1',
        stock_prefix_plus_active=stock_result,current_v2_prefix_plus_active=v2_result,preservation=preservation))
    proof=write('proof.json',dict(schema='garmin-v3-single-stream-reachability-proof/v1',started_utc=started,
        finished_utc=datetime.now(timezone.utc).isoformat(),all_assigned_feasibility_checks_completed=True,
        source_inputs=inputs,actual_source_candidate=dict(path=CANDIDATE,bytes=153346048,inherited_whole_sha256=CANDIDATE_SHA,
            stat_before=before,stat_after=stat(p),handle_closed=True,whole_hash_not_repeated=True),
        actual_IMG_bytes_read=budget.bytes,actual_IMG_read_cap=IMG_CAP,actual_MDR_stream_bytes=stream['streamed_bytes'],
        actual_MDR_stream_hash_matches_sealed_readback=True,one_MDR_source_stream=True,source_whole_IMG_hash_repeated=False,
        actual_arrays_fixed_bytes=stream['fixed_field_arrays_bytes'],range_array_cap_per_target=RANGE_CAP,
        RSS_guard_KiB=RSS_CAP_KIB,max_RSS_KiB=rss(),stock_original_counts=stock,
        actual_profile_L3=dict(first_width=23,stride=112,count=47870),actual_lower_strides=[128,126,68],
        source_ledger_PBF_or_MAIN_bytes_read=0,CPU_guest_or_audio_executed=False,physical_device_IO=False,
        new_IMG_or_full_backup_or_full_tables_or_remapped_records_written=False,
        original_seal_or_IMG_or_report_or_canonical_modified=False,
        all_own_and_source_handles_closed=True,artifacts=dict(read_receipts=receipt,summary=results),
        stock_prefix_plan_arithmetic_fits_4K=stock_result['arithmetic']['fits_4K_capacity_arithmetic'],
        stock_prefix_plan_child_encoding_anomalies=stock_result['invalid_or_unclassified_child_encoding_counts'],
        current_v2_prefix_plan_arithmetic_fits_4K=v2_result['arithmetic']['fits_4K_capacity_arithmetic'],
        compact_fix_or_native_install_or_renderer_acceptance_ready=False,full_Taiwan_goal_complete=False,
        unresolved_limits=stock_result['caveats'],elapsed_seconds_receipt_only=time.monotonic()-t0))
    need(sum(x.stat().st_size for x in HERE.iterdir() if x.is_file())<=SUMMARY_CAP,'Total stage summaries/source under1MiB')
    print(json.dumps(dict(all_assigned_feasibility_checks_completed=True,proof=proof,source_handle_closed=True,
        actual_IMG_read_bytes=budget.bytes,max_RSS_KiB=rss(),stock_projection=stock_result['arithmetic'],
        stock_child_encoding_anomalies=stock_result['invalid_or_unclassified_child_encoding_counts']),ensure_ascii=False),flush=True)


if __name__=='__main__':
    try:main()
    except Exception as e:
        if not (HERE/'actual-failure.json').exists():
            write('actual-failure.json',dict(exception_type=type(e).__name__,error=str(e),retry_or_guard_relaxation=False,
                source_or_device_modified=False,new_IMG_produced=False))
        raise
