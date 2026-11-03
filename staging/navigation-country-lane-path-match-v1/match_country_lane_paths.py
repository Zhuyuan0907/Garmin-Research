#!/usr/bin/env python3
"""One unresolved-key stream pass; exact existing stock lane/alley parents only.

No coordinates/source IDs in this input, no full source groups/PBF, no writer,
JAI, CPU, device, ZIP or canonical mutations. Bounded caches hold compact
plans and inventories; original packed bytes and label reads are logged.
"""
import ast
from collections import Counter, defaultdict, OrderedDict
from datetime import datetime,timezone
import gzip
import hashlib
import heapq
import json
from pathlib import Path
import re
import resource
import struct
import time
import unicodedata

ROOT=Path('/root/garmin'); OUT=Path(__file__).resolve().parent
AP=ROOT/'backups/20261002T154458Z/files/.System/gmapprom1.img'
JOIN=ROOT/'staging/navigation-country-address-ready-join-v1/proof.json'
ROSTER=ROOT/'staging/navigation-taiwan-address-ingestion-v1/native-hierarchy.jsonl.gz'
KEYS=JOIN.parent/'unresolved-native-name-group-keys.jsonl.gz'
SMALL=ROOT/'staging/navigation-native-lane-path-resolution-v1/resolve_lane_paths.py'
SMALL_PROOF=SMALL.parent/'proof.json'
READER=ROOT/'staging/navigation-native-deeper-address-plan-v1/inspect_deeper_address_paths.py'
EXPECTED={JOIN:'b61cd949152fece0548265ccf438c14d3bbeeddfc5e3ae05140df20d3aa0a175',
 ROSTER:'45333390cec4996db40b4a4a987eb421641fec352203bb318aedfd6a6fce2776',
 SMALL:'11e2632d21111f2c84fab984303fa2518e14fbb2166b5b7736eb08b62ff92cdc',
 SMALL_PROOF:'d020ae04a8d466dade1e5f03927e20930b476c1637e199bc8dc003ad8b2acdf0',
 READER:'1348bcb2f0191bd1fa5b32ca446ee15b084e76dd7ed3ea33c31b5351b2d021ec'}
MAX_RSS_KIB=500*1024
MAX_IMAGE_BYTES=384*1024*1024
GROUP_CACHE_BYTES=32*1024*1024
MAX_PATHS=50000; MAX_ROOTS=12000; MAX_LABELS=80000
SUMMARY_BATCH_PATHS=5000
DIRECT_CITIES={'基隆市','台北市','新竹市','嘉義市'}

def need(ok,message):
    if not ok:raise ValueError(message)

def sha(raw):return hashlib.sha256(raw).hexdigest()

def stat(path):
    s=path.stat();return [s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]

def encoded(row):return (json.dumps(row,ensure_ascii=False,separators=(',',':'))+'\n').encode()

def small_input(path,inputs):
    before=stat(path);need(before[2]<5_000_000,'Bounded helper/proof/roster input')
    raw=path.read_bytes();need(stat(path)==before and sha(raw)==EXPECTED[path],'Sealed input binding:'+str(path))
    inputs.append(dict(path=str(path.relative_to(ROOT)),bytes=len(raw),sha256=sha(raw),
        stat_before=before,stat_after=stat(path),stat_unchanged=True,content_passes=1))
    return raw

class HashReader:
    def __init__(self,stream):self.stream=stream;self.hash=hashlib.sha256();self.count=0
    def read(self,amount=-1):
        raw=self.stream.read(amount);self.hash.update(raw);self.count+=len(raw);return raw

class HashWriter:
    def __init__(self,stream):self.stream=stream;self.hash=hashlib.sha256();self.count=0
    def write(self,raw):
        n=self.stream.write(raw);need(n==len(raw),'Complete output write');self.hash.update(raw);self.count+=n;return n
    def flush(self):self.stream.flush()

class Ledger:
    def __init__(self,path):
        self.path=path;self.rows=0;self.plain_hash=hashlib.sha256();self.plain_bytes=0
        self.handle=path.open('xb');self.writer=HashWriter(self.handle)
        self.stream=gzip.GzipFile(filename='',mode='wb',fileobj=self.writer,compresslevel=6,mtime=0)
    def write(self,row):
        raw=encoded(row);self.stream.write(raw);self.plain_hash.update(raw);self.plain_bytes+=len(raw);self.rows+=1
    def close(self):
        self.stream.close();self.handle.close();need(stat(self.path)[2]==self.writer.count,'Output accounting')
        return dict(path=str(self.path.relative_to(ROOT)),rows=self.rows,bytes=self.writer.count,
            sha256=self.writer.hash.hexdigest(),uncompressed_sha256=self.plain_hash.hexdigest(),
            uncompressed_bytes=self.plain_bytes,hashes_computed_while_writing=True)

class LRU:
    def __init__(self,limit):self.limit=limit;self.data=OrderedDict();self.hits=0;self.misses=0;self.evictions=0;self.peak=0
    def get(self,key):
        if key not in self.data:self.misses+=1;return None
        self.hits+=1;self.data.move_to_end(key);return self.data[key]
    def put(self,key,value):
        self.data[key]=value;self.data.move_to_end(key)
        while len(self.data)>self.limit:self.data.popitem(last=False);self.evictions+=1
        self.peak=max(self.peak,len(self.data))
    def receipt(self):return dict(limit=self.limit,peak_entries=self.peak,hits=self.hits,misses=self.misses,evictions=self.evictions)

def helpers(raw):
    # Execute only selected definitions. No small-sample main or controls.
    tree=ast.parse(raw)
    names={'norm','suffix_tokens','exact_token_child','reused_reader','ActualLabels','ActualTree'}
    nodes=[n for n in tree.body if isinstance(n,(ast.FunctionDef,ast.ClassDef)) and n.name in names]
    need(len(nodes)==len(names),'Exact sealed reusable helper definitions')
    namespace=dict(need=need,sha=sha,ROOT=ROOT,READER=READER,ast=ast,re=re,struct=struct,
        hashlib=hashlib,unicodedata=unicodedata,TOKEN=re.compile(r'[1-9][0-9]*[巷弄]'),
        HOUSE=re.compile(r'[1-9][0-9]*(?:之[1-9][0-9]*)?號'),MAX_CHILD_ROWS=18000)
    exec(compile(ast.Module(body=nodes,type_ignores=[]),str(SMALL),'exec'),namespace)
    return namespace

def compact(r):
    names=('level','one_based_ID','native_record','primary_ref','primary_label',
           'first_child','child_count','child_level_and_flags','next_level')
    return {k:r[k] for k in names}

class Engine:
    def __init__(self,image,tables,labels,reader,h):
        self.image,self.tables,self.labels,self.reader,self.h=image,tables,labels,reader,h
        self.roots=LRU(MAX_ROOTS);self.paths=LRU(MAX_PATHS)
        self.groups=OrderedDict();self.group_bytes=0;self.group_peak=0;self.group_hits=0;self.group_misses=0;self.group_evictions=0
        self.decoded_child_rows=0;self.read_groups=0;self.guard_reasons=Counter()

    def root(self,row):
        key=row['low28_id'];r=self.roots.get(key)
        if r is None:
            tree=self.h['ActualTree'](self.image,self.tables,self.labels,self.reader)
            r=compact(tree.record(3,key))
            need((r['first_child'],r['child_count'],r['child_level_and_flags'],r['next_level'])==
                 (row['first_child'],row['child_count'],row['child_level_and_flags'],row['next_level']),
                 'Fresh original L3 fields agree with sealed corrected roster')
            need(self.h['norm'](r['primary_label'])==self.h['norm'](row['street']),
                 'Actual L3 primary label agrees with native roster')
            self.roots.put(key,r)
        return r

    def group(self,parent,houses=False):
        key=(parent['next_level'],parent['first_child'],parent['child_count'],houses)
        if key in self.groups:
            self.group_hits+=1;self.groups.move_to_end(key);return self.groups[key][0]
        self.group_misses+=1;self.read_groups+=1
        tree=self.h['ActualTree'](self.image,self.tables,self.labels,self.reader)
        try:
            children=tree.children(parent)
            result={'token_matches':{},'leaf_labels':{},'numeric_house_count':0,'count':len(children),'guard':None}
            for r in children:
                text=r['primary_label']
                if text is not None and self.h['TOKEN'].fullmatch(text):
                    result['token_matches'].setdefault(text,[]).append(compact(r))
                if houses and r['child_count']==0 and text is not None:
                    result['leaf_labels'].setdefault(text,[]).append((r['native_record'],r['primary_ref']))
                    if self.h['HOUSE'].fullmatch(text):result['numeric_house_count']+=1
            result['packed_span_sha256']=next(iter(tree.groups.values()))['packed_span_sha256'] if children else None
            result['actual_group_key']=list(key[:3]);self.decoded_child_rows+=len(children)
        except (ValueError,AssertionError,UnicodeDecodeError) as exc:
            if 'ceiling' in str(exc) or 'budget' in str(exc):raise
            result={'guard':str(exc),'actual_group_key':list(key[:3])}
            self.guard_reasons[str(exc)]+=1
        # Conservative accounting, plus a separately enforced actual process RSS.
        cost=1024+sum(768+len(text)*4+len(rows)*640 for text,rows in result.get('token_matches',{}).items())
        cost+=sum(384+len(text)*4+len(rows)*160 for text,rows in result.get('leaf_labels',{}).items())
        while self.groups and self.group_bytes+cost>GROUP_CACHE_BYTES:
            _,(_,oldcost)=self.groups.popitem(last=False);self.group_bytes-=oldcost;self.group_evictions+=1
        if cost<=GROUP_CACHE_BYTES:self.groups[key]=(result,cost);self.group_bytes+=cost
        self.group_peak=max(self.group_peak,self.group_bytes)
        need(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss<=MAX_RSS_KIB,'Actual RSS ceiling500MiB')
        return result

    def path(self,key,rootrow,tokens):
        cached=self.paths.get(key)
        if cached is not None:return cached
        try:
            parent=self.root(rootrow);records=[parent]
            for token in tokens:
                if not parent['child_count']:
                    answer={'reason':'parent_has_no_children_for_remaining_token','records':records};break
                group=self.group(parent)
                if group['guard']:
                    answer={'reason':'original_branch_decode_guard','guard':group['guard'],'records':records};break
                child,reason=self.h['exact_token_child'](group['token_matches'].get(token,[]),token)
                if reason:answer={'reason':reason,'records':records,'missing_token':token};break
                parent=child;records.append(parent)
            else:
                if parent['level'] not in (4,5) or not parent['child_count'] or parent['next_level'] not in (5,6):
                    answer={'reason':'resolved_token_record_has_no_supported_direct_leaf_group','records':records}
                else:
                    group=self.group(parent,True)
                    if group['guard']:
                        answer={'reason':'original_branch_decode_guard','guard':group['guard'],'records':records}
                    elif not group['numeric_house_count']:
                        answer={'reason':'resolved_parent_has_no_observed_numeric_house_leaves','records':records}
                    else:
                        answer={'reason':None,'records':records,'target':parent,
                            'numeric_house_count':group['numeric_house_count'],
                            'other_direct_child_count':group['count']-group['numeric_house_count'],
                            'final_group_sha256':group['packed_span_sha256']}
        except (ValueError,AssertionError,UnicodeDecodeError) as exc:
            if 'ceiling' in str(exc) or 'budget' in str(exc):raise
            answer={'reason':'original_branch_decode_guard','guard':str(exc),'records':[]}
            self.guard_reasons[str(exc)]+=1
        self.paths.put(key,answer);return answer

    def receipt(self):return dict(root_cache=self.roots.receipt(),path_cache=self.paths.receipt(),
        group_cache_accounting_limit_bytes=GROUP_CACHE_BYTES,group_cache_peak_accounting_bytes=self.group_peak,
        group_cache_hits=self.group_hits,group_cache_misses=self.group_misses,group_cache_evictions=self.group_evictions,
        actual_complete_group_reads=self.read_groups,actual_decoded_child_rows=self.decoded_child_rows,
        original_branch_guards=dict(self.guard_reasons))


def run_rows(meta,verified):
    path=ROOT/meta['path'];hashed_plain=hashlib.sha256();rows=0
    with path.open('rb') as source:
        hashed=HashReader(source)
        with gzip.GzipFile(fileobj=hashed,mode='rb') as stream:
            for line in stream:
                hashed_plain.update(line);rows+=1;yield json.loads(line)
        need(rows==meta['rows'] and hashed.count==meta['bytes'] and hashed.hash.hexdigest()==meta['sha256']
             and hashed_plain.hexdigest()==meta['uncompressed_sha256'],'Local sorted run readback/EOF binding')
    verified.append(dict(path=meta['path'],rows=rows,sha256=meta['sha256'],EOF_verified=True))

def merged_runs(metas,key,combine,verified):
    streams=[iter(run_rows(meta,verified)) for meta in metas];heap=[]
    for index,stream in enumerate(streams):
        row=next(stream,None)
        if row is not None:heapq.heappush(heap,(key(row),index,row))
    activekey=None;active=None
    while heap:
        k,index,row=heapq.heappop(heap)
        if active is None or k!=activekey:
            if active is not None:yield active
            activekey,active=k,row
        else:combine(active,row)
        following=next(streams[index],None)
        if following is not None:heapq.heappush(heap,(key(following),index,following))
    if active is not None:yield active

def combine_paths(a,b):
    need(a['actual_parent']==b['actual_parent'] and a['exact_actual_path_records']==b['exact_actual_path_records']
         and a['final_group_packed_span_sha256']==b['final_group_packed_span_sha256'],'Same path has immutable actual parent evidence')
    a['groups']+=b['groups']
    for field in ('house_membership_group_counts','coordinate_group_counts','source_label_group_counts'):
        for k,n in b[field].items():a[field][k]=a[field].get(k,0)+n

def combine_parents(a,b):a['matched_source_groups']+=b['matched_source_groups']


def main():
    need(not (OUT/'proof.json').exists(),'New output scope only')
    started=datetime.now(timezone.utc).isoformat();t0=time.monotonic();inputs=[]
    h=helpers(small_input(SMALL,inputs));reader=h['reused_reader'](small_input(READER,inputs))
    small=json.loads(small_input(SMALL_PROOF,inputs));need(small['all_assigned_checks_passed'],'Inherited bounded sample passed')
    joined=json.loads(small_input(JOIN,inputs)); artifact=joined['artifacts']['unresolved_native_names']
    need(artifact['path']==str(KEYS.relative_to(ROOT)) and artifact['rows']==2278269 and
         artifact['bytes']==45568995 and artifact['sha256']=='75ab32345e3cf8b1e1892ae029a5271a4be46908e2e647e1396244304a0252ba',
         'Sealed unresolved-key ledger binding')
    prefix_index=defaultdict(lambda:defaultdict(list));named_counts=Counter();roster_levels=Counter()
    for line in gzip.decompress(small_input(ROSTER,inputs)).splitlines():
        r=json.loads(line);roster_levels[r['level']]+=1
        if r['level']==3:
            named_counts[r['next_level']]+=1
            if r['district'] is not None:
                prefix_index[(h['norm'](r['city']),h['norm'](r['district']))][h['norm'](r['street'])].append(r)
    need(roster_levels=={1:22,2:343,3:47853} and named_counts=={4:20107,5:19036,6:8710},'Corrected original roster categories')
    output=Ledger(OUT/'matched-native-lane-groupkeys.jsonl.gz')
    readlog=Ledger(OUT/'original-map-read-log.jsonl.gz');progress=Ledger(OUT/'progress-receipts.jsonl.gz')
    before=stat(AP)
    class Image(reader['StockImage']):
        def __init__(self,handle):self.read_bytes=0;self.read_count=0;super().__init__(handle)
        def physical(self,offset,length,reason):
            need(self.read_bytes+length<=MAX_IMAGE_BYTES,'Actual original-map read budget')
            need(0<=offset<=offset+length<=before[2] and length<=2_000_000,'Actual physical read bounds')
            self.handle.seek(offset);raw=self.handle.read(length);need(len(raw)==length,'Complete original-map physical read')
            self.read_bytes+=length;self.read_count+=1
            readlog.write(dict(physical_offset=offset,bytes=length,sha256=sha(raw),reason=reason))
            return raw
    class Labels(h['ActualLabels']):
        def __init__(self,image):
            super().__init__(image);self.cache=OrderedDict();self.hits=0;self.misses=0;self.evictions=0;self.peak=0
        def get(self,ref):
            if ref is None:return None
            existed=ref in self.cache
            result=super().get(ref)
            if existed:self.hits+=1
            else:self.misses+=1
            self.cache.move_to_end(ref)
            while len(self.cache)>MAX_LABELS:self.cache.popitem(last=False);self.evictions+=1
            self.peak=max(self.peak,len(self.cache));return result
    classifications=Counter();held=Counter();matched_stats=Counter();city_stats=defaultdict(Counter)
    held_examples=defaultdict(list);path_summaries={};parent_counts=Counter();rows=0
    path_runs=[];parent_runs=[];local_run_readbacks=[]
    (OUT/'sorted-summary-runs').mkdir()
    def spill_paths():
        if not path_summaries:return
        ledger=Ledger(OUT/'sorted-summary-runs'/('paths-%05d.jsonl.gz'%len(path_runs)))
        for k,s in sorted(path_summaries.items()):ledger.write(s)
        path_runs.append(ledger.close());path_summaries.clear()
    def spill_parents():
        if not parent_counts:return
        ledger=Ledger(OUT/'sorted-summary-runs'/('parents-%05d.jsonl.gz'%len(parent_runs)))
        for ID,count in sorted(parent_counts.items()):ledger.write(dict(actual_parent_record=ID,matched_source_groups=count))
        parent_runs.append(ledger.close());parent_counts.clear()
    key_before=stat(KEYS);plain_hash=hashlib.sha256();plain_bytes=0
    with AP.open('rb') as map_handle,KEYS.open('rb') as source:
        image=Image(map_handle);tables,descriptor=reader['derive_tables'](image)
        need(all(a['start']+a['bytes']==b['start'] for a,b in zip(reversed(tables),list(reversed(tables))[1:])),
             'Actual physical6→5→4→3→2→1 boundaries')
        need(tables[0]['start']+tables[0]['bytes']==descriptor['u32_LE'][0] and
             descriptor['u32_LE'][0]+120==image.components['00004171.MDR']['bytes'],'Actual directory/EOF')
        labels=Labels(image);engine=Engine(image,tables,labels,reader,h);hashed=HashReader(source)
        with gzip.GzipFile(fileobj=hashed,mode='rb') as stream:
            for line in stream:
                plain_hash.update(line);plain_bytes+=len(line);row=json.loads(line);rows+=1
                need('source_ids' not in row and 'coordinate_strings' not in row,'Keys input has no IDs/coordinates')
                city,district,street,house=row['normalized_planning_key'];classification=row['native_match']
                need(row['house_label']==house and type(row['group_id']) is int,'Exact source group-key shape')
                classifications[classification]+=1;city_stats[city]['source_groups']+=1
                reason=None;path=None;tokens=None
                if classification!='missing_native_street':reason='source_classification_'+classification
                elif city in DIRECT_CITIES:reason='direct_city_source_district_unverified'
                else:
                    native=prefix_index.get((city,district))
                    if not native:reason='no_exact_native_city_district_roster'
                    else:
                        best=None
                        for end in range(1,len(street)+1):
                            if street[:end] in native:best=street[:end]
                        if best is None:reason='no_exact_native_street_prefix'
                        elif len(native[best])!=1:reason='duplicate_longest_native_street_prefix'
                        else:
                            tokens=h['suffix_tokens'](street[len(best):])
                            if tokens is None:reason='longest_exact_prefix_suffix_not_supported_numeric_lane_alley_tokens'
                            else:
                                pathkey=(city,district,street);path=engine.path(pathkey,native[best][0],tokens);reason=path['reason']
                if reason is not None:
                    held[reason]+=1;city_stats[city]['held_groups']+=1
                    if len(held_examples[reason])<8:
                        held_examples[reason].append(dict(source_key=row,reason=reason,
                            exact_path_records=path.get('records',[]) if path else [],
                            decode_guard=path.get('guard') if path else None))
                else:
                    parent=path['target'];group=engine.group(parent,True)
                    need(group['guard'] is None,'A validated cached parent became an undecodable group')
                    matches=group['leaf_labels'].get(house,[])
                    status='absent' if not matches else 'present_unique' if len(matches)==1 else 'duplicate_exact_leaf_labels'
                    matched_stats['groups']+=1;matched_stats['house_'+status]+=1
                    matched_stats['next'+str(parent['next_level'])+'_groups']+=1
                    matched_stats['coordinate_'+row['coordinate_status']]+=1
                    matched_stats['source_label_'+row['label_status']]+=1
                    city_stats[city]['matched_groups']+=1
                    if parent['native_record'] not in parent_counts and len(parent_counts)>=SUMMARY_BATCH_PATHS:spill_parents()
                    parent_counts[parent['native_record']]+=1
                    pathkey=(city,district,street)
                    if pathkey not in path_summaries:
                        if len(path_summaries)>=SUMMARY_BATCH_PATHS:spill_paths()
                        path_summaries[pathkey]=dict(city=city,district=district,source_full_street=street,
                            exact_tokens=tokens,root_street_record=path['records'][0]['native_record'],
                            exact_actual_path_records=path['records'],actual_parent=parent,
                            numeric_house_leaf_count=path['numeric_house_count'],other_direct_child_count=path['other_direct_child_count'],
                            final_group_packed_span_sha256=path['final_group_sha256'],groups=0,
                            house_membership_group_counts=Counter(),coordinate_group_counts=Counter(),source_label_group_counts=Counter())
                    summary=path_summaries[pathkey];summary['groups']+=1
                    summary['house_membership_group_counts'][status]+=1
                    summary['coordinate_group_counts'][row['coordinate_status']]+=1
                    summary['source_label_group_counts'][row['label_status']]+=1
                    output.write(dict(**row,matching_status='matched_existing_lane_house_parent',
                        native_root_street_record=path['records'][0]['native_record'],exact_path_tokens=tokens,
                        actual_path_record_ids=[r['native_record'] for r in path['records']],
                        actual_parent_record=parent['native_record'],actual_parent_level=parent['level'],
                        actual_parent_ID=parent['one_based_ID'],actual_parent_label=parent['primary_label'],
                        actual_parent_raw_flags=parent['child_level_and_flags'],actual_parent_high_flags=parent['child_level_and_flags']&~7,
                        next_leaf_level=parent['next_level'],old_first_child=parent['first_child'],old_child_count=parent['child_count'],
                        source_house_exact_membership=status,actual_matching_house_records=
                            [{'record':ID,'primary_ref':ref} for ID,ref in matches],
                        source_global_ref_is_membership_proof=False,coordinate_values_available=False,
                        complete_source_IDs_available=False,matching_planning_only=True,native_rewrite_ready=False))
                if rows%100000==0:
                    rss=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss;need(rss<=MAX_RSS_KIB,'Actual RSS ceiling500MiB')
                    receipt=dict(rows=rows,matched_groups=matched_stats['groups'],held_groups=sum(held.values()),
                        actual_original_read_bytes=image.read_bytes,actual_original_read_operations=image.read_count,
                        max_RSS_KiB=rss,elapsed_seconds=time.monotonic()-t0,utc=datetime.now(timezone.utc).isoformat())
                    progress.write(receipt);print(json.dumps(receipt),flush=True)
        need(rows==artifact['rows'] and hashed.count==artifact['bytes'] and hashed.hash.hexdigest()==artifact['sha256']
             and plain_hash.hexdigest()==artifact['uncompressed_sha256'],'One-pass source EOF/plain/compressed hashes')
        need(sum(held.values())+matched_stats['groups']==rows,'All source keys accounted')
        read_receipt=dict(path=str(KEYS.relative_to(ROOT)),rows=rows,bytes=hashed.count,sha256=hashed.hash.hexdigest(),
            uncompressed_sha256=plain_hash.hexdigest(),uncompressed_bytes=plain_bytes,gzip_validated_EOF=True,
            full_content_passes=1,stat_before=key_before,stat_after=stat(KEYS),stat_unchanged=key_before==stat(KEYS))
        cache_receipt=engine.receipt();cache_receipt['label_cache']=dict(limit=MAX_LABELS,peak_entries=labels.peak,
            hits=labels.hits,misses=labels.misses,evictions=labels.evictions)
        lbl_descriptor=labels.descriptor;actual_reads=image.read_bytes;actual_operations=image.read_count
    need(stat(AP)==before and stat(KEYS)==key_before,'Original AP/source stat unchanged')
    match_artifact=output.close();read_artifact=readlog.close();progress_artifact=progress.close()
    spill_paths();spill_parents()
    summaries=Ledger(OUT/'unique-parent-paths.jsonl.gz')
    parent_flags=Counter();parent_levels=Counter();summary_groups=0
    for s in merged_runs(path_runs,lambda r:(r['city'],r['district'],r['source_full_street']),combine_paths,local_run_readbacks):
        summaries.write(s);parent_flags[s['actual_parent']['child_level_and_flags']]+=1
        parent_levels[s['actual_parent']['level']]+=1;summary_groups+=s['groups']
    summary_artifact=summaries.close()
    parent_artifact=Ledger(OUT/'unique-actual-parent-group-counts.jsonl.gz')
    parent_groups=0
    for s in merged_runs(parent_runs,lambda r:r['actual_parent_record'],combine_parents,local_run_readbacks):
        parent_artifact.write(s);parent_groups+=s['matched_source_groups']
    parent_artifact=parent_artifact.close()
    need(summary_groups==parent_groups==matched_stats['groups'],'Spilled path/actual-parent aggregates preserve all matched groups')
    rss=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss;need(rss<=MAX_RSS_KIB,'Actual RSS ceiling500MiB')
    proof=dict(schema='country-existing-lane-path-matching/v1',started_utc=started,finished_utc=datetime.now(timezone.utc).isoformat(),
        all_assigned_checks_passed=True,script_sha256=sha(Path(__file__).read_bytes()),inputs=inputs,
        one_pass_unresolved_input=read_receipt,source_classification_counts=dict(classifications),held_reason_group_counts=dict(held),
        held_examples=dict(held_examples),matched_group_counts=dict(matched_stats),city_group_counts={k:dict(v) for k,v in city_stats.items()},
        unique_resolved_source_city_district_fullstreet_paths=summary_artifact['rows'],unique_actual_house_parent_records=parent_artifact['rows'],
        unique_parent_rawflag_counts=dict(parent_flags),unique_parent_levels=dict(parent_levels),
        artifacts=dict(matched_groupkeys=match_artifact,unique_parent_paths=summary_artifact,unique_actual_parent_groups=parent_artifact,
            original_map_read_log=read_artifact,progress_receipts=progress_artifact,sorted_summary_runs=path_runs+parent_runs),
        sorted_summary_run_EOF_readbacks=local_run_readbacks,summary_distinct_key_batch_limit=SUMMARY_BATCH_PATHS,
        original_AP=dict(path=str(AP.relative_to(ROOT)),stat_before=before,stat_after=stat(AP),stat_unchanged=True,
            full_SHA_reference_from_backup='864d128f8d4660570d443b2e14772c9c5356ebdf0bbb6a5891f3318b836053c2',
            fresh_full_image_hash=False,actual_bounded_read_bytes=actual_reads,actual_read_operations=actual_operations,
            explicit_read_budget_bytes=MAX_IMAGE_BYTES),original_directory=descriptor,original_tables=tables,actual_GMP_LBL_descriptor=lbl_descriptor,
        cache_and_decode_receipts=cache_receipt,max_RSS_KiB=rss,explicit_max_RSS_KiB=MAX_RSS_KIB,
        elapsed_seconds=time.monotonic()-t0,
        matching_policy='Only missing_native_street, exact city/district, longest exact native normalized street prefix, positive numeric巷/弄 suffix tokens, exact actual child primary labels. No alias, fuzzy, guessed字形, stripped route annotation or flattened L3 substitute.',
        preserved_flags_policy='Original full raw flags retained; nextlevel is raw&7. Raw13 without observed direct numeric houses held. Unknown branch guards remain held, never converted.',
        JAI_constraint='Actual unique parent_record must be grouped once. This tool neither creates nor modifies JAI families.',
        inherited_small_proof_reuse='Sealed 20-example source methods and passed proof referenced; old main/controls/map cases/CPU not rerun.',
        source_coordinate_values_or_complete_source_IDs_available=False,source_full_group_ledger_reopened=False,
        source_ready_ledgers_reopened=False,PBF_accessed=False,native_CPU_executed=False,new_native_records_encoded=False,
        IMG_MDR_JAI_DB_modified=False,device_IO=False,canonical_or_ZIP_modified=False,full_Taiwan_native_update_complete=False,
        limits=['Matching plans only. Later exact group-ID join must recover original source IDs/coordinates and independently check eligibility before any writer use.',
            'Only exact existing numeric lane/alley paths. New streets/admins, direct-city districts, unsupported names/branches and unknown flag semantics remain held.',
            'Existing global numeric text ref is not stock parent membership proof; actual leaf membership is separately observed, with duplicates retained.',
            'Coordinate readiness/label status are inherited metadata only. No entrances, navigation query, route or physical acceptance established.',
            'Counts concern this sealed unresolved input and exact resolver; no claim of complete street/address coverage or Taiwan2026 native update.'])
    (OUT/'proof.json').write_text(json.dumps(proof,ensure_ascii=False,indent=2)+'\n')
    receipt=dict(exit_status=0,started_utc=started,finished_utc=proof['finished_utc'],elapsed_seconds=proof['elapsed_seconds'],
        script_sha256=proof['script_sha256'],proof_sha256=sha((OUT/'proof.json').read_bytes()),input_rows=rows,
        matched_groups=matched_stats['groups'],held_groups=sum(held.values()),max_RSS_KiB=rss,
        actual_original_read_bytes=actual_reads,input_full_content_passes=1,source_stats_unchanged=True)
    (OUT/'execution-receipt.json').write_text(json.dumps(receipt,indent=2)+'\n');print(json.dumps(receipt),flush=True)

if __name__=='__main__':
    try:main()
    except Exception as exc:
        (OUT/'unfinalized-failure.json').write_text(json.dumps(dict(exception=repr(exc),script_sha256=sha(Path(__file__).read_bytes()),
            created_utc=datetime.now(timezone.utc).isoformat(),terminal_proof_written=(OUT/'proof.json').exists()),indent=2)+'\n')
        raise
