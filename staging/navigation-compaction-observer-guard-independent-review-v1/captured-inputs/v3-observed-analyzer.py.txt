#!/usr/bin/env python3
"""Fresh ordinary data scope with durable phase/RSS/read observations.

Uses only the closed allocation mapper and RAM algorithms, never their mains.
The Linux ru_maxrss cap stays384MiB and the actual IMG cap stays160000000B.
"""
from pathlib import Path
from datetime import datetime,timezone
from collections import Counter
from array import array
import ast
import hashlib
import json
import os
import resource
import struct
import sys
import time

ROOT=Path('/root/garmin'); HERE=Path(__file__).resolve().parent
RSS_CAP_KIB=384*1024; IMG_CAP=160000000; SUMMARY_CAP=1<<20; RANGE_CAP=2000000
COUNTS={3:47870,4:4896236,5:3077845,6:2062771}
STOCK={4:2133948,5:2341096,6:1973316}
CANDIDATE='staging/navigation-country-native-lane-candidate-v3/gmapprom1.img'
CANDIDATE_SHA='1f468eb78cc1268951873c82ffce4abe3292dcece69c0eee405c5d7aca3cc360'
ALGORITHM='staging/navigation-v3-reachable-suffix-compaction-feasibility-v1/analyze_reachable.py'
ALGORITHM_SHA='a1a7a9c94df6a8b715eca28366a9c94ed8895d6e0176fd05a4f076d506beb274'
MAPPER='staging/navigation-minimal-lane-render-isolation-plan-v1/prepare_control.py'
MAPPER_SHA='a20877fce09cbfe36f1f5621144f2ade44a031c26e4c6d330d07b2a1b86c4095'
STATE={'phase':'not started','IMG_bytes_read':0,'IMG_read_ops':0,'MDR_stream_started':False,
       'source_handle_open':False,'source_handle_closed':True,'inputs':[],'outcome':'running'}


def need(value,message):
    if not value: raise ValueError(message)


def sha(raw):return hashlib.sha256(raw).hexdigest()


def stat(path):
    s=path.stat()
    return dict(dev=s.st_dev,ino=s.st_ino,bytes=s.st_size,mtime_ns=s.st_mtime_ns,
                ctime_ns=s.st_ctime_ns,nlink=s.st_nlink,mode=oct(s.st_mode&0o777))


def save(name,obj):
    raw=json.dumps(obj,ensure_ascii=False,indent=2).encode()+b'\n'
    need(len(raw)<=SUMMARY_CAP,'Bounded summary artifact')
    with (HERE/name).open('xb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
    return dict(path=str((HERE/name).relative_to(ROOT)),bytes=len(raw),sha256=sha(raw))


class OwnBudgetError(ValueError):
    pass


class Observer:
    def __init__(self):
        self.p=HERE/'actual-phase-observations.jsonl';self.f=self.p.open('xb')
        self.rows=0;self.bytes=0;self.h=hashlib.sha256();self.last=None;self.max_observed={}
    def snapshot(self,phase,detail=None,enforce=True):
        ru=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        proc={}
        with open('/proc/self/status','r') as f:
            for line in f:
                key,_,value=line.partition(':')
                if key in {'VmRSS','VmHWM','VmSize','VmPeak'}:
                    parts=value.split();need(len(parts)==2 and parts[1]=='kB','Linux proc RSS unit kB')
                    proc[key+'_KiB']=int(parts[0])
        row=dict(ordinal=self.rows,utc=datetime.now(timezone.utc).isoformat(),phase=phase,
                 ru_maxrss_KiB=ru,proc_status=proc,RSS_cap_KiB=RSS_CAP_KIB,
                 ru_maxrss_is_historical_peak=True,IMG_bytes_read=STATE['IMG_bytes_read'],
                 IMG_read_ops=STATE['IMG_read_ops'],MDR_stream_started=STATE['MDR_stream_started'],
                 source_handle_open=STATE['source_handle_open'],fixed_counts=COUNTS,detail=detail)
        raw=json.dumps(row,ensure_ascii=False,separators=(',',':'),sort_keys=True).encode()+b'\n'
        need(self.bytes+len(raw)<=500000,'Phase observation ledger bounded500KB')
        self.f.write(raw);self.f.flush();os.fsync(self.f.fileno())
        self.h.update(raw);self.bytes+=len(raw);self.rows+=1;self.last=row;STATE['phase']=phase
        for key,val in {'ru_maxrss_KiB':ru,**proc}.items():self.max_observed[key]=max(self.max_observed.get(key,0),val)
        if enforce and ru>RSS_CAP_KIB:
            STATE['own_RSS_guard_value_KiB']=ru;STATE['own_RSS_guard_threshold_KiB']=RSS_CAP_KIB
            raise OwnBudgetError('Own Python ru_maxrss budget exceeded: '+str(ru)+' KiB > '+str(RSS_CAP_KIB)+' KiB')
        return ru
    def close(self):
        self.f.flush();os.fsync(self.f.fileno());self.f.close()
        return dict(path=str(self.p.relative_to(ROOT)),rows=self.rows,bytes=self.bytes,sha256=self.h.hexdigest(),
                    actual_max_observed=self.max_observed,last_observation=self.last)


OBS=None


def rss():
    return OBS.snapshot('guard:'+sys._getframe(1).f_code.co_name)


def load_bytes(path,pin,maximum=200000):
    OBS.snapshot('input before read/parse',dict(path=path))
    p=ROOT/path;before=stat(p);need(before['bytes']<=maximum,'Small sealed input maximum')
    with p.open('rb') as f:raw=f.read(maximum+1);need(f.read(1)==b'','Small input EOF')
    need(sha(raw)==pin and stat(p)==before,'Small source SHA/stat pin')
    STATE['inputs'].append(dict(path=path,bytes=len(raw),sha256=pin,stat_before=before,stat_after=stat(p)))
    OBS.snapshot('input bytes pin checked before parse',dict(path=path,bytes=len(raw)))
    return raw


def load(path,pin):
    raw=load_bytes(path,pin);obj=json.loads(raw)
    OBS.snapshot('input JSON parsed',dict(path=path))
    return obj


class ReadBudget:
    def __init__(self):
        self.bytes=0;self.ops=0;self.h=hashlib.sha256();self.first=[];self.last=[];self.by_purpose=Counter()
    def read(self,image,at,size,purpose):
        need(0<=at<=at+size<=image.size and self.bytes+size<=IMG_CAP,'Hard actual IMG160000000B cap')
        image.f.seek(at);raw=image.f.read(size);need(len(raw)==size,'Complete actual read')
        row=dict(ordinal=self.ops,physical_offset=at,bytes=size,sha256=sha(raw),purpose=purpose)
        self.h.update(json.dumps(row,separators=(',',':'),sort_keys=True).encode()+b'\n')
        self.bytes+=size;self.ops+=1;STATE['IMG_bytes_read']=self.bytes;STATE['IMG_read_ops']=self.ops
        if len(self.first)<8:self.first.append(row)
        self.last.append(row)
        if len(self.last)>8:self.last.pop(0)
        self.by_purpose[purpose.split(';')[0]]+=size
        return raw
    def summary(self):
        return dict(actual_IMG_bytes_read=self.bytes,actual_IMG_read_ops=self.ops,read_cap_bytes=IMG_CAP,
            rolling_all_physical_read_receipts_sha256=self.h.hexdigest(),first_bounded_reads=self.first,
            last_bounded_reads=self.last,bytes_by_purpose=dict(self.by_purpose),
            whole_IMG_hash_recomputed=False,full_tables_or_full_physical_ledger_not_saved=True)


def allocate_fields(count):
    fields={}
    for key,typecode in [('first','I'),('count','H'),('flags','H')]:
        detail=dict(record_count=count,typecode=typecode,field=key,elements=count+1,
                    planned_payload_bytes=(count+1)*array(typecode).itemsize)
        OBS.snapshot('array before allocation',detail)
        fields[key]=array(typecode,[0])*(count+1)
        OBS.snapshot('array allocated',dict(detail,actual_payload_bytes=len(fields[key])*fields[key].itemsize))
    return fields


class ObserveAllocations(ast.NodeTransformer):
    """Only add durable observations around the RAM algorithm's allocations."""
    def visit_Assign(self,node):
        self.generic_visit(node)
        targets=[t.id for t in node.targets if isinstance(t,ast.Name)]
        observed={'keep','ranges','ranks','values'}&set(targets)
        if not observed:return node
        label='RAM '+','.join(sorted(observed))
        def point(s):return ast.Expr(value=ast.Call(func=ast.Attribute(value=ast.Name(id='OBS',ctx=ast.Load()),
            attr='snapshot',ctx=ast.Load()),args=[ast.Constant(s)],keywords=[]))
        return [ast.copy_location(point(label+' before allocation'),node),node,
                ast.copy_location(point(label+' after allocation'),node)]


def main():
    global OBS
    need(not(HERE/'proof.json').exists(),'Fresh observed namespace')
    OBS=Observer();STATE['started_utc']=datetime.now(timezone.utc).isoformat()
    OBS.snapshot('initial before any input parse or field array allocation',dict(host_platform=sys.platform,
        fixed_field_array_bytes=sum((n+1)*8 for n in COUNTS.values() if n!=COUNTS[6]),
        original_attempt_not_replayed=True,RSS_cap_unchanged=True))
    need(sys.platform=='linux' and array('I').itemsize==4 and array('H').itemsize==2 and array('Q').itemsize==8,'Linux/fixed array ABI')
    oldseal=load('staging/navigation-v3-reachable-suffix-compaction-feasibility-v1/sealed-files.json',
        '2dd746f8a1286cecd31b68c79726a5009a2536a9eb757a4863be4b359caee442')
    need(oldseal['actual_attempt_exit_code']==1 and oldseal['original_source_and_failure_preserved'],'Old failed evidence remains closed')
    oldraw=load_bytes(ALGORITHM,ALGORITHM_SHA)
    OBS.snapshot('algorithm AST before parse')
    oldtree=ast.parse(oldraw.decode())
    OBS.snapshot('algorithm AST parsed')
    selected={'stream_actual','prefix_mask','fill_all','mark','contains','make_rank','mapped_ID','analyze'}
    functions=[n for n in oldtree.body if isinstance(n,ast.FunctionDef) and n.name in selected]
    need(len(functions)==len(selected),'Only bounded ordinary data helpers, no historical main')
    original_AST={n.name:sha(ast.dump(n,include_attributes=False).encode()) for n in functions}
    transformed=ObserveAllocations().visit(ast.Module(body=functions,type_ignores=[]));ast.fix_missing_locations(transformed)
    env=dict(need=need,hashlib=hashlib,json=json,struct=struct,Counter=Counter,array=array,rss=rss,
        allocate_fields=allocate_fields,RANGE_CAP=RANGE_CAP,KNOWN_RAW_FLAGS={0,4,5,6,8,12,13,14},OBS=OBS)
    exec(compile(transformed,ALGORITHM,'exec'),env)
    del oldtree,oldraw,functions,transformed
    OBS.snapshot('ordinary RAM functions compiled without historical main')
    mapperraw=load_bytes(MAPPER,MAPPER_SHA)
    OBS.snapshot('mapper AST before parse')
    mt=ast.parse(mapperraw.decode());image_node=next(n for n in mt.body if isinstance(n,ast.ClassDef) and n.name=='Image')
    names=next(n for n in mt.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='NAMES' for t in n.targets))
    mapper_AST=sha(ast.dump(image_node,include_attributes=False).encode())
    mapperenv=dict(need=need,struct=struct)
    exec(compile(ast.Module(body=[names,image_node],type_ignores=[]),MAPPER,'exec'),mapperenv)
    del mt,image_node,names,mapperraw
    OBS.snapshot('mapper-only compiled without old main')
    original=load('staging/navigation-country-native-house-merge-v1/proof.json',
        'bfc55b01f1f567cbad495ba3e35301d358cf54d1fdddea9fe1b8a9e6c8412a41')
    need({int(k):v for k,v in original['original_counts'].items()}==STOCK,'Sealed stock counts')
    del original
    facts=load('staging/navigation-native-L3-width-policy-static-v1/candidate-layout-and-CPU-facts.json',
        '3305e1aa1019c1920fee5e8993936d21aa0fe0ebb79d745a624ae900978868e9')
    base=load('staging/navigation-country-native-lane-candidate-v3/proof.json',
        'b5baf538981a60aceb2b8cbb2c31ce3e8159363a719909791e31ef0ca0cb58d0')
    sealed=load('staging/navigation-country-native-lane-candidate-v3/sealed-files.json',
        'dfc47744887137f944d710dffeb5ea6f6821c24eb8abbeb522cb406576754335')
    producer=load('staging/navigation-native-lane-tree-cow-append-v1/proof.json',
        '1cde367d1d3aba44290b7f44be40c9cb5d04bf911a3e8bd3898e071a1329b4e9')
    need(base['all_assigned_checks_passed'] and sealed['all_assigned_checks_passed'] and producer['all_assigned_checks_passed'],
        'Closed producer and actual composition gates')
    need(all(r['all_significant_bits_identical'] for r in base['lower_prefix_significant_bit_checks'])
        and all(r['matches_sealed_producer_stream'] for r in base['actual_append_extraction_checks'])
        and producer['all_old_relative_order_preserved']
        and producer['lower_original_fields_except_explicit_first_count_patches_preserved'],'Inherited v2/COW preservation')
    profile=facts['profiles']['lane_v3'];tables={r['level']:dict(r,stride=r['stride_bits']) for r in profile['tables']}
    need({i:tables[i]['count'] for i in COUNTS}==COUNTS and tables[3]['widths'][0]==23
        and tables[3]['stride']==112 and [tables[i]['stride'] for i in (4,5,6)]==[128,126,68],'Actual current profile')
    v2_prefix={r['level']:r['count'] for r in facts['profiles']['country_v2']['tables'] if r['level'] in (4,5,6)}
    component=next(r for r in base['complete_actual_component_checks'] if r['name']=='00004171.MDR')
    stream_pin=dict(actual_DIR_hex=profile['directory_source']['hex'],actual_MDR_SHA=component['sha256'])
    oldleaf_preservation=dict(counts=producer['prior_v2_new_leaf_identity_counts'],
        source_digest=producer['prior_v2_source_content_identity_digest'],old_relative_order_preserved=True,
        actual_streams_not_reopened=True)
    source_row=next(r for r in sealed['files'] if r['path']==CANDIDATE)
    before=stat(ROOT/CANDIDATE)
    need(source_row['sha256']==CANDIDATE_SHA and [before[k] for k in ('dev','ino','bytes','mtime_ns')]
        ==source_row['stat_at_seal'][:4] and before['mode']=='0o444','Frozen source content/stat binding')
    STATE['source_stat_before']=before
    expected_sizes={r['name']:r['bytes'] for r in base['complete_actual_component_checks']}
    del facts,base,sealed,producer,profile,component,source_row
    OBS.snapshot('small inputs retained only as lean tables/pins')
    budget=ReadBudget();STATE['budget']=budget
    OBS.snapshot('before source rb open and mapper',dict(exact_IMG_budget=budget.bytes))
    try:
        with (ROOT/CANDIDATE).open('rb') as f:
            STATE['source_handle_open']=True;STATE['source_handle_closed']=False
            image=mapperenv['Image']('v3',f,dict(bytes=153346048,block_bytes=8192),budget)
            need({k:v['size'] for k,v in image.components.items()}==expected_sizes,'Actual six component FAT sizes')
            OBS.snapshot('actual mapper complete',dict(actual_IMG_bytes_read=budget.bytes,metadata_end=image.directory_end))
            STATE['MDR_stream_started']=True
            fields,stream=env['stream_actual'](image,tables,stream_pin)
            container=dict(MDR_bytes=149220356,component_sizes={k:v['size'] for k,v in image.components.items()},
                current_block_bytes=8192,current_metadata_end=image.directory_end)
            need(stat(ROOT/CANDIDATE)==before,'Source stat/nlink stable through data pass')
    finally:
        STATE['source_handle_open']=False;STATE['source_handle_closed']=True
    OBS.snapshot('MDR single stream done and source closed',dict(streamed_bytes=stream['streamed_bytes']))
    stream_receipt=save('actual-stream-read-receipts.json',dict(schema='garmin-observed-single-MDR-data-stream-receipt/v2',
        read_budget=budget.summary(),stream=stream,source_stat_before=before,source_stat_after=stat(ROOT/CANDIDATE),
        actual_input_handle_closed=True,actual_source_whole_IMG_SHA_not_repeated=True))
    stock_result=env['analyze']('retain_all_stock_lower_prefixes_plus_all_L3_active_tree',STOCK,fields,tables,container)
    OBS.snapshot('stockprefix RAM feasibility completed')
    v2_result=env['analyze']('retain_all_current_v2_lower_prefixes_plus_all_L3_active_tree',v2_prefix,fields,tables,container)
    OBS.snapshot('v2prefix RAM feasibility completed')
    need(stat(ROOT/CANDIDATE)==before,'Source stat/nlink still immutable')
    results=save('feasibility-summary.json',dict(schema='garmin-v3-reachable-suffix-observed-feasibility/v2',
        stock_prefix_plus_active=stock_result,current_v2_prefix_plus_active=v2_result,
        current_v2_leaf_preservation_inherited=oldleaf_preservation,
        all47870_L3_IDs_and_JAI_keys_preserved=True,all_stock_lower_prefix_IDs_preserved=True,
        external_lower_record_reference_ABIs_proven_absent=False,
        actual_native_UI_renderer_or_physical_installation_verified=False))
    STATE['outcome']='completed data feasibility';STATE['finished_utc']=datetime.now(timezone.utc).isoformat()
    OBS.snapshot('all assigned normal data calculations completed')
    observation=OBS.close();STATE['observer_closed']=True
    proof=save('proof.json',dict(schema='garmin-v3-observed-reachability-proof/v2',
        all_assigned_data_feasibility_checks_completed=True,old_failed_scope_unmodified=True,
        own_budget_exception_or_platform_interruption=False,start_utc=STATE['started_utc'],finished_utc=STATE['finished_utc'],
        source_inputs=STATE['inputs'],reused_original_RAM_helper_AST_sha256=original_AST,mapper_AST_sha256=mapper_AST,
        measurement_changes='Durable phase/RSS/read receipts and per-array allocation observations; unchanged384MiB ru_maxrss cap',
        original_RAM_allocation_observation_insertions_only=True,original_historical_main_not_executed=True,
        actual_RSS_measurement=dict(cap_KiB=RSS_CAP_KIB,unit='Linux KiB',method='resource.getrusage(RUSAGE_SELF).ru_maxrss',
            historical_peak=True,proc_current_RSS_and_HWM_observed=True,actual_max_observed=observation['actual_max_observed']),
        actual_IMG_read_bytes=budget.bytes,actual_IMG_read_cap=IMG_CAP,one_actual_MDR_stream_bytes=stream['streamed_bytes'],
        actual_MDR_hash_matches_sealed_complete_readback=True,whole_IMG_hash_not_repeated=True,
        source_candidate=dict(path=CANDIDATE,bytes=153346048,inherited_whole_sha256=CANDIDATE_SHA,
            stat_before=before,stat_after=stat(ROOT/CANDIDATE),handle_closed=True),
        actual_original_stock_counts=STOCK,actual_current_profile=dict(L3_first_width=23,L3_stride=112,L3_count=47870,
            lower_strides=[128,126,68]),artifacts=dict(observations=observation,read_receipts=stream_receipt,summary=results),
        stock_plan_fits_4K_arithmetic=stock_result['arithmetic']['fits_4K_capacity_arithmetic'],
        whole_v2prefix_plan_fits_4K_arithmetic=v2_result['arithmetic']['fits_4K_capacity_arithmetic'],
        external_lowerrefs_absence_or_live_query_preservation_proved=False,
        native_install_fix_or_renderer_acceptance_ready=False,
        MAIN_CPU_guest_PBF_bigsourceledger_audio_or_device_IO=0,source_IMG_or_seals_report_canonical_modified=False,
        new_IMG_or_fulltables_or_remapped_records_created=False,all_own_and_source_handles_closed=True))
    need(sum(p.stat().st_size for p in HERE.iterdir() if p.is_file())<SUMMARY_CAP,'All outputs/source under1MiB')
    print(json.dumps(dict(all_assigned_data_feasibility_checks_completed=True,proof=proof,
        actual_IMG_bytes_read=budget.bytes,max_observed=observation['actual_max_observed'],
        stock_plan=stock_result['arithmetic'],stock_unknowns=stock_result['invalid_or_unclassified_child_encoding_counts'],
        source_handle_closed=True),ensure_ascii=False),flush=True)


if __name__=='__main__':
    try:
        main()
    except Exception as exc:
        STATE['outcome']='own budget exception' if isinstance(exc,OwnBudgetError) else 'ordinary program exception'
        STATE['finished_utc']=datetime.now(timezone.utc).isoformat()
        budget=STATE.get('budget')
        if OBS is not None and not STATE.get('observer_closed'):
            try:OBS.snapshot('exception durable final snapshot',dict(type=type(exc).__name__,error=str(exc)),enforce=False)
            finally:observation=OBS.close();STATE['observer_closed']=True
        else:observation=None
        row=dict(schema='garmin-observed-data-failure-receipt/v2',exception_type=type(exc).__name__,error=str(exc),
            classification=STATE['outcome'],tool_platform_or_automatic_review_interruption=False,
            actual_phase=STATE['phase'],actual_IMG_bytes_read=STATE['IMG_bytes_read'],actual_IMG_read_ops=STATE['IMG_read_ops'],
            actual_read_budget=budget.summary() if budget else None,actual_RSS_guard_value_KiB=STATE.get('own_RSS_guard_value_KiB'),
            actual_RSS_guard_threshold_KiB=RSS_CAP_KIB,cap_not_raised_or_removed=True,observations=observation,
            source_handle_closed=STATE['source_handle_closed'],source_stat_before=STATE.get('source_stat_before'),
            source_stat_after=stat(ROOT/CANDIDATE),source_inputs=STATE['inputs'],
            retry_or_guard_relaxation=False,source_IMG_or_device_or_shared_seal_modified=False,
            MDR_table_scan_completed=(HERE/'actual-stream-read-receipts.json').exists(),
            actual_MDR_stream_started=STATE['MDR_stream_started'],new_IMG_or_guest_or_audio_executed=False)
        result=save('actual-failure.json',row)
        print(json.dumps(dict(actual_program_failure=result,actual_phase=row['actual_phase'],
            guard_value_KiB=row['actual_RSS_guard_value_KiB'],actual_IMG_bytes_read=row['actual_IMG_bytes_read'],
            source_handle_closed=row['source_handle_closed']),ensure_ascii=False),flush=True)
        raise
