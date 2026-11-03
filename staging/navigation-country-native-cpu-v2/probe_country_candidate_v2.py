#!/usr/bin/env python3
"""NEW finite actual-v2 CPU scope; only frozen function providers are reused."""
from datetime import datetime,timezone
import argparse
import gc
import hashlib
import importlib.util
import json
from pathlib import Path
import resource
import struct
import sys
import time

sys.dont_write_bytecode=True
ROOT=Path('/root/garmin');HERE=Path(__file__).resolve().parent
V1='staging/navigation-country-native-cpu-v1/probe_country_candidate.py'
V1_SHA='312d8dc58e2c2cf7e6c6ab1b295e5befece64929dc8e56625561220d1c2f22ff'


def need(ok,message):
    if not ok:raise ValueError(message)


def sha(raw):return hashlib.sha256(raw).hexdigest()


def identity(path):
    s=path.stat();return [s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]


def load(relative,digest,name,dependencies):
    path=ROOT/relative;before=identity(path);raw=path.read_bytes()
    need(sha(raw)==digest and identity(path)==before,'Pinned reusable source '+relative)
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);sys.modules[name]=module;spec.loader.exec_module(module)
    dependencies.append({'path':relative,'bytes':len(raw),'sha256':digest,
                         'historical_main_cases_or_producer_selection_executed':False})
    return module


def main():
    parser_args=argparse.ArgumentParser();parser_args.add_argument('--selection-sha256',required=True)
    args=parser_args.parse_args()
    need(not(HERE/'proof.json').exists(),'New terminal CPU proof only')
    start=datetime.now(timezone.utc).isoformat();t0=time.monotonic();dependencies=[]
    path=HERE/'finite-selection.json';selection_before=identity(path);raw=path.read_bytes()
    need(sha(raw)==args.selection_sha256,'Explicit finite selection binding')
    selection=json.loads(raw)
    need(selection['CPU_executed_during_selection'] is False and
         selection['complete_kept_new_records_count']==130637 and selection['complete_selected_street_ranges_count']==18823,
         'Only finalized actual builder dataset may be executed')
    for receipt in selection['prepared_producer_input_receipts']:
        need(identity(ROOT/receipt['path'])==receipt['stat_after']==receipt['stat_before'],'Prepared final input immutable before CPU')
    v1=load(V1,V1_SHA,'frozen_v1_native_prefix_function_only',dependencies)
    reused=load('staging/navigation-taichung-native-cpu-v1/probe_actual_candidate_native_v1.py',
        'bb7882322906bd38877debf79921d1ad1ca68e94401bf849d4eb93d39053fc54','frozen_v2_directory_projection_only',dependencies)
    old=load('staging/navigation-native-address-supplement-native-v1/probe_candidate_native_v1.py',
        '2a59e48ee4b9fd435084672368f9a87a796299d13c32bf7f70c055ce9fc0eaaa','frozen_v2_machine_FAT_only',dependencies)
    parser_method=load('staging/navigation-native-MDR-provider-fields-v1/probe_native_mdr_header_v1.py',
        '0915ec397ac74774c9bde9dbd30573b2e28691a302c995688d5334cc855da349','frozen_v2_header_parser_only',dependencies)
    lbl_method=load('staging/navigation-stock-AP-LBL-labels-v1/probe_original_AP_LBL_fragments_v2.py',
        'bae9d6f09fbae1e99044b296af85720e62dfdb93cf46af74cb6dfc0708c06c04','frozen_v2_GMP_LBL_fragments_only',dependencies)
    source=selection['candidate'];candidate_path=ROOT/source['path']
    need(identity(candidate_path)==source['stat_at_selection'],'Final actual IMG unchanged since sealed selection')
    parents=selection['parent_samples'];samples=selection['new_leaf_samples'];old_samples=selection['separate_old_prefix_samples']
    need(len(parents)<=30 and len(samples)<=30,'Finite parent/new-leaf caps before execution')
    plan=selection['mdr_plan'];cpu=old.CPU(v1.NativeImage());candidate=old.CandidateIMG(candidate_path)
    records=[];label_targets=[];progress=[]
    try:
        need(candidate.before[2]==source['bytes'] and candidate.block_size==4096,'Actual finalized 4K v2 IMG geometry')
        header_source,header=candidate.read('00004171.MDR',0,772,'actual_v2_MDR_header')
        parser=parser_method.invoke(cpu.image,header,'actual_v2_width23_candidate');gc.collect()
        need(parser['success'] and parser['native_context_offset2b8']==20 and parser['native_context_offset2c0']==6,'Genuine v2 MDR header parser')
        native_start=struct.unpack_from('<I',bytes.fromhex(parser['native_context_slice280_2c4']),0x34)[0]
        header_start,dbytes,itembytes,dflags=struct.unpack_from('<4I',header,600)
        component_size=candidate.components['00004171.MDR']['bytes']
        need((dbytes,itembytes,dflags)==(120,20,1) and native_start==header_start and native_start+120==component_size,
             'Genuine parser supplies actual final directory ending at real component EOF')
        directory_source,raw_directory=candidate.read('00004171.MDR',native_start,120,'actual_v2_MDR_directory')
        native_directory,layouts,directory_proof=reused.directory(cpu,parser,raw_directory,native_start)
        for layout,expected in zip(layouts,plan['new_tables']):
            need((layout['start'],layout['bytes'],layout['record_bits'],layout['count'],layout['widths'],layout['flags'])==
                 (expected['start'],expected['bytes'],expected['stride'],expected['count'],expected['widths'],expected['flags']),
                 'Actual native directory differs from sealed v2 writer plan')
        need(layouts[2]['record_bits']==112 and layouts[2]['widths'][0]==23,'Actual v2 L3 dynamic profile23/112')
        need({level:layouts[level-1]['count'] for level in (4,5,6)}=={4:3781594,5:2667573,6:1984066},'Actual v2 final table counts')
        def run_record(layout,ID,expected,purpose):
            bit=(ID-1)*layout['record_bits'];offset=layout['start']+bit//8
            length=((bit%8)+layout['record_bits']+7)//8+4
            witness,raw=candidate.read('00004171.MDR',offset,length,purpose)
            result=v1.native_record(cpu,reused,native_directory,layout,ID,raw,offset,component_size,expected)
            result['candidate_source']=witness
            return result,raw
        def update_progress():
            if len(records)%6==0:
                observation={'actual_record_prefixes_finished':len(records),'candidate_bytes_read_so_far':sum(x['bytes'] for x in candidate.log),
                    'elapsed_seconds':round(time.monotonic()-t0,3),'max_RSS_KiB':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss}
                progress.append(observation);print(json.dumps({'progress':observation}),flush=True)
        for group in sorted(parents,key=lambda r:r['nativeStreetID']):
            ID=group['nativeStreetID'];layout=layouts[2]
            expected={'+00':group['new_first'],'+0c':group['new_count'],'+04':group['original_flags'],'+08':1}
            result,_=run_record(layout,ID,expected,'actual_v2_parent_'+str(ID))
            result.update(name='parent_'+str(ID),street_ID=ID,expected_label=group['street'],
                source_selected_range=group,next_child_level=group['next_level'],source_merge=group['source_merge'],
                affected6676_parent_only_sample=ID==6676)
            records.append(result);label_targets.append(result);update_progress()
        for selected in samples:
            row=selected['sample'];level=row['next_level'];layout=layouts[level-1];ID=row['new_lowID']
            expected={'+00':0,'+04':0,'+08':1,'+0c':0,'+10':row['primary_ref'],
                '+14':row['raw24'][0],'+18':row['raw24'][1],'+1c':0xffffffff}
            result,wire=run_record(layout,ID,expected,'actual_v2_new_L%d_leaf_%d'%(level,ID))
            normalized=result['significant_wire_record_normalized_for_comparison_hex']
            need(normalized==row['payload'],'Actual un-realigned v2 leaf significant payload')
            result.update(name='new_L%d_leaf_%d'%(level,ID),street_ID=row['nativeStreetID'],
                expected_label=row['house_label'],independent_prepared_new_house_source=row,
                source_merge=row['source_merge'],selection_names=selected['selection_names'],new_leaf=True,
                native_flat_district_null= row['source_merge']=='flat_city_v1' and row['district'] is None)
            records.append(result);label_targets.append(result);update_progress()
        for sample in old_samples:
            level=sample['level'];ID=sample['lowID'];layout=layouts[level-1]
            bit=(ID-1)*layout['record_bits'];offset=layout['start']+bit//8
            length=((bit%8)+layout['record_bits']+7)//8+4
            witness,wire=candidate.read('00004171.MDR',offset,length,'actual_v2_separate_old_prefix_'+sample['selection_name'])
            value=(int.from_bytes(wire,'little')>>(bit%8))&((1<<layout['record_bits'])-1)
            expected,_=reused.projection(value.to_bytes((layout['record_bits']+7)//8,'little'),layout)
            result=v1.native_record(cpu,reused,native_directory,layout,ID,wire,offset,component_size,expected)
            result.update(name=sample['selection_name'],street_ID=sample['street_ID'],new_leaf=False,
                expected_label=None,candidate_source=witness,separate_old_prefix_source=sample,
                source_validation='Native prefix versus actual wire projection only; kept-original origin uses sealed builder complete readback.')
            records.append(result);label_targets.append(result);update_progress()
        gmp_source,gmp=candidate.read('I053061A.GMP',0,57,'actual_v2_GMP_header')
        need(struct.unpack_from('<H',gmp)[0]==57 and gmp[2:12]==b'GARMIN GMP','Actual GMP header')
        lbl_start=struct.unpack_from('<7I',gmp,25)[2]
        prefix_source,prefix=candidate.read('I053061A.GMP',lbl_start,2,'actual_v2_LBL_length')
        lbl_size=struct.unpack('<H',prefix)[0];need(lbl_size==661,'Actual unchanged public LBL shape')
        tail_source,tail=candidate.read('I053061A.GMP',lbl_start+2,lbl_size-2,'actual_v2_LBL_body')
        need((prefix+tail)[2:12]==b'GARMIN LBL','Actual GMP-derived LBL signature')
        lbl_parser=lbl_method.parser_case(cpu.read,prefix+tail);gc.collect();metadata=lbl_parser['actual_metadata_fields'];labels=[]
        for i,result in enumerate(label_targets):
            ref=result['actual_native_fields']['+10'];offset=metadata['label_start']+(ref<<metadata['shift'])
            witness,window=candidate.read('I053061A.GMP',offset,64,'actual_v2_native_LBL_ref_'+str(ref))
            copied=lbl_method.fragment_case(cpu.read,ref,metadata,window);gc.collect()
            expected=result['expected_label']
            if expected is None:
                end=window.find(b'\0');need(end>=0,'Bounded actual old-label NUL for wire comparison')
                expected=window[:end].decode('cp950',errors='strict')
            need(copied['actual_byte_copy_and_termination_passed'] and copied['host_CP950_display_of_actual_native_output']==expected,
                 'Genuine actual-v2 LBL byte-copy/termination/text')
            labels.append({'record_name':result['name'],'native_reference':ref,'candidate_source':witness,
                'source_native_field':'+10','expected_text':expected,
                'expected_text_provenance':'Selected sealed street/house name' if result['expected_label'] is not None else 'Actual old-prefix wire window decoded CP950; not a new house',
                'actual_partial_original_CPU':copied})
            if (i+1)%8==0:
                observation={'actual_partial_LBL_labels_finished':i+1,'candidate_bytes_read_so_far':sum(x['bytes'] for x in candidate.log),
                    'elapsed_seconds':round(time.monotonic()-t0,3),'max_RSS_KiB':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss}
                progress.append(observation);print(json.dumps({'progress':observation}),flush=True)
        candidate.close()
        need(identity(path)==selection_before,'Finite input immutable across CPU')
        for receipt in selection['prepared_producer_input_receipts']:
            need(identity(ROOT/receipt['path'])==receipt['stat_after'],'Sealed prepared producer inputs unchanged through CPU')
        reads=sum(row['bytes'] for row in candidate.log);need(reads<160000,'Actual-candidate read budget')
        new_results=[r for r in records if r.get('new_leaf') is True]
        for source_merge in ('country_v1','kaohsiung_v1'):
            need({r['initial_bit_offset'] for r in new_results if r['source_merge']==source_merge and r['level']==5}=={0,2,4,6},'Each true source L5 packing shifts')
            need({r['initial_bit_offset'] for r in new_results if r['source_merge']==source_merge and r['level']==6}=={0,4},'Each true source L6 packing shifts')
        need({r['independent_prepared_new_house_source']['city'] for r in new_results if r['source_merge']=='flat_city_v1'}==
             {'基隆市','台北市','新竹市','嘉義市'},'All four actual flat cities covered')
        proof={'schema':'actual-country-native-candidate-CPU/v2','started_utc':start,
            'finished_utc':datetime.now(timezone.utc).isoformat(),'elapsed_seconds':time.monotonic()-t0,
            'all_assigned_checks_passed':True,'script_sha256':sha(Path(__file__).read_bytes()),'stock_MAIN_sha256':v1.EXPECTED,
            'dependencies':dependencies,'finite_selection_sha256':args.selection_sha256,
            'prepared_producer_inputs':selection['prepared_producer_input_receipts'],
            'candidate':{'path':source['path'],'bytes':source['bytes'],'stat_before':candidate.before,'stat_after':identity(candidate_path),
                         'stat_unchanged':True,'inherited_root_readback_sha256':source['inherited_root_readback_sha256'],
                         'whole_candidate_hash_repeated':False,'FAT_extent':candidate.extent,'block_size':candidate.block_size},
            'exact_parent_count':len(parents),'exact_new_leaf_count':len(samples),'separate_old_prefix_count':len(old_samples),
            'exact_record_prefix_count':len(records),'complete_kept_source_records':130637,'complete_selected_streets':18823,
            'actual_final_counts':{4:layouts[3]['count'],5:layouts[4]['count'],6:layouts[5]['count']},
            'actual_MDR_header_source':header_source,'actual_original_header_parser':parser,
            'actual_directory_source':directory_source,'actual_original_directory':directory_proof,
            'directory_position_from_actual_native_parser':True,'record_positions_from_actual_native_directory':True,
            'actual_native_records':records,'actual_GMP_source':gmp_source,'actual_GMP_derived_LBL_header_offset':lbl_start,
            'actual_LBL_length_source':prefix_source,'actual_LBL_body_source':tail_source,
            'actual_partial_LBL_parser':lbl_parser,'actual_partial_LBL_labels':labels,
            'actual_candidate_read_log':candidate.log,'total_actual_candidate_bytes_read':reads,
            'runtime_progress':progress,'max_RSS_KiB':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
            'leaf_initial_bit_offsets_by_source_and_level':{
                source_merge:{str(level):sorted({r['initial_bit_offset'] for r in new_results if r['source_merge']==source_merge and r['level']==level}) for level in (4,5,6)}
                for source_merge in ('country_v1','kaohsiung_v1','flat_city_v1')},
            'affected6676_native_parent_count':next(r['actual_native_fields']['+0c'] for r in records if r['name']=='parent_6676'),
            'affected6676_is_not_sampled_as_new_house':True,
            'only_function_hooks':['underlying FS open0x1C8682','underlying FS read0x3324B8','underlying FS mapping0x112194'],
            'metadata_registry_query_sort_result_or_policy_hooks':[],'stop_before_metadata':'0x0448F740',
            'full_reader_getter_query_UI_or_route_executed':False,'device_IO':False,'installation_performed':False,
            'whole_image_copied':False,'canonical_ZIP_or_services_mutated':False,'old_closed_suites_replayed':False,
            'complete_Taiwan_native_update':False,'complete_candidate_acceptance_asserted':False,
            'limits':['Finite actual-v2 header→directory→packed-prefix CPU, stopped before metadata, with only actual FS slices as fixtures.',
                'CPU receives un-realigned candidate bytes and four actual following bytes at unmapped guard page; normalized significant bytes are direct comparison only.',
                'GMP/LBL byte-copy fragments are separately executed; no complete registry getter, query result, native UI/search/route or physical device acceptance.',
                'Old-prefix samples are actual retained bytes versus native/direct wire projection; complete kept-original identity is inherited sealed builder readback.',
                'Actual country+KH packed shifts/splice sides, Minquan6/150 goldens and four flat district=null cities are finite samples, not all new130637 CPU reads.',
                'Source district provenance does not create a native district record; unknown flags and pending names/lanes/subnumbers remain unresolved.']}
        (HERE/'proof.json').write_text(json.dumps(proof,ensure_ascii=False,indent=2)+'\n')
        (HERE/'execution-receipt.json').write_text(json.dumps({'actual_script_completed_exit_status':0,'started_utc':start,
            'finished_utc':proof['finished_utc'],'elapsed_seconds':proof['elapsed_seconds'],'script_sha256':proof['script_sha256'],
            'proof_sha256':sha((HERE/'proof.json').read_bytes()),'finite_selection_sha256':args.selection_sha256,
            'exact_parent_count':len(parents),'exact_new_leaf_count':len(samples),'separate_old_prefix_count':len(old_samples),
            'total_actual_candidate_bytes_read':reads,'device_IO':False},indent=2)+'\n')
        print(json.dumps({'all_assigned_checks_passed':True,'exact_parent_count':len(parents),'exact_new_leaf_count':len(samples),
            'separate_old_prefix_count':len(old_samples),'actual_partial_LBL_labels':len(labels),
            'total_actual_candidate_bytes_read':reads,'max_RSS_KiB':proof['max_RSS_KiB'],
            'proof_sha256':sha((HERE/'proof.json').read_bytes()),'candidate_inherited_sha256':source['inherited_root_readback_sha256'],
            'device_IO':False},ensure_ascii=False),flush=True)
    finally:
        if not candidate.stream.closed:candidate.stream.close()


if __name__=='__main__':main()
