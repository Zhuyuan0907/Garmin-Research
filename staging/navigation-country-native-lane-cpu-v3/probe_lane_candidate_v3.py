#!/usr/bin/env python3
"""NEW finite actual AP8K COW CPU fragments; no old main/case replay."""
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
sys.dont_write_bytecode = True
ROOT = Path('/root/garmin');HERE = Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
from strict_ap8k_reader import Candidate8K,need,stat
CANDIDATE = ROOT/'staging/navigation-country-native-lane-candidate-v3'
CANDIDATE_SHA = '1f468eb78cc1268951873c82ffce4abe3292dcece69c0eee405c5d7aca3cc360'
CANDIDATE_STAT = [45826,538039,153346048,1791317242895661512,1791317284446198518]
PROOF_SHA = 'b5baf538981a60aceb2b8cbb2c31ce3e8159363a719909791e31ef0ca0cb58d0'
LAYOUT_SHA = '4abdc75c4af78dbfcdae421d68e838042e1756f978bff0f342c793bc4d411a9a'
SEAL_SHA = 'dfc47744887137f944d710dffeb5ea6f6821c24eb8abbeb522cb406576754335'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def load(relative,digest,name,dependencies):
    path = ROOT/relative;before = stat(path);raw = path.read_bytes()
    need(sha(raw) == digest and stat(path) == before,'Pinned native helper source:'+relative)
    spec = importlib.util.spec_from_file_location(name,path);module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module;spec.loader.exec_module(module)
    dependencies.append({'path':relative,'sha256':digest,'historical_main_or_cases_executed':False})
    return module


def bound_json(path,digest):
    before = stat(path);raw = path.read_bytes()
    need(sha(raw) == digest and stat(path) == before,'Exact bounded metadata pin:'+str(path))
    return json.loads(raw),before


def main():
    parser = argparse.ArgumentParser();parser.add_argument('--selection-sha256',required=True);args = parser.parse_args()
    need(not (HERE/'proof.json').exists(),'Refuse overwrite terminal v3 CPU proof')
    started = datetime.now(timezone.utc).isoformat();t0 = time.monotonic();deps = []
    selection,selection_stat = bound_json(HERE/'finite-selection.json',args.selection_sha256)
    need(selection['schema'] == 'finite-lane-COW-native-CPU-selection/v3' and not selection['native_CPU_executed'], 'Fresh finite selection')
    need(not selection.get('raw13_clone_witness_pending_from_new_independent_producer_review',True),'Actual raw13 source witness required')
    for receipt in selection['prepared_input_receipts']:
        need(stat(ROOT/receipt['path']) == receipt['stat_after'] == receipt['stat_before'],'Prepared source input immutable')
    builder,builder_stat = bound_json(CANDIDATE/'proof.json',PROOF_SHA)
    layout,layout_stat = bound_json(CANDIDATE/'actual-output-layout.json',LAYOUT_SHA)
    seal,seal_stat = bound_json(CANDIDATE/'sealed-files.json',SEAL_SHA)
    need(builder['all_assigned_checks_passed'] and builder['candidate_sha256'] == layout['candidate_sha256'] == CANDIDATE_SHA and
         builder['candidate_bytes'] == layout['candidate_bytes'] == CANDIDATE_STAT[2], 'Completed actual v3 builder/readback binding')
    need(builder['new_lane_integer_houses'] == 58233 and builder['selected_L3_root_changes'] == 7650,'Exact resulting COW dataset')
    v1 = load('staging/navigation-country-native-cpu-v1/probe_country_candidate.py',
        '312d8dc58e2c2cf7e6c6ab1b295e5befece64929dc8e56625561220d1c2f22ff','v3_sealed_record_prefix_only',deps)
    reused = load('staging/navigation-taichung-native-cpu-v1/probe_actual_candidate_native_v1.py',
        'bb7882322906bd38877debf79921d1ad1ca68e94401bf849d4eb93d39053fc54','v3_sealed_directory_projection_only',deps)
    old = load('staging/navigation-native-address-supplement-native-v1/probe_candidate_native_v1.py',
        '2a59e48ee4b9fd435084672368f9a87a796299d13c32bf7f70c055ce9fc0eaaa','v3_sealed_CPU_machine_only',deps)
    header_method = load('staging/navigation-native-MDR-provider-fields-v1/probe_native_mdr_header_v1.py',
        '0915ec397ac74774c9bde9dbd30573b2e28691a302c995688d5334cc855da349','v3_sealed_header_parser_only',deps)
    lbl_method = load('staging/navigation-stock-AP-LBL-labels-v1/probe_original_AP_LBL_fragments_v2.py',
        'bae9d6f09fbae1e99044b296af85720e62dfdb93cf46af74cb6dfc0708c06c04','v3_sealed_LBL_fragments_only',deps)
    cpu = old.CPU(v1.NativeImage());candidate = Candidate8K(CANDIDATE/'gmapprom1.img',layout,CANDIDATE_STAT)
    records = [];byrecord = {};progress = []
    try:
        hs,header = candidate.read('00004171.MDR',0,772,'actual_v3_MDR_header')
        parsed = header_method.invoke(cpu.image,header,'actual_v3_AP8K_current_width23');gc.collect()
        need(parsed['success'] and parsed['native_context_offset2b8'] == 20 and parsed['native_context_offset2c0'] == 6,
             'Actual original header parser shape')
        native_start = struct.unpack_from('<I',bytes.fromhex(parsed['native_context_slice280_2c4']),0x34)[0]
        hstart,hbytes,hstride,hflags = struct.unpack_from('<4I',header,600)
        component_size = candidate.components['00004171.MDR']['bytes']
        need((hbytes,hstride,hflags) == (120,20,1) and native_start == hstart and native_start+120 == component_size,
             'Genuine parser directory position at actual EOF')
        ds,directory = candidate.read('00004171.MDR',native_start,120,'actual_v3_MDR_directory')
        native_directory,layouts,directory_proof = reused.directory(cpu,parsed,directory,native_start)
        for actual,expected in zip(layouts,layout['tables']):
            need((actual['level'],actual['start'],actual['bytes'],actual['record_bits'],actual['count'],actual['widths'],actual['flags']) ==
                 (expected['level'],expected['start'],expected['bytes'],expected['stride'],expected['count'],expected['widths'],expected['flags']),
                 'Actual original directory projection versus actual8K descriptor')
        need(layouts[2]['record_bits'] == 112 and layouts[2]['widths'][0] == 23 and
             [layouts[i-1]['count'] for i in (4,5,6)] == [4896236,3077845,2062771], 'Actual v3 profile and counts')
        def run(level,ID,expected,purpose,label=None,payload=None,source=None):
            descriptor = layouts[level-1];bit = (ID-1)*descriptor['record_bits'];at = descriptor['start']+bit//8
            n = (bit%8+descriptor['record_bits']+7)//8+4
            witness,wire = candidate.read('00004171.MDR',at,n,purpose)
            result = v1.native_record(cpu,reused,native_directory,descriptor,ID,wire,at,component_size,expected)
            if payload is not None:
                need(result['significant_wire_record_normalized_for_comparison_hex'] == payload,'Actual unchanged producer payload')
            result.update(name=purpose,expected_label=label,candidate_source=witness,independent_prepared_source=source)
            records.append(result);byrecord[(level<<28)|ID] = result
            if len(records)%6 == 0:
                observation = {'record_prefixes_finished':len(records),'actual_bytes_read':sum(r['bytes'] for r in candidate.log),
                               'elapsed_seconds':round(time.monotonic()-t0,3)}
                progress.append(observation);print(json.dumps({'progress':observation}),flush=True)
            return result
        need(len(selection['copied_path_parent_samples'])+len(selection['extra_root_samples']) <= 20 and
             len(selection['new_leaf_samples']) <= 10,'Finite node caps')
        for parent in selection['copied_path_parent_samples']:
            expected = {'+00':parent['expected_first'],'+0c':parent['expected_count'],'+04':parent['expected_flags'],'+08':1}
            run(parent['level'],parent['lowID'],expected,'actual_v3_path_parent_'+str(parent['record']),
                parent['expected_label'],source=parent)
        for pick in selection['extra_root_samples']:
            parent = pick['sample'];expected = {'+00':parent['first_child'],'+0c':parent['count'],'+04':parent['original_flags'],'+08':1}
            run(3,parent['one_based_street_ID'],expected,pick['selection_name'],pick['expected_label'],source=pick)
        leaf_results = []
        for pick in selection['new_leaf_samples']:
            row = pick['sample'];expected = {'+00':0,'+04':0,'+08':1,'+0c':0,'+10':row['primary_ref'],
                                           '+14':row['raw24'][0],'+18':row['raw24'][1],'+1c':0xffffffff}
            result = run(row['level'],row['new_lowID'],expected,'actual_v3_new_leaf_'+str(row['new_lowID']),
                         row['house_label'],row['payload'],row)
            result['selection_names'] = pick['selection_names'];leaf_results.append(result)
        retained = selection['retained_prior_v2_leaf_sample'];level = retained['level'];ID = retained['cloned_lowID']
        need(retained['status'] == 'actual_cloned_append_payload_identical','Prior v2 leaf exact payload source')
        expected,_ = reused.projection(bytes.fromhex(retained['unchanged_payload']),layouts[level-1])
        run(level,ID,expected,'actual_v3_retained_prior_v2_leaf',payload=retained['unchanged_payload'],source=retained)
        raw13 = selection['raw13_clone_witness'];level = raw13['level'];ID = raw13['new_lowID']
        payload = raw13.get('payload',raw13.get('new_payload'));need(payload is not None,'Raw13 actual source payload required')
        expected,_ = reused.projection(bytes.fromhex(payload),layouts[level-1]);need(expected['+04'] == 13,'Actual selected old clone raw13')
        run(level,ID,expected,'actual_v3_unchanged_raw13_clone',payload=payload,source=raw13)
        # Prove the sampled native-decoded ancestor range contains the next ID.
        paths = []
        for path in selection['complete_path_samples']:
            observed = []
            for edge in path['ancestor_links']:
                parent = byrecord[edge['parent_new_record']]['actual_native_fields']
                child_level,child_ID = edge['child_new_record']>>28,edge['child_new_record']&0xfffffff
                need((parent['+04']&7) == child_level == edge['next_level'] and
                     parent['+00'] == edge['first_child'] and parent['+0c'] == edge['count'] and
                     parent['+00'] <= child_ID < parent['+00']+parent['+0c'] and
                     child_ID-parent['+00'] == edge['child_ordinal'],'Actual native decoded sampled ancestor link')
                observed.append({'parent_record':edge['parent_new_record'],'child_record':edge['child_new_record'],
                                 'actual_native_parent_fields':parent,'child_ordinal':edge['child_ordinal']})
            paths.append({'stock_parent_record':path['stock_parent_record'],'actual_sampled_native_links':observed})
        need(any(len(p['actual_sampled_native_links']) >= 2 for p in paths),'At least one true multi-ancestor sampled path')
        roots = [r for r in records if r['level'] == 3]
        need({r['actual_native_fields']['+04']&7 for r in roots} >= {4,5,6},'Actual root branches4/5/6')
        need(any(r['actual_native_fields']['+00'] > 4194304 for r in roots),'Actual23-bit first beyond22-bit limit')
        need({r['initial_bit_offset'] for r in leaf_results if r['level'] == 5} == {0,2,4,6} and
             {r['initial_bit_offset'] for r in leaf_results if r['level'] == 6} == {0,4},'All true global v3 packed leaf shifts')
        gs,gmp = candidate.read('I053061A.GMP',0,57,'actual_v3_GMP_header')
        need(struct.unpack_from('<H',gmp)[0] == 57 and gmp[2:12] == b'GARMIN GMP','Actual unchanged GMP header')
        lbl_start = struct.unpack_from('<7I',gmp,25)[2]
        ps,prefix = candidate.read('I053061A.GMP',lbl_start,2,'actual_v3_LBL_length')
        lbl_size = struct.unpack('<H',prefix)[0];need(lbl_size == 661,'Actual LBL header shape')
        ts,tail = candidate.read('I053061A.GMP',lbl_start+2,lbl_size-2,'actual_v3_LBL_body')
        need((prefix+tail)[2:12] == b'GARMIN LBL','Actual GMP-derived LBL header')
        lbl_parser = lbl_method.parser_case(cpu.read,prefix+tail);gc.collect();metadata = lbl_parser['actual_metadata_fields'];labels = []
        for i,result in enumerate(records):
            ref = result['actual_native_fields']['+10'];at = metadata['label_start']+(ref<<metadata['shift'])
            witness,window = candidate.read('I053061A.GMP',at,64,'actual_v3_LBL_ref_'+str(ref))
            copied = lbl_method.fragment_case(cpu.read,ref,metadata,window);gc.collect()
            expected_text = result['expected_label']
            if expected_text is None:
                end = window.find(b'\0');need(end >= 0,'Actual bounded CP950 label terminator')
                expected_text = window[:end].decode('cp950',errors='strict')
            need(copied['actual_byte_copy_and_termination_passed'] and
                 copied['host_CP950_display_of_actual_native_output'] == expected_text,'Actual LBL partial CPU copy/termination')
            labels.append({'record_name':result['name'],'native_reference':ref,'expected_text':expected_text,
                           'expected_text_provenance':'Producer exact label' if result['expected_label'] is not None else 'Actual unchanged wire CP950 label only',
                           'candidate_source':witness,'actual_partial_original_CPU':copied})
            if (i+1)%6 == 0:
                print(json.dumps({'progress':{'partial_labels_finished':i+1,'actual_bytes_read':sum(r['bytes'] for r in candidate.log)}}),flush=True)
        candidate.close();reads = sum(r['bytes'] for r in candidate.log);need(reads < 160000,'Finite actual read budget')
        need(stat(HERE/'finite-selection.json') == selection_stat and stat(CANDIDATE/'proof.json') == builder_stat and
             stat(CANDIDATE/'actual-output-layout.json') == layout_stat and stat(CANDIDATE/'sealed-files.json') == seal_stat,
             'Exact prepared/candidate metadata inputs unchanged')
        for receipt in selection['prepared_input_receipts']:
            need(stat(ROOT/receipt['path']) == receipt['stat_after'],'Closed producer selection inputs unchanged across CPU')
        proof = {'schema':'actual-lane-COW-AP8K-finite-native-CPU/v3','all_assigned_checks_passed':True,
            'started_utc':started,'finished_utc':datetime.now(timezone.utc).isoformat(),'elapsed_seconds':time.monotonic()-t0,
            'script_sha256':sha(Path(__file__).read_bytes()),'mapper_sha256':sha((HERE/'strict_ap8k_reader.py').read_bytes()),
            'stock_MAIN_sha256':v1.EXPECTED,'dependencies':deps,'selection_sha256':args.selection_sha256,
            'candidate':{'path':str((CANDIDATE/'gmapprom1.img').relative_to(ROOT)),'bytes':CANDIDATE_STAT[2],
                         'sha256_inherited_from_completed_actual_builder_readback':CANDIDATE_SHA,
                         'stat_before':candidate.before,'stat_after':stat(CANDIDATE/'gmapprom1.img'),'stat_unchanged':True,
                         'block_size':8192,'FAT_extent':candidate.extent,'metadata_sha256':candidate.metadata_sha256,'whole_candidate_hash_repeated':False},
            'builder_proof_sha256':PROOF_SHA,'actual_output_layout_sha256':LAYOUT_SHA,'candidate_seal_sha256':SEAL_SHA,
            'prepared_input_receipts':selection['prepared_input_receipts'],'actual_MDR_header_source':hs,
            'actual_original_header_parser':parsed,'actual_directory_source':ds,'actual_original_directory':directory_proof,
            'actual_native_records':records,'actual_sampled_native_paths':paths,'exact_record_prefix_count':len(records),
            'exact_new_leaf_count':len(leaf_results),'exact_path_parent_count':len(selection['copied_path_parent_samples']),
            'exact_extra_root_count':len(selection['extra_root_samples']),'exact_raw13_clone_count':1,'exact_prior_v2_leaf_count':1,
            'actual_root_branches':[4,5,6],'actual_root_first_above4194304':True,
            'actual_new_leaf_bit_shifts':{str(level):sorted({r['initial_bit_offset'] for r in leaf_results if r['level'] == level}) for level in (5,6)},
            'actual_GMP_source':gs,'actual_GMP_derived_LBL_header_offset':lbl_start,'actual_LBL_length_source':ps,'actual_LBL_body_source':ts,
            'actual_partial_LBL_parser':lbl_parser,'actual_partial_LBL_labels':labels,
            'actual_candidate_read_log':candidate.log,'total_actual_candidate_bytes_read':reads,'runtime_progress':progress,
            'max_RSS_KiB':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
            'only_function_hooks':['Underlying FS open0x1C8682','Underlying FS read0x3324B8','Underlying FS mapping0x112194'],
            'stop_before_metadata':'0x0448F740','full_getter_registry_query_UI_route_executed':False,
            'device_IO':False,'installation_performed':False,'old_closed_suites_replayed':False,'whole_image_copied':False,
            'canonical_ZIP_services_or_prior_frozen_files_modified':False,'header_checksum_rule_or_device_acceptance_verified':False,
            'full_Taiwan_native_update_complete':False,
            'limits':['Finite actual AP8K FAT/header/directory/packed-prefix CPU and separate real GMP/LBL byte-copy fragments only.',
                      'Every record fixture retains its true bit offset and actual next4bytes at an unmapped guard page; significant normalization is comparison only.',
                      'Sampled parent/child links are decoded fields and bounded range checks, not full original getter/name search/comparator or routing execution.',
                      'One untouched branch6 root is separate from newly affected lane roots; no branch is fabricated.',
                      'Full source/geometry/ordering/old-record/new-leaf coverage is inherited closed producer/builder evidence, not rerun by this finite CPU scope.',
                      '8K checksum/device acceptance, query/UI and physical routing remain unproved.']}
        with (HERE/'proof.json').open('x') as stream:
            json.dump(proof,stream,ensure_ascii=False,indent=2);stream.write('\n')
        receipt = {'actual_exit_status':0,'script_sha256':proof['script_sha256'],'proof_sha256':sha((HERE/'proof.json').read_bytes()),
                   'exact_records':len(records),'new_leaves':len(leaf_results),'labels':len(labels),'actual_read_bytes':reads,
                   'candidate_immutable':True,'device_IO':False,'elapsed_seconds':proof['elapsed_seconds']}
        with (HERE/'execution-receipt.json').open('x') as stream:
            json.dump(receipt,stream,indent=2);stream.write('\n')
        print(json.dumps(receipt),flush=True)
    finally:
        if not candidate.stream.closed:
            candidate.stream.close()


if __name__ == '__main__':
    main()
