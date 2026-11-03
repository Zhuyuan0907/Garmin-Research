#!/usr/bin/env python3
"""Seal completed V5 normal-DATA evidence. No IMG/algorithm/guest reopens.

AST checks are source identity and binding checks only, not an independent V5
graph execution/review. All capacity and consumer limitations remain explicit.
"""
from pathlib import Path
from datetime import datetime, timezone
import argparse
import ast
import copy
import hashlib
import json
import os

ROOT=Path('/root/garmin')
HERE=ROOT/'staging/navigation-v3-reachable-suffix-compaction-dependency-preflight-v5'
V4=ROOT/'staging/navigation-v3-reachable-suffix-compaction-current-mm-v4/observed_analyzer.py'
RAM=ROOT/'staging/navigation-v3-reachable-suffix-compaction-feasibility-v1/analyze_reachable.py'
MAPPER=ROOT/'staging/navigation-minimal-lane-render-isolation-plan-v1/prepare_control.py'
SOURCE_SHA='1e7888373c759b72c206f0fef11cf189cffa4ef98299f61ebe2c7bb948be1a6b'
V4_SHA='ad46dda03730cab4a73e39346fd597b13bc91604a811147840499a123baa3e04'
RAM_SHA='a1a7a9c94df6a8b715eca28366a9c94ed8895d6e0176fd05a4f076d506beb274'
MAPPER_SHA='a20877fce09cbfe36f1f5621144f2ade44a031c26e4c6d330d07b2a1b86c4095'
PROOF_SHA='ca6e4225536d9240b58c7424934f49f1c86c58c23dd956b5c8f1c223500f4d82'
MDR_SHA='b23a67f80ad4275b40faf15fd12ac02e32c34d359108489d51404c9791a657d1'
IMG_SHA='1f468eb78cc1268951873c82ffce4abe3292dcece69c0eee405c5d7aca3cc360'
CAP=1048576
INPUTS=[]


def need(value,message):
    if not value:raise ValueError(message)


def sha(data):return hashlib.sha256(data).hexdigest()


def st(p):
    s=p.stat();return [s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]


def read(p,limit=CAP):
    need(p.parent==HERE or p in (V4,RAM,MAPPER),'Exact small artifact/code allowlist')
    need(p.is_file() and not p.is_symlink(),'Small regular nonsymlink evidence')
    before=st(p);need(before[2]<=limit,'Individual small read bound')
    with p.open('rb') as f:
        data=f.read(limit+1);need(f.read(1)==b'','Actual small-file EOF')
    need(len(data)==before[2] and st(p)==before,'Stable actual EOF/stat')
    item={'path':str(p.relative_to(ROOT)),'bytes':len(data),'sha256':sha(data),
          'stat_before':before,'stat_after':st(p),'EOF_verified':True}
    INPUTS.append(item)
    return data,item


def obj(name):
    data,item=read(HERE/name);return json.loads(data),item


def save(name,value):
    p=HERE/name;data=(json.dumps(value,ensure_ascii=False,indent=2)+'\n').encode()
    need(len(data)<=CAP,'Small closure output bound')
    with p.open('xb') as f:f.write(data);f.flush();os.fsync(f.fileno())
    return {'path':str(p.relative_to(ROOT)),'bytes':len(data),'sha256':sha(data)}


def dump(node):return ast.dump(node,include_attributes=False)


def source_binding(proof):
    current,item=read(HERE/'observed_analyzer.py',32768)
    need(item['sha256']==SOURCE_SHA and len(current)==24314,'Actual prepared V5 source pin')
    old,olditem=read(V4,32768);ram,ramitem=read(RAM,32768);mapper,mapitem=read(MAPPER,40960)
    need(olditem['sha256']==V4_SHA and ramitem['sha256']==RAM_SHA and mapitem['sha256']==MAPPER_SHA,
         'Closed predecessor/core/mapper exact source pins')
    need(sum(x['bytes'] for x in (item,olditem,ramitem,mapitem))<=131072,'Aggregate static code under128KiB')
    a=ast.parse(current);b=ast.parse(old)
    ad={n.name:n for n in a.body if isinstance(n,(ast.FunctionDef,ast.ClassDef))}
    bd={n.name:n for n in b.body if isinstance(n,(ast.FunctionDef,ast.ClassDef))}
    unchanged=sorted(k for k in bd if k!='main')
    need(all(k in ad and dump(ad[k])==dump(bd[k]) for k in unchanged),'All existing non-main helper/class ASTs identical')
    need(set(ad)-set(bd)=={'verify_extracted_globals'},'Only new dependency-preflight function')
    need(dump(ad['Observer'])==dump(bd['Observer']),'Observer exact AST identity to ad46 predecessor')
    assignments=lambda t:[dump(n) for n in t.body if isinstance(n,(ast.Assign,ast.AnnAssign,ast.AugAssign))]
    need(assignments(a)==assignments(b),'Counts/caps/all module assignment AST identity')
    normalized=copy.deepcopy(ad['main'])
    normalized.body=[n for n in normalized.body if not (isinstance(n,ast.Assign) and len(n.targets)==1 and
        isinstance(n.targets[0],ast.Name) and n.targets[0].id in {'helper_global_preflight','mapper_global_preflight'})]
    for n in ast.walk(normalized):
        if isinstance(n,ast.Assign) and len(n.targets)==1 and isinstance(n.targets[0],ast.Name) and n.targets[0].id=='env':
            n.value.keywords=[k for k in n.value.keywords if k.arg!='sha']
        if isinstance(n,ast.Call):n.keywords=[k for k in n.keywords if k.arg!='extracted_global_dependency_preflight']
    need(dump(normalized)==dump(bd['main']),'Main drift only sha environment and two preflights plus their proof field')
    rt=ast.parse(ram);mt=ast.parse(mapper)
    expected=proof['reused_original_RAM_helper_AST_sha256']
    actual={n.name:sha(dump(n).encode()) for n in rt.body if isinstance(n,ast.FunctionDef) and n.name in expected}
    need(len(actual)==8 and actual==expected,'All8 original RAM helper AST bindings match actual proof')
    im=[n for n in mt.body if isinstance(n,ast.ClassDef) and n.name=='Image']
    need(len(im)==1 and sha(dump(im[0]).encode())==proof['mapper_AST_sha256'],'Pinned mapper Image AST matches actual proof')
    return {'predecessor_source_sha256':V4_SHA,'current_source_sha256':SOURCE_SHA,
            'Observer_AST_sha256':sha(dump(ad['Observer']).encode()),'Observer_AST_identical':True,
            'preexisting_nonmain_function_class_names_identical':unchanged,
            'all_module_assignments_AST_identical':True,
            'main_changes_limited_to_sha_binding_preflights_and_proof_field':True,
            'core_RAM_source_sha256':RAM_SHA,'core_helper_AST_bindings':actual,
            'mapper_source_sha256':MAPPER_SHA,'mapper_Image_AST_sha256':proof['mapper_AST_sha256'],
            'static_only_no_original_main_or_helper_execution':True,
            'independent_V5_algorithm_graph_or_preflight_runtime_review_claim':False},item


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--terminal-chunk',required=True);args=ap.parse_args()
    need(args.terminal_chunk=='c4d30e' and not (HERE/'sealed-files.json').exists(),'Assigned completed fresh V5 scope')
    initial_names={p.name for p in HERE.iterdir()}
    need(initial_names=={'observed_analyzer.py','prepared-source.json','proof.json','feasibility-summary.json',
                       'actual-phase-observations.jsonl','actual-stream-read-receipts.json','actual-root-tool-receipts.json'},
         'Exact closed source/output inventory')
    prep,prepitem=obj('prepared-source.json');proof,proofitem=obj('proof.json');receipts,receiptitem=obj('actual-root-tool-receipts.json')
    need(proofitem['sha256']==PROOF_SHA and prep['source_sha256']==SOURCE_SHA and prep['source_bytes']==24314 and
         prep['predecessor_source_sha256']==V4_SHA and prep['Observer_AST_unchanged'] and
         prep['IMG_budget']==160000000 and prep['RSS_guard_current_mm_KiB']==393216,'Prepared/actual identity and unchanged caps')
    need(receipts['terminal'] is True and receipts['actual_final_exit_code']==0 and receipts['actual_session']==55836,
         'Actual unique root run ended EXIT0')
    terminal=receipts['observations'][-1]
    need(terminal['chunk_id']==args.terminal_chunk and terminal['exit_code']==0 and not terminal.get('session_id'),
         'Exact final completed tool receipt')
    parsed=[json.loads(l) for l in terminal['output'].splitlines() if l.startswith('{')]
    completed=[x for x in parsed if x.get('all_assigned_data_feasibility_checks_completed')]
    need(len(completed)==1 and completed[0]['proof']['sha256']==PROOF_SHA and completed[0]['source_handle_closed'] is True,
         'Actual terminal binds completed proof and source handle closure')
    need(proof['all_assigned_data_feasibility_checks_completed'] and proof['actual_IMG_read_bytes']==149290500 and
         proof['actual_IMG_read_cap']==160000000 and proof['one_actual_MDR_stream_bytes']==149220356 and
         proof['actual_MDR_hash_matches_sealed_complete_readback'] and proof['whole_IMG_hash_not_repeated'] and
         proof['all_own_and_source_handles_closed'],'Exact completed bounded stream/handles evidence')
    candidate=proof['source_candidate']
    need(candidate['bytes']==153346048 and candidate['inherited_whole_sha256']==IMG_SHA and
         candidate['handle_closed'] is True and candidate['stat_before']==candidate['stat_after'],
         'Source pin and immutable full stat inherited; no IMG open/stat here')
    need(proof['actual_original_stock_counts']=={'4':2133948,'5':2341096,'6':1973316} and
         proof['actual_current_profile']=={'L3_first_width':23,'L3_stride':112,'L3_count':47870,'lower_strides':[128,126,68]},
         'Exact fixed stock IDs and actual current profile')
    need(proof['MAIN_CPU_guest_PBF_bigsourceledger_audio_or_device_IO']==0 and
         proof['source_IMG_or_seals_report_canonical_modified'] is False and
         proof['new_IMG_or_fulltables_or_remapped_records_created'] is False and
         proof['native_install_fix_or_renderer_acceptance_ready'] is False,'Normal-DATA boundaries and acceptance limits')
    binding,sourceitem=source_binding(proof)
    preflight=proof['extracted_global_dependency_preflight']
    need(all(v['unresolved_global_names']==[] and v['image_bytes_read']==0 for v in preflight.values()) and
         'sha' in preflight['helpers']['required_global_names'],'Actual root preflight global resolution before image reads')
    stream,streamitem=obj('actual-stream-read-receipts.json');summary,summaryitem=obj('feasibility-summary.json')
    for key,item in [('read_receipts',streamitem),('summary',summaryitem)]:
        artifact=proof['artifacts'][key]
        need(all(artifact[k]==item[k] for k in ('path','bytes','sha256')),'Exact producer artifact pin '+key)
    need(stream['stream']['streamed_bytes']==149220356 and stream['stream']['actual_MDR_SHA256']==MDR_SHA and
         stream['read_budget']['actual_IMG_bytes_read']==149290500 and
         stream['read_budget']['actual_IMG_read_ops']==18377 and stream['read_budget']['read_cap_bytes']==160000000 and
         stream['actual_input_handle_closed'] and stream['source_stat_before']==stream['source_stat_after']==candidate['stat_before'],
         'Actual source EOF/digest/counters and stable stat')
    need(sum(s['bytes'] for s in stream['stream']['segments'])==149220356 and
         stream['stream']['fixed_field_arrays_bytes']==64175632,'Exact complete MDR segment totals and allocation bytes')
    stock=summary['stock_prefix_plus_active'];v2=summary['current_v2_prefix_plus_active']
    need(stock['retained_total_lower_counts']=={'4':3889829,'5':3074293,'6':2062771} and
         stock['structurally_unreferenced_postprefix_records']=={'4':1006407,'5':3552,'6':0} and
         stock['arithmetic']['projected_conservative_4K_IMG_bytes']==137170944 and
         stock['arithmetic']['capacity_margin_conservative']==-2953216 and
         stock['total_parent_first_fields_needing_remap']==36617 and stock['L3_roots_needing_first_pointer_remap']==19077,
         'Actual stock-prefix retain/remove/remap counts and explicit not-fit arithmetic')
    need(v2['retained_total_lower_counts']=={'4':4896236,'5':3077845,'6':2062771} and
         v2['arithmetic']['projected_conservative_4K_IMG_bytes']==153337856 and
         v2['structurally_unreferenced_postprefix_records']=={'4':0,'5':0,'6':0},'Actual whole-V2-prefix identity plan')
    for plan in (stock,v2):
        need(plan['all_L3_roots']==47870 and plan['original_prefix_IDs_unchanged'] and
             plan['L3_IDs_and_JAI_record_keys_unchanged'] and not plan['GMP_or_other_five_components_changed'] and
             plan['arithmetic']['declared_original_4K_capacity']==134217728 and
             plan['arithmetic']['fits_4K_capacity_arithmetic'] is False and
             plan['unknown_raw_flag_counts']=={} and plan['invalid_or_unclassified_child_encoding_counts']=={} and
             not plan['any_unknown_or_invalid_encoding_forced_all_lower_suffix_retention'] and
             not plan['native_context_renderer_UI_or_install_ready'],'No observed anomalies; unchanged IDs and no4K-fit/install claim')
    need(summary['external_lower_record_reference_ABIs_proven_absent'] is False and
         summary['actual_native_UI_renderer_or_physical_installation_verified'] is False,'External lowerrefs/live consumer unknown')
    artifact=proof['artifacts']['observations'];data,phaseitem=read(ROOT/artifact['path'],500000)
    need(all(artifact[k]==phaseitem[k] for k in ('path','bytes','sha256')),'Exact durable phase pin')
    rows=[];maxguard=0;maxru=0;priorbytes=0;priorops=0;preflight_rows=[]
    for index,line in enumerate(data.splitlines()):
        row=json.loads(line);rows.append(row)
        need(row['ordinal']==index and row['RSS_cap_KiB']==393216 and row['proc_status_errors']==[] and
             row['RSS_guard_method']=='max(/proc/self/status VmRSS, VmHWM)' and
             row['ru_maxrss_diagnostic_only'],'Actual unchanged current-mm phase guard')
        current=max(row['proc_status']['VmRSS_KiB'],row['proc_status']['VmHWM_KiB'])
        need(current==row['guarded_post_exec_current_mm_KiB'] and current<=393216 and
             priorbytes<=row['IMG_bytes_read']<=160000000 and priorops<=row['IMG_read_ops'],'Every actual guard/counter observation')
        maxguard=max(maxguard,current);maxru=max(maxru,row['ru_maxrss_KiB'])
        priorbytes=row['IMG_bytes_read'];priorops=row['IMG_read_ops']
        if row['phase']=='extracted helper global preflight before any image open':
            need(row['IMG_bytes_read']==0 and row['source_handle_open'] is False,'Runtime preflight before source image open')
            preflight_rows.append(row['detail'])
    need(len(rows)==artifact['rows']==251 and rows[0]['IMG_bytes_read']==0 and not rows[0]['source_handle_open'] and
         rows[-1]==artifact['last_observation'] and rows[-1]['IMG_bytes_read']==149290500 and
         not rows[-1]['source_handle_open'] and maxguard==105872 and maxru==424240 and
         preflight_rows==[preflight['helpers'],preflight['mapper']],'Phase EOF, runtime preflight, peak and final handle evidence')
    memory=proof['actual_RSS_measurement']
    need(memory['cap_KiB']==393216 and memory['current_mm_RSS_and_HWM_enforced'] and
         memory['inherited_ru_maxrss_diagnostic_only'] and
         memory['actual_max_observed']['guarded_post_exec_current_mm_KiB']==maxguard,'Actual105872KiB current-mm peak under unchanged cap')
    helper=Path(__file__).resolve();helper_data=helper.read_bytes();helperstat=st(helper)
    audit=save('actual-output-closure-proof.json',{
        'schema':'garmin-current-mm-v5-completed-small-output-closure/v1',
        'created_utc':datetime.now(timezone.utc).isoformat(),'all_assigned_output_closure_checks_passed':True,
        'actual_root_analyzer_exit_code':0,'actual_root_terminal_chunk':args.terminal_chunk,
        'actual_producer_proof_sha256':PROOF_SHA,'producer_kept_original_v4_proof_schema':True,
        'source_and_prepared_pin_inputs':INPUTS,'static_source_AST_binding':binding,
        'AST_identity_checks_are_not_independent_V5_graph_review':True,
        'root_actual_preflight_helpers_and_mapper_before_IMG_open':True,
        'actual_IMG_bytes_read':149290500,'actual_IMG_read_ops':18377,'actual_MDR_bytes':149220356,'actual_MDR_SHA256':MDR_SHA,
        'actual_current_mm_peak_KiB':maxguard,'RSS_cap_KiB':393216,'historical_ru_maxrss_diagnostic_KiB':maxru,
        'stock_prefix_retained_lower_counts':stock['retained_total_lower_counts'],
        'stock_prefix_removed_lower_counts':stock['structurally_unreferenced_postprefix_records'],
        'stock_prefix_projected_4K_IMG_bytes':137170944,'original4K_capacity':134217728,'stock_prefix_exceeds_capacity_by':2953216,
        'stock_prefix_parent_first_fields_to_remap':36617,'stock_prefix_L3_roots_to_remap':19077,
        'whole_v2_prefix_projected_4K_IMG_bytes':153337856,'both_plans_fit4K':False,'no_observed_anomalies_or_force_all':True,
        'force_all_or_anomaly_range_census_caveat_remains_in_general':True,
        'external_lower_ID_consumers_and_live_UI_continuity_still_unknown':True,
        'no_compact_IMG_fix_renderer_install_or_acceptance_result':True,
        'source_full_stat_inherited_unchanged':candidate['stat_before'],
        'source_handle_closed':True,'closure_IMG_largeledger_algorithm_guest_audio_or_device_reads':0,
        'closure_helper':{'path':str(helper.relative_to(ROOT)),'bytes':len(helper_data),'sha256':sha(helper_data),
                          'stat_before':helperstat,'stat_after':st(helper)},'all_own_handles_closed':True})
    note=('V5 actual c4d30e EXIT0 completed the single149220356B MDR read and RAM feasibility analysis. '
          'Total actual IMG149290500B/18377 reads; current-mm peak105872KiB under393216KiB.\n\n'
          'Stock-prefix+active plan retains L4/L5/L6=3889829/3074293/2062771; removes1006407/3552/0. '
          'Its projected4K IMG137170944B exceeds original134217728B capacity by2953216B. '
          'Whole-V2-prefix plan retains all records and projects153337856B. Neither fits.\n\n'
          'No observed unknown flag/range anomaly or force_all occurred. Source/prepared bytes and '
          'Observer AST are pinned; eight core helper ASTs and mapper match producer bindings. These '
          'are static closure identity checks, not an independent V5 graph/runtime review. '
          'External lower-ID consumer/caches/live-query relocation remains unknown. No compact IMG, '
          'renderer fix, UI or install acceptance is claimed. No IMG was reopened for closure.\n')
    with (HERE/'HANDOFF.md').open('xb') as f:f.write(note.encode());f.flush();os.fsync(f.fileno())
    files=[];total=0
    for p in sorted(HERE.iterdir()):
        need(p.is_file() and not p.is_symlink(),'Only complete regular small outputs')
        total+=p.stat().st_size;need(total<=CAP,'Complete namespace under1MiB')
        if p.name not in ('observed_analyzer.py','prepared-source.json','actual-root-tool-receipts.json') and p.stat().st_mode&0o777!=0o444:p.chmod(0o444)
        dat,item=read(p);need(p.stat().st_mode&0o777==0o444,'Complete sealed output mode0444')
        files.append({'path':item['path'],'bytes':len(dat),'sha256':sha(dat),'mode':'0444','stat_at_seal':st(p)})
    need(st(HERE/'observed_analyzer.py')==sourceitem['stat_before'] and
         st(HERE/'prepared-source.json')==prepitem['stat_before'] and
         st(HERE/'actual-root-tool-receipts.json')==receiptitem['stat_before'],
         'Original source/preparation/actual root receipt full stat preserved')
    for item in INPUTS:
        if Path(ROOT/item['path']) in (V4,RAM,MAPPER):need(st(ROOT/item['path'])==item['stat_before'],'Closed external source/helper stats unchanged')
    need(st(helper)==helperstat,'Own helper stat unchanged')
    seal_obj={'schema':'garmin-current-mm-v5-completed-data-output-seal/v1',
              'all_assigned_output_closure_checks_passed':True,'actual_analyzer_exit_code':0,'actual_terminal_chunk':args.terminal_chunk,
              'source_sha256':SOURCE_SHA,'source_and_prepared_full_stat_unchanged':True,'actual_producer_proof_sha256':PROOF_SHA,
              'actual_output_closure_proof':audit,'files':files,'file_count':len(files),'bytes_before_seal':total,
              'all_source_and_own_handles_closed':True,'no_IMG_or_algorithm_or_guest_or_device_reopened':True,
              'both_projected4K_plans_do_not_fit':True,'compact_or_renderer_or_UI_install_ready':False,
              'static_AST_bindings_do_not_claim_independent_V5_review':True}
    raw=(json.dumps(seal_obj,ensure_ascii=False,indent=2)+'\n').encode()
    need(total+len(raw)<=CAP,'Final output seal included in1MiB budget')
    seal=save('sealed-files.json',seal_obj);(HERE/'sealed-files.json').chmod(0o444)
    print(json.dumps({'all_assigned_output_closure_checks_passed':True,'actual_root_exit_code':0,'actual_root_terminal':'c4d30e',
                      'actual_output_closure_proof_sha256':audit['sha256'],'sealed_files_sha256':seal['sha256'],
                      'file_count':len(files),'namespace_bytes_including_seal':total+seal['bytes'],
                      'stock_plan_exceeds4K_by2953216B':True,'no_IMG_or_algorithm_reopened':True,'all_handles_closed':True}))


if __name__=='__main__':main()
