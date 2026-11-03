#!/usr/bin/env python3
"""Small-only output closure after root supplies the completed actual receipt.

Never opens source IMG, source ledgers, old algorithms or native code. The
prepared-source stat is kept exact; chmod applies only to new output files.
"""
from pathlib import Path
from datetime import datetime,timezone
import argparse
import hashlib
import json
import os
import stat as statmod

ROOT=Path('/root/garmin')
OUTPUT=ROOT/'staging/navigation-v3-reachable-suffix-compaction-current-mm-v4'
PREPARED_SHA='c280de5f6888ea334a4527d5e03613dd86898db2752eb9ed80f220b0d72e94ef'
SOURCE_SHA='ad46dda03730cab4a73e39346fd597b13bc91604a811147840499a123baa3e04'
MDR_SHA='b23a67f80ad4275b40faf15fd12ac02e32c34d359108489d51404c9791a657d1'
IMG_SHA='1f468eb78cc1268951873c82ffce4abe3292dcece69c0eee405c5d7aca3cc360'
CAP=1<<20


def need(value,message):
    if not value:raise ValueError(message)


def sha(raw):return hashlib.sha256(raw).hexdigest()


def status(p):
    s=p.stat()
    return [s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]


def read(p,limit=CAP):
    need(p.parent==OUTPUT and not p.is_symlink() and p.is_file(),'Only exact output-namespace small regular files')
    before=status(p);need(before[2]<=limit,'Small output bound')
    with p.open('rb') as f:
        raw=f.read(limit+1);need(f.read(1)==b'','Actual complete small output EOF')
    need(len(raw)==before[2] and status(p)==before,'Stable full small-file read/stat')
    return raw,before


def save(name,row):
    p=OUTPUT/name;raw=json.dumps(row,ensure_ascii=False,indent=2).encode()+b'\n'
    need(len(raw)<CAP,'Bounded closure JSON')
    with p.open('xb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
    return dict(path=str(p.relative_to(ROOT)),bytes=len(raw),sha256=sha(raw))


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--receipt',required=True,help='Saved final actual root exec/write_stdin tool-result JSON in output namespace')
    ap.add_argument('--receipt-sha256',required=True)
    ap.add_argument('--terminal-chunk',required=True)
    args=ap.parse_args()
    need(not (OUTPUT/'sealed-files.json').exists(),'Fresh actual-output closure only')
    rp=Path(args.receipt).resolve()
    need(rp.parent==OUTPUT and len(args.receipt_sha256)==64,'Exact namespace and root supplied receipt pin')
    raw,rs=read(rp);need(sha(raw)==args.receipt_sha256,'Actual execution receipt identity')
    execution=json.loads(raw)
    need(execution.get('exit_code')==0 and execution.get('chunk_id')==args.terminal_chunk,
         'Root supplied exact completed terminal and EXIT0; live session is not completion')
    need(not execution.get('session_id'),'Final tool receipt must not still report a running session')
    execution_input=dict(path=str(rp.relative_to(ROOT)),bytes=len(raw),sha256=sha(raw),stat_before=rs,stat_after=status(rp))
    prepared_raw,prepared_stat=read(OUTPUT/'prepared-files.json')
    need(sha(prepared_raw)==PREPARED_SHA,'Original prepared-seal exact pin')
    prepared=json.loads(prepared_raw)
    need(prepared['all_assigned_source_preparation_and_static_checks_passed'] and
         not prepared['normal_DATA_scanner_or_runtime_guard_cases_executed'],'Original preparation scope intact')
    prefiles={}
    for row in prepared['files']:
        p=ROOT/row['path'];data,st=read(p)
        need(len(data)==row['bytes'] and sha(data)==row['sha256'] and st==row['stat_at_seal'],
             'Original prepared source/doc bytes and full stat unchanged')
        need(p.stat().st_mode&0o777==0o444,'Original prepared modes remain0444')
        prefiles[p.name]=dict(row)
    need(prefiles['observed_analyzer.py']['sha256']==SOURCE_SHA,'Exact independently reviewed V4 source')
    inputs=[execution_input]
    def obj(name):
        data,st=read(OUTPUT/name);inputs.append(dict(path=str((OUTPUT/name).relative_to(ROOT)),bytes=len(data),sha256=sha(data),
            stat_before=st,stat_after=status(OUTPUT/name)))
        return json.loads(data)
    proof=obj('proof.json')
    need(proof['schema']=='garmin-v3-current-mm-reachability-proof/v4' and
         proof['all_assigned_data_feasibility_checks_completed'],'Completed actual data proof')
    need(proof['actual_IMG_read_bytes']<=160000000 and proof['actual_IMG_read_cap']==160000000 and
         proof['one_actual_MDR_stream_bytes']==149220356 and proof['actual_MDR_hash_matches_sealed_complete_readback'] and
         proof['whole_IMG_hash_not_repeated'],'Single bounded actual MDR stream and unchanged read cap')
    memory=proof['actual_RSS_measurement']
    need(memory['cap_KiB']==393216 and memory['unit']=='Linux KiB' and
         memory['method']=='max(/proc/self/status VmRSS, VmHWM)' and
         memory['current_mm_RSS_and_HWM_enforced'] and memory['inherited_ru_maxrss_diagnostic_only'],
         'Actual393216KiB current-mm guard, historical rusage diagnostic only')
    need(memory['actual_max_observed']['guarded_post_exec_current_mm_KiB']<=393216,
         'Every actual completed guarded current-mm observation stayed below cap')
    need(proof['all_own_and_source_handles_closed'] and not proof['source_candidate']['handle_closed'] is False,
         'Producer and actual source handle closure')
    candidate=proof['source_candidate']
    need(candidate['bytes']==153346048 and candidate['inherited_whole_sha256']==IMG_SHA and
         candidate['stat_before']==candidate['stat_after'],'Actual source pin and immutable stat inherited; no IMG open here')
    need(proof['actual_original_stock_counts']=={'4':2133948,'5':2341096,'6':1973316} and
         proof['actual_current_profile']=={'L3_first_width':23,'L3_stride':112,'L3_count':47870,'lower_strides':[128,126,68]},
         'Exact stock-preservation counts and current profile')
    need(proof['MAIN_CPU_guest_PBF_bigsourceledger_audio_or_device_IO']==0 and
         proof['new_IMG_or_fulltables_or_remapped_records_created'] is False and
         proof['source_IMG_or_seals_report_canonical_modified'] is False,
         'Assigned normal data scope boundaries')
    stream=obj('actual-stream-read-receipts.json');summary=obj('feasibility-summary.json')
    sb=stream['read_budget'];sd=stream['stream']
    need(sb['actual_IMG_bytes_read']==proof['actual_IMG_read_bytes'] and sb['read_cap_bytes']==160000000 and
         sd['streamed_bytes']==149220356 and sd['actual_MDR_SHA256']==MDR_SHA and
         not sb['whole_IMG_hash_recomputed'],'Actual small stream receipt/EOF/component pin')
    need(stream['actual_input_handle_closed'] and stream['source_stat_before']==stream['source_stat_after']==candidate['stat_before'],
         'Actual rb source stat/handle scope')
    for key in ('stock_prefix_plus_active','current_v2_prefix_plus_active'):
        result=summary[key]
        need(result['all_L3_roots']==47870 and result['original_prefix_IDs_unchanged'] and
             result['L3_IDs_and_JAI_record_keys_unchanged'] and
             not result['GMP_or_other_five_components_changed'] and
             not result['native_context_renderer_UI_or_install_ready'],'Graph summary scope and IDs preservation')
        # This audits existing arithmetic/flags only, never traverses tables or
        # reruns ranks/aliases. Root must retain force_all/census qualifications.
        need(result['arithmetic']['declared_original_4K_capacity']==134217728,'Original4K capacity stated precisely')
    need(summary['all47870_L3_IDs_and_JAI_keys_preserved'] and summary['all_stock_lower_prefix_IDs_preserved'] and
         not summary['external_lower_record_reference_ABIs_proven_absent'] and
         not summary['actual_native_UI_renderer_or_physical_installation_verified'],'External consumer and acceptance limits')
    observed_art=proof['artifacts']['observations'];phase_path=ROOT/observed_art['path']
    phasedata,phasestat=read(phase_path,500000)
    need(sha(phasedata)==observed_art['sha256'] and len(phasedata)==observed_art['bytes'],'Durable phase ledger output hash pin')
    count=0;maxguard=0;first=None;last=None
    for line in phasedata.splitlines():
        row=json.loads(line);count+=1
        need(row['RSS_cap_KiB']==393216 and row['RSS_guard_method']=='max(/proc/self/status VmRSS, VmHWM)' and
             row['ru_maxrss_diagnostic_only'] and not row['proc_status_errors'],'Every actual durable phase has valid unchanged guard')
        value=max(row['proc_status']['VmRSS_KiB'],row['proc_status']['VmHWM_KiB'])
        need(row['guarded_post_exec_current_mm_KiB']==value and value<=393216,'Actual phase current-mm values/cap')
        maxguard=max(maxguard,value)
        if first is None:first=row
        last=row
    need(count==observed_art['rows'] and maxguard==memory['actual_max_observed']['guarded_post_exec_current_mm_KiB'] and
         first['IMG_bytes_read']==0 and not first['source_handle_open'] and
         last['IMG_bytes_read']==proof['actual_IMG_read_bytes'] and not last['source_handle_open'],
         'Complete phase EOF/count, actual counter and closed final source handle')
    need(status(phase_path)==phasestat,'Phase ledger immutable after bounded pass')
    inputs.append(dict(path=str(phase_path.relative_to(ROOT)),bytes=len(phasedata),rows=count,sha256=sha(phasedata),
        stat_before=phasestat,stat_after=status(phase_path),EOF_verified=True))
    audit=save('actual-output-audit.json',dict(schema='garmin-current-mm-v4-small-output-closure-audit/v1',
        created_utc=datetime.now(timezone.utc).isoformat(),all_assigned_completed_output_closure_checks_passed=True,
        completed_actual_root_exit_code=0,terminal_chunk=args.terminal_chunk,actual_root_execution_receipt=execution_input,
        source_sha256=SOURCE_SHA,original_prepared_seal_sha256=PREPARED_SHA,
        all_original_prepared_file_bytes_and_stat_unchanged=True,small_completed_output_inputs=inputs,
        actual_IMG_read_bytes=proof['actual_IMG_read_bytes'],actual_MDR_stream_bytes=149220356,
        actual_max_current_mm_KiB=maxguard,diagnostic_historical_ru_maxrss_KiB=memory['actual_max_observed'].get('ru_maxrss_KiB'),
        actual_phase_rows=count,source_handle_closed_proved_by_completed_proof_and_final_phase=True,
        stock_prefix_plan=dict(retained_total_lower_counts=summary['stock_prefix_plus_active']['retained_total_lower_counts'],
            arithmetic=summary['stock_prefix_plus_active']['arithmetic'],
            anomalies=summary['stock_prefix_plus_active']['invalid_or_unclassified_child_encoding_counts'],
            force_all=summary['stock_prefix_plus_active']['any_unknown_or_invalid_encoding_forced_all_lower_suffix_retention']),
        whole_v2prefix_plan=dict(retained_total_lower_counts=summary['current_v2_prefix_plus_active']['retained_total_lower_counts'],
            arithmetic=summary['current_v2_prefix_plus_active']['arithmetic'],
            anomalies=summary['current_v2_prefix_plus_active']['invalid_or_unclassified_child_encoding_counts'],
            force_all=summary['current_v2_prefix_plus_active']['any_unknown_or_invalid_encoding_forced_all_lower_suffix_retention']),
        alias_complete_not_standalone_if_force_all_or_anomalies=True,external_lower_ID_reference_ABIs_unknown=True,
        phase_and_summary_reads_only=True,IMG_or_bigsource_or_algorithm_guest_or_device_read_or_rerun=False,
        native_UI_renderer_fix_install_or_acceptance_certified=False))
    files=[]
    total=0
    for p in sorted(OUTPUT.iterdir()):
        need(p.is_file() and not p.is_symlink(),'Only small complete output files, no tempdirs or symlinks')
        total+=p.stat().st_size;need(total<=CAP,'Total output/source receipts remainunder1MiB')
        # Never chmod original presealed preparation/source, even to same mode.
        if p.name not in prefiles and p.name!='prepared-files.json' and p.stat().st_mode&0o777!=0o444:p.chmod(0o444)
        data,st=read(p);files.append(dict(path=str(p.relative_to(ROOT)),bytes=len(data),sha256=sha(data),mode='0444',stat_at_seal=st))
    for name,row in prefiles.items():need(status(OUTPUT/name)==row['stat_at_seal'],'Prepared stat still unchanged after sealing outputs')
    need(status(OUTPUT/'prepared-files.json')==prepared_stat,'Prepared manifest ctime/stat unchanged')
    seal=save('sealed-files.json',dict(schema='garmin-current-mm-v4-actual-data-output-seal/v1',
        all_assigned_completed_output_closure_checks_passed=True,actual_root_program_exit_code=0,
        actual_root_terminal_chunk=args.terminal_chunk,source_sha256=SOURCE_SHA,original_prepared_sha256=PREPARED_SHA,
        source_preparation_bytes_and_stat_unchanged=True,actual_data_proof_input_sha256=inputs[1]['sha256'],
        output_audit=audit,files=files,file_count=len(files),total_input_and_output_bytes=total,
        all_actual_source_and_own_handles_closed=True,no_IMG_or_algorithm_or_guest_or_device_reopened=True,
        force_all_census_and_external_lowerrefs_limits_preserved=True,UI_renderer_or_install_ready=False,
        no_IMG_or_records_generated=True))
    (OUTPUT/'sealed-files.json').chmod(0o444)
    print(json.dumps(dict(all_assigned_completed_output_closure_checks_passed=True,actual_exit_code=0,
        actual_root_terminal=args.terminal_chunk,output_audit_sha256=audit['sha256'],sealed_files_sha256=seal['sha256'],
        file_count=len(files),source_preparation_stat_unchanged=True,all_handles_closed=True)))


if __name__=='__main__':main()
