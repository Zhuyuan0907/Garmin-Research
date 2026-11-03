#!/usr/bin/env python3
"""Close the completed EXIT1 V4 normal-DATA run using small saved evidence only.

Never opens/stat-queries IMG or executes the scanner/algorithm. Preparation
ctime/stat stays unchanged. Only new, unsealed failure outputs are chmodded.
"""
from pathlib import Path
from datetime import datetime, timezone
import argparse
import hashlib
import json
import os

ROOT=Path('/root/garmin')
HERE=ROOT/'staging/navigation-v3-reachable-suffix-compaction-current-mm-v4'
PREPARED_SHA='c280de5f6888ea334a4527d5e03613dd86898db2752eb9ed80f220b0d72e94ef'
SOURCE_SHA='ad46dda03730cab4a73e39346fd597b13bc91604a811147840499a123baa3e04'
FAILURE_SHA='aa5c75b10c4caa86da2aeb88c552943895c9e56952d03d93cf30e4ea6a3bf5ce'
RECEIPT_SHA='ce5bfdddbf19ba9569f8c0ab3cda8462a029ea3b28eade71b209098043a45e26'
CAP=1048576
EXPECTED_COUNTS={1:22,2:343,3:47870,4:4896236,5:3077845,6:2062771}
EXPECTED_TABLE_BYTES={1:336,2:5231,3:670180,4:78339776,5:48476059,6:17533554}


def need(value,message):
    if not value:raise ValueError(message)


def sha(data):return hashlib.sha256(data).hexdigest()


def status(p):
    s=p.stat();return [s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]


def read(p,limit=CAP):
    need(p.parent==HERE and p.is_file() and not p.is_symlink(),'Exact small evidence namespace only')
    before=status(p);need(before[2]<=limit,'Small evidence bound')
    with p.open('rb') as f:
        data=f.read(limit+1);need(f.read(1)==b'','Actual small-file EOF')
    need(len(data)==before[2] and status(p)==before,'Stable full small-file EOF/stat')
    return data,before


def save(name,value):
    p=HERE/name
    data=(json.dumps(value,ensure_ascii=False,indent=2)+'\n').encode()
    need(len(data)<=CAP,'Small closure output bound')
    with p.open('xb') as f:f.write(data);f.flush();os.fsync(f.fileno())
    return {'path':str(p.relative_to(ROOT)),'bytes':len(data),'sha256':sha(data)}


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--terminal-chunk',required=True)
    args=ap.parse_args()
    need(args.terminal_chunk=='f176d1','Only assigned actual EXIT1 terminal')
    need(not (HERE/'sealed-files.json').exists(),'Fresh failed-run closure only')
    prepared_data,prepared_stat=read(HERE/'prepared-files.json')
    need(sha(prepared_data)==PREPARED_SHA,'Exact original prepared seal')
    prepared=json.loads(prepared_data)
    need(prepared['source_sha256']==SOURCE_SHA and prepared['RSS_numeric_cap_KiB']==393216 and
         prepared['IMG_read_cap_bytes']==160000000 and not prepared['normal_DATA_scanner_or_runtime_guard_cases_executed'],
         'Prepared source and unchanged engineering caps')
    prefiles={}
    for item in prepared['files']:
        p=ROOT/item['path'];data,st=read(p)
        need(len(data)==item['bytes'] and sha(data)==item['sha256'] and st==item['stat_at_seal'],
             'Prepared files byte/hash/full-stat identity')
        need(p.stat().st_mode&0o777==0o444,'Prepared modes unchanged')
        prefiles[p.name]=item
    failure_data,failure_stat=read(HERE/'actual-failure.json')
    receipt_data,receipt_stat=read(HERE/'actual-root-tool-receipts.json')
    need(sha(failure_data)==FAILURE_SHA and sha(receipt_data)==RECEIPT_SHA,'Exact saved actual failure/root execution pins')
    failure=json.loads(failure_data);receipt=json.loads(receipt_data)
    need(receipt['terminal'] is True and receipt['actual_final_exit_code']==1 and receipt['actual_session']==50926,
         'Saved root actual session ended EXIT1')
    terminal=receipt['observations'][-1]
    need(terminal['chunk_id']==args.terminal_chunk and terminal['exit_code']==1 and not terminal.get('session_id'),
         'Actual final tool result, not a live session')
    need(failure['schema']=='garmin-current-mm-data-failure-receipt/v4' and
         failure['exception_type']=='NameError' and failure['error']=="name 'sha' is not defined" and
         failure['classification']=='ordinary program exception' and
         failure['tool_platform_or_automatic_review_interruption'] is False,
         'Actual ordinary unresolved extracted-helper dependency; no platform/risk block')
    need(failure['actual_IMG_bytes_read']==149290500 and failure['actual_IMG_read_ops']==18377 and
         failure['actual_read_budget']['read_cap_bytes']==160000000 and
         failure['actual_RSS_guard_threshold_KiB']==393216 and failure['cap_not_raised_or_removed'] is True,
         'Exact actual counters and unchanged caps')
    need(failure['source_handle_closed'] is True and failure['source_stat_before']==failure['source_stat_after'] and
         failure['source_IMG_or_device_or_shared_seal_modified'] is False and
         failure['new_IMG_or_guest_or_audio_executed'] is False and
         failure['retry_or_guard_relaxation'] is False and failure['MDR_table_scan_completed'] is False,
         'Original source and handles stable; incomplete analyzer preserved')
    need(failure['actual_RSS_guard_value_KiB'] is None and failure['historical_ru_maxrss_diagnostic_only'] is True,
         'NameError was not a custom RSS-cap failure')
    rb=failure['actual_read_budget'];purposes=rb['bytes_by_purpose']
    need(sum(purposes.values())==149290500 and
         sum(v for k,v in purposes.items() if k.startswith('single MDR '))==149220356 and
         purposes['single MDR DIR']==120 and rb['whole_IMG_hash_recomputed'] is False,
         'Full physical MDR byte consumption and bounded metadata; no whole-IMG hash repetition')
    stdout_rows=[]
    for observation in receipt['observations']:
        for line in observation['output'].splitlines():
            if line.startswith('{'):
                try:stdout_rows.append(json.loads(line))
                except json.JSONDecodeError:raise ValueError('Malformed actual JSON stdout row')
    tables=[r for r in stdout_rows if r.get('stage')=='single actual table complete']
    need(len(tables)==6 and {r['level']:r['records'] for r in tables}==EXPECTED_COUNTS and
         {r['level']:r['bytes'] for r in tables}==EXPECTED_TABLE_BYTES,'Actual six table counts/bytes printed once each')
    announced=[r for r in stdout_rows if 'actual_program_failure' in r]
    need(len(announced)==1 and announced[0]['actual_program_failure']['sha256']==FAILURE_SHA and
         announced[0]['source_handle_closed'] is True and
         'receipts.append(dict(segment=\'DIR\'' in terminal['output'] and
         "NameError: name 'sha' is not defined" in terminal['output'],
         'Actual saved terminal exception point and failure binding')
    artifact=failure['observations'];phase=ROOT/artifact['path']
    need(phase==HERE/'actual-phase-observations.jsonl','Exact phase ledger path')
    phase_data,phase_stat=read(phase,500000)
    need(sha(phase_data)==artifact['sha256'] and len(phase_data)==artifact['bytes'],'Durable phase SHA/length pin')
    rows=[];maxguard=0;maxru=0;previous_bytes=0;previous_ops=0
    for index,line in enumerate(phase_data.splitlines()):
        row=json.loads(line);rows.append(row)
        need(row['ordinal']==index and row['RSS_cap_KiB']==393216 and
             row['RSS_guard_method']=='max(/proc/self/status VmRSS, VmHWM)' and
             row['ru_maxrss_diagnostic_only'] is True and row['proc_status_errors']==[],
             'Actual ordered durable valid current-mm phases')
        current=max(row['proc_status']['VmRSS_KiB'],row['proc_status']['VmHWM_KiB'])
        need(row['guarded_post_exec_current_mm_KiB']==current and current<=393216,
             'Recorded actual current-mm values below unchanged cap')
        need(previous_bytes<=row['IMG_bytes_read']<=160000000 and previous_ops<=row['IMG_read_ops'],
             'Monotone actual reader counters within cap')
        previous_bytes=row['IMG_bytes_read'];previous_ops=row['IMG_read_ops']
        maxguard=max(maxguard,current);maxru=max(maxru,row['ru_maxrss_KiB'])
    need(len(rows)==artifact['rows']==214 and rows[0]['IMG_bytes_read']==0 and not rows[0]['source_handle_open'] and
         rows[-1]==artifact['last_observation'] and rows[-1]['IMG_bytes_read']==149290500 and
         rows[-1]['IMG_read_ops']==18377 and not rows[-1]['source_handle_open'] and
         maxguard==artifact['actual_max_observed']['guarded_post_exec_current_mm_KiB']==87952 and
         maxru==artifact['actual_max_observed']['ru_maxrss_KiB']==424240,
         'Complete actual phase EOF/counters, peak values and closed final handle')
    need(not (HERE/'proof.json').exists() and not (HERE/'feasibility-summary.json').exists() and
         not (HERE/'actual-stream-read-receipts.json').exists(),'Failed analyzer created no successful returned-stream or graph summary')
    source=Path(__file__).resolve();helper=source.read_bytes();helper_stat=status(source)
    proof=save('failed-run-closure-proof.json',{
        'schema':'garmin-current-mm-v4-actual-failure-closure-proof/v1',
        'created_utc':datetime.now(timezone.utc).isoformat(),
        'all_assigned_failure_closure_checks_passed':True,
        'actual_reachability_analyzer_exit_code':1,'actual_root_terminal_chunk':args.terminal_chunk,
        'actual_failure':{'path':str((HERE/'actual-failure.json').relative_to(ROOT)),
                          'bytes':len(failure_data),'sha256':sha(failure_data)},
        'actual_root_tool_receipts':{'path':str((HERE/'actual-root-tool-receipts.json').relative_to(ROOT)),
                                    'bytes':len(receipt_data),'sha256':sha(receipt_data)},
        'original_prepared_files_sha256':PREPARED_SHA,'analyzer_source_sha256':SOURCE_SHA,
        'all_original_prepared_bytes_and_full_stat_unchanged':True,
        'closure_helper':{'path':str(source.relative_to(ROOT)),'bytes':len(helper),
                          'sha256':sha(helper),'stat_before':helper_stat,'stat_after':status(source)},
        'actual_IMG_bytes_read':149290500,'actual_IMG_read_ops':18377,'IMG_read_cap_bytes':160000000,
        'actual_MDR_physical_bytes_consumed':149220356,'actual_six_table_stdout_counts':tables,
        'actual_phase_ledger':{'path':artifact['path'],'bytes':len(phase_data),'sha256':sha(phase_data),'rows':len(rows)},
        'actual_current_mm_peak_KiB':maxguard,'current_mm_guard_cap_KiB':393216,
        'historical_ru_maxrss_diagnostic_peak_KiB':maxru,'historical_peak_did_not_enforce_guard':True,
        'exception_type':'NameError','exception_message':failure['error'],
        'failure_frontier':'stream_actual DIR-receipt SHA expression, analyze_reachable.py line156',
        'failure_is_memory_shortage_or_platform_risk_block':False,
        'complete_MDR_EOF_and_hash_need_checks_passed':'root terminal report; stream function failed before returning its receipts object',
        'measured_MDR_digest_returned_in_success_stream_artifact':False,
        'stream_actual_returned':False,'reachability_rank_alias_and_capacity_results_produced':False,
        'all_assigned_data_feasibility_checks_completed':False,
        'no_compaction_or_4K_fit_or_fix_or_install_success_claim':True,
        'source_stat_before':failure['source_stat_before'],'source_stat_after':failure['source_stat_after'],
        'source_handle_closed':True,'closure_IMG_source_algorithm_guest_audio_or_device_reads':0,
        'all_own_handles_closed':True,'new_IMG_or_tables_or_remapped_records_created':False,
        'shared_source_IMG_seals_canonical_report_modified':False,
        'next_dependency_repair_and_preflight_is_separate_scope':True})
    note=(
        'V4 unique actual run ended EXIT1/f176d1 after physical MDR consumption149220356B '
        '(total IMG149290500B,18377 reads). All six table counts were printed, but '
        "stream_actual failed at DIR-receipt construction: NameError: name 'sha' is not defined.\n\n"
        'The durable214 phases record current-mm peak87952KiB under393216KiB; '
        'historical ru_maxrss424240KiB was diagnostic only. This is an ordinary '
        'program dependency error, not an RSS-cap or platform-risk interruption. '
        'Source handle is closed and source/prepared full stats remain unchanged.\n\n'
        'No returned stream object, reachability/rank/alias/capacity summary, compact '
        'IMG or4K-fit/install/UI result exists. Root reports that complete MDR '
        'EOF/hash guards preceded the error; the returned stream digest artifact '
        'was not produced. Only small saved evidence was read for this closure. '
        'Repair/preflight and any next single stream belong to a separate scope.\n')
    p=HERE/'HANDOFF-failed-run.md'
    with p.open('xb') as f:f.write(note.encode());f.flush();os.fsync(f.fileno())
    files=[];total=0
    for p in sorted(HERE.iterdir()):
        need(p.is_file() and not p.is_symlink(),'Only bounded regular failure/preparation outputs')
        total+=p.stat().st_size;need(total<=CAP,'Aggregate small source/output budget')
        if p.name not in prefiles and p.name!='prepared-files.json' and p.stat().st_mode&0o777!=0o444:p.chmod(0o444)
        data,st=read(p);files.append({'path':str(p.relative_to(ROOT)),'bytes':len(data),
                                   'sha256':sha(data),'mode':'0444','stat_at_seal':st})
    for name,item in prefiles.items():need(status(HERE/name)==item['stat_at_seal'],'Prepared ctime and full stat preserved')
    need(status(HERE/'prepared-files.json')==prepared_stat and status(source)==helper_stat,
         'Original preparation manifest and closure-helper stat stable')
    seal_obj={'schema':'garmin-current-mm-v4-failed-actual-run-seal/v1',
              'all_assigned_failure_closure_checks_passed':True,
              'actual_analyzer_exit_code':1,'actual_terminal_chunk':args.terminal_chunk,
              'original_prepared_sha256':PREPARED_SHA,'original_prepared_bytes_and_stat_unchanged':True,
              'failure_closure_proof':proof,'files':files,'file_count':len(files),
              'bytes_before_seal':total,'all_source_and_own_handles_closed':True,
              'small_evidence_only_no_IMG_or_algorithm_rerun':True,
              'successful_feasibility_or_compaction_UI_install_claim':False}
    seal_raw=(json.dumps(seal_obj,ensure_ascii=False,indent=2)+'\n').encode()
    need(total+len(seal_raw)<=CAP,'Complete namespace including final seal below1MiB')
    seal=save('sealed-files.json',seal_obj);(HERE/'sealed-files.json').chmod(0o444)
    print(json.dumps({'all_assigned_failure_closure_checks_passed':True,
                      'actual_analyzer_exit_code':1,'actual_terminal_chunk':args.terminal_chunk,
                      'failure_closure_proof_sha256':proof['sha256'],
                      'sealed_files_sha256':seal['sha256'],'file_count':len(files),
                      'namespace_total_bytes_including_seal':total+seal['bytes'],
                      'all_handles_closed':True}))


if __name__=='__main__':main()
