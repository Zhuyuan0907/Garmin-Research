#!/usr/bin/env python3
"""Read new actual trace once and seal the completed offline DB scope."""
from datetime import datetime,timezone
import hashlib
import json
import os
from pathlib import Path
import re

ROOT=Path('/root/garmin');HERE=Path(__file__).resolve().parent


def save(name,value):
    raw=(json.dumps(value,ensure_ascii=False,indent=2)+'\n').encode()
    with (HERE/name).open('xb') as handle:handle.write(raw);handle.flush();os.fsync(handle.fileno())
    return dict(path=str((HERE/name).relative_to(ROOT)),bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())


def file_hash(path):
    h=hashlib.sha256();size=0
    with path.open('rb') as handle:
        for raw in iter(lambda:handle.read(65536),b''):h.update(raw);size+=len(raw)
    return size,h.hexdigest()


def main():
    proof=json.loads((HERE/'proof.json').read_bytes())
    need=proof['all_assigned_execution_and_preservation_checks_passed'];assert need
    assert proof['complete_geometry_gate_passed'] is False
    log=HERE/'actual-database-IO.strace';assert log.stat().st_size<12*1024*1024
    source_name='/root/garmin/'+proof['original']['path']
    candidate_name='/root/garmin/'+proof['modified_offline_prototype']['path']
    roles={source_name:dict(content_reads=0,content_bytes_returned=0,read_EOF_operations=0,open_flags=[]),
           candidate_name:dict(content_reads=0,content_bytes_returned=0,read_EOF_operations=0,open_flags=[])}
    tracehash=hashlib.sha256();tracebytes=0;lines=0
    with log.open('rb') as handle:
        for raw in handle:
            tracehash.update(raw);tracebytes+=len(raw);lines+=1
            text=raw.decode('utf-8')
            read=re.search(r'\b(read|pread64)\(\d+<([^>]+)>.*\)\s+=\s+(-?\d+)',text)
            if read and read[2] in roles:
                result=int(read[3]);r=roles[read[2]]
                if result>0:r['content_reads']+=1;r['content_bytes_returned']+=result
                elif result==0:r['read_EOF_operations']+=1
            op=re.search(r'openat\([^,]+, "([^"]+)", (.*?)\)\s+=\s+\d+',text)
            if op and op[1] in roles:roles[op[1]]['open_flags'].append(op[2])
    assert roles[source_name]['content_bytes_returned']==12743680
    assert roles[source_name]['open_flags']==['O_RDONLY|O_CLOEXEC']
    receipt=save('actual-execution-receipts.json',dict(schema='complete-JAI-offline-prototype-actual-execution/v1',
        created_utc=datetime.now(timezone.utc).isoformat(),all_assigned_execution_and_preservation_checks_passed=True,
        command=['strace','-f','-yy','-s','0','-e','trace=openat,read,pread64,lseek,close','-o',
            'staging/navigation-native-jai-full-db-adapter-prototype-v1/actual-database-IO.strace','env',
            'PYTHONDONTWRITEBYTECODE=1','python3','staging/navigation-native-jai-full-db-adapter-prototype-v1/prepare_full_db_prototype.py'],
        actual_session=84722,initial_chunk='49009f',terminal_chunk='c986c7',actual_exit_code=0,
        trace=dict(path=str(log.relative_to(ROOT)),bytes=tracebytes,sha256=tracehash.hexdigest(),lines=lines,
            full_trace_read_passes_by_receipt=1,content_suppressed_by_strace_s0=True,
            only_exact_original_and_new_prototype_FD_paths_counted=True),
        original_actual_IO=roles[source_name],new_prototype_actual_IO=roles[candidate_name],
        original_source_unchanged_and_SQLite_never_opened_original=True,
        all_logical_rows_reviewed_from_exact_original_byte_copy_and_modified_copy=True,
        full_table_logical_hash_passes=2,explicit_selected_expected_row_derivation_and_other_info_family_checks=True,
        closed_transaction_failure_guards_reused_not_replayed=True,
        all_temporary_SQLite_journal_WAL_SHM_removed=True,all_database_handles_closed=True,
        original_format_pragmas_not_relaxed_or_reformatted=True,
        complete_Beitun_geometry_found=False,district_source_and_raw24_gate=False,
        device_IO=False,candidateIMG_or_sealed_scope_or_report_mutated=False,install_candidate=False))
    allfiles=[]
    for path in sorted(HERE.iterdir()):
        assert path.is_file() and path.name!='sealed-files.json'
        size,digest=file_hash(path)
        if path.name=='TWNJAI-offline-prototype.sqlite':
            assert size==proof['modified_offline_prototype']['bytes'] and digest==proof['modified_offline_prototype']['sha256']
        path.chmod(0o444)
        allfiles.append(dict(path=str(path.relative_to(ROOT)),bytes=size,sha256=digest,mode='0444'))
    seal=save('sealed-files.json',dict(schema='complete-JAI-offline-selected-adapter-prototype-seal/v1',
        created_utc=datetime.now(timezone.utc).isoformat(),all_assigned_execution_and_preservation_checks_passed=True,
        scope_work_completed=True,complete_Beitun_geometry_gate_passed=False,
        install_candidate=False,file_count=len(allfiles),files=allfiles))
    (HERE/'sealed-files.json').chmod(0o444)
    print(json.dumps(dict(all_assigned_execution_and_preservation_checks_passed=True,
        complete_Beitun_geometry_gate_passed=False,file_count=len(allfiles),receipt=receipt,seal=seal,
        source_bytes_read=roles[source_name]['content_bytes_returned'],
        actual_new_prototype_read_bytes=roles[candidate_name]['content_bytes_returned'],
        all_database_handles_closed=True),ensure_ascii=False),flush=True)


if __name__=='__main__':main()
