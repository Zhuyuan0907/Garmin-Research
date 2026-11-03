#!/usr/bin/env python3
"""Close only the new bounded prefix/selected-adapter namespace."""
from datetime import datetime,timezone
import hashlib
import json
import os
from pathlib import Path

ROOT=Path('/root/garmin');HERE=Path(__file__).resolve().parent


def sha(raw):return hashlib.sha256(raw).hexdigest()


def save(name,value):
    raw=(json.dumps(value,ensure_ascii=False,indent=2)+'\n').encode()
    with (HERE/name).open('xb') as handle:handle.write(raw);handle.flush();os.fsync(handle.fileno())
    return dict(path=str((HERE/name).relative_to(ROOT)),bytes=len(raw),sha256=sha(raw))


def main():
    proof=json.loads((HERE/'final-proof.json').read_bytes())
    assert proof['all_assigned_checks_passed'] and proof['executed_focused_new_adapter_controls']==8
    reads=json.loads((HERE/'extended-source-read-receipt.json').read_bytes())
    assert reads['actual_bytes_read']==12288 and reads['source_stat_unchanged']
    for row in reads['windows']:
        raw=(HERE/row['saved_file']).read_bytes()
        assert len(raw)==row['bytes'] and sha(raw)==row['sha256']
    receipts=dict(schema='native-JAI-prefix-selected-adapter-actual-receipts/v1',
        created_utc=datetime.now(timezone.utc).isoformat(),all_assigned_checks_passed=True,
        raw_MAIN_capture=[dict(actual_terminal_chunk='dbfeb2',actual_exit_code=0,actual_MAIN_bytes_read=9216),
                          dict(actual_terminal_chunk='554df0',actual_exit_code=0,actual_MAIN_bytes_read=3072)],
        selected_adapter_controls=dict(command=['python3','staging/navigation-native-jai-prefix-consumer-v1/run_adapter_controls.py'],
            environment={'PYTHONDONTWRITEBYTECODE':'1'},actual_terminal_chunk='bba7d8',actual_exit_code=0,
            tool_wall_seconds=0.188833144,focused_controls=8,
            original_DB_opened=False,only_small_multi_table_host_fixtures=True,
            temporary_readonly_fixture_removed=True,closed_suites_replayed=False),
        saved_actual_prefix_name_observation=dict(command=['python3','staging/navigation-native-jai-prefix-consumer-v1/observe_original_dun_prefix_names.py'],
            environment={'PYTHONDONTWRITEBYTECODE':'1'},actual_terminal_chunk='61a535',actual_exit_code=0,
            existing_original_Dun_streets=5,old_queries_or_native_CPU_replayed=False),
        exact_bounded_MAIN_read_receipt='extended-source-read-receipt.json',
        final_proof=dict(path=str((HERE/'final-proof.json').relative_to(ROOT)),bytes=2180,
            sha256='65e62f5a11fc6174062eeb39847eaea75b302f76c1b6be7f1088d4b0fe0e2545'),
        true_native_prefix_case_or_UI_proved=False,device_IO=False,source_PBF_or_addressledger_read=False,
        all_input_handles_closed=True,other_sealed_scope_mutated=False,install_candidate=False)
    receipt=save('actual-receipts.json',receipts)
    files=[]
    for path in sorted(HERE.iterdir()):
        assert path.is_file() and path.name!='sealed-files.json'
        raw=path.read_bytes();path.chmod(0o444)
        files.append(dict(path=str(path.relative_to(ROOT)),bytes=len(raw),sha256=sha(raw),mode='0444'))
    seal=save('sealed-files.json',dict(schema='native-JAI-prefix-selected-adapter-seal/v1',
        created_utc=datetime.now(timezone.utc).isoformat(),all_assigned_checks_passed=True,
        scope='New bounded prefix diagnosis and selected441/1444 adapter only.',files=files,file_count=len(files)))
    (HERE/'sealed-files.json').chmod(0o444)
    print(json.dumps(dict(all_assigned_checks_passed=True,file_count=len(files),seal=seal,
                          receipt=receipt,all_source_handles_closed=True,device_IO=False),ensure_ascii=False),flush=True)


if __name__=='__main__':main()
