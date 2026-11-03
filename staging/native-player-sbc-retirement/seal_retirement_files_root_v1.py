#!/usr/bin/env python3
"""Seal terminal ROOT FILE reconstruction. No VM, device or canonical writes."""
import hashlib,json
from pathlib import Path
from datetime import datetime,timezone
ROOT=Path(__file__).resolve().parents[2]
BASE=Path(__file__).resolve().parent
OUT=BASE/'root-file-review-v3/ROOT-file-reconstruction-seal.json'
def sha(p):
    h=hashlib.sha256()
    with p.open('rb')as f:
        for b in iter(lambda:f.read(8<<20),b''):h.update(b)
    return h.hexdigest()
def read(p):return json.loads((ROOT/p).read_text())
def main():
    assert not OUT.exists(),'Terminal seal already exists; create a NEW source'
    b=str(BASE.relative_to(ROOT))+'/'
    proof=read(b+'root-file-review-v3/ROOT-retirement-six-scope-file-reconstruction.json')
    selected=read(b+'native-retirement-selected-six-scope-v1.json')
    receipt=read(b+'root-file-review-v3/terminal-tool-receipt.json')
    assert proof['all_passed'] and proof['ROOT_FILE_reconstruction'] and proof['case_count']==6
    assert not proof['new_independent_agent_review'] and not proof['VM_import_or_execution']
    assert receipt['terminal'] and receipt['started_session_id']==21617
    assert receipt['actual_terminal_result']['exit_code']==0 and 'session_id'not in receipt['actual_terminal_result']
    assert receipt['actual_terminal_result']['chunk_id']=='d8c9b3'
    terminal=json.loads(receipt['actual_terminal_result']['output'].splitlines()[-1])
    assert terminal['all_passed'] and terminal['totals']==proof['totals']
    assert [c['name']for c in selected['cases']]==[c['name']for c in proof['cases']]
    assert [c['guest_suite_terminal_exit']for c in selected['cases']]==[1,1,1,1,0,0]
    for name,exit_code,completed in [('v1',1,4),('v2',0,2)]:
        r=read(b+'guest-'+name+'-terminal-tool-receipt.json')
        # Receipts retain actual tool result schemas from their respective run.
        assert exit_code in [x.get('exit_code')for x in r.values()if isinstance(x,dict)]or r.get('exit_code')==exit_code
    files=dict(proof['source_sha256'])
    for p in BASE.rglob('*'):
        if p.is_file()and '__pycache__'not in p.parts:
            files[str(p.relative_to(ROOT))]=sha(p)
    for p,h in files.items():assert sha(ROOT/p)==h,p
    d=dict(all_passed=True,ROOT_FILE_reconstruction_complete=True,new_independent_agent_review=False,
        source_sha256=files,selected_case_count=6,totals=proof['totals'],actual_FILE_terminal_receipt=b+'root-file-review-v3/terminal-tool-receipt.json',
        guest_selection='Four completed scopes from EXIT1 prefix, plus two new EXIT0 controls; no guest rerun.',
        preserved_failed_guest_suite=True,preserved_failed_build=True,preserved_two_FILE_reviewer_failures=True,
        physical_original_voice_restored=True,physical_2_10_control_pending=True,
        native_STOP_DONE_heap_exclusive_phone_App_speaker_hardware_drain_safe_unload_verified=False,
        device_IO=False,VM_execution=False,updated_utc=datetime.now(timezone.utc).isoformat())
    with OUT.open('x')as f:json.dump(d,f,indent=2);f.write('\n')
    print(json.dumps(dict(all_passed=True,output=str(OUT.relative_to(ROOT)),output_sha256=sha(OUT),protected_files=len(files),case_count=6,totals=proof['totals'])))
if __name__=='__main__':main()
