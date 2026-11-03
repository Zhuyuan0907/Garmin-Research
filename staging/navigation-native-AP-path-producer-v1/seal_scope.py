#!/usr/bin/env python3
"""Seal finite static path producer observations; no original binaries are opened."""
from pathlib import Path
import hashlib
import json
import os

ROOT = Path('/root/garmin')
HERE = Path(__file__).resolve().parent

def sha(b):
    return hashlib.sha256(b).hexdigest()

def stat(p):
    s = p.stat()
    return [s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]

def save(n,d):
    assert not (HERE/n).exists(), n
    (HERE/n).write_text(json.dumps(d,ensure_ascii=False,indent=2)+'\n')

def main():
    assert not (HERE/'sealed-files.json').exists()
    proof = json.loads((HERE/'proof.json').read_bytes())
    assert proof['all_assigned_checks_passed'] and proof['new_MAIN_read_bytes']==5434
    assert proof['IMG_read_bytes']==proof['CPU_cases']==0
    assert not proof['AP_filename_to_mapping_caller_closed']
    pins = json.loads((HERE/'input-bindings.json').read_bytes())
    for row in pins['files']:
        p = ROOT/row['path']
        assert stat(p)==row['stat']
        b = p.read_bytes()
        assert len(b)==row['bytes'] and sha(b)==row['sha256']
        assert stat(p)==row['stat']
    ledger = json.loads((HERE/'read-ledger.json').read_bytes())
    assert stat(ROOT/'evidence/firmware-analysis/main_02bd.bin')==ledger['MAIN_stat']
    save('actual-tool-receipts.json',dict(schema='finite-AP-path-static-actual-tool-receipts/v1',
      MAIN_capture_runs=[
       dict(chunk_id='6efdca',exit_code=0,tag='directproducer',actual_MAIN_bytes=1008),
       dict(chunk_id='236940',exit_code=0,tag='APliteral',actual_MAIN_bytes=2048),
       dict(chunk_id='ea9032',exit_code=0,tag='APpathliteral',actual_MAIN_bytes=1796),
       dict(chunk_id='83847d',exit_code=0,tag='APobject',actual_MAIN_bytes=304),
       dict(chunk_id='a09579',exit_code=0,tag='APpathtail',actual_MAIN_bytes=160),
       dict(chunk_id='c27a43',exit_code=0,tag='namedfields',actual_MAIN_bytes=118)],
      audit_runs=[
       dict(chunk_id='ebfabc',exit_code=1,source='finalize_static_initial_length_failure.py',
        source_sha256=sha((HERE/'finalize_static_initial_length_failure.py').read_bytes()),
        reason='UTF16 AP basename length incorrectly hardcoded26 instead of28; byte assertion failed before derived proof outputs'),
       dict(chunk_id='88a8a0',exit_code=0,source='finalize_static.py',source_sha256=sha((HERE/'finalize_static.py').read_bytes()),
        proof_sha256=sha((HERE/'proof.json').read_bytes()),witnesses=5,actual_MAIN_bytes=5434,IMG_bytes=0,CPU_cases=0)],
      source_preservation_receipt=dict(chunk_id='9256ac',exit_code=0),
      bounded_host_inspection_chunks=['d8529c','b1459a','2aeb3e','f53d54','05625d','831bf6','0e823c',
        '49097c','5126eb','9f1314','6613e5','c82071','d29309','1d5c3d'],
      truncated_console_output_not_used_as_complete_source=True,
      pinned_source_JSON_and_exact_selected_raw_bytes_used=True,
      no_IMG_MAIN_fullhash=True,old_guest_suite_reruns=0,CPU_execution=0,
      device_license_token_UNL_audio_access=False,all_original_handles_closed=True))
    save('sealer-receipt.json',dict(schema='finite-static-source-final-seal-preconditions/v1',
      actual_input_pins_checked=len(pins['files']),all_input_stat_sha_stable=True,
      MAIN_stat_stable=True,MAIN_not_opened_by_sealer=True,IMG_not_opened=True,
      CPU_cases=0,initial_failed_audit_and_corrected_pass_both_preserved=True,
      seal_script_sha256=sha(Path(__file__).read_bytes()),handles_closed=True))
    rows=[]
    for p in sorted(HERE.iterdir()):
        assert p.is_file(),p
        b=p.read_bytes();rows.append(dict(path=str(p.relative_to(ROOT)),bytes=len(b),sha256=sha(b)))
    for p in HERE.iterdir():
        os.chmod(p,0o444)
    for row in rows:
        p=ROOT/row['path'];row.update(stat=stat(p),mode='0o444')
    save('sealed-files.json',dict(schema='finite-AP-path-producer-static-seal/v1',
      all_assigned_checks_passed=True,scope='navigation-native-AP-path-producer-v1',files=rows,
      new_MAIN_bytes=5434,new_MAIN_max=24576,IMG_bytes=0,CPU_cases=0,
      AP_filename_to_live_mapping_closed=False,root_cause_or_renderer_or_v3fix_proven=False,
      immutable_mode='0444',handles_closed=True))
    os.chmod(HERE/'sealed-files.json',0o444)
    for row in rows:
        p=ROOT/row['path'];assert stat(p)==row['stat'] and sha(p.read_bytes())==row['sha256']
    print(json.dumps(dict(result='SEALED finite static path producer scope; physical AP edge missing',
      files=len(rows)+1,mode='0444',proof_sha256=sha((HERE/'proof.json').read_bytes()),
      seal_sha256=sha((HERE/'sealed-files.json').read_bytes()),new_MAIN_bytes=5434,
      IMG_bytes=0,CPU_cases=0,handles_closed=True)))

if __name__=='__main__':
    main()
