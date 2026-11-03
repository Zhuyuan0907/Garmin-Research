#!/usr/bin/env python3
"""Seal this finite capture namespace only; no candidate/source IMG access."""
from pathlib import Path
from datetime import datetime,timezone
import hashlib,json,os

ROOT=Path('/root/garmin'); HERE=Path(__file__).resolve().parent

def sha(raw): return hashlib.sha256(raw).hexdigest()

def main():
    assert not (HERE/'sealed-files.json').exists()
    proof=json.loads((HERE/'proof.json').read_bytes())
    receipts=json.loads((HERE/'actual-execution-receipts.json').read_bytes())
    assert proof['all_assigned_capture_and_plan_checks_passed'] and not proof['first_run_all_guards_passed']
    assert receipts['first_run']['exit_code']==1 and receipts['separate_capture_only_run']['exit_code']==0
    assert proof['first_failed_source_sha256']==sha((HERE/'prepare_control.py').read_bytes())
    assert proof['first_actual_failure_retained']['sha256']==sha((HERE/'failure.json').read_bytes())
    assert proof['combined_IMG_read_upper_bound']<=proof['combined_IMG_read_cap']
    assert proof['all_own_and_IMG_handles_closed'] and not proof['CPU_executed']
    # Fresh output integrity only; no old suite, actual source IMG or source ledger.
    artifacts=list(proof['artifacts'].values())
    capture=json.loads((HERE/'actual-raw-capture-metadata.json').read_bytes())
    artifacts += [r['artifact'] for r in capture['captures'].values()]
    for row in artifacts:
        p=ROOT/row['path']; raw=p.read_bytes()
        assert p.parent==HERE and len(raw)==row['bytes'] and sha(raw)==row['sha256']
    files=[]
    for path in sorted(HERE.iterdir()):
        assert path.is_file() and path.name not in {'sealed-files.json','actual-sealer-receipt.json'}
        path.chmod(0o444); raw=path.read_bytes(); s=path.stat()
        files.append(dict(path=str(path.relative_to(ROOT)),bytes=len(raw),sha256=sha(raw),mode='0444',
            stat_at_seal=[s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]))
    seal=dict(schema='garmin-minimal-lane-finite-capture-seal/v1',created_utc=datetime.now(timezone.utc).isoformat(),
        all_assigned_capture_and_plan_checks_passed=True,first_run_all_guards_passed=False,
        first_failure_retained=True,old_failed_source_or_guard_modified=False,
        control_status='actual membership/capture passed; direct all-zero subtree clone guard failed and retained',
        files=files,file_count=len(files),own_artifact_hashes_verified=True,
        all_own_and_IMG_handles_closed=True,MAIN_bytes_read=0,CPU_executed=False,device_IO=False,
        new_IMG_or_patched_delta_produced=False,source_or_shared_seal_or_report_modified=False,
        renderer_UI_or_device_acceptance_verified=False,full_Taiwan_complete=False)
    raw=json.dumps(seal,ensure_ascii=False,indent=2).encode()+b'\n'
    with (HERE/'sealed-files.json').open('xb') as f:
        f.write(raw); f.flush(); os.fsync(f.fileno())
    (HERE/'sealed-files.json').chmod(0o444)
    print(json.dumps(dict(all_assigned_capture_and_plan_checks_passed=True,first_failure_retained=True,
        sealed_files_sha256=sha(raw),sealed_file_count=len(files),all_own_handles_closed=True)))

if __name__=='__main__': main()
