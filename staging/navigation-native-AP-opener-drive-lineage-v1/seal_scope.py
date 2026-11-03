#!/usr/bin/env python3
"""Close this finite static scope, preserving exact tool receipts and immutable inputs."""
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
    return [s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns]

def write(n, d):
    p = HERE / n
    assert not p.exists(), n
    p.write_text(json.dumps(d, ensure_ascii=False, indent=2) + '\n')

def main():
    assert not (HERE / 'sealed-files.json').exists()
    proof = json.loads((HERE/'proof.json').read_bytes())
    audit = json.loads((HERE/'audit.json').read_bytes())
    assert proof['all_assigned_checks_passed'] and audit['all_assigned_static_checks_passed']
    assert proof['new_MAIN_read_bytes'] == 2260 and proof['IMG_read_bytes'] == proof['CPU_cases'] == 0
    # Final evidence-only immutable-input check. Never open MAIN or an IMG.
    checked = []
    for n in ['input-bindings.json', 'additional-input-bindings.json']:
        for row in json.loads((HERE/n).read_bytes())['files']:
            p = ROOT / row['path']
            assert stat(p) == row['stat']
            b = p.read_bytes()
            assert sha(b) == row['sha256'] and len(b) == row['bytes']
            assert stat(p) == row['stat']
            checked.append(row['path'])
    ledger = json.loads((HERE/'read-ledger.json').read_bytes())
    assert stat(ROOT/'evidence/firmware-analysis/main_02bd.bin') == ledger['MAIN_stat']
    write('actual-tool-receipts.json', dict(schema='finite-static-scope-actual-tool-receipts/v1',
      source='actual exec_command results in this task; no simulated exit status',
      MAIN_capture_runs=[
        dict(chunk_id='b9099a', exit_code=0, source='capture_windows.py', tag='APinventory', actual_MAIN_bytes=928),
        dict(chunk_id='bd402e', exit_code=0, source='capture_windows.py', tag='APsource', actual_MAIN_bytes=824),
        dict(chunk_id='7b4693', exit_code=0, source='capture_windows.py', tag='FILEdrive', actual_MAIN_bytes=424),
        dict(chunk_id='e179c1', exit_code=0, source='capture_windows.py', tag='drivegetter', actual_MAIN_bytes=84),
      ],
      final_static_audit=dict(chunk_id='16ed4f', exit_code=0, source='finalize_static.py',
          source_sha256=sha((HERE/'finalize_static.py').read_bytes()), verified_input_files=44,
          exact_witnesses=5, actual_MAIN_bytes=2260, IMG_bytes=0, CPU_cases=0,
          proof_sha256='97829b32857916e86a510012d5dedc8942b5c10f08ee5e21abf1df398742ae1a'),
      host_static_inspection_chunks=['dbdb1a','28d403','a815a7','a928b8','f2f6b0','748cac','0f43c1',
       '0fe5e9','11cb19','f082e1','4caa9d','91730e','b54ffc','591346','8d58b4','454c0d','cb3fce','14a0d1',
       'c5656c','165c87','c94df7','07f5d0','a2639b','200835','048a8e','9d5c5d','0a1b47','247bc0','e2ffb6',
       'dd35ea','1f5d56','c1e47b','7d0a36','6bc0e6'],
      host_inspection_notes=['Some console results were truncated; raw evidence JSON remains pinned and final audit reads every selected anchor.',
       '048a8e rg printed missing old input-bindings.json path; pipeline exit0, no evidence derived from that missing file.',
       'Heuristic names2D40FC/11215E/111E0A were disproved; preserved captures and errata document this.'],
      closed_suite_execution=False, new_guest_execution=False, physical_device_access=False,
      no_MAIN_or_IMG_full_hash=True, all_read_handles_closed=True))
    write('sealer-receipt.json', dict(schema='finite-static-sealing-preconditions/v1',
      seal_script_sha256=sha(Path(__file__).read_bytes()), actual_final_input_files_checked=len(checked),
      inputs_stat_and_sha256_stable=True, MAIN_stat_stable=True, MAIN_bytes_not_opened=True,
      IMG_not_opened=True, CPU_not_executed=True, all_handles_closed=True,
      scope='navigation-native-AP-opener-drive-lineage-v1', shared_inputs_untouched=True))
    files = []
    for p in sorted(HERE.iterdir()):
        assert p.is_file(), str(p)
        b = p.read_bytes()
        files.append(dict(path=str(p.relative_to(ROOT)), bytes=len(b), sha256=sha(b)))
    for p in HERE.iterdir():
        os.chmod(p, 0o444)
    for row in files:
        p = ROOT / row['path']
        row['stat'] = stat(p)
        row['mode'] = '0o444'
        assert p.stat().st_mode & 0o777 == 0o444
    seal = dict(schema='finite-native-static-scope-sealed-files/v1',
      all_assigned_checks_passed=True, AP_opener_to_production_storage_closed=False,
      root_cause_proven=False, renderer_or_admission_success=False,
      scope='navigation-native-AP-opener-drive-lineage-v1', files=files,
      handles_closed=True, immutable_mode='0444', new_MAIN_bytes=2260, IMG_bytes=0, CPU_cases=0)
    write('sealed-files.json', seal)
    os.chmod(HERE/'sealed-files.json', 0o444)
    for row in files:
        p = ROOT / row['path']
        assert stat(p) == row['stat'] and sha(p.read_bytes()) == row['sha256']
    print(json.dumps(dict(result='SEALED finite static scope, AP opener gap explicit',
      files=len(files)+1, all_mode='0444', proof_sha256=sha((HERE/'proof.json').read_bytes()),
      seal_sha256=sha((HERE/'sealed-files.json').read_bytes()), MAIN_bytes=2260, IMG_bytes=0,
      CPU_cases=0, handles_closed=True)))

if __name__ == '__main__':
    main()
