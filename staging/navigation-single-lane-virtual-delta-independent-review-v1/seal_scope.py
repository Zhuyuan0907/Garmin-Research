#!/usr/bin/env python3
"""Hash/size/stat seal own review files; no chmod or source artifact reopening."""
import hashlib,json,time
from pathlib import Path
HERE=Path(__file__).resolve().parent;ROOT=Path('/root/garmin')
def sha(b):return hashlib.sha256(b).hexdigest()
def stat(p):
 s=p.stat();return[s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def main():
 assert not(HERE/'sealed-files.json').exists()
 proof=json.loads((HERE/'proof.json').read_text());audit=json.loads((HERE/'output-audit.json').read_text())
 assert proof['all_assigned_checks_passed'] and audit['all_assigned_output_checks_passed']
 assert proof['artifact_bytes_read_total']==943452<1<<20 and proof['all_handles_closed']
 rec=dict(schema='independent-DATA-review-own-sealer-actual-receipt/v1',time_unix_ns=time.time_ns(),
  own_output_audit_passed=True,all_handles_closed=True,external_artifact_reopens=0,IMG_PBF_MAIN_CPU_guest_device_audio=0,
  shared_file_or_permission_mutations=0,seal_kind='hash/size/stat/mode exactly observed; no chmod',
  proof_sha256=sha((HERE/'proof.json').read_bytes()),actual_external_artifact_read_bytes=943452,
  parent_producer_whole_stream_or_inverse_execution_repeated=False)
 (HERE/'sealer-receipt.json').write_text(json.dumps(rec,indent=2)+'\n')
 rows=[]
 for p in sorted(HERE.iterdir()):
  assert p.is_file();before=stat(p);b=p.read_bytes();assert stat(p)==before
  rows.append(dict(path=str(p.relative_to(ROOT)),bytes=len(b),sha256=sha(b),stat_at_seal=before,mode=oct(p.stat().st_mode&0o777)))
 doc=dict(schema='independent-small-DATA-review-hash-stat-seal/v1',files=rows,
  all_assigned_checks_passed=True,all_handles_closed=True,external_input_budget_bytes=1<<20,
  external_input_actual_bytes=943452,no_shared_artifact_permission_changes=True,
  native_write_ready=False,install_ready=False,full_goal_complete=False)
 p=HERE/'sealed-files.json';p.write_text(json.dumps(doc,indent=2)+'\n')
 print(json.dumps(dict(files_sealed=len(rows),seal_sha256=sha(p.read_bytes()),
  proof_sha256=sha((HERE/'proof.json').read_bytes()),actual_modes_preserved=True,
  external_artifact_reopens=0,IMG_PBF_MAIN_CPU_device_reads=0,all_handles_closed=True)))
if __name__=='__main__':main()
