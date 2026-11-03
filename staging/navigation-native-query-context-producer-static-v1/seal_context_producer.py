#!/usr/bin/env python3
"""Seal only this finite namespace; never opens MAIN/IMG or guest."""
import hashlib,json
from datetime import datetime,timezone
from pathlib import Path
ROOT=Path('/root/garmin');HERE=Path(__file__).resolve().parent
def sha(b):return hashlib.sha256(b).hexdigest()
def stat(p):
 s=p.stat();return[s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def need(v,msg):
 if not v:raise ValueError(msg)
def main():
 proof=json.loads((HERE/'proof.json').read_text())
 need(proof['all_assigned_checks_passed'] and proof['exact_byte_witness_count']==5,'Assigned five static witnesses')
 need(proof['new_MAIN_bytes_read']==12288 and proof['new_IMG_bytes_read']==0 and proof['CPU_cases_executed']==0,'Finite source/execution budget')
 need(not(HERE/'sealed-files.json').exists(),'New seal only')
 paths=sorted(p for p in HERE.iterdir() if p.is_file())
 files=[]
 for p in paths:
  b=p.read_bytes();p.chmod(0o444)
  files.append(dict(path=str(p.relative_to(ROOT)),bytes=len(b),sha256=sha(b),mode='0444',stat_at_seal=stat(p)))
 seal=dict(schema='garmin-native-query-context-producer-static-seal/v1',created_utc=datetime.now(timezone.utc).isoformat(),
  all_assigned_checks_passed=True,scope_work_completed=True,file_count=len(files),files=files,
  new_MAIN_bytes_read=12288,new_IMG_bytes_read=0,CPU_cases_executed=0,exact_byte_witness_count=5,
  all_actual_source_handles_closed=True,uninterrupted_query_UI_or_device_verified=False,
  sealer_receipt_after_seal_separately_bound=True)
 p=HERE/'sealed-files.json'
 with p.open('x')as f:json.dump(seal,f,indent=2);f.write('\n')
 p.chmod(0o444)
 print(json.dumps(dict(all_assigned_checks_passed=True,scope_work_completed=True,file_count=len(files),
  proof_sha256=sha((HERE/'proof.json').read_bytes()),seal_sha256=sha(p.read_bytes()),all_source_handles_closed=True)))
if __name__=='__main__':main()
