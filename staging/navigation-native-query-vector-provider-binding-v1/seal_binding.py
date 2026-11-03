#!/usr/bin/env python3
import hashlib,json,os
from pathlib import Path
from datetime import datetime,timezone
HERE=Path(__file__).resolve().parent;ROOT=Path('/root/garmin')
def sha(b):return hashlib.sha256(b).hexdigest()
def main():
 proof=json.loads((HERE/'proof.json').read_bytes())
 assert proof['all_assigned_checks_passed']and proof['new_MAIN_bytes_read']==32768
 assert proof['new_IMG_bytes_read']==0 and proof['guest_cases_executed']==0
 assert proof['all_actual_source_handles_closed'] and not proof['held']['query_to_getter_uninterrupted']
 expected=proof['original_MAIN_stat_after'];s=(ROOT/'evidence/firmware-analysis/main_02bd.bin').stat()
 assert [s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]==expected
 assert not (HERE/'sealed-files.json').exists()
 rows=[]
 for p in sorted(HERE.iterdir()):
  assert p.is_file() and not p.is_symlink()
  raw=p.read_bytes();p.chmod(0o444);s=p.stat()
  rows.append(dict(path=str(p.relative_to(ROOT)),bytes=len(raw),sha256=sha(raw),mode='0444',stat_at_seal=[s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]))
 seal=dict(schema='garmin-native-query-vector-provider-binding-seal/v1',created_utc=datetime.now(timezone.utc).isoformat(),all_assigned_checks_passed=True,scope_work_completed=True,file_count=len(rows),files=rows,all_actual_source_handles_closed=True,guest_cases_executed=0,new_MAIN_bytes_read=32768,new_IMG_bytes_read=0,receipt_after_seal_is_separately_bound=True)
 p=HERE/'sealed-files.json'
 with p.open('x')as f:json.dump(seal,f,ensure_ascii=False,indent=2);f.write('\n')
 p.chmod(0o444)
 print(json.dumps(dict(all_assigned_checks_passed=True,file_count=len(rows),proof_sha256=sha((HERE/'proof.json').read_bytes()),sealed_files_sha256=sha(p.read_bytes()),all_actual_source_handles_closed=True)))
if __name__=='__main__':main()
