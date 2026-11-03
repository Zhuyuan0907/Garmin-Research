#!/usr/bin/env python3
import hashlib,json
from pathlib import Path
from datetime import datetime,timezone
HERE=Path(__file__).resolve().parent;ROOT=Path('/root/garmin')
def sha(b):return hashlib.sha256(b).hexdigest()
def main():
 p=json.loads((HERE/'proof.json').read_bytes());assert p['all_assigned_checks_passed']and p['exact_byte_witness_count']==5
 assert p['new_MAIN_bytes_read']==8192 and p['new_IMG_bytes_read']==0 and p['logical_guest_cases']==1
 assert p['all_source_handles_closed'] and not p['remaining']['query_DIR_handle_created']
 s=(ROOT/'evidence/firmware-analysis/main_02bd.bin').stat();assert [s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]==p['source_MAIN_stat_after']
 assert not(HERE/'sealed-files.json').exists();rows=[]
 for f in sorted(HERE.iterdir()):
  assert f.is_file()and not f.is_symlink();raw=f.read_bytes();f.chmod(0o444);s=f.stat()
  rows.append(dict(path=str(f.relative_to(ROOT)),bytes=len(raw),sha256=sha(raw),mode='0444',stat_at_seal=[s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]))
 seal=dict(schema='garmin-native-query-dir-constructor-seal/v1',created_utc=datetime.now(timezone.utc).isoformat(),all_assigned_checks_passed=True,scope_work_completed=True,file_count=len(rows),files=rows,all_source_handles_closed=True,exact_byte_witness_count=5,new_MAIN_bytes_read=8192,new_IMG_bytes_read=0,logical_guest_cases=1,execution_attempts=2,receipt_after_seal_separately_bound=True)
 f=HERE/'sealed-files.json'
 with f.open('x')as out:json.dump(seal,out,ensure_ascii=False,indent=2);out.write('\n')
 f.chmod(0o444)
 print(json.dumps(dict(all_assigned_checks_passed=True,file_count=len(rows),proof_sha256=sha((HERE/'proof.json').read_bytes()),sealed_files_sha256=sha(f.read_bytes()),all_source_handles_closed=True)))
if __name__=='__main__':main()
