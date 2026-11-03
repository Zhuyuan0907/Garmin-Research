#!/usr/bin/env python3
"""Seal own output files only. No shared input mutation or dataset reexecution."""
import hashlib,json,os,time
from pathlib import Path
ROOT=Path('/root/garmin');HERE=Path(__file__).resolve().parent
def sha(b):return hashlib.sha256(b).hexdigest()
def main():
 assert not(HERE/'sealed-files.json').exists()
 proof=json.loads((HERE/'proof.json').read_text());assert proof['all_assigned_checks_passed']
 assert proof['all_image_handles_closed'] and not proof['proof_limits']['install_ready']
 files=sorted(p for p in HERE.iterdir() if p.is_file())
 for p in files:os.chmod(p,0o444)
 modes={p.name:oct(p.stat().st_mode&0o777)for p in files};assert set(modes.values())=={'0o444'}
 receipt=dict(schema='own-scope-final-sealing-actual-receipt/v1',time_unix_ns=time.time_ns(),
  prior_output_files_chmod444_completed=len(files),prior_output_modes_actual=modes,
  proof_sha256=sha((HERE/'proof.json').read_bytes()),shared_input_or_device_mutations=0,
  original_CPU_Java_or_geometry_reexecution=False,all_image_handles_already_closed=True,
  completion_phase='This receipt and manifest written after prior output chmod; manifest hash returned in actual tool terminal.')
 receiptpath=HERE/'sealer-receipt.json';receiptpath.write_text(json.dumps(receipt,ensure_ascii=False,indent=2)+'\n');os.chmod(receiptpath,0o444)
 rows=[]
 for p in sorted(q for q in HERE.iterdir()if q.is_file()):
  raw=p.read_bytes();assert p.stat().st_mode&0o777==0o444
  rows.append(dict(path=str(p.relative_to(ROOT)),bytes=len(raw),sha256=sha(raw),mode='0444'))
 manifest=dict(schema='bounded-readonly-scope-seal/v1',files=rows,
  all_assigned_checks_passed=True,own_files_only=True,all_image_handles_closed=True,
  IMG_MAP_DB_device_install_candidate_written=False,native_write_ready=False)
 seal=HERE/'sealed-files.json';seal.write_text(json.dumps(manifest,ensure_ascii=False,indent=2)+'\n');os.chmod(seal,0o444)
 assert all((ROOT/r['path']).stat().st_mode&0o777==0o444 for r in rows)
 print(json.dumps(dict(files_sealed=len(rows),seal_sha256=sha(seal.read_bytes()),
  proof_sha256=sha((HERE/'proof.json').read_bytes()),all_files_mode='0444',
  all_handles_closed=True,shared_input_device_mutations=0),ensure_ascii=False))
if __name__=='__main__':main()
