#!/usr/bin/env python3
"""Seal only this completed bounded scope; never execute captured guest cases."""
from pathlib import Path
import hashlib,json

ROOT=Path('/root/garmin');HERE=Path(__file__).resolve().parent
def sha(b):return hashlib.sha256(b).hexdigest()

def main():
 assert not(HERE/'sealed-files.json').exists()
 proof=json.loads((HERE/'proof.json').read_bytes())
 assert proof['all_assigned_bounded_checks_passed'] and proof['all_scope_handles_closed']
 assert proof['completed_original_CPU_cases']==7 and not proof['v3_road_regression_rootcause_proved']
 assert proof['source_sha256']==sha((HERE/'finalize_evidence.py').read_bytes())
 assert proof['CPU_proof_sha256']==sha((HERE/'new-state-cpu-proof.json').read_bytes())
 assert proof['witnesses_sha256']==sha((HERE/'node-semantics-witnesses.json').read_bytes())
 assert proof['receipts_sha256']==sha((HERE/'actual-tool-receipts.json').read_bytes())
 rows=[]
 for p in sorted(HERE.iterdir()):
  assert p.is_file(),str(p)
  b=p.read_bytes();p.chmod(0o444);assert p.stat().st_mode&0o777==0o444
  rows.append(dict(path=str(p.relative_to(ROOT)),bytes=len(b),sha256=sha(b),mode='0444'))
 out=dict(schema='garmin-bounded-readonly-scope-seal/v1',scope=str(HERE.relative_to(ROOT)),files=rows,file_count=len(rows),all_assigned_checks_passed=True,all_assigned_checks_scope='bounded exact-byte and seven new independent state/arithmetic cases; producer and physical rootcause gaps explicitly retained',scope_closed_with_gaps=True,all_handles_closed=True,device_or_shared_source_mutation=False,full_goal_completed=False)
 p=HERE/'sealed-files.json';p.write_text(json.dumps(out,indent=2)+'\n');p.chmod(0o444)
 print(json.dumps(dict(sealed_files=str(p.relative_to(ROOT)),sha256=sha(p.read_bytes()),files=len(rows),bytes=sum(r['bytes']for r in rows),all_modes='0444',proof_sha256=sha((HERE/'proof.json').read_bytes()),witness_sha256=sha((HERE/'node-semantics-witnesses.json').read_bytes()),CPU_proof_sha256=sha((HERE/'new-state-cpu-proof.json').read_bytes()),all_handles_closed=True,closed_with_producer_gap=True)))

if __name__=='__main__':main()
