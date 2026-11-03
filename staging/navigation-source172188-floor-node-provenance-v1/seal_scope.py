#!/usr/bin/env python3
"""Private namespace seal only. No PBF read or shared-file mutation."""
import hashlib,json,os,time
from pathlib import Path
ROOT=Path('/root/garmin');HERE=Path(__file__).resolve().parent
def sha(b):return hashlib.sha256(b).hexdigest()
def main():
 assert not(HERE/'sealed-files.json').exists()
 proof=json.loads((HERE/'proof.json').read_text());assert proof['all_assigned_checks_passed']
 assert proof['actual_all_handles_closed'] and not proof['source_scope_limits']['native_write_ready']
 assert HERE.stat().st_mode&0o777==0o700
 files=sorted(p for p in HERE.iterdir()if p.is_file())
 for p in files:os.chmod(p,0o400 if p.name=='rawextract.osm' else 0o444)
 modes={p.name:f'{p.stat().st_mode&0o777:04o}'for p in files}
 assert modes['rawextract.osm']=='0400' and all(v=='0444'for k,v in modes.items()if k!='rawextract.osm')
 receipt=dict(schema='private-source-scope-sealer-actual-receipt/v1',time_unix_ns=time.time_ns(),
  actual_prior_files_modes=modes,namespace_mode='0700',source_PBF_reads=0,source_PBF_or_shared_input_mutations=0,
  private_XML_never_publicly_dumped=True,all_source_handles_closed=True,
  proof_sha256=sha((HERE/'proof.json').read_bytes()),
  receipt_created_after_actual_prior_file_modes_checked=True,final_manifest_hash_in_tool_terminal=True)
 rec=HERE/'sealer-receipt.json';rec.write_text(json.dumps(receipt,ensure_ascii=False,indent=2)+'\n');os.chmod(rec,0o444)
 rows=[]
 for p in sorted(q for q in HERE.iterdir()if q.is_file()):
  b=p.read_bytes();rows.append(dict(path=str(p.relative_to(ROOT)),bytes=len(b),sha256=sha(b),mode=f'{p.stat().st_mode&0o777:04o}',
   private_original_metadata=p.name=='rawextract.osm'))
 seal=HERE/'sealed-files.json';seal.write_text(json.dumps(dict(schema='private-targeted-source-provenance-seal/v1',
  files=rows,namespace_mode='0700',all_assigned_checks_passed=True,all_source_handles_closed=True,
  original_group_held=True,native_write_ready=False,install_ready=False),ensure_ascii=False,indent=2)+'\n');os.chmod(seal,0o444)
 print(json.dumps(dict(files_sealed=len(rows),seal_sha256=sha(seal.read_bytes()),proof_sha256=sha((HERE/'proof.json').read_bytes()),
  directory_mode='0700',rawextract_mode='0400',all_other_files_mode='0444',all_source_handles_closed=True,
  source_PBF_read_or_mutation_in_sealer=False)))
if __name__=='__main__':main()
