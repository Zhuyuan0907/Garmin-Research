#!/usr/bin/env python3
"""Qualify overly narrow wording in frozen native reprofile control."""
import hashlib,json
from pathlib import Path
B=Path(__file__).resolve().parent;ROOT=B.parents[1]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 source=B/'boundary-controls-v1/original-reprofile-bypass.json'
 d=json.loads(source.read_text());require=d['passed']
 rows=[r for r in d['CPU_store_journal']if r['phase']=='actual_original_reprofile']
 callback=[r for r in rows if int(r['address'],16)==0x34e6f08+8*0x208+0x160]
 assert len(callback)==1 and callback[0]['PC']=='0x277dbc' and callback[0]['value']==0x277c6b
 addresses={r['address']for r in rows}
 assert len(addresses)>1
 out=dict(all_passed=True,source_sha256={str(source.relative_to(ROOT)):sha(source),
  str(Path(__file__).relative_to(ROOT)):sha(Path(__file__))},
  frozen_proof_retained=True,overly_narrow_field='native_reprofile_replaced_only_RAM_callback_slot',
  all_profile_writes_limited_to_one_slot=False,
  correct_scope='The native callback slot is restored in RAM as one of multiple original profile-field and stack writes; original MAIN code is not patched.',
  actual_profile_CPU_store_events=len(rows),actual_distinct_store_addresses=len(addresses),
  actual_callback_store=callback[0],original_reprofile_bypass_result=d['actual_original_high_return'],
  certification_remains_negative200=True,device_io=False,physical_App=False)
 with (B/'reprofile-scope-erratum.json').open('x')as f:json.dump(out,f,indent=2);f.write('\n')
 print(json.dumps(dict(all_passed=True,profile_CPU_stores=len(rows),distinct_addresses=len(addresses))))
if __name__=='__main__':main()
