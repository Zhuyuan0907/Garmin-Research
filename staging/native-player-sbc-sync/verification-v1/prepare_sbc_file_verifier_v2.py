#!/usr/bin/env python3
"""Correct a reviewer fixture-scope premise in NEW source, never execute VM."""
from pathlib import Path
import hashlib,json
B=Path(__file__).resolve().parent
p=B/'verify_sbc_sync_v1_files_v1.py';s=p.read_text()
old="require(not any(sec['flags']&3==3 and a<sec['address']+sec['size'] and a+len(after)>sec['address'] for sec in self.elf.sections if sec['size']),'Fixture seeded compiled data/payload/capability state')"
new="require(not any(sec['flags']&3==3 and a<sec['address']+sec['size'] and a+len(after)>sec['address'] for sec in self.elf.sections if sec['size']) or supported_compiled_stack_fixture(self,e,a,after),'Fixture seeded compiled data/payload/capability state')"
assert s.count(old)==1;s=s.replace(old,new)
s=s.replace("def main():\n    output=",'''def supported_compiled_stack_fixture(rp,e,address,after):
    if len(after)!=4 or not 0x07800040<=address<0x07803f90:return False
    services=[x for x in rp.row['declared_service_calls'] if x['before']['ordinal']==e['ordinal'] and x['before']['current_TCB']==S]
    for x in services:
        gp=x['before']['GP16']
        if e['reason']=='opaque allocator output cell fixture' and x['name']=='opaque node/selector allocation':
            if gp[15]==0x38853c and gp[2]==address and 0<gp[0]<4000 and gp[1] in (2,3):
                h=struct.unpack('<I',after)[0]
                return str(h) in rp.row['opaque_handles'] and gp[13]<=address<gp[13]+524
        if e['reason']=='opaque release output fixture' and x['name']=='opaque release':
            return gp[15]==0x3887a2 and gp[0]==address and after==bytes(4) and gp[13]<=address<gp[13]+524
    return False

def main():
    output=''',1)
s=s.replace("ROOT/'scripts/analyze_native_sections.py'):sources[rel(p)]=sha(p)","ROOT/'scripts/analyze_native_sections.py',Path(__file__).resolve().parent/'verify_sbc_sync_v1_files_v1.py',Path(__file__).resolve().parent/'prepare_sbc_file_verifier_v2.py',Path(__file__).resolve().parent/'file-verifier-v1-terminal-failure-receipt.json'):sources[rel(p)]=sha(p)")
s=s.replace("'Opaque handles/allocation/query/release, mixer stack/FIFO backing,", "'First FILE verifier deny-all compiled memory premise rejected a native38853C fixture handle output on Source stack; v1 source/actual EXIT1 remain. NEW v2 permits only captured original service exact4-byte output cell with matched Source actor/PC/args/ordinal/stack range. No guest rerun. Opaque handles/allocation/query/release, mixer stack/FIFO backing,")
with (B/'verify_sbc_sync_v1_files_v2.py').open('x') as f:f.write(s)
for name in ['verify_sbc_sync_v1_files_v1.py','prepare_sbc_file_verifier_v1.py','sbc_file_verifier_extension_v1.py','source-copy-provenance-v1.json','file-verifier-v1-terminal-failure-receipt.json']:(B/name).chmod(0o444)
print(json.dumps(dict(all_passed=True,new_source='staging/native-player-sbc-sync/verification-v1/verify_sbc_sync_v1_files_v2.py',sha256=hashlib.sha256((B/'verify_sbc_sync_v1_files_v2.py').read_bytes()).hexdigest(),guest_execution=False)))
