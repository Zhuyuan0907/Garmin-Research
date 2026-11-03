#!/usr/bin/env python3
"""Preserve allocator's internal loop target using an eight-byte entry patch.
All outputs are new offline files; frozen v1/v4 evidence remains unchanged.
"""
from pathlib import Path
import sys,json,hashlib
ROOT=Path(__file__).resolve().parents[2];BASE=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'scripts'))
from analyze_native_sections import NativeImage
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def dump(p,d):
 with p.open('x')as f:json.dump(d,f,indent=2);f.write('\n')
def main():
 n=NativeImage()
 prior=json.loads((BASE/'route-entry-derivation-v1.json').read_text())
 old=next(p for p in prior['patches']if p['name']=='allocate')
 assert old['address']==0x48ee68 and old['patch_bytes']==12
 loop=[dict(address=i.address,mnemonic=i.mnemonic,op_str=i.op_str,bytes=i.bytes.hex())for i in n.instructions(0x48ee68,0x48ee9a)]
 branch=next(i for i in loop if i['address']==0x48ee98)
 assert branch['mnemonic']=='blt' and '48ee72'in branch['op_str']
 fail=json.loads((BASE/'guest-v4/terminal-failure.json').read_text())
 stores=[r for r in fail['CPU_store_journal']if r['phase']=='unclaimed output original provider allocator forwarding' and r['PC']in('0x48ee8c','0x48ee8e')]
 assert len(stores)==2 and stores[0]['before_hex']=='01' and stores[1]['value']==0
 erratum=dict(schema='route-allocator-internal-loop-patch-erratum-v1',
  failed_guest='staging/native-player-route-entries/guest-v4/terminal-failure.json',
  error=fail['error'],original_opcodes=loop,old_patch=old,
  internal_loop_target=0x48ee72,old_patch_overwrites_internal_loop_target=True,
  private_slot_was_already_busy_before_other_caller=True,actual_other_allocator_stores=stores,
  real_patch_bug_not_test_precondition=True,old_build_not_validated_or_installable=True,
  proposed_eight_byte_patch_preserves_loop_header_and_back_edge=True,device_IO=False)
 dump(BASE/'guest-v4-allocator-loop-erratum.json',erratum)
 asm=(BASE/'route_original_entries_v2.S').read_text()
 start=asm.index('.section .text.rg_allocate_entry')
 tail=asm[start:].replace('ldr r3, [sp], #4\nb rg_allocate_gate','b rg_allocate_gate')
 tail=tail.replace('movs r1,#0\nlsls r3,r1,#3\n','').replace('1: .word 0x48ee75','1: .word 0x48ee71')
 assert '0x48ee75'not in tail and 'movs r1,#0'not in tail
 assembly=BASE/'route_original_entries_v3.S'
 with assembly.open('x')as f:f.write(asm[:start]+tail)
 patches=[]
 for row in prior['patches']:
  row=dict(row)
  if row['name']=='allocate':
   assert n.read(row['address'],8).hex()=='30b404003248314a'
   row.update(patch_bytes=8,before_hex=n.read(row['address'],8).hex(),
    restore_r3_and_SP_in_ARM_shim=False,one_argument_r0_preserved=True,
    patch_direct_ARM_C_gate=True,original_loop_header_and_back_edge_preserved=True,
    relocated_prefix_return=0x48ee71)
  patches.append(row)
 inputs=[Path(__file__),BASE/'route-entry-derivation-v1.json',BASE/'route_original_entries_v2.S',assembly,
  BASE/'guest-v4/terminal-failure.json',BASE/'guest-v4-terminal-tool-receipt.json',
  BASE/'guest-v4-allocator-loop-erratum.json',ROOT/'scripts/analyze_native_sections.py',ROOT/'evidence/firmware-analysis/main_02bd.bin']
 dump(BASE/'route-entry-derivation-v2.json',dict(all_passed=True,source_sha256={str(p.relative_to(ROOT)):sha(p)for p in inputs},patches=patches,VM_only=True,device_IO=False,durable_ownership=False))
 print(json.dumps(dict(all_passed=True,allocator_patch_bytes=8,preserves_native_loop_target=True,guest_executed=False,device_IO=False)))
if __name__=='__main__':main()
