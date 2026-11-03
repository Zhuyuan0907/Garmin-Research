#!/usr/bin/env python3
"""Bounded file/MAIN-only peer review of final caller-stack guard, no VM."""
import sys
sys.dont_write_bytecode=True
from pathlib import Path
from datetime import datetime,timezone
import hashlib,json,ast
ROOT=Path(__file__).resolve().parents[3];OUT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'scripts'))
from analyze_native_sections import NativeImage
H=ROOT/'staging/native-player-global-subobject/gui-static/global_subobject_observer_v2.py'
C=H.parent/'global-subobject-observer-v2-contract.json'
def sha(p):
 h=hashlib.sha256()
 with p.open('rb')as f:
  for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
 return h.hexdigest()
def main():
 assert sha(H)=='e1a25494f632d73b5154d0be6546fc1d8eed5fcee4f57fc1b7c6c20976205dd3'
 assert sha(C)=='9d2b9613037778c3d8e2989a6ee9ca7647036164e26e07a4ae76023294f78898'
 text=H.read_text();d=json.loads(C.read_text());im=NativeImage();rows=[];checks=[]
 def check(name,value,evidence):
  assert value,name;checks.append(dict(name=name,passed=True,evidence=evidence))
 for pc,expect in [(0x115204,'25ad'),(0x11521e,'2596'),(0x115220,'2696'),(0x1152ca,'2900'),(0x114612,'10b5'),(0x11461a,'84b0'),(0x11eab2,'f0b5'),(0x11eab4,'8fb0'),(0x26de3c,'10b5')]:
  i=next(im.md.disasm(im.read(pc,4),pc,count=1));assert i.bytes.hex()==expect
  rows.append(dict(PC=hex(pc),load_PC=hex(pc),opcode_hex=i.bytes.hex(),instruction=i.mnemonic+' '+i.op_str))
 for pc,load,expect in [(0x4501088,0xe24c54,'2860'),(0x450108e,0xe24c5a,'6960')]:
  assert im.runtime_to_load(pc,2)==load;i=next(im.md.disasm(im.read(load,2),pc,count=1));assert i.bytes.hex()==expect
  rows.append(dict(PC=hex(pc),load_PC=hex(load),opcode_hex=i.bytes.hex(),instruction=i.mnemonic+' '+i.op_str))
 check('exact_original_caller_stack_pointer_and_register_transfer',"pointer==function_SP+0x94" in text and 'pointer==uc.reg_read(UC_ARM_REG_R5)' in text,rows[:4])
 check('native_getter_derived_base_frame_bytes24_80_8', 'FRAMES={0x114612:(0x1152D2,24),0x11EAB2:(0x114630,80),0x26DE3C:(0x11EABA,8)}' in text,rows[4:9])
 check('runtime_copy_map_and_original_binding_store_opcodes',"('0x4501088',0xE24C54,pointer,4,'2860')" in text and "('0x450108e',0xE24C5A,pointer+4,4,'6960')" in text,rows[9:])
 old=d['actual_sealed_caller_stack_input_evidence'];terminal=ROOT/old['terminal'];assert sha(terminal)==old['terminal_sha256']
 sp=int(old['original114612entry_SP'],16);pointer=int(old['actual_native_R1_derived_from11EAB2_savedR4'],16)
 check('old_actual_saved_R4_reconstructs_original_R1_stack_span',pointer==sp+0x94 and old['source_saved_R4']['value']==pointer,dict(SP=hex(sp),pointer=hex(pointer),saved_R4_store=old['source_saved_R4']))
 history=old['whole_D_stack_CPU_history'];buf=None
 for r in history:
  a=int(r['address'],16);n=r['size'];assert pointer<=a and a+n<=pointer+8
  if buf is None:buf=bytearray(8)
  o=a-pointer
  if not any(int(p['address'],16)<=a and a+n<=int(p['address'],16)+p['size']for p in history[:history.index(r)]):buf[o:o+n]=bytes.fromhex(r['before_hex'])
  assert buf[o:o+n].hex()==r['before_hex'];buf[o:o+n]=r['value'].to_bytes(n,'little')
 assert buf.hex()==old['caller_stack_span8_before_native_getter_hex']
 check('old_actual_stack_history_replays_zero_setup_and_latest_binding', [(r['PC'],int(r['address'],16))for r in history[-2:]]==[('0x4501088',pointer),('0x450108e',pointer+4)],dict(actual_before_hex=buf.hex(),source_terminal_sha256=sha(terminal),last_two=history[-2:]))
 check('whole_D_stack_chronological_opcode_current_owner_and_final_bytes_required',all(s in text for s in ['Caller input stack history omitted an intervening write',"row['running_task']==hex(self.dispatcher_task)",'Actual stack input differs from whole-stack history']),dict(source_lines=[110,118,124,126,127]))
 forbidden={'reg_write','mem_write','mem_map','mem_unmap','context_restore','emu_start','emu_stop','kernel_invoke','invoke','ret','put'}
 bad=[n.func.attr for n in ast.walk(ast.parse(text))if isinstance(n,ast.Call)and isinstance(n.func,ast.Attribute)and n.func.attr in forbidden]
 check('observer_has_no_guest_mutator_executor_or_return_replacement',not bad,dict(forbidden=sorted(forbidden),calls=bad))
 check('parent_settings_decoder_epilogues_delegated_and_fullbody_unproved', 'return super().observe_dispatcher_actor(uc,address,size,data)' in text and d['qualification']['fullbody'] is False, d['qualification'])
 deps={str(p.relative_to(ROOT)):sha(p)for p in [H,C,terminal,Path(__file__).resolve(),ROOT/'scripts/analyze_native_sections.py',ROOT/'evidence/firmware-analysis/main_02bd.bin',OUT/'verification.json']}
 record=dict(updated_utc=datetime.now(timezone.utc).isoformat(),status='bounded_static_peer_no_concrete_blocker_identified',source_sha256=deps,assertions=checks,assertions_passed=len(checks),original_instruction_evidence=rows,concrete_blockers=[],limits=dict(readonly=True,VM_instantiated=False,guest_execution=False,root_session_polled=False,device_IO=False,newcompile=False,previous_terminal_reused_only_as_old_captured_input=True,new_runtime_property_guard_success_not_proven=True,fullbody_foreground_music_acceptance=False,existing_sources_canonical_or_proofs_modified=False))
 out=OUT/'global-subobject-v2-caller-stack-peer.json'
 with out.open('x')as f:json.dump(record,f,indent=2,ensure_ascii=False);f.write('\n')
 print(json.dumps(dict(path=str(out.relative_to(ROOT)),sha256=sha(out),assertions_passed=len(checks))))
if __name__=='__main__':main()
