#!/usr/bin/env python3
"""Independently verify a sealed partial first native Dispatcher FP exchange.

This is a file-backed verifier. It imports neither runtime observer nor Unicorn,
constructs no emulator, and writes only its unique local partial-scope artifact.
"""
from pathlib import Path
from datetime import datetime, timezone
import ast, hashlib, json, struct, sys
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB
_WORKSPACE=Path(__file__).resolve().parents[3]
sys.path.insert(0,str(_WORKSPACE/'scripts'))
from analyze_native_sections import ROOT, NativeImage, EXPECTED

BASE='staging/native-player-dispatcher-native-body/'
STAGE=BASE+'runtime/'
OUT=BASE+'fp-static/first-native-Dispatcher-FP-exchange.json'
RUNNER='scripts/probe_native_dispatcher_body_fp.py'
HELPER='scripts/native_dispatcher_multiowner_vfp.py'
PARENT='scripts/probe_native_multiowner_vfp.py'
PINS={RUNNER:'a0315eadfe40ab66ea8e601c236d9c358731ed1513983a3a2e2bc88c9b05a4e0',
 HELPER:'5dbe3df3dc3f220dd658d6c25408b1292025a5009338cc89faafc74b671aeff8',
 PARENT:'8fc0a2bcf6319f9a2b5a00c15c1f9c213b1717f6c55105b0785433e594a4cab4',
 'scripts/probe_native_task_mutex.py':'ae5236477a15d99f5dc8b44abbfa59c7abd89a045a5c321d5aa3ae1e8544c97a',
 BASE+'fp-static/runner-peer-review-a0315e.json':'83d4b64b32961c53fb9815156bdcee9f161c620ac5efd3e4be1b381b61d0c404',
 'evidence/firmware-analysis/main_02bd.bin':EXPECTED}
C,D,CM,DM,CS,DS,U,OWNER=0x9503f90,0x8804fb8,0x9400900,0x8800fe0,0x9500000,0x8801024,0x18310fe0,0x3ab1038
ZONES={OWNER&~4095:4096,DM:40,DS:320,D:108,CM:40,CS:320,C:108,U-4096+32:4096}

def sha(path):return hashlib.sha256((ROOT/path).read_bytes()).hexdigest()
def read(path):return json.loads((ROOT/path).read_text())
def digest(raw):return hashlib.sha256(raw).hexdigest()
def require(value,message):
 if not value:raise AssertionError(message)
def integer(value):return int(value,16) if isinstance(value,str) else value


def main():
 require(not (ROOT/OUT).exists(),'Preserve unique first-exchange artifact')
 dependencies=dict(PINS)
 for p,h in PINS.items():require(sha(p)==h,'Pinned source changed '+p)
 metadata=read(STAGE+'terminal-metadata.json');probe=read(STAGE+'terminal-probe.json');inputs=read(STAGE+'inputs-before-run.json')
 require(metadata['authoritative_terminal_result_received_from_exec'] and metadata['session_id']==67576
         and metadata['terminal_exit_code']==1,'Need exact authoritative partial terminal')
 for key in ['runner','runner_snapshot','inputs','probe','FP_helper','GUI_observer','sealer','cold_prefix']:
  path=metadata[key];require(sha(path)==metadata[key+'_sha256'],'Sealed dependency changed '+key)
  dependencies[path]=sha(path)
 require(metadata['runner_sha256']==PINS[RUNNER] and metadata['FP_helper_sha256']==PINS[HELPER],'Executed observer identity differs')
 for p in [RUNNER,HELPER,PARENT,'scripts/analyze_native_sections.py','scripts/probe_native_task_mutex.py']:
  require(inputs['source_sha256'][p]==metadata['source_sha256'][p]==sha(p),'Input registry differs '+p)
  dependencies[p]=sha(p)
 for p in [STAGE+'terminal-metadata.json',str(Path(__file__).resolve().relative_to(ROOT))]:dependencies[p]=sha(p)
 helper_AST=ast.parse((ROOT/HELPER).read_text())
 require(not any(isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute)
                 and n.func.attr in ('emu_start','emu_stop','mem_write','reg_write') for n in ast.walk(helper_AST)),
         'New helper performs host guest-state mutation/execution')
 require(probe['phase']=='actual_Dispatcher405340_body' and not probe['completed']
         and not probe['body_full_guards_passed'] and probe['callback_entry_seen']
         and not probe['callback_return_seen'],'Terminal partial/body completion differs')
 require(probe['error']=='Native mutex caller outside explicit per-task GUI scope: 0x396b4e'
         and probe['registers']['pc']=='0x3009a0','Terminal boundary differs')
 require(probe['cold_prefix_full_guards_passed'] and probe['callback_entry_reached'],'Missing completed prefix/native callback')
 rows=probe['original_lazy_handler_rows'];require(len(rows)==1,'This verifier covers exactly one post-cold exchange')
 row=rows[0];before,after=row['before'],row['after_native_handler']
 require(row['old_owner']==hex(C) and row['new_owner']==hex(D) and row['old_context']=='0x0'
         and row['new_context_before']=='0x0' and row['save_complete'] and not row['restore_complete'],
         'Not the first C-save/no-D-restore exchange')
 require(before['PC']=='0x70dff8' and row['fault_load_PC']==before['PC'] and before['FPowner']==hex(C)
         and before['current_TCB']==hex(D) and row['actual_native_running_task']==hex(D), 'Fault/current provenance differs')
 require(row['original_IRQ_marker']==0 and row['original_getter_preentry_result']==hex(D)
         and row['original_current_getter_entered'] and row['original_current_getter_returned']
         and row['actual_original_current_getter_result']==hex(D), 'Original current getter did not actually return Dispatcher')
 require(row['original_handler_entered'] and row['original_exception_return_seen'] and row['original_opcode_retry_reached']
         and not row['host_wrote_FP_enable_or_context'] and row['undefined_entry_is_explicit_architectural_fixture'],
         'Original handler/return/retry attribution differs')
 require(before['GP15']==after['GP15'] and before['CPSR']==after['CPSR'] and before['FPEXC']=='0x0'
         and after['FPEXC']=='0x40000000' and after['FPowner']==hex(D),'Fault GP15/CPSR/enable/owner preservation differs')
 require(integer(before['CPSR'])&0x3f==0x1f and integer(before['CPACR'])&0xf00000==0xf00000,
         'Fault is outside original ARM SYS/access fixture')
 require(row['expected_retry_bank_source']=='actual_fault_bank' and before['D16']==after['D16']==row['expected_retry_D16']
         and before['FPSCR']==after['FPSCR']==row['expected_retry_FPSCR'],'FirstD no-slot retry bank differs')
 require('restore_bank_hex' not in row and 'restore_controls' not in row
         and not row.get('original_VLDM128_readback_passed',False),'Unexpected new-owner restore')
 allocations=probe['native_FP_allocations'];require(len(allocations)==1,'Unexpected D save/clone allocation')
 allocation=allocations[0]
 require((allocation['task'],allocation['request'],allocation['advance'],allocation['LR'],allocation['result'],allocation['end'])
         ==(hex(C),148,152,'0x20ecc4','0x9500008','0x95000a0') and allocation['returned'],
         'Original C allocation ABI/cursor differs')
 stock=NativeImage();disassemblers={False:Cs(CS_ARCH_ARM,CS_MODE_ARM),True:Cs(CS_ARCH_ARM,CS_MODE_THUMB)}
 fault=stock.read(0x70dff8,4);ins=list(disassemblers[False].disasm(fault,0x70dff8,count=1))
 require(len(ins)==1 and ins[0].mnemonic.startswith('v') and ((struct.unpack('<I',fault)[0]>>8)&15) in (10,11)
         and fault.hex()==row['opcode_hex'],'Fault is not exact original ARM VFP opcode')
 getter=stock.read(0x358d24,24)
 require(getter[:16].hex()=='002003490968002901d1024800687047'
         and struct.unpack_from('<2I',getter,16)==(0xf09094,0xf09090)
         and stock.read(0x20ec84,4).hex()=='262805fa','Original getter CFG/literals/caller differ')
 last_restore=probe['native_restores'][-1]
 require(last_restore['current']==hex(D) and last_restore['previous_running_task']==hex(C)
         and last_restore['saved_PC']=='0x2fd0ac' and last_restore['original_restore_entry_reached']
         and last_restore['original_task_resume_destination_reached'] and not last_restore['python_CPU_context_restore'],
         'Dispatcher current lacks an actual original restore destination')
 callback=next(r for r in probe['signal_chain'] if r['entry']=='0x405340')
 require(callback['running_task']==callback['ready_head']==hex(D) and callback['SP']=='0x8804f78'
         and callback['LR']=='0x60935d','Actual queued callback actor/frame differs')
 source_zones=probe['native_FP_zone_journals'];readbacks=probe['partial_FP_zone_verification']
 require(isinstance(readbacks,list) and len(source_zones)==len(readbacks)==8,'Need all8 actual partial FP readbacks')
 require({int(k):v['bytes'] for k,v in source_zones.items()}==ZONES,'Unexpected FP zone shape')
 replayed={};zone_results=[];store_count=0;original_writer_sites={}
 for start,n in sorted(ZONES.items()):
  zone=source_zones[str(start)];memory=bytearray.fromhex(zone['before_hex'])
  require(zone['start']==hex(start) and len(memory)==n,'Zone baseline length/start differs')
  for store in zone['stores']:
   pc,load=integer(store['PC']),integer(store['load_PC']);opcode=bytes.fromhex(store['opcode_hex']);thumb=store['Thumb']
   require(stock.runtime_to_load(pc,len(opcode))==load and stock.read(load,len(opcode))==opcode,
           'Recorded store is outside exact original runtime-to-load opcode')
   decoded=list(disassemblers[thumb].disasm(opcode,pc,count=1))
   require(len(decoded)==1 and decoded[0].size==len(opcode)
           and decoded[0].mnemonic.startswith(('str','stm','push','vstm','swp')),
           'Journaled writer is not an original CPU store instruction')
   require(decoded[0].mnemonic+' '+decoded[0].op_str==store['original_instruction'],
           'Recorded original writer disassembly differs')
   a,size=integer(store['address'])-start,store['size'];value=store['value']
   require(size in (1,2,4,8) and 0<=a and a+size<=n and 0<=value<1<<(8*size)
           and memory[a:a+size].hex()==store['before_hex'],'Chronological store-before/whole-zone boundary differs')
   memory[a:a+size]=value.to_bytes(size,'little');store_count+=1
   original_writer_sites[(pc,thumb)]=dict(PC=hex(pc),load_PC=hex(load),Thumb=thumb,opcode_hex=opcode.hex(),instruction=store['original_instruction'])
  readback=next(z for z in readbacks if z['start']==hex(start))
  require(readback['bytes']==n and readback['whole_zone_replayed'] and readback['stores']==zone['stores']
          and readback['before_hex']==zone['before_hex'] and digest(memory)==readback['after_sha256'],
          'Independent replay differs from sealed actual whole-zone readback')
  replayed[start]=bytes(memory)
  zone_results.append(dict(start=hex(start),bytes=n,CPU_store_events=len(zone['stores']),
                           independently_replayed=True,actual_guest_readback_sha256=readback['after_sha256']))
 ctx=integer(allocation['result']);pending=row['pending_save'];bank=struct.pack('<16Q',*[integer(v) for v in before['D16']])
 require(pending['context']==ctx and bytes.fromhex(pending['bank_hex'])==bank,'Captured pre-VSTM bank differs from actual fault D16')
 callbacks=row['VSTM_callbacks'];coverage=set();actual=bytearray(128)
 for event in callbacks:
  a,size=integer(event['address'])-ctx,event['size']
  require(size==8 and 0<=a and a+size<=128 and not coverage.intersection(range(a,a+size)),
          'Actual8-byte VSTM callback overlap/range differs')
  payload=event['value'].to_bytes(size,'little')
  require(payload==bank[a:a+size],'VSTM payload differs from actual captured D register')
  coverage.update(range(a,a+size));actual[a:a+size]=payload
  require(any(s['PC']=='0x20ecd8' and s['address']==event['address'] and s['size']==size
              and s['value']==event['value'] for s in source_zones[str(CS)]['stores']),
          'VSTM callback absent from independently replayed whole pool')
 require(len(callbacks)==16 and coverage==set(range(128)) and bytes(actual)==bank
         and row['VSTM_full128_readback_passed'],'ActualVSTM128 coverage/readback incomplete')
 controls=[integer(v) for v in row['actual_control_register_words']]
 require(controls==[0x40000000,C,0x20ecc4,integer(before['FPSCR'])],'Mutablefirstsave actual residual control provenance differs')
 require([(integer(s['address']),s['size'],s['value']) for s in row['control_STM_callbacks']]
         ==[(ctx+132+4*i,4,v) for i,v in enumerate(controls)],'Actual four control STM words differ')
 for s in row['control_STM_callbacks']:
  require(any(j['PC']=='0x20ecf8' and j['address']==s['address'] and j['size']==4 and j['value']==s['value']
              for j in source_zones[str(CS)]['stores']),'Control STM callback absent from whole-zone history')
 pool=replayed[CS];offset=ctx-CS
 require(pool[offset:offset+128]==bank and pool[offset+132:offset+148]==struct.pack('<4I',*controls)
         and pool[offset+128:offset+132]==pool[offset+148:offset+152]==b'\xff'*4
         and pending['hole_hex']==pending['padding_hex']=='ffffffff','SavedC context hole/control/padding or full replay differs')
 require(struct.unpack_from('<2I',pool)==(0xfce3e2ca,ctx+152) and pool[256:320]==b'\xff'*64,
         'C native allocator magic/cursor/trailing64 differs')
 original_Cmeta=bytearray.fromhex(source_zones[str(CM)]['before_hex']);struct.pack_into('<I',original_Cmeta,28,ctx)
 require(replayed[CM]==original_Cmeta and struct.unpack_from('<I',replayed[C],28)[0]==CM,
         'MutableC native slot/unchangedTCBmetadata publication differs')
 require(replayed[DM]==bytes.fromhex(source_zones[str(DM)]['before_hex'])
         and struct.unpack_from('<I',replayed[DM],28)[0]==0 and struct.unpack_from('<I',replayed[D],28)[0]==DM
         and replayed[DS]==b'\xff'*320,'FirstD unexpectedly gained metadata clone or savedcontext/pool header')
 require(struct.unpack_from('<I',replayed[OWNER&~4095],OWNER-(OWNER&~4095))[0]==D,
         'Actual native owner publication was not retained')
 require(any(s['PC']=='0x20ec98' and integer(s['address'])==OWNER and s['size']==4 and s['value']==D
             for s in source_zones[str(OWNER&~4095)]['stores']),'Original owner publication event missing')
 require(replayed[U-4096+32][:32]==replayed[U-4096+32][-32:]==b'\xa5'*32,'WholeUND guarded canaries changed')
 GP=[integer(v) for v in before['GP15']];pushes=row['push_rows']
 expected_pushes=[(0x20ebe0,U,[GP[i] for i in (0,1,2,3,4,12)]),
                  (0x20ec78,U-24,[GP[5],integer(before['PC'])+4]),
                  (0xf6edc,U-32,[C,D,GP[6],0x20ecc4]),
                  (0x6e0830,U-32,[ctx,0x20ecd4])]
 require(len(pushes)==len(expected_pushes),'Unexpected firstsave UND nested frame count')
 for push,(pc,pre,vals) in zip(pushes,expected_pushes):
  post=pre-4*len(vals);expected_words={hex(post+4*i):hex(v) for i,v in enumerate(vals)}
  require(push['PC']==hex(pc) and push['before_SP']==pre and push['after_SP']==post
          and push['expected_words']==expected_words and sorted(push['seen'])==sorted(integer(a) for a in expected_words)
          and stock.read(pc,len(bytes.fromhex(push['opcode_hex']))).hex()==push['opcode_hex'],
          'Independent original UND frame ABI/payload/coverage differs')
  for address,value in expected_words.items():
   require(any(s['PC']==hex(pc) and s['address']==address and s['size']==4 and s['value']==integer(value)
               for s in source_zones[str(U-4096+32)]['stores']), 'Observed push store absent from whole UND history')
 result=dict(updated_utc=datetime.now(timezone.utc).isoformat(),source_sha256=dependencies,
  MAIN_sha256=EXPECTED,all_passed=True,assertions_passed=True,partial_scope=True,
  verifier_executes_guest=False,helper_imported_or_instantiated=False,device_io=False,sounds_emitted=False,
  frozen_source_proof_or_canonical_modified=False,terminal_session_id=67576,root_terminal_exit_code=1,
  root_run_completed=False,terminal_boundary=probe['error'],
  first_actual_native_Dispatcher_FP_exchange_verified_under_declared_inputs=True,
  native_callback=dict(entry='0x405340',actual_TCB=hex(D),actual_SP='0x8804f78',actual_LR='0x60935d',
                       original_queued_Signal_dispatch=True,original_restore_destination=last_restore),
  FP_stage=dict(fault_PC=before['PC'],fault_load_PC=row['fault_load_PC'],original_fault_opcode_hex=fault.hex(),
    original_fault_instruction=ins[0].mnemonic+' '+ins[0].op_str,old_owner=hex(C),new_owner=hex(D),
    C_oldslot=0,D_newslot_before=0,save_C=True,restore_D=False,retry_bank_source='actual_fault_bank',
    actual_original_current_getter_result=hex(D),original_IRQ_marker=0,original_handler_and_exception_return_retry_completed=True,
    GP15_CPSR_D16_FPSCR_preserved_before_actual_retry=True,original_FPEXC_disabled_then_handler_enabled=True),
  native_C_allocation148_advance152=allocation,actual_control_register_words=[hex(v) for v in controls],
  saved_context_hole128_and_padding148_remain_FF=True,independent_actual_VSTM128=dict(callbacks=16,
    callback_widths=[8],complete_exact_byte_coverage=True,actual_D16_payload_sha256=digest(bank),saved_pool_actual_readback_matches=True),
  independent_FP_whole_zone_replays=zone_results,original_CPU_store_events=store_count,
  original_store_writer_sites=list(original_writer_sites.values()),independent_UND_push_ABI_frames=4,
  D_metadata40_unchanged=True,D_TCB_metadata_pointer_unchanged=True,D_slot0_and_pool320FF=True,
  no_D_context_save_observed=True,no_D_metadata_clone40_observed=True,no_C_saved_bank_restore_observed=True,
  no_D_saved_bank_restore_observed=True,full_three_stage_native_exchange_verified=False,
  complete_native_cold_Dispatcher_suite_verified=False,callback_body_returned=False,
  full_body_or_foreground_guards_passed=False,physical_App_direct_phone_music_package_acceptance_verified=False,
  limits='Sealed EXIT1 partial run: original queued Dispatcher reached405340 and fault70DFF8. Nativehandler saved priorController148/advance152 and retried firstDispatcher with slot0, retaining faultbank. EightFP zones independently replay exact original opcodes/store-before/payload to runtime whole-zone readback hashes. Two resident native task contexts derive from guarded virtual cold/kernel inputs; CPACR and architecturalUNDentry remain declared fixtures. No D save/clone, laterC/D restore, callback completion, complete foreground/font/cache/lifecycle/wholecode suite, hardware exception entry, physicalApp, music or acceptedpackage claim.')
 with (ROOT/OUT).open('x') as f:json.dump(result,f,ensure_ascii=False,indent=2);f.write('\n')
 print(json.dumps(dict(output=OUT,sha256=sha(OUT),verifier_sha256=sha(str(Path(__file__).resolve().relative_to(ROOT))),
                      all_passed=True,partial_scope=True,zones=8,stores=store_count,VSTM_callbacks=16)))

if __name__=='__main__':main()
