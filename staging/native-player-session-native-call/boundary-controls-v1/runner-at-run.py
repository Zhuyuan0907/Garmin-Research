#!/usr/bin/env python3
"""Two NEW native boundary controls using frozen six-case runner inputs."""
import sys
sys.dont_write_bytecode=True
import importlib.util,json,hashlib
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];BASE=Path(__file__).resolve().parent
def module(name,path):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
def main():
 old=module('frozen_qcs',BASE/'emulate_queue_call.py')
 el=module('frozen_elf',ROOT/'staging/native-player-dispatcher-native-body/music-static/analyze_single_image_link_bindings.py')
 build=json.loads((BASE/'build-v3.json').read_text());elf=el.ELF32(ROOT/build['ELF']);stock=old.NativeImage()
 runtime=BASE/'boundary-controls-v1';runtime.mkdir(exist_ok=False)
 (runtime/'runner-at-run.py').write_bytes(Path(__file__).read_bytes())
 source=json.loads((BASE/'guest-v1/inputs-at-run.json').read_text())
 source[old.rel(Path(__file__).resolve())]=old.sha(Path(__file__).resolve())
 source[old.rel(ROOT/'staging/native-player-dispatcher-native-body/music-static/analyze_single_image_link_bindings.py')]=old.sha(ROOT/'staging/native-player-dispatcher-native-body/music-static/analyze_single_image_link_bindings.py')
 old.dump(runtime/'inputs-at-run.json',source)
 for p,h in source.items():old.require(old.sha(ROOT/p)==h,'frozen input changed '+p)
 cases=[];m=None
 try:
  m=old.QueueCall(stock,elf,build);m.setup();old.require(m.call('qcs_begin')==0,'permit begin failed')
  first=m.call(0x270459,(8,10,12,old.PARAMS),(0x20c,0,1),phase='first_owned_registration')
  second=m.call(0x270459,(8,10,12,old.PARAMS),(0x20c,0,1),phase='second_owned_registration')
  old.require(first==0 and second==8,'consumed permit did not preserve first and reject second')
  row=m.finish('consumed_permit_rejects_second_original_call',second,8,1)
  row['first_actual_original_result']=first
  path=runtime/'consumed-permit.json';old.dump(path,row);cases.append(dict(path=old.rel(path),sha256=old.sha(path),passed=True))
  print('consumed permit original two-call control PASS',flush=True)
  m.uc=None;m=None
  m=old.QueueCall(stock,elf,build);m.setup()
  profile_result=m.call(0x277d27,(8,1,1),phase='actual_original_reprofile')
  old.require(profile_result==10 and m.word(old.RECORD+0x160)==0x277c6b,'original alternate profile did not restore stock callback')
  begin=m.call('qcs_begin',phase='compiled_begin_after_reprofile')
  old.require(begin==(-201&0xffffffff),'new guard admitted rewritten profile')
  result=m.call(0x270459,(8,10,12,old.PARAMS),(0x20c,0,1),phase='original_call_after_reprofile')
  old.require(result==0 and len(m.lower_calls)==1 and not m.bridge_calls,'expected native direct callback bypass not observed')
  old.require(len(m.lower_returns)==1 and m.lower_returns[0]['actual_r0']==0,'stock writer did not actually return')
  old.require(m.lower_calls[0]==[old.RECORD+0x1a8,0xffff,10,12,old.PARAMS,0x20c,0],'native restored callback ABI changed')
  witness=m.call('mcs_native_ownership_snapshot',(0,1,0x1352,old.RESULT+64),phase='uncertified_witness_after_real_bypass')
  old.require(witness==(-200&0xffffffff),'ownership incorrectly certified despite actual reprofile bypass')
  old.require(not any(m.mutex.values()),'retained fixture mutex')
  row=dict(name='actual_original_reprofile_bypasses_RAM_guard',passed=True,
   actual_native_reprofile_return=profile_result,compiled_begin_after_reprofile=begin,
   actual_original_high_return=result,compiled_bridge_entries=0,
   original_lower_seven_arguments=m.lower_calls,original_lower_actual_returns=m.lower_returns,
   native_reprofile_replaced_only_RAM_callback_slot=True,MAIN_code_patch=False,
   native_ownership_snapshot=-200,full_exclusive_not_certified=True,
   conclusion='Actual original277D26 can restore original277C6B and native270458 then bypasses the new RAM queue guard; this must be covered before enabling ownership.',
   CPU_store_journal=m.journal,declared_fixture_mutations=m.fixtures,lower_fixture_calls=m.native_boundaries,
   initial_whole_zones=m.initial,final_whole_zones={str(a):bytes(m.uc.mem_read(a,n)).hex()for a,n,p in m.zones if not p&old.UC_PROT_EXEC},
   native_visits={hex(k):v for k,v in m.visits.items()if v},device_io=False,
   mutex_heap_wake_and_actor_fixtures_explicit=True,physical_App_or_audio=False)
  path=runtime/'original-reprofile-bypass.json';old.dump(path,row);cases.append(dict(path=old.rel(path),sha256=old.sha(path),passed=True))
  proof=dict(all_passed=True,source_sha256=source,cases=cases,case_count=2,
   actual_original_reprofile_bypass_now_executed=True,no_native_ownership_or_exclusive_claim=True,
   full_native_player_or_App_or_STOP_DONE=False,device_io=False)
  old.dump(BASE/'queue-reprofile-boundary-proof.json',proof)
  print('actual original reprofile bypass demonstrated; witness remains -200',flush=True)
 except BaseException as e:
  error=dict(error=str(e),completed=cases,device_io=False)
  if m:error.update(trace=m.trace,fixture_calls=m.native_boundaries,
    registers={k:hex(m.uc.reg_read(r))for k,r in [('pc',old.UC_ARM_REG_PC),('lr',old.UC_ARM_REG_LR),('sp',old.UC_ARM_REG_SP)]},CPU_store_journal=m.journal,declared_fixture_mutations=m.fixtures)
  old.dump(runtime/'terminal-failure.json',error);raise
if __name__=='__main__':main()
