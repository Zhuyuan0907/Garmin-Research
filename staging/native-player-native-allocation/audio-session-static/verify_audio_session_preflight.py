#!/usr/bin/env python3
"""Pure source/ELF/opcode verifier. Does not import runner or instantiate Uc."""
import ast,hashlib,importlib.util,json,struct,sys
from pathlib import Path
sys.dont_write_bytecode=True
BASE=Path(__file__).resolve().parent;ROOT=BASE.parents[2]
sys.path.insert(0,str(ROOT/'scripts'))
from analyze_native_sections import NativeImage,EXPECTED
from analyze_sdp_activation import trace
from capstone import Cs,CS_ARCH_ARM,CS_MODE_ARM
def sha(p):
 h=hashlib.sha256()
 with p.open('rb')as f:
  for block in iter(lambda:f.read(8*1024*1024),b''):h.update(block)
 return h.hexdigest()
def rel(p):return str(p.relative_to(ROOT))
def dump(p,d):
 with p.open('x')as f:json.dump(d,f,indent=2);f.write('\n')
def main():
 m=json.loads((BASE/'build-v3.json').read_text());assert m['all_passed']and not m['guest_executed']
 source=dict(m['source_sha256']);source.update(m['generated_sha256'])
 for p,h in source.items():assert sha(ROOT/p)==h,p
 auditpath=BASE.parent/'previous-audit.json';audit=json.loads(auditpath.read_text())
 assert audit['all_passed']and len(audit['protected_sources'])==1721
 prior={p:h for p,h in source.items()if not p.startswith(rel(BASE)+'/')}
 for p,h in prior.items():assert audit['protected_sources'].get(p)==h,('frozen source registry',p)
 for p in (Path(__file__).resolve(),BASE/'emulate_audio_session.py',BASE/'build-v3.json',auditpath,
     ROOT/'staging/native-player-session-native-call/emulate_queue_call.py',
     ROOT/'staging/native-player-session-native-call/native-queue-call-emulation-proof.json',
     ROOT/'staging/native-player-session-native-call/queue-reprofile-boundary-proof.json',
     ROOT/'scripts/emulate_native_audio_registration.py',ROOT/'scripts/emulate_native_memory_audio.py',
     ROOT/'evidence/firmware-analysis/main_02bd.bin',ROOT/'scripts/analyze_native_sections.py',ROOT/'scripts/analyze_sdp_activation.py'):
  source[rel(p)]=sha(p)
 for p,h in source.items():
  if p in audit['protected_sources']:assert audit['protected_sources'][p]==h,p
 for p in BASE.glob('*.py'):ast.parse(p.read_text(),filename=str(p))
 q=json.loads((ROOT/'staging/native-player-session-native-call/native-queue-call-emulation-proof.json').read_text())
 assert q['all_passed']and q['case_count']==6
 rp=json.loads((ROOT/'staging/native-player-session-native-call/queue-reprofile-boundary-proof.json').read_text())
 assert rp['all_passed']
 image=NativeImage();assert sha(ROOT/'evidence/firmware-analysis/main_02bd.bin')==EXPECTED
 assert image.read(0x2f9cca,4)==bytes.fromhex('f1b58ab0')
 assert image.read(0x388b22,2)==bytes.fromhex('7047')
 assert any(z['runtime_start']<=0x034e3000 and z['runtime_end']>=0x034e5000 for z in image.zeros)
 loader=ROOT/'staging/native-player-dispatcher-native-body/music-static/analyze_single_image_link_bindings.py'
 spec=importlib.util.spec_from_file_location('aas_static_elf',loader)
 mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
 e=mod.ELF32(ROOT/m['ELF']);assert e.kind==2 and sha(ROOT/m['ELF'])==m['ELF_sha256']
 assert not [s for s in e.symbols if s['name']and s['section_index']==0]
 symbols=m['symbols'];thunk=symbols['mcs_original_pull_thunk']['value']&~1
 assert e.at(thunk,4)[0]==image.read(0x2f9cca,4)
 assert struct.pack('<I',0x2f9ccf)in e.at(thunk,symbols['mcs_original_pull_thunk']['size'])[0]
 bridge=symbols['mcs_pull_bridge']['value'];body=e.at(bridge,symbols['mcs_pull_bridge']['size'])[0]
 calls=list(Cs(CS_ARCH_ARM,CS_MODE_ARM).disasm(body,bridge))
 assert any(i.mnemonic=='blx' and i.op_str==hex(thunk).replace('0x','#0x') for i in calls)
 offsets=struct.unpack('<5I',e.at(symbols['aas_offsets']['value'],20)[0]);assert offsets==(108,40,44,96,100),offsets
 for i in range(4):assert symbols['pcm'+str(i)]['value']==0x07700000+i*4096
 direct=list(image.instructions(0x2fa572,0x2fa576));assert len(direct)==1 and direct[0].mnemonic=='bl'and direct[0].operands[0].imm==0x2f9cca
 spans=[(0x48ee68,0x48ee98),(0x2f9d10,0x2f9d28),(0x2fa050,0x2fa0b4),(0x2f9e18,0x2f9e84)]
 bounded=[dict(start=hex(a),end=hex(b),original_bytes=image.read(a,b-a).hex(),instructions=
   [dict(PC=hex(i.address),instruction=i.mnemonic+' '+i.op_str,bytes=i.bytes.hex())for i in image.instructions(a,b)])for a,b in spans]
 cfg={hex(a):trace(image,a,n)for a,n in ((0x2f9f2e,250),(0x4379d4,200),(0x437a3e,100),(0x2f9cca,250),(0x277536,200))}
 runner=(BASE/'emulate_audio_session.py').read_text()
 assert 'self.fixture(RECORD+0xf0'not in runner and 'self.fixture(provider+12'not in runner
 assert "name in ('two_full_original_pulls','local_Stop_prevents_original_pull')"in runner
 result=dict(all_passed=True,assertion_scope='pure source/protected-input/ARM ELF/opcode checks, not runtime',
  source_sha256=source,ELF=m['ELF'],ELF_sha256=m['ELF_sha256'],guest_executed=False,device_io=False,
  borrowed_frozen_sources_match_1721_registry=True,runner_syntax_verified_without_import=True,
  no_undefined_ARM_ET_EXEC=True,copied_native_pull_prologue_exact=True,offset_ABI=list(offsets),
  entrypoints=dict(initialize='aas_initialize(record,pool)',publish='aas_pcm_publish(ptr,len)',
   register='aas_register(actual_returned_ticket)',select='aas_select(actual_returned_ticket)',
   full_pull='aas_pull(channel8) -> frozen mcs_pull_bridge -> unchanged original2F9CCE',status='aas_status(out30words)'),
  actual_native_order=[
   'original277D26(8,0,1) installs original277C6B callback',
   'compiled rawPCM init -> real memory_output_configure/media_queue_init/begin -> session guard callback store',
   'NEW rawPCM producer -> frozen memory_output_submit copy/publish ticket -> private FIFO publication',
   'leased compiled register -> original270458/2704B2 -> compiled mcs_queue_bridge -> original277C6A full return',
   'original277536(record+1A8) writes current list key -> original2F9F2E(8,0)',
   'original4379D4/437764(kind10)/48EE68 -> native recordF0/providerbusy -> original437A3E',
   'source-owner memory_output_after_selection -> frozen mcs_capture_selected -> RAM reader+108 only',
   'explicit bounded outer caller aas_pull -> both leases -> original full pull2F9CCE -> actual2F9D1A BLX selected reader',
   'compiled admission -> frozen continuous_media_read real FIFO copy -> original ARM memcpy3732C8 -> mixer cursor store',
   'complete64-byte native frame returns with both leases still live -> frozen mcs_pull_end -> both leases released'],
  per_case_contract={
   'two_full_original_pulls':dict(input_bytes=512,pulls=2,read_capacity=256,ring_capacity=2048,wraps=1,
     ticket_source='actual compiled submit return, never host seed',index_source='actual original48EE8E store',
     busy_source='actual original48EE8C byte store',leases_during_reader=[1,1],leases_after_full_wrapper=[0,0],
     payload='two native mixer copy chunks byte-equal original caller PCM fixture',ticket_consumed=True),
   'local_Stop_prevents_original_pull':dict(actual_local_stop_return=1,new_full_native_pulls=0,
      ring_unchanged=True,local_admission_only=True,STOP_DONE=False)},
  boundary_guards=[
   'all RW mappings replay from whole initial bytes using one ordinal for every CPU and declared fixture write; exact before images',
   'whole MAIN and compiled RX mappings unchanged',
   'all neighboring17 source records unchanged',
   'all opaque allocation leading/trailing32 bytes unchanged, no native heap/pinning claim',
   'nine-word mixer descriptor,2048byte ring,256byte reader scratch,512byte input leading/trailing32 unchanged',
   'actual source format mono16bit/16k from original factory/format; no host-selected method/index',
   'reader admitted only during live72byte borrow frame; native64byte full frame restores SP before lease release',
   'original native full-pull R0 preserved separately from reader byte count/mixer committed bytes',
   'fixture mutex depths balanced; currentTCB/interrupt marker unchanged; ownership witness returns-200 untouched',
   'positive ends with active native anchor/provider pinned; FIFO freed only after copied bytes; no source retirement/reset/unload'],
  fixture_boundaries={
   'single_actor':'F09090=08820000 and F09094=0 caller inputs; actual getter/IRQ instructions run, not native task boot',
   'resident_storage':'cold linked BSS and PCM pages; no native allocation/module acceptance claim',
   'queue_heap_mutex':'inherited38853C/388804 and3009A0/3008B0 fixtures; original388B22 BXLR retained',
   'opaque_release':'3887A2 fixture consumes the parameter handle, clears caller handle; no pin or original free claim',
   'mixer':'declared descriptor/ring/scratch/message handle and mode; no actual hardware consumer advance',
   'priority':'2F9C52 explicit fixture',
   'transport':'37BCE4 explicit fixture, with original copied message observed',
   'diagnostic':'3B9674 explicit fixture; original455C86 reporting wrapper remains native',
   'source_wake_cancel':'compiled wake fixture counter; cancel and ownership remain-200',
   'raw_pcm':'new rawPCM-only queue reset and packet decoder unavailable-201; frozen FIFO reader is real, no SBC/phone claim'},
  next_unfinished_contract={
   'native_mixer_callsite':'original2FA572 direct BL2F9CCA remains unchanged; RAM reader replacement alone does not enter full wrapper',
   'source_to_mixer':'this control keeps source-owner actor for all outer calls; live original actor/context handoff remains unverified',
   'direct_caller_hook':'must recover a real RAM callback/import or authorized MAIN redirect before physical complete-pull lease installation',
   'selection_hook':'post-selector refresh is explicit bounded driver call; production repeated selection/rehook/quiescence remains uninstalled',
   'provider_mutation':'full5-provider concurrency/writers/277C6A bypass/native pool reservation remain outside single-owner contract',
   'active_ticket_lifetime':'one512byte ticket only; metadata selected_ticket remains native anchor generation while slot is freed; later reuse needs stable anchor identity design',
   'remaining':'actual source worker/mixer scheduling, decoder integration, native leases/ownership/cancel cleanup/STOP_DONE, DAC/speaker/SEP/UI/App remain unverified'},
  bounded_original_fragments=bounded,bounded_CFG=cfg,
  bounded_CFG_is_not_complete_kernel=True,native_code_not_executed_by_preflight=True,
  required_root_command='staging/unicorn-stream-venv/bin/python -B staging/native-player-native-allocation/audio-session-static/emulate_audio_session.py',
  root_runtime_outputs={'directory':rel(BASE/'guest-v1'),'proof':rel(BASE/'audio-session-emulation-proof.json'),
   'failure':rel(BASE/'guest-v1/terminal-failure.json'),
   'receipt_requested':rel(BASE/'guest-v1-terminal-tool-receipt.json')},
  instruction_limit=200000,timeout_microseconds_per_call=10000000,case_VM_lifetimes='sequential; do not co-run from this agent',
  complete_native_reader_runtime_verified=False,full_player_or_App_or_exclusive_or_physical_audio_verified=False)
 dump(BASE/'audio-session-runtime-preflight.json',result)
 print(json.dumps(dict(all_passed=True,artifact=rel(BASE/'audio-session-runtime-preflight.json'),
  SHA256=sha(BASE/'audio-session-runtime-preflight.json'),guest_executed=False)))
if __name__=='__main__':main()
