#!/usr/bin/env python3
"""NEW FILE ONLY peer review. No inherited verifier, runner or VM import.

Does not repeat the GUI peer's completed partial journals. Reviews exact MAIN
mapping/page-pop code and the evidence/provenance needed by the NEXT scope.
"""
import hashlib,json,struct,sys
from pathlib import Path
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[3]
HERE=Path(__file__).resolve().parent
BASE=ROOT/'staging/native-player-native-allocation'
sys.path.insert(0,str(ROOT/'scripts'))
from analyze_native_sections import NativeImage,EXPECTED
from capstone import Cs,CS_ARCH_ARM,CS_MODE_ARM,CS_MODE_THUMB

def sha(p):
 h=hashlib.sha256()
 with p.open('rb')as f:
  for b in iter(lambda:f.read(8388608),b''):h.update(b)
 return h.hexdigest()
def rel(p):return str(p.relative_to(ROOT))
def read(p):return json.loads(p.read_text())
def create(p,obj):
 with p.open('x')as f:json.dump(obj,f,indent=2);f.write('\n')

def main():
 contractp=BASE/'gui-static/native-allocation-v3-next-private-page-contract.json'
 peerp=BASE/'gui-static/native-allocation-v3-observed-native-prefix-review.json'
 assert sha(contractp)=='cfee05c73d93984f46130a778ead2e06649485a0e92ec0ba763c86903e57fa2d'
 assert sha(peerp)=='c306ffea7021f5bde9e217287e7cc30b376980a55036a67b556192c76a6cdd1a'
 contract=read(contractp);peer=read(peerp)
 for registry in(contract['source_sha256'],peer['source_sha256']):
  for p,h in registry.items():assert sha(ROOT/p)==h,p
 meta=read(BASE/'runtime-v3/terminal-metadata.json')
 for field in('runner','runner_snapshot','inputs','probe','FP_helper','GUI_observer','sealer','cold_prefix','terminal_tool_receipt'):
  assert sha(ROOT/meta[field])==meta[field+'_sha256'],field
 receipt=read(ROOT/meta['terminal_tool_receipt'])
 assert (meta['session_id'],meta['actual_exec_chunk'],meta['terminal_exit_code'])==(27241,'61dabd',1)
 assert receipt['observed_session_id']==27241 and receipt['tool_result']['chunk_id']=='61dabd'and receipt['tool_result']['exit_code']==1
 assert peer['all_passed']and peer['actual_guest_session']==27241 and peer['actual_guest_terminal_chunk']=='61dabd'
 assert peer['genuine_native_handle_or_malloc48_8_return_verified']is False
 assert peer['original_page_pop_body_executed']is False and peer['original_MMU_page_mapping_executed']is False
 assert len(peer['actual_inherited_whole_zone_replays'])==24 and len(peer['actual_body_whole_zone_replays'])==7 and len(peer['actual_FP_whole_zone_replays'])==8
 assert all(r['recorded_actual_after_SHA_available']and r['equals_actual_after_SHA']for group in(
  peer['actual_inherited_whole_zone_replays'],peer['actual_body_whole_zone_replays'],peer['actual_FP_whole_zone_replays'])for r in group)
 probe=read(ROOT/meta['probe']);a=probe['body_actor_observations']['native_allocation_observer'];pending=a['pending']
 assert probe['completed']is False and probe['body_full_guards_passed']is False
 assert probe['registers']==contract['actual_registers']==peer['actual_next_boundary']
 assert probe['registers']['pc']=='0x38806c'and not pending['lower_return_seen']and not pending['query_return_seen']
 work_before=struct.unpack('<24I',bytes.fromhex(pending['WORK96_before_hex']))
 assert work_before[1]==work_before[2]==0
 assert contract['actual_WORK_fields']['private_extent_remaining_head']==contract['actual_WORK_fields']['free_private_page_head']=='0x0'
 assert probe['native_public_heap_declared_input']['private_extent']==['0x18301000',8192]
 assert probe['native_public_heap_declared_input']['fixture_only']and not probe['native_public_heap_declared_input']['physical_heap_available_verified']
 assert len(pending['heap_stores'])==13 and len(pending['raw_operations'])==1
 assert pending['raw_operations'][0]['native_lock_acquired_by_originating_task']
 assert peer['native_heap_mutex_still_owned_by_D']and peer['actual_native_raw_unlock_returns']==0
 stock=NativeImage();assert hashlib.sha256(stock.data).hexdigest()==EXPECTED
 md={True:Cs(CS_ARCH_ARM,CS_MODE_THUMB),False:Cs(CS_ARCH_ARM,CS_MODE_ARM)}
 def instruction(pc,thumb=True):
  i=next(md[thumb].disasm(stock.read(pc,4),pc,count=1))
  return dict(PC=hex(pc),Thumb=thumb,opcode_hex=i.bytes.hex(),instruction=i.mnemonic+' '+i.op_str)
 def bounded(start,end,thumb=True):
  return [dict(PC=hex(i.address),Thumb=thumb,opcode_hex=i.bytes.hex(),instruction=i.mnemonic+' '+i.op_str)
   for i in md[thumb].disasm(stock.read(start,end-start),start)]
 calls=((0x3883ae,0x38806c),(0x3883bc,0x221d34),(0x388084,0x23d6e8),
  (0x221d3a,0x21b6cc),(0x221d40,0x3275a4),(0x221d44,0x33e664),(0x221d88,0x33e678),(0x221d8e,0x21b6dc))
 for pc,target in calls:
  assert instruction(pc)['instruction']in('bl #'+hex(target),'blx #'+hex(target))
 table_literal=((0x221d48+4)&~3)+0x3fc
 work_literal=((0x38806e+4)&~3)+0x3fc
 assert table_literal==0x222148 and stock.word(table_literal)==0x3e00000
 assert stock.word(work_literal)==0x3a7f170
 assert instruction(0x221d48)['instruction']=='ldr r7, [pc, #0x3fc]'
 assert instruction(0x221d4a)['instruction']=='lsrs r0, r6, #0x14'
 assert instruction(0x221d4c)['instruction']=='lsls r3, r0, #2'
 assert instruction(0x221d4e)['instruction']=='ldr r0, [r7, r3]'
 VA=0x18305000;slot=0x3e00000+4*(VA>>20)
 assert slot==0x3e0060c==int(contract['required_L1_slot'],16)
 assert not any(z['runtime_start']<=slot<z['runtime_end']for z in stock.copies+stock.zeros)
 # Exact descriptor masks/classes. These are code-derived software rules,
 # not fabricated actual descriptors or proof of hardware translation.
 expectations={0x221d62:'bne #0x221d88',0x221d6e:'lsrs r3, r2, #0x1e',
  0x221d74:'str r2, [r1, r0]',0x221d86:'str r2, [r1, r0]',0x221d9a:'str r0, [r7, r3]',
  0x221da8:'lsrs r3, r2, #0x1e',0x221dae:'str r2, [r1, r0]',
  0x221dbc:'str r2, [r1, r0]',0x221dc6:'str r2, [r1, r0]',0x221d8c:'movs r0, r5'}
 for pc,text in expectations.items():assert instruction(pc)['instruction']==text
 for pc,target in((0x3275a4,0x6f012c),(0x33e664,0x6f0250),(0x33e678,0x6f040c)):
  assert instruction(pc,False)['instruction']=='b #'+hex(target)
 cp15_blocks={hex(start):bounded(start,end,False)for start,end in((0x6f012c,0x6f0170),(0x6f0250,0x6f0258),(0x6f040c,0x6f0430))}
 assert instruction(0x6f012c,False)['instruction']=='mrc p15, #0, r0, c1, c0, #0'
 assert instruction(0x6f0138,False)['instruction']=='beq #0x6f016c'
 assert instruction(0x6f0140,False)['instruction']=='stmdb sp!, {r0}'
 original_rows=bounded(0x38806c,0x3880bc)+bounded(0x388398,0x3883d2)+bounded(0x221d34,0x221dca)
 sources={**contract['source_sha256'],**peer['source_sha256'],rel(Path(__file__).resolve()):sha(Path(__file__).resolve())}
 sources[rel(contractp)]=sha(contractp);sources[rel(peerp)]=sha(peerp)
 for p in(ROOT/meta['runner'],ROOT/meta['runner_snapshot'],ROOT/meta['inputs'],BASE/'runtime-v3/sealer-terminal-receipt.json',
  ROOT/'scripts/probe_native_heap_settings_boot.py',ROOT/'scripts/probe_native_cold_fp_controller.py'):
  sources[rel(p)]=sha(p)
 gaps=[
  'The current private extent contains8192bytes. Native cold constructor reserved first4096 and consumed the only remaining4096 page for descriptor storage. Actual WORK+4 and WORK+8 are both0 before pending malloc. No stock pagepop return is available.',
  'Original38806C entry was stopped before its PUSH/body. Following empty-pool branch would call23D6E8 with caller identity395535 and lastrequest56; that diagnostic was not executed. This is not an observed firmware invalid-descriptor diagnostic.',
  'R1=18306000/R2=18305000 at terminal are incidental core arithmetic. Pagepop API usesWORK and caller identityR0, not those registers as backing-page inputs. After actualpagepop return, original3883B2 copies returnR0 toR7 and221D34 receivesvirtualR0=18305000 andactualpageR1=R7.',
  'L1 literal03E00000/slot03E0060C is absent from original MAIN startup filecopy andzero ranges and all captured body/inherited/FP whole zones. No actual L1 orL2 descriptor bytes, original table producer or active CPUtranslation state were captured.',
  'Zero L1 type0 makes original221D34 execute maintenance/IRQrestore andreturn without a mappingstore. A nonzero coarse descriptor with L2classbits31:30=0 still does not replace pageaddress. Return alone, or a mapped host virtual region, cannot certify softwaremapping.',
  'Native221D34 has24-byte PUSH; when CP15SCTLR.M bit0 is1, native3275A4->6F012C adds a4-byte ARMSTM stackstore before CPSRrestore. Root extended journal must admit this exact original STM/SP/register value, not only ThumbPUSH or guest stores1/2/4 by arbitrarycaller.',
  'Native maintenance calls execute original CP15 operations; actual SCTLR.M andTTBR register snapshots are absent. Tablebytes/stores can certify a bounded softwaredescriptor update only; actual hardware translation, physicalbacking, cache/TLB effectiveness and livekernel/IRQ remainunverified.',
  'Frozen guards/recipes hardcode8192 private pool,18302000 descriptorpage and old canaries. A larger coldinput needs NEW exact recipe/full-zone guards and provenance, never WORK/pagehead seeding or silent parentpredicate widening.',
  'Native heapmutex remainsowned by Dispatcher with pendingmalloc frame. No unlock, handle/pointer/query/prefix/callerreturn for48 or8, no MainMenu constructor completion orforeground. Preserve this exact failure boundary.']
 branches=[
  dict(L1_low2_type=0,flow='221D62->221D88->221D8E->221D92',mapping_store=False),
  dict(L1_low2_type=1,L2_base='L1word & FFFFFC00',L2_slot_offset=4*((VA&0xfffff)>>12),L2_class='L2word >>30',retag_store_PC='221DAE',replacement=dict(class1='221DC0/221DC6: ((L2word|class)&0000FFFF)|actual_page',class2='221DB6/221DBC: ((L2word|class)&00000FFF)|actual_page'),class0_or3='No address replacement; continuation221D88'),
  dict(L1_low2_type=2,L1_slot='03E0060C',replacement='221D94/221D9A: (L1word&000FFFFF)|actual_page',mapping_granularity_guard='Actualdescriptorclass/alignment must justify this branch; do not acceptsection mapping merelybecause store occurs'),
  dict(L1_low2_type=3,L2_base='L1word & FFFFF000',L2_slot_offset=4*((VA&0xfffff)>>10),L2_class='L2word >>30',retag_store_PC='221D74',replacement=dict(class1='221DC0/221DC6 low16',class2='221DB6/221DBC low12',class3='221D80/221D86 low10'),class0='No address replacement')]
 doc=dict(all_passed=True,pure_static_plus_sealed_file_review=True,source_sha256=sources,
  output_sha256={rel(contractp):sha(contractp),rel(peerp):sha(peerp),meta['probe']:meta['probe_sha256'],meta['terminal_tool_receipt']:meta['terminal_tool_receipt_sha256']},
  actual_guest_session=27241,actual_terminal_chunk='61dabd',actual_terminal_exit_code=1,
  reused_GUI_independent_partial_proof=True,equivalent_partial_replay_reexecuted=False,
  reviewed_GUI_contract_and_original_instructions=True,original_opcode_rows=original_rows,
  original_L1_literal=dict(load_instruction='221D48',literal_address=hex(table_literal),value='03E00000',slot_for_virtual18305000=hex(slot),filecopy_or_startupzero_backing=False,actual_L1_L2_bytes_available=False),
  original_mapping_branch_rules=branches,original_privileged_maintenance_blocks=cp15_blocks,
  exact_future_input_requirements=['NEW coldprivateextent leaves at leastone4096 nativepageafter originalprefix+descriptorpage;12KiB is arithmeticalminimum only, not executedrecipe or validatedphysicalcapacity',
   'Recover original L1/L2 tableproducer or explicitlydeclare backedtablebeforebytes with class/alignment/runtimephysicalmappinglimitations before coldconstruction',
   'Actual original38806C frame/PUSH/WORKspan/pageheaderwrites/returnR0 and24-byte221D34frame/calls/IRQflags/privilegedCP15state snapshots',
   'Branch-specific descriptor before/type/mask/address exact CPUstores plus whole L1/L2 after, zero-store and wrongclass negativecontrols',
   'Preserve private/publicdescriptor/canaries/WORK96,ownedheapmutex/TCB108/backgroundframes and pending return scopes;hostmappedRAM is only declaredstorage'],
  concrete_gaps=gaps,actual_after_snapshots_for_V3_partial_scopes_reported_by_GUI_peer=True,
  actual_after_snapshots_for_future_MMU_tables_missing=True,per_store_complete_GP_CPSR_available=False,
  original_pagepop_or_mapping_executed=False,native_malloc48_8_return_verified=False,
  physical_MMU_or_RAM_backing_verified=False,full_Dispatcher_or_foreground_or_App_verified=False,
  VM_import_or_instantiation=False,guest_execution=False,device_io=False,canonical_write=False)
 assert not any(k=='unicorn'or k.startswith('unicorn.')for k in sys.modules)
 for p,h in sources.items():assert sha(ROOT/p)==h,p
 out=HERE/'native-MMU-input-contract-independent-review.json';create(out,doc)
 print(json.dumps(dict(all_passed=True,review=rel(out),SHA256=sha(out),partial_replay_reexecuted=False,guest_execution=False)))

if __name__=='__main__':main()
