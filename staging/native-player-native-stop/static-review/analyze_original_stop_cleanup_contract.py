#!/usr/bin/env python3
"""File-only next stop contract; original bytes, no VM or device execution."""
from pathlib import Path
from collections import deque
from datetime import datetime, timezone
import hashlib,json,struct,sys
ROOT=Path(__file__).resolve().parents[3]
HERE=Path(__file__).resolve().parent
sys.dont_write_bytecode=True
sys.path.insert(0,str(ROOT/'scripts'))
from analyze_native_sections import NativeImage,EXPECTED
from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB
from capstone.arm import (ARM_INS_B,ARM_INS_BL,ARM_INS_BLX,ARM_INS_BX,
                          ARM_CC_AL,ARM_OP_IMM,ARM_OP_MEM,ARM_REG_PC)
R,M=0x034E7F48,0x034E5CF8
OUT=HERE/'original-mixer-stop-cleanup-next-contract.json'
SYNC='staging/native-player-mixer-sync/static-review/original-mixer-sync-cold-initialization-contract.json'
SYNC_SHA='ff64814f1b0ba943a0fac0b2a22d677884f53f8e559c2b39180f368c0943ed2d'
CASE='staging/native-player-mixer-sync/guest-v3/normal_reuse_reselection_reset.json'
PROOF='staging/native-player-mixer-sync/mixer-sync-v3-proof.json'
PROOF_SHA='1203ebadc01d44f4199aabcf6ea7f0dbfdd82134a328e86520b459896bc59554'

def sha(p):
 h=hashlib.sha256()
 with p.open('rb')as f:
  while b:=f.read(1<<20):h.update(b)
 return h.hexdigest()

def main():
 assert not OUT.exists(),'New output only'
 n=NativeImage();assert sha(ROOT/'evidence/firmware-analysis/main_02bd.bin')==EXPECTED
 assert sha(ROOT/SYNC)==SYNC_SHA and sha(ROOT/PROOF)==PROOF_SHA
 prior=json.loads((ROOT/SYNC).read_text());sources=dict(prior['source_sha256'])
 sources.update({SYNC:SYNC_SHA,PROOF:PROOF_SHA,CASE:sha(ROOT/CASE)})
 for p,h in sources.items():assert sha(ROOT/p)==h,p
 md=Cs(CS_ARCH_ARM,CS_MODE_THUMB);md.detail=True
 tables={0x2FA25E:(0x2FA260,0x2FA262,8),0x455CA4:(0x455CA8,0x455CA8,13),
         0x455B76:(0x455B78,0x455B7A,13)}
 table_rows={hex(pc):dict(table_address=hex(t),computed_PC_base=hex(base),
             original_table_hex=n.read(t,count).hex(),
             targets=[hex(base+v*2)for v in n.read(t,count)])for pc,(t,base,count)in tables.items()}
 def cfg(start,end,tails=(),computed=None):
  queue=deque([start]);seen={};returns=[];calls=[]
  while queue:
   pc=queue.popleft()
   if pc in seen:continue
   assert start<=pc<end and len(seen)<512,hex(pc)
   i=next(md.disasm(n.read(pc,4),pc,count=1))
   row=dict(PC=hex(pc),mode='Thumb',size=i.size,opcode_hex=i.bytes.hex(),instruction=i.mnemonic+' '+i.op_str)
   seen[pc]=row
   if i.mnemonic=='ldr'and i.operands[-1].type==ARM_OP_MEM and i.operands[-1].mem.base==ARM_REG_PC:
    a=((pc+4)&~3)+i.operands[-1].mem.disp
    row.update(literal_address=hex(a),literal_value=hex(n.word(a)))
   if i.mnemonic=='pop'and'pc'in i.op_str or i.id==ARM_INS_BX and i.op_str=='lr':
    returns.append(hex(pc));continue
   if i.id in (ARM_INS_BL,ARM_INS_BLX):
    row.update(callee=hex(i.operands[0].imm)if i.operands[0].type==ARM_OP_IMM else'actual register '+i.op_str,
               architectural_LR=hex((pc+i.size)|1),normalized_continuation=hex(pc+i.size))
    calls.append(row)
   elif i.id==ARM_INS_B:
    target=i.operands[0].imm
    if start<=target<end:queue.append(target)
    else:
     assert target in tails,(hex(pc),hex(target))
     row['bounded_external_tail']=hex(target)
    if i.cc==ARM_CC_AL:continue
   elif ARM_REG_PC in i.regs_access()[1]:
    assert computed==pc and pc in tables,(hex(pc),row)
    t,base,count=tables[pc]
    targets=[base+v*2 for v in n.read(t,count)]
    assert all(start<=p<end for p in targets)
    row['computed_targets']=[hex(p)for p in targets]
    queue.extend(targets);continue
   queue.append(pc+i.size)
  return dict(entry=hex(start),bounds=[hex(start),hex(end)],
              instructions=[seen[p]for p in sorted(seen)],calls=calls,
              original_returns=returns,local_CFG_exits_resolved=True,
              indirect_callees_are_contract_boundaries=True,complete_kernel=False)
 specs=[(0x2FA45C,0x2FA4C2,(0x2FA588,),None),
        (0x2FA2E8,0x2FA36C,(0x2FA588,),None),
        (0x2F9F1C,0x2F9F2E,(),None),(0x437A90,0x437AC2,(),None),
        (0x48EE12,0x48EE30,(),None),(0x4CAE44,0x4CAE6C,(),None),
        (0x5E75B2,0x5E75BA,(),None),(0x48EE58,0x48EE68,(),None),
        (0x277674,0x277696,(),None),(0x277596,0x277674,(),None),
        (0x2773A6,0x2773C2,(),None),(0x27746A,0x2774A8,(),None),
        (0x455C86,0x455D38,(),0x455CA4),
        (0x455B64,0x455C42,(),0x455B76),
        (0x455C42,0x455C86,(),None),
        (0x36B22E,0x36B24E,(),None),(0x36B24E,0x36B27A,(),None)]
 functions={hex(a):cfg(a,b,c,d)for a,b,c,d in specs}
 rows={int(r['PC'],16):r for f in functions.values()for r in f['instructions']}
 expected={0x2FA48E:'strb r0, [r1]',0x2FA492:'strb r0, [r5, #4]',
           0x437AB0:'str r0, [r5, #0x30]',0x437AB2:'strb r0, [r4, #2]',
           0x27763C:'subs r0, r0, #1',0x277642:'strh r0, [r4, #0x18]',
           0x455D12:'ldm r0, {r0, r1, r2, r3}',0x455D16:'stm r7!, {r0, r1, r2, r3}'}
 for pc,text in expected.items():assert rows[pc]['instruction']==text,(hex(pc),rows[pc])
 case=json.loads((ROOT/CASE).read_text())
 def snapshot(a,size):
  hits=[]
  for key,value in case['final_whole_RW_zones'].items():
   lo=int(key);b=bytes.fromhex(value)
   if lo<=a and a+size<=lo+len(b):hits.append(b[a-lo:a-lo+size])
  assert len(hits)==1
  return hits[0]
 rb=snapshot(R,0x208);mb=snapshot(M,0x130)
 word=lambda b,o:struct.unpack_from('<I',b,o)[0]
 observed=dict(record_prepared=rb[2],provider_index=word(rb,0xF0),
     first_stop_method=hex(word(rb,0xF4)),reader=hex(word(rb,0x108)),
     release_method=hex(word(rb,0x120)),notice_owner=word(rb,0x1B0),
     notice_mask=word(rb,0x1B4),source_nodes=struct.unpack_from('<H',rb,0x1C0)[0],
     current_list_index=word(rb,0x1AC),output_descriptor=hex(word(mb,0)),
     mixer_active=mb[0x84],mixer_reset_pending=mb[0x85],mixer_resampling_flag=mb[0x7F],
     mixer_scratch_handle=word(mb,0xB0),mixer_scratch_pointer=hex(word(mb,0xB4)))
 assert observed['notice_owner']==observed['notice_mask']==0
 assert observed['first_stop_method']=='0x48ee13'and observed['release_method']=='0x48ee59'
 assert observed['mixer_resampling_flag']==observed['mixer_scratch_handle']==0
 for path in ['scripts/emulate_native_memory_completion.py','scripts/emulate_native_source_controller.py',
              'native/music-continuous/media_coordinator.c','native/music-continuous/memory_output.c',
              'staging/native-player-mixer-sync/memory_output_session_owner_v4.c',
              'staging/native-player-mixer-sync/guest-v3-terminal-tool-receipt.json']:
  p=ROOT/path
  if p.exists():sources[path]=sha(p)
 # Actual build snapshot is the authoritative owner wrapper, not a possibly
 # absent sibling TU path. Store the exact immutable copy as input.
 p=ROOT/'staging/native-player-mixer-sync/build-v2/source-snapshot/12-memory_output_session_owner_v4.c'
 sources[str(p.relative_to(ROOT))]=sha(p)
 sources[str(Path(__file__).resolve().relative_to(ROOT))]=sha(Path(__file__).resolve())
 messages={str(kind):hex(0x2FA262+n.read(0x2FA260,8)[kind-13]*2)for kind in range(13,21)}
 result=dict(all_passed=True,proof_kind='bounded static next-call contract; new stop guest not executed',
   updated_utc=datetime.now(timezone.utc).isoformat(),MAIN_sha256=EXPECTED,
   source_sha256=dict(sorted(sources.items())),functions=functions,
   counts={'bounded_local_CFGs':len(functions),'reachable_original_instructions':sum(len(f['instructions'])for f in functions.values())},
   original_computed_tables=table_rows,mixer_messages=messages,
   reference_endpoint={'case':CASE,'case_sha256':sources[CASE],
      'serialized_actual_after_fields':observed,
      'independent_whole_runtime_CPU_replay_in_this_static_note':False,
      'registration_flags12_are_not_notice_mask':True},
   next_executable_primitive={
      'scope':'bounded original mixer stop/cleanup and source-list retirement; retain module/tasks/hardware allocations',
      'source_actor':'actual compiled Source TCB, normal context/currentgetter, existing selected scoped session',
      'steps':['Close compiled PLAY/producer admission via actual Stop API; preserve existinganchor/module/stack/session andall pendingcallback leases.',
        'Send original37BCE5(MTCB,12-byte command15 channel8) from Source; then command19 throughsame actualFIFO.',
        'Direct original46CC7B(R,1,0) queuescommand20 and waits actualACK8. No call3B9B66: that alsoqueues13 andwouldreselect.',
        'After whole46CC7A returns0, inspect actualnative stoppedprovider/methods/listidentity andzero fullreturn leases beforedeletion.',
        'Source invokes original277675(R+1A8,actualmatchedindex0) under scoped native_calls hold releasedonlyafter277694 fullreturn.',
        'Only after wholedelete return andmatchingownedhead/count/handle release, runcompiled session release then cancelunborrowedREADY FIFO slots. Keep originaltasks/module/pinnedstorageresident.'],
      'message_ABI':{'r0':'originalMTCB fromM+78','r1':'actualsource stack12-byte message',
           'fields':{'byte0':'15 then19','byte1':8,'word1':0,'word2':0},
           'queue_call_copies_input':'37BCE4 original, donotreuseinputbeforefullsendreturns'},
      'barrier_ABI':{'entry':'0x46cc7b','r0':hex(R),'r1':1,'r2':0,'r3':'unused input',
           'frame_bytes':96,'flag12_lifetime':'residentSourceframe untilwholeoriginalreturn',
           'result':'original46CD02 returns0; actualflagACK8 consumed by30ED30',
           'condition_token_owner':'retainednativeTimer, not Source orMixer',
           'extra_command13_or_synthetic17_needed':False},
      'FIFO_order_guarantee_bound':'Actualorderedqueue processing within same residentMixer task. ACK20 is laterthan15/19; it doesnotdrainotheractors/IRQ/physicalDMA.',
      'source_and_mixer_both_use_original_scheduler':'Source conditionwait/ACKpreemption/reacquisition as sealed synccontract, nothostack/contextrestore'},
   command15={'entry':'0x2fa45c','caller':'computed message15 target from2FA25E',
      'resident_mixer_frame_bytes':88,'channel_r4':8,
      'actual_writers':[{'PC':'0x2fa48e','address':'*(M+0)+0x20','value':1,'size':1},
                        {'PC':'0x2fa492','address':'M+0x84','value':0,'size':1},
                        {'PC':'0x2fa4be','address':'M+0xb4','value':0,'size':4}],
      'suppresses_future_message18_reader':'2FA564..568 checksM+84=0 before2FA572',
      'hardware_alternates':{'M_plus7F_nonzero':'2FA4A2->3FAEFE then clearsM+7F; outside narrow raw fixture',
         'M_plusB0_nonzero':'2FA4B0->388B22 then2FA4B8->3887A2(&M+B0); originallowerheap release still fixture boundary'},
      'physical_silence_or_DMA_drained_verified':False},
   command19={'entry':'0x2fa2e8','caller':'computed message19 target from2FA25E',
      'cleanup_chain':['2FA316->2F9F1C(channel)','2F9F28->437A90(record)',
         '437A9C BLX actualR+F4 stopmethod withr0=R+F0 providerindex',
         '437AAC optionalBLX actualR+120 releasemethod withsameindex',
         '437AB0 clearsR+F0;437AB2 clearsR+2;437ABA ARMmemzero R+F4 length68'],
      'kind10_exact_current_methods':{'stop':'48EE13->4CAE44(provider+10)->original5E75B3 backendclose',
                                    'release':'48EE59 clearspool[index*240]+C busybyte'},
      'result':'437A90 returnsfirststopmethodresult; mixer2FA316doesnotcheckR0 beforeits notices',
      'notices':{'if_R_plusA5_nonzero':[21],'if_R_plusA5_zero':[26,25],'always':22,
         'mask_source':'R+1B4, separatefromsourcekindflags12',
         'payload':'mixerSP+8 points16-bytecopyinput; word0=R+1B0,word1/2 writtenfor26 path; unusedword3 maystackresidue',
         'callers':{'26':'2FA34E','25':'2FA35A','22':'2FA366'},
         'notice20byte_packet':'455D0E channelbyte0;455D10eventbyte1;455D12/16 copiesfourpayloadwords to+4..19; bytes2,3 originalstackresidue'}},
   list_removal={'entry':'0x277675','r0':hex(R+0x1A8),'r1':'matchednative index0, notFIFO ticket4',
      'public_frame_bytes':16,'lock':'27767E->3009A0(driver+38=R+1E0),continuation277682',
      'inner':'277686->277596(driver,index),48-byteinnerframe',
      'unlock':'27768E->3008B0(same),continuation277692',
      'fullreturn_PC':'277694 POPr4-r6,PC; requirecallerSP/LR/GPpreserved',
      'validity':'index<count ANDheadhandle034E68D8[channel]nonzero; invalidreturns8',
      'head_case':'2775C2 getsnext;2775CC storesnewhead;388804 readsoldnode;455C86 event23 thenqueryrelease388B22 thenopaque3887A2(&oldhandle)',
      'later_index_case':'findpredecessor27746A;unlinkmatchednode+0 andsameevent23/delete; notcoveredbyone-nodescope',
      'deletion_commit':'277642 decrementsdriver+18 count AFTERevent23 andopaque release;lastnode setsdriver+4=FFFF,+1E=0,+1C=FFFF',
      'notice23_PC':'2775E2 forindex0 or277612 forlaterindex',
      'notice23_not_quiescence':'Publishedbeforelistcountdecrement/fullouterunlockreturn; native_calls andnode/storageleases mustremainheld.',
      'driver_raw_initializer':'cold original26A04C initializesR+1E0; direct3008A1 call canbe declared onlyoncebeforefirstliveuse, neverresetreleasedstalelinks',
      'opaque_query_release_fields':'Preserveexact original388804/388B22/3887A2 ABI; pinning/reclamation remainsfixture/no realallocatorclaim'},
   notification_contract={'455C86_ABI':{'r0':'signedchannel','r1':'noticebitmask','r2':'event21..33','r3':'16bytesactualpayload'},
      'zero_mask':'455C94 directly455D34 return; noqueuepost',
      'event_masks':{'22':'bit1=2','23':'bit2=4','25':'bit4=16','26':'bit5=32'},
      'if_enabled':'455D1E original37BCE4(*F2936C,20-bytepacket); requires actualnotifierTCB+queueABI or explicittransportfixture, nofakeconsumerACK',
      'original_notifier_entry':'455C42 waits original2FD034,37BC00 copiespacket,455C68->455B64 dispatches it',
      'dispatch_targets':{'22':'455B94->36B22E','23':'455BA2->36B24E','25':'455BBE->36B28A','26':'455BCC->36B29A'},
      'identity_caveat':'36B22E/36B24E reload currentR+1B0 owner; packetowner alonecannotidentify originalretirednode afterreselection',
      'current_V3_NULL_metadata':'actualnotice mask/owner0 meansall foureventsdisabled, no syntheticnotice delivery neededfornarrowretirement control',
      'nonzero_metadata_followup':'Mustbuild/runoriginalnotifier andvalidate lifetimecurrentowner+native consumer ABI; unrelatedcentral/App dispatch remainsfurther scope'},
   compiled_changes_needed=['NEW compiledSource stoptransaction, native per-taskcleanup hold andvalidatedcurrentepoch/identity; oldaas_stop onlyclosesnewpulls anddoesnotretireanchor.',
      'Keepg->held/registration_ticket/selected_session pinned whileclosingPLAY andwaiting; permitSource-onlycleanup mutation underStopstate withoutreopeningCONFIG/PLAY.',
      'Expose guardedSource retirement afteractualACKbarrier: no borrowedfullpull/readerinflight, R+2=0,method68zero,M+84=0,actualpoolbusy0,nodeidentity/count1.',
      'memory_output_release_session presentlyrequiresheld+native_mutation andactualretirement; do notclearg->selected_session early orfabricateoldtoken.',
      'Runtime snapshots mustserializestop15/cleanup19/ACK20/full277674 return andprovider/list/leaseafterbytes, nottrust event23 orreturn0 alone.'],
   negative_controls=['Do notdeletewhilea fullnativepull/reader/copyframe is pending; preserveprivateleases untilactualreturn.',
      'WrongTCB/non-normal/changednodeidentity/count>1/matchingproviderreselection rejectsretirement.',
      'Stopbarrier mustnotrun3B9B66 orenqueue13; no17hardware-reset-complete seed.',
      'Disablednoticemask sendsnothing; enabledmask requiresactualproducer/consumertransportcontract andcannotfakequiescence.',
      'Aftercleanup, stalecompiledinstalledmetadata alonecannotauthorizecallback: originalmethodsnowzero,providerbusy0.',
      'QueueFIFOcapacity andoriginalsendreturnchecked; donotoverfillorassumedeferredmessagecopy lifetime.'],
   draft_erratum={'earlier_agent_message':'incorrectly associatedkind10 registrationflags12 withnotice mask andclaimed23enabled',
      'correction':'ActualV3 owner/maskR+1B0/+1B4are0; originalmetadata=NULL. Eventmask andregistrationflags aredifferent typedfields.',
      'older_sealed_sources_or_proofs_modified':False},
   assertions={'exact_MAIN_input':True,'new_local_original_CFGs_bounded':True,'jump_tables_original_bytes':True,
      'selected_store_opcodes':True,'reference_actualafter_fields_readonly':True,
      'registrationflags_notice_mask_distinguished':True},
   scope={'static_only':True,'guest_executed':False,'VM_import_or_instantiation':False,'device_io':False,
      'new_native_stop_cleanup_runtime_proof':False,'canonical_writes':False,
      'native_STOP_DONE':False,'physical_mute_DMA_or_hardware_drain':False,
      'cross_actor_future_callback_exclusion':False,'exclusive_channel_ownership':False,'safe_unload':False},
   limits=['ACK20 proves sameMixerFIFO ordering only; hardwarecentral opcode3/7 andphysicaldrain are separate originalpaths.',
      'Declared currentrawoutput M+7F0/B00 andNULLmetadata restrict thisnextcontrol; initializedhardwarealternates3FAEFE/realnoticeAppconsumer notclaimed.',
      'Opaqueheap/query/release andhardwareoutputbacking remainexplicitfixtures; no nativeallocator orphysicalownership inference.',
      'No VM import/run, no newinstallcandidate/device/sound; MAIN unchanged.'])
 OUT.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
 print(json.dumps(dict(all_passed=True,proof=str(OUT.relative_to(ROOT)),proof_sha256=sha(OUT),counts=result['counts'],guest_execution=False)))

if __name__=='__main__':main()
