#!/usr/bin/env python3
"""NEW FILE ONLY build/source/original instruction review, no guest imports."""
import hashlib,json,struct,sys
from pathlib import Path
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[3]
BASE=ROOT/'staging/native-player-mixer-handoff';HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'scripts'))
sys.path.insert(0,str(ROOT/'staging/native-player-dispatcher-native-body/music-static'))
from analyze_native_sections import NativeImage,EXPECTED
from analyze_single_image_link_bindings import ELF32
from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB,CS_MODE_ARM
def sha(p):
 h=hashlib.sha256()
 with p.open('rb')as f:
  for b in iter(lambda:f.read(8388608),b''):h.update(b)
 return h.hexdigest()
def rel(p):return str(p.relative_to(ROOT))
def read(p):return json.loads(p.read_text())
def main():
 manifestp=BASE/'build-v4.json';m=read(manifestp)
 assert sha(manifestp)=='77172b5b8cd5e2772c06bb0496f0af6180e37f8aa4a5e6a17a86b977e2dc24fa'
 assert m['all_passed']and not m['guest_executed']and not m['complete_player_image']
 sources={**m['source_sha256'],**m['generated_sha256']}
 for p,h in sources.items():assert sha(ROOT/p)==h,p
 snapshots=[]
 for i,(p,h)in enumerate(m['source_sha256'].items()):
  s=BASE/'build-v4/source-snapshot'/('%02d-%s'%(i,Path(p).name));assert sha(s)==h,p
  sources[rel(s)]=h;snapshots.append(dict(source=p,snapshot=rel(s),sha256=h))
 assert read(BASE/'build-v4/inputs.json')==m['source_sha256']
 elfp=ROOT/m['ELF'];assert sha(elfp)==m['ELF_sha256']=='06293cf160291ceecb56c30f886acfa96803479a1b5b3da76601a052af5a9183'
 e=ELF32(elfp);assert e.kind==2
 assert not any(s['name']and s['section_index']==0 for s in e.symbols)
 for name,s in m['symbols'].items():assert any(x==s for x in e.symbols),(name,s)
 assert m['symbols']['source_stack']['value']==0x7800000 and m['symbols']['source_stack']['size']==16384
 assert m['symbols']['source_descriptor']['size']==20
 stacksec=e.sections[m['symbols']['source_stack']['section_index']];assert stacksec['type']==8 and stacksec['alignment']>=4096
 command_rows=[]
 for p in sorted((BASE/'build-v4').glob('command-*.json')):
  c=read(p);assert c['exit_code']==0;pname=rel(p);sources[pname]=sha(p)
  command_rows.append(dict(path=pname,exit_code=0))
 assert len(command_rows)==14
 n=NativeImage();md={True:Cs(CS_ARCH_ARM,CS_MODE_THUMB),False:Cs(CS_ARCH_ARM,CS_MODE_ARM)}
 for x in md.values():x.detail=True
 def rows(start,end,thumb=True):
  return [dict(PC=hex(i.address),Thumb=thumb,opcode_hex=i.bytes.hex(),instruction=i.mnemonic+' '+i.op_str)for i in md[thumb].disasm(n.read(start,end-start),start)]
 def text(pc,thumb=True):return rows(pc,pc+4,thumb)[0]['instruction']
 expected={0x358c68:'ldrb r0, [r4, #0xe]',0x358c6a:'strb r0, [r5, #0x10]',0x358c6c:'strb r0, [r5, #0x11]',
  0x2fcf9e:'ldrb r1, [r0, #0x11]',0x2fcfa4:'ldrb r3, [r2, #0x11]',0x2fcfa6:'cmp r1, r3',0x2fcfa8:'bhs #0x2fcffa',
  0x3b9bf4:'movs r0, #0xc',0x3b9bf8:'strb r0, [r5, #0x10]',0x3b9bfa:'movs r0, #0x14',0x3b9bfc:'strb r0, [r5, #0x11]',
  0x3b9bfe:'movs r0, #0x17',0x3b9c00:'strb r0, [r5, #0x12]',0x3b9c08:'strb r7, [r5, #0x13]',
  0x3b9c10:'bl #0x358bf8',0x3b9c22:'blx #0x2fcf44',0x3b9c4a:'bl #0x37bce4',0x3b9c54:'bl #0x46cc7a',
  0x46cc92:'bl #0x30ed08',0x46cca4:'bl #0x30ed10',0x46ccc4:'bl #0x37bce4',0x46ccce:'bl #0x30ed30',
  0x30ed14:'bl #0x3009a0',0x30ed4a:'bl #0x3ec6a2',0x30ed66:'bl #0x3ec6aa',
  0x2fa294:'bl #0x2f9f2e',0x2fa536:'bl #0x2f9cca',0x2fa572:'bl #0x2f9cca',0x2fa438:'bl #0x2f9cca',
  0x2fa2d4:'bl #0x30ed10',0x2fa2dc:'bl #0x30ed24',0x2fa2e2:'bl #0x30ed1a'}
 for pc,t in expected.items():assert text(pc)==t,(hex(pc),text(pc),t)
 assert n.word(((0x46ccc8+4)&~3)+0x10c)==0x7ffffff
 table=n.read(0x2fa260,8);assert table.hex()=='0385fdfbfaf94322'
 assert 0x2fa262+2*table[0]==0x2fa268 and 0x2fa262+2*table[7]==0x2fa2a6
 sourcep=BASE/'mixer_source_task_v3.c';guardp=BASE/'music_session_guard_v4.c';asm=BASE/'pull_bridge_v4.S'
 source=sourcep.read_text();guard=guardp.read_text();bridge=asm.read_text()
 assert 'source_descriptor[3]=12u<<16;source_descriptor[4]=0;'in source
 assert source.index('0x3b9b67u')<source.index('mcs_handoff_source_to_mixer(&aas_guard)')
 assert 'entry_lr!=0x2fa299u'in guard and 'entry_lr!=0x2fa577u && entry_lr!=0x2fa53bu'in guard
 assert 'mcs_native_ownership_snapshot'in guard and 'return MCS_UNCERTIFIED;'in guard
 assert 'ldr r2,[r8,#36]'in bridge and '.hword 0xb5f1'in bridge and '.hword 0xb08a'in bridge
 elfrows={}
 for name in('mh_boot_source','mh_selector_bridge','mcs_pull_bridge'):
  s=m['symbols'][name];raw=e.at(s['value'],s['size'])[0]
  elfrows[name]=[dict(PC=hex(i.address),Thumb=False,opcode_hex=i.bytes.hex(),instruction=i.mnemonic+' '+i.op_str)for i in md[False].disasm(raw,s['value'])]
 bpc=m['symbols']['mh_boot_source']['value'];ins={int(r['PC'],16):r['instruction']for r in elfrows['mh_boot_source']}
 assert ins[bpc+0x34]=='mov r2, #0xc0000'and ins[bpc+0x38]=='strd r2, r3, [r4, #0xc]'
 assert n.read(0x2f9cca,4).hex()=='f1b58ab0'
 thunk=m['symbols']['mcs_original_pull_thunk'];raw=e.at(thunk['value']&~1,thunk['size'])[0]
 assert thunk['value']&1 and raw[:4].hex()=='f1b58ab0'and struct.unpack_from('<I',raw,8)[0]==0x2f9ccf
 # Only original-PC/static relationships are asserted here. No callsite patch,
 # original source/mixer creation or native scheduling occurred in this review.
 prior={
 'staging/native-player-native-allocation/verification-v3/native-MMU-input-contract-independent-review-seal.json':'ff3ab9d4097613683a4e48e569507860a0affb7879d41d04e6a07aab281aa12b',
 'staging/native-player-native-allocation/verification-v3/table-provenance/stock-BOOT-MAIN-table-provenance-seal.json':'250b819715cfec4093039930d72e721d4093a93b4563864d0b812f755804a8d7',
 'staging/native-player-mmu-software/software-mapping-v2-independent-file-seal.json':'ce36577a5dc413f6912bb77a78092e7b318076bd2b3b07317081c01ee64fe60a'}
 for p,h in prior.items():assert sha(ROOT/p)==h,p
 more=[Path(__file__).resolve(),manifestp,elfp,BASE/'build-v4/inputs.json',BASE/'build-v4/readelf.txt',BASE/'build-v4/audio-session.map',ROOT/'scripts/analyze_native_sections.py',ROOT/'staging/native-player-dispatcher-native-body/music-static/analyze_single_image_link_bindings.py',ROOT/'evidence/firmware-analysis/main_02bd.bin']
 sources.update({rel(p):sha(p)for p in more});sources.update(prior)
 findings=[dict(kind='Concrete sequencing issue if admitted original sync body',source_function='initialize_source',trigger='3B9B66(record,1,0) tail46CC7A executes native sync wait before returning',facts='Original3B9C4A queues selector message13, then3B9C54 enters46CC7A. Its flag starts1; r1=1 locksrecord+58, sendsmessage20 with stackflagpointer, waitsbit8 via30ED30->3EC6A2/6AA. Source can therefore block and allow mixer23 to consume13 before source publishes capability. Guard rejects early selector and source command1 only asks18, so no later automatic reselection is guaranteed.',severity='Conditional native integration blocker',minimal_choices=['Keep46CC7A an explicit bounded policy fixture; do not claim original native sync lifecycle.','Use a NEW source transaction publishing validated mixer capability before admitting native queued selector, with actual queue/mutex/condition/ack evidence and failure cleanup. Preserve frozen build-v4.']),
  dict(kind='Source admission versus successful delivery',source_function='process_command/send_mixer',facts='process_command casts every send_mixer result tovoid; mh_messages increments even when original37BCE4 returns failure. command_completed/last_result0 alone cannot prove queue acceptance, actor execution or PCM read.',severity='Runtime assertions required',minimal_choices=['Root must assert original send results or actual queue CPU publication/consumption, exact selector/fullpull returns, payload and leases.']),
  dict(kind='Original pull route outside the proposed two paths',source_function='original2FA0DC message14 branch',facts='Original2FA438 is another directBL2F9CCA with continuation2FA43D. Proposed guard admits only2FA53B/2FA577; slot+108 reader admission will deny unborrowed calls if this path occurs. Retain failclosed denial and uncertifiedownership; scoped13/16/17/18 execution is not complete native route coverage.',severity='Scope boundary')]
 d=dict(all_passed=True,pure_FILE_ONLY_build_source_static_review=True,source_sha256=sources,
  build_manifest_sha256=sha(manifestp),ELF_sha256=sha(elfp),source_snapshots_checked=snapshots,actual_build_terminal_command_files_checked=command_rows,
  original_MAIN_sha256=EXPECTED,priority_facts=dict(source_descriptor_word3='000C0000',source_kernel_base_current_priority=12,mixer_descriptor_word3='0117140C',mixer_flags=12,mixer_message_capacity=20,mixer_kernel_base_current_priority=23,mixer_tag_high_nibble=1,descriptor_priority_byte_offset=14,TCB_base_priority_offset=16,TCB_current_priority_offset=17,lower_number_preempts=True,source_POST_may_preempt_controller_priority16=True,mixer_POST_alone_preempts_source12=False,native_sync_tail_may_block_before_handoff=True),
  entry_and_return_contracts=[dict(caller='compiledmh_boot_source',entry='358BF9',descriptor20=['compiledmh_source_entry',0,'07804000','000C0000',0],TCB='(07804000-108)&~7 =07803F90',POST_event1=True),dict(caller='compiledinitialize_source',entry='3B9B67',r0=8,r1=0,native_stack_allocation=8192,native_queue_allocation=240,allocator_shape='38853C(size,kind2,0) returnsopaquehandle inR0; differs selectoroutcell API',query='388804(handle) returnsaddress',native_descriptor='M+64 words[2FA0DD,M+30,M+2C+8192,0117140C,M+3C]',native_builder_caller='3B9C10',kernel_boot_POST_caller='3B9C22',message13_send_caller='3B9C4A',sync_tail_caller='3B9C54'),dict(entry='mh_selector_bridge',actual_original_caller='2FA294',normalized_return_LR='2FA299',original_target='2F9F2F',preserving_original_R0_result=True,postbind_result_separate=True),dict(entry='mcs_pull_bridge',actual_original_callers=['2FA536','2FA572'],normalized_return_LRs=['2FA53B','2FA577'],original_target='2F9CCA via nativeprologue-compatibleThumbthunk+2F9CCF',wrapper_saved_LR_offset=36,wrapper_frame=80,zeroed_borrow_bytes=72,native_original_frame_bytes=64,full_original_return_required_before_release=True)],
  concrete_findings=findings,source_bugs_and_conditional_gaps_present=True,
  remaining_necessary_fixtures=['Declared initial controller/idle native descriptors/stacks/ready membership andCPUmode; original358BF8/POST/WAIT/restore must produce source/mixer taskprovenance, neverhostTCB actor substitution.',
   'Opaque38853C/388804 service allocation/query for queue node, selectorprovider, mixer8192 stack/240 queue; exact per-caller ABI and failure inputs. No nativeheap/publicMMU backing claim.',
   'Original mixer native metadata40 atM+3C and108-byteTCB/internal56/80 sem/messageflags/capacity plus8192 fullstack guards and actual saved context must remainresident.',
   'Existing queue/mutex/wake/policy/46CC7A-sync/hardware-reset boundaries must be explicitly enumerated; priority12 alone is not a proof that source cannot block before handoff.',
   'Three guest-only original BL redirects require bounded range/interworking veneers preserving actualoddLR2FA299/2FA53B/2FA577; unmodifiedstockMAINhash and patchledger must remain distinct.',
   'Raw deterministic compiled PCM generator/FIFO buffers and output-consumer read-index input remain testfixtures, not nativeaudio writer/DAC/decoderworker evidence.',
   'Actual original selector writesF0/poolbusy and fullpull returnleases must be observed with nativecurrentgetter, savedrestore destination/stack/TCB, per-task mutex/state/ownedlists and all wholememory journals.'],
  original_opcode_ranges={hex(s)+('_Thumb'if t else'_ARM'):rows(s,e,t)for s,e,t in((0x3b9b66,0x3b9c5e,True),(0x358bf8,0x358c2a,True),(0x358c2c,0x358c40,False),(0x358c40,0x358ce8,True),(0x2fcf44,0x2fcf6c,False),(0x2fcf6c,0x2fcfb0,True),(0x2fcfb0,0x2fcfec,False),(0x2fcfec,0x2fd01c,True),(0x2fd050,0x2fd06c,True),(0x2fd0a8,0x2fd0c4,True),(0x46cc7a,0x46cd08,True),(0x30ed08,0x30ed7c,True),(0x2fa286,0x2fa2a6,True),(0x2fa2a6,0x2fa2e8,True),(0x2fa430,0x2fa440,True),(0x2fa52a,0x2fa584,True))},
  compiled_opcode_ranges=elfrows,unchanged_prior_MMU_seals=prior,
  VM_import_or_instantiation=False,guest_execution=False,build_execution_by_this_review=False,device_io=False,canonical_write=False,
  native_source_or_mixer_scheduler_handoff_executed_by_this_review=False,exclusive_ownership_STOP_DONE_or_App_verified=False,
  limits=['Static source/ELF and original bounded instructions only; unrecursed allocator,mutex,wake,sync/calibration/clock/IRQ callees are not a complete kernel or audio lifecycle.',
   'Descriptor priority byte14 is already kernel priority; logical priority conversion from521E5E does not apply to this direct descriptor recipe.',
   'The source comment saying lowerprioritymixer only runs after grantsandblocks is conditional on intercepted sync/policy tail. It is not true for the full original3B9B66 tail by priorityalone.',
   'Build-only flags/comments inherited from the singleactor prototype do not prove new native actor scheduling or message success. Root owns the fresh actual guest and final scope assertions.'])
 assert not any(k=='unicorn'or k.startswith('unicorn.')for k in sys.modules)
 for p,h in sources.items():assert sha(ROOT/p)==h,p
 out=HERE/'mixer-handoff-build-v4-source-and-priority-review.json'
 with out.open('x')as f:json.dump(d,f,indent=2);f.write('\n')
 print(json.dumps(dict(all_passed=True,review=rel(out),review_sha256=sha(out),source_priority=12,mixer_priority=23,conditional_sync_tail_blocker=True,guest_execution=False)))
if __name__=='__main__':main()
