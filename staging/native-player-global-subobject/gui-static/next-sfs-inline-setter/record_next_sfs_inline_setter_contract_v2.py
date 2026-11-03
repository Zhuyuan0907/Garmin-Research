#!/usr/bin/env python3
"""Bounded file-only30399 inline setter contract; no VM or next helper."""
from pathlib import Path
from datetime import datetime,timezone
import hashlib,json,sys
ROOT=Path(__file__).resolve().parents[4]
STAGE=Path(__file__).resolve().parent
BASE='staging/native-player-global-subobject/'
sys.path.insert(0,str(ROOT/'scripts'))
from analyze_native_sections import NativeImage,EXPECTED
from capstone import Cs,CS_ARCH_ARM,CS_MODE_ARM,CS_MODE_THUMB
def sha(p):
    h=hashlib.sha256()
    with (ROOT/p).open('rb') as f:
        while block:=f.read(1024*1024):h.update(block)
    return h.hexdigest()
def read(p):return json.loads((ROOT/p).read_text())
def main():
    probe_path=BASE+'runtime-v2/terminal-probe.json';receipt_path=BASE+'runtime-v2/terminal-tool-receipt.json'
    t=read(probe_path);receipt=read(receipt_path)
    assert receipt['session_id']==30399 and receipt['authoritative_result_from_exec']
    assert receipt['actual_exec_result']['exit_code']==1 and receipt['actual_exec_result']['chunk_id']=='6ed1b9'
    assert not t['completed'] and t['cold_prefix_full_guards_passed'] and not t['body_full_guards_passed']
    assert t['callback_entry_seen'] and not t['callback_return_seen']
    assert t['registers']==dict(r0='0x3aaf81c',r1='0xb14',r2='0x0',r3='0x3',lr='0x26dd05',pc='0x44f76d0',sp='0x8804048')
    assert t['error']=='Dispatcher settings boundary: Unreviewed writer in bounded native SFS page'
    state=t['body_actor_observations']['settings_actor_observer'];global_state=t['body_actor_observations']['global_subobject_observer']
    assert not state['raw_ops'] and not state['defaults'] and not state['zero_calls']
    assert len(global_state['stores'])==1 and not global_state['base_native_return'] and not global_state['three_store_prefix_complete']
    assert len(global_state['once_calls'])==2 and all(r['actual_return_seen'] for r in global_state['once_calls'])
    sfs=state['frames'][str(0x26DCE8)];assert len(sfs)==1 and sfs[0]['SP']==0x8804090 and sfs[0]['LR']==0x26DE5D
    assert sfs[0]['arguments'][0]=='0x3aaed08' and not sfs[0]['returned']
    zone=t['body_zone_journals'][str(0x3AAF000)];rows=zone['stores']
    assert [(r['PC'],r['address'],r['size'],r['value']) for r in rows]==[
        ('0x26de42','0x3aaf844',4,0xC035F8),('0x26dcf6','0x3aaf818',1,0),('0x44f76d0','0x3aaf81c',4,0)]
    actual=bytearray.fromhex(zone['before_hex'])
    for r in rows:
        low=int(r['address'],16)-0x3AAF000;n=r['size'];assert actual[low:low+n].hex()==r['before_hex']
        actual[low:low+n]=r['value'].to_bytes(n,'little')
    partial=[r for r in t['partial_body_zone_verification'] if r['start']=='0x3aaf000']
    assert len(partial)==1 and hashlib.sha256(actual).hexdigest()==partial[0]['after_sha256']
    stock=NativeImage();copies=[r for r in stock.copies if r['runtime_start']<=0x44F76CE and 0x44F76D8<=r['runtime_end']]
    assert len(copies)==1 and stock.runtime_to_load(0x44F76CE,10)==0xE1B29A
    leaf=list(Cs(CS_ARCH_ARM,CS_MODE_THUMB).disasm(stock.read(0xE1B29A,10),0x44F76CE))
    assert [(i.mnemonic,i.op_str) for i in leaf]==[('movs','r2, #0'),('str','r2, [r0]'),('str','r2, [r0, #4]'),('strb','r2, [r0, #8]'),('bx','lr')]
    assert [i.bytes.hex() for i in leaf]==['0022','0260','4260','0272','7047']
    veneer=list(Cs(CS_ARCH_ARM,CS_MODE_ARM).disasm(stock.read(0x462FA4,4),0x462FA4))
    assert len(veneer)==1 and veneer[0].mnemonic=='ldr' and veneer[0].op_str=='pc, [pc, #-4]'
    assert stock.word(0x462FA8)==0x44F76CF
    caller=stock.instructions(0x26DCE8,0x26DD26);by_pc={i.address:i for i in caller}
    assert by_pc[0x26DD00].mnemonic==by_pc[0x26DD08].mnemonic=='blx'
    assert by_pc[0x26DD00].op_str==by_pc[0x26DD08].op_str=='#0x462fa4'
    assert stock.word(0x26E0B8)==0xFFFFF4EC
    assert by_pc[0x26DD04].mnemonic+' '+by_pc[0x26DD04].op_str=='adds r4, r0, r4'
    assert by_pc[0x26DD06].mnemonic+' '+by_pc[0x26DD06].op_str=='adds r0, r4, r5'
    assert by_pc[0x26DD0C].mnemonic+' '+by_pc[0x26DD0C].op_str=='movs r1, r5'
    # Static dataflow from the complete prologue/callsite, no guest execution.
    BASEPTR=0x3AAED08
    first=BASEPTR+0xB14;second=BASEPTR+0xB20
    assert first==0x3AAF81C and second==0x3AAF828
    calls=[];control_rows=[]
    for call,continuation,target,r1 in [(0x26DD00,0x26DD04,first,0xB14),(0x26DD08,0x26DD0C,second,0xB14)]:
        stores=[dict(PC=hex(0x44F76D0+2*i),load_PC=hex(0xE1B29C+2*i),address=hex(target+offset),size=n,
            value=0,source_register='r2',opcode_hex=opcode) for i,(offset,n,opcode) in enumerate([(0,4,'0260'),(4,4,'4260'),(8,1,'0272')])]
        calls.append(dict(original_call=hex(call),call_opcode_hex=by_pc[call].bytes.hex(),veneer='0x462fa4',
            ARM_literal='0x462fa8',leaf_Thumb_entry='0x44f76ce',LR=hex(continuation|1),continuation=hex(continuation),
            entry_SP='captured26DCE8entrySP-72',actual30399_SP='0x8804048',
            native_entry_r0=hex(target),native_entry_r1=hex(r1),stores=stores,
            leaf_callees=[],leaf_stack_bytes=0,actual_return_required=dict(R0=hex(target),R1=hex(r1),R2=0,SP='same native entrySP',mode='Thumb'),
            runtime_completion_observed=False))
        for before in (bytes(9),bytes.fromhex('112233445566778899')):
            after=bytearray(before)
            for offset,n in [(0,4),(4,4),(8,1)]:after[offset:offset+n]=bytes(n)
            assert after==bytes(9)
            control_rows.append(dict(kind='static9byte_shape',target=hex(target),before_hex=before.hex(),after_hex=after.hex(),
                neighboring_padding_admitted=False,guest_execution=False))
    leaf_rows=[dict(PC=hex(i.address),load_PC=hex(stock.runtime_to_load(i.address,i.size)),opcode_hex=i.bytes.hex(),
        instruction=i.mnemonic+' '+i.op_str,size=i.size,successors=[hex(i.address+2)] if i.mnemonic!='bx' else [],
        returns_to='actual LR' if i.mnemonic=='bx' else None) for i in leaf]
    source_paths=[str(Path(__file__).resolve().relative_to(ROOT)),probe_path,receipt_path,
        BASE+'runtime-v2/runner-at-run.py',BASE+'runtime-v2/inputs-before-run.json',
        BASE+'gui-static/global_subobject_observer_v2.py',BASE+'gui-static/global-subobject-observer-v2-contract.json',
        'staging/native-player-settings-scope/gui-static/settings_actor_observer.py',
        'scripts/probe_native_dispatcher_global_subobject_v2.py','scripts/analyze_native_sections.py',
        'evidence/firmware-analysis/main_02bd.bin',
        str(Path(__file__).resolve().with_name('record_next_sfs_inline_setter_contract.py').relative_to(ROOT)),
        str(STAGE.relative_to(ROOT))+'/next-sfs-inline-setter-contract.json']
    metadata=ROOT/BASE/'runtime-v2/terminal-metadata.json'
    if metadata.exists():
        m=json.loads(metadata.read_text());assert m['session_id']==30399 and m['terminal_exit_code']==1
        assert sha(probe_path)==m['probe_sha256'];source_paths.append(str(metadata.relative_to(ROOT)))
    doc=dict(superseded_static_candidate=dict(path=str(STAGE.relative_to(ROOT))+'/next-sfs-inline-setter-contract.json',sha256=sha(str(STAGE.relative_to(ROOT))+'/next-sfs-inline-setter-contract.json'),guest_execution=False,wrong_field='Second entryR1 was listedB20; exact original26DD0C setsB20 only after second return, so second entry and returnR1 remainB14',runtime_or_firmware_failure=False),updated_utc=datetime.now(timezone.utc).isoformat(),source_sha256={p:sha(p) for p in source_paths},
        exact_target=dict(HWID=1352,software='8.00',MAIN_sha256=EXPECTED),analysis='complete bounded original inline9-byte initializer and two exact SFS caller shapes',
        guest_execution=False,VM_import_or_instantiation=False,device_io=False,new_helper_generated=False,
        actual_terminal=dict(session_id=30399,exit_code=1,chunk='6ed1b9',registers=t['registers'],
            original_store_seen=rows[-1],actual_page_before_and_three_store_history_replay_SHA=partial[0]['after_sha256'],
            whole_page_observer_scope_gap=True,firmware_fault_proven=False),
        runtime_qualification=dict(original_caller_stack_v2_passed=True,first_global_vtable_store_passed=True,outer_and_inner_once_returned=True,
            global_stores_completed=1,total_expected_global_stores=3,base_returned=False,SFS_returned=False,
            first_inline_initializer_return_observed=False,second_inline_initializer_entered=False,
            settings_raw_executed=False,settings_default_executed=False,native_memzero_executed=False,
            fullbody=False,foreground=False,physicalApp=False),
        original_copy_provenance=dict(copy=copies[0],startup_conditional=True,physical_startup_flag_proven=False,
            runtime_leaf_start='0x44f76ce',runtime_leaf_end_exclusive='0x44f76d8',load_start='0xe1b29a',load_end_exclusive='0xe1b2a4',
            exact10byte_leaf_SHA=hashlib.sha256(stock.read(0xE1B29A,10)).hexdigest(),runtime_actual_store_bytes_match_original=True),
        complete_leaf_CFG=dict(entry='0x44f76ce',Thumb=True,all5_instructions=leaf_rows,
            direct_or_indirect_callees=[],stack_delta=0,return_behavior='BX LR, r0/r1/r3/LR/SP unchanged; r2=0, MOVS updates native flags',
            original_ARM_veneer=dict(entry='0x462fa4',opcode_hex=veneer[0].bytes.hex(),instruction='ldr pc, [pc, #-4]',
                literal='0x462fa8',literal_value='0x44f76cf',mode_change='Thumb BLX to ARM veneer, LDR-PC bit1 re-enters Thumb leaf, BXLR returns original Thumb caller')),
        exact_source_dataflow=dict(captured_containing_function=sfs[0],native_object_base='0x3aaed08',
            prologue_R4_literal=dict(PC='0x26dcee',literal='0x26e0b8',value='0xfffff4ec',signed_value=-0xB14),
            first_call='26DCFA RSBS R1,R4,#0 givesB14;26DCFE ADD R0,R0,R1 givesBASE+B14; actual26DD00 BLX',
            after_first_return='26DD04 ADD R4,R0,R4 recoversBASE because leaf preservesR0',
            second_call='26DCF8 R5=59;26DCFC LSL5 producesB20;26DD06 R0=R4+R5 yieldsBASE+B20; R1 staysB14 through first leaf return and26DD04/26DD06; actual26DD08 BLX',
            after_second_return='26DD0C R1=R5=B20;26DD0E R4=R0-R1 recoversBASE;26DD10 R5=BASE+B20',
            original_callsite_instructions=[dict(PC=hex(i.address),opcode_hex=i.bytes.hex(),instruction=i.mnemonic+' '+i.op_str) for i in caller]),
        minimal_next_scope=dict(actor='Only actualD8804FB8/currentF09090/captured native26DCE8→26DE58 frame and its declared live native stack',
            input='Capture real wholepage/each9-byte beforebytes; preserve original mapped bytes and native object/literal provenance; no reset or scalar seed',
            calls=calls,exact_total_original_stores=6,
            pending_ledger='Capture native26DD00/26DD08 call→actualARMveneer→actualThumbleaf; only own three store events in PC/addr/size/value order, then exact actual caller continuation/SP/R0 before any next call',
            mode_guard='ActualCPSR at veneer must ARM; at leaf/store/return must Thumb; never assume inherited default mode',
            unchanged_parent_guards='Delegate every other wholepage write, native settings/raw300A0A/30092A epilogue, FP/GIR/font/cache and global-object observers',
            forbidden='No generic zero-store or arbitrary9-byte setter allowance, host invoke, seeded state, stub return, guest register/context writes',
            fields_order=[dict(offset='B10',address='0x3aaf818',size=1,writer='0x26dcf6',status='already original parent direct-store observed'),
                dict(offset='B14',address='0x3aaf81c',size=4,writer='0x44f76d0',status='first call first store observed'),
                dict(offset='B18',address='0x3aaf820',size=4,writer='0x44f76d2',status='prospective'),
                dict(offset='B1C',address='0x3aaf824',size=1,writer='0x44f76d4',status='prospective, byte only'),
                dict(offset='B20',address='0x3aaf828',size=4,writer='0x44f76d0',status='second call prospective'),
                dict(offset='B24',address='0x3aaf82c',size=4,writer='0x44f76d2',status='second call prospective'),
                dict(offset='B28',address='0x3aaf830',size=1,writer='0x44f76d4',status='second call prospective, byte only')],
            padding_excluded=['B11..B13','B1D..B1F','B29..B2B'],
            subsequent_native_parent_sequence='Original26DD14 byteB2C,26DD16 wordB34,26DD1A byteB38,26DD20 byteB39, then originalARM35B4F4 clearsBASE..BASE+B10 exclusive; inherited frozen parent scope stays unchanged'),
        pure_host_static_controls=control_rows,all_static_shape_controls_passed=True,
        no_existing_frozen_sources_or_canonical_modified=True)
    output=STAGE/'next-sfs-inline-setter-contract-v2.json'
    with output.open('x') as f:json.dump(doc,f,ensure_ascii=False,indent=2);f.write('\n')
    print(json.dumps(dict(path=str(output.relative_to(ROOT)),sha256=sha(str(output.relative_to(ROOT))),
        original_leaf_instructions=5,static_shapes=len(control_rows),guest_execution=False,new_helper_generated=False)))
if __name__=='__main__':main()
