#!/usr/bin/env python3
"""File-only39489 next-writer contract, not a settings/native closure proof."""
from pathlib import Path
from datetime import datetime,timezone
import hashlib,json,struct,sys
ROOT=Path(__file__).resolve().parents[3]
STAGE=Path(__file__).resolve().parent
BASE='staging/native-player-settings-scope/'
sys.path.insert(0,str(ROOT/'scripts'))
from analyze_native_sections import NativeImage,EXPECTED
from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB
from capstone.arm import ARM_OP_MEM,ARM_REG_PC
def read(p):return json.loads((ROOT/p).read_text())
def sha(p):return hashlib.sha256((ROOT/p).read_bytes()).hexdigest()
def replay(row):
    start=int(row['start'],16);out=bytearray.fromhex(row['before_hex'])
    assert len(out)==row['bytes']
    for store in row['stores']:
        i=int(store['address'],16)-start;n=store['size']
        assert 0<=i and i+n<=len(out) and out[i:i+n].hex()==store['before_hex']
        out[i:i+n]=store['value'].to_bytes(n,'little')
    return bytes(out)
def main():
    meta=read(BASE+'runtime/terminal-metadata.json');t=read(meta['probe'])
    receipt=read(meta['terminal_tool_receipt'])
    assert meta['session_id']==receipt['session_id']==39489
    assert meta['terminal_exit_code']==receipt['actual_exec_result']['exit_code']==1
    assert meta['actual_exec_chunk']==receipt['actual_exec_result']['chunk_id']=='4446d3'
    assert meta['authoritative_terminal_result_received_from_exec']
    for field in ['runner','runner_snapshot','inputs','probe','FP_helper','GUI_observer','sealer','cold_prefix','terminal_tool_receipt']:
        assert sha(meta[field])==meta[field+'_sha256'],field
    assert not t['completed'] and t['cold_prefix_full_guards_passed'] and not t['body_full_guards_passed']
    assert t['callback_entry_seen'] and not t['callback_return_seen']
    assert t['error']=='Dispatcher settings boundary: Unreviewed writer in bounded native SFS page'
    assert t['registers']==dict(r0='0xc035f8',r1='0x1',r2='0x8824320',r3='0x3',lr='0x11eabb',pc='0x26de42',sp='0x8804090')
    for path,digest in meta['source_sha256'].items():assert sha(path)==digest,path
    registry=read(BASE+'previous-audit.json')['protected_sources']
    assert len(registry)==1078 and all(sha(p)==h for p,h in registry.items())
    settings=t['body_actor_observations']['settings_actor_observer']
    assert all(not settings[k] for k in ['raw_ops','raw_returns_pending','lower_queries','defaults','direct_stores','zero_calls'])
    assert settings['source_id_witness'] is settings['zero_call'] is settings['default_pending'] is None
    unknown=settings['unknown_boundaries'];assert len(unknown)==1
    assert unknown[0]==dict(PC='0x26de42',reason='Unreviewed writer in bounded native SFS page',
        running_task='0x8804fb8',SP='0x8804090',actual_target='0x3aaf844',span_bytes=4,is_mapped=True,before_hex='00000000')
    whole=[];images={}
    for zone in t['partial_body_zone_verification']:
        actual=replay(zone);assert zone['whole_zone_replayed'] and hashlib.sha256(actual).hexdigest()==zone['after_sha256']
        start=int(zone['start'],16);images[start]=actual
        whole.append(dict(start=zone['start'],bytes=zone['bytes'],CPU_store_count=len(zone['stores']),
            independent_before_value_replay_matches_recorded_runtime_after_sha256=True,after_sha256=zone['after_sha256']))
    assert len(whole)==7
    page=t['body_zone_journals'][str(0x3AAF000)];assert len(page['stores'])==1
    actualstore=page['stores'][0]
    assert (actualstore['PC'],actualstore['address'],actualstore['size'],actualstore['value'],actualstore['opcode_hex'],actualstore['running_task'])==('0x26de42','0x3aaf844',4,0xC035F8,'2060','0x8804fb8')
    assert images[0x3AAF000][0x844:0x848]==struct.pack('<I',0xC035F8)
    # Mutable bank beforebytes are available for the first time in this runner.
    bank=t['partial_initialized_bank_verification'];initial=bytes.fromhex(t['mutable_bank_initial_before_hex'])
    assert len(initial)==bank['bytes'] and hashlib.sha256(initial).hexdigest()==bank['before_sha256']
    bank_image=replay(dict(bank,before_hex=initial.hex()))
    assert hashlib.sha256(bank_image).hexdigest()==bank['after_sha256']
    once=[r for r in bank['stores'] if int(r['address'],16)==0xF701FC]
    assert len(once)==1 and once[0]['PC']=='0x385450' and once[0]['size']==4 and once[0]['value']==1
    assert once[0]['before_hex']=='00000000' and once[0]['running_task']=='0x8804fb8'
    stack=images[0x8801024]
    def word(p):return struct.unpack_from('<I',stack,p-0x8801024)[0]
    assert word(0x8804094)==0x11EABB and word(0x88040E4)==0x114631 and word(0x88040FC)==0x1152D3
    stack_rows=t['body_zone_journals'][str(0x8801024)]['stores']
    pushes={hex(pc):[r for r in stack_rows if r['PC']==hex(pc)] for pc in [0x114612,0x11EAB2,0x26DE3C]}
    assert [len(pushes[hex(pc)]) for pc in [0x114612,0x11EAB2,0x26DE3C]]==[2,5,2]
    stock=NativeImage();md=Cs(CS_ARCH_ARM,CS_MODE_THUMB);md.detail=True;evidence=[];by_pc={};literals=[]
    spans=[(0x1152C8,0x1152D6),(0x114612,0x114652),(0x11EAB2,0x11EB32),
        (0x26DE32,0x26DE72),(0x385448,0x38545A),(0x362A2C,0x362A40)]
    for low,high in spans:
        raw=stock.read(low,high-low);rows=[]
        for i in md.disasm(raw,low):
            row=dict(PC=hex(i.address),opcode_hex=i.bytes.hex(),instruction=i.mnemonic+' '+i.op_str)
            if i.mnemonic=='ldr' and len(i.operands)==2 and i.operands[1].type==ARM_OP_MEM and i.operands[1].mem.base==ARM_REG_PC:
                p=((i.address+4)&~3)+i.operands[1].mem.disp
                row.update(literal=hex(p),literal_value=hex(stock.word(p)));literals.append(row)
            rows.append(row);by_pc[i.address]=row
        evidence.append(dict(start=hex(low),end_exclusive=hex(high),bytes_sha256=hashlib.sha256(raw).hexdigest(),instructions=rows))
    assert by_pc[0x1152CE]['instruction']=='bl #0x114612'
    assert by_pc[0x11462C]['instruction']=='bl #0x11eab2'
    assert by_pc[0x11EAB6]['instruction']=='bl #0x26de3c'
    assert by_pc[0x26DE42]['opcode_hex']=='2060' and by_pc[0x26DE42]['instruction']=='str r0, [r4]'
    assert by_pc[0x26DE32]['instruction']=='mov r8, r8'
    assert by_pc[0x11462A]['literal_value']=='0x3aaf844' and by_pc[0x26DE40]['literal_value']=='0xc035f8'
    assert by_pc[0x26DE6A]['literal_value']=='0x3aaed08' and by_pc[0x11EABA]['literal_value']=='0xc12d50'
    dependencies={p:sha(p) for p in [str(Path(__file__).resolve().relative_to(ROOT)),
        BASE+'previous-audit.json',BASE+'gui-static/settings_actor_observer.py',
        BASE+'gui-static/settings-actor-observer-contract.json',BASE+'runtime/terminal-metadata.json',
        *[meta[k] for k in ['runner','runner_snapshot','inputs','probe','terminal_tool_receipt','cold_prefix']],
        'scripts/analyze_native_sections.py','evidence/firmware-analysis/main_02bd.bin']}
    doc=dict(updated_utc=datetime.now(timezone.utc).isoformat(),source_sha256=dependencies,
        exact_target=dict(HWID=1352,software='8.00',MAIN_sha256=EXPECTED),
        analysis='new independent file-only bounded next-writer contract',guest_execution=False,VM_import_or_instantiation=False,
        authoritative_terminal=dict(session_id=39489,exit_code=1,actual_chunk='4446d3',registers=t['registers'],
            native_store_observed_and_committed_under_root_whole_page_replay=actualstore,
            observer_boundary=unknown[0],firmware_fault_proven=False),
        preserved_negative_scope=dict(settings_raw_executed=False,settings_default_executed=False,settings_zero_executed=False,
            settings_full_native_closure=False,fullbody=False,foreground=False,physicalApp=False,
            older44634_partial_settings_boundary_valid_with_its_original_six_page_scope=True,
            new_guard_reports_previously_unjournaled_global_page_writer=True),
        independent_file_checks=dict(protected_files=1078,metadata_source_hashes_verified=len(meta['source_sha256']),
            whole_body_pages_and_stacks=whole,total_stores=sum(r['CPU_store_count'] for r in whole),
            initialized_bank=dict(start=bank['start'],bytes=bank['bytes'],stores=len(bank['stores']),
                initial_before_sha256=bank['before_sha256'],replayed_after_sha256=bank['after_sha256'],
                matches_runtime_after_sha256=True),native_once_store=once[0]),
        object_provenance=dict(storage='0x3aaf844',bounded_base_subobject_bytes=8,
            storage_kind='Original global startup-zero storage, not an allocated MainMenu field or the old551C804 conditional-copy object',
            root_page_fixture='Only-if-unmapped3AAF000 original startup-zero mapping; existing mapped bytes preserved, no physical beforeRAM claim',
            original_global_literal=dict(instruction='0x11462a',literal='0x114688',value='0x3aaf844'),
            actual_D='0x8804fb8',actual_Current='Must equalF09090/D at every admitted constructor boundary/store',
            observed_call_stack=[dict(function='0x114612',entry_SP='0x8804100',saved_LR='0x1152d3',body_SP='entry-24'),
                dict(function='0x11eab2',entry_SP='0x88040e8',saved_LR='0x114631',body_SP='entry-80'),
                dict(function='0x26de3c',entry_SP='0x8804098',saved_LR='0x11eabb',body_SP='entry-8')],
            entry_argument_chain='11462A native literal R0=3AAF844 →11462C BL11EAB2; no argument-changing instruction before11EAB6 BL26DE3C; native26DE3E R4=R0',
            terminal_R4='Not separately serialized; effective R4 target is derived from original STR2060 address plus original entry/copy chain',
            outer_once='F701FC actual original385450 wrote0→1 under D before ctor; flag1 alone does not prove ctor completion',
            inner_once='F701F8 native385448/385450 gate for3AAED08 SFS constructor is prospective after this terminal',
            base_exit_registration='26DE60 original3896F8(R0=3AAED08 returned from SFS,R1=26DCB1,R2=C7F980), prospective',
            derived_exit_registration='114634 original3896F8(R0=3AAF844 returned from11EAB2,R1=11EA69,R2=C7F980), prospective',
            destructor_vtable_sources=dict(base_C035F8=[hex(stock.word(0xC035F8+4*i)) for i in range(4)],
                derived_C12D50=[hex(stock.word(0xC12D50+4*i)) for i in range(4)]),
            global_lifetime_inference='Once-gated global constructor plus registered original exit destructors; neither constructor return nor destructor execution proved by39489'),
        minimal_next_observer_contract=dict(
            entry_frames='Capture actual114612 and11EAB2/currentD/caller1152D2/114630, then26DE3C exactcaller11EABA; all original call/prologue bytes unchanged',
            before='Capture whole8-byte global subobject plus whole4096 page actualbefore; do not reset or require allzero on replay/reentry',
            write_order=[dict(PC='0x26de42',target='object+0=3AAF844',value='0xc035f8',size=4,
                original_opcode='2060',mode='Thumb',SP='captured26DE3Centry-8',binding='R4=object,R0=literalC035F8'),
                dict(PC='0x26de6c',target='object+4=3AAF848',value='0x3aaed08',size=4,
                mode='Thumb',SP='captured26DE3Centry-8',binding='R4=object,R0=literal3AAED08; after real nested SFS return or exact native once-skip branch'),
                dict(PC='0x11eabe',target='object+0=3AAF844',value='0xc12d50',size=4,
                original_opcode='0160',mode='Thumb',SP='captured11EAB2entry-80',binding='actual26DE3C return R0=object at11EABA, nativeR1=literalC12D50')],
            closure='Exact native26DE3C return11EABA with SPentrysame/R0object, then real11EAB2 return114630 with entrySP/R0object; preserve SFS/settings/raw/zero closure separately',
            non_generic='Only this global object and this captured dynamic caller; no blanket original-vtable writer permission or reuse of551C8047writer whitelist',
            first_additional_page_scope=dict(call='0x11eb28',entry='0x362a2c',continuation='0x11eb2c',
                R0='globalobject+8=3AAF84C from original11EAC2 stack+28',R1='captured11EAB2bodySP+18',
                R2='captured11EAB2bodySP+10 native heap8 functor pointer, not host-seeded',
                entry_SP='captured11EAB2entrySP-80',body_SP='entrySP-40',
                next_writes=[dict(PC='0x362a36',target='3AAF84C',value=0,opcode='02c0'),
                    dict(PC='0x362a38',target='3AAF850',value=0,opcode='0160')],
                admission=False,reason='Separate bounded container construction/actual allocator and native return provenance required; whole-page scope must reject it until admitted'),
            remaining_allocation_or_callback='11EAC6 native3954CC size8; later362A3C native3954CC size3C and callbacks/containers require actual returned pointers, live allocations and exact call frames; no invented defaults'),
        original_bounded_evidence=evidence,bounded_instruction_count=sum(len(e['instructions']) for e in evidence),
        no_existing_source_or_canonical_modified=True)
    path=STAGE/'settings-global-subobject-next-writer-contract.json'
    with path.open('x') as f:json.dump(doc,f,ensure_ascii=False,indent=2);f.write('\n')
    print(json.dumps(dict(artifact=str(path.relative_to(ROOT)),sha256=sha(str(path.relative_to(ROOT))),
        bounded_instructions=doc['bounded_instruction_count'],protected_files=1078,guest_execution=False)))
if __name__=='__main__':main()
