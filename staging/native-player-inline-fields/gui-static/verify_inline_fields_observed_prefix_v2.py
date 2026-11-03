#!/usr/bin/env python3
"""Independent sealed-file inline-fields prefix replay; no guest VM import.

Run only after root supplies the authoritative terminal receipt and sealer
metadata. Missing operations/returns produce a partial observation, never a
completed native closure. Output uses exclusive create to preserve evidence.
"""
from pathlib import Path
from datetime import datetime,timezone
import argparse,hashlib,json,sys
ROOT=Path(__file__).resolve().parents[3]
STAGE=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'scripts'))
from analyze_native_sections import NativeImage,EXPECTED
from capstone import Cs,CS_ARCH_ARM,CS_MODE_ARM,CS_MODE_THUMB
BASE='staging/native-player-inline-fields/'
PAGE=0x3AAF000
D=0x8804FB8
LEAF=0x44F76CE
LEAF_LOAD=0xE1B29A
PC_OPS=[(LEAF,'0022'),(LEAF+2,'0260'),(LEAF+4,'4260'),(LEAF+6,'0272'),(LEAF+8,'7047')]
CALLS=[(0x26DD00,0x26DD04,0x3AAF81C),(0x26DD08,0x26DD0C,0x3AAF828)]
GAPS=[(0x3AAF819,3),(0x3AAF825,3),(0x3AAF831,3)]
STORE_KEYS=['PC','load_PC','Thumb','address','size','value','before_hex','opcode_hex','original_instruction','running_task']
def read(p):return json.loads((ROOT/p).read_text())
def sha(p):
    h=hashlib.sha256()
    with (ROOT/p).open('rb') as f:
        while chunk:=f.read(1024*1024):h.update(chunk)
    return h.hexdigest()
def normalize(s):return {k:s[k] for k in STORE_KEYS}
def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--metadata',default=BASE+'runtime/terminal-metadata.json')
    parser.add_argument('--output',default=BASE+'gui-static/inline-fields-observed-prefix.json')
    args=parser.parse_args()
    assert not (ROOT/args.output).exists(),'Preserve previous independent file proof'
    meta=read(args.metadata);t=read(meta['probe']);receipt=read(meta['terminal_tool_receipt'])
    assert meta['authoritative_terminal_result_received_from_exec'] is True
    assert receipt['source']=='Authoritative tools.write_stdin return for the same original live35110 handle; no restart.'
    actual=receipt['actual_exec_result']
    assert 'session_id' not in actual and actual['exit_code'] in (0,1)
    assert meta['session_id']==receipt['session_id']==35110
    assert actual['exit_code']==meta['terminal_exit_code']==(0 if t['completed'] else 1)
    assert actual['chunk_id']==meta['actual_exec_chunk']
    expected_gui='f8ef74225acadc6a8e9ec13791baf9103a5227e66c1532ce177d2226e6a8c681'
    expected_runner='9585208df30e30f11e8151c5c910d86cd0082835add9890da233bb2bdee2e3e8'
    assert meta['GUI_observer_sha256']==expected_gui and meta['runner_sha256']==expected_runner
    checked={}
    for key in ['runner','runner_snapshot','inputs','probe','FP_helper','GUI_observer','sealer','terminal_tool_receipt','cold_prefix']:
        if key not in meta:continue
        p=meta[key];h=sha(p);assert h==meta[key+'_sha256'],key;checked[p]=h
    assert t['source_sha256_before_run']==expected_runner and meta['runner_snapshot_sha256']==expected_runner
    for p,h in checked.items():
        if p in meta['source_sha256']:assert meta['source_sha256'][p]==h
    stock=NativeImage();dis={True:Cs(CS_ARCH_ARM,CS_MODE_THUMB),False:Cs(CS_ARCH_ARM,CS_MODE_ARM)}
    leaf=list(dis[True].disasm(stock.read(LEAF_LOAD,10),LEAF))
    assert [(i.address,i.bytes.hex()) for i in leaf]==PC_OPS
    assert [i.mnemonic+' '+i.op_str for i in leaf]==['movs r2, #0','str r2, [r0]','str r2, [r0, #4]','strb r2, [r0, #8]','bx lr']
    assert stock.runtime_to_load(LEAF,10)==LEAF_LOAD
    veneer=list(dis[False].disasm(stock.read(0x462FA4,4),0x462FA4))
    assert len(veneer)==1 and veneer[0].bytes.hex()=='04f01fe5'
    assert veneer[0].mnemonic+' '+veneer[0].op_str=='ldr pc, [pc, #-4]' and stock.word(0x462FA8)==LEAF|1
    for call,_,_ in CALLS:
        ins=list(dis[True].disasm(stock.read(call,4),call));assert len(ins)==1 and ins[0].mnemonic+' '+ins[0].op_str=='blx #0x462fa4'
    opcodes={}
    def original_store(s):
        pc=int(s['PC'],16);load=int(s['load_PC'],16);op=bytes.fromhex(s['opcode_hex']);thumb=s['Thumb']
        expected=stock.runtime_to_load(pc,len(op)) if any(r['runtime_start']<=pc and pc+len(op)<=r['runtime_end'] for r in stock.copies) else pc
        assert load==expected and stock.read(load,len(op))==op
        key=(pc,thumb,op.hex())
        if key not in opcodes:
            ins=list(dis[thumb].disasm(op,pc,count=1));assert len(ins)==1 and ins[0].size==len(op)
            assert ins[0].mnemonic.startswith(('str','stm','swp','push','vstm','vstr'))
            opcodes[key]=ins[0].mnemonic+' '+ins[0].op_str
        assert opcodes[key]==s['original_instruction']
    observer=t.get('body_actor_observations',{})
    fields=observer.get('inline_fields_observer',{})
    settings=observer.get('settings_actor_observer',{})
    global_state=observer.get('global_subobject_observer',{})
    inputs=fields.get('inputs');ops=fields.get('operations',[]);stores=fields.get('stores',[])
    assert len(ops)<=2 and len(stores)<=6
    page_info=None;page_before=None;page_after=None;page_stores=[]
    raw_zones=t.get('body_zone_journals',{})
    if str(PAGE) in raw_zones:
        zone=raw_zones[str(PAGE)];assert zone['start']==hex(PAGE) and zone['bytes']==4096
        page_before=bytes.fromhex(zone['before_hex']);assert len(page_before)==4096
        replay=bytearray(page_before);page_stores=zone['stores']
        for s in page_stores:
            low=int(s['address'],16)-PAGE;n=s['size']
            assert 0<=low and low+n<=4096 and n in (1,2,4,8)
            assert replay[low:low+n].hex()==s['before_hex'];original_store(s)
            replay[low:low+n]=s['value'].to_bytes(n,'little')
        page_after=bytes(replay)
        partial=t.get('partial_body_zone_verification',[])
        if not isinstance(partial,list):partial=[]
        matches=[r for r in partial if r['start']==hex(PAGE)]
        assert len(matches)==1,'Root has no actual-after whole-page replay SHA for this observed prefix'
        assert matches[0]['bytes']==zone['bytes']
        # Partial metadata supplies actual-after SHA; before/stores live in the raw journal above.
        assert matches[0]['whole_zone_replayed'] and hashlib.sha256(page_after).hexdigest()==matches[0]['after_sha256']
        page_info=dict(start=hex(PAGE),bytes=4096,CPU_store_count=len(page_stores),
            independent_before_value_replayed_after_sha256=hashlib.sha256(page_after).hexdigest(),matches_root_actual_after_sha256=True)
    if inputs:
        assert inputs==t['settings_inputs_after_cold_prefix']['inline_fields_inputs']
        assert inputs['original_current']==inputs['captured_running_task']=='0x9503f90'
        assert not inputs['actual_mapped_bytes_reset'] and not inputs['host_seeded_scalar_or_backend']
        assert page_before is not None and inputs['whole_page_before_sha256']==hashlib.sha256(page_before).hexdigest()
        assert [(r['start'],r['bytes']) for r in inputs['fields']]==[(hex(target),9) for _,_,target in CALLS]
        assert [(r['start'],r['bytes']) for r in inputs['padding']]==[(hex(p),n) for p,n in GAPS]
        for r in inputs['fields']+inputs['padding']:
            start=int(r['start'],16);n=r['bytes'];assert r['before_hex']==page_before[start-PAGE:start-PAGE+n].hex()
    else:assert not ops and not stores,'Operations cannot exist without captured input beforebytes'
    frame_history=settings.get('frame_history',[])
    sfs=[r for r in frame_history if r['entry']=='0x26dce8']
    if ops:assert len(sfs)==1 and sfs[0]['LR']==0x26DE5D and sfs[0]['arguments'][0]=='0x3aaed08'
    flattened=[];returns=0;detailed=[]
    for index,row in enumerate(ops):
        call,cont,target=CALLS[index];T=sfs[0]['SP']
        assert row['continuation']==cont and row['LR']==cont|1 and row['entry_SP']==T-72 and row['SFS_entry_SP']==T
        assert row['target']==target and row['entry_arguments'][:2]==[target,0xB14]
        assert row['before_hex']==inputs['fields'][index]['before_hex'] and row['original_ARM_veneer_seen']
        assert not row['host_return_supplied'] and not row['guest_context_restored_by_host']
        shape=dict(call=call,continuation=cont,LR=cont|1,entry_SP=T-72,veneer=0x462FA4,
            leaf=LEAF,leaf_load=LEAF_LOAD,target=target,bytes=9,entry_R1=0xB14)
        assert row['reviewed_shape']==shape
        sequence=row['instructions_seen'];assert sequence==[pc for pc,_ in PC_OPS][:len(sequence)] and len(sequence)<=5
        assert row['leaf_entry_seen']==bool(sequence)
        own=row['stores'];assert len(own)<=3
        local=bytearray.fromhex(row['before_hex'])
        for i,s in enumerate(own):
            offset,n,pc,opcode=[(0,4,LEAF+2,'0260'),(4,4,LEAF+4,'4260'),(8,1,LEAF+6,'0272')][i]
            assert (int(s['PC'],16),int(s['load_PC'],16),int(s['address'],16),s['size'],s['value'],s['opcode_hex'])==(
                pc,LEAF_LOAD+pc-LEAF,target+offset,n,0,opcode)
            assert pc in sequence and s['Thumb'] and s['running_task']==hex(D)
            assert local[offset:offset+n].hex()==s['before_hex'];original_store(s)
            local[offset:offset+n]=bytes(n);flattened.append(s)
        assert row['original_return_branch_seen']==(len(sequence)==5)
        if row['actual_return_seen']:
            assert len(own)==3 and len(sequence)==5 and row['original_return_branch_seen']
            assert row['actual_return_SP']==hex(T-72) and row['actual_return_arguments']==[
                hex(target),'0xb14','0x0',hex(row['entry_arguments'][3])]
            assert local==bytes(9) and row['after_hex']==local.hex() and row['after_sha256']==hashlib.sha256(local).hexdigest()
            returns+=1
        detailed.append(dict(call=hex(call),target=hex(target),entry_SP=hex(T-72),leaf_code_events=len(sequence),
            native_store_events=len(own),native_return_seen=row['actual_return_seen'],after_own_prefix_hex=local.hex()))
    assert [normalize(s) for s in stores]==[normalize(s) for s in flattened]
    both=len(ops)==2 and returns==2 and len(stores)==6
    assert fields.get('both_actual_returns_seen',False)==both
    pending=fields.get('pending')
    if pending is not None:assert ops and pending==ops[-1] and not pending['actual_return_seen']
    elif ops:assert all(row['actual_return_seen'] for row in ops)
    derived=[];unknown_narrow=[]
    for _,_,target in CALLS:
        if page_before is None:continue
        subset=[r for r in page_stores if target<=int(r['address'],16) and int(r['address'],16)+r['size']<=target+9]
        owned=[r for r in stores if target<=int(r['address'],16) and int(r['address'],16)+r['size']<=target+9]
        assert [normalize(r) for r in subset[:len(owned)]]==[normalize(r) for r in owned]
        unknown_narrow.extend(subset[len(owned):])
        derived.append(dict(start=hex(target),bytes=9,before_hex=page_before[target-PAGE:target-PAGE+9].hex(),
            terminal_after_hex=page_after[target-PAGE:target-PAGE+9].hex(),own_prefix_stores=len(owned),
            total_actual_terminal_stores=len(subset),derived_from_whole_page=True))
    padding=[]
    for target,n in GAPS:
        if page_before is None:continue
        events=[r for r in page_stores if target<int(r['address'],16)+r['size'] and int(r['address'],16)<target+n]
        before=page_before[target-PAGE:target-PAGE+n];after=page_after[target-PAGE:target-PAGE+n]
        padding.append(dict(start=hex(target),bytes=n,before_hex=before.hex(),after_hex=after.hex(),
            original_padding_unchanged=before==after,actual_writes=events))
    global_stores=global_state.get('stores',[])
    expected_global=[(0x26DE42,0x3AAF844,0xC035F8),(0x26DE6C,0x3AAF848,0x3AAED08),(0x11EABE,0x3AAF844,0xC12D50)]
    assert len(global_stores)<=3
    for row,(pc,p,v) in zip(global_stores,expected_global):
        assert (int(row['PC'],16),int(row['address'],16),row['size'],row['value'])==(pc,p,4,v)
        assert normalize(row) in [normalize(s) for s in page_stores];original_store(row)
    menu=[r for r in frame_history if r['entry']=='0x40434c']
    ctor=bool(menu) and all(r['returned'] for r in menu)
    if ctor:
        assert len(menu)==1 and int(menu[0]['result'],16)==int(menu[0]['arguments'][0],16)
    unknowns=settings.get('unknown_boundaries',[]);last=unknowns[-1] if unknowns else None
    critical=['scripts/analyze_native_sections.py','evidence/firmware-analysis/main_02bd.bin',
        BASE+'gui-static/inline-fields-observer-contract.json',
        'staging/native-player-global-subobject/gui-static/global_subobject_observer_v2.py']
    for p in critical:
        h=sha(p)
        if p in meta['source_sha256']:assert h==meta['source_sha256'][p]
        checked[p]=h
    source=str(Path(__file__).resolve().relative_to(ROOT))
    dependencies=dict(checked);dependencies[source]=sha(source);dependencies[args.metadata]=sha(args.metadata)
    doc=dict(updated_utc=datetime.now(timezone.utc).isoformat(),all_passed=True,
        source_sha256=dependencies,verified_runtime_dependencies={p:h for p,h in checked.items() if p in meta['source_sha256']},
        root_sealed_runtime_dependency_registry_count=len(meta['source_sha256']),
        complete_registry_rescan_by_this_verifier=False,metadata_registry_integrity_referenced_by= args.metadata,
        proof_scope='Observed original inline-field prefix; completion flags are separate from file integrity checks',
        session_id=meta['session_id'],original_guest_exit_code=actual['exit_code'],actual_exec_chunk=actual['chunk_id'],
        guest_execution_by_this_verifier=False,guest_VM_imported_or_instantiated=False,device_io=False,
        actual_inline_operations=ops,actual_inline_stores=stores,both_actual_returns_seen=both,
        inline_prefix_observed=bool(ops),inline_native_closure_complete=both,
        actual_global_stores=global_stores,settings_raw_operations=settings.get('raw_ops',[]),
        constructor_return_verified=ctor,constructor_identity='OriginalMainMenu40434C allocated page, not merely SFS/base entry',
        next_unreviewed_writer=last['PC'] if last else None,next_target=last['actual_target'] if last else None,
        next_boundary=last,next_unreviewed_entry=t.get('registers',{}).get('PC') if not last else None,
        next_boundary_kind='execution observer/frame boundary' if not last else 'original page writer',
        original_error=t.get('error'),terminal_registers=t.get('registers'),
        superseded_file_verifier_source=BASE+'gui-static/verify_inline_fields_observed_prefix.py',
        superseded_file_verifier_failure=BASE+'gui-static/inline-fields-file-verifier-v1-schema-failure.json',
        independently_replayed_whole_page=page_info,derived_inline_ranges=derived,padding=padding,
        unmatched_terminal_narrow_stores=unknown_narrow,detailed_inline_operations=detailed,
        original_ARM_veneer=dict(PC='0x462fa4',opcode_hex='04f01fe5',literal='0x462fa8',target='0x44f76cf'),
        complete_five_instruction_Thumb_leaf=[dict(PC=hex(i.address),load_PC=hex(stock.runtime_to_load(i.address,i.size)),
            opcode_hex=i.bytes.hex(),instruction=i.mnemonic+' '+i.op_str) for i in leaf],
        original_store_opcode_modes_verified=len(opcodes),
        source_bound_entry_return_qualification='Native ARM/current-task/Thumb-entry/return register checks are the frozen observer emission contract; actual store modes/opcodes and before/value histories replay independently here',
        cold_prefix_full_guards_passed_recorded=t['cold_prefix_full_guards_passed'],
        cold_prefix_complete_suite_verified_by_this_file=False,callback_return_seen_recorded=t.get('callback_return_seen',False),
        body_full_guards_passed_recorded=t['body_full_guards_passed'],
        full_dispatcher_body_or_foreground_verified=False,physical_App_or_hardware_or_install_verified=False)
    with (ROOT/args.output).open('x') as f:json.dump(doc,f,ensure_ascii=False,indent=2);f.write('\n')
    print(json.dumps(dict(path=args.output,sha256=sha(args.output),all_passed=True,inline_operations=len(ops),
        stores=len(stores),both_actual_returns_seen=both,constructor_return_verified=ctor,guest_execution=False)))
if __name__=='__main__':main()
