#!/usr/bin/env python3
"""Independent file-backed partial decoder proof; no guest VM import/run."""
from pathlib import Path
from datetime import datetime,timezone
import hashlib,json,struct,sys
ROOT=Path(__file__).resolve().parents[3]
STAGE=Path(__file__).resolve().parent
BASE='staging/native-player-decoder-scope/'
sys.path.insert(0,str(ROOT/'scripts'))
from analyze_native_sections import NativeImage
from capstone import Cs,CS_ARCH_ARM,CS_MODE_ARM,CS_MODE_THUMB
D=0x8804FB8
DECODER=0x2D1654C
SLOT=0x2D1F9D0
BACKEND=SLOT+4
TABLE=0x2D1FA30
ROOT_ZONES={0x9500000:16384,0x8801024:16384,0x34F9000:4096,
            0x3AAE000:4096,0x2D16000:4096,0x2D1F000:4096}
def read(p):return json.loads((ROOT/p).read_text())
def sha(p):return hashlib.sha256((ROOT/p).read_bytes()).hexdigest()
def word(data,offset):return struct.unpack_from('<I',data,offset)[0]
def main():
    meta=read(BASE+'runtime/terminal-metadata.json');t=read(meta['probe'])
    receipt_path=BASE+'runtime/terminal-tool-receipt.json';receipt=read(receipt_path)
    assert meta['session_id']==receipt['session_id']==44634
    assert meta['authoritative_terminal_result_received_from_exec'] and meta['terminal_exit_code']==1
    assert receipt['actual_exec_result']['exit_code']==1 and receipt['actual_exec_result']['chunk_id']=='66f1d6'
    assert not t['completed'] and t['cold_prefix_full_guards_passed'] and not t['body_full_guards_passed']
    assert t['callback_entry_seen'] and not t['callback_return_seen']
    assert t['error']=='Native raw mutex pointer/actor/storage differs'
    for key in ['runner','runner_snapshot','inputs','probe','FP_helper','GUI_observer','sealer','cold_prefix']:
        assert sha(meta[key])==meta[key+'_sha256'],key
    for p,h in meta['source_sha256'].items():assert sha(p)==h,p
    protected=read(BASE+'previous-audit.json')['protected_sources']
    assert len(protected)==892 and all(sha(p)==h for p,h in protected.items())
    stock=NativeImage();dis={True:Cs(CS_ARCH_ARM,CS_MODE_THUMB),False:Cs(CS_ARCH_ARM,CS_MODE_ARM)}
    checked={}
    def original_store(s):
        pc=int(s['PC'],16);load=int(s['load_PC'],16);op=bytes.fromhex(s['opcode_hex']);thumb=s['Thumb']
        expect=stock.runtime_to_load(pc,len(op)) if any(r['runtime_start']<=pc and pc+len(op)<=r['runtime_end'] for r in stock.copies) else pc
        assert load==expect and stock.read(load,len(op))==op
        key=(pc,thumb,op)
        if key not in checked:
            ins=list(dis[thumb].disasm(op,pc,count=1))
            assert len(ins)==1 and ins[0].size==len(op)
            assert ins[0].mnemonic.startswith(('str','stm','swp','push','vstm','vstr'))
            checked[key]=ins[0].mnemonic+' '+ins[0].op_str
        assert checked[key]==s['original_instruction']
    def replay(row):
        lo=int(row['start'],16);n=row['bytes'];out=bytearray.fromhex(row['before_hex']);assert len(out)==n
        for s in row['stores']:
            p=int(s['address'],16)-lo;m=s['size']
            assert 0<=p and p+m<=n and m in (1,2,4,8)
            assert out[p:p+m].hex()==s['before_hex'];original_store(s)
            out[p:p+m]=s['value'].to_bytes(m,'little')
        return bytes(out)
    partial={int(z['start'],16):z for z in t['partial_body_zone_verification']}
    assert {p:z['bytes'] for p,z in partial.items()}==ROOT_ZONES
    final={};whole=[]
    for p,z in partial.items():
        journal=t['body_zone_journals'][str(p)]
        assert z['before_hex']==journal['before_hex'] and z['stores']==journal['stores']
        data=replay(z);h=hashlib.sha256(data).hexdigest()
        assert z['whole_zone_replayed'] and h==z['after_sha256']
        final[p]=data;whole.append(dict(start=hex(p),bytes=z['bytes'],events=len(z['stores']),
            independent_replay_sha256=h,equals_root_recorded_actual_after_sha256=True))
    d=t['body_actor_observations']['decoder_actor_observer'];inputs=d['inputs']
    assert inputs==t['decoder_inputs_after_cold_prefix']
    assert not inputs['host_seeded_or_reset_bytes'] and not inputs['native_decoder_ctor_observed']
    assert inputs['original_current']==inputs['captured_running_task']=='0x9503f90'
    assert not d['raw_returns_pending'] and not d['unknown_boundaries']
    assert all(not frames for frames in d['frames'].values()) and not d['full_scoped_guards_passed']
    narrow=[]
    keys=['PC','load_PC','Thumb','address','size','value','before_hex','opcode_hex','original_instruction','running_task']
    for p,n in [(DECODER,24),(SLOT,32),(TABLE,24)]:
        z=d['zones'][str(p)];assert z['bytes']==n and bytes.fromhex(z['before_hex'])==bytes(n)
        assert any(x['start']==hex(p) and x['before_hex']==z['before_hex'] and not x['stores'] for x in inputs['rows'])
        page=p&~4095;off=p-page
        assert partial[page]['before_hex'][off*2:(off+n)*2]==z['before_hex']
        zs=replay(z);assert zs==final[page][off:off+n]
        subset=[s for s in partial[page]['stores'] if p<=int(s['address'],16) and int(s['address'],16)+s['size']<=p+n]
        assert [{k:s[k] for k in keys} for s in subset]==[{k:s[k] for k in keys} for s in z['stores']]
        prov=z['input_provenance'];r=prov['startup_zero_range']
        assert r in stock.zeros and r['runtime_start']<=p and p+n<=r['runtime_end']
        assert not prov['captured_native_initializer_rows'] and not prov['native_constructor_execution_inferred_from_zero_bytes']
        narrow.append(dict(start=hex(p),bytes=n,events=len(z['stores']),
            final_hex=zs.hex(),derived_from_full_page_replay=True,
            narrow_history_exactly_matches_full_page_CPU_store_subset=True))
    assert [(r['events']) for r in narrow]==[6,6,0]
    assert narrow[2]['final_hex']==bytes(24).hex()
    slot_stores=d['zones'][str(SLOT)]['stores']
    statuses=[s for s in slot_stores if int(s['address'],16)==SLOT+28]
    assert [(s['PC'],s['size'],s['value'],s['before_hex']) for s in statuses]==[
        ('0x36945e',1,1,'00'),('0x3697c2',1,0,'01')]
    assert [(s['PC'],s['value']) for s in d['status_writes']]==[('0x36945e',1),('0x3697c2',0)]
    frames=d['frame_history'];expected=[(0x39720C,0x8804F50,0x405394,0),
        (0x396B3E,0x8804F40,0x397218,0),(0x36944A,0x8804F28,0x396B56,0),
        (0x369438,0x8804F18,0x369468,0),(0x3697CC,0x8804F28,0x396B68,8),
        (0x3697B8,0x8804F28,0x396B9C,BACKEND)]
    assert len(frames)==len(expected)
    for f,(entry,sp,cont,result) in zip(frames,expected):
        assert int(f['entry'],16)==entry and f['SP']==sp and f['LR']==cont|1
        assert f['returned'] and int(f['result'],16)==result
        call=f['original_call'];opcode=bytes.fromhex(call['opcode_hex']);pc=int(call['call'],16)
        assert stock.read(pc,len(opcode))==opcode and pc+len(opcode)==cont
        ins=list(dis[True].disasm(opcode,pc,count=1));assert len(ins)==1
        assert ins[0].mnemonic=='bl' and ins[0].op_str=='#'+hex(entry)
    assert frames[1]['arguments'][:2]==['0x0','0x8804f40']
    assert frames[2]['arguments'][:2]==['0x0','0x186a0']
    assert frames[3]['arguments'][:2]==['0x186a0','0x0']
    assert frames[4]['arguments']==['0x0','0x1','0x21','0x8804f30']
    # Original caller's stack1,1 is visible in the same full-stack history at
    # the call-time STRs, independently of the entry observer's frame tuple.
    ds=t['body_zone_journals'][str(0x8801024)]['stores']
    assert any(s['PC']=='0x396b58' and s['address']=='0x8804f28' and s['value']==1 for s in ds)
    assert any(s['PC']=='0x396b5a' and s['address']=='0x8804f2c' and s['value']==1 for s in ds)
    ops=d['raw_ops'];shapes=[(DECODER,0x396B4E,'lock',0x8804F28),
        (BACKEND,0x36945C,'lock',0x8804F18),(BACKEND,0x3697CA,'unlock',0x8804F20),
        (DECODER,0x396BA2,'unlock',0x8804F28)]
    assert len(ops)==4
    for o,(ptr,cont,kind,sp) in zip(ops,shapes):
        assert o in t['native_mutex_operations']
        assert int(o['pointer'],16)==ptr and int(o['native_caller'],16)==cont and o['operation']==kind
        assert o['running_task']=='0x8804fb8' and o['ready_head_at_epilogue']=='0x8804fb8'
        assert int(o['entry_SP'],16)==int(o['actual_return_SP'],16)==sp and int(o['entry_LR'],16)==cont|1
        assert o['native_body_returned'] and o['original_return_branch_reached'] and o['actual_caller_continuation_seen']
        assert o['original_return']==o['actual_return_r0']==(0 if kind=='lock' else ptr)
        before=[int(v,16) for v in o['before_words']];after=[int(v,16) for v in o['after_words']]
        assert after[2]==(D if kind=='lock' else 0) and after[3:]==[0,0,0]
        assert before[2]==(0 if kind=='lock' else D) and o['native_recursion_count']==0
        assert not o['host_CPU_context_restore'] and o['semaphore_fields_written_by_original_only']
    assert [o['thread_owned_list_head'] for o in ops]==[hex(DECODER),hex(BACKEND),hex(DECODER),'0x8810718']
    for p in (DECODER,BACKEND):
        raw=final[p&~4095][p%4096:p%4096+24]
        assert word(raw,8)==word(raw,12)==word(raw,16)==0 and raw[20:]==bytes(4)
        assert word(raw,0)!=0 and word(raw,4)==D+32 # Native released links deliberately remain.
    assert final[SLOT&~4095][(SLOT+28)%4096]==0
    # Terminal boundary comes later in native MainMenu code; it is preserved.
    assert t['registers']['pc']=='0x3009a0' and t['registers']['lr']=='0x2cabfb'
    assert t['registers']['r0']=='0x148e6cc' and t['registers']['sp']=='0x8804018'
    source=str(Path(__file__).resolve().relative_to(ROOT))
    paths=[source,BASE+'previous-audit.json',BASE+'runtime/terminal-metadata.json',meta['probe'],
        meta['inputs'],meta['runner_snapshot'],meta['cold_prefix'],receipt_path,
        'scripts/analyze_native_sections.py','evidence/firmware-analysis/main_02bd.bin',meta['GUI_observer']]
    doc=dict(updated_utc=datetime.now(timezone.utc).isoformat(),all_passed=True,
        proof_scope='Partial original native decoder query after completed cold prefix, before later settings actor guard',
        session_id=44634,original_guest_terminal_exit_code=1,actual_exec_chunk='66f1d6',
        guest_execution_by_this_verifier=False,guest_VM_imported_or_instantiated=False,device_IO=False,
        source_sha256={p:sha(p) for p in paths},verified_runtime_source_dependencies=meta['source_sha256'],
        protected_registry_count=892,verified_protected_sources=protected,
        independently_replayed_root_whole_zones=whole,derived_exact_decoder_slot_callback_ranges=narrow,
        original_store_opcode_modes_verified=len(checked),native_raw_operations=ops,
        exact_native_function_returns=frames,native_slot_status_writes=statuses,
        cold_zero_driver_qualification='Original startupzero ranges were explicit mapped input; actual beforebytes are allzero, table+16/+0 remainzero. Native369438 returned0, native3697CC returned8, original query returned0. Original39799E/hardware driver initialization and native decoder tag were not executed/proven.',
        actual_after_SHA_qualification='Independent replay equals SHA of final actual bytes recorded by root live verifier; this file verifier reads no guest state and infers no unrecorded physical state.',
        released_link_qualification='Native +0/+4 links remain nonzero after release; owners/waiters/tag/class/depth remainzero. They were never reset or required to become allzero.',
        later_boundary=dict(error=t['error'],registers=t['registers'],guard_source='scripts/probe_mainmenu_native_settings_journal.py:105'),
        callback_return_seen=False,fullbody_guards_verified=False,foreground_or_App_or_hardware_driver_verified=False,
        complete_multiowner_scheduling_or_D_to_C_to_D_exchange_verified=False,
        decoder_mixin_full_guard_was_called=False,
        scope_limit='Six root zones and three derived decoder ranges replay independently through the partial terminal boundary. Root attempt still failed before callback completion; this is not a complete foreground, scheduling, hardware or App suite.')
    out=STAGE/'decoder-native-prefix-partial-verification.json'
    with out.open('x') as h:json.dump(doc,h,ensure_ascii=False,indent=2);h.write('\n')
    print(json.dumps(dict(path=str(out.relative_to(ROOT)),sha256=sha(str(out.relative_to(ROOT))),
        full_zones=len(whole),narrow_zones=len(narrow),raw_operations=4,function_returns=6,guest_execution=False)))
if __name__=='__main__':main()
