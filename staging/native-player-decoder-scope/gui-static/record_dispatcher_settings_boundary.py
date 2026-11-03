#!/usr/bin/env python3
"""Bounded MAIN and file-backed terminal frame contract, no guest VM."""
from pathlib import Path
from datetime import datetime,timezone
import hashlib,json,struct,sys
ROOT=Path(__file__).resolve().parents[3]
STAGE=Path(__file__).resolve().parent
BASE='staging/native-player-decoder-scope/'
sys.path.insert(0,str(ROOT/'scripts'))
from analyze_native_sections import NativeImage
from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB
def sha(p):return hashlib.sha256((ROOT/p).read_bytes()).hexdigest()
def read(p):return json.loads((ROOT/p).read_text())
def replay(z):
    start=int(z['start'],16);out=bytearray.fromhex(z['before_hex'])
    for s in z['stores']:
        p=int(s['address'],16)-start;n=s['size'];assert out[p:p+n].hex()==s['before_hex']
        out[p:p+n]=s['value'].to_bytes(n,'little')
    return bytes(out)
def main():
    meta=read(BASE+'runtime/terminal-metadata.json');t=read(meta['probe']);stock=NativeImage()
    assert meta['session_id']==44634 and meta['terminal_exit_code']==1 and not t['completed']
    assert t['registers']['r0']=='0x148e6cc' and t['registers']['lr']=='0x2cabfb'
    assert t['registers']['sp']=='0x8804018' and t['error']=='Native raw mutex pointer/actor/storage differs'
    dzone=t['body_zone_journals'][str(0x8801024)];dbytes=replay(dzone)
    def w(p):return struct.unpack_from('<I',dbytes,p-0x8801024)[0]
    assert w(0x880402C)==0x2CAD37 and w(0x8804044)==0x26DD39
    pushes=[s for s in dzone['stores'] if s['PC'] in ('0x2cabbc','0x2cad0a')]
    assert len(pushes)==12 and all(s['running_task']=='0x8804fb8' and s['size']==4 for s in pushes)
    bzone=t['journal_zones'][str(0x148E680)];bbytes=replay(bzone);off=0x148E6CC-0x148E680
    raw=bbytes[off:off+24];words=list(struct.unpack('<6I',raw))
    assert words==[0,0x9503FB0,0,0,0x2CBF6C,0]
    init=[s for s in bzone['stores'] if s['PC'] in [hex(p) for p in range(0x3008A2,0x3008AE,2)]
          and 0x148E6CC<=int(s['address'],16)<0x148E6CC+24]
    assert len(init)==6 and [(int(s['address'],16),s['value']) for s in init]==[(0x148E6CC+4*i,0) for i in range(6)]
    tagstores=[s for s in bzone['stores'] if s['PC']=='0x2cbd58' and s['address']=='0x148e6dc']
    assert len(tagstores)==1 and tagstores[0]['value']==0x2CBF6C
    assert all(s['running_task']=='0x9503f90' for s in init+tagstores)
    assert stock.word(0x2CADC8)==0x148E6CC and stock.word(0x26E0BC)==0x100D
    pagepush=[s for s in dzone['stores'] if s['PC']=='0x40434c']
    assert len(pagepush)==7 and pagepush[-1]['value']==0x4053C3
    pageentry=int(pagepush[-1]['address'],16)+4
    assert pageentry==0x8804F50 and pagepush[0]['value']!=0
    ranges=[(0x2CABBC,0x2CAC22),(0x2CAD0A,0x2CAD5E),(0x26DD26,0x26DD3E)]
    md=Cs(CS_ARCH_ARM,CS_MODE_THUMB);evidence=[]
    for lo,hi in ranges:
        ins=list(md.disasm(stock.read(lo,hi-lo),lo));assert ins[-1].address+ins[-1].size==hi
        evidence.extend(dict(PC=hex(i.address),opcode_hex=i.bytes.hex(),instruction=i.mnemonic+' '+i.op_str) for i in ins)
    deps=[str(Path(__file__).resolve().relative_to(ROOT)),BASE+'runtime/terminal-metadata.json',meta['probe'],
        BASE+'runtime/terminal-tool-receipt.json',meta['runner'],meta['GUI_observer'],
        BASE+'gui-static/decoder-native-prefix-partial-verification.json',
        'scripts/probe_mainmenu_native_settings_journal.py','scripts/probe_native_player_mainmenu.py',
        'staging/native-player-mainmenu-native-prep/mutex-static/mainmenu-native-settings-mutex-preflight.json',
        'scripts/analyze_native_sections.py','evidence/firmware-analysis/main_02bd.bin']
    doc=dict(updated_utc=datetime.now(timezone.utc).isoformat(),static_and_supplied_runtime_record_review=True,
        guest_execution=False,guest_VM_imported_or_instantiated=False,frozen_sources_or_canonical_modified=False,
        source_sha256={p:sha(p) for p in deps},session_id=44634,authoritative_terminal_exit_code=1,
        terminal_error=t['error'],terminal_registers=t['registers'],
        guard=dict(source='scripts/probe_mainmenu_native_settings_journal.py:105',
            predicate='r0==reviewedpointer and running_task==controller and ready_current==controller and declared_storage(pointer,24)',
            current_boundary='Original raw caller/pointer match settingsget pair; actual queuedDispatcher stack is present. Old controller-only admission rejects this actor before native rawbody/ledger begin.',
            firmware_fault_or_deadlock_proven=False),
        actor_contract=dict(actor='original constructed Dispatcher0x8804FB8',callback_SP='0x8804f78',
            PageMainMenu_entry_SP=hex(pageentry),PageMainMenu_original_call='0x4053be',PageMainMenu_actual_LR='0x4053c3',
            observed_page_ctor_pointer=hex(pagepush[0]['value']),observed_page_ctor_flag=pagepush[1]['value'],
            PageMainMenu_return_observed=False,settings_containing_function='0x2cabbc',
            settings_function_entry_SP='T=0x8804030',function_push_bytes=24,
            lock=dict(entry='0x3009a0',call='0x2cabf6',continuation='0x2cabfa',LR='0x2cabfb',SP='T-24=0x8804018'),
            unlock=dict(entry='0x3008b0',call='0x2cac04',continuation='0x2cac08',LR='0x2cac09',SP='T-24'),
            pointer='0x148e6cc',literal='0x2cadc8',tag='0x2cbf6c',tag_ascii='&get_smphr',classification_byte=0,
            native_pending_compatibility='Only this actualD pair adds existing native_mutex_runs/task_mutex_ops[D] rows; native300A0A/30092A remain delegated, with actual caller/SP/result/ownership checks. Controller init/other36 pairs stay unchanged.',
            fullsettings_or_original_raw_return_observed=False),
        exact_frame_witnesses=dict(original_stack_pushes=pushes,
            inner_saved_LR=dict(address='0x880402c',value='0x2cad37',original_call='0x2cad32',callee='0x2cabbc'),
            outer_entry_SP='0x8804048',outer_saved_LR=dict(address='0x8804044',value='0x26dd39',original_call='0x26dd34',callee='0x2cad0a'),
            original_settings_id_literal='0x26e0bc',original_settings_id='0x100d',
            outer_arguments=dict(r0='0x100d',r1='0x3aaf838',r2=4,r3='0x8804048'),
            child_arguments=dict(r0='0x100d',r1='0x8804048'),
            current_child_local_output_word=hex(w(0x8804018))),
        backend_before_native_entry=dict(raw24_hex=raw.hex(),words=[hex(v) for v in words],
            whole_inherited_zone_replayed_to_derive=True,native_initializer_six_zero_witnesses=init,
            native_controller_tag_store=tagstores[0],native_owner=0,native_waiter=0,native_depth=0,
            released_plus4_link='0x9503fb0 retained from prior originalcontroller ownership',
            no_reinitialization_or_host_seed_required_or_authorized=True),
        known_next_lower_input=dict(entry='0x2cab14',call='0x2cabfe',continuation='0x2cac02',
            r0='actualsettingsid100D',r1='original local outputSP0x8804018',
            existing_parent_fixture='MainMenuVM at scripts/probe_native_player_mainmenu.py:77 supplies no record for IDs other than19B when catalog fixture exists and output word is0; this is a declared lower inventory input, not physical settings content.',
            candidate_no_record_branch='If actual existing lower fixture returns no record, original2CABBC returnsFFFFFFFF, original2CAD0A performs no memcpy, and26DD38 nonpositive branch may execute26DD3C zero store at actualR7+30=3AAF838.',
            future_callback_or_store_actual_execution_not_proven=True,
            scope_warning='That possible3AAF838 writer lies in3AAF000, outside rootnew3AAE000 page; require its own original store/input scope before claiming full newGUI memory closure.'),
        exact_original_instruction_evidence=evidence,bounded_MAIN_ranges=len(ranges),
        full_Dispatcher_body_or_foreground_or_hardware_or_App_verified=False)
    out=STAGE/'dispatcher-settings-2cabfa-boundary-contract.json'
    with out.open('x') as h:json.dump(doc,h,ensure_ascii=False,indent=2);h.write('\n')
    print(json.dumps(dict(path=str(out.relative_to(ROOT)),sha256=sha(str(out.relative_to(ROOT))),instructions=len(evidence))))
if __name__=='__main__':main()
