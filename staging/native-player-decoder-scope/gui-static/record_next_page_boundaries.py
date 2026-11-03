#!/usr/bin/env python3
"""Bounded original callback/page call sites; static only, no VM imports."""
from pathlib import Path
from datetime import datetime,timezone
import hashlib,json,sys
ROOT=Path(__file__).resolve().parents[3]
STAGE=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'scripts'))
from analyze_native_sections import NativeImage
from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB
def sha(p):return hashlib.sha256((ROOT/p).read_bytes()).hexdigest()
def main():
    stock=NativeImage();md=Cs(CS_ARCH_ARM,CS_MODE_THUMB)
    bounds=[(0x405386,0x4053E6),(0x40434C,0x404382),
            (0x36BA5C,0x36BAA2),(0x3404EC,0x3404F8),(0x38E696,0x38E6F6)]
    rows=[]
    for lo,hi in bounds:
        ins=list(md.disasm(stock.read(lo,hi-lo),lo));assert ins[-1].address+ins[-1].size==hi
        rows.extend(dict(PC=hex(i.address),opcode_hex=i.bytes.hex(),instruction=i.mnemonic+' '+i.op_str) for i in ins)
    assert stock.word(0x40545C)==0x3F04 and stock.word(0x40459C)==0xFFFFF5B4
    paths=[str(Path(__file__).resolve().relative_to(ROOT)),
        'scripts/probe_native_dispatcher_decoder.py','scripts/probe_native_dispatcher_body_fp.py',
        'staging/native-player-decoder-scope/gui-static/decoder_actor_observer_v2.py',
        'staging/native-player-decoder-scope/gui-static/runner-wiring-review-a9deadbb.json',
        'scripts/probe_native_controller_gir_component.py','scripts/probe_native_player_mainmenu.py',
        'scripts/analyze_native_sections.py','evidence/firmware-analysis/main_02bd.bin']
    doc=dict(updated_utc=datetime.now(timezone.utc).isoformat(),static_only=True,guest_execution=False,
        guest_VM_imported_or_instantiated=False,frozen_sources_or_canonical_modified=False,
        source_sha256={p:sha(p) for p in paths},bounded_MAIN_ranges=len(bounds),
        observed_runtime_boundary=False,
        ordered_possible_calls=['After original39720C result0, branch405396→4053A0',
            '4053A0 original391270 and conditional4053A8 original389970 determine flagR5',
            '4053B4 originalARM3954CC allocation','4053BE originalThumb40434C constructor',
            '4053C8 originalcached393A2C getter','4053D2 original38E696 manager transition'],
        allocator=dict(original_call='0x4053b4',entry='0x3954cc',entry_Thumb=False,
            literal_address='0x40545c',request='0x3f04',request_bytes=16132,
            LR='0x4053b9',actual_continuation='0x4053b8',SP='captured callback E-40',
            next_register_binding='4053B8 copies actual returnedr0 toR6; constructor receives actualr0. Require exact native/declared allocator backing and actual return rather than host object seed.',
            null_result='No null check between4053B8 and40434C. Unknown/failing allocation stays boundary evidence; no firmware fault inference.'),
        page_constructor=dict(entry='0x40434c',original_call='0x4053be',LR='0x4053c3',
            actual_continuation='0x4053c2',entry_SP='P=callback E-40',r0='actual allocator returned pointer',
            r1='actualR5 flag: initialized1 at405386, optionally0 at4053B0; capture branch result, do not force1',
            push_bytes=28,signed_stack_literal='0xfffff5b4 = -2636',literal_address='0x40459c',
            body_SP='P-2664 = callback E-2704; actual67576 E8804F78 would yield88044E8, derived only',
            first_base_call=dict(call='0x404358',entry='0x36ba5c',LR='0x40435d',entry_SP='P-2664'),
            base_widget_call=dict(call='0x36ba64',entry='0x3404ec',LR='0x36ba69',entry_SP='P-2704 = callback E-2744'),
            nested_initializer_call=dict(call='0x3404ee',entry='0x376464',LR='0x3404f3',entry_SP='P-2712 = callback E-2752',
                callee_body_outside_this_bounded_note=True),
            next_embedded_widget_call=dict(call='0x404366',entry='0x3404ec',LR='0x40436b',
                entry_SP='P-2664',r0='actual page+0x118 if preceding ctor preserves actual page identity'),
            next_embedded_calls=['40437C original2E3860 with native register/stackarguments',
                'Later page resource/font/GIR actors remain unadmitted if existing controller-only predicates reject currentDispatcher.']),
        manager_transition=dict(entry='0x38e696',call='0x4053d2',LR='0x4053d7',entry_SP='callback E-40',
            r0='actual393A2C cached manager result',r1='actual40434C returned page pointerR6',r2=0,r3=0,
            stack_delta=56,body_SP='entrySP-56',r3_zero_path='38E6AA skips38E284 branch; native38E6DC calls38E358 using original wrappers.',
            callback_return_or_root_registration_or390306_closure_verified=False),
        inherited_resource_boundary=dict(source='scripts/probe_native_controller_gir_component.py:186',
            original_GIR_raw_pairs=['3009A0→11C510','3008B0→41CCD2'],backend='0x34f773c',tag='0x41b544',
            current_candidate='Decoder observer only adds decoder/slot scopes. Existing GIR guards require actual controller, so actualDispatcher resource entry must remain strict until separately observed actor-specific frames are admitted.',
            exact_first_reachable_GIR_call_or_hardware_driver_not_proven=True),
        no_broad_admission='This note authorizes no generic allocator/page/GIR writer relaxation; exact actual actor, containing-function SP, argument/caller/return and resource inventory are still required.',
        exact_original_instruction_evidence=rows,foreground_or_complete_page_or_root_or_App_verified=False)
    out=STAGE/'next-page-and-root-bounded-caller-inputs.json'
    with out.open('x') as h:json.dump(doc,h,ensure_ascii=False,indent=2);h.write('\n')
    print(json.dumps(dict(path=str(out.relative_to(ROOT)),sha256=sha(str(out.relative_to(ROOT))),instructions=len(rows))))
if __name__=='__main__':main()
