#!/usr/bin/env python3
"""Pure source/shape/MAIN review; never imports or instantiates a guest VM."""
from pathlib import Path
from datetime import datetime,timezone
import ast,hashlib,importlib.util,json,sys
ROOT=Path(__file__).resolve().parents[3]
STAGE=Path(__file__).resolve().parent
SOURCE=STAGE/'decoder_actor_observer_v2.py'
def sha(p):return hashlib.sha256((ROOT/p).read_bytes()).hexdigest()
sys.path.insert(0,str(ROOT/'scripts'))
from analyze_native_sections import NativeImage
from capstone import Cs,CS_ARCH_ARM,CS_MODE_THUMB,CS_MODE_ARM

def main():
    target='staging/native-player-decoder-scope/gui-static/decoder_actor_observer_v2.py'
    registry='staging/native-player-decoder-scope/previous-audit.json'
    protected=json.loads((ROOT/registry).read_text())['protected_sources']
    assert len(protected)==892
    assert all(sha(p)==h for p,h in protected.items())
    spec=importlib.util.spec_from_file_location('pure_decoder_observer_shape_review',SOURCE)
    mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
    controls=[]
    for (entry,continuation),(function,delta,pointer) in mod.RAW.items():
        for sp in (0x8804F40,0x8804F28):
            result=mod.raw_shape(entry,continuation,sp)
            assert result['function']==function and result['entry_SP']==sp-delta
            assert result['pointer']==pointer and result['LR']==continuation|1
            controls.append(dict(entry=hex(entry),continuation=hex(continuation),
                captured_function_SP=hex(sp),expected_raw_SP=hex(sp-delta),passed=True))
    for args in ((0x3009A0,0x396B4E,3),(0x3009A0,0x396B50,0x8804F40)):
        try:mod.raw_shape(*args)
        except RuntimeError:controls.append(dict(input=[hex(a) for a in args],rejected=True))
        else:raise AssertionError('Malformed pure shape input accepted')
    tree=ast.parse(SOURCE.read_text())
    banned={'mem_write','reg_write','emu_start','emu_stop','invoke','kernel_invoke','ret','put','mem_map'}
    calls=[n.func.attr for n in ast.walk(tree) if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute)]
    assert not (set(calls)&banned)
    stock=NativeImage();md=Cs(CS_ARCH_ARM,CS_MODE_THUMB)
    ranges=[(0x39720C,0x397226),(0x396B3E,0x396BAE),(0x369438,0x36944A),
        (0x36944A,0x36946A),(0x3697B8,0x3697CC),(0x3697CC,0x3697F4),(0x39799E,0x3979BA)]
    evidence=[]
    for lo,hi in ranges:
        ins=list(md.disasm(stock.read(lo,hi-lo),lo));assert ins[-1].address+ins[-1].size==hi
        evidence.extend(dict(PC=hex(i.address),opcode_hex=i.bytes.hex(),instruction=i.mnemonic+' '+i.op_str) for i in ins)
    arm=Cs(CS_ARCH_ARM,CS_MODE_ARM);arm_mode=[];raw_stores=[]
    for lo,hi in [(0x3008B8,0x3008CC),(0x3009A8,0x3009BC),
                  (0x300918,0x300924),(0x3009F8,0x300A04)]:
        ins=list(arm.disasm(stock.read(lo,hi-lo),lo))
        assert ins[-1].address+ins[-1].size==hi
        arm_mode.extend(dict(PC=hex(i.address),opcode_hex=i.bytes.hex(),
            instruction=i.mnemonic+' '+i.op_str,Thumb=False) for i in ins)
    assert not any(r['instruction'].startswith(('str','stm','swp')) for r in arm_mode)
    for lo,hi in [(0x3008CC,0x300916),(0x3009BC,0x3009F8)]:
        ins=list(md.disasm(stock.read(lo,hi-lo),lo))
        assert ins[-1].address+ins[-1].size==hi
        raw_stores.extend(dict(PC=hex(i.address),opcode_hex=i.bytes.hex(),
            instruction=i.mnemonic+' '+i.op_str,Thumb=True) for i in ins
            if i.mnemonic.startswith(('str','stm','swp')))
    assert raw_stores
    by_pc={int(r['PC'],16):r for r in evidence}
    for entry,cont in mod.RAW:
        assert by_pc[cont-4]['instruction']=='bl #'+hex(entry)
    assert stock.word(0x396E78)==stock.word(0x3979BC)==mod.DECODER
    assert stock.word(0x369768)==stock.word(0x3698D4)==mod.SLOT
    assert stock.word(0x369758)==stock.word(0x3698D8)==mod.CALLBACKS
    paths=[target,str(Path(__file__).resolve().relative_to(ROOT)),registry,
        'staging/native-player-dispatcher-native-body/gui-static/dispatcher_actor_observer.py',
        'staging/native-player-dispatcher-fp/gui-static/dispatcher_actor_shapes.py',
        'staging/native-player-dispatcher-native-body/gui-static/native-396b4e-next-actor-boundary.json',
        'scripts/probe_native_dispatcher_body_fp.py','scripts/probe_native_task_mutex.py',
        'scripts/probe_native_heap_settings_boot.py','scripts/probe_native_dispatcher_condition.py',
        'scripts/probe_native_mutex_owner.py','scripts/probe_native_controller_gir_component.py',
        'scripts/analyze_native_sections.py','evidence/firmware-analysis/main_02bd.bin',
        'staging/native-player-decoder-scope/gui-static/decoder_actor_observer-v1-static-candidate.py',
        'staging/native-player-decoder-scope/gui-static/decoder-actor-observer-contract.json',
        'staging/native-player-decoder-scope/gui-static/record_decoder_observer_contract.py']
    doc=dict(updated_utc=datetime.now(timezone.utc).isoformat(),static_only=True,guest_execution=False,
        guest_VM_imported_or_instantiated=False,device_IO=False,frozen_sources_or_canonical_modified=False,
        source_sha256={p:sha(p) for p in paths},protected_registry=dict(path=registry,sha256=sha(registry),
            count=len(protected),changed_or_missing=[]),verified_protected_sources=protected,
        interface=dict(class_name='DecoderDispatcherActorObserverMixin',parent_SHA=mod.PARENT_SHA,
            methods=['init_dispatcher_actor_observer','observe_dispatcher_actor','snapshot_dispatcher_actor_observer',
                     'verify_dispatcher_actor_observer','capture_decoder_inputs'],
            sequence='Existing root constructor maps only unmapped verified-zero pages before init. After complete cold prefix call capture_decoder_inputs() while body inactive, then existing actual Signal/register/queue/WAIT path. Old journals continue. Root uses observe return bool unchanged.',
            capture='Three real before-images, startupzero provenance, existing native-init ledger rows, actual owner/tag/class and callback words. Deepcopied inputs do not share later zone stores.',
            epilogues='300A0A/30092A remain False; parent consumes existing task_mutex_ops[D] and synchronizes native owned/depth fields once; new actual caller/SP/result observations happen afterward.'),
        pure_host_controls=dict(passed=True,count=len(controls),cases=controls,
            compile='Python py_compile passed; no guest VM instance, emu_start or guest execution',
            AST_no_guest_mutation_or_invocation=True),
        whole_zone_scopes=[dict(start=hex(mod.DECODER),bytes=24),dict(start=hex(mod.SLOT),bytes=32),
                          dict(start=hex(mod.CALLBACKS),bytes=24)],
        exact_raw_pairs=[dict(entry=hex(e),continuation=hex(c),function=hex(f),SP_formula='captured function SP-'+str(d),pointer=hex(p))
                         for (e,c),(f,d,p) in mod.RAW.items()],
        strict_input_qualifier='This candidate admits observed all-zero decoder24 and slot32 in exact stock startupzero ranges; that is an explicit cold input, not proof39799E ran. Nonzero initialized input needs another provenance scope. No tag is seeded.',
        caller_sequence='405390→39720C(E-40)→396B3E(T=outer-16), decoder lock(T-24)→36944A(slot0,100000), slot lock(entry-16)→369438, 3697CC(0,1,0x21,SP+8;stack1,1)→3697B8(slot0), slot unlock(entry-8)→decoder unlock(T-24)→query caller returns.',
        original_null_driver='Actual table+16==0 runs native369438 return0; actual table+0==0 runs native3697CC return8, then native396B3E/39720C return0. No host success return.',
        hardstops=['Unknown nonzero prepare/IO callback before original indirect jump',
            '39799E constructor or396D6E hardware path', 'Unexpected writer to immutable24byte callback table',
            'Nonzero initial decoder/slot object without separately captured native init',
            'Unknown caller/SP/backend/class/tag/store/cross-boundary provenance'],
        journal_formula='Exact original MAIN STR/STM/SWP opcodes, before bytes and values replay whole24/32/24. Native pending operation binds raw writes; nested slot operation may update still-owned decoder+0/+4 links. Slot status exact36945E=1/3697C2=0. +0/+4 released links retain original journaled values.',
        completion='Parent full manager/callback guard must pass first, then all decoder frames/raw pending returns close and all3zones replay; owners/waiters/depth and slot active byte clear. No runtime completion or foreground is claimed by this static contract.',
        prior_unrun_candidate_rejected=dict(source_snapshot='staging/native-player-decoder-scope/gui-static/decoder_actor_observer-v1-static-candidate.py',
            source_SHA='0210a261925b1d5a68efc5e3bd2624937223fdfef46df7942dd4e8c686ae29aa',
            contract='staging/native-player-decoder-scope/gui-static/decoder-actor-observer-contract.json',
            reason='V1 memory journal required default Thumb despite mixed-mode actor paths. Source was never run; exact immediate raw stores in these two functions are actually Thumb, so no actual ARM-store rejection is claimed.',
            fix='Journal actor validation uses actual CPSR Thumb bit; original_store decodes/verifies that same mode. Function/raw entry and actual Thumb continuations retain strict Thumb checks.'),
        exact_original_ARM_save_restore_evidence=arm_mode,
        exact_original_immediate_raw_store_evidence=raw_stores,
        mode_distinction='ARM IRQ save/restore blocks contain no stores. Original immediate backend stores are in Thumb blocks3008CC..300914/3009BC..3009F6. Do not decode those blocks as ARM.',
        exact_original_instruction_evidence=evidence,bounded_MAIN_ranges=len(ranges)+6,
        runtime_validation_performed=False,full_Dispatcher_body_or_foreground_verified=False)
    out=STAGE/'decoder-actor-observer-contract-v2.json'
    with out.open('x') as h:json.dump(doc,h,ensure_ascii=False,indent=2);h.write('\n')
    print(json.dumps(dict(source_sha256=sha(target),contract=str(out.relative_to(ROOT)),
        contract_sha256=sha(str(out.relative_to(ROOT))),protected=len(protected),controls=len(controls))))
if __name__=='__main__':main()
