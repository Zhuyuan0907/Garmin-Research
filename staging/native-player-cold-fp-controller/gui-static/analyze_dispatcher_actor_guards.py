#!/usr/bin/env python3
"""Narrow exact-MAIN source contract; no VM/Unicorn import or execution."""
from datetime import datetime,timezone
from pathlib import Path
import ast,hashlib,json,sys
ROOT=Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT/'scripts'))
from capstone import Cs,CS_ARCH_ARM,CS_MODE_ARM,CS_MODE_THUMB
from analyze_native_sections import NativeImage
from dispatcher_run_contract import PHASES

STAGE=Path(__file__).resolve().parent
AUDIT='evidence/firmware-analysis/native-cache-declared-checkpoint-audit.json'
OLD='staging/native-player-controller-gir-integration/fp-static/new-dispatcher-followup/dispatcher-body-next-call-contract.json'
FP='staging/native-player-cache-declared-followup/fp-static/native-multiowner-fp-input-and-journal-recipe.json'
PROOF='evidence/firmware-analysis/native-controller-gir-cache-declared-emulation.json'
TERMINAL='staging/native-player-controller-gir-integration/runtime-cache-declared/terminal-probe.json'

def sha(p):return hashlib.sha256((ROOT/p).read_bytes()).hexdigest()
def read(p):return json.loads((ROOT/p).read_text())
def save(name,data):
    p=STAGE/name
    with p.open('x')as out:json.dump(data,out,ensure_ascii=False,indent=2);out.write('\n')
    return dict(path=str(p.relative_to(ROOT)),sha256=sha(str(p.relative_to(ROOT))))

def main():
    audit=read(AUDIT);protected=audit['protected_sources'];assert len(protected)==707
    bad=[p for p,w in protected.items()if sha(p)!=w];assert not bad,bad
    old=read(OLD);fp=read(FP);proof=read(PROOF);terminal=read(TERMINAL)
    assert proof['all_passed'] and proof['case_count']==1 and len(proof['source_sha256'])==619
    assert terminal['registers']['sp']=='0x9503f90'
    assert terminal['native_endpoint']['actual_controller_SP']=='0x9503f90'
    assert terminal['component_result20'][6]==0x9503f68
    stock=NativeImage();mds={'Thumb':Cs(CS_ARCH_ARM,CS_MODE_THUMB),'ARM':Cs(CS_ARCH_ARM,CS_MODE_ARM)}
    slices=[(0x38d456,0x38d4be,'Thumb'),(0x38d9cc,0x38da18,'Thumb'),
        (0x390142,0x390184,'Thumb'),(0x392eea,0x392efe,'Thumb'),(0x394596,0x39462c,'Thumb'),
        (0x3896f8,0x389724,'Thumb'),(0x385448,0x38545a,'Thumb'),(0x3008a0,0x3008b0,'Thumb'),
        (0x353a9c,0x353aa2,'Thumb'),(0x38d90e,0x38d920,'Thumb'),
        (0x20ed68,0x20edac,'ARM'),(0x20edb0,0x20edbc,'Thumb'),(0x6e0c08,0x6e0c10,'ARM'),
        (0x405340,0x4053e6,'Thumb'),(0x393a2c,0x393a58,'Thumb'),(0x392de4,0x392df2,'Thumb')]
    evidence=[]
    for lo,hi,mode in slices:
        ins=list(mds[mode].disasm(stock.read(lo,hi-lo),lo))
        assert ins and ins[-1].address+ins[-1].size==hi
        evidence.extend(dict(address=hex(i.address),mode=mode,opcode_hex=i.bytes.hex(),instruction=i.mnemonic+' '+i.op_str)for i in ins)
    insby={int(row['address'],16):row for row in evidence}
    raw=[]
    table=[(0x3009a0,0x38d9d4,'0x34f9b28',0x38d860,'0x38d4be','entry_SP-216','callback_entry_SP-376'),
        (0x3008b0,0x38da12,'0x34f9b28',0x38d860,'0x38d4be','entry_SP-216','callback_entry_SP-376'),
        (0x3009a0,0x390154,'0x34f9b28',0x38d860,'0x390142','entry_SP-16',None),
        (0x3008b0,0x390180,'0x34f9b28',0x38d860,'0x390142','entry_SP-16',None),
        (0x3009a0,0x3945a8,'M+0xe04',0x3931fc,'0x394596','entry_SP-32',None),
        (0x3008b0,0x394618,'M+0xe04',0x3931fc,'0x394596','entry_SP-32',None)]
    for entry,cont,ptr,tag,method,sp,cbsp in table:
        assert insby[cont-4]['instruction']=='bl '+hex(entry).replace('0x','#0x')
        raw.append(dict(entry=hex(entry),call=hex(cont-4),continuation=hex(cont),actual_LR=hex(cont|1),
            pointer=ptr,tag=hex(tag),classification_byte=0,bytes=24,actor='actual_Dispatcher8804FB8',
            containing_function=method,SP_formula=sp,callback_SP_formula=cbsp,
            require=['current_F09090_equals_actual_running_task','live_original_constructed_storage',
                'exact_MAIN_call_and_body','original_owner_waiter_recursion_lists','native_epilogue_r3_LR',
                'actual_continuation_SP','last_native_released_words_not_synthetic_zero']))
    for literal,expected in [(0x38d858,0xf2cbf4),(0x38d85c,0x34f9b28),(0x38d86c,0xf2cbf8),
        (0x3931f8,0xe04),(0x393bc0,0xf2cd08),(0x6e0c14,0x3aaec70),(0x353aa4,0xf09098)]:assert stock.word(literal)==expected
    deps=[str(Path(__file__).resolve().relative_to(ROOT)),str((STAGE/'dispatcher_run_contract.py').relative_to(ROOT)),
        AUDIT,OLD,FP,PROOF,TERMINAL,'scripts/analyze_native_sections.py','evidence/firmware-analysis/main_02bd.bin',
        'scripts/probe_native_controller_gir_component.py','scripts/probe_native_controller_gir_component_contiguous.py',
        'scripts/probe_native_controller_gir_cache_declared.py','scripts/probe_native_heap_settings_boot.py',
        'scripts/probe_native_task_mutex.py','scripts/probe_native_signal_dispatch.py','scripts/emulate_native_independent_signal.py',
        'scripts/probe_native_mainmenu_controller.py','scripts/emulate_native_mainmenu_constructor.py',
        'scripts/probe_native_settings_lazy_vfp_v2.py','scripts/probe_native_lazy_vfp.py',
        'staging/native-player-cache-declared-followup/fp-static/controller-terminal14246-fp-recipe-supplement.json']
    base=dict(updated_utc=datetime.now(timezone.utc).isoformat(),static_only=True,
        MAIN_sha256=sha('evidence/firmware-analysis/main_02bd.bin'),source_sha256={p:sha(p)for p in deps},
        protected_registry=dict(path=AUDIT,sha256=sha(AUDIT),count=707,changed_or_missing=[]),
        verified_protected_sources=protected,guest_execution=False,emulator_imported=False,device_io=False,
        frozen_source_or_canonical_modified=False,foreground_or_closure_claim=False)
    contract=save('native-dispatcher-complete-run-contract.json',dict(base,phases=PHASES,
        preserved_positive=dict(path=PROOF,sha256=sha(PROOF),scenarios=1,integrity_dependencies=619,
            new_cold_metadata_FPboot_configuration_not_yet_proven=True),
        endpoint_SP_erratum=dict(actual_terminal_SP='0x9503f90',component_result_frame_P='0x9503f68',
            relation='P=E-40 during compiled component; terminal SP has been restored'),
        cold_order_requires_exit_list_constructor_removed_from_later_inherited_driver=True,
        all_new_phase_gates_need_new_actual_observations=True))
    branch=save('manager-clock-cleanup-and-cold-fp-actor-guards.json',dict(base,
        evidence_kind='Exact small MAIN slices and frozen contract reuse; no new recursive callee closure',
        exact_original_instruction_evidence=evidence,raw_manager_continuations=raw,
        manager_initializers=[dict(entry='0x3008a0',call='0x38d46c',continuation='0x38d470',LR='0x38d471',
            pointer='0x34f9b28',tag='0x38d860',native_tag_store='0x38d474',
            SP='callback_entry_SP-384; actual captured38D456 entrySP-8',once_cell='0xf2cbf4',
            before='cold onceword0 and backend24 coldzero proven from actual fresh runtime',
            observed_native_writes='3008A2/A4/A6/A8/AA/AC exactly six4-byte zero stores; originaltag+16 after return'),
            dict(entry='0x3008a0',call='0x392ef6',continuation='0x392efa',LR='0x392efb',
            pointer='M+0xe04',tag='0x3931fc',native_tag_store='0x392efc',SP='callback_entry_SP-160',
            before='M is actual native3954CC(0xE50) liveallocation; do not require malloc body alreadyzero',
            observed_native_writes='Same exact six stores followed originaltagstore; no hosttag/header seeding')],
        actor_and_frame=dict(callback_actor='0x8804fb8',entry_SP='0x8804f78',entry_LR='0x60935d',
            body_SP='E-40',getter393A2C_SP='E-56',manager392DE4_SP='E-160',base38D4BE_SP='E-376',
            maximum_full_recursive_stack_bound_proven=False,manager_cache='0xf2cd0c',
            registry='0x34f9b40',registry_append='38D9DA358D24 returns actualDispatcher; capture originalvectorbegin/end/capacity and liveallocation'),
        cleanup_registration=dict(head='0x3aaec70',getter='ARM0x6e0c08',caller='0x38d4b0',
            args=['0x34f9b40','0x20dc53','0xc7f980'],node_bytes=16,allocator='original39544C',
            node_words=['actual_previous_head','registered_object34F9B40','callback20DC53','argumentC7F980'],
            writers=['38970Ecallback','389710object','389714argument','38971Coldhead','38971Epublishhead'],
            require='Capture actual head and all reachable existing nodes before newbranch; preserve priorchain and liveallocations. Journal head/nodenative stores; actual3896F8 return0 plus live newnode. This process cleanup list differs from kernel2D226B4 exitlisteners and TCB+36.',
            no_zero_head_assumption=True,no_safe_cleanup_claim=True),
        clock_scope=dict(choice='fixed existing declared clock0; minimal new actor-specific scope',
            entry='0x353a9c',native_function='LDRr1,literal353AA4=F09098;LDRr0,[r1];BXLR',
            allowed_continuations=['0x38d912','0x38d91e'],actual_LRs=['0x38d913','0x38d91f'],
            before='Dispatcher/bodyphase/currentnativeTCB matched, exactopcode and clockword0',
            skip='InheritedControllerVM.observe353A9C host+20/writeF09098 must be bypassed; call lowerConstructorVM.observe only for this exact reviewed boundary',
            after='Capture returnedr0==unchangedclockword0 and native38D918/38D91E stores at actualr6+38/+3C; r6 derivesactualr4+340; expectedM+378/+37C requires actualregistercheck',
            invariant='No hostclockwrites/newtimeadvance. Preserve Threadtimednode20/deadline1, mailbox/state/ready/priorities and originalconditionTimer chain unless actualkernel operations separatelyobserved.',
            other_clock_callers='Unknown newcaller stops; pool3B4BB0 remains separately declared lowerfixture'),
        cold_FP_boot=dict(reused_recipe=FP,guard_summary=fp['original_FP_boot_integration'],
            current14246_owner_is_live_without_metadata_and_cannot_be_retrofitted=True,
            registration_wrapper_does_not_check_r0_and_newobserver_must=True,
            list_mutex_SP='3CC5C2 entrySP-40; boot ARM20ED68 has entrySP-8 at its BLX',
            boot_return='Original20EDA0 r0=0,20EDA8 BXLR; actualmodeARM. Owner0/nativeFPSCR03000000/listnodeactualchain and wholehistories.',
            later_heap_chain=['3A7F150','3A7F160','3AB1028'],
            callbacks_resident=True,registration_not_task_exit_or_unload=True),
        next_unadmitted_boundaries=[
            dict(id='INIT_NOOP',source='scripts/emulate_native_voice_outer.py',detail='Manager new3008A0 callers otherwise reach inheritedret noop; intercept before delegation and capture full six writes/tag/continuation.'),
            dict(id='RAW_ACTOR',source='scripts/probe_native_heap_settings_boot.py:142',detail='exact_raw requirescontroller. New body must admit only six manager pairs plus separately exact inherited heap/settings/currentTCB shapes under actualDispatcher; never relax actor globally.'),
            dict(id='CURRENT_TCB_INTERNAL',detail='Original1C0618/1C0634 pointer actualcurrent+56 may recur underDispatcher. Snapshot actualtag beforeoperation and use current constructedTCB; inheritedexact_raw controller gate needs localactor extension.'),
            dict(id='CLOCK_HOSTWRITE',source='scripts/probe_native_mainmenu_controller.py:41',detail='Hosttick20 breaks clock/F0chronologicaljournal and timed invariants; nativegetteritself does notwriteclock.'),
            dict(id='FP_MULTI_OWNER',detail='NativeD FP fault after20EBD4 may encounter C owner. ExistingLazyVFPState first/same guard stillrejects; metadata alone does not implement save/clone/restore. C→D saveonly, D→C nativeCrestore, laterC→D nativeDrestore are distinct evidence.'),
            dict(id='FONT_CACHE_ACTOR',source='scripts/probe_native_controller_gir_component_contiguous.py',detail='Allocator/rawbuffer/CPUcache history gates stillcomponent_active/controller. D glyphmiss must retain exact original26491C→14F084/lowerhandle binding and livegeneration, admit only actualDstack or originalcachepayload, keep all old221payloads/8streams resident.'),
            dict(id='COMPONENT_FLAG',source='scripts/probe_native_controller_gir_component.py',detail='Disablingcomponent_active dropsGUIjournal/EAreservation; retainingit blindly enforceswrongcontrollerGIRframe. Newbodyphase must preserve reservation and alljournals with independent actors/frameformulas.'),
            dict(id='BODY_RESUME',source='scripts/probe_native_signal_dispatch.py:38',detail='invoke_to_callback is entry-stop harness without multiownertrap loop. Resume actualnative PC/CPSR/SP/LR/registers; do notreenter405340/forgecallbackreturn.'),
            dict(id='RETURN_THEN_SCHEDULING',detail='Callback4053E4/60935C is not controllerWAITreturn. Observe originalthreeRAIIreleases and nextnativeDWAIT; actualidlePOST(C,1) may be required to return controllercurrentWAIT. Idle/Dispatcherold consumedframes must not be compared as stillresumable.'),
            dict(id='LOWER_POOL',detail='3B4BA8/3EC6AA absentaudio-pool lowerfailure and mapped1076E2 counter remainfixtures; body reachingthem needs preserved qualification, not nativehardware claim.')],
        conditional_foreground_branch=dict(lookup='40536A38EE28 PageMainMenu lookup; captureactualresult/localobject and405384 branch',
            create='Only actualmissinglookup route executes4053BE40434C and4053D238E696(M,Page,0,0). Existingrootroute mayreturnwithoutnewPage.',
            queue='4053D82DA69E→4565C6→390142 membership→394596 originalM+E1C closure underM+E04; F0B5500 skipsPOST512.',
            endpoints='Capture bodyreturn, root0registration/frame, queuedclosure and GUIactorprocessing separately. No foreground/display/touch/closurefree inference from bodyreturn.',
            retain='IndependentSignal/nativeholders/vector/Dispatcher/module/fonts/MainMenu/manager and queuedclosure remainresident; no destruction or safeunload claim')))
    print(json.dumps(dict(contract=contract,branch=branch,phase_count=len(PHASES),original_instruction_count=len(evidence),protected_count=707,static_only=True)))

if __name__=='__main__':main()
