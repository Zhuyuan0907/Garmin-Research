#!/usr/bin/env python3
"""Bounded MAIN/source review and pure host-data guard controls; no VM import."""
from datetime import datetime, timezone
from pathlib import Path
import ast
import hashlib
import json
import sys

ROOT=Path(__file__).resolve().parents[3]
STAGE=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'scripts'))
from analyze_native_sections import NativeImage
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_ARM
import dispatcher_actor_shapes as helper

AUDIT='staging/native-player-dispatcher-fp/previous-audit.json'
PROOF='evidence/firmware-analysis/native-cold-fp-controller-emulation.json'
OLD='staging/native-player-cold-fp-controller/gui-static/manager-clock-cleanup-and-cold-fp-actor-guards.json'
ORDER='staging/native-player-cold-fp-controller/gui-static/native-dispatcher-complete-run-contract.json'


def sha(path):
    return hashlib.sha256((ROOT/path).read_bytes()).hexdigest()


def save(name, doc):
    path=STAGE/name
    with path.open('x') as handle:
        json.dump(doc,handle,ensure_ascii=False,indent=2);handle.write('\n')
    return dict(path=str(path.relative_to(ROOT)),sha256=sha(str(path.relative_to(ROOT))))


def method(path, classname, name):
    source=(ROOT/path).read_text();lines=source.splitlines(keepends=True)
    cls=next(c for c in ast.parse(source).body if isinstance(c,ast.ClassDef) and c.name==classname)
    function=next(f for f in cls.body if isinstance(f,ast.FunctionDef) and f.name==name)
    raw=''.join(lines[function.lineno-1:function.end_lineno]).encode()
    return dict(path=path,class_name=classname,method=name,line=function.lineno,
                end_line=function.end_lineno,method_source_sha256=hashlib.sha256(raw).hexdigest())


def controls():
    rows=[];sample_manager=0x8810000;entry_sp=0x8804F78
    shapes=[helper.manager_init_shape(c,sample_manager,entry_sp) for c in [0x38D470,0x392EFA]]
    shapes += [helper.manager_raw_shape(e,c,sample_manager,entry_sp) for e,c in helper._MANAGER_RAW]
    shapes += [helper.current_internal_shape(e,c,entry_sp,0xC943E0) for e,c in [(0x3009A0,0x1C0618),(0x3008B0,0x1C0634)]]
    shapes += [helper.clock_shape(c,entry_sp,0) for c in [0x38D912,0x38D91E]]
    shapes += [helper.gir_raw_shape(f,e,c,entry_sp) for f,e,c in [
        (0x41C3DA,0x3009A0,0x11C510),(0x41C3DA,0x3008B0,0x41C68E),
        (0x41C944,0x3009A0,0x11C510),(0x41C944,0x3008B0,0x41C998)]]
    for shape in shapes:
        assert helper.check_event_shape(shape,dict(shape))
        rows.append(dict(name='exact_supplied_shape_'+hex(shape['entry'])+'_'+hex(shape['continuation']),passed=True))
    def reject(name, action):
        try: action()
        except helper.ShapeError: rows.append(dict(name=name,passed=True,rejected=True));return
        raise AssertionError('Invalid data shape accepted: '+name)
    row=shapes[2]
    for field,value in [('actor',0x9503F90),('current',0x9503F90),('LR',row['LR']-2),
                        ('entry_SP',row['entry_SP']-4),('pointer',row['pointer']+4),
                        ('tag',0),('classification_byte',1),('Thumb',False),('scope','controller_component')]:
        reject('reject_wrong_'+field,lambda field=field,value=value:helper.check_event_shape(row,dict(row,**{field:value})))
    reject('reject_unreviewed_manager_pair',lambda:helper.manager_raw_shape(0x3009A0,0x41CCD2,sample_manager,entry_sp))
    reject('reject_clock_tick20',lambda:helper.clock_shape(0x38D912,entry_sp,20))
    reject('reject_unreviewed_clock_caller',lambda:helper.clock_shape(0x38D920,entry_sp,0))
    reject('reject_wrong_resource_unlock',lambda:helper.gir_raw_shape(0x41C3DA,0x3008B0,0x41CCD2,entry_sp))
    old=0x8820000;tail=old+64;new=old+128
    before={old:[tail,1,3,5],tail:[0,7,9,11]};shape=helper.cleanup_registration_shape(new,old)
    after=dict(before);after[new]=shape['node_words'];live=set(before);stores=shape['ordered_native_stores']
    assert helper.check_cleanup_linkage(shape,before,after,live,live|{new},new,stores)
    rows.append(dict(name='nonzero_two_node_old_cleanup_chain_preserved_with_five_ordered_stores',passed=True))
    reject('reject_cleanup_reordered_stores',lambda:helper.check_cleanup_linkage(shape,before,after,live,live|{new},new,list(reversed(stores))))
    changed=dict(after);changed[old]=[0,1,3,5]
    reject('reject_old_cleanup_node_mutation',lambda:helper.check_cleanup_linkage(shape,before,changed,live,live|{new},new,stores))
    reject('reject_dead_old_cleanup_node',lambda:helper.check_cleanup_linkage(shape,before,after,live,live-{tail}|{new},new,stores))
    reject('reject_live_cleanup_node_reuse',lambda:helper.check_cleanup_linkage(shape,before,after,live|{new},live|{new},new,stores))
    reject('reject_cyclic_cleanup_chain',lambda:helper.cleanup_reachable(old,{old:[old,1,3,5]},live))
    return rows,shapes


def main():
    audit=json.loads((ROOT/AUDIT).read_text());registry=audit['protected_sources']
    assert len(registry)==751
    bad=[path for path,digest in registry.items() if sha(path)!=digest]
    assert not bad,bad
    proof=json.loads((ROOT/PROOF).read_text());assert proof['all_passed'] and proof['case_count']==1
    assert sha('scripts/probe_native_cold_fp_controller.py')=='0c4f4bb7e0077da701da225c183c262fa14346685dd605994438bd3edac1be3c'
    old=json.loads((ROOT/OLD).read_text())
    stock=NativeImage();mds={'Thumb':Cs(CS_ARCH_ARM,CS_MODE_THUMB),'ARM':Cs(CS_ARCH_ARM,CS_MODE_ARM)}
    slices=[(0x3008A0,0x3008B0,'Thumb'),(0x38D456,0x38D4BE,'Thumb'),
            (0x392DE4,0x392DF2,'Thumb'),(0x392EEA,0x392EFE,'Thumb'),
            (0x38D4BE,0x38D4C8,'Thumb'),(0x38D9CC,0x38DA18,'Thumb'),
            (0x390142,0x390184,'Thumb'),(0x394596,0x39462C,'Thumb'),
            (0x353A9C,0x353AA2,'Thumb'),(0x38D90E,0x38D922,'Thumb'),
            (0x3896F8,0x389724,'Thumb'),(0x6E0C08,0x6E0C10,'ARM'),
            (0x405340,0x4053E6,'Thumb'),(0x393A2C,0x393A58,'Thumb'),
            (0x390306,0x390328,'Thumb'),(0x38CDC6,0x38CE04,'Thumb'),
            (0x11C504,0x11C514,'Thumb'),(0x41C3DA,0x41C424,'Thumb'),
            (0x41C688,0x41C694,'Thumb'),(0x41C944,0x41C99E,'Thumb'),
            (0x1C0600,0x1C0620,'Thumb'),(0x1C0624,0x1C063A,'Thumb'),
            (0x385448,0x38545A,'Thumb')]
    instructions=[]
    for lo,hi,mode in slices:
        dis=list(mds[mode].disasm(stock.read(lo,hi-lo),lo))
        assert dis and dis[-1].address+dis[-1].size==hi
        instructions += [dict(address=hex(i.address),mode=mode,opcode_hex=i.bytes.hex(),instruction=i.mnemonic+' '+i.op_str) for i in dis]
    indexed={int(row['address'],16):row for row in instructions}
    for entry,cont in helper._MANAGER_RAW:
        assert indexed[cont-4]['instruction']=='bl #'+hex(entry)
    for pc,w in [(0x353AA4,0xF09098),(0x6E0C14,0x3AAEC70),(0x38D858,0xF2CBF4),
                 (0x38D85C,0x34F9B28),(0x38D86C,0xF2CBF8),(0x3931F8,0xE04)]:
        assert stock.word(pc)==w
    rows,shapes=controls()
    methods=[method(*item) for item in [
        ('scripts/emulate_native_voice_outer.py','OuterVM','observe'),
        ('scripts/probe_native_mainmenu_controller.py','ControllerVM','observe'),
        ('scripts/emulate_native_mainmenu_constructor.py','ConstructorVM','observe'),
        ('scripts/probe_native_heap_settings_boot.py','HeapSettingsVM','exact_raw'),
        ('scripts/probe_native_heap_settings_boot.py','HeapSettingsVM','observe'),
        ('scripts/probe_mainmenu_native_settings_journal.py','JournalSettingsVM','observe'),
        ('scripts/probe_mainmenu_native_settings_journal.py','JournalSettingsVM','journal_mutable_write'),
        ('scripts/probe_native_controller_gir_component.py','ControllerGIRVM','observe'),
        ('scripts/probe_native_controller_gir_component.py','ControllerGIRVM','journal_gui_write'),
        ('scripts/probe_native_controller_gir_component_contiguous.py','ContiguousFontControllerGIRVM','journal_cache_CPU_write'),
        ('scripts/probe_native_controller_gir_component_contiguous.py','ContiguousFontControllerGIRVM','map_verified_file_destination'),
        ('scripts/probe_native_cold_fp_controller.py','ColdFPControllerVM','verify_cold_metadata'),
        ('scripts/probe_native_cold_fp_controller.py','ColdFPControllerVM','verify_extra_zones'),
        ('scripts/native_cold_fp_guard_copies.py','ColdFPGuardMixin','_verify_component_base')]]
    deps=[str(Path(__file__).resolve().relative_to(ROOT)),str((STAGE/'dispatcher_actor_shapes.py').relative_to(ROOT)),
          AUDIT,PROOF,OLD,ORDER,'scripts/analyze_native_sections.py','evidence/firmware-analysis/main_02bd.bin',
          'scripts/emulate_native_independent_signal.py','scripts/emulate_native_player_widget.py',
          'scripts/emulate_native_mainmenu_constructor.py','scripts/probe_native_player_resources.py',
          'scripts/probe_native_controller_gir_cache_declared.py','scripts/probe_native_controller_gir_component.py',
          'scripts/probe_native_controller_gir_component_contiguous.py','scripts/probe_native_cold_fp_controller.py',
          'scripts/native_cold_fp_guard_copies.py','scripts/probe_native_heap_settings_boot.py',
          'scripts/probe_mainmenu_native_settings_journal.py','scripts/probe_native_signal_dispatch.py',
          'scripts/probe_native_mainmenu_controller.py','scripts/emulate_native_voice_outer.py']
    base=dict(updated_utc=datetime.now(timezone.utc).isoformat(),static_only=True,
              guest_execution=False,emulator_imported=False,device_IO=False,
              frozen_sources_or_canonical_modified=False,foreground_or_callee_closure_claim=False,
              MAIN_sha256=sha('evidence/firmware-analysis/main_02bd.bin'),
              source_sha256={p:sha(p) for p in deps},
              protected_registry=dict(path=AUDIT,sha256=sha(AUDIT),count=len(registry),changed_or_missing=bad),
              verified_protected_sources=registry)
    control_artifact=save('dispatcher-shape-helper-host-controls.json',dict(base,
        evidence_kind='Pure Python data-shape controls; no native task/function execution',
        control_count=len(rows),all_passed=True,controls=rows,
        illustrative_shapes=shapes,illustrative_SP_and_manager_are_synthetic_inputs_not_runtime=True))
    artifact=save('dispatcher-actor-guard-contract.json',dict(base,
        helper=dict(path=str((STAGE/'dispatcher_actor_shapes.py').relative_to(ROOT)),
                    sha256=sha(str((STAGE/'dispatcher_actor_shapes.py').relative_to(ROOT))),
                    functions=['manager_init_shape','manager_raw_shape','current_internal_shape','clock_shape',
                               'gir_raw_shape','check_event_shape','cleanup_registration_shape','check_cleanup_linkage'],
                    scope='Exact actor/caller/frame tuples only; all live-storage/opcode/journal/native-pending/FP evidence must come from new observer'),
        host_controls=control_artifact,
        frozen_parent=dict(path='scripts/probe_native_cold_fp_controller.py',terminal_session=76222,
            proof=PROOF,scenario_count=1,integrity_dependency_count=711,scope='Cold first/same controller FP and full preparation only'),
        minimal_native_sequence=[
            'Reproduce complete cold metadata/FP boot/heap/settings/component native preparation and original finalguards.',
            'Capture pre-body whole inventories/old journals once; no reset baseline or call existing fixed-STACK helper.',
            'Use current controller original3954CC(80)→57458D signal constructor, original4B571D(S,405341), original5D28FF(D,S). Preserve original default signal/holders.',
            'Current controller originalWAIT; preserve original kernel restore and dispatcher37BCE4→52353C→609338→405340 register/stack frame.',
            'At actual405340 entry declare independent body phase; original manager393A2C runs under actualDispatcher and scoped current-TCB raw/heap/settings paths.',
            'Resume actual original PC/CPSR/SP/LR/registers through reviewed lazy-FP path; do not invoke405340 again.',
            'After callback return require native callback/RAII release/D WAIT and separately original idle POST(controller,1) only if controller still blocked; final inventories are distinct from entry proof.'],
        manager_initializers=old['manager_initializers'],raw_manager_continuations=old['raw_manager_continuations'],
        capture_rules=dict(callback=dict(actor='0x8804fb8',entry='0x405340',expected_entry_SP='0x8804f78',LR='0x60935d',
                note='Observe real entry; helper uses separately captured function entrySP, not a global synthetic stack.'),
            frames={'405340':'E-40','393A2C':'E-56','392DE4':'E-160','38D4BE':'E-376',
                    '38D456 raw init':'captured getter entrySP-8','394596 raw':'captured entrySP-32','390142 raw':'captured entrySP-16'},
            published_manager='Actual native3954CC(0xE50) live pointer M, returned by392DE4 and native393A46 stored intoF2CD0C. Do not create oncontroller.',
            once='38D456 bit0 test then385448 whole-word==0. Capture actual F2CBF4/F2CBF8 before body; never reset oncewords.',
            raw_pending='Add exact per-actor native pending op before originalbody; 300A0A/30092A epilogue r3==originalLR then actual continuation+sameSP; distinguish registry raw from retained GUI condition token.',
            raw_released='Whole last original backend24 is history-derived. Owner+8/waiter+12/depth low16=0/classbyte+22=0; +0/+4 may be stale and cannot be forced zero.'),
        clock=dict(entry='0x353a9c',literal='353AA4=F09098',fixed_declared_word=0,
            original_function='LDR r1,[PC,#4]; LDR r0,[r1]; BX LR; read-only',
            exact_LRs=['0x38d913','0x38d91f'],SP='captured38D4BE entrySP-216',
            delegation='For only these exact body tuples, direct ConstructorVM.observe delegate bypasses ControllerVM.observe host+20; preserve all other parent handling. Unknown caller remains a boundary.',
            output='Native38D918 and38D91E store result0 to actualr6+38/+3C; r6=actualr4+340, require actualr4==M before naming M+378/+37C.',
            invariants='No hostclock store/tick; timedThread20 deadline1/nativeTimer chain/ready/state/mailbox/priorities remain history guarded. This fixedclock input does not simulate real time.'),
        cleanup=dict(shape_function='cleanup_registration_shape',checker='check_cleanup_linkage',
            head='0x3aaec70',node_bytes=16,actual_oldhead_capture_PC='0x38971a',
            ordered_writers=['38970E node+8 callback20DC53','389710 node+4 object34F9B40',
                '389714 node+12 argC7F980','38971C node+0 actualoldhead','38971E head=newnode'],
            mandatory='Original39544C(16) actual return→live new16 with canary/nonoverlap; actual old full reachable list and live allocation snapshot; five original stores with before/value/opcode replay; original3896F8 returns0 at38D4B4. Preserve every old node/raw metadata. No newnode address reuse.',
            distinct_lists='Process cleanup3AAEC70 is not kernelEXIT_LIST2D226B4/FP+heaplisteners/TCB+36.',
            failure='NULL alloc returns1; retain failure, never infer successful cleanup/unload from registration.'),
        first_actor_scopes=dict(
            root=dict(path=['40536A→38EE28 PageMainMenu lookup','missing lookup4053BE→40434C',
                '4053D2→38E696(M,Page,0,0)','38E6DC→38E358','38E3EC→38E15E','virtual390306/3904D2'],
                branch='Existing page may skip new40434C; require actual lookup outcome rather than forcing cold branch.',
                first_root_frame='390306 entrySP-152; r0actualM/r1actualrootdescriptor, descriptor+8 selects originalbranch.',
                resolved_FP_path='390518→38CDC6(category0), entrySP-56;38CDF6→20BBB8;20BBC6 BLX ARM376454; later37857C/378590. Bounded path, not global firstFP/callee closure.'),
            widget=dict(existing_native_init='395981 and2DB541 already returned duringcontroller prep; do not reinitialize singleton before body.',
                allocations='WidgetVM calloc2DC982/aligned2DC954 guarded lower storage remains explicitfixture. CONTROL_CALLBACK syntheticret0 and pixelbuffers do not prove UI/touch/rendering.',
                transition='Exact2DC954 caller6F8364 remains guarded input. Preserve EA10000 RX and EA11000 component BSS reservation when component_active becomesFalse; do not use inherited unchecked body-phase transition allocator.'),
            GIR=dict(prepared='34F7730 catalog24 live vector and initialized34F773C/tag41B544 must persist unchanged unless actual scoped original writes.',
                resource_query_41C3DA=dict(entry_frame_bytes=112,RAII='T-44',wrapper='11C504 LR41C413/SP=T-112/r0=T-44/r1=34F773C',
                    lock='3009A0 LR11C511/SP=T-120',unlock='3008B0 LR41C68F/SP=T-112'),
                optional_file_header_41C944=dict(entry_frame_bytes=80,RAII='T-76',wrapper='11C504 LR41C957/SP=T-80/r0=T-76/r1=34F773C',
                    lock='3009A0 LR11C511/SP=T-88',unlock='3008B0 LR41C999/SP=T-80'),
                policy='Capture originalRAII store11C50A and exact parent entry before lock. Shared11C510 alone is insufficient. Registration unlock41CCD2 is not either query unlock. No guestquery reached claim.'),
            fonts=dict(first_new_observer='Cache journal hook immediately requirescomponent_active/controller on any786432cache write;263F60 request and raw stack destination similarlycontroller-only.',
                needed='A distinct body actor-specific extension preserves exact263F60/26475C caller→epilogue→return,26491C→14F084 LR264939→31CF22 unique H+livegeneration/control/context binding and original opcode.',
                protected='Keep wholeK620, parser152/context100,13metadata/records,TCB108/otherblockedframes52/rawsem24/timednode20 and companion/inputguards outside rawfile destination; permit actualD live stack only bounded by captured actualSP/stacklimit.',
                existing='8 resident streams/13font descriptors/221 live cache payloads from prep remain; newbody may allocate/free through capturedoriginalpaths. SQL statements stillclose; sourceDB immutable. Do not require unchangedcache occupancy if nativebody changes it.')),
        initialized_and_BSS_scope=dict(
            seven_conditional_writers='Frozen exact seven original tuples remain the only previously reviewed05400000 initialized-bank writes. ControllerGIRVM.journal_gui_write turns off withcomponent_active; newbody must retain chronology and exact tuples, not rebaseline or admitallBSS.',
            F00000='JournalSettingsVM whole467532-byte original CPU before/value replay stays active. Newnative managerF2CD0C publish is within this bank and must be captured; no host353A9C clockwrite.',
            new_BSS='Declare actualregistry34F9B28 backend24,registry34F9B40 vector12,onceF2CBF4/F2CBF8 words viaexistingF0journal,cleanuphead3AAEC70 word and actual16nodes,liveM E50 and exact root/page allocation metadata. Other previously undeclared BSS writes stop for newboundedscope.',
            first_same_FP_predicates='ColdFPControllerVM.verify_cold_metadata/verify_extra_zones still requireM40unchanged,slot0,pool256FF andownerC; nativecrossowner saves legitimately change those. NewFPobserver must journal actual148save/advance152/VSTM128,Dclone40 and poolguards before revising only these predicates.'),
        source_method_boundaries=methods,exact_bounded_original_slices=[dict(start=hex(a),end=hex(b),mode=m) for a,b,m in slices],
        exact_original_instruction_evidence=instructions,
        remaining_unproven=['ActualDispatcher405340 body/manager/root/page fullrun',
            'Any newGIR/font actor path actually reached','MultiownerFP exchange and laterhandlercleanup',
            'Callback-return plus scheduler-to-controller and allnewwholeguards',
            'Touch/display/hardware/deviceApp/modifiedpackage acceptance/safeunload']))
    print(json.dumps(dict(contract=artifact,host_controls=control_artifact,
                         protected_count=len(registry),exact_instructions=len(instructions)),ensure_ascii=False))


if __name__=='__main__':
    main()
