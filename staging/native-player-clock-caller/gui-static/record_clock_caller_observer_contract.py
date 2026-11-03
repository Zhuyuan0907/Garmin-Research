#!/usr/bin/env python3
"""Pure import/shape/opcode review; no VM/guest/device/canonical writes."""
from pathlib import Path
from datetime import datetime,timezone
import ast,hashlib,importlib.util,json,sys

ROOT=Path(__file__).resolve().parents[3]
BASE='staging/native-player-clock-caller/gui-static/'
sys.path.insert(0,str(ROOT/'scripts'))
from analyze_native_sections import NativeImage,EXPECTED
from capstone import Cs,CS_ARCH_ARM,CS_MODE_ARM,CS_MODE_THUMB

def sha(path):
    h=hashlib.sha256()
    with (ROOT/path).open('rb') as handle:
        while chunk:=handle.read(1024*1024):h.update(chunk)
    return h.hexdigest()

def main():
    source_path=BASE+'clock_caller_observer.py'
    spec=importlib.util.spec_from_file_location('new_clock_caller_pure_review',ROOT/source_path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    shape=module.clock_caller_shapes(0x8804090)
    assert shape['wrapper_entry_SP']==0x8804048 and shape['wrapper_body_SP']==0x8804030
    assert shape['constructor_entry_SP']==0x8804030 and shape['clock_entry_SP']==0x8803FB0
    assert shape['clock_result_address']==0x8803FEC and shape['clock_host_write_allowed'] is False
    valid=dict(actor=0x8804FB8,current=0x8804FB8,Thumb=True,entry=0x353A9C,LR=0x39552D,SP=0x8803FB0,clock_word=0)
    store=dict(actor=0x8804FB8,current=0x8804FB8,Thumb=True,actual_return_seen=True,
        PC=0x39552C,address=0x8803FEC,size=4,value=0,SP=0x8803FB0)
    module.check_clock_actor(shape,valid);module.check_clock_result_store(shape,store)
    controls=[dict(name='exact395528_clock_currentD_native_frame',accepted=True),
              dict(name='exact_return_bound_original_stack_store',accepted=True)]
    def reject(name,fn,args):
        try:fn(*args)
        except RuntimeError as error:
            controls.append(dict(name=name,accepted=False,expected_rejection=True,error=str(error)))
        else:raise AssertionError('Expected pure rejection '+name)
    for key,value in [('actor',0x9503F90),('current',0x9503F90),('Thumb',False),
                      ('entry',0x353A76),('LR',0x38D913),('SP',0x8803FB4),('clock_word',20)]:
        event=dict(valid);event[key]=value;reject('clock_wrong_'+key,module.check_clock_actor,(shape,event))
    for key,value in [('PC',0x39552E),('address',0x8803FF0),('size',8),('value',1),
                      ('SP',0x8803FB4),('actor',0x9503F90),('current',0x9503F90),
                      ('Thumb',False),('actual_return_seen',False)]:
        event=dict(store);event[key]=value;reject('result_wrong_'+key,module.check_clock_result_store,(shape,event))
    reject('unaligned_real_SFS_frame',module.clock_caller_shapes,(0x8804091,))
    reject('non_address_real_SFS_frame',module.clock_caller_shapes,('0x8804090',))

    stock=NativeImage();cs={True:Cs(CS_ARCH_ARM,CS_MODE_THUMB),False:Cs(CS_ARCH_ARM,CS_MODE_ARM)}
    def code(start,length,thumb=True):
        rows=[dict(PC=hex(i.address),opcode_hex=i.bytes.hex(),instruction=i.mnemonic+' '+i.op_str,Thumb=thumb)
              for i in cs[thumb].disasm(stock.read(start,length),start)]
        assert sum(len(bytes.fromhex(r['opcode_hex'])) for r in rows)==length
        return rows
    originals=dict(SFS_exact_caller=code(0x26DD3E,0x22),wrapper=code(0x39578E,0x2A),
        constructor_clock_prefix=code(0x395520,0x26),clock_getter=code(0x353A9C,6),
        manager_E34_accessor=code(0x223A08,6),unknown_allocator_ARM_gate=code(0x3954CC,8,False))
    rows={int(r['PC'],16):r for group in originals.values() for r in group}
    exact={0x26DD5C:('27f117fd','bl #0x39578e'),0x39578E:('f8b5','push {r3, r4, r5, r6, r7, lr}'),
        0x3957B2:('fff7b5fe','bl #0x395520'),0x395520:('ffb5','push {r0, r1, r2, r3, r4, r5, r6, r7, lr}'),
        0x395522:('97b0','sub sp, #0x5c'),0x395524:('209d','ldr r5, [sp, #0x80]'),
        0x395526:('1c00','movs r4, r3'),0x395528:('bef7b8fa','bl #0x353a9c'),
        0x39552C:('0f90','str r0, [sp, #0x3c]'),0x39552E:('3020','movs r0, #0x30'),
        0x395530:('fff7ccef','blx #0x3954cc'),0x39553E:('0820','movs r0, #8'),
        0x395540:('fff7c4ef','blx #0x3954cc')}
    for pc,(opcode,instruction) in exact.items():
        assert rows[pc]['opcode_hex']==opcode and rows[pc]['instruction']==instruction
    assert [(r['PC'],r['opcode_hex']) for r in originals['clock_getter']]==[(hex(p),op) for p,op in module.GETTER_OPS]
    assert stock.word(0x353AA4)==0xF09098 and stock.word(0x26E0C4)==0xEA60
    assert stock.word(0x223A10)==0xE34 and stock.word(0x3954D4)==0x2DC9EB

    tree=ast.parse((ROOT/source_path).read_text())
    forbidden={n.attr for n in ast.walk(tree) if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute)
               for n in [n.func] if n.attr in ('mem_write','reg_write','emu_start','emu_stop','ret','put','kernel_invoke','invoke','mem_map')}
    assert not forbidden
    classes=[n for n in tree.body if isinstance(n,ast.ClassDef)]
    assert len(classes)==1 and classes[0].name=='ClockCallerDispatcherActorObserverMixin'
    assert ast.unparse(classes[0].bases[0])=='parent.InlineFieldDispatcherActorObserverMixin'
    methods={n.name for n in classes[0].body if isinstance(n,ast.FunctionDef)}
    assert {'init_dispatcher_actor_observer','capture_dispatcher_settings_inputs',
            'observe_dispatcher_actor','snapshot_dispatcher_actor_observer','verify_dispatcher_actor_observer'}<=methods
    assert 'journal_settings_actor_write' not in methods

    audit_path='evidence/firmware-analysis/native-inline-fields-checkpoint-audit.json'
    assert sha(audit_path)=='05649316d052441a3a7d00e68fc931dbce189b462de57f4a80aae52f325db784'
    audit=json.loads((ROOT/audit_path).read_text())
    assert audit['all_passed'] and audit['original_guest_session']==35110
    assert not audit['complete_Dispatcher_body_or_foreground_or_physical_App']
    protected=audit['protected_sources']
    producer=str(Path(__file__).resolve().relative_to(ROOT))
    paths=[source_path,producer,audit_path,
        'staging/native-player-inline-fields/gui-static/inline_fields_observer.py',
        'staging/native-player-inline-fields/gui-static/inline-fields-observer-contract.json',
        'staging/native-player-inline-fields/gui-static/next-clock-caller-contract.json',
        'staging/native-player-inline-fields/gui-static/inline-fields-observed-prefix.json',
        'staging/native-player-inline-fields/runtime/terminal-probe.json',
        'staging/native-player-inline-fields/runtime/terminal-metadata.json',
        'staging/native-player-inline-fields/runtime/terminal-tool-receipt.json',
        'staging/native-player-dispatcher-native-body/gui-static/dispatcher_actor_observer.py',
        'staging/native-player-dispatcher-fp/gui-static/dispatcher_actor_shapes.py',
        'scripts/probe_native_dispatcher_inline_fields.py','scripts/probe_native_mainmenu_controller.py',
        'scripts/emulate_native_player_menu_loaded.py','scripts/analyze_native_sections.py',
        'evidence/firmware-analysis/main_02bd.bin']
    sources={p:sha(p) for p in paths}
    for p,h in sources.items():
        if p in protected:assert protected[p]==h
    assert sources['staging/native-player-inline-fields/gui-static/inline_fields_observer.py']==module.PARENT_SHA
    doc=dict(updated_utc=datetime.now(timezone.utc).isoformat(),source_sha256=sources,
        helper=dict(path=source_path,sha256=sources[source_path],class_name=classes[0].name),
        exact_MAIN_sha256=EXPECTED,all_static_and_pure_controls_passed=True,
        guest_execution=False,VM_driver_imported=False,VM_instantiated=False,device_io=False,
        source_fixture_supplied_or_guest_registers_or_memory_changed=False,
        checkpoint=dict(path=audit_path,sha256=sources[audit_path],protected_files=len(protected),
            full_registry_rescan_by_this_producer=False,only_referenced_dependency_hashes_rechecked=True),
        interface=dict(init='Call init_dispatcher_actor_observer after root constructor mappings; super initializes frozen parents.',
            capture='Existing capture_dispatcher_settings_inputs chain adds clock_caller_inputs; call after begin_body_observer and decoder capture, before Signal80 publication.',
            observe='Root calls observe_dispatcher_actor first when dispatcher_body_active; True only at exact353A9C newcaller to suppress inherited clock observer, never suppress native guest instruction.',
            snapshot='Adds clock_caller_observer to inherited snapshot; records incomplete containing functions and allocator boundary explicitly.',
            verify='Runs frozen parent verification first; clock-prefix verification cannot elevate incomplete parent body/foreground.',
            root_attributes=['body_zones existing whole-D stack journal','dispatcher_body_active','dispatcher_task',
                'dispatcher_callback_SP','manager_object','running_task','native_TCBs','pending_restore'],
            new_guest_mappings_required=False,new_native_pages_or_host_scalars_seeded=False),
        exact_shape=shape,actual_native_frame_guards=dict(native_source_caller='26DD5C→39578E→3957B2→395520',
            wrapper_arguments=['SFSbodySP+28','SFSbodySP+10','EA60','1'],
            constructor_arguments=['wrapperR0','actual_live_manager+E34','wrapperR1','wrapperR2'],
            constructor_fifth='Original3957B0 STRr7,[SP] value1 verified in root whole-stack ledger',
            PUSH_capture='Capture actual beforebytes/pre-instruction registers at native entry; consume root original actual-SP/register-bound PUSH6/PUSH9 stores and independently replay their spans.',
            native_frame_or_clock_seeded=False,synthetic_manager38D4BE_frame_allowed=False,
            function_entry_bypassed_or_synthesized=False),
        clock_contract=dict(original_read='353A9C LDRr1,literalF09098;353A9E LDRr0,[r1];353AA0 BXLR',
            entry_LR='39552D',entry_SP='captured395520SP−128',native_current='8804FB8',fixed_existing_clock_input=0,
            original_instruction_events_required=3,actual_return_PC='39552C',actual_return_SP='same getter entrySP',
            actual_return_registers=['R0=0','R1=F09098','R2=originalentryR2','R3=originalentryR3'],
            result_store='Original39552C STRr0,[SP,#3C], exact4bytes0; native return ledger required before CPU write.',
            native_getter_return_or_original_stack_store_observed_by_this_static_record=False,
            clock_host_tick_increment_or_return_allowed=False,
            original_clock_word_attempted_writes_hardstop=True,
            result_hook_preserves_old_journals_and_root_records_original_store_once=True),
        preserved_parent_scopes=dict(manager_clock_callers=['38D912','38D91E'],manager38D4BE_frame_guards_unchanged=True,
            native_raw_epilogues=['300A0A','30092A'],all_old_GIR_font_cache_settings_decoder_FP_guards_unchanged=True,
            unrecognized_clock_callers_delegate_to_frozen_parent_and_remain_unreviewed=True),
        explicit_next_boundaries=[dict(entry='3954CC ARM',original_call='395530 BLX',continuation='395534',request48=48,
                shape_SP='captured395520SP−128',admitted=False),
            dict(entry='3954CC ARM',original_call='395540 BLX',continuation='395544',request8=8,
                shape_SP='captured395520SP−128',admitted=False)],
        allocation_qualification='Inherited guarded C++ allocation/hostreturn remains an offline provider fixture; this new caller stops before provider dispatch. Neither native heap success nor those returns is admitted.',
        bounded_original_instructions=originals,pure_host_controls=controls,
        pure_host_controls_count=len(controls),code_ast_has_guest_execution_or_mutation_calls=False,
        whole395520_constructor_or39578E_function_return_verified=False,
        full_dispatcher_body_or_foreground_verified=False,physical_App_music_or_install_verified=False)
    out=BASE+'clock-caller-observer-contract.json'
    with (ROOT/out).open('x') as handle:json.dump(doc,handle,ensure_ascii=False,indent=2);handle.write('\n')
    print(json.dumps(dict(path=out,sha256=sha(out),helper_sha256=sources[source_path],
        pure_host_controls=len(controls),original_instruction_count=sum(map(len,originals.values())),guest_execution=False)))

if __name__=='__main__':main()
