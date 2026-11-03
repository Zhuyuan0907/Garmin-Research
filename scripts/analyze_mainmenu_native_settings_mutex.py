#!/usr/bin/env python3
"""Exact static settings mutex callers before native MainMenu preparation.

Reads immutable backup bytes and proof sources. It does not instantiate a VM,
execute guest instructions, touch hardware, or overwrite completed evidence.
The recursive closure is bounded to the settings code window; it is not a
complete kernel, flash-driver, interrupt, or indirect-call closure.
"""
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path
import hashlib
import json

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
from capstone.arm import ARM_CC_AL, ARM_INS_B, ARM_INS_BL, ARM_INS_BLX, ARM_REG_R0
from analyze_native_sections import ROOT, NativeImage, EXPECTED
from analyze_native_gui_worker_boot import FileBackedRuntimeImage
from analyze_native_gui_foreground_boot import cfg, extract

STAGE = ROOT / 'staging/native-player-mainmenu-native-prep/mutex-static'
OUTPUT = STAGE / 'mainmenu-native-settings-mutex-preflight.json'
WINDOW = (0x2ca000, 0x2cc2a4)
ROOTS = (0x2cbd16, 0x2ca82c)
SEM_TAGS = {0x148e69c: 0x2cbf5c, 0x148e6b4: 0x2cbf4c,
            0x148e6cc: 0x2cbf6c, 0x148e6e4: 0x2cbf7c, 0x148e920: 0x2cbfa0}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def literal_provenance(image, function, call, register=ARM_REG_R0):
    """Walk every local CFG predecessor until the last register definition.

    A call clobbers argument registers even if Capstone only reports LR. A
    pointer is accepted only when every predecessor path ends at a literal
    LDR of that same pointer, with no intervening register write/call.
    """
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    md.detail = True
    rows = {int(r['address'], 16): r for r in function['instructions']}
    decoded = {a: next(md.disasm(image.read(a, 4), a, count=1)) for a in rows}
    predecessors = defaultdict(set)
    for a, ins in decoded.items():
        if 'terminal' in rows[a]:
            successors = []
        elif ins.id == ARM_INS_B:
            successors = [ins.operands[0].imm]
            if ins.cc != ARM_CC_AL:
                successors.append(a + ins.size)
        else:
            successors = [a + ins.size]
        for target in successors:
            if target in rows:
                predecessors[target].add(a)
    pending = list(predecessors[call])
    seen, definitions = set(), {}
    assert pending, hex(call)
    while pending:
        a = pending.pop()
        if a in seen:
            continue
        seen.add(a)
        ins, row = decoded[a], rows[a]
        assert ins.id not in (ARM_INS_BL, ARM_INS_BLX), (hex(call), 'intervening call', row)
        if register in ins.regs_access()[1]:
            assert row['instruction'].startswith('ldr ' + ins.reg_name(register) + ', [pc,'), row
            assert 'literal_value' in row, row
            definitions[a] = row
        else:
            assert predecessors[a], (hex(call), 'unresolved function argument', row)
            pending.extend(predecessors[a])
    assert definitions
    values = {int(r['literal_value'], 16) for r in definitions.values()}
    assert len(values) == 1, (hex(call), definitions)
    return next(iter(values)), dict(
        all_local_incoming_paths_resolve_same_pointer=True,
        no_intervening_register_write_or_call=True,
        literal_definitions=[definitions[a] for a in sorted(definitions)],
        local_predecessor_instructions_checked=[hex(a) for a in sorted(seen)])


def main():
    assert not OUTPUT.exists(), 'Never overwrite completed static evidence'
    image = FileBackedRuntimeImage(NativeImage())
    functions, graph, todo = {}, [], list(ROOTS)
    while todo:
        entry = todo.pop()
        if entry in functions:
            continue
        function = cfg(image, entry, [WINDOW])
        functions[entry] = function
        for row in function['instructions']:
            if 'direct_call' not in row:
                continue
            target = int(row['direct_call'], 16)
            in_window = WINDOW[0] <= target < WINDOW[1]
            graph.append(dict(containing_function=hex(entry), call=row['address'],
                target=hex(target), recursively_recovered_in_settings_window=in_window))
            if in_window:
                todo.append(target)
    assert len(functions) == 39
    witnesses = {}
    for root in ROOTS:
        paths, pending = {root: []}, deque([root])
        while pending:
            entry = pending.popleft()
            for edge in graph:
                target = int(edge['target'], 16)
                if int(edge['containing_function'], 16) == entry and target in functions and target not in paths:
                    paths[target] = paths[entry] + [edge]
                    pending.append(target)
        witnesses[root] = paths
    assert len(witnesses[0x2cbd16]) == 39
    rows = {int(r['address'], 16): r for f in functions.values() for r in f['instructions']}
    raw_calls, raw_sites = [], set()
    for entry, function in sorted(functions.items()):
        for row in function['instructions']:
            if row.get('direct_call') not in ['0x3009a0', '0x3008b0']:
                continue
            call = int(row['address'], 16)
            assert call not in raw_sites
            raw_sites.add(call)
            pointer, provenance = literal_provenance(image, function, call)
            assert pointer in SEM_TAGS
            tag = SEM_TAGS[pointer]
            raw_calls.append(dict(entry=row['direct_call'], continuation=hex(call+4),
                pointer=hex(pointer), tag=hex(tag), containing_function=hex(entry), call=hex(call),
                mode='Thumb', actual_entry_LR=hex((call+4)|1), bytes=24,
                operation='lock' if row['direct_call']=='0x3009a0' else 'unlock',
                tag_ascii=image.read(tag,64).split(b'\0')[0].decode('ascii'),
                r0_provenance=provenance,
                reachable_from=[hex(root) for root in ROOTS if entry in witnesses[root]],
                initializer_direct_call_witness=witnesses[0x2cbd16][entry],
                caller_requires_observed_runtime_execution=True))
    assert len(raw_calls) == 36
    raw_calls.sort(key=lambda r: int(r['call'], 16))
    initializers = []
    for call, pointer, producer, retag, writer in [
            (0x2cbd38,0x148e6b4,0x2cbd32,0x2cbd3e,0x2cbd40),
            (0x2cbd44,0x148e69c,0x2cbd42,0x2cbd4a,0x2cbd4c),
            (0x2cbd50,0x148e6cc,0x2cbd4e,0x2cbd56,0x2cbd58),
            (0x2cbd5c,0x148e6e4,0x2cbd5a,0x2cbd62,0x2cbd64),
            (0x2cbd7e,0x148e920,0x2cbd7c,0x2cbd84,0x2cbd86)]:
        assert rows[call]['direct_call']=='0x3008a0'
        value, provenance = literal_provenance(image, functions[0x2cbd16], call)
        assert value == pointer and rows[producer]['literal_value'] == hex(pointer)
        tag = SEM_TAGS[pointer]
        assert rows[retag]['address_value']==hex(tag)
        assert rows[writer]['instruction']=='str r0, [r1, #0x10]'
        assert rows[call+4]['literal_value']==hex(pointer)
        zero = next(z for z in image.stock.zeros if z['runtime_start']<=pointer and pointer+24<=z['runtime_end'])
        initializers.append(dict(entry='0x3008a0',call=hex(call),continuation=hex(call+4),
            pointer=hex(pointer),tag=hex(tag),tag_ascii=image.read(tag,64).split(b'\0')[0].decode('ascii'),
            containing_function='0x2cbd16',bytes=24,r0_provenance=provenance,
            original_retag_ADR=hex(retag),original_retag_store_PC=hex(writer),retag_offset=16,
            storage=dict(kind='original_startup_zero_BSS',range_start=hex(zero['runtime_start']),
                range_end=hex(zero['runtime_end']),filebacked_live_bytes=False)))
    assert rows[0x2cbd6e]['direct_call']=='0x3ec540'
    assert rows[0x2cbd6c]['literal_value']=='0x148e8ec'
    assert rows[0x2cbd74]['address_value']==rows[0x2cbd78]['address_value']=='0x2cbf8c'
    assert rows[0x2cbd76]['instruction']=='str r1, [r0, #0x10]'
    assert rows[0x2cbd7a]['instruction']=='str r1, [r0, #0x2c]'
    assert rows[0x2cac9a]['literal_value']=='0x148e920'
    assert rows[0x2cac9c]['literal_value']=='0x148e8ec'
    assert rows[0x2cb570]['literal_value']==rows[0x2cb5b4]['literal_value']=='0x148e8ec'
    assert image.word(0xf06f24)==image.word(0xf08a78)==0 and image.read(0xf08c88,1)==b'\0'
    core_path = ROOT/'staging/native-player-task-mutex/task-mutex-static-preflight.json'
    core = json.loads(core_path.read_text())
    assert sha(core_path)=='ce58164830245667cfd0d805b97e0abd609239c354ffc3f1bcd7ee82cc1f878d'
    assert core['MAIN_sha256']==EXPECTED
    verified = {}
    proof_paths = [core_path,
        ROOT/'staging/native-player-independent-signal/mainmenu-controller-prerequisites-static.json',
        ROOT/'evidence/firmware-analysis/native-independent-signal-emulation.json']
    for path in proof_paths:
        proof = json.loads(path.read_text())
        assert proof['MAIN_sha256']==EXPECTED
        for name, expected in proof['source_sha256'].items():
            assert sha(ROOT/name)==expected, name
            assert name not in verified or verified[name]==expected, name
            verified[name]=expected
    selected_core = {key:core['functions'][key] for key in ['0x3008a0','0x3009a0','0x3008b0',
        '0x300ae4','0x300bb8','0x300a14','0x300d08','0x358e70','0x358ec4','0x3ec540','0x3ec498','0x3ec5c6']}
    normal_copy = next(r for r in image.stock.copies if r['runtime_start']==0xf00000)
    assert normal_copy['size']==467532 and normal_copy['load_start']==0xcb1980
    dependencies = [Path(__file__).resolve(),
        ROOT/'scripts/analyze_native_sections.py',ROOT/'scripts/analyze_native_gui_worker_boot.py',
        ROOT/'scripts/analyze_native_gui_foreground_boot.py',ROOT/'scripts/analyze_native_task_mutex_static.py',
        ROOT/'scripts/probe_native_task_mutex.py',ROOT/'scripts/probe_native_dispatcher_condition.py',
        ROOT/'scripts/probe_native_settings_writer.py',ROOT/'scripts/emulate_native_independent_signal.py',
        ROOT/'evidence/firmware-analysis/main_02bd.bin',*proof_paths]
    payload = dict(updated_utc=datetime.now(timezone.utc).isoformat(),MAIN_sha256=EXPECTED,
        exact_target=dict(HWID=1352,software='8.00',region='Taiwan'),
        source_sha256={str(p.relative_to(ROOT)):sha(p) for p in dependencies},
        verified_frozen_dependency_hashes=verified,
        raw_mutex_calls=raw_calls,native_initializers=initializers,
        settings_module_CFGs={hex(a):f for a,f in sorted(functions.items())},
        settings_direct_call_graph=graph,
        recursive_bound=dict(window_start=hex(WINDOW[0]),window_end=hex(WINDOW[1]),
            roots=[hex(a) for a in ROOTS],settings_function_count=39,
            local_instruction_count=sum(len(f['instructions']) for f in functions.values()),
            raw_call_count=36,all_local_CFGs_complete=True,
            every_in_window_direct_call_recursively_recovered=True,
            all_paths_potential_not_all_paths_executed=True,complete_kernel_or_hardware_boot=False,
            callees_outside_window_not_recursively_recovered=True,
            indirect_calls_not_resolved_by_this_closure=True),
        reused_frozen_core_CFGs=selected_core,
        new_core_slices=dict(settings_condition_wait_wrapper=extract(image,0x3ec6a2,0x3ec6aa),
            original_settings_init_and_retag=extract(image,0x2cbd16,0x2cbd88)),
        native_shapes=dict(semaphore_bytes=24,offsets=dict(owned_next=0,owned_previous_link_pointer=4,
            owner_TCB=8,waiter_head=12,tag=16,extra_recursion_u16=20,classification_byte=22),
            initializer=dict(entry='0x3008a0',zero_store_PCs=[hex(a) for a in range(0x3008a2,0x3008ae,2)],
                offsets=list(range(0,24,4)),zero_store_size=4,original_return='0x3008ae',
                native_register_R0_preserved_as_pointer_not_status=True),
            lock_return='0x300a0a',unlock_return='0x30092a',lower_wait_return='0x300ada',
            lock_return_zero_requires_actual_originating_task_owner=True,
            unlock_R0_not_a_boolean_success_status=True),
        settings_condition=dict(entry='0x3ec540',call='0x2cbd6e',continuation='0x2cbd72',
            pointer='0x148e8ec',bytes=52,auxiliary='0x148e908',magic_offset=24,magic='0xd4475b83',
            tag='0x2cbf8c',tag_ascii=image.read(0x2cbf8c,64).split(b'\0')[0].decode('ascii'),
            token_initializer_continuation='0x3ec562',aux_initializer_continuation='0x3ec56a',
            native_lock_continuation='0x3ec572',native_transfer_entry='0x300ae4',
            native_transfer_continuation='0x3ec57c',native_target_TCB='word(F090A0)',
            actual_Timer_fixture_TCB='0x2d227c8',IRQ_restore_entry='0x21b6dc',IRQ_restore_continuation='0x3ec582',
            original_token_retag_store='0x2cbd76',original_aux_retag_store='0x2cbd7a',
            no_once_guard_at_settings_initializer_entry=True,
            no_repeat_init_over_owned_or_queued_live_semantics=True,
            constructor_temporary_owner='actual controller while lock executes',
            constructor_final_owner='native Timer after actual300AE4 transfer',
            retained_token_not_an_ordinary_mutex_count=True,
            coexistence_at_completed_preparation=dict(Timer_owned_head='0x148e8ec',
                settings_token=dict(next='0x8805290',previous_link='TimerTCB+32',owner='TimerTCB',
                    waiter=0,recursion_u16=0,classification_byte=0,tag='0x2cbf8c'),
                GUI_token=dict(pointer='0x8805290',next=0,previous_link='0x148e8ec',owner='TimerTCB',
                    waiter=0,recursion_u16=0,classification_byte=0,tag='0x6048e8'),
                auxiliary=dict(owner=0,waiter=0,recursion_u16=0,classification_byte=0,tag='0x2cbf8c'),
                both_tokens_retained_and_backing_live=True,
                expected_list_assumes_no_additional_native_Timer_owned_acquisitions=True),
            wait_call=dict(call='0x2cac9e',continuation='0x2caca2',entry='0x3ec6a2',
                r0='0x148e8ec',r1='0x148e920',r2_from_wrapper='0xffffffff',r3_from_wrapper=1,
                tail='0x3ec5c6',loop='F06EF4+2 remains nonzero',
                require_real_mutex_reacquisition_and_original_saved_return=True),
            broadcasts=[dict(call=hex(a),continuation=hex(a+4),entry='0x3ec498',pointer='0x148e8ec')
                        for a in [0x2cb572,0x2cb5b6]],
            core_aux_lock='0x3ec4be',core_aux_unlock='0x3ec4ee',
            original_broadcast_clear_waiter_marker_and_POST8_no_fake_wake=True),
        setter=dict(entry='0x2ca82c',containing_function='0x2ca82c',
            arguments=['record_ID','data_pointer','byte_length','optional_cursor_pointer'],
            explicit_proposed_input=dict(record='0x19b',bytes=4,value=1,original_stock_boot_input=False),
            original_return_sites=functions[0x2ca82c]['returns'],
            initializer_can_call_setter_via=['2CC264->2CB4A8->2CB590','2CC270->2CAC22->2CACC0'],
            mutex_order='initial put; pressure path releases put, locks get then put; del is nested later',
            pressure_retry_release_sites=['0x2ca972','0x2ca978'],
            existing_record_delete_helper='0x2ca5da, del lock2CA5E6/unlock2CA642',
            reader='0x2cabbc, get lock2CABFA/unlock2CAC08',
            caller_table_covers_helper_branches_not_a_claim_every_call_executes=True),
        conditional_native_posts=[
            dict(call='0x2caa74',continuation='0x2caa78',entry='0x2fcf44',target='word(F06F24)',event='0x100',
                gates=['byte(F06EF4+2)==0','original2CA128 returns nonzero']),
            dict(call='0x2caa8e',continuation='0x2caa92',entry='0x2fcf44',target='word(F06F24)',event='0x200',
                gates=['byte(F06EF4+2)==0','signed word(148E938+4)>word(148E938+8)','byte(F08C88)!=9']),
            dict(call='0x2ca112',continuation='0x2ca116',entry='0x2fcf44',target='word(F08A78)',event='0x1000',
                gates=['unless inputr0==1 and byteF08C00==1 selects265C26 alternate'],
                reachable_helper='0x2ca0f6',distinct_target_from_settings_F06F24=True)],
        native_TCB_target_limits=dict(filebacked_initial_F06F24=0,filebacked_initial_F08A78=0,
            filebacked_initial_byteF08C88=0,
            target_for_2CAC8A_priority_API='word(F06F24),r1=0x10,entry358E18',
            task_builder_not_recovered_in_settings_closure=True,
            never_whitelist_NULLpost_or_fake_delivery=True,
            runtime_must_capture_actual_target_writer_and_native_constructed_TCB_before_taken_post_or_priority_call=True),
        observer_extension_requirements=[
            'New subclass/source only: intercept the five exact3008A0 continuation/pointer pairs before the inherited no-op. Set active_backend and preserve DispatcherVM six native zero-store/completion guards.',
            'For raw_mutex_calls, key by(entry,normalizedLR), require exactr0 pointer/native tag/live24byte BSS/class0, register native semaphore, append actual-running-task pending row, then execute nativebody with registers untouched.',
            'Preserve native300A0A/30092A epilog,300BB8/300A14 nested return,300D08 waiter and actual saved restore destination observation. No synthetic success or owner/queue/context writes.',
            'Allow generic condition constructor at148E8EC with existing3EC562/56A init and3EC572 actual lock path. NativeTaskMutexVM must intercept before inherited SettingsVM constructor-ret0 hook.',
            'Track both retained Timer tokens and the exact native owned-list prepend/previous-link changes. Update new endpoint guard instead of old single-GUI-token next0/head assumptions.',
            'Existing per-task broadcast/wait journaling supports settings condition when both token and148E920 mutex are registered. Preserve original fullrelease, wait and reacquisition; validate actual branch before claiming it ran.',
            'At each completed controller API require actualcontroller/SP/return and empty settings pending scopes. If original code blocks, retain live frame/backing and do not invoke another host API over it.',
            'Retain original POST native-TCB guard; first taken F06F24/F08A78 path needs original target-provider observation. No NULL target allowance.'],
        initialized_data_guard=dict(original_start='0xf00000',bytes=467532,end='0xf7224c',load_start='0xcb1980',
            original_copy_sha256=hashlib.sha256(image.read(0xf00000,467532)).hexdigest(),
            proposed_native_CPU_store_journal_and_whole_bank_compare=True,
            settings_flags_and_target_cells_are_in_this_bank=True,
            settings_sem_and_condition_are_BSS_and_need_separate_exact_native_shape_guards=True,
            CPU_journal_is_store_evidence_not_instrumented_physical_hardware=True,
            host_change_must_not_be_hidden_by_replacing_expected_baseline=True),
        fixture_and_hardware_limits=dict(original_ARM_Thumb_bytes_and_ABI_analyzed=True,
            existing_5TCB_controller_idle_initial_ready_membership_virtual_clock_and_NOR_services_are_fixtures=True,
            no_new_guest_execution=True,physical_kernel_IRQ_timer_flash_audio_UI_BT_behavior_verified=False,
            safe_cleanup_unload_or_install_candidate=False),
        assertions_passed=True,device_io=False,sounds_emitted=False,frozen_source_or_proof_modified=False,
        limits='Bounded static direct-call closure39 settings functions/3395 local instructions plus verified frozen mixed-mode kernel CFGs. Raw caller arguments have every-local-predecessor literal proofs. External driver/kernel callees and indirect calls are not a complete recursive kernel or stock boot path; future prepared-controller execution and endpoint guards are separate evidence.')
    STAGE.mkdir(parents=True,exist_ok=True)
    with OUTPUT.open('x') as stream:
        stream.write(json.dumps(payload,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(dict(output=str(OUTPUT.relative_to(ROOT)),sha256=sha(OUTPUT),
        source_sha256=sha(Path(__file__).resolve()),raw_mutex_calls=len(raw_calls),
        settings_CFG_count=len(functions),verified_frozen_dependencies=len(verified))))


if __name__=='__main__':
    main()
