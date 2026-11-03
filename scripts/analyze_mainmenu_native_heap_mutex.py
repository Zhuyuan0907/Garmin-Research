#!/usr/bin/env python3
"""Static heap/list mutex ABI after the preserved settings20581 boundary.

Backup/proof reads only. No VM construction or guest execution. Outputs are
exclusive new files and existing settings39CFG/core proofs stay immutable.
"""
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
import hashlib
import json

from analyze_native_sections import ROOT, NativeImage, EXPECTED
from analyze_native_gui_worker_boot import FileBackedRuntimeImage
from analyze_native_gui_foreground_boot import cfg, extract
from analyze_native_task_mutex_static import bounded
from analyze_native_loader import scan_calls

STAGE=ROOT/'staging/native-player-mainmenu-native-prep/heap-static'
OUTPUT=STAGE/'mainmenu-native-heap-mutex-preflight.json'
WINDOW=(0x388000,0x388f4c)
ROOTS=(0x388804,0x388af4,0x3887a2,0x388b22,0x388b6c,0x388b56,0x388b36)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    assert not OUTPUT.exists(),'Never overwrite completed evidence'
    image=FileBackedRuntimeImage(NativeImage())
    functions,edges,todo={},[],list(ROOTS)
    while todo:
        entry=todo.pop()
        if entry in functions:continue
        function=cfg(image,entry,[WINDOW]);functions[entry]=function
        for row in function['instructions']:
            target=None
            if 'direct_call' in row:target=int(row['direct_call'],16)
            elif row['instruction']=='b #0x388746':target=0x388746
            if target is None:continue
            inside=WINDOW[0]<=target<WINDOW[1]
            edges.append(dict(containing_function=hex(entry),call=row['address'],target=hex(target),
                kind='direct_call' if 'direct_call' in row else 'original_direct_tail',recursed_heap_window=inside))
            if inside:todo.append(target)
    rows={int(r['address'],16):r for f in functions.values() for r in f['instructions']}
    for a,b in [(0x3cc57c,0x3cc594),(0x3cc5c2,0x3cc624),(0x3cc594,0x3cc5c2),
                (0x3cc624,0x3cc65e),(0x1c0600,0x1c0624),(0x1c0624,0x1c063c),
                (0xf6e68,0xf6eba),(0x217596,0x2175a8)]:
        functions[a]=cfg(image,a,[(a,b)])
    functions[0x388b24]=bounded(image,0x388b24,'Thumb',[(0x388b24,0x388b36,'Thumb')],
        tails={0x388b34:'bx r3'})
    functions[0x21210c]=bounded(image,0x21210c,'ARM',[(0x21210c,0x212154,'ARM')],
        tails={0x212150:'bx lr'})
    rows={int(r['address'],16):r for f in functions.values() for r in f['instructions']}
    assert rows[0x388bcc]['direct_call']=='0x3008a0'
    assert rows[0x388bca]['literal_value']=='0x3a7f18c'
    assert rows[0x388bd0]['address_value']=='0x388d00'
    assert rows[0x388bd2]['instruction']=='str r0, [r5, #0x2c]'
    heap_tag=image.read(0x388d00,64).split(b'\0')[0].decode('ascii')
    assert heap_tag=='&tsk_mem_ws.mem_smphr'
    assert rows[0x388b6e]['literal_value']=='0x3a7f170'
    assert rows[0x388b72]['instruction']=='ldr r0, [r0, #0x18]'
    assert rows[0x388b78]['instruction']=='bne #0x388bfa'
    assert rows[0x388b90]['instruction']=='ldr r4, [r0]'
    assert rows[0x3cc58a]['address_value']=='0x3cc660'
    list_tag=image.read(0x3cc660,64).split(b'\0')[0].decode('ascii')
    assert list_tag=='&p_list->smphr'
    assert rows[0x388b26]['literal_value']==rows[0x388b32]['literal_value']=='0x3a7f170'
    assert rows[0x388b30]['instruction']=='pop {r3}'
    assert rows[0x388b32]['instruction'].startswith('ldr r0,')
    init_path=ROOT/'staging/native-player-mainmenu-native-prep/mutex-static/mainmenu-native-settings-mutex-preflight.json'
    settings=json.loads(init_path.read_text())
    assert sha(init_path)=='a2a6b1f38f4b6903f25c142a834dadc04e653b82c6c8fbc0dbb77f1a166ba377'
    srows={int(r['address'],16):r for f in settings['settings_module_CFGs'].values() for r in f['instructions']}
    assert srows[0x2cbd88]['literal_value']=='0x148e680'
    assert srows[0x2cbd8a]['direct_call']=='0x3cc57c'
    heap_calls=[]
    for call,entry,owner,argument in [
        (0x38880e,0x3009a0,0x388804,'388808 LDR literal3A7F18C'),
        (0x388822,0x3008b0,0x388804,'r5 saved3A7F18C at38880C;388820 MOVr0,r5'),
        (0x388b00,0x3009a0,0x388af4,'388AF8 LDR literal3A7F18C'),
        (0x388b18,0x3008b0,0x388af4,'r5 saved3A7F18C at388AFE;388B16 MOVr0,r5'),
        (0x388756,0x3009a0,0x388746,'388752 LDR literal3A7F18C;388754 saveSP+0'),
        (0x388766,0x3008b0,0x388746,'388764 LDRr0,[SP+0] savedheap backend'),
        (0x388780,0x3009a0,0x388746,'38877E LDRr0,[SP+0] savedheap backend'),
        (0x388790,0x3008b0,0x388746,'38878E LDRr0,[SP+0] savedheap backend'),
        (0x388eb0,0x3008b0,0x388e92,'388EAE LDR literal3A7F18C;invalid-descriptor branch'),
        (0x388b5c,0x3009a0,0x388b56,'388B56 LDR literal3A7F18C'),
        (0x388b62,0x3008b0,0x388b56,'r4 saved3A7F18C at388B5A;388B60 MOVr0,r4')]:
        assert rows[call]['direct_call']==hex(entry)
        heap_calls.append(dict(entry=hex(entry),continuation=hex(call+4),call=hex(call),pointer='0x3a7f18c',
            tag='0x388d00',tag_ascii=heap_tag,classification_byte=0,bytes=24,
            containing_function=hex(owner),argument_provenance=argument,
            operation='lock' if entry==0x3009a0 else 'unlock',
            actual_entry_LR=hex((call+4)|1),original_mode='Thumb',
            failure_path=call==0x388eb0))
    listener_calls=[]
    for call,entry,owner in [(0x3cc5d0,0x3009a0,0x3cc5c2),(0x3cc616,0x3008b0,0x3cc5c2),
                            (0x3cc59c,0x3009a0,0x3cc594),(0x3cc5b8,0x3008b0,0x3cc594),
                            (0x3cc62e,0x3009a0,0x3cc624),(0x3cc652,0x3008b0,0x3cc624)]:
        assert rows[call]['direct_call']==hex(entry)
        for head in [0x2d226b4,0x148e680]:
            listener_calls.append(dict(entry=hex(entry),continuation=hex(call+4),call=hex(call),
                pointer=hex(head+4),list_head=hex(head),tag='0x3cc660',tag_ascii=list_tag,
                classification_byte=0,bytes=24,containing_function=hex(owner),
                scope='reviewed original generic-list API with exact instance gate',
                original_list_argument_must_match_instance=True,
                static_callsite_not_a_claim_this_instance_executed=True))
    proof_dir=ROOT/'staging/native-player-mainmenu-native-prep/journal-runtime'
    terminal_path=proof_dir/'settings-native-prep-terminal-probe.json'
    metadata_path=proof_dir/'terminal-metadata.json'
    terminal=json.loads(terminal_path.read_text());metadata=json.loads(metadata_path.read_text())
    assert metadata['session_id']==20581 and metadata['terminal_exit_code']==1
    assert sha(terminal_path)==metadata['probe_sha256']
    assert terminal['MAIN_sha256']==EXPECTED and not terminal['completed']
    assert terminal['registers']['pc']=='0x3009a0' and terminal['registers']['r0']=='0x3a7f18c'
    assert terminal['registers']['lr']=='0x388813' and terminal['registers']['sp']=='0x9503f40'
    assert terminal['error'].endswith('0x388812')
    assert len(terminal['settings_init_rows'])==5 and all(r['original_body_executed'] for r in terminal['settings_init_rows'])
    dependencies=[Path(__file__).resolve(),init_path,terminal_path,metadata_path,proof_dir/'runner-at-run.py',
        ROOT/'scripts/probe_mainmenu_native_settings_prep.py',ROOT/'scripts/probe_mainmenu_native_settings_journal.py',
        ROOT/'scripts/probe_native_heap_callback.py',ROOT/'scripts/analyze_native_heap_callback.py',
        ROOT/'scripts/analyze_native_heap_release.py',ROOT/'scripts/probe_native_task_mutex.py',
        ROOT/'scripts/probe_native_dispatcher_condition.py',ROOT/'scripts/probe_native_kernel_context.py',
        ROOT/'scripts/analyze_native_sections.py',ROOT/'scripts/analyze_native_gui_worker_boot.py',
        ROOT/'scripts/analyze_native_gui_foreground_boot.py',ROOT/'scripts/analyze_native_task_mutex_static.py',
        ROOT/'scripts/analyze_native_loader.py',ROOT/'evidence/firmware-analysis/main_02bd.bin']
    assert sha(ROOT/metadata['driver'])==metadata['driver_sha256']==terminal['source_sha256_before_run']
    assert sha(ROOT/metadata['runner'])==sha(proof_dir/'runner-at-run.py')==metadata['runner_snapshot_sha256']
    verified={}
    for name,expected in settings['source_sha256'].items():
        assert sha(ROOT/name)==expected,name
        verified[name]=expected
    payload=dict(updated_utc=datetime.now(timezone.utc).isoformat(),MAIN_sha256=EXPECTED,
        exact_target=dict(HWID=1352,software='8.00',region='Taiwan'),
        source_sha256={str(p.relative_to(ROOT)):sha(p) for p in dependencies},
        verified_previous_settings_source_hashes=verified,
        raw_mutex_calls=heap_calls,listener_mutex_calls=listener_calls,
        functions={hex(a):f for a,f in sorted(functions.items())},heap_direct_call_graph=edges,
        recursive_bound=dict(heap_window=[hex(a) for a in WINDOW],roots=[hex(a) for a in ROOTS],
            heap_direct_call_and_3887A2_tail_closure_complete_within_window=True,
            outside_callees_not_a_complete_recursive_kernel_or_allocator=True,
            callback_trampolines_indirect_targets_not_recursively_recovered=True,
            complete_bounded_local_CFG_count=len(functions)),
        preserved20581=dict(terminal_probe_sha256=sha(terminal_path),metadata_sha256=sha(metadata_path),
            completed=False,full_final_guards=False,original_five_settings_init_bodies_completed=True,
            original_settings_condition_token_lock_Timer_transfer_and_ctorreturn_observed=True,
            exact_before_heap_lock_body_registers=terminal['registers'],
            whitelist_boundary_is_not_firmware_corruption=True,
            no_heap_mutex_body_or_heap_init_claim=True,
            generic_settings_list_six_zero_stores_not_established_by_this_run=True),
        heap_native_initialization=dict(workspace='0x3a7f170',workspace_bytes=96,
            workspace_reset_entry='0x388b24',workspace_native_memzero='0x35b4f4',
            reset_argument_r0='3A7F170',reset_argument_r1='0x60',reset_return_R0='3A7F170',
            reset_return='0x388b34',no_reset_over_live_heap_or_owned_queued_semaphore=True,
            ctor_entry='0x388b6c',ctor_return='0x388df0',
            ctor_arguments=['r0:primary8byte[base,length]extentarray','r1:primarycount',
                            'r2:secondary8byte[base,length]extentarray','r3:secondarycount'],
            cold_gate_address='0x3a7f188',cold_gate='word(workspace+18)==0',cold_branch='388B78 nottaken',
            pointer='0x3a7f18c',pointer_offset=28,bytes=24,classification_byte=0,
            init_call='0x388bcc',entry='0x3008a0',continuation='0x388bd0',
            original_pointer_literal_producer='0x388bca',tag='0x388d00',tag_ascii=heap_tag,
            native_retag_ADR='0x388bd0',native_retag_store_PC='0x388bd2',
            retag_field='workspace+2C == semaphore+16',
            six_native_zero_stores_and_following_original_tag_store_required=True,
            primary_descriptor_used_before_count_gate=True,
            bit_helper='ARM21210C floorlog2(7FFFFFFF)=30',
            header_parameter=27,unaligned_header_bytes=3580,
            header_reserve='align_up(primarybase+0xDFC,4096)-primarybase',
            reserve_for_page_aligned_base=4096,
            native_prefix_clear='388BBE35B4F4(base,reserve)',
            native_header_stores=['388BC6:[base]=27','388BC8:[base+78]=base+7C'],
            ctor_mutates_private_heap_workspace_metadata_and_listener_nodes=True,
            original_direct_Thumb_BL_caller_candidates=scan_calls(image.stock,{0x388b6c}),
            recovered_stock_caller_slices=[extract(image,0x20b86e,0x20b88a),
                dict(**functions[0x217596],explicit_extent_literal='0x8dd398',
                    filebacked_extent8_hex=image.read(0x8dd398,8).hex(),
                    stock_primary_base='0x551ce40',stock_primary_bytes='0x1400000')],
            stock_memory_extent_not_to_be_mapped_as_actual_device_RAM_by_assumption=True),
        empty_extent_control=dict(arguments=[0,0,0,0],
            cold_legal=False,cold_path=['388B78 nottaken','388B8C reloadoriginalr0=0','388B90 LDRr4,[0]'],
            count_zero_does_not_prevent_initial_NULL_descriptor_read=True,
            warm_legal_only_if_prior_nonzero_workspace18_and_valid_native_init_inventory=True,
            warm_path=['388B78->388BFA','388BFE->388C10 withr3=0','388C16->388C88 withr1=0',
                '388C8E->388D88 withr3=0','388D88->388DEA','388DF0 originalreturn'],
            warm_empty_performs_no_init_retag_or_listener_registration=True,
            warm_return0_is_not_a_heap_boot_success_proof=True,
            cold_input_candidate=dict(primary_pointer='explicit guarded8byte descriptor',
                primary_array='[guarded pagealigned writablebuffer,bufferlength>=4096]',r1=0,r2=0,r3=0,
                private_buffer_prefix_cleared_by_original_CPU=True,
                metadata_and_two_native_exit_listeners_constructed=True,
                zero_primary_and_secondary_count_means_no_allocator_free_extent=True,
                empty_heap_not_real_allocator=True,lower_opaque_payload_services_remain_fixtures=True,
                actual_execution_not_done_here=True),
            one_normal_extent_candidate=dict(primary_array='[pagealigned guardedbuffer,8192]',r1=1,r2=0,r3=0,
                prefix_clear_bytes=4096,original_free_header='buffer+4096: [oldfreehead=0,length4096]',
                workspace_field4='buffer+4096',workspace_field18='buffer',
                workspace_field50=8192,workspace_field54=4096,workspace_field58=4096,
                requires_exact_original_zero_workspace_and_no_old_live_allocations=True,
                not_executed_not_full_physical_allocator=True)),
        list_native_initializers=[
            dict(ctor_entry='0x3cc57c',outer_call='0x2cbd8a',outer_continuation='0x2cbd8e',
                literal_producer='0x2cbd88',literal_address='0x2cbfb4',pointer='0x148e680',
                backend='0x148e684',bytes=28,tag='0x3cc660',tag_ascii=list_tag,
                init_entry='0x3008a0',init_call='0x3cc586',init_continuation='0x3cc58a',
                head_store_PC='0x3cc582',retag_store_PC='0x3cc58c',classification_byte=0,
                supported_settings_constructor_scope=True,observed20581_sixstores_not_proven=True),
            dict(ctor_entry='0x3cc57c',outer_call='0xf6ea0',outer_continuation='0xf6ea4',
                literal_producer='0xf6e9e',literal_address='0xf6ed0',pointer='0x2d226b4',
                backend='0x2d226b8',bytes=28,tag='0x3cc660',tag_ascii=list_tag,
                init_entry='0x3008a0',init_call='0x3cc586',init_continuation='0x3cc58a',
                head_store_PC='0x3cc582',retag_store_PC='0x3cc58c',classification_byte=0,
                cold_explicit_API_may_initialize_verified_empty_inventory_only=True,
                no_reset_existing_nonempty_exit_listener_chain=True)],
        heap_exit_listeners=dict(list='0x2d226b4',native_register_entry='0x3cc5c2',node_bytes=16,
            node_offsets=dict(next=0,signed_order=4,callback=8,argument=12),
            constructor_registrations=[dict(call='0x388be2',continuation='0x388be6',node='0x3a7f150',
                order='0x1000000',callback='0x388b57',argument=0),
                dict(call='0x388bf4',continuation='0x388bf8',node='0x3a7f160',
                order='0x3000000',callback='0x388b37',argument=0)],
            stock_F6E68_standard_listener=dict(call='0xf6eb0',node='0x2d226d0',order='0x2000000',
                callback='0x300c2d',argument=0,actual_prior_inventory_not_inferred=True),
            if_old_list_empty_expected_new_order=['0x3a7f150','0x3a7f160'],
            if_only_standard_listener_was_present_expected_new_order=['0x3a7f150','0x2d226d0','0x3a7f160'],
            callback_388B56='locks and unlocks heap backend as originalexit barrier',
            callback_388B36='reads exitingTCB+24hex(36decimal) owned-heap head and invokes388746 until empty',
            registration_duplicate_returns_minus1_preserving_old_node_fields=True,
            registration_orders_by_signed32_comparison_and_same_order_is_stable=True,
            actual_old_exit_head_and_full_nodes_not_dumped_in20581_terminal=True,
            required_guard='Snapshot live28byte list/sem and every bounded16byte oldnode before constructor. Require no duplicates/cycles and preserved original old order/callback/argument; native3CC608..612 may alter oldnext only to insert two exact new nodes. Verify new class/tag/owner/waiters/counts and all pending returns. No head reset if nonempty.'),
        internal_current_TCB_mutex_calls=[
            dict(entry='0x3009a0',call='0x1c0614',continuation='0x1c0618',containing_function='0x1c0600',
                pointer='word(F09090)+56',bytes=24,classification_byte=0,
                gate='owner already equals selectedTCB => return0 withno extra acquisition; otherwise actual lock thenhelperreturns1',
                native_body_and_actual_originating_task_owner_required=True),
            dict(entry='0x3008b0',call='0x1c0630',continuation='0x1c0634',containing_function='0x1c0624',
                pointer='word(F09090)+56',bytes=24,classification_byte=0,
                caller_release_gate='388794 compare prior1C0600 result;1C0624 only ifnonzero')],
        internal_sem_and_join_distinction=dict(internal_sem_original_builder_init_continuation='0x358c82',
            internal_sem_tag='originaldescriptor metadata[0] ifmetadata!=0,else0;observe actualnativebuilder tag',
            native_metadata_tag_store='0x358c94 TCB+72',
            require_ready_selected_equals_actual_running_task_at_normal_helper_entry=True,
            join_entry='0x1c0640',join_sem='separate24byte stacklocalSP+4',join_tag='0xc7f374',
            join_classification_byte=1,join_magic_flag_and_real_exit_required=True,
            internal_helper_lock_not_a_join_call_or_join_completion=True,no_ret0_replacement=True),
        wrapper_and_lifetime_semantics=dict(query_entry='0x388804',query_masks_payload_low3_flags=True,
            query_does_not_pin_or_increment_payload_lifetime=True,
            register_entry='0x388af4',register_original_stores=['388B0C descriptor+12=callback','388B14 descriptor+4 OR2'],
            zero_callback_does_not_clear_lowflag2_or_disable_release_callback_branch=True,
            unlock_wrapper='0x388b22 BXLR, noheap mutexoperation',
            release_entry='0x3887a2 MOVr1,LR thenoriginaltail388746',
            release_core='0x388676',release_callback='flags&6==6: payloadr0, callbackr1 through427582',
            callback_invoked_after_heap_unlock_before_relock=True,
            original_core_release_has_no_NULLcallback_check=True,
            preserved20581_and_priorlower_services_do_not_prove_native388746_or388676_executed=True,
            lower_opaque_translation_descriptor_and_payload_allocation_release_are_fixtures=True,
            only_future_runtime_entry_body_return_journal_can_claim_original_release_execution=True),
        next_observer_requirements=[
            'New source only. No old39CFG/table/proof changes. Execute supported original3CC57C head/24byte backend constructor with exact instance/outercaller context; intercept3CC58A native zero initializer instead of inherited noop.',
            'Audit actualexit list before any initialization. Initialize verified empty new inventory once; preserve any existing standard/listener chain. Never reset a nonempty list.',
            'Actual heap cold ctor needs guarded descriptor/buffer. Preserve original388BCC six nativezero stores/388BD2 tagstore and two3CC5C2 registrations; do not seedtag or synthesizeinitreturn.',
            'Add exact heap/list rawentry+caller+pointer+tag/class/live24 gates and use actual-running-task pending epilog/owner synchronization. Keep failure388EB4 as originalfatal-boundary path, not a recovery status.',
            'Support1C0618/1C0634 only with exactoriginal currentTCB+56 provenance/nativebuilder inventory and real nativebody; separate from stacklocal join1C0640.',
            'Capture workspace96/prefix/listnodes/sem states and exactoriginal CPUwriters in new guard scope; zeroextent cold NULL path must not be whitelisted as success.',
            'Keep retained Timer dual-token chain, ALL/ready/context/pending/native owned inventory and whole initialized-data journal. Do not claim fullheapallocator, taskexit, safeunload or hardware behavior.'],
        static_only=True,new_guest_execution=False,device_io=False,sounds_emitted=False,
        frozen_source_or_proof_modified=False,canonical_or_report_modified=False,
        assertions_passed=True,full_kernel_or_allocator_or_original_hardware_boot=False)
    STAGE.mkdir(parents=True,exist_ok=True)
    with OUTPUT.open('x') as stream:stream.write(json.dumps(payload,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(dict(output=str(OUTPUT.relative_to(ROOT)),sha256=sha(OUTPUT),
        source_sha256=sha(Path(__file__).resolve()),local_CFG_count=len(functions),
        heap_raw_call_count=len(heap_calls),list_raw_instance_call_count=len(listener_calls))))


if __name__=='__main__':main()
