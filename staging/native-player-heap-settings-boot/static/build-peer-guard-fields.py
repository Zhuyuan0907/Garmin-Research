#!/usr/bin/env python3
"""Exclusive backup-only peer field assertions; no guest execution or VM."""
from pathlib import Path
from datetime import datetime, timezone
import hashlib
import json
import struct
import sys

ROOT=Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT/'scripts'))
from analyze_native_sections import NativeImage, EXPECTED
from analyze_native_gui_worker_boot import FileBackedRuntimeImage


def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    out=Path(__file__).with_name('peer-heap-settings-guard-fields.json')
    assert not out.exists(),'Preserve unique evidence'
    heap_path=ROOT/'staging/native-player-mainmenu-native-prep/heap-static/mainmenu-native-heap-mutex-preflight.json'
    settings_path=ROOT/'staging/native-player-mainmenu-native-prep/mutex-static/mainmenu-native-settings-mutex-preflight.json'
    kernel_path=ROOT/'staging/native-player-task-mutex/task-mutex-static-preflight.json'
    terminal_path=ROOT/'staging/native-player-mainmenu-native-prep/journal-runtime/settings-native-prep-terminal-probe.json'
    assert sha(heap_path)=='3fa1f71ecc3d8454de931ad8637631f7d1e732ea4e261b6dfa158f7990df37bb'
    assert sha(settings_path)=='a2a6b1f38f4b6903f25c142a834dadc04e653b82c6c8fbc0dbb77f1a166ba377'
    heap=json.loads(heap_path.read_text());settings=json.loads(settings_path.read_text())
    kernel=json.loads(kernel_path.read_text());terminal=json.loads(terminal_path.read_text())
    image=FileBackedRuntimeImage(NativeImage())
    assert all(p['MAIN_sha256']==EXPECTED for p in [heap,settings,kernel,terminal])
    verified={}
    for p in [heap,settings,kernel]:
        for name,expected in p['source_sha256'].items():
            assert sha(ROOT/name)==expected,name
            assert name not in verified or verified[name]==expected,name
            verified[name]=expected
    rows={int(r['address'],16):r for f in heap['functions'].values() for r in f['instructions']}
    expected_stores={0x388ba0:'str r4, [r5, #0x18]',0x388bc6:'str r7, [r0]',
        0x388bc8:'str r4, [r0, #0x78]',0x388bd2:'str r0, [r5, #0x2c]',
        0x388c2c:'str r2, [r1, #0x50]',0x388c3c:'str r2, [r1, #0x54]',
        0x388c6c:'str r0, [r2, #0x54]',0x388c74:'str r0, [r2, #0x58]',
        0x388c7c:'str r3, [r0]',0x388c7e:'str r0, [r2, #4]',0x388c80:'str r1, [r0, #4]'}
    assert all(rows[a]['instruction']==s for a,s in expected_stores.items())
    assert len(heap['raw_mutex_calls'])==11 and len(heap['listener_mutex_calls'])==12
    assert len({(r['entry'],r['continuation']) for r in heap['raw_mutex_calls']})==11
    assert all(r['pointer']=='0x3a7f18c' and r['tag']=='0x388d00' and r['classification_byte']==0
               for r in heap['raw_mutex_calls'])
    assert all(r['pointer'] in ['0x2d226b8','0x148e684'] and r['tag']=='0x3cc660'
               for r in heap['listener_mutex_calls'])
    workspace_offsets={4:'B+0x1000',0x18:'B',0x2c:'0x388d00',0x50:8192,0x54:4096,0x58:4096}
    B=0x10000000
    workspace=bytearray(96)
    for offset,value in [(4,B+4096),(0x18,B),(0x2c,0x388d00),(0x50,8192),(0x54,4096),(0x58,4096)]:
        struct.pack_into('<I',workspace,offset,value)
    prefix=bytearray(4096);struct.pack_into('<I',prefix,0,27);struct.pack_into('<I',prefix,0x78,B+0x7c)
    fullrelease={int(r['address'],16):r['instruction'] for r in kernel['functions']['0x300bb8']['instructions']}
    assert fullrelease[0x300bbe]=='str r2, [r0, #8]' and fullrelease[0x300bc0]=='strh r2, [r0, #0x14]'
    assert fullrelease[0x300bc6]=='str r2, [r1]'
    backgrounds=[]
    for task in terminal['native_inventory']['tasks']:
        if task['TCB']=='0x9503f90':continue
        words=task['saved_frame13_words']
        backgrounds.append(dict(TCB=task['TCB'],state=task['state'],base_priority=task['base_priority'],
            effective_priority=task['effective_priority'],context_format=task['context_format'],
            saved_frame=task['saved_frame'],saved_PC=words[1],saved_SP=words[11],saved_LR=words[12],
            raw13_words=words,source='preserved20581 endpoint, not a newruntime snapshot'))
    core_shapes={}
    for r in heap['listener_mutex_calls']:
        core_shapes.setdefault(r['containing_function'],[]).append(r)
    dependencies=[Path(__file__).resolve(),heap_path,settings_path,kernel_path,terminal_path,
        ROOT/'scripts/probe_native_task_mutex.py',ROOT/'scripts/probe_native_dispatcher_condition.py',
        ROOT/'scripts/probe_native_heap_callback.py',ROOT/'scripts/emulate_native_task_runtime_full.py',
        ROOT/'scripts/emulate_native_independent_signal.py',ROOT/'scripts/analyze_native_sections.py',
        ROOT/'scripts/analyze_native_gui_worker_boot.py',ROOT/'evidence/firmware-analysis/main_02bd.bin']
    candidate=ROOT/'scripts/probe_native_heap_settings_boot.py'
    payload=dict(updated_utc=datetime.now(timezone.utc).isoformat(),MAIN_sha256=EXPECTED,
        source_sha256={str(p.relative_to(ROOT)):sha(p) for p in dependencies},
        verified_frozen_dependency_hashes=verified,
        candidate_source_present_at_static_review=candidate.exists(),
        candidate_source_sha256_at_static_review=sha(candidate) if candidate.exists() else None,
        candidate_runtime_not_executed_or_claimed_by_peer=True,
        field_assertions=dict(one_extent_input=dict(r0='live8byte[pagealignedB,8192] descriptor',r1=1,r2=0,r3=0,
            B_page_aligned=True,B_and_descriptor_storage_retained=True,zero_workspace_before_cold_ctor=True),
            original_cold_metadata=dict(workspace='0x3a7f170',workspace_bytes=96,header_parameter=27,
                header_unaligned_bytes='0xdfc',header_reserved_bytes=4096,
                cold_metadata_field18_becomes_B=True,
                native_store_PCs={hex(a):s for a,s in expected_stores.items()},
                prefix_exact_bytes_recipe='zeros4096;word+0=27;word+78=B+7C',
                symbolic_example_B=hex(B),symbolic_example_prefix_sha256=hashlib.sha256(prefix).hexdigest(),
                second_page_only_native_free_header8byte_stores_required=True,
                second_page_recipe='preserve originalbefore4096 exceptwords+0=0,+4=4096',
                workspace_nonzero_word_offsets={hex(k):v for k,v in workspace_offsets.items()},
                all_other_workspace_words_zero_at_ctor_return_before_heap_queries=True,
                symbolic_example_workspace_raw96_hex=workspace.hex(),
                requires_388B24_original_memzero_and_no_old_heap_inventory=True,
                later_settings_heap_mutex_queries_change_workspace_sem_stale_fields_legitimately=True,
                final_workspace_guard_must_replay_actual_CPU_writes_not_reuse_ctor_zero_baseline=True,
                full_buffer_and_canary_recipe='Compare whole8192 againstbefore plusnative clear/header stores;front/backcanaries unchanged.'),
            exact_initializers=[dict(entry='0x3008a0',continuation='0x388bd0',pointer='0x3a7f18c',tag='0x388d00',
                native_outer_ctor='0x388b6c',original_retag_store='0x388bd2',classification_byte=0),
                dict(entry='0x3008a0',continuation='0x3cc58a',pointer='0x2d226b8',tag='0x3cc660',
                    listhead='0x2d226b4',native_outer_ctor='0x3cc57c',original_retag_store='0x3cc58c',classification_byte=0),
                dict(entry='0x3008a0',continuation='0x3cc58a',pointer='0x148e684',tag='0x3cc660',
                    listhead='0x148e680',native_outer_call='0x2cbd8a',outer_return='0x2cbd8e',
                    native_outer_ctor='0x3cc57c',original_retag_store='0x3cc58c',classification_byte=0)],
            initializer_journal='active_backend exactpointer/caller/live24; originalsixzero writes; native3008AE completion; originalretag afterreturn, nohosttag/ret0.',
            outer_list_context_guard='Caller3CC58A is shared: bind to observedactive3CC57C argument/head. Settings outer2CBD8A uses148E680. Exit initialization is anexplicitnewAPI onactualcontroller afterinventory, not recoveredboot.',
            original_heap_raw_calls=heap['raw_mutex_calls'],original_generic_list_raw_calls=heap['listener_mutex_calls'],
            current_TCB_internal_sem_calls=heap['internal_current_TCB_mutex_calls']),
        exit_list_guard=dict(head='0x2d226b4',backend='0x2d226b8',native_tag='0x3cc660',
            before_snapshot_bytes=28,node_bytes=16,max_nodes=1024,acyclic_unique_live_nodes=True,
            initialize_once_only_for_verified_empty_uninitialized_inventory=True,
            preserve_nonempty_head_and_all_old_nodes_not_reset=True,
            empty_initialized_list_reinitialization_not_needed_and_must_not_hide_initializer_evidence=True,
            node_offsets=heap['heap_exit_listeners']['node_offsets'],
            two_new_nodes=heap['heap_exit_listeners']['constructor_registrations'],
            empty_old_chain_expected_order=['0x3a7f150','0x3a7f160'],
            standard_old_chain_expected_order=['0x3a7f150','0x2d226d0','0x3a7f160'],
            arbitrary_old_chain_recipe='Signedstable insertorders01000000/03000000;oldorder/callback/arg remainidentical. Oldnext changesonlywhereoriginal3CC612 linksnewnode.',
            expected_node_arguments=0,two_actual_original_registration_returns0_required=True,
            original_ctor_does_not_check_registration_return_but_peer_guard_must=True,
            all_nodes_remain_live_no_exit_or_safe_cleanup_claim=True),
        settings_list_guard=dict(head='0x148e680',backend='0x148e684',bytes=28,
            constructor_head_store='0x3cc582',constructor_native_init='0x3cc586',tag_store='0x3cc58c',
            onlysettingsmodulelistctor_recovered=True,
            no3CC5C2_or3CC594_or3CC624_in_settings39_function_directclosure=True,
            final_expected_head0_if_no_external_callback_registered_or_notified=True,
            final_backend_after_unused_ctor='[0,0,0,0,3CC660,0]',
            no_reset_prior_nonempty_settings_list_whenreentering2CBD16=True),
        released_semantics=dict(no_waiter_unlock_original_stores=['3008F2 owner=0','3008F8 *prev=next','3008FE successor.prev=prev ifnextnonzero'],
            fullrelease_original_clears=['300BBE owner=0','300BC0 recursionu16=0'],
            released_gate=dict(owner=0,waiter_head=0,recursion_u16=0),
            owned_next_and_previous_link_not_zeroed_by_native_unlock_or_fullrelease=True,
            no_requirement_unowned_prev_cell_still_points_back_to_sem=True,
            do_not_traverse_stale_links_from_unowned_sem=True,
            exact_raw24_guard='Compare whole24 againstlatest observedoriginalepilogue orreplayed originalCPU writes; includeclass/tag/reservedbyte. Neveraccept arbitrarylink changes byowner0 alone.',
            native_unlock_return_R0_not_bool=True),
        TCB108_and_owned_guards=dict(all_head='0xf0908c',ready_head='0xf09090',owned_head_offset=32,
            all_next_offset=40,all_previous_cell_offset=44,TCB_bytes=108,internal_sems=[56,80],
            every_TCB_live_unfreed_builder_observed=True,ALL_ready_unique_bounded_native_order=True,
            raw108_before_after_plus_CPUwriter_diff_required=True,
            internalsem_owner_waiter_recursion0_at_completed_no_pending_endpoint=True,
            internalsem_full24_not_assumed_zero=True,
            internalsem_tag='originalTCBmetadata[0] ifmetadata!=0 else0;preservedmetadata andclass0',
            observed_controller_internal56_use='1C0600 deriveswordF09090+38;owner==selectedTCB returns0 withoutacquire,else original3009A0 returnsandhelperreturns1. Onlynonzerohelperresult requires1C0624 originalunlock.',
            no_return0_replacement_or_stacklocal_join_substitution=True,
            normal_helper_entry_requires_actualrunningtask_equals_readyselected=True,
            owned_chain_recipe='FromeachTCB+32:registeredlive24,ownerTCB,prev==previouslinkcell,*prev==sem,nextcyclefree,next.prev==sem;class/tag/depth andwaiter linkschecked. Eachownedsem exactlyonce acrossallchains.',
            all_sem_owner_nonzero_matches_exact_owned_chain_membership=True,
            ordinary_counter_equals1_plus_recursion_for_owned_nonretained=True,
            retained_Timer_tokens_excluded_from_ordinary_counter=True,
            final_after_settings_owned_heads=dict(controller=0,Dispatcher=0,Thread=0,idle=0,Timer='0x148e8ec'),
            retained_Timer_chain=['0x148e8ec','0x8805290'],
            token_links=dict(settings_next='0x8805290',settings_prev='TimerTCB+32',GUI_next=0,GUI_prev='0x148e8ec'),
            all_task_pending_mutex_wait_fullrelease_lowerwait_notify_ctor_scopes_empty_at_return=True),
        resident_background_guards=dict(reproduced_20581_reference_rows=backgrounds,
            compare_whole13_frames_and_whole_raw108_except_logged_native_deltas=True,
            Thread20byte_node=dict(pointer='0x8809264',head_F0909C_samepointer=True,next=0,target='0x88092b0',
                deadline=1,type_byte_offset=12,type_byte_value=2,parameter_word_offset=16,
                type_word_padding_and_parameter_observed_not_guessed=True,virtual_clock=0,
                exact_before_after_raw20_unchanged_while_no_native_clock_advance=True),
            idle_POST_frame='0x9508f54 PC2FD016 SP9508F88 LR10001 remainslive',
            controller_current_active='ActualSP==controller9503F90 aftereachAPI;TCB+12 old9503F54 frameconsumed andmayoverwrittenbyAPI stack. Do notrequireoldcontrollerWAITframe stillresumable.',
            future_controller_WAIT='IfstartingfreshWAIT/publishstage, captureactualnewnative savedframe/PC2FD0AC;requirefreshdescriptorbacking,notoldconsumedbytes.',
            keep_GUI_FF_leading64_synthetic_A5_leading64_timer_A5_leading24_guards=True,
            CPSR_mode_and_format_must_be_actualobserved_not_arbitrary_lowbyteBF=True,
            no_task_exit_timerIRQ_or_safeunload_claim=True),
        strict_scope=dict(one_extent_metadata_and_list_native_bodies_are_requested_next_runtime=True,
            lower_opaque_handles_and_translation_remain_explicitfixtures=True,
            native388804_query_is_not_payloadpin=True,native388B22_is_BXLR_notheapunlock=True,
            native3887A2_388746_388676_release_requires_actual_entry_body_return_observation=True,
            no_new_runtime_emulator_or_device_execution=True,no_frozen_source_proof_or_canonical_changes=True),
        assertions_passed=True)
    with out.open('x') as stream:stream.write(json.dumps(payload,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(dict(output=str(out.relative_to(ROOT)),sha256=sha(out),source_sha256=sha(Path(__file__).resolve()),
        verified_prior_source_hashes=len(verified))))


if __name__=='__main__':main()
