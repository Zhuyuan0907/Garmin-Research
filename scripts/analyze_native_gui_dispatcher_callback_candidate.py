#!/usr/bin/env python3
"""Read-only continuation/callback/manager preflight after preserved run3875.

No emulator/loader, hardware/service I/O, guest mutations or old proof writes.
"""
from datetime import datetime, timezone
from pathlib import Path
import hashlib
import json
import struct

from analyze_native_sections import ROOT, NativeImage, EXPECTED
from analyze_native_gui_worker_boot import FileBackedRuntimeImage
from analyze_native_gui_foreground_boot import cfg, extract


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    stock=NativeImage()
    image=FileBackedRuntimeImage(stock)
    proof_path=ROOT/'evidence/firmware-analysis/native-task-runtime-full-emulation.json'
    development_path=ROOT/'staging/native-player-task-runtime-full/post-guard-background-development-probe.json'
    foreground_path=ROOT/'staging/native-player-task-runtime-full/gui-foreground-boot-preflight.json'
    proof=json.loads(proof_path.read_text())
    development=json.loads(development_path.read_text())
    foreground=json.loads(foreground_path.read_text())
    assert proof['MAIN_sha256']==EXPECTED and proof['all_passed'] and proof['case_count']==3
    assert proof['full_scoped_nonmutating_memory_and_native_inventory_guards_passed']
    assert development['prior_complete_proof_sha256']==sha(proof_path)
    assert development['idle_sentinel_reached'] and not development['original_controller_wait_returned']
    assert not development['full_scoped_background_final_guards_passed']
    assert not development['invalid_accesses'] and not development['native_fatal_entries']
    assert development['pending_mutex_operations']=={}
    verified=[]
    for path,expected in proof['source_sha256'].items():
        assert sha(ROOT/path)==expected,path
        verified.append(dict(path=path,sha256=expected))
    for path,expected in foreground['source_sha256'].items():
        assert sha(ROOT/path)==expected,path
    assert sha(ROOT/proof['build_manifest'])==proof['build_manifest_sha256']
    assert development['source_sha256_before_run']==sha(ROOT/'scripts/emulate_native_task_runtime_full.py')
    inventory=development['current_native_inventory']
    assert inventory['ready']==['0x9508f90']
    by_tcb={int(t['TCB'],16):t for t in inventory['tasks']}
    controller,dispatcher,thread,timer,idle=(0x9503f90,0x8804fb8,0x88092b0,0x2d227c8,0x9508f90)
    assert set(by_tcb)=={controller,dispatcher,thread,timer,idle}
    parsed={}
    for tcb,task in by_tcb.items():
        raw=bytes.fromhex(task['raw108_hex'])
        assert len(raw)==108
        words=struct.unpack('<27I',raw)
        assert task['base_priority']==raw[16] and task['effective_priority']==raw[17]
        assert task['state']==raw[22] and task['context_format']==raw[23]
        assert task['saved_frame']==hex(words[3]) and task['owned_mutex_head']==hex(words[8])
        parsed[tcb]=dict(TCB=hex(tcb),raw108_hex=raw.hex(),mailbox=hex(words[1]),
                        queue_buffer=hex(words[2]),read_index=raw[18],slots=raw[19],
                        message_width=raw[20],write_index=raw[21],state=raw[22],
                        flags=hex(words[6]),saved_frame=task['saved_frame'],
                        saved_frame13_words=task['saved_frame13_words'],
                        owned_mutex_head=task['owned_mutex_head'])
    assert parsed[controller]['saved_frame13_words'][1]=='0x2fd0ac'
    assert parsed[controller]['saved_frame13_words'][11:]==['0x9503f88','0x10001']
    assert parsed[dispatcher]['saved_frame13_words'][1]=='0x2fd0ac'
    assert parsed[dispatcher]['saved_frame13_words'][11:]==['0x8804f90','0x5d21a9']
    assert parsed[thread]['saved_frame13_words'][1]=='0x353c64'
    assert parsed[dispatcher]['mailbox']=='0x0' and parsed[dispatcher]['read_index']==parsed[dispatcher]['write_index']==0
    assert parsed[dispatcher]['queue_buffer']=='0x8805024' and parsed[dispatcher]['message_width']==8
    assert parsed[dispatcher]['slots']==20 and parsed[dispatcher]['flags']=='0x5ed1a247'
    assert all(parsed[t]['owned_mutex_head']=='0x0' for t in [controller,dispatcher,thread,idle])
    assert parsed[timer]['owned_mutex_head']=='0x8805290'
    ranges=[
        (0x351be2,[(0x351be2,0x351bf2)]),
        (0x5a5924,[(0x5a5924,0x5a5990)]),
        (0x5e6182,[(0x5e6182,0x5e6290)]),
        (0x5d28de,[(0x5d28de,0x5d28e8)]),
        (0x393a2c,[(0x393a2c,0x393a58)]),
        (0x392de4,[(0x392de4,0x39303a)]),
        (0x38d4be,[(0x38d4be,0x38d858),(0x38d890,0x38da8a)]),
        (0x38d456,[(0x38d456,0x38d480)]),
        (0x38d480,[(0x38d480,0x38d4be)]),
        (0x38cd94,[(0x38cd94,0x38cdac)]),
        (0x38cd78,[(0x38cd78,0x38cd94)]),
        (0x38ccd8,[(0x38ccd8,0x38cd78)]),
        (0x38cdc6,[(0x38cdc6,0x38ce04)]),
        (0x4cecb8,[(0x4cecb8,0x4cecc0)]),
        (0x4d4560,[(0x4d4560,0x4d4564)]),
        (0x5d2942,[(0x5d2942,0x5d2982)]),
    ]
    functions={hex(a):cfg(image,a,segments) for a,segments in ranges}
    functions['0x4d4564']=cfg(image,0x4d4564,[(0x4d4564,0x4d457c)],
        external_tails={0x4d457a:0x5d2942})
    functions['0x4d4564']['external_tail_resolution_is_conditional_on_exact_holder_pair']=['0x5d2943','0x0']
    functions['0x2fd034']=cfg(image,0x2fd034,[(0x2fd034,0x2fd03a),(0x2fd03c,0x2fd0d4)],
        {0x2fd038:(0x2fd03c,'ARM'),0x2fd04c:(0x2fd050,'Thumb'),
         0x2fd06a:(0x2fd06c,'ARM'),0x2fd0a4:(0x2fd0a8,'Thumb'),
         0x2fd0c2:(0x2fd0c4,'ARM'),0x2fd0cc:(0x2fd0d0,'Thumb')})
    functions['normal_post_core_after_ARM_entry']=cfg(image,0x2fcf6c,
        [(0x2fcf6c,0x2fcfae),(0x2fcfb0,0x2fd02c)],
        {0x2fcfac:(0x2fcfb0,'ARM'),0x2fcfe8:(0x2fcfec,'Thumb'),
         0x2fd01a:(0x2fd01c,'ARM'),0x2fd024:(0x2fd028,'Thumb')})
    rows={int(r['address'],16):r for f in functions.values() for r in f['instructions']}
    for pc,target in {0x393a40:0x392de4,0x392dee:0x38d4be,0x38d46c:0x3008a0,
                      0x38d9d0:0x3009a0,0x38d9da:0x358d24,0x38da0e:0x3008b0,
                      0x38da80:0x38cd94,0x38cda0:0x38cd78,0x38cd8c:0x38ccd8,
                      0x38cdf6:0x20bbb8,0x39300a:0x377ab8,0x5e61e8:0x3954e4}.items():
        assert rows[pc]['direct_call']==hex(target),hex(pc)
    assert rows[0x38d46a]['literal_value']=='0x34f9b28'
    assert rows[0x38d496]['literal_value']=='0x34f9b40'
    assert rows[0x351bee]['instruction']=='movs r0, r4'
    assert rows[0x2fd0b0]['instruction']=='ldr r0, [r2, #4]'
    assert rows[0x2fd0bc]['instruction']=='str r3, [r2, #4]'
    assert rows[0x392fd2]['instruction']=='str r0, [r7, #8]'
    assert rows[0x392fd8]['instruction']=='str r0, [r7, #0xc]'
    assert struct.unpack('<4I',image.read(0xc1b56c,16))==(0,0x4cecb9,0x4d4561,0x4d4565)
    assert struct.unpack('<2I',image.read(0x9dd99c,8))==(0x5d2943,0)
    assert rows[0x4d4560]['instruction']=='ldr r0, [r0, #4]'
    assert rows[0x4d4568]['instruction']=='asrs r3, r1, #1'
    assert rows[0x4d456c]['instruction']=='lsls r3, r1, #0x1f'
    assert rows[0x4d457a]['instruction']=='bx r1'
    assert rows[0x5d2954]['instruction']=='beq #0x5d297e'
    dependencies=[Path(__file__).resolve(),ROOT/'scripts/analyze_native_gui_foreground_boot.py',
                  ROOT/'scripts/analyze_native_gui_worker_boot.py',ROOT/'scripts/analyze_native_sections.py',
                  ROOT/'evidence/firmware-analysis/main_02bd.bin',proof_path,development_path,foreground_path,
                  ROOT/'scripts/probe_native_mainmenu_controller_bootstrap.py',
                  ROOT/'scripts/probe_native_mainmenu_controller.py']
    output=dict(updated_utc=datetime.now(timezone.utc).isoformat(),MAIN_sha256=EXPECTED,
        exact_target=dict(HWID=1352,software='8.00'),
        source_sha256={str(p.relative_to(ROOT)):sha(p) for p in dependencies},
        preserved_run3875_scope=dict(proof=str(proof_path.relative_to(ROOT)),proof_sha256=sha(proof_path),
            successful_pre_background_guard_groups=3,exact_frozen_dependencies_verified=len(verified),
            verified_frozen_dependency_hashes=verified,
            development_probe=str(development_path.relative_to(ROOT)),development_probe_sha256=sha(development_path),
            original_controller_WAIT_returned=False,idle_endpoint_reached=True,
            old_background_mutex_pending_empty=True,post_background_full_final_guards_passed=False,
            captures_are_preserved_emulator_observations_not_device_reads=True),
        preserved_native_task_inventory=[parsed[t] for t in [controller,dispatcher,thread,timer,idle]],
        complete_bounded_new_local_CFG_count=len(functions),mixed_mode_local_CFG_count=2,
        functions=functions,
        controller_resume_candidate=dict(
            call='Original ARM2FCF44(r0=controller9503F90,r1=event1) from actual idle9508F90 stack',
            explicit_input_fixture='Native event stimulus only; this is not an original firmware boot caller or hardware IRQ claim.',
            current_before=dict(running_task='0x9508f90',ready_head='0x9508f90',controller_state=2),
            target_saved_frame='0x9503f54',target_saved_PC='0x2fd0ac',entry_mode='Thumb via original restored CPSR',
            expected_WAIT_return='2FD0AC reloads original currentTCB;2FD0B0 returns mailbox1;TCB+8==0 so2FD0BC clears mailbox;2FD0D2 BXLR10001.',
            required_endpoint=dict(original_restore_destination_reached='0x2fd0ac',running_task='0x9503f90',
                                   ready_head='0x9503f90',SP='0x9503f90',PC='0x10000',WAIT_return_r0=1),
            native_preemption_saves_idle_POST_resume_PC='0x2fd016',
            idle_POST_call_can_remain_suspended_after_controller_WAIT_returns=True,
            do_not_infer_idle_POST_return_from_same_host_sentinel=True,
            do_not_overwrite_idle_saved_POST_stack_or_free_it=True,
            original_ARM_entry_slice=extract(image,0x2fcf44,0x2fcf6c,'ARM'),
            alternate_IRQ_marker_branch_at2FCE38_not_exercised_or_claimed=True),
        registration_and_call_return=dict(
            original_register='4B571D(r0=8800984=S=D+464,r1=405341)',
            new_holder='4B5758 native allocate8 bytes;4B5762 vtableC1B584;4B5760 holder+4=405341',
            holder_allocation_NULL_unchecked='4B5760 writes[NULL+4] if original allocator returnsNULL.',
            empty_signal_vector_growth='Original5E6182 grows capacity0 to2 pointers:3954E4(r0=8,r1=0),placement3819D4 copies holder pointer.',
            vector_metadata='S+4 begin,S+8 end,S+C capacity_end;after empty insertion begin=V,end=V+4,capacity_end=V+8.',
            pending_removal_vector='S+10/S+14/S+18;5A5924 reap/erase executes before register and before emission.',
            registration_return_r0='351BE2 returns its guard address;4B571C leaves r0=entrySP-0x18 after epilogue. It is not a success status or retained callback object.',
            registration_success_requires=['S originalvtableC1B59C, aligned valid original vector ranges and bounded inventories.',
                                           'Known allocated holder has originalvtableC1B584 and function405341.',
                                           'Exactly one matching function in original vector; duplicate registration must leave one.',
                                           'NonNULL original holder and vector allocation, with original storage/canaries intact.'],
            publication='5D28FF(D,S): stack-local [S,0] atentrySP-0xC copied by original37BCE4 to owned queue storage; no borrowed stack-record lifetime.',
            publication_return_r0='No defined errno/status; verify actual queue bytes/index/native post rather than a guessed return value.',
            queue_before='Preserved3875 has read=write=0,queuebuffer8805024,width8,slots20,mailbox0.',
            one_message_expected=dict(raw_hex=struct.pack('<2I',0x8800984,0).hex(),read_index=0,write_index=1,event=2),
            queue_no_malloc_in_original37BCE4=True,
            queue_flags5_bypass_capacity_mutex=True,
            full_queue_or_parallel_producer_safety_not_claimed=True,
            queue_record_has_raw_S_pointer_and_no_refcount=True,
            retain_D_S_adapters_vector_module_until_callbacks_and_pending_scopes_complete=True,
            unregister_or_destroy_signal_is_not_safe_while_queue_or_callback_is_inflight=True),
        original_member_holder_and_runtime_inventory_erratum=dict(
            original_registration='Ctor5D2684 selectsS=D+464;5D2688 loadsreadonlypair9DD99C;5D26C6 alloc16;5D26CE/+D2/+D4/+D6 storememberholder.',
            expected_original_holder_words=['0xc1b56c','D','0x5d2943','0x0'],
            vtable_words=['0x0','0x4cecb9','0x4d4561','0x4d4565'],
            original_holder_is_member_callback_not_free_function=True,
            getter='4D4560 returns holder+4=thisD, used for original member target matching.',
            invoke='4D4564 reads holder+C;ASR1 adjusts this;bit0 chooses virtual dispatch;holder+8 isfunction orvirtualoffset;BXresolvedfunction withr0=adjustedthis.',
            exact_readonly_pair='9DD99C=5D2943,9DD9A0=0 => direct Thumb5D2942(r0=D),zero this adjustment.',
            member_callback='5D2942 checks D+4BA4 at5D294C; ifNULL5D2954 branches5D297E and originalreturns5D2980.',
            constructor_null_store='Ctor5D2682 original STRr5,[D+4B80+24] initializesD+4BA4=NULL.',
            constructor_store_is_not_latest_runtime_RAM_observation=True,
            required_current_null_observation='Record currentword(D+4BA4) before queue or original5D294C loadedr0;zero permits exact bounded no-op path.',
            if_nonnull='5D295A calls objectvtable+4;5D295E clearsD+4BA4;5D2974 appendsD toS+10 pending-removalvector under recursiveguard. Calleeobject/preconditions require separate evidence.',
            source_error='Root SignalVM.signal_inventory labels holder+4 ascallback for all vtables. ForC1B56C this isobjectD;actual encodedfunction5D2943 lives+8,adjustmentword0 lives+C.',
            metadata_semantics_correction_does_not_patch_guest_or_replace_existing_holder=True,
            retain_every_existing_original_holder_pointer_vtable_and_full_member16bytes=True,
            free_function_target_check='C1B584 holder+4=405341 iscorrect;dedupmustbequalifiedbyvtableC1B584.',
            old_empty_vector_growth_description_is_conditional_not_constructor_runtime_claim=True,
            static_ctor_registration_slice=extract(image,0x5d2680,0x5d2718),
            original_member_pair_bytes_hex=image.read(0x9dd99c,8).hex(),
            original_member_vtable_bytes_hex=image.read(0xc1b56c,16).hex()),
        callback_entry_boundary=dict(
            native_chain=foreground['most_direct_next_input']['native_callback_chain'],
            expected_current_TCB='0x8804fb8',expected_dispatcher_working_SP='0x8804f98',
            expected_entry_SP='0x8804f78',expected_entry_LR='0x60935d',
            expected_entry_r0='0x405341 (original adapter BX target;no argument used by405340)',
            body405340_not_executed_in_entry_only_candidate=True,
            active_native_mutexes=[dict(pointer='0x880100c',expression='D+AEC',owner='0x8804fb8',count=1,
                                       guard='DispatcherD+AE8 scopedguard atworkerSP+8'),
                                  dict(pointer='0x88009bc',expression='S+38 = recursiveCpp(S+1C)+28',
                                       owner='0x8804fb8',count=2,
                                       guards=['52353C outerguardSP8804F88','609338 innerguardSP8804F78'])],
            active_guards_must_not_be_counter_cleared_or_treated_as_completed_cleanup=True,
            full_callback_return_endpoint_requires='Original405340 returns60935C;inner351BE2 releases one recursion,outer351BE2 releases remaining recursion,worker351BE2 releasesD+AEC,then originalworker wait may block.',
            stopping_at_entry_is_distinct_from_original_callback_return_foreground_or_quiescence=True),
        next_controller_body_prerequisites=dict(
            status='Source-grounded preparation candidates only; not observed inrun3875 or executed here.',
            source_entry='scripts/probe_native_mainmenu_controller_bootstrap.py lines29-35',
            known_original_preparation=['2CBD16 settings initialization;2CA82C writes actuallower record19B=1 for the fixture.',
                                       '395980 widget initialization;2DB540 native display-list initialization.',
                                       'register_stock_GIR() places the exact original GUI resource mapping through the priorharness.',
                                       '4DF248 plus4DE236(1) original external-font preparation under priorfilesystem input.',
                                       '4A388A original signal initialization;priorSQLite fixture cell12=PLAYER_ID.'],
            these_source_preconditions_do_not_mean_installed_or_live_init=True,
            frozen_ctor_resource_and_virtual_clock_scopes_still_apply=True,
            no_new_fake_clock_settings_thread_identity_or_synthetic_foreground_return_supplied=True),
        manager_cold_init_and_root0=dict(
            cache_word='0xF2CD0C',cold_path='393A2C ->allocateE50 ->392DE4 ->38D4BE ->publishF2CD0C after ctor',
            existing_manager_skips_cold_ctor=True,
            native_registry_mutex=dict(getter='0x38d456',onceword='0xf2cbf4',mutex='0x34f9b28',
                                      initializer='0x38d46c ->3008A0',tag_address='0x38d860',
                                      acquire_call='0x38d9d0',acquire_return_caller='0x38d9d4',
                                      release_call='0x38da0e',release_return_caller='0x38da12'),
            native_task_registry=dict(getter='0x38d480',onceword='0xf2cbf8',vector='0x34f9b40',
                                      current_query='38D9DA ->358D24',append='3819D4 or20DB44 under originalregistrymutex'),
            registration_of_current_TCB_does_not_prove_public_UI_thread_API=True,
            geometry=dict(ten_category_records='M+D8,stride16',
                          default_normalized_float_words=['0x0','0x0','0x3f800000','0x3f800000'],
                          initialization='38DA80 ->38CD94 loops10 ->38CD78 ->38CCD8 copies normalizedrectangle',
                          retrieval='38CDC6 ->3777AA getsMframe;20BBB8 applies normalizedrect to create actualframe',
                          category0_record_is_not_four_pixel_coordinates=True,
                          derived_display_dimensions='392FD2 setsF2CD10=480;392FD8 setsF2CD14=272',
                          derived_display='392FE4 ctor2DB594 storedM+44;392FEE2DB716 dimensions;39300A377AB8 nativeMframe'),
            root0_chain=foreground['controller_root_and_foreground']['original_sync_transition_chain'],
            no_required_GUI_main_actor_in_this_statically_sync_root0_chain_claimed=True,
            GUI_main_F0B550_internal_queue_is_separate_dependency_for_later_callback_and_input_processing=True,
            actual_manager_Page_frames_visibility_and_transition_callbacks_need_new_runtime=True),
        assertions_passed=True,new_emulation_executed=False,device_io=False,sounds_emitted=False,
        frozen_source_or_proof_modified=False,firmware_modified=False,install_candidate=False,
        limits='Static original byte/literal/CFG analysis and readonly crosscheck of preserved3875 proof/development snapshots. Only prior3 guard groups are full proofs; later idlebackground snapshot lacks finalfullguards. Proposednative wake/register/queue/callback-entry/body/manager paths have not executed here. Existing32 CFG artifact is referenced unchanged. No newrootforeground, touch/display, hardwareIRQ clock, physicalApp/directphoneaudio, safe task/adapter/module cleanup or accepted package is established.')
    path=ROOT/'staging/native-player-task-runtime-full/dispatcher-mainmenu-callback-static-preflight.json'
    assert not path.exists(),'New evidence exists; do not overwrite'
    path.write_text(json.dumps(output,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(dict(output=str(path.relative_to(ROOT)),sha256=sha(path),source_sha256=sha(Path(__file__).resolve()),
                         complete_bounded_new_local_CFGs=len(functions),verified_frozen_dependencies=len(verified))))


if __name__=='__main__':
    main()
