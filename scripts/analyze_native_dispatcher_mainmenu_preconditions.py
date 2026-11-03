#!/usr/bin/env python3
"""Exact static placement/ABI note before native Dispatcher MainMenu body.

Reads immutable firmware/proofs only; never starts a VM or hardware service.
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
    image=FileBackedRuntimeImage(NativeImage())
    stage=ROOT/'staging/native-player-independent-signal'
    out=stage/'mainmenu-controller-prerequisites-static.json'
    assert not out.exists(),'Do not overwrite completed evidence'
    signal_path=ROOT/'evidence/firmware-analysis/native-independent-signal-emulation.json'
    ctor_path=ROOT/'evidence/firmware-analysis/native-mainmenu-constructor-emulation.json'
    fg_path=ROOT/'staging/native-player-task-runtime-full/gui-foreground-boot-preflight.json'
    candidate_path=ROOT/'staging/native-player-task-runtime-full/dispatcher-mainmenu-callback-static-preflight.json'
    signal=json.loads(signal_path.read_text());ctor=json.loads(ctor_path.read_text());fg=json.loads(fg_path.read_text())
    assert sha(signal_path)=='0fe4fe2314f75932e68e6768517d1830ab5d2db8bb22b4d58c5f0c83d9d85582'
    assert signal['MAIN_sha256']==EXPECTED and signal['all_passed'] and signal['case_count']==4
    assert signal['full_scoped_memory_and_native_callback_endpoint_inventory_guards_passed']
    assert not signal['original_MainMenu_callback_body_foreground_device_App_direct_music_or_safe_cleanup_verified']
    assert ctor['MAIN_sha256']==EXPECTED and ctor['all_passed']
    assert ctor['full_scoped_general_MainMenu_constructor_final_guards_passed']
    assert not ctor['general_MainMenu_controller_root_foreground_and_recreation_verified']
    verified={}
    for proof in [signal,ctor,fg,json.loads(candidate_path.read_text())]:
        for path,expected in proof['source_sha256'].items():
            assert sha(ROOT/path)==expected,path
            assert path not in verified or verified[path]==expected,path
            verified[path]=expected
    ranges=[(0x2cbd16,0x2cc2a4),(0x2ca82c,0x2caaea),(0x2cabbc,0x2cac22),(0x2ca128,0x2ca16a),
        (0x395980,0x3959c4),(0x2db540,0x2db584),(0x4df248,0x4df27a),(0x4de236,0x4de2a0),
        (0x4de0e0,0x4de236),(0x41cc46,0x41ccd8),(0x41b198,0x41b1c2),(0x11c504,0x11c514),
        (0x41b15a,0x41b198),(0x4a388a,0x4a39f6),(0x316276,0x3162f2),(0x390142,0x390184),
        (0x26de3c,0x26de72),(0x385448,0x38545a),(0x265f16,0x265fec),(0x4ddbc2,0x4ddc0c)]
    functions={hex(a):cfg(image,a,[(a,b)])for a,b in ranges}
    rows={int(r['address'],16):r for f in functions.values()for r in f['instructions']}
    calls={0x2cbd38:0x3008a0,0x2cbd44:0x3008a0,0x2cbd50:0x3008a0,0x2cbd5c:0x3008a0,
        0x2cbd6e:0x3ec540,0x2cbd7e:0x3008a0,0x41b1ae:0x3008a0,0x11c50c:0x3009a0,
        0x41ccce:0x3008b0,0x390150:0x3009a0,0x39017c:0x3008b0,
        0x2cabf6:0x3009a0,0x2cac04:0x3008b0,0x2caa74:0x2fcf44,0x2caa8e:0x2fcf44,
        0x3162b0:0x2361ae,0x3162de:0x2378ae,0x3162e4:0x2376b8}
    assert all(rows[pc]['direct_call']==hex(target)for pc,target in calls.items())
    assert rows[0x41b1ac]['literal_value']=='0x34f773c'
    assert rows[0x2cbd6c]['literal_value']=='0x148e8ec'
    assert image.word(0xf06f24)==image.word(0xf08c88)==0
    native_writers=ctor['snapshot']['original_native_writer_events']
    assert len(native_writers)==7
    expected_writers=[(0x551c7f8,1,0x385450),(0x551c80c,1,0x385450),(0x551c800,1,0x385450),
        (0x551c804,0xc035f8,0x26de42),(0x551c808,0x3aaed08,0x26de6c),
        (0x551c804,0xc0fd70,0x344e22),(0x551c7fc,1,0x385450)]
    assert [(int(r['address'],16),int(r['value'],16),int(r['PC'],16))for r in native_writers]==expected_writers
    settings_initializers=[]
    for call,pointer,tag in [(0x2cbd38,0x148e6b4,0x2cbf4c),(0x2cbd44,0x148e69c,0x2cbf5c),
        (0x2cbd50,0x148e6cc,0x2cbf6c),(0x2cbd5c,0x148e6e4,0x2cbf7c),(0x2cbd7e,0x148e920,0x2cbfa0)]:
        settings_initializers.append(dict(call=hex(call),return_caller=hex(call+4),backend=hex(pointer),bytes=24,
            tag=hex(tag),tag_ascii=image.read(tag,64).split(b'\0')[0].decode('ascii')))
    settings_locks=[]
    for call,target,pointer in [(0x2ca89c,0x3009a0,0x148e6e4),(0x2ca906,0x3008b0,0x148e6e4),
        (0x2ca90c,0x3009a0,0x148e6cc),(0x2ca912,0x3009a0,0x148e6e4),
        (0x2ca972,0x3008b0,0x148e6e4),(0x2ca978,0x3008b0,0x148e6cc),
        (0x2ca9f8,0x3009a0,0x148e69c),(0x2caabe,0x3008b0,0x148e69c),
        (0x2caac4,0x3008b0,0x148e6e4),(0x2cabf6,0x3009a0,0x148e6cc),
        (0x2cac04,0x3008b0,0x148e6cc)]:
        assert rows[call]['direct_call']==hex(target)
        settings_locks.append(dict(call=hex(call),API=hex(target),return_caller=hex(call+4),backend=hex(pointer),
                                   status='All localCFG alternatives;not all paths claimed to execute'))
    dependencies=[Path(__file__).resolve(),signal_path,ctor_path,fg_path,candidate_path,
        ROOT/'scripts/analyze_native_gui_foreground_boot.py',ROOT/'scripts/analyze_native_gui_worker_boot.py',
        ROOT/'scripts/analyze_native_sections.py',ROOT/'evidence/firmware-analysis/main_02bd.bin',
        ROOT/'scripts/probe_native_mainmenu_controller_bootstrap.py',ROOT/'scripts/probe_native_player_resources.py',
        ROOT/'scripts/emulate_native_player_menu_selection.py',ROOT/'scripts/probe_native_settings_writer.py',
        ROOT/'scripts/probe_native_task_mutex.py',ROOT/'scripts/probe_native_dispatcher_condition.py',
        ROOT/'scripts/emulate_native_task_runtime_full.py']
    payload=dict(updated_utc=datetime.now(timezone.utc).isoformat(),MAIN_sha256=EXPECTED,
        exact_target=dict(HWID=1352,software='8.00'),source_sha256={str(p.relative_to(ROOT)):sha(p)for p in dependencies},
        verified_frozen_dependency_hashes=verified,complete_bounded_new_local_CFG_count=len(functions),functions=functions,
        preserved_scopes=dict(native_signal_proof=str(signal_path.relative_to(ROOT)),native_signal_proof_sha256=sha(signal_path),
            actual_callback_entry='0x405340',actual_task='0x8804fb8',actual_SP='0x8804f78',actual_LR='0x60935d',
            signal='0x8809360',retained_signal_recursive_backend='0x8809398',resident_depth_native=1,acquisitions=2,
            retained_Dispatcher_backend='0x880100c',Dispatcher_acquisitions=1,
            GUI_condition_token='0x8805290',GUI_condition_owner='0x2d227c8',GUI_condition_tag='0x6048e8',
            four_complete_groups_and_deep_endpoint_guards_verified=True,MainMenu_body_executed=False,
            older_ctor_proof=str(ctor_path.relative_to(ROOT)),older_ctor_whole_scoped_final_guards=True,
            older_ctor_current_thread_real_kernel_root_or_foreground_proof=False),
        code_placement_note=dict(
            candidate='New unique subclass/source reproduces proven boot and native idlePOST/controllerWAITreturn;prepare onactualcontroller BEFORE constructing/publishing independentSignal.',
            frozen_endpoint_cannot_be_reused_as_controller_call_stack=True,
            do_not_call_generic_invoke_when_kernel_active=True,
            convenience_methods_with_hidden_genericinvoke=['register_stock_GIR()','set_cell()'],
            controller_call_invariant='running_task==controller9503F90,originalreadyheadF09090==controller,SPcontroller9503F90,LRRETURN10001;every completed API mustreturnactualcontroller before nextAPI.',
            initial_API_arguments_are_explicit_inputs_not_recovered_stock_boot_order=True,
            if_native_API_blocks='Retainnativeframe/stack/inputbuffer;reachdeclaredidle/actualrestoredestination. Do not begin next hostcall or replacewaitreturn/owners/ready.',
            prepared_controller_sequence=[
                dict(entry='0x2cbd17',arguments=[],purpose='Original settingscoldinit onexisting syntheticNOR geometry;captures native globals/semaphores/condition.'),
                dict(entry='0x2ca82d',arguments=['0x19b','INPUT+400=9700420',4,0],purpose='Original settings recordwrite of explicitscratchu32=1;require0 andreadbacklowerrecord.'),
                dict(entry='0x395981',arguments=[],purpose='Originalwidgetregistry initialization34F9B60.'),
                dict(entry='0x2db541',arguments=[],purpose='Originaldisplay-list initialization34A5614.'),
                dict(entry='0x25dc81',arguments=[],purpose='Originalplatformquery;match stockGIR headerword12.'),
                dict(entry='0x41cc47',arguments=['GIR=B800000','INPUT=9700020'],purpose='OriginalGIR register;require1,outputkind/catalogrecordactualfields.'),
                dict(entry='0x41b15b',arguments=[],purpose='Originalcatalogquery;inventory only,exact24-byte GIRrecord backing andreadonlyhash.'),
                dict(entry='0x4df249',arguments=[],purpose='Originalstaticfonttables init;retain lowerreadonlyfilemapping.'),
                dict(entry='0x4de237',arguments=[1],purpose='Originalexternalfontinit;require0,observefontinventory/closedfiles,parameter1 isexplicitlowerinput.'),
                dict(entry='0x4a388b',arguments=[],purpose='Originalmenu signal registration;retaincallback/subscriptionstorage.'),
                dict(entry='lowerDBfixture binding',arguments=['menu=word(F11E04+8)','DB=84C0000'],purpose='Explicit SQL-engine/DB-ready provider fixture;not originalphysicalDBbootstrap or UIlink.'),
                dict(entry='0x316277',arguments=['menu', 'PLAYER_ID',12,0],purpose='OriginalSQLcellsetter;checkselectedmemoryDBrow/statementsclosed;avoidset_cell genericinvoke.'),
                dict(entry='existing original allocator/Signal ctor/register/queue APIs',arguments=[],purpose='Then originalcontrollerWAIT executes actual405340 callback under originalDispatcherguards.')],
            scratch_writes_only='Explicitinput/outputscratchandlowerDBprovider state;neverGUIframe/tree/vtables/semaphore/context mutation.'),
        settings_native_kernel_dependencies=dict(
            initializers=settings_initializers,local_lock_and_unlock_alternatives=settings_locks,
            condition=dict(call='0x2cbd6e',return_caller='0x2cbd72',entry='0x3ec540',token='0x148e8ec',
                aux='0x148e908',bytes=52,magic='0xd4475b83',
                native_inner_lock_call='0x3ec56e',native_inner_lock_caller='0x3ec572',
                native_transfer_call='0x3ec578',native_transfer_caller='0x3ec57c',target='actualwordF090A0 timerTCB',
                original_token_and_aux_retag='2CBD76 token+16 and2CBD7A aux+16 become2CBF8C afterctorreturn.',
                tag_ascii=image.read(0x2cbf8c,64).split(b'\0')[0].decode('ascii'),
                old_SettingsVM_ret0_constructor_lock_hook_does_not_prove_native_kernel_and_must_not_be_used=True,
                separately_inventory_both_GUI_and_settings_retained_timer_owned_tokens=True),
            initializer_resets_semaphores_without_once_guard='2CBD16 startswritingF06EF4+3=1;there isnoentry onceguard. Do notrepeat it overliveowned/waited settings state.',
            conditional_posts=[dict(call='0x2caa74',target='wordF06F24',event='0x100',gate='2CA128 returnsnonzero'),
                dict(call='0x2caa8e',target='wordF06F24',event='0x200',gate='148E938+4 > +8 andbyteF08C88!=9')],
            filebacked_initial_wordF06F24_zero=True,filebacked_initial_byteF08C88_zero=True,
            no_settings_task_builder_in_local2CBD16_CFG=True,
            conditional_POST_branch_target_and_actual_native_TCB_need_new_runtime_observation=True,
            no_whitelist_NULLpost_or_fake_delivery_success=True,
            lowerNOR_geometry_reads_programerase_remain_explicitfictionalstorage_no_device_or_backupwrite=True),
        GIR_native_kernel_dependencies=dict(
            constructor_once='41B198 usesonceF29540;initializercall41B1AE->3008A0:return41B1B2.',
            backend='0x34f773c',tag='0x41b544',tag_ascii=image.read(0x41b544,64).split(b'\0')[0].decode('ascii'),
            acquire='11C504 scopedguard calls3009A0 at11C50C:return11C510,actualmutex34F773C.',
            release='41CCCE calls3008B0:return41CCD2,fromnativeguardcell.',
            kernelactive_source_method_replacement='Spellout25DC81/41CC47/41B15B usingkernel_invoke;keeporiginalGIR bytesreadonly andboundedoutputscratch.',
            already_registered_catalog_dedup_or_noadditionalrecord_claim_requires_actualinventory=True),
        manager_identity_frame_and_root_dependencies=dict(
            placement='Leave original393A2C coldgetter insideactual405340 Dispatcher callback;preparingglobalhelpers doesnot callit.',
            original_registration='38D4BE ->38D9DA358D24 ->appendcurrentTCB tovector34F9B40 underregistrymutex34F9B28.',
            precreating_oncontroller_changes_registered_TCB_and_must_not_be_silently_substituted=True,
            registry_mutex='38D456 onceF2CBF4,initcall38D46C:return38D470,tag38D860.',
            registry_cold_ctor_acquire='38D9D0->3009A0:return38D9D4',registry_cold_ctor_release='38DA0E->3008B0:return38DA12',
            registry_current_check='390142 readsactualTCB358D24;acquire390150:return390154;scan34F9B40;release39017C:return390180;returns membershipbool.',
            post_controller_gate='4053E2 ->4565C6;4565CC calls390142,branch4565D6 dependsactualregisteredDispatcherTCB.',
            cold_root_chain=fg['controller_root_and_foreground']['original_sync_transition_chain'],
            category0_normalized_frame='M+D8 [0,0,1.0,1.0];38CDC6 usesMactualframe and20BBB8 normalizedconversion,not rawpixels.',
            actual_display_frame='392DE4 makes480x272 nativeMframe usingdisplayctor2DB594/2DB716/getter/377AB8.',
            Page_root0_native_frame_or_animation='3904D2 ->390636377AB8 orPagevirtual+C4 transition. ObservePage+20..2C,+84,+85,+DC andmanagerrootcatalog.',
            original_transition_buffer='2DC954 caller6F8364 requires existingguarded explicitlowerstorage,bytes/alignment evidence;not hostpixelcontent.',
            clock='PriorControllerVM writesvirtualF09098+20 at353A9C;cannot silentlyreuse onceactualThread timednode/livekernel exists. Futureclock/timedwakeup invariant mustbe separatelydeclared/verified.',
            full_hardware_gui_main_actor_F0B550_touch_display_not_established_by_sync_root0=True),
        seven_original_conditional_GUI_writer_scope=dict(
            observed_in_older_full_ctor_proof=native_writers,
            exact_event_order_required_for_same_cold_baseline=True,
            unique_affected_words=6,region='0x05400000 optionalstartupinitializedregion',
            do_not_treat_initialize_data_writer_PC_as_code_patch=True,
            exact_static_writer_slices=[extract(image,0x385448,0x38545a),extract(image,0x26de3c,0x26de72),extract(image,0x344e16,0x344e28)],
            existingFullTaskVM_no_writer_rule_does_not_cover_MainMenu_body=True,
            new_whole_guard_recipe='Newscope computesexpectedhostbytes fromoriginalreadonlybaseline plusactualordered7nativewriter events;comparewholeinitializedregionwithoutguestwrite/baselinecounterreset. Preservewholeoriginalcode/RX/voice40/private12/player2/DB/GIR/fonts/heap/stackguards.',
            controller_preparation_should_be_journaled_separately_from_body_writers=True),
        database_and_scope_limits=dict(
            oldinitDBfixture='Hostlowerbinding writesmenu+24=DB,menu+28 readybyte1,DBword0;SQLiteengine isrealinmemorycopyofreadonlybackup.',
            originalSQLsetter='316276 wrappersprepare2361AE,bind23762C,step2378AE,finalize2376B8;completionnotification remainslowerfixture.',
            selected_cell12_is_explicitlowerinput_not_originalstockselection=True,
            temporary_selectedDB_requires_declared_guard_and_originalrestoreAPI_aftercontrollerresume='Do notcallset_cell whileDispatcherpaused;restorethrough316277 onactualcontroller aftercallbackreturns/wakes. RequireallnativeSQLwrappersclosed plusDBbaselinebackuphash.',
            no_preconditions_native_execution_or_MainMenu_body_run_done_here=True),
        assertions_passed=True,new_emulation_executed=False,device_io=False,sounds_emitted=False,
        frozen_source_or_proof_modified=False,firmware_modified=False,install_candidate=False,
        limits='Static exactlocalCFG/calls/literals plusfreshimmutable66913 independentSignal/olderconstructorproof crosschecks. Proposedcontrollerpreparation underrealnativeTCB,newsettingscondition/sem/GIRmutex/current-managerregistry/Post/clock/root/frame/visibility have notexecuted inthisartifact. No newMainMenubodycompletion/foreground/rendering/touch/deviceApp/directphonemusic/acceptedpackage/safetaskcleanup proof.')
    stage.mkdir(exist_ok=True)
    out.write_text(json.dumps(payload,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(dict(output=str(out.relative_to(ROOT)),sha256=sha(out),source_sha256=sha(Path(__file__).resolve()),
                         complete_bounded_local_CFGs=len(functions),verified_frozen_dependencies=len(verified))))


if __name__=='__main__':
    main()
