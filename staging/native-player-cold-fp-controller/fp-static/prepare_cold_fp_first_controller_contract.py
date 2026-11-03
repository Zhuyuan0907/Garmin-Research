#!/usr/bin/env python3
"""Narrow cold FP boot / first-controller contract; no guest execution."""
from datetime import datetime, timezone
from pathlib import Path
import hashlib
import json
import struct
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'scripts'))
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB
from analyze_native_sections import NativeImage, EXPECTED
from analyze_native_gui_worker_boot import FileBackedRuntimeImage


def sha(path):
    return hashlib.sha256((ROOT / path).read_bytes()).hexdigest()


def read(path):
    return json.loads((ROOT / path).read_text())


def span(low, length):
    return dict(start=hex(low), end_exclusive=hex(low + length), bytes=length)


def main():
    stage = Path(__file__).parent
    out = stage / 'cold-fp-first-controller-boot-contract.json'
    assert not out.exists(), 'No prior artifact overwrite'
    paths = dict(
        recipe='staging/native-player-cache-declared-followup/fp-static/native-multiowner-fp-input-and-journal-recipe.json',
        supplement='staging/native-player-cache-declared-followup/fp-static/controller-terminal14246-fp-recipe-supplement.json',
        metadata='staging/native-player-settings-vfp-context/tcb-fp-static/native-tcb-fp-metadata-preflight.json',
        vfp='staging/native-player-heap-settings-boot/vfp-static/native-vfp-context-preflight.json',
        heap='staging/native-player-mainmenu-native-prep/heap-static/mainmenu-native-heap-mutex-preflight.json',
        mutex='staging/native-player-task-mutex/task-mutex-static-preflight.json')
    pinned = dict(recipe='87db585fdcdda4d7c84969a429c46d2c3efdd932428316757e25fd815c6803a3',
        supplement='e43f27fcce376174cf39eea85b5b97ae0f77cfccfbd6bb533da33ff7f89b15cb')
    docs, verified = {}, {}
    for key, path in paths.items():
        if key in pinned:
            assert sha(path) == pinned[key], path
        docs[key] = read(path)
        if key == 'mutex':
            assert not docs[key]['new_runtime_execution'] and not docs[key]['complete_kernel_or_interrupt_exit_verified']
        else:
            assert docs[key]['assertions_passed']
        for registry in ['source_sha256', 'rechecked_existing_source_registry']:
            for source, digest in docs[key].get(registry, {}).items():
                assert sha(source) == digest, source
                assert source not in verified or verified[source] == digest, source
                verified[source] = digest
    assert sha('evidence/firmware-analysis/main_02bd.bin') == EXPECTED
    stock = FileBackedRuntimeImage(NativeImage())
    decoders = {mode: Cs(CS_ARCH_ARM, flag) for mode, flag in [('ARM', CS_MODE_ARM), ('Thumb', CS_MODE_THUMB)]}
    selectors = dict(
        vfp={'0x20ed68': None, '0x20edb0': None, '0x20ebe0': {0x20ebe0,0x20ec78,0x20ec80,0x20ec98,0x20ecd8,0x20ecf8,0x20ed0c,0x20ed3c}},
        metadata={'0x358bf8': set(range(0x358c84,0x358c98,2)), '0xf6f26': None,
                  '0xf6edc': {0xf6f02,0xf6f10,0xf6f18}, '0xf6e08': {0xf6e2e,0xf6e32,0xf6e36,0xf6e3c,0xf6e40},
                  '0x6e0830': {0x6e0858}},
        heap={'0x3cc57c': None, '0x3cc5c2': None, '0x388b6c': set(range(0x388bca,0x388bfa,2))},
        mutex={'0x3008a0': None, '0x3009a0': {0x3009a0,0x3009a2,0x3009ca,0x3009d0,0x3009d2,0x3009d4},
               '0x3008b0': {0x3008b0,0x3008b2,0x3008f2,0x3008f8}})
    evidence = []
    for key, entries in selectors.items():
        functions = docs[key].get('bounded_CFGs', docs[key].get('functions'))
        for entry, pcs in entries.items():
            for row in functions[entry]['instructions']:
                pc = int(row['address'], 16)
                if pcs is not None and pc not in pcs:
                    continue
                mode = row.get('mode', 'Thumb')
                instruction = next(decoders[mode].disasm(stock.read(pc,4),pc,count=1))
                raw = stock.read(pc,instruction.size).hex()
                assert instruction.mnemonic+' '+instruction.op_str == row['instruction'], hex(pc)
                stored_raw = row.get('opcode_hex', row.get('bytes_hex'))
                if stored_raw is not None:
                    assert raw == stored_raw, hex(pc)
                if 'literal_address' in row:
                    assert stock.word(int(row['literal_address'],16)) == int(row['literal_value'],16)
                evidence.append(dict(row, opcode_hex=raw, reused_CFG=paths[key], containing_function=entry,
                    exact_original_MAIN_rechecked=True))
    C, L, B, F, M, N, S = 0x9503f90, 0x2d226b4, 0x2d226b8, 0x3ab1028, 0x9400900, 0x9400980, 0x9500000
    tag = 0x3cc660
    zero_stores = [dict(PC=hex(0x3008a2+2*n), relative_offset=4*n, size=4, value=0,
                        target=hex(B+4*n), instruction='str r1,[r0+offset]') for n in range(6)]
    ctor_post = [0,0,0,0,tag,0]
    release_post = [0,C+32,0,0,tag,0]
    FP_words = [0,0x7fffffff,0x20edb1,0]
    raw_calls = [r for r in docs['heap']['listener_mutex_calls']
                 if r['list_head'] == hex(L) and r['containing_function'] == '0x3cc5c2']
    assert len(raw_calls) == 2
    source_paths = [str(Path(__file__).relative_to(ROOT)), 'evidence/firmware-analysis/main_02bd.bin',
        *paths.values(), 'scripts/probe_native_kernel_context.py', 'scripts/probe_native_task_mutex.py',
        'scripts/probe_native_heap_settings_boot.py', 'scripts/probe_native_settings_lazy_vfp_v2.py',
        'scripts/probe_native_lazy_vfp.py', 'scripts/emulate_native_task_runtime_full.py',
        'scripts/emulate_native_player_widget.py', 'scripts/probe_native_controller_gir_cache_declared.py',
        'staging/native-player-controller-gir-integration/runtime-cache-declared/outer-observer-at-run.py']
    payload = dict(updated_utc=datetime.now(timezone.utc).isoformat(), static_only=True,
        guest_executed=False, device_io=False, sounds_emitted=False, frozen_source_proof_or_canonical_modified=False,
        MAIN_sha256=EXPECTED, source_sha256={p:sha(p) for p in source_paths},
        rechecked_existing_source_registry=verified, new_CFG_count=0, complete_recursive_kernel_CFG=False,
        exact_instruction_evidence=evidence,
        existing_recipe_preserved=dict(path=paths['recipe'], sha256=sha(paths['recipe']),
            supplement=paths['supplement'], supplement_sha256=sha(paths['supplement'])),
        contract_stage='Freshcold-controller/newsource; first/samecontroller FP only, before future actualDispatcherFP admission.',
        typed_inputs=docs['recipe']['typed_cold_inputs'],
        original_exitlist_ctor=dict(entry='0x3cc57c', Thumb_API='0x3cc57d',
            r0=hex(L), input=span(L,28), pre_hex='00'*28, original_current_task=hex(C),
            caller='Declaredtop-levelRETURN=10000; actualincomingLR10001 withThumbinterworkfixture',
            stack='Original3CC57Cpush8 at[C-8,C);3008A0has no frame.',
            native_head_zero=dict(PC='0x3cc582', range=span(L,4), value=0),
            native_backend_call=dict(call='0x3cc586', entry='0x3008a0', mode='Thumb',
                actual_LR='0x3cc58b', continuation='0x3cc58a', r0=hex(B), range=span(B,24), zero_stores=zero_stores),
            native_retag=dict(PC='0x3cc58c', range=span(L+20,4), value=hex(tag)),
            post_head=0, post_backend_words=[hex(v)for v in ctor_post],
            post28_hex=struct.pack('<7I',0,*ctor_post).hex(),
            original_return='3CC592BX savedr3/LR; r0=3CC660tag, notret0status.',
            once=True, refuse_initialized_or_nonempty_input=True,
            preserve_later_settings_ctor='Settings2CBD88->3CC57C148E680 still executes once with exactcaller2CBD8E; do not skip it.',
            later_exitlist_rector_forbidden=True),
        original_FPboot=dict(entry='0x20ed68', mode='ARM', original_SP=hex(C), actual_incoming_LR='0x10001',
            prerequisites=['Actualcontroller/nativeTCB exists; ready/currentheadF09090=runningcontroller;F09094=0.',
                'Before first358EC4restore/POSTtimer and before FPownerlive; metadata40/name17declared beforefirstbuilder.',
                'ActualreadbackCPACRF00000/FPEXC40000000; originalowner3AB1038=0 andFPnode16coldzero.',
                'Originalexitlistctorreturned; L.head0/B24=[0,0,0,0,3CC660,0]; C.ownedhead0; noordinarylock/pendingwait/FP trap.',
                'BootCPUjournals captured beforector/boot, notafter registration.'],
            owner_zero=dict(PC='0x20ed78', range=span(0x3ab1038,4), value=0),
            FPSCR=dict(PC='0x20ed80', register='FPSCR', value='0x03000000', memory_range=None,
                FPEXC_unchanged=True, FPSCR_differs_from_legacy_startup_zero=True),
            native_argument_zero=dict(PC='0x20ed88', range=span(C-8,4), value=0),
            registration=dict(entry='0x3cc5c2', mode='Thumb', call='0x20ed9c', actual_LR='0x20eda0',
                continuation='0x20eda0', caller_mode='ARM', r0=hex(L),r1=hex(F),r2='0x7fffffff',r3='0x20edb1',
                stack_argument_address=hex(C-8), stack_argument=0,
                outer_result_at20EDA0=0, no_duplicate_node_allowed=True),
            node16_store_table=[dict(PC='0x3cc608', range=span(F,8), values=['0x0','0x7fffffff'],
                    note='STM two4B registers; actualcallbackwidth/address journal required.'),
                dict(PC='0x3cc60c', range=span(F+8,4), value='0x20edb1'),
                dict(PC='0x3cc610', range=span(F+12,4), value=0),
                dict(PC='0x3cc612', range=span(L,4), value=hex(F))],
            raw_mutex_calls=raw_calls,
            raw_return_contract='Lock3CC5D4r0=0; no-waiterunlock3CC61Ar0=B, then originalMOVr0,r5 makes registerresult0. Neitherhostret0norstatusassumption.',
            owned_field_stores=[dict(PC='0x3009ca',range=span(B+8,4),value=hex(C)),
                dict(PC='0x3009d0',range=span(B,4),value=0),
                dict(PC='0x3009d2',range=span(B+4,4),value=hex(C+32)),
                dict(PC='0x3009d4',range=span(C+32,4),value=hex(B)),
                dict(PC='0x3008f2',range=span(B+8,4),value=0),
                dict(PC='0x3008f8',range=span(C+32,4),value=0)],
            post_backend_words=[hex(v)for v in release_post],
            stale_prev_link_exact_value=hex(C+32), stale_links_must_not_be_cleared=True,
            post_FPnode_words=[hex(v)for v in FP_words], post_FPnode16_hex=struct.pack('<4I',*FP_words).hex(),
            final_return='20EDA0ADDsp4/20EDA4LDMlr/20EDA8BXLR; r0=0 derivedoriginalregistration, SP=C.',
            after_boot_before_firstrestore=dict(owner=0,FPEXC='0x40000000',FPSCR='0x03000000',
                TCB108_unchanged_from_preboot=True, metadata40_unchanged=True, FPslot=0, pool256='allFF'),
            does_not_enable_FPEXC=True, rerun_after_live_owner_forbidden=True),
        boot_stack_recipe=dict(range=span(C-64,64), all_range_highs_exclusive=True,
            original_layer_bytes=[dict(entry='0x20ed68 ARM',push=4,local=4),
                dict(entry='0x3cc5c2 Thumb',push=36,local=4),
                dict(entry='0x3009a0 Thumb',push=4,local=4),
                dict(entry='0x3008b0 Thumb',push=8,local=8)],
            normal_no_waiter_deepest=hex(C-64), range_not_UND_stack=True,
            separate_ctor_range=span(C-8,8), normal_list_no_contention_required=True,
            hook_gate='OriginalMAINopcode, actualmode/SP/registersnapshot andeachstoreaddress/value. ARM20ED68pushLR, Thumb3CC57C/3CC5C2/rawpushesneedexplicitpushsupport; genericfrozenstr/stm journal rejectsThumbpush.',
            no_recursive_callee_stack_bound_claim=True),
        later_heap_listener_guard=dict(
            listhead=hex(L), nodes=[dict(address='0x3a7f150',next='0x3a7f160',order='0x01000000',callback='0x388b57',argument=0,
                    call='0x388be2',actual_LR='0x388be7',continuation='0x388be6',result=0),
                dict(address='0x3a7f160',next=hex(F),order='0x03000000',callback='0x388b37',argument=0,
                    call='0x388bf4',actual_LR='0x388bf9',continuation='0x388bf8',result=0),
                dict(address=hex(F),next=0,order='0x7fffffff',callback='0x20edb1',argument=0)],
            register_generic_writes='3CC608node+0/+4;3CC60C+8;3CC610+12;3CC612 predecessorlink. FirstheapnodechangesL.head,secondchanges150.next; FPnode16unchangedafterboot.',
            registered_node_intervals=[span(0x3a7f150,16),span(0x3a7f160,16),span(F,16)],
            no_late_exitlist_ctor=True, no_node_seed_or_reset=True,
            heap_workspace96_extent8192_recipe_unchanged=True,
            list_count='Originalexitlistctor + originalsettingslistctor remain2constructorrecords; FPregistration adds thirdlistener, notanotherctor.',
            ancestor_verify_heap_two_node_chain_must_be_replaced=True),
        metadata_pool_VSTM_spans=dict(
            typed_metadata=span(M,40), immutable_name=span(N,17), descriptor=span(0x9400820,20),
            native_construction=[dict(PC='0x358c8c',range=span(C+28,4),value=hex(M)),
                dict(PC='0x358c94',range=span(C+72,4),value=hex(N)),dict(PC='0x358c96',range=span(C+96,4),value=hex(N))],
            cold_native_fill=dict(entry='0x3794f0 ARM',call='0xf6f44 ThumbBLX',actual_LR='0xf6f49',continuation='0xf6f48',
                range=span(S,16384),byte=255,verify_before_native_TCB_frame_stores=True),
            wholeTCB=span(C,108), initial_integer_frame=span(0x9503f5c,52),
            first_same_controller_pool=span(S,256), first_same_expected_pool='allFF; no magic/cursor/contextallocation yet',
            future_save_only=dict(request_bytes=148,advance_bytes=152,context=span(S+8,148),
                magic_store=dict(PC='0xf6f02',range=span(S,4),value='0xfce3e2ca'),
                initial_cursor_store=dict(PC='0xf6f10',range=span(S+4,4),value=hex(S+8)),
                bump_cursor_store=dict(PC='0xf6f18',range=span(S+4,4),value=hex(S+160)),
                FPslot_store=dict(PC='0x6e0858',range=span(M+28,4),value=hex(S+8)),
                VSTM=dict(PC='0x20ecd8',range=span(S+8,128),source='actualpreinstructionD0-D15; callbackwidthunknownstatically'),
                control_STM=dict(PC='0x20ecf8',range=span(S+8+132,16),source='actualr1,r2,r3,ip; FPEXCafterhandlerenable, notfaultFPEXC'),
                holes=[span(S+8+128,4),span(S+8+148,4)],
                these_writers_not_admitted_by_first_same_scope=True),
            future_clone='GUIreadonlyM40requiresnativecopy40/F6E3C/F6E40 onfuturefirstsave; controllerM.byte4=1 skipsclone. Futurecaller/range recipe remainspreviousartifact.',
            native_allocator_no_capacity_check=True,
            first_same_runtime_pools_untouched_including_Dispatcher_Thread=True),
        first_same_full_endpoint_delta=dict(
            architecture='OriginalFPbootFPSCR03000000 replaceslegacy0; everyfirst/samefaultretry comparedtoactualbeforeD16/FPSCR, notconstantprior14246bank.',
            owner='Bootowner0; originalfirsthandler20EC98assignsC; subsequentcontrollerfaultsameowner noexchange. EndpointownerC/FPEXC40000000.',
            unchanged_M40_and_slot0=True, unchanged_named_descriptor_and_input_guards=True,
            whole_controller_pool256_FF=True, no_FPalloc_clone_VSTM_VLDM=True,
            kernelrestore_disable_remains_original=True,
            controller_raw108='Atsamecoldphaseonly+28=M,+72=N,+96=N versusNULLoldfixture; latercompareactualnewcoldbaseline plusnativeTimerhead/internalstale links. +36no relaxation.',
            controller_leading64='Replace frozenFullTaskVM A5controllerpredicate with witnessednativeFF64; keepidleA5_64/TimerA5_24/twoGUIFF64 exact. Do nothostrewritecanary to callparentguard.',
            GUI_stack_canary_count_stays2='Storecontrollercoldfillrowseparately; parentGUIcount2 remains.',
            TCB_internal_tags='OriginalbuilderwritesN atC+72/+96; preoperationinternal56/80native tagsmustuseactualnewTCB snapshot. No hostretag.',
            old_controller_WAIT_frame_consumed='Do notassertoldcontroller+12raw52resumable; backgroundfourframes52 andThreadnode20 compareexactendpoint.',
            retained_Timer_dual_condition_chain_unchanged=True, ALL_ready_priorities_unchanged_except_original_phase_history=True,
            component='Freshnewsource must complete11helperreturns/result20/full19zones/cache193typedzeroinputs/wholecacheCPUwrites/rawreads/frees/SQL/fontstreams/inputhistories plus allvoice/API/GUI/F0/heap/storage/code guards. Old14246proofdoesnottransfer to newcoldconfiguration.',
            file_lifetime='Original eightfontstreams stayresident as declared; retainexactnative ownership, notforcecloseallfonts.',
            blocked_scope='AnyothernativeTCB FPowner/exchange orF6EDC/contextwriter is failclosed inthisfirst/sameendpoint; futuremultiownerrequirespreviousrecipe.',
            no_final_background_foreground_physical_App_claim=True),
        journal_phases=dict(
            construction='Tracewhole16384nativefill frombeforefirstbuilder; verifyF6F48allFF, thenactualTCB/contextnativewrites. Initialreadyfixturehoststores remainexplicitone-timedeclaredinputs, notCPUstores.',
            boot='CaptureL/backend/node16/ownerpage/TCB108/activecontrollerstack beforeexitctor; supportexactARMandThumbpushpayload. No baseline reset before verifyingboot.',
            runtime='Keepownerpage4096 inclnode16, M40/name17/descriptor+canaries, pool256 andimmutableFF64, liveTCB108/backgroundframes/Threadnode20, F0/GUI/componentjournals active. Laterjournalbaseline includesonly separatelysealednativebootbytes.',
            owner_page=span(0x3ab1000,4096), FPnode=span(F,16), FPowner=span(0x3ab1038,4),
            fresh_unused_CODE_subrange_guards='Recheck existing exactguardintervals inpreviousrecipe;M/nameoutsideS16KBfill.',
            disjoint_journal_zone_intervals=True,
            native_store_hooks_plus_whole_net_replay_required=True,
            double_count_or_missed_overlapping_region_replay_forbidden=True,
            virtualclock0_andtimednode20_unchanged=True),
        original_exit_callback=dict(entry='0x20edb0 Thumb',callback='0x20edb1',r0='exitingTCB',r1=0,
            native_owner_clear_PC='0x20edb8',onlymatchingowner=True,
            context_metadata_andstack_not_freed=True, taskexit_callback_not_run_here=True),
        first_source_review_checklist=['TypedD/M/namebeforefirstbuilder; neverhotpatchTCB orinvokeoriginalbuilderagainonalivetask.',
            'Correctbeforefirstrestorebootreadbacks; exitlistctoronce; actualARM20EDA0r0=0 andfinalbootSP.',
            'ReleasedlistbackendstaleprevC+32; original2heapreturn0 andexact3nodechain; noresetlisteners.',
            'ControllerFFguard andM40/slot0/wholeTCB108nativeNtag baseline; nofirst/samepoolwriteorcontextallocation.',
            'Bootstack64originalpushjournals distinctfromUND32; fulljournalscapturedbeforewriters andclosedbeforefuturebaselines.',
            'Repeat11helper/fullcache/19zones andalloldnativeguards; preserveclock/timednode/fourbackgroundframes/twoTimerconditions.',
            'CrossownerFP remainsrejecteduntilseparatenewsource/ranges/allocator/context/VSTM/UND72scope.'],
        assertions_passed=True,
        limits='PurestaticreusedboundedCFG/unchangedMAIN/sourcehashreview. No rootnewrunnerreview yet, no guest execution/newcoldFPboot/metadata/fullcomponentendpoint/multiownerproof; no physicalboot/IRQ/foreground/acceptedpackage/directphoneaudio/safeunload. Nativecaller success requiresactualreturn andoriginalfield/store evidence.')
    with out.open('x') as handle:
        json.dump(payload,handle,ensure_ascii=False,indent=2)
        handle.write('\n')
    print(json.dumps(dict(artifact=str(out.relative_to(ROOT)),sha256=sha(str(out.relative_to(ROOT))),
        generator_sha256=sha(str(Path(__file__).relative_to(ROOT))),
        old_registry_sources_revalidated=len(verified), exact_instructions_rechecked=len(evidence),
        static_assertions_passed=True,guest_executed=False)))


if __name__ == '__main__':
    main()
