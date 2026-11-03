#!/usr/bin/env python3
"""Prepare immutable-source, typed cold FP inputs; static analysis only.

No Unicorn VM is constructed and no guest, device or service is executed.
Existing bounded CFGs are reused and selected instructions are rechecked.
"""
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


def main():
    stage = Path(__file__).parent
    out = stage / 'native-multiowner-fp-input-and-journal-recipe.json'
    assert not out.exists(), 'Preserve every previous artifact'
    paths = dict(
        cold='staging/native-player-controller-gir-integration/fp-static/cold-controller-fp-recipe.json',
        dispatcher='staging/native-player-controller-gir-integration/fp-static/new-dispatcher-followup/dispatcher-body-next-call-contract.json',
        metadata='staging/native-player-settings-vfp-context/tcb-fp-static/native-tcb-fp-metadata-preflight.json',
        vfp='staging/native-player-heap-settings-boot/vfp-static/native-vfp-context-preflight.json',
        heap='staging/native-player-mainmenu-native-prep/heap-static/mainmenu-native-heap-mutex-preflight.json')
    pinned = dict(cold='874f6ff0ab614526feafe7a6426ed5a468abc691b9b09e4e036119a7ca9389ac',
        dispatcher='b00ce6979410dcf9dadbeb2f1588d4fe9414d41462a2c389841bf7fdd67dbc50',
        metadata='19fc548d527d4ebb363a30e9910e1913e679f6bc5fbbc9fc4eabbdce651f08b6',
        vfp='c2b7da27512b0f73ad22cf25179fbe9e605bab406fdced877433639be906fe35',
        heap='3fa1f71ecc3d8454de931ad8637631f7d1e732ea4e261b6dfa158f7990df37bb')
    docs = {}
    verified = {}
    for key, path in paths.items():
        assert sha(path) == pinned[key], path
        docs[key] = read(path)
        assert docs[key]['assertions_passed'] and docs[key]['static_only']
        for registry in ['source_sha256', 'rechecked_existing_source_registry']:
            for source, digest in docs[key].get(registry, {}).items():
                assert sha(source) == digest, source
                assert source not in verified or verified[source] == digest, source
                verified[source] = digest
    assert sha('evidence/firmware-analysis/main_02bd.bin') == EXPECTED
    stock = FileBackedRuntimeImage(NativeImage())
    decoders = {mode: Cs(CS_ARCH_ARM, flag) for mode, flag in [('ARM', CS_MODE_ARM), ('Thumb', CS_MODE_THUMB)]}
    selected = {
        0x358c8a, 0x358c8c, 0x358c92, 0x358c94, 0x358c96,
        0x521e9a, 0xf6f44, 0xf6f48, 0xf6e14, 0xf6e28, 0xf6e2c, 0xf6e30,
        0xf6e32, 0xf6e34, 0xf6e36, 0xf6e3c, 0xf6e40, 0xf6edc,
        0xf6f02, 0xf6f10, 0xf6f18, 0x6e0830, 0x6e0854, 0x6e0858,
        0x20ebd4, 0x20ebd8, 0x20ebdc, 0x20ebe0, 0x20ec78, 0x20ec80,
        0x20ec84, 0x20ec94, 0x20ec98, 0x20ecc0, 0x20ecd0, 0x20ecd8,
        0x20ecdc, 0x20ece0, 0x20ece8, 0x20ecf0, 0x20ecf4, 0x20ecf8,
        0x20ed00, 0x20ed08, 0x20ed0c, 0x20ed14, 0x20ed18, 0x20ed20,
        0x20ed28, 0x20ed2c, 0x20ed30, 0x20ed34, 0x20ed38, 0x20ed3c,
        0x20edb0, 0x20edb8, 0x3cc586, 0x3cc58c, 0x3cc5d0, 0x3cc5ee, 0x3cc616}
    rows = {}
    for key in ['metadata', 'vfp', 'heap']:
        for entry, function in docs[key].get('bounded_CFGs', docs[key].get('functions', {})).items():
            for row in function['instructions']:
                pc = int(row['address'], 16)
                if pc in selected or entry == '0x20ed68':
                    rows.setdefault(pc, (paths[key], entry, row))
    assert selected <= rows.keys(), [hex(p) for p in sorted(selected - rows.keys())]
    evidence = []
    for pc, (source, containing, row) in sorted(rows.items()):
        mode = row.get('mode', 'Thumb')
        instruction = next(decoders[mode].disasm(stock.read(pc, 4), pc, count=1))
        raw = stock.read(pc, instruction.size).hex()
        assert instruction.mnemonic + ' ' + instruction.op_str == row['instruction'], hex(pc)
        assert raw == row.get('opcode_hex', row.get('bytes_hex')), hex(pc)
        if 'literal_address' in row:
            assert stock.word(int(row['literal_address'], 16)) == int(row['literal_value'], 16)
        evidence.append(dict(row, opcode_hex=raw, reused_CFG_source=source,
                             containing_function=containing, original_MAIN_rechecked=True))

    cold = docs['cold']['coherent_cold_recipe']
    typed = [('controller-descriptor20.bin', int(cold['descriptor']['address'], 16),
              bytes.fromhex(cold['descriptor']['raw_hex']), 'cold input; native builder reads descriptor+16'),
             ('controller-metadata40.bin', int(cold['metadata']['address'], 16),
              bytes.fromhex(cold['metadata']['raw_hex']), 'cold input; original521E9A-shaped writable metadata'),
             ('controller-name17.bin', int(cold['name']['address'], 16),
              cold['name']['ASCII_with_NUL'].encode('ascii'), 'new explicit cold task name, not physical descriptor recovery')]
    assert [len(raw) for _, _, raw, _ in typed] == [20, 40, 17]
    descriptor_words = struct.unpack('<5I', typed[0][2])
    metadata_words = struct.unpack('<10I', typed[1][2])
    assert descriptor_words == (0x9400004, 0, 0x9504000, 0x100000, 0x9400900)
    assert metadata_words == (0x9400980, 1, 0x9500000, 4096, 0, 0, 0, 0, 0, 0)
    assert metadata_words[2] + metadata_words[3] * 4 == descriptor_words[2]
    typed_rows = []
    for filename, address, raw, provenance in typed:
        target = stage / filename
        with target.open('xb') as handle:
            handle.write(raw)
        typed_rows.append(dict(path=str(target.relative_to(ROOT)), address=hex(address), bytes=len(raw),
            raw_hex=raw.hex(), sha256=sha(str(target.relative_to(ROOT))), provenance=provenance,
            installable_or_device_input=False, before_first_original_builder_only=True))

    controller_save = docs['cold']['future_first_controller_save_recipe']
    GUI_recipes = docs['metadata']['first_GUI_save_recipes']
    for recipe in GUI_recipes:
        base = int(recipe['pool_base'], 16)
        context = (base + 15) & ~7
        assert context == int(recipe['first_FP_context'], 16)
        assert context + 152 == int(recipe['native_metadata_clone'], 16)
        assert context + 152 + 40 == int(recipe['final_cursor'], 16)
        assert int(recipe['post_clone_FP_slot'], 16) == context + 152 + 28
        assert int(recipe['final_cursor'], 16) < base + 256
    assert 0x9500008 + 152 == int(controller_save['allocation_end'], 16)
    fp_node = 0x3ab1028
    nodes = [(0x3a7f150, 0x3a7f160, 0x01000000, 0x388b57),
             (0x3a7f160, fp_node, 0x03000000, 0x388b37),
             (fp_node, 0, 0x7fffffff, 0x20edb1)]
    node_rows = [dict(address=hex(pointer), words=[hex(v) for v in [next_node, order, callback, 0]],
                      predicted_after_original_heap_ctor=True, native_registration_required=True)
                 for pointer, next_node, order, callback in nodes]
    listener_calls = [r for r in docs['heap']['listener_mutex_calls']
                      if r['list_head'] == '0x2d226b4' and r['containing_function'] == '0x3cc5c2']
    assert len(listener_calls) == 2
    direct = [str(Path(__file__).relative_to(ROOT)), 'evidence/firmware-analysis/main_02bd.bin', *paths.values(),
        'scripts/probe_native_kernel_context.py', 'scripts/probe_native_condition_timer_owner.py',
        'scripts/probe_native_task_mutex.py', 'scripts/emulate_native_task_runtime_full.py',
        'scripts/probe_native_heap_settings_boot.py', 'scripts/probe_native_settings_lazy_vfp_v2.py',
        'scripts/probe_native_lazy_vfp.py', 'scripts/emulate_native_player_widget.py',
        'scripts/probe_native_mainmenu_controller.py', 'scripts/emulate_native_independent_signal.py',
        'evidence/firmware-analysis/native-settings-lazy-vfp-emulation.json',
        'staging/native-player-controller-gir-integration/runtime/terminal-metadata.json',
        'staging/native-player-controller-gir-integration/runtime/terminal-probe.json',
        'scripts/analyze_native_sections.py', 'scripts/analyze_native_gui_worker_boot.py',
        *[r['path'] for r in typed_rows]]
    payload = dict(updated_utc=datetime.now(timezone.utc).isoformat(), exact_target=dict(HWID=1352, software='8.00'),
        MAIN_sha256=EXPECTED, static_only=True, emulator_guest_executed=False, device_io=False,
        sounds_emitted=False, frozen_source_proof_or_canonical_modified=False,
        source_sha256={p: sha(p) for p in direct}, rechecked_existing_source_registry=verified,
        reused_static_contracts=[dict(path=p, sha256=pinned[k]) for k, p in paths.items()],
        new_CFGs=0, bounded_callee_closure_complete=False,
        rechecked_existing_instruction_evidence=evidence, typed_cold_inputs=typed_rows,
        cold_configuration=cold, metadata40_layout=docs['metadata']['metadata40_layout'],
        TCB108_comparison=docs['cold']['TCB108_guards'],
        first_builder_contract=dict(
            entry='0x358bf8', Thumb_API='0x358bf9', r0='controller descriptor9400820',
            declared_descriptor='Replace only cold descriptor construction before first invoke; override cannot call frozen configure then patch liveTCB.',
            frozen_overwrite='KernelContextVM.configure_native_kernel_inventory writes +16=0 immediately before invoke. New source must pass exact new20-byte descriptor at that first call.',
            native_outputs='TCB9503F90; integerframe9503F5C52; native358C8C+28=M,358C94+72=N,358C96+96=N.',
            input_lifetime='M40/name17 immutable lifetime input outside whole16KB native fill; M.word28 subsequently nativeFPslot only.',
            metadata_capacity='metadata.word12=4096 supports16384-byte fill; native pool does not use it as an allocation limit.',
            idle_Timer_metadata_zero=True, initial_ready_membership_remains_explicit_fixture=True,
            no_original_physical_controller_descriptor_recovered=True, no_live_TCB_host_patch_or_rebuild=True),
        cold_fill_and_canary_changes=docs['cold']['cold_fill_and_canary_changes'],
        per_task_pool_recipes=dict(controller=controller_save, Dispatcher=GUI_recipes[0],
            Thread_future_only=GUI_recipes[1],
            Thread_FP_execution_not_required_or_admitted_by_this_minimal_scope=True,
            original_allocator=docs['metadata']['native_pool_allocator'],
            original_clone=docs['metadata']['native_metadata_clone'],
            scoped_pool_bytes=256, all_range_highs_exclusive=True,
            replacement_FF64=dict(controller=['0x9500100','0x9500140'],Dispatcher=['0x8801124','0x8801164']),
            collision_guard='Each cursor/end must be below base+256 and strictly below every live taskframe/minSP; metadata/name are not in this stack fill.',
            no_ordinary_heap_TCB_plus36_or_kernel_timed_node_mutation=True),
        original_FP_boot_integration=dict(
            required_when='New cold observer before firstPOST(timer,16)/358EC4 restore and before any live FPowner; not rerun after settings or component.',
            architecture='InheritedWidgetVM FPEXC40000000 and newdeclaredCPACRF00000 are explicit virtualstartupinputs. Before20ED68 require actualreadback, owner0, no existing FPnode and no lazytrap active.',
            does_not_enable_FPEXC=True,
            safe_sequence=['Declare typedD/M/name before firstcontrollerbuilder; observe originalwholeFFfill andTCB108.',
                'Complete original idle/controller/Timer construction and initialreadyfixture; assert actualcontroller/currenthead and owner0/EN1.',
                'Begin and capture disjoint bootCPUjournals before any exitlist writes.',
                'Original3CC57D(exitlist2D226B4) exactlyonce from controller when all28bytes are coldzero; observe3008A0 caller3CC58A and native3CC58C tag.',
                'ARM20ED68 originalboot from samecontrollerSP; original20ED9C BLX3CC5C2, actualreturn20EDA0 ARM; original20EDA8BXLR returns to initiatingfixture endpoint.',
                'Require bootFPSCR03000000, owner0, node3AB1028 [0,7FFFFFFF,20EDB1,0], lock/unlock returns and wholelist/node/TCB/pool histories.',
                'Proceed originalPOST/restore/GUI/singleton/background, laterheapctor registersits2listeners intoexistingFPnode list; remove lateexitlistctor from newdriver sequence.'],
            boot_entry='0x20ed68', mode='ARM', incoming_SP='0x9503f90',
            owner_native_zero_PC='0x20ed78', FPSCR_native_PC='0x20ed80', FPSCR='0x03000000',
            outer_registration=dict(entry='0x3cc5c2', call='0x20ed9c', actual_LR='0x20eda0', caller_mode='ARM',
                r0='0x2d226b4', r1='0x3ab1028', r2='0x7fffffff', r3='0x20edb1', stack_argument=0),
            raw_mutex_calls=listener_calls,
            listener_list_backend=dict(pointer='0x2d226b8', tag='0x3cc660', class_byte=0,
                post_release_stale_links='Originalnormalepiloguestalelinks remain legal only with exactnativewrite/return history; never clear them.'),
            predicted_final_chain=node_rows, signed_ascending_stable_order_PC='0x3cc5ee',
            no_standard_listener_2D226D0_invented=True,
            no_nonempty_list_reset_no_duplicate_FPnode=True,
            original_boot_wrapper_does_not_check_registration_retval=True,
            new_explicit_registration_return_guard='Observe successful r0=0 at20EDA0, FPnode uniqueness and actualnativechain insertion.',
            heap_extent96_8192_recipes_unchanged=True,
            exit_callback=dict(entry='0x20edb0 Thumb', r0='exitingTCB', r1=0,
                native_clear='20EDB8 onlyif matchingowner', no_context_stack_or_metadata_free=True,
                listener_registration_does_not_prove_taskexit_or_safeunload=True),
            original_FP_boot_executed_in_existing_settings_proof=False,
            refuse_if_EN_already_zero_or_owner_live='Stop; no host reenable/reset or midflight FPboot. This proposal requires exactprecondition, not inferred hardwareboot.'),
        native_exception_exchange=dict(
            handler='0x20ebe0 ARM', disable='Original358EC4 executes20EBD4 each integerrestore; bank payload remains.',
            architecture_fixture='Only undefinedmode/bankedSP/LR=PC+4/SPSR; no FPbank/owner/mutex/contextswitch host replacement.',
            actual_task_gate='ReadyheadF09090 == actualrunning_task at fault, originalnativeTCB live, IRQmarkerF09094=0; switch observerrunning_task only when native saved destination reached.',
            owner_store='20EC98 publishesnewcurrent before save/allocation; failure is a partialnative exchange, never success.',
            old_owner_slot_zero='20ECC0->F6EDC(oldTCB,148); advances152;20ECD0->6E0830 attach; writableM or nativeclone40; allocationNULL unchecked natively.',
            save='20ECD8 storesD0-D15 128bytes;20ECF8 storesactual r1,r2,r3,ip atctx+132 after20ECE0 reads handlerenabledFPEXC40000000.',
            controls='FPEXC+132,FPINST/staleR2+136,FPINST2/staleR3+140,FPSCR+144; unusedR2/R3 require actualprestore registercapture, never assumedzero or faultGP.',
            holes='[ctx+128,ctx+132) and padding[ctx+148,ctx+152) preserved accordingwholeCPUhistory.',
            new_owner_slot_zero='20ED08->20ED30 skipsVLDM/allocation/zero; actualpreviousFPbank retained.',
            new_owner_slot_existing='20ED0C nativeVLDM D16;20ED14controlLDM;20ED18FPEXC;conditional20ED20/28;20ED2CFPSCR.',
            return_epilogue='20ED30/34/38 then20ED3C MOVS PC,LR returnswithSPSR to exactfaultPC; GP15/CPSR equalfaultsnapshot.',
            retry_FP_predicate='No/sameowner or newslot0: comparefaultD16/FPSCR. Newslotvalid: compare newowner savedbank, not oldfaultbank.',
            require_original_retry_opcode_and_result=True, no_direct_host_float_return_or_enable=True),
        runtime_evidence_stages=[
            dict(stage='first_controller', trigger='Originalsettings/helperFP', owner_after='controller', allocations=0,
                proves='First/sameowner handler only; metadataFPslot remains0.'),
            dict(stage='first_C_to_D', trigger='ActualkernelrestoreDispatcher thenactualnativeDispatcherVFP',
                required='NativeCsave148/advance152, M.slot=9500008, ownerD; D.slot0 skipsrestore.',
                proves='Csave plus actualcrossowner; noDrestore claim.'),
            dict(stage='first_D_to_C', trigger='ActualDispatchernativework/RAII/WAIT thenactualoriginalcontrollerWAITresume andoriginalC VFP',
                required='NativeDsave152 + clone40/F6E40, oldDmetadata unchanged, CslotVLDMrestore.',
                proves='Bothsavedcontexts plusCrestore; completeDrestore stillpending.'),
            dict(stage='later_C_to_D', trigger='LateractualoriginalDispatcherFP afteractualnativekernelrestore',
                required='C existingcontextresave withoutbump, D existingcontextVLDM withsavedD16/FPSCR.',
                proves='FullC/Dsave/restoreroundtrip onlywhenactualpath is reached; not static guaranteed.')],
        CPUjournal_recipe=dict(
            construction='StartseparatewholeS16384 originalstorehistory beforefirstbuilder, capturewholeFFatF6F48, sealtrace before laterdisjointTCB/frame/pool zones.',
            boot='Beforeexitlistctor/20ED68 captureexitlist28 or parent64 with exactadjacenttimerdescriptor, ownerpage4096 inclFPnode16, controllerTCB108 and activenative stackwrites; sealbootphase. Laterbaselines may include verifiednativebootbytes, never hide unjournaled mutations.',
            runtime_zones=['Controllerpool[S,S+256),M40/name17+guards, Dispatcherpool[B,B+256), oldM40+guards, clone40 withinpool, eachliveTCB108, allresidentframes52 andThreadtimednode20, exactownerpage4096, guardedUNDinterior, initializedF0bank and existingGUI/heap/voice/DB/code/storage journals.'],
            disjoint_zones_required=True,
            pool_writers=['F6F02 magic','F6F10 initialcursor','F6F18 bumpcursor','F6E2E/32/36 clonecopies','F6E3C mutablebyte','6E0858 FPslot','20ECD8 D16','20ECF8 controls'],
            TCB_metadata_writer='F6E40 onlyGUIclone; controller+28 staysM. FPpath otherwise preserveswholeTCB108, including+36 and internal56/80 sem fields.',
            VSTM='Oldscalar1/2/4 storejournal cannot accept nativeVSTM blindly. Capture observedwidth/addresses/value atoriginal20ECD8 inUNDmode; comparefull128B with preinstructionD16 and completewholepoolhistory. Staticanalysis does not establish callbackwidth/completeness.',
            control_STM='20ECF8 four4B writes checked againstactualprestore r1,r2,r3,ip; plus132=handlerenabledFPEXC, notfaultFPEXC.',
            pushes=['20EBE0 ARM24','20EC78 ARM8','6E0830 ARM8','F6E14 Thumb16','F6EDC Thumb16'],
            maximum_listed_nested_bytes=72, recursive_callee_stack_bound_complete=False,
            exact_push_gate='ActiveUNDmode, unchangedMAINopcode, preinstructionSP/registerpayload, exactstoreaddresses/liveguardedzone; Thumbcallee push is legitimate while processor remainsUND.',
            retry_general_frame='Beforefault/after20ED3C atretryGP15/CPSR equal; oldnativecallbackSP/LR and integercontext remainlive; originalfunction not reentered.',
            full_net_history='Compare eachwholejournalzone reconstruction toguestbytes and holes/padding/canaries; hooks alone do not establish writecoverage.',
            unchanged_canaries='IdleA5_64/TimerA5_24/ThreadFF64 unchanged; controller/Dispatcherleading64 replaced only by separatelyprovennativepoolprefix + fixedFF64afterbudget.',
            all_frozen_wholememory_checks_retained=True),
        fixed_live_kernel_inventory=dict(
            clock='F09098 unchanged by FPboot/exchange; originalpool/clone never writes it.',
            inherited_clock_hook='ControllerVM.observe353A9C hostadds20/writesF09098; manager38D90E/91A reachesit. Newsource must stop inheritedhostclockwrite, retain declaredfixedclock native read, and verify timednode/ready/priorities. Separateclock scope needed for actualticks.',
            timed_Thread=dict(node='0x8809264', bytes=20, type_byte=2, raw20_unchanged_by_FP=True,
                plus16='observed unused field, notprevlink'),
            retained_Timer_owned='Timer2D227C8 owns148E8EC then GUI8805290; exactboth52byteconditions/tokens/head chain remains.',
            frozen_background_frames='ActualcontrollerWAIT/idlePOST/TimerWAIT/Threadtimedwait52bytes remain resident as appropriate to currentphase; comparetrap entry/retry bytes unchanged. Actualkernelrestores have separatejournal/history.',
            ordinary_owned='DispatcherD+AEC and independentS+56 recursiveownerchain unchanged bylazytrap; RAII releases occuronly originalcallbackpath.',
            ALL_ready_priority='Atfault/handlerretry no list/state/priority/mailbox change; actualintegerkernelphase keeps its own exactinventory observer.',
            TCB_plus36_unchanged_by_FP=True, real_IRQ_clock_or_hardware_task_inventory_not_proven=True),
        minimum_new_source_changes=[
            'Coldconfigure override exactD/M/name beforefirst358BF8; storage+guards/nativeFFwholefill/controllerTCB108 tags.',
            'NewFPbootphase andoriginalexitlistctoronce beforefirstrestore; real20ED68 registration successful andlater3nodeheapguard; neverresetlivechain.',
            'Newmultiownerundefinedobserver withvalidmetadata/pool/range gates; permitnativeallocator/clone/save/restore and correctnewownerbank retrypredicate.',
            'Disjointconstruction/boot/runtime histories includingVSTM/control/ARM+ThumbUNDpush exactbytes; controller/Dispatcherpool256+FF64 andnewM/TCBdelta predicates.',
            'Preserveactualkernelrunningtask,liveclock/timednode/background frames/ownedtokens; explicitly remove inheritedhostclocktick when nativebodyreaches353A9C.',
            'Driver mustresumeactualnativecallbackPC/SP/LR through traps andactualWAIT/POST; distinguishCsave/Crestore/Drestore endpoints, keepresidentmodule/fonts/signals/closures.'],
        assertions_passed=True,
        limits='Static typed input and originalopcode/immutable registry review only. No guestexecution, newsource/proof validation, physicalcoldcontrollerdescriptor/FPboot/IRQ/timer/App/audio/package, actualDispatcherFP, multiownercontext exchange, hardwareperformance, taskexit/free/safecleanup demonstrated. Existingsettingsfirst/sameowner positive and partialcomponent38139 remain unchanged.')
    with out.open('x') as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2)
        handle.write('\n')
    print(json.dumps(dict(artifact=str(out.relative_to(ROOT)), artifact_sha256=sha(str(out.relative_to(ROOT))),
        generator_sha256=sha(str(Path(__file__).relative_to(ROOT))), typed_input_files=typed_rows,
        exact_dependencies_revalidated=len(verified), selected_original_instructions_rechecked=len(evidence),
        assertions_passed=True, guest_executed=False), ensure_ascii=False))


if __name__ == '__main__':
    main()
