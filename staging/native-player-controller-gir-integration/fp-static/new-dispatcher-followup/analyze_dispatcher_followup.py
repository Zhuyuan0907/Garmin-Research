#!/usr/bin/env python3
"""Narrow, immutable-source Dispatcher follow-up; no VM construction/execution."""
from datetime import datetime, timezone
from pathlib import Path
import hashlib
import json
import struct
import sys

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / 'scripts'))
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB
from analyze_native_sections import NativeImage, EXPECTED
from analyze_native_gui_worker_boot import FileBackedRuntimeImage
from analyze_native_gui_foreground_boot import cfg, extract
from analyze_native_task_mutex_static import bounded


def sha(path):
    return hashlib.sha256((ROOT / path).read_bytes()).hexdigest()


def read(path):
    return json.loads((ROOT / path).read_text())


def main():
    out = Path(__file__).with_name('dispatcher-body-next-call-contract.json')
    assert not out.exists(), 'Preserve every prior artifact'
    im = FileBackedRuntimeImage(NativeImage())
    assert sha('evidence/firmware-analysis/main_02bd.bin') == EXPECTED
    body_path = 'staging/native-player-task-runtime-full/gui-foreground-boot-preflight.json'
    callback_path = 'staging/native-player-task-runtime-full/dispatcher-mainmenu-callback-static-preflight.json'
    prerequisite_path = 'staging/native-player-independent-signal/mainmenu-controller-prerequisites-static.json'
    cold_path = 'staging/native-player-controller-gir-integration/fp-static/cold-controller-fp-recipe.json'
    meta_path = 'staging/native-player-controller-gir-integration/runtime/terminal-metadata.json'
    probe_path = 'staging/native-player-controller-gir-integration/runtime/terminal-probe.json'
    settings_path = 'evidence/firmware-analysis/native-settings-lazy-vfp-emulation.json'
    signal_path = 'evidence/firmware-analysis/native-independent-signal-emulation.json'
    body, callback, prerequisites, cold = map(read, [body_path, callback_path, prerequisite_path, cold_path])
    meta, probe, settings, signal = map(read, [meta_path, probe_path, settings_path, signal_path])
    assert meta['terminal_exit_code'] == 1 and meta['session_id'] == 38139
    assert meta['runner_sha256'] == meta['runner_snapshot_sha256'] == sha(meta['runner_snapshot'])
    assert meta['probe_sha256'] == sha(probe_path) and meta['inputs_sha256'] == sha(meta['inputs'])
    assert settings['all_passed'] and signal['all_passed']
    assert meta['settings_all_scoped_guards_passed'] and not meta['full_scoped_final_guards_passed']
    assert len(probe['component_calls']) == 9 and sum(r['returned'] for r in probe['component_calls']) == 8
    assert probe['actual_FPU_state']['FPowner'] == probe['actual_FPU_state']['current_TCB'] == '0x9503f90'
    verified = {}
    for proof in [settings, signal, body, callback, prerequisites, cold]:
        for path, digest in proof['source_sha256'].items():
            assert sha(path) == digest, path
            assert path not in verified or verified[path] == digest, path
            verified[path] = digest
    old = {}
    for source in [body, callback, prerequisites]:
        for entry, function in source['functions'].items():
            for row in function['instructions']:
                pc = int(row['address'], 16)
                old[pc] = row
    decoders = {mode: Cs(CS_ARCH_ARM, flag) for mode, flag in [('ARM', CS_MODE_ARM), ('Thumb', CS_MODE_THUMB)]}
    selected = [0x405340, 0x405342, 0x40535e, 0x4053be, 0x4053c8, 0x4053d2, 0x4053d8,
                0x4053e4, 0x60935a, 0x60935c, 0x393a3a, 0x393a40, 0x393a46,
                0x392dee, 0x38d4c4, 0x38d46c, 0x38d474, 0x38d4b0, 0x38d9d0,
                0x38d9da, 0x38da0e, 0x390150, 0x39017c, 0x392ef6, 0x392efc,
                0x3945a4, 0x394614, 0x39461c, 0x394624, 0x394628, 0x38cdf6,
                0x390518, 0x39300a]
    evidence = []
    for pc in selected:
        row = old[pc]
        mode = row.get('mode', 'Thumb')
        ins = next(decoders[mode].disasm(im.read(pc, 4), pc, count=1))
        assert ins.mnemonic + ' ' + ins.op_str == row['instruction'], hex(pc)
        if 'bytes_hex' in row:
            assert im.read(pc, ins.size).hex() == row['bytes_hex']
        evidence.append(dict(row, bytes_hex=im.read(pc, ins.size).hex(), source='reused frozen local CFG; exact MAIN rechecked'))
    functions = {}
    for start, end in [(0x3404ec, 0x3404f8), (0x20bbb8, 0x20bc10), (0x3896f8, 0x389724)]:
        functions[hex(start)] = cfg(im, start, [(start, end)])
    for start, end, tail in [(0x376454, 0x376464, 0x376460), (0x37857c, 0x378590, 0x37858c),
                             (0x378590, 0x3785a0, 0x37859c), (0x6e0c08, 0x6e0c10, 0x6e0c0c)]:
        functions[hex(start)] = bounded(im, start, 'ARM', [(start, end, 'ARM')], tails={tail: 'bx lr'})
    assert im.word(0x6e0c14) == 0x3aaec70
    assert im.word(0x3931f8) == 0xe04
    assert im.read(0x3931fc, 32).split(b'\0')[0] == im.read(0x38d860, 32).split(b'\0')[0] == b'&mSemaphore'
    assert im.word(0x393bc0) == 0xf2cd08 and im.word(0xf2cd0c) == im.word(0xf0b550) == 0
    assert any(r['address'] == '0x20bbc6' and r.get('direct_call') == '0x376454'
               for r in functions['0x20bbb8']['instructions'])
    raw = []
    for entry, continuation, pointer, tag, containing in [
            (0x3009a0, 0x38d9d4, '0x34f9b28', 0x38d860, '0x38d4be'),
            (0x3008b0, 0x38da12, '0x34f9b28', 0x38d860, '0x38d4be'),
            (0x3009a0, 0x390154, '0x34f9b28', 0x38d860, '0x390142'),
            (0x3008b0, 0x390180, '0x34f9b28', 0x38d860, '0x390142'),
            (0x3009a0, 0x3945a8, 'actual_native_manager+0xe04', 0x3931fc, '0x394596'),
            (0x3008b0, 0x394618, 'actual_native_manager+0xe04', 0x3931fc, '0x394596')]:
        assert old[continuation - 4]['direct_call'] == hex(entry)
        raw.append(dict(entry=hex(entry), call=hex(continuation - 4), continuation=hex(continuation),
                        pointer=pointer, tag=hex(tag), classification_byte=0, containing_function=containing,
                        required_actor='actual native Dispatcher at body scope', guest_instruction_execution_required=True))
    source_paths = [str(Path(__file__).relative_to(ROOT)), 'evidence/firmware-analysis/main_02bd.bin',
        body_path, callback_path, prerequisite_path, cold_path, meta_path, probe_path, settings_path, signal_path,
        meta['runner_snapshot'], meta['inputs'], 'scripts/probe_native_controller_gir_component.py',
        'scripts/probe_native_settings_lazy_vfp_v2.py', 'scripts/probe_native_lazy_vfp.py',
        'scripts/probe_native_heap_settings_boot.py', 'scripts/probe_mainmenu_native_settings_journal.py',
        'scripts/probe_native_task_mutex.py', 'scripts/probe_native_dispatcher_condition.py',
        'scripts/probe_native_signal_dispatch.py', 'scripts/emulate_native_independent_signal.py',
        'scripts/probe_native_mainmenu_controller.py', 'scripts/probe_native_pool_clock.py',
        'scripts/emulate_native_voice_outer.py', 'scripts/probe_native_player_mainmenu.py',
        'scripts/analyze_native_sections.py', 'scripts/analyze_native_gui_foreground_boot.py',
        'scripts/analyze_native_gui_worker_boot.py', 'scripts/analyze_native_task_mutex_static.py',
        'staging/native-player-mainmenu-controller/controller-static-preflight.json',
        'staging/native-player-mainmenu/MainMenu-root-settings-preflight.json',
        'staging/native-player-controller-gir-integration/resource-static/font-stream-owner-supplement.json',
        'staging/controller-gir-prep-stock-v2/verification.json']
    payload = dict(updated_utc=datetime.now(timezone.utc).isoformat(), MAIN_sha256=EXPECTED,
        exact_target=dict(HWID=1352, software='8.00'), static_only=True, emulator_guest_executed=False,
        device_io=False, sounds_emitted=False, frozen_source_proof_or_canonical_modified=False,
        source_sha256={p: sha(p) for p in source_paths}, rechecked_existing_source_registry=verified,
        reused_static_contracts=[dict(path=p, sha256=sha(p)) for p in [body_path, callback_path, prerequisite_path, cold_path]],
        new_local_CFG_count=len(functions), new_CFGs=functions, rechecked_existing_instruction_evidence=evidence,
        exact_slices=[extract(im, 0x392ed0, 0x392f06), extract(im, 0x377ab8, 0x377b4c),
                      extract(im, 0x4565c6, 0x4565d8), extract(im, 0x45669e, 0x4566bc)],
        preserved_runtime=dict(settings_positive= settings_path, settings_positive_sha256=sha(settings_path),
            first_component_terminal=dict(session=38139, exit_code=1, settings_full_guards_passed=True,
                helper_entries=9, helper_returns=8, last_pending=probe['component_calls'][-1],
                first_component_final_guards_passed=False, fault=meta['error'], registers=meta['registers'],
                actual_FPU_state=probe['actual_FPU_state'], sequence_completion_not_assumed=True),
            independent_signal_positive=signal_path, independent_signal_positive_sha256=sha(signal_path),
            independent_signal_stopped_before405340_body=True,
            original_body_or_multiowner_completed_here=False),
        next_call_contract=dict(
            first_gate='Obtain new terminal completed helper11/returned11 + component result/SQL/font/catalog/native task/whole-memory guards; first terminal38139 cannot serve this gate.',
            invoke='Actual controller native APIs3954CC(80),57458D(S),4B571D(S,405341),5D28FF(D,S), then original controllerWAIT2FD035; retain original cleanupSignal/Thread object.',
            entry_PC='0x405340', entry_mode='Thumb', entry_r0='0x405341; original free-function adapter target, unused by body',
            entry_r1_r2_r3='Incidental inherited registers; body has no input object argument and no promised argument/result status ABI.',
            actual_call='60935A BLX holder.vtable+12=C1B584+12=574761;574760 loads holder+4 then BX405341',
            native_LR='0x60935d', continuation='0x60935c', actual_task='0x8804fb8', actual_SP='0x8804f78',
            body_push_and_local_bytes=40, body_SP='0x8804f50',
            held_locks='IndependentS+56 recursion1/count2 ->DispatcherD+AEC recursion0/count1 ->0; Timer keeps both GUI/settings condition tokens.',
            global_inputs='Original readonly PageMainMenu UTF16 at404560; original manager cacheF2CD0C; initialized settings19B and native GIR/catalog/fonts/menu/SQL state from returned helper sequence.',
            no_direct_host_call_or_generic_invoke='Do not kernel_invoke405341 on controller or replace callback LR/SP. Preserve actual native callback stack across new trap/resume quanta.',
            after_body='Observe4053E4 return60935C at same DispatcherSP; inner609366351BE2, outer523566351BE2, worker5D2192351BE2 release only their original scopes; original worker nextWAIT may leave controller blocked.',
            callback_r0_is_not_success_status=True,
            retained_frames='Controller2FD0AC WAIT/idle2FD016 POST/Timer2FD0AC WAIT/Thread353C64 timed node8809264; active Dispatcher old saved frame consumed, not independently resumable.'),
        native_cold_manager=dict(
            cache='0xf2cd0c', filebacked_cache_zero=True, cold_chain='40535E->393A2C->393A3A3954CC(0xE50)->393A40392DE4->392DEE38D4BE;393A46 publishes returned manager.',
            ctor_actor='Dispatcher;38D9DA358D24 appends actual native TCB to34F9B40. Controller precreation changes registered identity.',
            stack_offsets_from_callback_entry=dict(body=40, getter=56, manager_ctor=160, base_ctor=376,
                deepest_listed_prefix='3404EC/376464 add56 more:entrySP-432; unrecursed callees can use more'),
            manager_frame=dict(display='392FD2/F2CD10=480;392FD8/F2CD14=272;2DB594/2DB716/377AB8 actual writers',
                normalized_categories='M+D8 ten16-byte records [0,0,3F800000,3F800000]; not pixel coordinates'),
            initializers=[dict(entry='0x3008a0', call='0x38d46c', continuation='0x38d470', pointer='0x34f9b28',
                tag='0x38d860', tag_store_PC='0x38d474', once='0xf2cbf4 bit0', native_zero_stores=6),
                dict(entry='0x3008a0', call='0x392ef6', continuation='0x392efa', pointer='actual_native_manager+0xe04',
                tag='0x3931fc', tag_store_PC='0x392efc', bytes=24, native_zero_stores=6)],
            registry_vector=dict(pointer='0x34f9b40', once='0xf2cbf8 bit0', ctor='0x38d480',
                current_TCB_append='38D9DA358D24;38D9F43819D4 or38DA0620DB44; retain live vector bounds/allocation',
                cleanup='38D4B03896F8(vector34F9B40,callback20DC53,argC7F980) alloc16 via39544C.'),
            process_cleanup_chain=dict(getter='ARM6E0C08', literal='0x6e0c14', head='0x3aaec70',
                node16_layout=['previous_head','registered_object34F9B40','callback20DC53','argumentC7F980'],
                node_writers=['389710 object','38970E callback','389714 argument','38971C oldhead','38971E publishnode'],
                neither_TCB_plus36_nor_kernel_exit_listener2D226B4=True, whole_head_native_history_and_node_lifetime_required=True),
            raw_mutex_calls=raw,
            later_callback_queue='2DA69E->4565C6;390142 actualDispatcher registry membership selects branch;4566BA manager.vtable+C4->394596 retains native closure inM+E1C underM+E04.',
            GUI_actor='F0B550 is initially0;39461C/61E tests it and may skippost512 while native callback closure remains resident. GUI main separate descriptor9CB854/400E40 not created by two-worker singleton.',
            do_not_reset_live_once_vector_mutex_or_list=True),
        earliest_resolved_FP_paths=dict(
            exact_global_first_fault_PC_not_proven='Callee closure before these paths remains incomplete, including optional mapped runtime veneers/widget/PNG/font/manager virtual callbacks. No claim that earlier native code cannot use FP.',
            non_FP_entry_correction='38D4C4 BL3404EC is Thumb object ctor3404EC->376464; it is not ARM uint32 conversion3404DC.',
            cold_manager_conditional_path='39300A377AB8: if widget+50 animation/context pointer nonzero,377ADC BLX376454 (signed int->float); if +50zero,377AD8 skips this direct FP group. Alternate377B40/48 requires animation route.',
            root0_resolved_path='4053D238E696->38E6DC38E358->38E3EC38E15E->virtual390306/3904D2->39051838CDC6(category0)->38CDF620BBB8->20BBC6 BLX376454.',
            first_opcode_of_that_resolved_conversion='ARM376454 VMOVs0,r0, followed376458VCVT.f32.s32; continuation20BBCA/LR20BBCB',
            following_math='20BBCE BLX37857C multiplies float;20BBD2 BLX378590 converts result to signedint. Four component conversions; native word/results must be observed.',
            phase_hazard='Any actual Dispatcher VFP after original358EC4 restore has FPEXC.EN cleared; firstcomponent owner/controller9503F90 differs from runningDispatcher8804FB8.',
            frozen_helper_rejects='LazyVFPState.enter requires owner in[0,current].observe also rejects20ECD8VSTM/20ED0CVLDM; cold metadata alone does not extend it.',
            new_runtime_before_exchange='Use cold-controller-fp-recipe before firstbuilder; exact controllerM/pool + GUIreadonlymetadata cloning; actual oldowner D16/FPSCR/context save, newowner context restore, ownerjournal, allocator+clone/ranges+nativeVSTM callback widths and UNDpush journals.',
            first_new_owner_without_slot='Nativehandler saves oldowner; newDispatcher slot absent may return retaining currentFP payload. Capture behavior; do not zero FP bank or claim restored prior Dispatcher state.',
            foreground_or_multiowner_runtime_proof=False),
        inherited_hook_and_guard_gaps=[
            dict(id='INIT_NOOP', source='scripts/emulate_native_voice_outer.py', finding='Unsupported3008A0 reaches OuterVM.ret() noop. Manager callers38D470/392EFA need exact native-body observers; do not tagseed or accept retval as ctor proof.'),
            dict(id='RAW_CALL_AND_ACTOR', source='scripts/probe_native_task_mutex.py', finding='Six manager raw continuations outside GUI per-task whitelist. JournalSettingsVM/HeapSettingsVM exactraw requirecontroller; bodysettings/default writes and current-TCB+56 wrappers need exact Dispatcher admission, original native owner/queues/returns.'),
            dict(id='CLOCK_HOST_WRITE', source='scripts/probe_native_mainmenu_controller.py', finding='Inherited353A9C observer hostincrements20 and writesF09098. Coldmanager reaches38D90E/38D91A. With live timedThread and activeF0 CPUjournal this is outside prior fixedclock invariant; explicitly new scope must execute original read with declared clock policy and preserve/validate timednode/priority/scheduling, not inherit silently.'),
            dict(id='FIRST_OWNER_ONLY', source='scripts/probe_native_lazy_vfp.py', finding='First/same helper and controllermetadata==0/leadingA5 guard cannot prove cross-taskFP; new cold recipe/allocator/save/clone/journal/inventory predicates before allowing ownerexchange.'),
            dict(id='BODY_DRIVER', source='scripts/probe_native_signal_dispatch.py', finding='invoke_to_callback expects stopping boundary, no lazy exception loop; use newbody phase resuming actualcurrentPC/mode/SP/LR/registers with original undefined handling. Do not restart function.'),
            dict(id='COMPONENT_ACTIVE_COUPLING', source='scripts/probe_native_controller_gir_component.py', finding='GUI bankjournal and EA10000 text/BSS exclusion in transitionallocator are currently gatedcomponent_active; GIR rawstack assumption fixescontrollerP. Bodyphase needs its own journal/reservation/frame checks. Disabling flag blindly loses exclusions; leaving it blindly retainswrongcontrollerstack predicate.'),
            dict(id='FONT_RESIDENCY', finding='Eight externalfont parserstreams remain open by original265524/14F084 ownership; eight initial probe handles close. Retain exact fonts/opaque caches/inputledger; do not require allfontstreamsclosed or forceclose. NewDispatcher glyph inputs on its live stack need exact provenance.'),
            dict(id='LOWER_POOL_FAILURE', source='scripts/probe_native_pool_clock.py', finding='Absent audio pool3B4BA8/3EC6AA caller3B4C14 is explicit lowerfailure1 under prior mutexcounter/clock assumptions, not nativecondition scheduling. Future reachedbody must retain this qualifier or implement separate actual initialized native pool/condition scope.'),
            dict(id='RETURN_VS_FOREGROUND', finding='Callbackreturn, rootregistered/pageframe, GUIactorcallbackqueue and real display/input are separate endpoints. M+E1C queue/nativeclosure plus D/S/vector/module/fonts remainlive after bodyreturn; no safeunload or physicalApp claim.')],
        minimal_new_observer_changes=['first finish completecomponent endpoint underactualcontroller',
            'cold metadata if firstDispatcherFP admitted; retain first/same fallback rejection otherwise',
            'exacttwoinit+sixmanagerraw continuations and per-task actor provenance',
            'processcleanup head3AAEC70/node16 andregistryvector guards',
            'bodycurrentPC/lazyFP continuation driver, timedclock policy and actual residentframe inventory',
            'GUI/F0/pool/TCB/metadata/UND/SQL/font input histories without baseline reset; independenttext/BSS reservation',
            'observe bodyreturn/native RAII releases then originalworkerwait; retainpendingmanager callbackstorage'],
        assertions_passed=True,
        limits='Seven new bounded local CFGs plus immutable exact opcode/literal/terminal/source crosschecks. Callees and earlier dynamic FP reachability incomplete. No new emulator execution, fullcomponent success, MainMenu body/foreground/touch/display, native multiownerFP, realheapallocator, hardwareIRQ/exception/timer, acceptedpackage/deviceApp/directphoneaudio/safecleanup proof.')
    with out.open('x') as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2)
        handle.write('\n')
    print(json.dumps(dict(path=str(out.relative_to(ROOT)), sha256=sha(str(out.relative_to(ROOT))),
        script_sha256=sha(str(Path(__file__).relative_to(ROOT))), new_local_CFGs=len(functions),
        exact_sources=len(source_paths), revalidated_existing_sources=len(verified))))


if __name__ == '__main__':
    main()
