#!/usr/bin/env python3
"""Read-only terminal crosscheck supplement; no VM construction/execution."""
from datetime import datetime, timezone
from pathlib import Path
import hashlib
import json
import struct
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'scripts'))
from analyze_native_sections import NativeImage, EXPECTED
from analyze_native_gui_worker_boot import FileBackedRuntimeImage


def sha(path):
    return hashlib.sha256((ROOT / path).read_bytes()).hexdigest()


def read(path):
    return json.loads((ROOT / path).read_text())


def main():
    stage = Path(__file__).parent
    out = stage / 'controller-terminal14246-fp-recipe-supplement.json'
    assert not out.exists()
    recipe = str((stage / 'native-multiowner-fp-input-and-journal-recipe.json').relative_to(ROOT))
    assert sha(recipe) == '87db585fdcdda4d7c84969a429c46d2c3efdd932428316757e25fd815c6803a3'
    proof_path = 'evidence/firmware-analysis/native-controller-gir-cache-declared-emulation.json'
    meta_path = 'staging/native-player-controller-gir-integration/runtime-cache-declared/terminal-metadata.json'
    proof, meta = read(proof_path), read(meta_path)
    assert sha(proof_path) == '22806ae2805df8c59f5521b7a2fdcaef10b6371f6e055355f82b1454797f9121'
    assert sha(meta_path) == 'c96782475c3e3d9d1b774cb968d078cc8375766183bde32a86d22d85c82d55c0'
    assert proof['all_passed'] and meta['terminal_exit_code'] == 0 and meta['session_id'] == 14246
    assert meta['authoritative_terminal_result_received_from_exec']
    assert meta['full_scoped_final_guards_passed'] and meta['settings_all_scoped_guards_passed']
    assert meta['component_native_original_helpers_entered'] == meta['component_native_original_helpers_returned'] == 11
    assert not proof['physical_App_or_foreground_or_multiowner_FP_or_package_acceptance_or_direct_phone_music_verified']
    sources = [recipe, proof_path, meta_path, str(Path(__file__).relative_to(ROOT)),
               'evidence/firmware-analysis/main_02bd.bin', 'scripts/analyze_native_sections.py',
               'scripts/analyze_native_gui_worker_boot.py']
    for role in ['runner', 'inner_observer', 'driver']:
        snapshot_role = {'runner': 'runner_snapshot', 'inner_observer': 'inner_snapshot', 'driver': 'driver_snapshot'}[role]
        assert sha(meta[role]) == meta[role + '_sha256']
        assert sha(meta[snapshot_role]) == meta[role + '_sha256']
        assert proof['source_sha256'][meta[role]] == meta[role + '_sha256']
        sources.extend([meta[role], meta[snapshot_role]])
    for role in ['outer_inputs', 'inner_inputs', 'driver_inputs', 'probe', 'actual_observer_state', 'declared_cache_state']:
        assert sha(meta[role]) == meta[role + '_sha256']
        sources.append(meta[role])
    probe = read(meta['probe'])
    assert probe['completed'] and probe['full_scoped_final_guards_passed'] and len(probe['component_calls']) == 11
    assert all(row['returned'] for row in probe['component_calls'])
    fpu = probe['actual_FPU_state']
    assert fpu['FPowner'] == fpu['current_TCB'] == '0x9503f90' and fpu['FPEXC'] == '0x40000000'
    inventory = probe['native_endpoint']['native_inventory']
    assert inventory['all_tasks'] == ['0x88092b0','0x8804fb8','0x2d227c8','0x9503f90','0x9508f90']
    assert inventory['ready'] == ['0x9503f90','0x9508f90']
    tcbs = {int(row['TCB'],16): bytes.fromhex(row['raw108_hex']) for row in inventory['tasks']}
    assert all(len(raw) == 108 for raw in tcbs.values())
    assert struct.unpack_from('<I', tcbs[0x9503f90], 28)[0] == 0
    assert struct.unpack_from('<I', tcbs[0x8804fb8], 28)[0] == 0x8800fe0
    assert struct.unpack_from('<I', tcbs[0x88092b0], 28)[0] == 0x8805240
    timed = probe['native_endpoint']['timed_thread']
    assert timed['node'] == '0x8809264' and timed['current_clock'] == 0 and timed['type_byte'] == 2
    assert timed['raw20_hex'] == '00000000b0928008010000000200000000000000'
    assert sha('evidence/firmware-analysis/main_02bd.bin') == EXPECTED
    stock = FileBackedRuntimeImage(NativeImage())
    assert stock.read(0xf6e2e, 2).hex() == '4ec0'
    payload = dict(updated_utc=datetime.now(timezone.utc).isoformat(), static_only=True,
        emulator_guest_executed=False, device_io=False, frozen_source_proof_or_canonical_modified=False,
        source_sha256={path: sha(path) for path in sources},
        original_recipe_unchanged_sha256=sha(recipe),
        preserved_terminal=dict(session=14246, exit_code=0, helpers_entered=11, helpers_returned=11,
            full_scoped_final_guards_passed=True, actual_FPU_state=fpu,
            whole_native_inventory=inventory, Thread_timed_node=timed,
            FPboot20ED68_or_multiowner_FP_completed=False),
        current_live_constraint='Terminal14246controller has liveFPowner9503F90 but TCB+28=0. It cannot safely save as oldowner; coldtypedmetadata must be declared in a freshsource before originalfirstbuilder. Do not patch/rebuild this liveTCB, clearowner, or run20ED68onthis liveendpoint.',
        descriptor_pool_data='Use the three exact typed input binaries and nativewriters in immutable mainrecipe. Freshcoldsource must repeat inherited componentguards; prior14246 does not prove thatnewcoldconfiguration yet.',
        existing_FP_payload='D16/FPSCR are actual terminalcontroller payload; no expected hostfloat results or copyintoa newruntimebank inferred from this record.',
        clone_copy_evidence=dict(PC='0xf6e2e', mode='Thumb', opcode_hex='4ec0', instruction='stm r0!, {r1, r2, r3, r6}',
            source='Reused metadata-preflightCFG; originalMAINexactopcode rechecked',
            complete_copy_store_PCs=['0xf6e2e','0xf6e32','0xf6e36']),
        resident_frame_limit='Controller oldWAITframe is consumed and reused as ordinarycontrollerstack; do not treat its currentTCB+12raw52 as resumable. Fourbackgroundframes are endpoint-specific. ActualfuturecontrollerWAIT must be observed anew.',
        original_dispatcher_next_call='IndependentoriginalSignal constructor/register/publication and nativecontrollerWAIT drive realDispatchercallback405340; entrySP/LR andcontextcontract remain in frozen dispatcher-body-next-call-contract.',
        evidence_labels=['firstC_to_D: saveC only whileD.slot0; noDrestore',
            'firstD_to_C: saveD+clone40 and actualVLDM_Crestore',
            'laterC_to_D: actualVLDM_Drestore necessary before fullC/D roundtrip claim'],
        clock_followup='353A9Chost+20actor policy is a separate next-bodybranch. This supplement adds no clock/tick/IRQ/multiowner runtime evidence and keeps liveclock0/timednode unchanged.',
        assertions_passed=True,
        limits='Terminal reread/hash/opcode review only; no newguestexecution, newcoldsourcevalidation, Dispatcherbody/foreground/hardwareApp/audio or safeexit/unload proof. The immutable mainrecipe was sealed before the14246terminal supplement and still preserves firstcomponent38139partial history.')
    with out.open('x') as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2)
        handle.write('\n')
    print(json.dumps(dict(artifact=str(out.relative_to(ROOT)), sha256=sha(str(out.relative_to(ROOT))),
        source_count=len(payload['source_sha256']), assertions_passed=True, guest_executed=False)))


if __name__ == '__main__':
    main()
