#!/usr/bin/env python3
"""Stock loader, normal Widget factory/signal and Add-node constructor.

Heap/DB/platform inventories and audio API endpoints are declared fixtures.
GUI constructors, vtables, event connection and signal invocation execute stock
instructions. Signal emission is requested by the test, not by physical touch.
No redraw/render, full Page/Add builder, device/SIG acceptance or audio is proved.
"""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import struct
import sys
import unicorn
from analyze_native_sections import NativeImage, ROOT, EXPECTED
from analyze_native_loader import IMAGE, STUBS
from emulate_native_player_widget import WidgetVM
from emulate_native_player_menu_selection import BUILD, DATABASE, sha
from emulate_native_player_menu_loaded import PLAYER_ID
from emulate_native_vpm_filesystem import require
from emulate_native_sbc import verify_guard_faults


def digest(data):
    return hashlib.sha256(data).hexdigest()


def main():
    require(unicorn.__version__ == '2.1.4' and unicorn.uc_version() == (2, 1, 33621247),
            'Use staging/unicorn-stream-venv/bin/python')
    build = json.loads((ROOT / BUILD).read_text())
    for path, expected in build['source_sha256'].items():
        require(sha(path) == expected, 'Build dependency changed: ' + path)
    database_sha = sha(DATABASE)
    stock = NativeImage()
    vm = WidgetVM(stock, build)
    vm.invoke(0x395981, ())
    print(json.dumps({'phase': 'before_original_outer_loader'}), flush=True)
    loaded = vm.load()
    print(json.dumps({'phase': 'original_outer_loader_returned'}), flush=True)
    oldram = struct.unpack_from('<I', (ROOT / build['original_binary']).read_bytes(), 4)[0]
    original_voice_after_load = bytes(vm.uc.mem_read(IMAGE + 12, oldram - 12))
    exports_after_load = bytes(vm.uc.mem_read(STUBS, 480))
    vm.init_DB_fixture()
    vm.set_cell(15, PLAYER_ID, 0)
    cases = []

    normal = vm.normal_lookup(15, 0)
    obj = int(normal['widget'], 16)
    require(normal['matched'] == 1 and obj in vm.raw_allocations and
            vm.raw_allocations[obj]['length'] == 0x550 and normal['caption'] == 'Pi 播放器',
            'Original factory did not construct a normal player Widget')
    require(vm.word(obj) == 0xc00b38 and vm.word(vm.word(obj) + 16) == 0x27a503 and
            vm.word(obj + 0x88) != 0, 'Original normal vtable or signal is missing')
    normal.update({'vtable': hex(vm.word(obj)), 'event_slot': hex(vm.word(vm.word(obj) + 16)),
                   'click_signal': hex(vm.word(obj + 0x88)), 'Widget_bytes': 0x550})
    emitted = []
    for n in range(2):
        count = len(vm.audio)
        # Original software signal entry -> stock signal list/thunks -> copied
        # catalog member -> original31649A -> compiled resident player callback.
        # No host bind construction or direct compiled callback call is used.
        vm.invoke(0x27a98b, (obj,))
        require(len(vm.audio) == count + 2, 'Stock Widget signal did not reach loaded playback request')
        emitted.append({'activation': n + 1, 'new_audio_API_requests': vm.audio[count:]})
    require(vm.visits[0x6acf3a] == 1 and vm.visits[0x31649a] == 2 and
            vm.visits[vm.symbol('native_player_menu_activate')] == 2,
            'Normal factory connection or loaded callback count differs')
    cases.append({'name': 'original_normal_Widget_factory_signal_to_loaded_player', 'passed': True,
                  'normal_lookup': normal, 'software_signal_activations': emitted,
                  'input_driver_or_physical_touch': False, 'host_constructed_member_bind': False,
                  'host_called_compiled_callback_directly': False,
                  'default_state_after_factory': list(vm.uc.mem_read(obj + 0xc8, 2)),
                  'actual_clickable_page_or_rendering_verified': False})
    print(json.dumps({'case': cases[-1]['name'], 'passed': True}), flush=True)

    count = len(vm.audio)
    preview = vm.normal_lookup(15, 1)
    preview_obj = int(preview['widget'], 16)
    require(preview['matched'] == 1 and preview_obj in vm.raw_allocations and
            vm.word(preview_obj) == 0xc00b38 and vm.word(preview_obj + 0x88) == 0,
            'Factory flag1 control differs')
    vm.invoke(0x27a98b, (preview_obj,))
    require(len(vm.audio) == count and vm.visits[0x31649a] == 2,
            'Unbound flag1 Widget invoked a player callback')
    require(vm.word(int(normal['output_holder'], 16)) == obj and
            vm.word(int(preview['output_holder'], 16)) == preview_obj,
            'Constructed Widget holders were overwritten')
    cases.append({'name': 'factory_flag1_Widget_has_no_player_subscription', 'passed': True,
                  'normal_lookup': preview, 'vtable': hex(vm.word(preview_obj)),
                  'click_signal': 0, 'software_signal_added_audio_requests': 0,
                  'flag_semantics_beyond_observed_branch_unknown': True,
                  'separate_original_shared_ptr_holders_retained': True})
    print(json.dumps({'case': cases[-1]['name'], 'passed': True}), flush=True)

    entry = vm.menu_records()[0]
    node = vm.invoke(0x3954cc, (0x8f4,))
    result = vm.invoke(0x6a56d9, (node, PLAYER_ID, entry + 28, entry + 8), (0, 1, 0))
    label = vm.wide(vm.invoke(0x3927f5, (node + 0x678,)))
    require(result == node and vm.word(node) == 0xc15f38 and vm.word(node + 0x8f0) == PLAYER_ID and
            label == 'Pi 播放器' and vm.word(node + 0x688) == 0 and
            list(vm.uc.mem_read(node + 0x544, 3)) == [0, 1, 0], 'Original Add-node constructor differs')
    cases.append({'name': 'complete_original_Add_node_constructor_from_loaded_catalog', 'passed': True,
                  'node': hex(node), 'node_bytes': 0x8f4, 'vtable': hex(vm.word(node)),
                  'caption': label, 'caption_auxiliary': vm.word(node + 0x688), 'id': vm.word(node + 0x8f0),
                  'flags': list(vm.uc.mem_read(node + 0x544, 3)),
                  'constructor_returned': True, 'stock_base_and_child_constructors_executed': True,
                  'direct_constructor_test_call': True, 'complete_Add_function_or_page_executed': False})
    print(json.dumps({'case': cases[-1]['name'], 'passed': True}), flush=True)

    vm.set_cell(*vm.database_before[-1])
    require(list(vm.db.execute('SELECT id,icon,size FROM custom_table ORDER BY id')) == vm.database_before,
            'In-memory DB restore differs')
    require(all(s['closed'] for s in vm.statements.values()) and sha(DATABASE) == database_sha,
            'Native statement or backup integrity failed')
    require(not vm.invalid_accesses and not vm.control_clicks, 'Unexpected memory fault or synthetic callback')
    require(bytes(vm.uc.mem_read(IMAGE + 12, oldram - 12)) == original_voice_after_load and
            bytes(vm.uc.mem_read(STUBS, 480)) == exports_after_load, 'GUI changed original voice image or exports')
    snapshot = vm.finish()
    require(snapshot['native_menu_state'] == [1, 2, 2, 0x13528000, 2, 2],
            'Loaded player state differs after two stock signal activations')
    observed_addresses = [0x315b64, 0x315f16, 0x316276, 0x30c3ec, 0x30c374, 0x27a364,
                          0x351ffc, 0x38545c, 0x376e5e, 0x376e4e, 0x27a98a, 0x6acf3a,
                          0x6ad580, 0x31649a, 0x3954f0, 0x395980, 0x6a56d8, 0x34163a,
                          0x361c02, 0x39270c]
    visits = {hex(a): vm.visits[a] for a in observed_addresses}
    require(all(visits.values()), 'A claimed original constructor/event function was not reached')
    vm.db.close()
    paths = {ROOT / path for path in build['source_sha256']} | {
        ROOT / BUILD, ROOT / DATABASE, Path(__file__).resolve(), ROOT / build['package'],
        ROOT / build['combined_binary'], ROOT / build['extension_elf'], ROOT / build['extension_flat'],
        ROOT / 'staging/native-music-stream/emulator-runtime.json',
        ROOT / 'staging/native-player-widget/host-crash.json'}
    for module in tuple(sys.modules.values()):
        name = getattr(module, '__file__', None)
        if name:
            path = Path(name).resolve()
            if path.is_file() and path.is_relative_to(ROOT / 'scripts'):
                paths.add(path)
    proof = {'updated_utc': datetime.now(timezone.utc).isoformat(), 'MAIN_sha256': EXPECTED,
             'build_manifest': BUILD, 'build_manifest_sha256': sha(BUILD),
             'source_sha256': {str(path.relative_to(ROOT)): digest(path.read_bytes()) for path in sorted(paths)},
             'case_count': len(cases), 'all_passed': True, 'cases': cases, 'load': loaded, 'snapshot': snapshot,
             'original_GUI_entry_visits': visits, 'mapped_startup_zero_pages': vm.zero_pages,
             'virtual_VFP_access_supplied': True, 'original_GUI_timer_constructor_invoked_by_test': True,
             'GUI_timer_expiry_or_event_loop_not_executed': True,
             'allocator_boundaries': ['existing C++ heap services', '0x2dc954 aligned allocation', '0x2dc982 calloc'],
             'large_canvas_allocations': [event for event in vm.events if event.get('length', 0) >= 0x10000],
             'DB_ready_and_host_SQLite_engine_are_fixtures': True,
             'database_sha256': database_sha, 'all15_rows_restored_in_memory': True,
             'all_statements_finalized_by_original_wrappers': True, 'database_backup_unchanged': True,
             'original_voice_RAM_and40_exports_retained_after_GUI': True,
             'Widget_holders_callbacks_module_and_UI_resources_remain_pinned': True,
             'emulator_binding_version': unicorn.__version__, 'emulator_native_version': list(unicorn.uc_version()),
             'guard_fault_controls': verify_guard_faults(), 'device_io': False, 'device_files_modified': False,
             'sounds_emitted': False, 'device_install_candidate': False, 'native_App_running_on_device': False,
             'actual_package_acceptance_verified': False, 'rendered_touchable_icon_verified': False,
             'phone_direct_music_verified': False,
             'limits': 'Original normal Widget factory and all reached constructors, vtables, connection/slot thunks '
                      'and software signal emission execute in the same VM as the original outer/module loader '
                      'and compiled resident player. Two signal requests reach WAV register/start boundaries; '
                      'these are host-requested software signals, not real touch or an enabled/laid-out Page. '
                      'Factory flag1 constructs a Widget without the launch subscription. Direct Add-node '
                      'constructor finishes from catalog resources; complete Add builder/Page not run. '
                      'Heap, directory/driver/cache/platform/DB inventories and host SQLite/audio boundaries '
                      'remain fixtures. Startup-zero BSS pages are mapped on demand, including conditional '
                      'sections, virtual VFP access and original GUI timer ctor are supplied by the test; '
                      'actual boot ordering, timer/event delivery and UI thread are unknown. Visual catalog '
                      'strings are still empty; no rendering/font/bitmap/display/input-driver/SIG acceptance, '
                      'WAV decoder/kernel/DAC/speaker, sourceID9 reuse ownership, safe reload/unload, physical '
                      'App or direct phone music is proved. Constructed objects/holders and callbacks remain '
                      'pinned; release/detach is not claimed. Verified backup DB remains unchanged.'}
    path = ROOT / 'evidence/firmware-analysis/native-player-widget-emulation.json'
    path.write_text(json.dumps(proof, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({'evidence': str(path.relative_to(ROOT)), 'groups': len(cases),
                      'dependencies': len(proof['source_sha256']), 'all_passed': True, 'device_io': False}), flush=True)


if __name__ == '__main__':
    main()
