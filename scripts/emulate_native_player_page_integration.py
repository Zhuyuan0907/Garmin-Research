#!/usr/bin/env python3
"""Original Page construction/attachment/input dispatch to a loaded player.

Fixtures supply heap, DB, explicit geometry and numeric input events. Original
Page/Widget visibility and event code execute; physical input classification,
automatic grid population, rendering and accepted package remain unverified.
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
from emulate_native_player_page import PageVM
from emulate_native_player_menu_selection import BUILD, DATABASE, SQL_OUT, sha
from emulate_native_player_menu_loaded import PLAYER_ID
from emulate_native_vpm_filesystem import require
from emulate_native_sbc import verify_guard_faults


def main():
    require(unicorn.__version__ == '2.1.4' and unicorn.uc_version() == (2, 1, 33621247),
            'Use staging/unicorn-stream-venv/bin/python')
    build = json.loads((ROOT / BUILD).read_text())
    for path, expected in build['source_sha256'].items():
        require(sha(path) == expected, 'Build dependency differs: ' + path)
    database_sha = sha(DATABASE)
    vm = PageVM(NativeImage(), build)
    vm.invoke(0x395981, ())
    print(json.dumps({'phase': 'before_original_outer_loader'}), flush=True)
    loaded = vm.load()
    print(json.dumps({'phase': 'original_outer_loader_returned'}), flush=True)
    oldram = struct.unpack_from('<I', (ROOT / build['original_binary']).read_bytes(), 4)[0]
    voice = bytes(vm.uc.mem_read(IMAGE + 12, oldram - 12))
    exports = bytes(vm.uc.mem_read(STUBS, 480))
    vm.init_DB_fixture()
    vm.set_cell(15, PLAYER_ID, 0)
    cases = []
    page = vm.invoke(0x3954cc, (0x7c4,))
    vm.watch = (page, page + 0x7c4)
    sql_before = len(vm.native_setter_calls)
    result = vm.invoke(0x5a2995, (page,))
    require(result == page and vm.word(page) == 0xc0e5f0 and vm.word(page + 0x7c) == 4,
            'Original Page constructor did not produce its four children')
    rows_after_ctor = list(vm.db.execute('SELECT id,icon,size FROM custom_table ORDER BY id'))
    cleared = list(vm.db.execute('SELECT icon,size FROM custom_table WHERE id=15'))
    require(cleared == [(0, 0)], 'Observed Page initialization no longer clears the test slot')
    construction_calls = vm.native_setter_calls[sql_before:]
    require(any(row['arguments'][1:4] == [0, 15, 0] for row in construction_calls),
            'Slot clear was not observed at the original SQL setter')
    holders = [{'offset': hex(offset), 'child': hex(vm.word(page + offset)),
                'control_block': hex(vm.word(page + offset + 4)),
                'vtable': hex(vm.word(vm.word(page + offset)))}
               for offset in [0x7ac, 0x7b4, 0x7bc]]
    cases.append({'name': 'complete_original_Page_constructor_and_native_slot_clear', 'passed': True,
        'page': hex(page), 'allocation_bytes_from_original_caller_literal': 0x7c4,
        'vtable': hex(vm.word(page)), 'original_children': 4, 'three_child_holders': holders,
        'slot15_after_constructor': list(cleared[0]), 'original_SQL_setter_entries': construction_calls,
        'rows_after_constructor': rows_after_ctor,
        'slot_clear_cause_beyond_this_fixture_not_generalized': True,
        'page_controller_switch_or_automatic_grid_population_executed': False})
    print(json.dumps({'case': cases[-1]['name'], 'passed': True}), flush=True)
    # Repeat the original SQL setter after construction. No host DB row change
    # or reinitialized registry is needed; this is explicit test orchestration.
    vm.set_cell(15, PLAYER_ID, 0)
    normal = vm.normal_lookup(15, 0)
    require(normal['matched'] == 1 and normal['caption'] == 'Pi 播放器', 'Player Widget lookup failed')
    widget = int(normal['widget'], 16)
    vm.watch = (widget, widget + 0x550)
    vm.page_writes = []
    vm.invoke(vm.word(vm.word(widget) + 39 * 4), (widget, 0))
    vm.invoke(0x27abf9, (widget, 0x36))
    vm.invoke(0x37707b, (page, widget))
    require(vm.word(widget + 0x48) == page and vm.word(page + 0x7c) == 5,
            'Original parent/child attachment differs')
    hidden_before = vm.uc.mem_read(widget + 0x85, 1)[0]
    vm.invoke(vm.word(vm.word(page) + 9 * 4), (page, 1))
    require(hidden_before == 0 and bytes(vm.uc.mem_read(widget + 0x84, 2)) == b'\0\1',
            'Original Page visibility propagation differs')
    vm.uc.mem_write(page + 0x20, struct.pack('<4I', 0, 0, 480, 272))
    vm.uc.mem_write(widget + 0x20, struct.pack('<4I', 100, 200, 100, 40))
    event = SQL_OUT + 0x400
    vm.uc.mem_write(event, b'\0' * 64)
    vm.put(event + 0x10, 150)
    vm.put(event + 0x14, 220)

    def dispatch(action, x=150, y=220):
        vm.put(event + 0x10, x)
        vm.put(event + 0x14, y)
        vm.uc.mem_write(event + 0x28, bytes([action]))
        before = len(vm.audio)
        value = vm.invoke(vm.word(vm.word(page) + 16), (page, event))
        require(vm.word(event + 0x10) == x and vm.word(event + 0x14) == y,
                'Parent failed to restore input coordinates')
        return {'numeric_action': action, 'point': [x,y], 'returned': hex(value),
            'Widget_state_C8_C9_CA': list(vm.uc.mem_read(widget + 0xc8, 3)),
            'new_audio_API_requests': vm.audio[before:]}

    actions = [dispatch(a) for a in [0,1,2]]
    require(all(row['returned'] == hex(widget) for row in actions) and
            [len(row['new_audio_API_requests']) for row in actions] == [0,0,2] and
            [row['Widget_state_C8_C9_CA'] for row in actions] == [[1,2,2],[1,0,0],[1,0,0]],
            'Original Page numeric event sequence differs')
    require(vm.uc.mem_read(widget + 0x112, 1)[0] == 0 and not vm.control_clicks,
            'Unexpected fixture callback or modified Widget flag')
    cases.append({'name': 'original_parent_attachment_visibility_and_numeric_input_to_loaded_player', 'passed': True,
        'normal_lookup': normal, 'original_parent': hex(vm.word(widget + 0x48)), 'Page_children_after_attach': 5,
        'stock_parent_API': '0x37707a', 'stock_Page_and_Widget_event_dispatch_executed': True,
        'parent_restores_input_coordinates': True, 'actions': actions,
        'test_supplied_geometry': {'Page':[0,0,480,272], 'Widget':[100,200,100,40]},
        'test_requested_enabled_state0_and_visibility1': True,
        'stock_sound_selector_API': '0x27abf8', 'test_sound_selector': 0x36,
        'optional_click_sound_wait_skipped_by_nondefault_test_setting': True,
        'Widget_flag112_remains_zero_no_capture_flag_fabricated': True,
        'original_input_driver_classification_or_real_touch_executed': False,
        'host_invoked_signal_or_compiled_player_directly': False})
    print(json.dumps({'case': cases[-1]['name'], 'passed': True}), flush=True)

    vm.invoke(vm.word(vm.word(page) + 9 * 4), (page, 0))
    require(vm.uc.mem_read(widget + 0x85, 1)[0] == 0, 'Page hide did not reach Widget')
    hidden = dispatch(2)
    vm.invoke(vm.word(vm.word(page) + 9 * 4), (page, 1))
    vm.invoke(vm.word(vm.word(widget) + 39 * 4), (widget, 4))
    disabled = dispatch(2)
    vm.invoke(vm.word(vm.word(widget) + 39 * 4), (widget, 0))
    outside = dispatch(2,480,272)
    require(all(not row['new_audio_API_requests'] for row in [hidden,disabled,outside]),
            'Hidden/disabled/outside-page event launched player')
    resumed = dispatch(2)
    require(len(resumed['new_audio_API_requests']) == 2, 'Restored visible/enabled event failed')
    cases.append({'name': 'original_visibility_disabled_and_outside_bounds_controls', 'passed': True,
        'hidden': hidden, 'disabled': disabled, 'outside_Page': outside, 'restored_visible_enabled': resumed,
        'only_original_state_APIs_used_for_visibility_and_enabled': True})
    print(json.dumps({'case': cases[-1]['name'], 'passed': True}), flush=True)

    for id, icon, size in vm.database_before:
        vm.set_cell(id,icon,size)
    require(list(vm.db.execute('SELECT id,icon,size FROM custom_table ORDER BY id')) == vm.database_before,
            'In-memory DB did not restore all fifteen rows')
    require(all(row['closed'] for row in vm.statements.values()) and sha(DATABASE) == database_sha,
            'Native statement closure or backup DB integrity failed')
    require(not vm.invalid_accesses and not vm.control_clicks, 'Final run has a memory fault or fixture callback')
    require(bytes(vm.uc.mem_read(IMAGE + 12, oldram - 12)) == voice and
            bytes(vm.uc.mem_read(STUBS,480)) == exports, 'Original voice RAM/exports changed after Page calls')
    snap = vm.finish()
    require(snap['native_menu_state'] == [1,1,2,0x13528000,2,2], 'Loaded player activation state differs')
    required = [0x5a2994,0x34014a,0x358068,0x3567f4,0x376bf6,0x37707a,0x376df8,
                0x27a502,0x27abf8,0x30c91a,0x27a992,0x27a98a,0x376e4e,0x31649a,0x316276]
    visits={hex(a):vm.visits[a] for a in required}
    require(all(visits.values()), 'Claimed original Page/event entry was not executed')
    vm.db.close()
    paths = {ROOT / p for p in build['source_sha256']} | {ROOT / BUILD,ROOT / DATABASE,
        ROOT / build['package'],ROOT / build['combined_binary'],ROOT / build['extension_elf'],ROOT / build['extension_flat'],
        ROOT / 'staging/native-music-stream/emulator-runtime.json'}
    paths.update((ROOT / 'staging/native-player-page').glob('*preflight.json'))
    for name in ['stock-call-index.json','vtable-references.json','first-lookup-failure.json',
                 'source-at-first-lookup-failure.py','kernel-wake-failure.json','source-at-kernel-wake-failure.py',
                 'partial-region-guard-failure.json','integration-source-at-region-failure.py','region-differences.json']:
        paths.add(ROOT / 'staging/native-player-page' / name)
    for module in tuple(sys.modules.values()):
        name=getattr(module,'__file__',None)
        if name:
            path=Path(name).resolve()
            if path.is_file() and path.is_relative_to(ROOT/'scripts'):paths.add(path)
    paths.add(Path(__file__).resolve())
    proof={'updated_utc':datetime.now(timezone.utc).isoformat(),'MAIN_sha256':EXPECTED,
        'build_manifest':BUILD,'build_manifest_sha256':sha(BUILD),
        'source_sha256':{str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest()for p in sorted(paths)},
        'case_count':len(cases),'all_passed':True,'cases':cases,'load':loaded,'snapshot':snap,
        'original_Page_event_entry_visits':visits,'original_Widget_writes_during_attachment_and_input':vm.page_writes,
        'original_kernel_wake_boundary_fixture':{'entry':'0x2fcf44','result':0,'requests':vm.wake_boundaries,
            'kernel_thread_or_notification_delivery_executed':False},
        'mapped_startup_zero_pages':vm.zero_pages,'virtual_VFP_access_supplied':True,
        'original_GUI_timer_constructor_invoked_by_test':True,'physical_input_event_classification_executed':False,
        'automatic_grid_population_or_page_controller_switch_executed':False,'rendered_touchable_icon_verified':False,
        'all15_DB_rows_restored_in_memory':True,'original_SQL_statement_finalization':True,
        'database_sha256':database_sha,'database_backup_unchanged':True,
        'original_voice_RAM_and40_exports_retained_after_Page_events':True,
        'only_two_original_GUI_guard_words_change_conditional_initialized_data':True,
        'Page_Widget_holders_callbacks_resources_and_module_remain_pinned':True,
        'emulator_binding_version':unicorn.__version__,'emulator_native_version':list(unicorn.uc_version()),
        'guard_fault_controls':verify_guard_faults(), 'device_io':False,'device_files_modified':False,
        'sounds_emitted':False,'device_install_candidate':False,'actual_package_acceptance_verified':False,
        'native_App_running_on_device':False,'phone_direct_music_verified':False,
        'limits':'Exact HWID1352 SW8.00 original PageCustomMainMenu constructor, native parent/child attachment, '
        'visibility propagation and Page/Widget numeric event dispatch execute after original outer/module loading. '
        'Controller supplies raw geometry, numeric events0/1/2, enable/visibility requests and nondefault sound '
        'selector36 via the original API, bypassing optional click-sound wait. OS wake2FCF44 is a result0 boundary '
        'fixture: no kernel thread, UI-loop/timer expiry or event delivery. Default field112 remains0; action2 '
        'direct path is tested, not the release-posted closure queue or actual physical input classification. '
        'Page construction clears test slot15 via original SQL setter under this sparse catalog/DB fixture; '
        'test explicitly reapplies selection afterwards. Cause/general real boot behavior is not inferred. '
        'Widget is manually attached through stock API; original automatic grid builder546878, page controller '
        'switch/root installation, native geometry/layout, nonempty graphics/font resources and rendering/display '
        'are not run. Inherited heap/DB-ready/host SQLite/platform/cache/driver/audio API boundaries remain '
        'fixtures; startup-zero BSS/VFP and native timer constructor supplied. Original voice RAM/40 exports '
        'and code/canaries retained. SourceID9 ownership, repeat/stop/cleanup, safe detach/unload/reload, accepted '
        'modified VPM/SIG loading, physical App, phone/direct music, native WAV/kernel/DAC/speaker are unproved. '
        'All objects/holders/callbacks/module/resources stay pinned. No device I/O or backup mutation.'}
    out=ROOT/'evidence/firmware-analysis/native-player-page-emulation.json'
    out.write_text(json.dumps(proof,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({'evidence':str(out.relative_to(ROOT)),'groups':len(cases),
                      'dependencies':len(proof['source_sha256']),'all_passed':True,'device_io':False}),flush=True)


if __name__=='__main__':main()
