#!/usr/bin/env python3
"""Original automatic grid construction to resident player, offline only.

Settings-record inventory, heap, host SQLite, outer frame/numeric input and
kernel/audio endpoints are declared fixtures. Native GUI geometry/rendering is
not run; an earlier original geometry attempt is preserved as a failed probe.
"""
from datetime import datetime,timezone
import hashlib
import json
from pathlib import Path
import struct
import sys
import unicorn
from analyze_native_sections import NativeImage,ROOT,EXPECTED
from analyze_native_loader import IMAGE,STUBS
from emulate_native_player_grid import GridVM
from emulate_native_player_menu_selection import BUILD,DATABASE,SQL_OUT,sha
from emulate_native_player_menu_loaded import PLAYER_ID
from emulate_native_vpm_filesystem import require
from emulate_native_sbc import verify_guard_faults


def main():
    require(unicorn.__version__=='2.1.4' and unicorn.uc_version()==(2,1,33621247),
            'Use isolated staging/unicorn-stream-venv/bin/python')
    build=json.loads((ROOT/BUILD).read_text())
    for path,expected in build['source_sha256'].items():require(sha(path)==expected,'Build dependency changed '+path)
    database_sha=sha(DATABASE);vm=GridVM(NativeImage(),build)
    vm.invoke(0x395981,());print(json.dumps({'phase':'before_original_outer_loader'}),flush=True)
    loaded=vm.load();print(json.dumps({'phase':'original_outer_loader_returned'}),flush=True)
    oldram=struct.unpack_from('<I',(ROOT/build['original_binary']).read_bytes(),4)[0]
    voice=bytes(vm.uc.mem_read(IMAGE+12,oldram-12));exports=bytes(vm.uc.mem_read(STUBS,480))
    vm.init_DB_fixture();cases=[];settings=[]
    # Exercise the actual menu read/reset and native record-copy wrappers.
    # Persistent record lookup is synthetic only in the two positive controls;
    # neither setting bit has been recovered from the physical unit.
    for value in [None,0,1]:
        vm.set_cell(12,PLAYER_ID,0)
        before=list(vm.db.execute('SELECT id,icon,size FROM custom_table ORDER BY id'))
        if value is not None:vm.supply_setting_record(value)
        setters=len(vm.setter_callers);reads=len(vm.setting_reads);searches=len(vm.settings_searches)
        returned=vm.invoke(0x31632f,(vm.menu_pointer(),))
        after=list(vm.db.execute('SELECT id,icon,size FROM custom_table ORDER BY id'))
        changes=vm.setter_callers[setters:];read_rows=vm.setting_reads[reads:]
        original_return=[r for r in read_rows if 'original_menu_read_return'in r]
        require(len(original_return)==1,'Settings read returned through unexpected path')
        if value is None:
            require(returned==0 and original_return[0]['original_menu_read_return']==-1 and
                    all(icon==size==0 for _,icon,size in after) and
                    len([r for r in changes if 'reset15_entry'in r])==1 and
                    len([r for r in changes if 'arguments'in r])==15,
                    'Uninitialized settings do not explain original reset15')
        else:
            require(returned==value and original_return[0]['original_menu_read_return']==4 and
                    original_return[0]['output_value']==value and before==after and not changes,
                    'Successful native setting read changed icon rows')
        settings.append({'setting_ID':'0x19b','supplied_value':value,'menu_status':returned,
            'read_trace':read_rows,'native_reset_and_setters':changes,
            'lower_record_inventory_requests':vm.settings_searches[searches:],
            'DB_preserved':before==after,'all15_cleared':all(icon==size==0 for _,icon,size in after),
            'actual_device_setting_value_recovered':False})
        vm.end_setting_fixture()
    require(vm.uc.mem_read(0xf06ef7,1)[0]==0 and vm.settings_catalog_fixture is None,
            'Settings inventory fixture remains active')
    cases.append({'name':'native_setting_read_failure_causes_reset15_positive0_and1_preserve_rows','passed':True,
        'stages':settings,'original_read_and_copy_entries':['0x31632e','0x2cad0a','0x2cabbc','0x3732c8'],
        'lower_record_search_fixture':'0x2cab14','settings_ready_byte_fixture':'0xf06ef7',
        'settings_ready_byte_restored_before_GUI':True,'actual_settings_store_boot_initialization_executed':False})
    print(json.dumps({'case':cases[-1]['name'],'passed':True}),flush=True)

    page=vm.invoke(0x3954cc,(0x7c4,));setter_start=len(vm.setter_callers);read_start=len(vm.setting_reads)
    require(vm.invoke(0x5a2995,(page,))==page and vm.word(page)==0xc0e5f0 and vm.word(page+0x7c)==4,
            'Original containing Page constructor failed')
    page_changes=vm.setter_callers[setter_start:];page_reads=vm.setting_reads[read_start:]
    require(len([r for r in page_changes if 'reset15_entry'in r])==3 and
            all(r['original_menu_read_return']==-1 for r in page_reads if 'original_menu_read_return'in r),
            'Original Page reset cause differs from the settings control')
    # Explicit native selection timing follows construction; no host DB update.
    vm.set_cell(12,PLAYER_ID,0)
    rows_before=list(vm.db.execute('SELECT id,icon,size FROM custom_table ORDER BY id'))
    grid=vm.invoke(0x3954cc,(0x420,));vm.watch=(grid,grid+0x420)
    require(vm.invoke(0x546c95,(grid,0))==grid,'Original Grid constructor did not return')
    rows=vm.grid_rows(grid);require(vm.word(grid)==0xc0dd9c and vm.word(grid+0xe4)==15 and
            len(rows)==15 and vm.word(grid+0x7c)==19,'Unexpected original automatic Grid inventory')
    require(rows_before==list(vm.db.execute('SELECT id,icon,size FROM custom_table ORDER BY id')),
            'Automatic Grid builder changed selected rows')
    chosen=rows[11];record=int(chosen['address'],16);widget=int(chosen['widget'],16)
    caption=vm.wide(vm.invoke(0x3927f5,(record+0x1c,)))
    require(caption=='Pi 播放器' and vm.word(record+0x40)==PLAYER_ID and
            vm.word(record+0x18)==0x13528000 and vm.word(widget)==0xc00b38 and
            vm.word(widget+0x48)==grid and vm.word(widget+0x88)!=0,
            'Original automatic normal Widget/caption/bind failed')
    require(len(vm.grid_builder_calls)==1 and vm.grid_builder_calls[0]['caller']=='0x546eb2' and
            len(vm.grid_factory_entries)==1 and vm.grid_factory_entries[0]['fifth_argument']==0,
            'Normal Widget was not made by the original Grid constructor')
    initial_state=list(vm.uc.mem_read(widget+0xc8,3))
    initial_rect=list(struct.unpack('<4I',vm.uc.mem_read(widget+0x20,16)))
    require(initial_state==[1,4,4] and initial_rect==[0,0,0,0],
            'Default Widget state/geometry changed')
    cases.append({'name':'complete_original_Grid_constructor_automatically_makes_and_attaches_loaded_player_Widget','passed':True,
        'containing_Page':{'object':hex(page),'vtable':hex(vm.word(page)),'children':4,
            'native_reset_and_setters':page_changes,'original_settings_read_trace':page_reads},
        'explicit_reselection_after_Page_using_original_SQL_setter':True,'selected_cell':12,
        'grid':hex(grid),'allocation_bytes_from_original_edit_Page_caller':0x420,'mode':0,
        'vtable':hex(vm.word(grid)),'row_limit':15,'record_stride_bytes':72,'row_count':len(rows),'child_count':19,
        'rows':rows,'chosen':dict(chosen,caption=caption,ID=hex(vm.word(record+0x40)),
            context=hex(vm.word(record+0x18)),click_signal=hex(vm.word(widget+0x88)),
            initial_state_C8_C9_CA=initial_state,initial_rectangle=initial_rect),
        'original_automatic_builder_calls':vm.grid_builder_calls,'original_factory_entries':vm.grid_factory_entries,
        'host_called_factory_or_attached_Widget_directly':False,'DB_preserved_after_Grid':True,
        'actual_general_MainMenu_constructor_or_root_switch_executed':False})
    print(json.dumps({'case':cases[-1]['name'],'passed':True}),flush=True)

    # Grid itself is attached via the stock API. The automatic builder already
    # attached its Widgets; do not call the factory or attach chosen Widget here.
    vm.invoke(0x37707b,(page,grid))
    require(vm.word(page+0x7c)==5 and vm.word(grid+0x48)==page,'Containing Page/Grid attachment failed')
    vm.invoke(vm.word(vm.word(widget)+39*4),(widget,0));vm.invoke(0x27abf9,(widget,0x36))
    vm.invoke(vm.word(vm.word(page)+9*4),(page,1))
    require(vm.uc.mem_read(grid+0x85,1)[0]==1 and vm.uc.mem_read(widget+0x85,1)[0]==1,
            'Original Page/Grid visibility did not reach automatically-created Widget')
    geometry={'Page':[0,0,480,272],'Grid':[40,40,360,200],'Widget_relative_to_Grid':[120,80,100,40]}
    for pointer,frame in [(page,geometry['Page']),(grid,geometry['Grid']),(widget,geometry['Widget_relative_to_Grid'])]:
        vm.uc.mem_write(pointer+0x20,struct.pack('<4I',*frame))
    event=SQL_OUT+0x400;vm.uc.mem_write(event,b'\0'*64)
    def dispatch(action,x=180,y=140):
        vm.put(event+0x10,x);vm.put(event+0x14,y);vm.uc.mem_write(event+0x28,bytes([action]))
        audio_start=len(vm.audio);input_start=len(vm.numeric_widget_inputs)
        returned=vm.invoke(vm.word(vm.word(page)+16),(page,event))
        require(vm.word(event+0x10)==x and vm.word(event+0x14)==y,'Nested parents did not restore input coordinates')
        return {'numeric_action':action,'global_point':[x,y],'returned':hex(returned),
            'Widget_state_C8_C9_CA':list(vm.uc.mem_read(widget+0xc8,3)),
            'native_Widget_inputs':vm.numeric_widget_inputs[input_start:],
            'new_audio_API_requests':vm.audio[audio_start:]}
    actions=[dispatch(a)for a in [0,1,2]]
    require([len(r['new_audio_API_requests'])for r in actions]==[0,0,2] and
            [r['Widget_state_C8_C9_CA']for r in actions]==[[1,2,2],[1,0,0],[1,0,0]],
            'Original nested Page/Grid numeric dispatch did not reach player')
    require(all(r['returned']==hex(widget) and len(r['native_Widget_inputs'])==1 and
                r['native_Widget_inputs'][0]['point']==[20,20]for r in actions),
            'Nested native coordinate translation differs')
    require(vm.uc.mem_read(widget+0x112,1)[0]==0 and not vm.control_clicks,'Fabricated callback/Widget flag used')
    cases.append({'name':'native_Page_Grid_Widget_coordinate_translation_and_numeric_event_to_resident_player','passed':True,
        'Page_children_after_Grid_attach':5,'Grid_parent':hex(vm.word(grid+0x48)),
        'Widget_parent_remains_automatic_Grid':hex(vm.word(widget+0x48)),
        'stock_Grid_event_entry':'0x5496ba','stock_base_event_entry':'0x376bf6','actions':actions,
        'test_supplied_geometry':geometry,'original_visibility_propagated':True,
        'test_enable0_and_sound_selector36_via_original_APIs':True,
        'host_invoked_signal_or_compiled_callback_directly':False,'actual_physical_touch_classification_executed':False,
        'native_layout_or_rendering_executed':False,'Widget_flag112_remains0':True})
    print(json.dumps({'case':cases[-1]['name'],'passed':True}),flush=True)
    vm.invoke(vm.word(vm.word(page)+9*4),(page,0));hidden=dispatch(2)
    vm.invoke(vm.word(vm.word(page)+9*4),(page,1))
    vm.invoke(vm.word(vm.word(widget)+39*4),(widget,4));disabled=dispatch(2)
    vm.invoke(vm.word(vm.word(widget)+39*4),(widget,0));outside=dispatch(2,400,240)
    require(all(not r['new_audio_API_requests']for r in [hidden,disabled,outside]),
            'Hidden/disabled/outside Grid control reached player')
    resumed=dispatch(2);require(len(resumed['new_audio_API_requests'])==2,'Restored Grid event failed')
    cases.append({'name':'native_nested_visibility_disabled_and_outside_Grid_bounds_controls','passed':True,
        'hidden_Page':hidden,'disabled_Widget':disabled,'outside_Grid_inside_Page':outside,
        'restored_visible_enabled':resumed})
    print(json.dumps({'case':cases[-1]['name'],'passed':True}),flush=True)
    for id,icon,size in vm.database_before:vm.set_cell(id,icon,size)
    require(list(vm.db.execute('SELECT id,icon,size FROM custom_table ORDER BY id'))==vm.database_before and
            all(r['closed']for r in vm.statements.values()) and sha(DATABASE)==database_sha,
            'Native DB restore/finalization/backup check failed')
    require(not vm.invalid_accesses and not vm.control_clicks,'Full integration has fault or synthetic callback')
    require(bytes(vm.uc.mem_read(IMAGE+12,oldram-12))==voice and bytes(vm.uc.mem_read(STUBS,480))==exports,
            'Original voice RAM or40 exports changed after automatic Grid/events')
    snapshot=vm.finish();require(snapshot['native_menu_state']==[1,1,2,0x13528000,2,2],'Resident player state differs')
    required=[0x31632e,0x2cad0a,0x2cabbc,0x3732c8,0x3162f2,0x316276,0x5a2994,0x546c94,
              0x546878,0x3164a0,0x315f16,0x315b64,0x66c7cc,0x5472d0,0x5496ba,0x376bf6,
              0x37707a,0x27a502,0x376e4e,0x31649a]
    visits={hex(a):vm.visits[a]for a in required};require(all(visits.values()),'Claimed native entry not executed')
    vm.db.close()
    paths={ROOT/p for p in build['source_sha256']}|{ROOT/BUILD,ROOT/DATABASE,ROOT/build['package'],
        ROOT/build['combined_binary'],ROOT/build['extension_elf'],ROOT/build['extension_flat'],
        ROOT/'staging/native-music-stream/emulator-runtime.json'}
    paths.update(p for p in (ROOT/'staging/native-player-grid').iterdir()if p.is_file() and
                 p.name not in ['development-probe.json','previous-checkpoint.json'])
    for module in tuple(sys.modules.values()):
        name=getattr(module,'__file__',None)
        if name:
            path=Path(name).resolve()
            if path.is_file() and path.is_relative_to(ROOT/'scripts'):paths.add(path)
    paths.add(Path(__file__).resolve())
    proof={'updated_utc':datetime.now(timezone.utc).isoformat(),'MAIN_sha256':EXPECTED,
        'build_manifest':BUILD,'build_manifest_sha256':sha(BUILD),
        'source_sha256':{str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest()for p in sorted(paths)},
        'case_count':len(cases),'all_passed':True,'cases':cases,'load':loaded,'snapshot':snapshot,
        'original_Grid_event_entry_visits':visits,'original_Grid_writes':vm.page_writes,
        'original_kernel_wake_boundary_fixture':{'entry':'0x2fcf44','result':0,'requests':vm.wake_boundaries,
            'kernel_thread_or_notification_delivery_executed':False},
        'settings_fixture_closed_before_GUI':True,'settings_native_ready_byte_restored':True,
        'separate_CXX_heap_fixture':{'base':'0x08800000','bytes':0x400000,'all_guards_intact':True,
            'does_not_overlap_inherited_SQL_or_large_canvas_heap':True,'actual_free_RAM_claim':False},
        'all15_DB_rows_restored_in_memory':True,'original_SQL_statement_finalization':True,
        'database_sha256':database_sha,'database_backup_unchanged':True,
        'original_voice_RAM_and40_exports_retained_after_Grid_events':True,
        'only_three_exact_original_GUI_guard_words_change_conditional_initialized_data':True,
        'objects_holders_callbacks_resources_and_module_remain_pinned':True,
        'automatic_grid_population_executed':True,'actual_page_controller_switch_executed':False,
        'native_geometry_or_font_rendering_completed':False,'rendered_touchable_icon_verified':False,
        'geometry_failed_probe':'staging/native-player-grid/geometry-boundary-failure.json',
        'emulator_binding_version':unicorn.__version__,'emulator_native_version':list(unicorn.uc_version()),
        'guard_fault_controls':verify_guard_faults(),'device_io':False,'device_files_modified':False,
        'sounds_emitted':False,'device_install_candidate':False,'actual_package_acceptance_verified':False,
        'native_App_running_on_device':False,'phone_direct_music_verified':False,
        'limits':'Original HWID1352 SW8.00 loader executes resident player registration, then actual setting read/reset, '
        'CustomMainMenuGrid constructor and its automatic builder546878 make and parent a normal player Widget. '
        'Original setting read returns-1 when ready byteF06EF7 is0 and resets15 rows; positive0/1 controls use a '
        'synthetic lower2CAB14 persistent-record inventory and ready-byte fixture while original wrappers/copy execute. '
        'Real persistent setting19B and boot initialization unknown. Containing Page ctor under uninitialized settings '
        'resets15 three times; test reapplies selection via stock SQL setter afterwards. Grid mode0 populates15 '
        'records and19 children without changing DB. Grid is explicitly attached to a containing Page through stock API. '
        'Page/Grid/Widget numeric events and native coordinate translations reach loaded player twice. Frames, '
        'numeric0/1/2, enable0 and sound selector36 are explicit fixtures/requests; real touch classification, kernel '
        'event-loop/wake delivery and default click-sound wait are unproved. Original geometry API attempt faults '
        'at4DDDBC reading218 because F071E8+8 lacks its initialized context; saved partial probe is not a pass. '
        'No native layout/text/font rendering/display/main-page controller/root switch claim. Original voice '
        'RAM40 exports, code, full initialized regions allowing only three stock385450 once-words, and all allocation '
        'canaries retained; SQL15 rows restored, backup unchanged. Separate synthetic4MiB C++ heap is not actual '
        'available device RAM. GUI BSS-zero/VFP/timer/host SQLite/platform/cache/driver/kernel/audio API fixtures '
        'remain; record-count resource resolution is inherited and not actual boot-resource proof. Objects,module '
        'and callbacks stay pinned; sourceID9 stop/repeat/ownership, safe unload/reload, accepted modified '
        'VPM/SIG, native physical App, direct phone Bluetooth, WAV/kernel/DAC/speaker remain open. No device I/O.'}
    out=ROOT/'evidence/firmware-analysis/native-player-grid-emulation.json'
    out.write_text(json.dumps(proof,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({'evidence':str(out.relative_to(ROOT)),'groups':len(cases),
                      'dependencies':len(proof['source_sha256']),'all_passed':True,'device_io':False}),flush=True)


if __name__=='__main__':main()
