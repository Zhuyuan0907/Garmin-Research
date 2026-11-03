#!/usr/bin/env python3
"""Original embedded fonts, native Grid geometry/state refresh/player events.

No invented font metrics/glyphs, Widget frames, enable0 write or direct compiled
callback. The containing window/outer Grid frames, numeric events, kernel/audio
endpoints, DB/cache/driver/heap inventory and module timing remain fixtures.
"""
from datetime import datetime,timezone
import hashlib,json,struct,sys
from pathlib import Path
import unicorn
from analyze_native_sections import NativeImage,ROOT,EXPECTED
from analyze_native_loader import IMAGE,STUBS
from emulate_native_player_text import TextVM
from emulate_native_player_menu_selection import DATABASE,SQL_OUT,sha
from emulate_native_player_menu_loaded import PLAYER_ID
from emulate_native_vpm_filesystem import require
from emulate_native_sbc import verify_guard_faults

BUILD='staging/native-player-text/manifest.json'


def main():
    require(unicorn.__version__=='2.1.4' and unicorn.uc_version()==(2,1,33621247),'Use isolated Unicorn2.1.4')
    build=json.loads((ROOT/BUILD).read_text())
    for path,expected in build['source_sha256'].items():require(sha(path)==expected,'Build dependency changed '+path)
    database_sha=sha(DATABASE);vm=TextVM(NativeImage(),build);cases=[]
    print(json.dumps({'phase':'before_original_outer_loader'}),flush=True);load=vm.load()
    print(json.dumps({'phase':'original_outer_loader_returned'}),flush=True)
    oldram=struct.unpack_from('<I',(ROOT/build['original_binary']).read_bytes(),4)[0]
    voice=bytes(vm.uc.mem_read(IMAGE+12,oldram-12));exports=bytes(vm.uc.mem_read(STUBS,480))
    appearance_state=vm.symbol('native_player_appearance_state')
    require(bytes(vm.uc.mem_read(appearance_state,24))==b'\0'*24,'Updater diagnostics BSS not cleared')
    require(vm.word(0xf071f0)==0,'Expected uninitialized native font context')
    vm.invoke(0x4df249,());font_status=vm.invoke(0x4de237,(0,));fonts=vm.fonts()
    active=[r['index']for r in fonts if r['metadata_flags'][1]]
    require(font_status==0 and active==[3,4,5] and vm.word(0xf071f0)==0x14b5004 and
            all(r['context_error']=='0x0' and int(r['context'],16)for r in fonts),
            'Original embedded-only font initializer failed')
    glyphs=[]
    for index in active:
        context=int(fonts[index]['context'],16)
        result={hex(ord(c)):vm.invoke(0x26849f,(context,ord(c)))for c in 'Pi播放器'}
        glyphs.append({'font_index':index,'native_glyph_indices':result})
    require([r['native_glyph_indices']for r in glyphs]==[
        {'0x50':49,'0x69':74,'0x64ad':0,'0x653e':0,'0x5668':0},
        {'0x50':100,'0x69':0,'0x64ad':0,'0x653e':0,'0x5668':0},
        {'0x50':49,'0x69':74,'0x64ad':0,'0x653e':0,'0x5668':0}],
        'Native embedded glyph mapping differs from parsed cmap')
    cases.append({'name':'original_font_initializers_load_three_embedded_sfnt_fonts_and_native_glyph_queries','passed':True,
        'static_initializer':'0x4df248','runtime_initializer':'0x4de236','initializer_return':font_status,
        'test_requested_external_font_loading_parameter':0,'active_embedded_indices':active,
        'font_inventory':fonts,'current_context_record':hex(vm.word(0xf071f0)),
        'native_glyph_queries':glyphs,'original_query_entry':'0x26849e',
        'embedded_tables':'staging/native-player-text/embedded-font-tables.json',
        'fonts_metrics_or_glyph_success_hooked_or_fabricated':False,'CJK_glyphs_available_in_loaded_fonts':False,
        'external_fonts_or_real_boot_resource_inventory_loaded':False,
        'original_reserved_cache_pointer':'0x34fa3bc','cache_requested_bytes':0xc0000,
        'host_constructed_current_font_context':False})
    print(json.dumps({'case':cases[-1]['name'],'passed':True}),flush=True)
    vm.invoke(0x395981,());vm.init_DB_fixture()
    page=vm.invoke(0x3954cc,(0x7c4,));require(vm.invoke(0x5a2995,(page,))==page,'Containing Page ctor failed')
    vm.set_cell(12,PLAYER_ID,0);database_selected=list(vm.db.execute('SELECT id,icon,size FROM custom_table ORDER BY id'))
    grid=vm.invoke(0x3954cc,(0x420,));require(vm.invoke(0x546c95,(grid,0))==grid,'Original automatic Grid ctor failed')
    rows=vm.grid_rows(grid);chosen=rows[11];record=int(chosen['address'],16);widget=int(chosen['widget'],16)
    require(len(rows)==15 and vm.word(grid+0x7c)==19 and vm.word(widget+0x48)==grid and
            vm.word(record+0x14)==vm.symbol('native_player_menu_appearance') and
            vm.word(record+0x18)==0x13528000,'Native updater registration/automatic parenting failed')
    before_state=list(vm.uc.mem_read(widget+0xc8,3));before_rect=list(struct.unpack('<4I',vm.uc.mem_read(widget+0x20,16)))
    require(before_state==[1,4,4] and before_rect==[0,0,0,0],'Unexpected factory initial state/frame')
    vm.watch=(widget,widget+0x550);vm.page_writes=[];layouts=[];rect=SQL_OUT+0x500
    for frame in [[0,0,480,220],[40,30,360,180]]:
        vm.uc.mem_write(rect,struct.pack('<4I',*frame));write_start=len(vm.page_writes)
        vm.invoke(0x377ab9,(grid,rect,0,0),(0,0,0,0))
        # Virtual3 consumes a one-time dirty flag. Subsequent resize alone
        # does not re-run layout in this partial controller fixture. Stock
        # MainMenu refresh403DEE itself calls547020 directly; request that
        # original body for this second size rather than inventing a flag.
        direct_relayout=bool(layouts)
        if direct_relayout:vm.invoke(0x547021,(grid,))
        layouts.append({'outer_Grid_frame_supplied_by_test':frame,
            'original_relayout_body_requested_by_test':direct_relayout,
            'original_calculated_Widget_frame':list(struct.unpack('<4I',vm.uc.mem_read(widget+0x20,16))),
            'native_Widget_writes':vm.page_writes[write_start:]})
    require([r['original_calculated_Widget_frame']for r in layouts]==[[288,146,96,73],[216,120,72,60]],
            'Original geometry did not recompute actual cell position/sizes')
    require(all(any(0x20<=int(w['offset'],16)<0x30 for w in r['native_Widget_writes'])for r in layouts),
            'Native frame writes not observed')
    caption=vm.wide(vm.invoke(0x3927f5,(record+0x1c,)))
    require(caption=='Pi 播放器' and database_selected==list(vm.db.execute('SELECT id,icon,size FROM custom_table ORDER BY id')),
            'Original geometry changed selected DB/caption')
    cases.append({'name':'original_automatic_Grid_native_geometry_recomputes_player_frame_for_two_outer_sizes','passed':True,
        'Page':hex(page),'Grid':hex(grid),'Widget':hex(widget),'record':hex(record),'selected_cell':12,
        'row_count':15,'child_count':19,'caption':caption,'normal_mode':0,
        'factory_initial_state':before_state,'factory_initial_frame':before_rect,'layouts':layouts,
        'native_geometry_API':'0x377ab8','native_Grid_geometry_body':'0x547020',
        'stock_MainMenu_direct_relayout_caller_verified':'0x403dee',
        'GUI_resize_or_dirty_flag_notification_executed':False,
        'host_Widgets_frame_writes_or_geometry_success_hook':False,
        'updater_pointer':hex(vm.word(record+0x14)),'native_appearance_symbol':hex(vm.symbol('native_player_menu_appearance')),
        'DB_rows_preserved':True,'Containing_Page_still_requires_native_reselection_after_setting_failure':True,
        'actual_MainMenu_controller_or_root_installation_executed':False})
    print(json.dumps({'case':cases[-1]['name'],'passed':True}),flush=True)
    # Native state-refresh54A4EC invokes the registered updater. Its outputs
    # are stock default shared_ptr/CString objects left byte-identical by C.
    vm.invoke(0x54a4ed,(grid,));enabled=list(vm.uc.mem_read(widget+0xc8,3))
    require(enabled==[1,0,0] and vm.appearance_calls[-1]['caller']=='0x54a364' and
            vm.appearance_calls[-1]['returned_state']==0,'Stock state refresh did not enable player')
    vm.invoke(0x37707b,(page,grid));vm.invoke(vm.word(vm.word(page)+9*4),(page,1))
    vm.uc.mem_write(rect,struct.pack('<4I',0,0,480,272));vm.invoke(0x377ab9,(page,rect,0,0),(0,0,0,0))
    require(list(struct.unpack('<4I',vm.uc.mem_read(widget+0x20,16)))==[216,120,72,60],
            'Containing Page altered native calculated cell frame')
    vm.invoke(0x27abf9,(widget,0x36))
    x,y,width,height=struct.unpack('<4I',vm.uc.mem_read(widget+0x20,16))
    gx,gy,gw,gh=struct.unpack('<4I',vm.uc.mem_read(grid+0x20,16));center=[gx+x+width//2,gy+y+height//2]
    event=SQL_OUT+0x400;vm.uc.mem_write(event,b'\0'*64)
    def dispatch(action,point=None):
        p=point or center;vm.put(event+0x10,p[0]);vm.put(event+0x14,p[1]);vm.uc.mem_write(event+0x28,bytes([action]))
        a=len(vm.audio);n=len(vm.numeric_widget_inputs)
        returned=vm.invoke(vm.word(vm.word(page)+16),(page,event))
        require([vm.word(event+0x10),vm.word(event+0x14)]==p,'Original nested parents did not restore global point')
        inputs=[r for r in vm.numeric_widget_inputs[n:]if r['widget']==hex(widget)]
        return {'numeric_action':action,'global_point':p,'returned':hex(returned),
            'player_Widget_inputs':inputs,'Widget_state':list(vm.uc.mem_read(widget+0xc8,3)),
            'new_audio_API_requests':vm.audio[a:]}
    actions=[dispatch(a)for a in [0,1,2]]
    require([len(r['new_audio_API_requests'])for r in actions]==[0,0,2] and
            all(r['returned']==hex(widget) and len(r['player_Widget_inputs'])==1 and
                r['player_Widget_inputs'][0]['point']==[36,30]for r in actions),
            'Input at native computed geometry did not launch resident player')
    require(not vm.control_clicks and vm.uc.mem_read(widget+0x112,1)[0]==0,'Synthetic callback/Widget flag used')
    cases.append({'name':'native_Grid_state_updater_enables_player_and_native_calculated_hit_region_dispatches','passed':True,
        'original_state_refresh':'0x54a4ec','state_before':before_state,'state_after':enabled,
        'compiled_updater_called_through_original_factory_and_refresh':True,
        'host_called_compiled_updater_or_enable0_API_or_signal_directly':False,
        'Containing_Page_frame_requested_through_original_API':[0,0,480,272],
        'native_Widget_frame':[x,y,width,height],'outer_Grid_frame':[gx,gy,gw,gh],'center_computed_by_test':center,
        'actions':actions,'test_nondefault_sound_selector36_via_original_API':True,
        'physical_touch_classification_or_OS_event_delivery_executed':False,'Widget_flag112_remains0':True})
    print(json.dumps({'case':cases[-1]['name'],'passed':True}),flush=True)
    vm.invoke(vm.word(vm.word(page)+9*4),(page,0));hidden=dispatch(2)
    vm.invoke(vm.word(vm.word(page)+9*4),(page,1))
    # Negative control changes only the in-memory row context. The original
    # refresh still calls C; C returns disabled4 and the native setter applies it.
    vm.put(record+0x18,0xffffffff);vm.invoke(0x54a4ed,(grid,))
    require(list(vm.uc.mem_read(widget+0xc8,3))==[1,4,4] and vm.appearance_calls[-1]['returned_state']==4,
            'Unexpected-context updater control did not disable Widget')
    disabled=dispatch(2)
    vm.put(record+0x18,0x13528000);vm.invoke(0x54a4ed,(grid,))
    require(list(vm.uc.mem_read(widget+0xc8,3))==[1,0,0],'Restored native refresh did not enable Widget')
    outside=dispatch(2,[gx+gw,gy+gh]);resumed=dispatch(2)
    require(all(not r['new_audio_API_requests']for r in [hidden,disabled,outside]) and
            len(resumed['new_audio_API_requests'])==2,'Native visibility/context/outside control failed')
    require(all(r['stock_output_objects_byte_unchanged']for r in vm.appearance_calls) and
            not vm.appearance_pending,'Compiled updater altered stock outputs or did not return')
    updater_state=list(struct.unpack('<6I',vm.uc.mem_read(appearance_state,24)))
    require(updater_state[0]==4 and updater_state[1]==1 and updater_state[2]==0x13528000,'Updater diagnostics differ')
    cases.append({'name':'native_visibility_unexpected_context_disabled_and_outside_Grid_controls_restore_player','passed':True,
        'hidden':hidden,'unexpected_context_disabled':disabled,'outside_Grid_inside_Page':outside,'restored':resumed,
        'test_modified_in_memory_row_context_only_then_restored':True,'DB_catalog_original_context_unchanged':True,
        'native_appearance_calls':vm.appearance_calls,'compiled_updater_state':updater_state,
        'stock_output_objects_byte_unchanged':True,'negative_context_return4_applied_by_native_Widget_setter':True})
    print(json.dumps({'case':cases[-1]['name'],'passed':True}),flush=True)
    for id,icon,size in vm.database_before:vm.set_cell(id,icon,size)
    require(list(vm.db.execute('SELECT id,icon,size FROM custom_table ORDER BY id'))==vm.database_before and
            all(r['closed']for r in vm.statements.values()) and sha(DATABASE)==database_sha,
            'DB restore/finalize/backup integrity failed')
    require(not vm.invalid_accesses and not vm.control_clicks,'Full run memory fault or fixture callback')
    require(bytes(vm.uc.mem_read(IMAGE+12,oldram-12))==voice and bytes(vm.uc.mem_read(STUBS,480))==exports,
            'Original voice RAM40 exports changed after font/GUI/events')
    snapshot=vm.finish();require(snapshot['native_menu_state']==[1,1,2,0x13528000,2,2],'Player state differs')
    required=[0x4df248,0x4de236,0x265f16,0x4de0e0,0x26707a,0x266d0e,0x26849e,0x140878,
        0x5a2994,0x546c94,0x546878,0x547020,0x377ab8,0x4ddd60,0x54a4ec,0x54a2fa,
        0x30c91a,0x5496ba,0x376bf6,0x27a502,0x31649a]
    visits={hex(a):vm.visits[a]for a in required};require(all(visits.values()),'Claimed native entry not executed')
    vm.db.close()
    paths={ROOT/p for p in build['source_sha256']}|{ROOT/BUILD,ROOT/DATABASE,ROOT/build['package'],
        ROOT/build['combined_binary'],ROOT/build['extension_elf'],ROOT/build['extension_flat'],
        ROOT/'staging/native-music-stream/emulator-runtime.json'}
    paths.update((ROOT/'staging/native-player-text').glob('*preflight.json'))
    for name in ['embedded-font-tables.json','inventory-pointer-references.json','context-literal-loads.json',
        'first-native-geometry-return.json','first-native-geometry-return-metadata.json','source-at-first-geometry-return.py',
        'first-state-refresh-return.json','first-state-refresh-return-metadata.json','source-at-first-state-refresh-return.py',
        'paint-no-pixels-probe.json','paint-no-pixels-metadata.json','source-at-paint-no-pixels.py','glyph-development-probe.json',
        'layout-assertion-failure.json','integration-source-at-layout-assertion.py','layout-development-probe.json',
        'containing-page-heap-failure.json','integration-source-at-containing-page-heap-failure.py','vm-source-at-containing-page-heap-failure.py']:
        paths.add(ROOT/'staging/native-player-text'/name)
    paths.add(ROOT/'scripts/analyze_native_player_fonts.py')
    for module in tuple(sys.modules.values()):
        name=getattr(module,'__file__',None)
        if name:
            path=Path(name).resolve()
            if path.is_file() and path.is_relative_to(ROOT/'scripts'):paths.add(path)
    paths.add(Path(__file__).resolve())
    proof={'updated_utc':datetime.now(timezone.utc).isoformat(),'MAIN_sha256':EXPECTED,'build_manifest':BUILD,
        'build_manifest_sha256':sha(BUILD),'source_sha256':{str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest()for p in sorted(paths)},
        'case_count':len(cases),'all_passed':True,'cases':cases,'load':load,'snapshot':snapshot,
        'native_font_geometry_state_entry_visits':visits,'original_font_calls':vm.font_calls,
        'original_font_allocator_post_allocate_records':vm.font_allocator_records,
        'mapped_startup_zero_pages':vm.zero_pages,'font_metrics_or_glyphs_mocked':False,
        'original_voice_RAM_and40_exports_retained_after_font_geometry_state_events':True,
        'only_three_exact_original_GUI_guard_words_change_conditional_initialized_data':True,
        'native_Widget_geometry_executed':True,'native_normal_state_refresh_executed':True,
        'actual_page_controller_switch_executed':False,'real_boot_font_inventory_or_CJK_loaded':False,
        'actual_input_classification_executed':False,'real_rendering_or_display_verified':False,
        'paint_probe':'staging/native-player-text/paint-no-pixels-probe.json',
        'original_kernel_wake_boundary_fixture':{'entry':'0x2fcf44','result':0,'requests':vm.wake_boundaries,'actual_kernel_wake_delivery':False},
        'all15_DB_rows_restored_in_memory':True,'original_SQL_statement_finalization':True,
        'database_sha256':database_sha,'database_backup_unchanged':True,
        'objects_fonts_contexts_handles_callbacks_module_remain_pinned':True,
        'emulator_binding_version':unicorn.__version__,'emulator_native_version':list(unicorn.uc_version()),
        'guard_fault_controls':verify_guard_faults(),'device_io':False,'device_files_modified':False,'sounds_emitted':False,
        'device_install_candidate':False,'actual_package_acceptance_verified':False,
        'native_App_running_on_device':False,'phone_direct_music_verified':False,
        'limits':'Exact HWID1352 SW8.00 original outer/module loading registers compiled player and recovered state updater. '
        'Stock font static/runtime initializers create13 records and load3 embedded sfnt fonts with r0=0 external-font '
        'parameter; actual startup sequence/resource inventory unknown. Native glyph queries match file cmap: Pi available '
        'in fonts3/5, Chinese caption characters absent. No fabricated font metrics/current context/glyph success. '
        'Original automatic Grid makes player Widget, geometry377AB8/547020 computes two layouts from test outerframes '
        'with explicit stock547020 relayout request for the second size after virtual3 clears its dirtyflag; '
        'actual controller resize/dirty notification is not run. '
        'without host writing Widgetframe. Compiled updater preserves original default output objects; original '
        'factory/refresh invokes it, refresh applies enabled0 or disabled4 for context control via native setter. '
        'Containing Page/Grid attach, outer window frames/numeric0/1/2 and sound36 remain explicit test requests. '
        'Events at native calculated center reach player twice; not real physical input/default click wait/UI loop. '
        'Kernel wake is result0 boundary. Prior development Grid paint returned but canvas0bytes changed/no fontcalls; '
        'not rendering/display proof. Actual Chinese/external fonts, nonempty icons/materials, clipping/canvas paint '
        'environment, normal MainMenu controller/root switch are open. DBready/host SQLite/cache/driver/heap/kernel/audio '
        'API/timer/VFP/startupzero are fixtures. Font cache uses stock requestedC0000 bytes/static34FA3BC, other font '
        'allocations use original140878 plus inherited guarded handle inventory; font handles retain original live '
        'lock1/pinned ownership. GUI calloc/aligned allocations use separate4MiB virtual raw arena, with unchanged '
        'length/alignment ABI/canaries; this is no physical RAM availability proof. All non-font outer/file/handle/code guards retained independently. Original voice '
        'RAM40 exports/private12/player2/code/full initialized regions with only three exact native once-words/canaries '
        'retained, SQL15 rows restored/backup unchanged. State updater diagnostics are private, no stable App SDK. '
        'EMULATION-ONLY package updatesDLLIMG/DLLINFO only, preserves othermembers/SIG, acceptance not proven. '
        'Native actual App/direct Bluetooth/audio kernel/DAC/speaker/sourceID9 lifecycle/unload/reload remain open. '
        'No device I/O or sounds.'}
    out=ROOT/'evidence/firmware-analysis/native-player-text-emulation.json'
    out.write_text(json.dumps(proof,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({'evidence':str(out.relative_to(ROOT)),'groups':len(cases),'dependencies':len(proof['source_sha256']),
                      'all_passed':True,'device_io':False}),flush=True)


if __name__=='__main__':main()
