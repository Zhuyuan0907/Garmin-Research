#!/usr/bin/env python3
"""Original corrected resource player, stock GIR decoding and native icon paint; offline.

Uses original native rectangle/text/cache/blit instructions, not host-created
caption pixels. Test frames, a white background and requested clips are
explicit inputs. No physical display, UI thread/root or installation claim.
"""
from datetime import datetime,timezone
from pathlib import Path
import hashlib,json,struct,sys
import unicorn
from analyze_native_sections import NativeImage,ROOT,EXPECTED
from analyze_native_loader import IMAGE,STUBS
BUILD='staging/native-player-resources/manifest.json'
from probe_native_player_resources import ResourceVM,STAGE,GIR,INPUT
from probe_native_player_resource_cache import ResourceCacheVM
from emulate_native_player_menu_selection import SQL_OUT,DATABASE,sha
from emulate_native_player_menu_loaded import PLAYER_ID
from emulate_native_vpm_filesystem import require


def main():
    require(unicorn.__version__=='2.1.4' and unicorn.uc_version()==(2,1,33621247),'Use isolated Unicorn2.1.4')
    build=json.loads((ROOT/BUILD).read_text())
    for path,expected in build['source_sha256'].items():require(sha(path)==expected,'Frozen build source changed '+path)
    database_sha=sha(DATABASE)
    vm=ResourceCacheVM(NativeImage(),build);cases=[];result={'phase':'before_original_outer_loader'}
    print(json.dumps(result),flush=True)
    try:
        load=vm.load();print(json.dumps(dict(phase='original_outer_loader_returned')),flush=True)
        vm.invoke(0x395981,());registration=vm.register_stock_GIR()
        oldram=struct.unpack_from('<I',(ROOT/build['original_binary']).read_bytes(),4)[0]
        voice=bytes(vm.uc.mem_read(IMAGE+12,oldram-12));exports=bytes(vm.uc.mem_read(STUBS,480))
        vm.external_IO_active=True
        vm.invoke(0x4df249,());require(vm.invoke(0x4de237,(1,))==0,'Native font initialization failed')
        fonts=vm.fonts();active=[r['index']for r in fonts if r['metadata_flags'][1]]
        require(active==[0,1,2,3,4,5,7,8,9,10,12],'Loaded fonts differ')
        context_map={r['context']:r['index']for r in fonts}
        vm.invoke(0x395981,());vm.init_DB_fixture()
        page=vm.invoke(0x3954cc,(0x7c4,));vm.invoke(0x5a2995,(page,));vm.set_cell(12,PLAYER_ID,0)
        grid=vm.invoke(0x3954cc,(0x420,));vm.invoke(0x546c95,(grid,0));rows=vm.grid_rows(grid)
        widget=int(rows[11]['widget'],16);rect=SQL_OUT+0x500;color=SQL_OUT+0x550
        vm.uc.mem_write(rect,struct.pack('<4I',0,0,480,220));vm.invoke(0x377ab9,(grid,rect,0,0),(0,0,0,0))
        vm.invoke(0x54a4ed,(grid,));vm.invoke(vm.word(vm.word(grid)+9*4),(grid,1))
        manager=vm.invoke(0x393a2d,(0,));canvas=vm.word(manager+0x44)
        tree=vm.tree(grid);selected=next(r for r in tree['children']if r['object']==hex(widget))
        label=next(r for r in selected['children']if r['vtable']=='0xc19058')
        label_object=int(label['object'],16)
        caption=vm.wide(vm.invoke(0x3927f5,(label_object+0x218,)))
        require(caption=='Pi 播放器' and selected['frame']==[288,146,96,73] and label['frame']==[2,56,91,19],
            'Native caption/Label geometry differs')
        candidates=json.loads((ROOT/'staging/native-player-external-fonts/candidate-inventory.json').read_text())
        preflight=json.loads((ROOT/'staging/native-player-external-fonts/byte-transform-path-preflight.json').read_text())
        by_name={Path(r['file']).name:r for r in candidates['files']}
        native_names={r['index']:r['filename']for r in preflight['descriptors']}
        matches=[]
        for row in vm.glyph_calls:
            if row['unicode'] not in map(ord,'播放器') or not row['native_returned_glyph_index']:continue
            index=context_map[row['context']];require(index in native_names,'CJK selected an unexpected embedded font')
            expected=by_name[native_names[index]]['cmap_glyph_queries'][hex(row['unicode'])]
            require(any(e['glyph']==row['native_returned_glyph_index']for e in expected),'Native caption fallback glyph differs')
            matches.append(dict(**row,font_index=index,independent_backup_cmap_matches=True))
        require(set(r['unicode']for r in matches)==set(map(ord,'播放器')) and not vm.pending_glyph_calls,
            'Caption geometry did not execute native CJK glyph lookups')
        require(any(r['entry']=='0x4de302'for r in vm.native_raster_calls) and
            any(r['entry']=='0x26659e'for r in vm.native_raster_calls) and
            any(r['entry']=='0x13cf46'for r in vm.native_raster_calls),'Actual native glyph rasterization path absent')
        cases.append(dict(name='original_loaded_player_Label_native_caption_geometry_CJK_fallback_and_rasterizer',passed=True,
            Grid=hex(grid),Widget=hex(widget),Label=label,caption=caption,active_font_indices=active,
            actual_native_CJK_query_results=matches,original_raster_entries=['0x4de302','0x26659e','0x13cf46'],
            actual_native_raster_flags8_path_not_unexecuted_14EC9C_branch=True,
            host_supplied_glyph_indices_metrics_or_caption_pixels=False,outer_Grid_frame_fixture=[0,0,480,220],
            real_root_controller_resize_and_boot_resource_initialization_executed=False))
        print(json.dumps(dict(case=cases[-1]['name'],passed=True)),flush=True)
        buffers=[p for p,e in vm.raw_allocations.items()if e['length']==480*272*2]
        require(len(buffers)==1,'Native canvas allocation differs');pixels=buffers[0];length=480*272*2
        vm.pixel_span=(pixels,pixels+length)
        vm.paint_entries.update([0x549baa,0x3766e4,0x3857b0,0x2db976,0x6f63f4,0x43866e])
        def white_background():
            vm.invoke(vm.word(vm.word(canvas)+10*4),(canvas,))
            require(list(struct.unpack('<4i',vm.uc.mem_read(canvas+0x3c,16)))==[0,0,480,272],'Native reset clip failed')
            vm.uc.mem_write(rect,struct.pack('<4I',0,0,480,272));vm.uc.mem_write(color,b'\xff'*4)
            vm.invoke(0x2db88b,(canvas,rect,color))
            require(bytes(vm.uc.mem_read(pixels,length))==b'\xff'*length,'Original pixel driver failed to draw white background')
        def paint(clip=None):
            white_background()
            if clip is not None:
                vm.uc.mem_write(rect,struct.pack('<4i',*clip))
                vm.invoke(vm.word(vm.word(canvas)+11*4),(canvas,rect))
            actual_clip=list(struct.unpack('<4i',vm.uc.mem_read(canvas+0x3c,16)))
            before=bytes(vm.uc.mem_read(pixels,length));call_start=len(vm.paint_calls);write_start=vm.pixel_write_count
            vm.paint_active=True;vm.invoke(vm.word(vm.word(grid)+8),(grid,canvas));vm.paint_active=False
            after=bytes(vm.uc.mem_read(pixels,length));values=struct.unpack('<130560H',after)
            changed=[(n%480,n//480)for n,v in enumerate(values)if v!=0xffff]
            require(list(struct.unpack('<4i',vm.uc.mem_read(canvas+0x3c,16)))==actual_clip,
                'Native traversal did not restore outer clip')
            bounds=None if not changed else [min(x for x,y in changed),min(y for x,y in changed),
                max(x for x,y in changed),max(y for x,y in changed)]
            return dict(explicit_clip_request=clip,original_canvas_clip=actual_clip,
                changed_bytes=sum(a!=b for a,b in zip(before,after)),changed_pixel_count=len(changed),changed_bounds=bounds,
                original_pixel_write_count=vm.pixel_write_count-write_start,canvas_sha256=hashlib.sha256(after).hexdigest(),
                native_paint_calls=vm.paint_calls[call_start:],outer_clip_restored=True),after,changed
        full,fullraw,fullpoints=paint()
        require(full['changed_pixel_count']>213 and full['changed_bytes']>426,
            'Native icon adds no pixels to the caption')
        require(all(0<=x<480 and 0<=y<272 for x,y in fullpoints),'Pixels escaped canvas')
        require(any(r['entry']=='0x3857b0'for r in full['native_paint_calls']) and
            any(r['entry']=='0x6f63f4'for r in full['native_paint_calls']),'Native Label/cache/blit path absent')
        (STAGE/'loaded-canvas.bin').write_bytes(fullraw)
        cases.append(dict(name='corrected_player_ResourceRef_original_GIR_image_and_caption_native_Grid_paint',passed=True,
            background_original_entry='0x2db88a',background_RGBA_test_input=[255]*4,
            canvas=hex(canvas),pixel_buffer=hex(pixels),raw_canvas_artifact='staging/native-player-rendering/loaded-canvas.bin',
            paint=full,host_wrote_pixel_buffer=False,actual_device_framebuffer_or_screen=False))
        print(json.dumps(dict(case=cases[-1]['name'],passed=True)),flush=True)
        player_area,playerraw,playerpoints=paint(selected['frame'])
        require(playerpoints and set(playerpoints)=={p for p in fullpoints if 288<=p[0]<384 and 146<=p[1]<219},
            'Player-only clip differs from original whole Grid pixels')
        require(any(r['entry']=='0x3620e4'for r in player_area['native_paint_calls']) and
            any(r['entry']=='0x3857b0'for r in player_area['native_paint_calls']),
            'Player clip did not paint both original Image and Label')
        cases.append(dict(name='native_player_icon_and_caption_only_clip_matches_full_Grid_subset',passed=True,
            paint=player_area,native_Widget_frame=selected['frame'],
            icon=next(r for r in selected['children']if r['vtable']=='0xc09e34'),Label=label,
            all_player_pixels_match_original_full_Grid=True))
        print(json.dumps(dict(case=cases[-1]['name'],passed=True)),flush=True)
        clipped,clipraw,clippoints=paint([330,178,8,4])
        require(clippoints and all(330<=x<338 and 178<=y<182 for x,y in clippoints) and
            set(clippoints)=={p for p in fullpoints if 330<=p[0]<338 and 178<=p[1]<182},'Original clipping changed/escaped caption subset')
        fullvalues=struct.unpack('<130560H',fullraw);clipvalues=struct.unpack('<130560H',clipraw)
        require(all(clipvalues[y*480+x]==fullvalues[y*480+x]for x,y in clippoints),'Clipped glyph colors differ')
        cases.append(dict(name='original_canvas_clip_keeps_exact_native_icon_caption_subset_and_colors',passed=True,
            paint=clipped,whole_caption_reference_pixels=full['changed_pixel_count'],all_changed_pixels_inside_requested_clip=True,
            clipped_pixels_and_native_antialias_values_equal_full_caption_subset=True))
        print(json.dumps(dict(case=cases[-1]['name'],passed=True)),flush=True)
        outside,outsideraw,outsidepoints=paint([0,0,20,20]);restored,restoredraw,restoredpoints=paint()
        require(not outsidepoints and outside['original_pixel_write_count']==0 and restoredraw==fullraw,'Outside clip or native repaint failed')
        require(not vm.audio and not vm.control_clicks,'Painting unexpectedly activated audio/callback fixture')
        cases.append(dict(name='outside_clip_no_pixel_or_audio_work_and_reset_repaint_byte_identical',passed=True,
            outside=outside,repaint=restored,caption_canvas_byte_identical_after_clip_restore=True,
            no_audio_requests_during_paint=True,synthetic_fixture_callbacks_executed=False))
        print(json.dumps(dict(case=cases[-1]['name'],passed=True)),flush=True)
        vm.invoke(0x37707b,(page,grid,0,0));vm.invoke(vm.word(vm.word(page)+9*4),(page,1))
        vm.uc.mem_write(page+0x20,struct.pack('<4I',0,0,480,272));vm.invoke(0x27abf9,(widget,0x36))
        event=SQL_OUT+0x400;vm.uc.mem_write(event,b'\0'*64);vm.put(event+0x10,336);vm.put(event+0x14,182)
        actions=[]
        for action in [0,1,2]:
            vm.uc.mem_write(event+0x28,bytes([action]));start=len(vm.audio)
            returned=vm.invoke(vm.word(vm.word(page)+16),(page,event))
            actions.append(dict(action=action,returned=hex(returned),new_audio_API_requests=vm.audio[start:]))
        require([len(r['new_audio_API_requests'])for r in actions]==[0,0,2] and not vm.control_clicks,
            'Native player events failed after rendering')
        cases.append(dict(name='native_parent_and_numeric_player_events_retained_after_software_rendering',passed=True,
            actions=actions,Containing_Page_frame_test_input=[0,0,480,272],numeric_point_test_input=[336,182],
            original_parent_API_arguments=[page,grid,0,0],actual_touch_kernel_delivery_and_speaker_executed=False))
        print(json.dumps(dict(case=cases[-1]['name'],passed=True)),flush=True)
        for id,icon,size in vm.database_before:vm.set_cell(id,icon,size)
        require(list(vm.db.execute('SELECT id,icon,size FROM custom_table ORDER BY id'))==vm.database_before and
            all(r['closed']for r in vm.statements.values()) and sha(DATABASE)==database_sha,'DB guards failed')
        require(bytes(vm.uc.mem_read(IMAGE+12,oldram-12))==voice and bytes(vm.uc.mem_read(STUBS,480))==exports,
            'Original whole voice RAM or40 exports changed')
        require(not vm.invalid_accesses and not vm.pending_glyph_calls,'Native memory fault or unfinished glyph lookup')
        require(bytes(vm.uc.mem_read(GIR,len(vm.resource_bytes)))==vm.resource_bytes,'Readonly resource bytes changed')
        snapshot=vm.finish();vm.db.close()
        paths={ROOT/BUILD,ROOT/DATABASE,ROOT/build['package'],ROOT/build['combined_binary'],ROOT/build['extension_elf'],
            ROOT/build['extension_flat'],ROOT/'staging/native-music-stream/emulator-runtime.json'}
        paths.update(ROOT/p for p in build['source_sha256']);paths.update(vm.backup_paths[key]for key in vm.raw_font_sources)
        for name in ['candidate-inventory.json','byte-transform-path-preflight.json']:
            paths.add(ROOT/'staging/native-player-external-fonts'/name)
        paths.update(STAGE/name for name in ['resource-ABI-and-MainMenu-preflight.json','loaded-canvas.bin',
            'resource-cache-and-MainMenu-caller-preflight.json'])
        paths.add(ROOT/'evidence/firmware-analysis/main_02bd.bin')
        for module in tuple(sys.modules.values()):
            name=getattr(module,'__file__',None)
            if name:
                path=Path(name).resolve()
                if path.is_file() and path.is_relative_to(ROOT/'scripts'):paths.add(path)
        paths.add(Path(__file__).resolve())
        proof=dict(updated_utc=datetime.now(timezone.utc).isoformat(),MAIN_sha256=EXPECTED,build_manifest=BUILD,
            build_manifest_sha256=sha(BUILD),source_sha256={str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest()for p in sorted(paths)},
            case_count=len(cases),all_passed=True,cases=cases,load=load,snapshot=snapshot,font_inventory=fonts,
            native_tree=tree,native_glyph_queries_with_results=vm.glyph_calls,native_raster_calls=vm.native_raster_calls,
            original_voice_whole_RAM_and40_exports_retained=True,native_software_canvas_pixels_verified=True,native_nonempty_icon_rendering_verified=True,
            original_stock_GIR_registration=registration,readonly_stock_GIR_unchanged=bytes(vm.uc.mem_read(GIR,len(vm.resource_bytes)))==vm.resource_bytes,
            resource_calls=vm.resource_calls,resource_mapping_input_bytes=len(vm.resource_bytes),resource_mapping_directory_bytes=vm.resource_directory_bytes,
            original_resource_stream_buffer_heap_requests=vm.resource_heap_requests,
            resource_mapping_is_explicit_fixture_not_recovered_boot=True,
            original_native_glyph_rasterization_and_cached_Label_blit_executed=True,
            glyph_metrics_indices_or_caption_pixels_mocked=False,host_wrote_pixel_buffer=False,
            actual_display_framebuffer_submission_verified=False,actual_UI_thread_root_touch_verified=False,
            eight_external_font_streams_still_resident=True,raw_font_backup_and_DB_unchanged=True,
            device_io=False,sounds_emitted=False,device_install_candidate=False,actual_package_acceptance_verified=False,
            native_App_running_on_device=False,phone_direct_music_verified=False,
            emulator_binding_version=unicorn.__version__,emulator_native_version=list(unicorn.uc_version()),
            limits='Original software canvas pixels and native caption rasterization are proven offline with explicit white background/clips, Grid/Page frames, numeric events and file/DB/heap/kernel/audio boundaries. Corrected hash32 resources borrow one stock64x64 MainMenu icon; no custom music icon or actual boot mapping claim. No physical framebuffer/display/UI thread/root/boot/input/DAC/phone-direct audio/accepted package installation, general-menu App or safe source/module/font-stream release verified.')
        target=ROOT/'evidence/firmware-analysis/native-player-resources-emulation.json'
        target.write_text(json.dumps(proof,ensure_ascii=False,indent=2)+'\n')
        print(json.dumps(dict(evidence=str(target.relative_to(ROOT)),groups=len(cases),dependencies=len(paths),all_final_guards_passed=True)),flush=True)
    except Exception as error:
        failure=dict(updated_utc=datetime.now(timezone.utc).isoformat(),error=str(error),completed_groups=cases,
            full_final_guard_pass=False,recent=list(vm.recent),invalid_accesses=vm.invalid_accesses,
            native_glyph_calls=vm.glyph_calls,native_raster_calls=vm.native_raster_calls,
            source_sha256_before_exit=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            conditional_writes=vm.conditional_region_writes,device_io=False,sounds_emitted=False)
        failure['resource_heap_requests']=vm.resource_heap_requests
        (STAGE/'integration-failure.json').write_text(json.dumps(failure,ensure_ascii=False,indent=2)+'\n')
        print(json.dumps(dict(error=str(error),completed_groups=len(cases),final_guards_passed=False)),flush=True)
        raise


if __name__=='__main__':main()
