#!/usr/bin/env python3
"""Audit original native caption pixels, clipping, guards and physical limits."""
from datetime import datetime,timezone
from pathlib import Path
import base64,hashlib,json,re,struct
from analyze_native_sections import ROOT,EXPECTED
from check_native_music_stream_checkpoint import read,sha,artifacts


def main():
    state,task,public=read('evidence/deep-research-state.json'),read('evidence/task-state.json'),read('reports/findings.json')
    report=(ROOT/'reports/nuvi2565RT.html').read_text();findings=state['native_app_music']['static_findings']
    item=findings['native_player_rendering'];proof=read(item['evidence']);build=read(proof['build_manifest'])
    artifacts(build)
    for path,expected in proof['source_sha256'].items():assert sha(path)==expected,path
    previous=read('staging/native-player-rendering/previous-checkpoint.json')
    before,prior=read(previous['state']),read(previous['audit'])
    for name,value in before['native_app_music']['static_findings'].items():assert findings[name]==value,name
    names=['native_voice_registry','native_voice_package_reads','native_voice_selection','native_voice_outer',
        'native_voice_compatibility','native_music_endpoint','native_music_configuration_gate','native_music_policy',
        'native_music_dispatch','native_l2cap_send','native_music_reply','native_music_loaded','native_music_stream',
        'native_music_runtime','native_music_ready','native_music_continuous','native_player_menu','native_player_menu_loaded',
        'native_player_menu_selection','native_player_widget','native_player_page','native_player_grid','native_player_text',
        'native_player_external_fonts']
    counts=[]
    for name in names:
        old=read(findings[name]['evidence']);assert sha(findings[name]['evidence'])==findings[name]['evidence_sha256'],name
        for path,expected in old['source_sha256'].items():assert sha(path)==expected,path
        counts.append(old['case_count'])
    fontproof=read(findings['native_player_external_fonts']['evidence'])
    for path,expected in fontproof['source_sha256'].items():
        if path.startswith('backups/'):
            assert proof['source_sha256'][path]==expected and sha(path)==expected,path
    preparation,caption,clipping,controls,event=proof['cases'];full=caption['paint'];clip=clipping['paint']
    raw=(ROOT/caption['raw_canvas_artifact']).read_bytes();values=struct.unpack('<130560H',raw)
    points={(n%480,n//480)for n,v in enumerate(values)if v!=0xffff}
    subset={p for p in points if 330<=p[0]<338 and 178<=p[1]<182}
    bounds=[min(x for x,y in points),min(y for x,y in points),max(x for x,y in points),max(y for x,y in points)]
    glyphs=preparation['actual_native_CJK_query_results'];expected={ord('播'):13358,ord('放'):13503,ord('器'):9705}
    preflight=read('staging/native-player-rendering/stock-draw-preflight.json')
    for path,expected_sha in preflight['source_sha256'].items():assert sha(path)==expected_sha,path
    zero=read('staging/native-player-rendering/zero-background-development-probe.json')
    failed=read('staging/native-player-rendering/raster-branch-assertion-failure-metadata.json')
    for name in ['zero-background-development-metadata.json','loaded-development-metadata.json']:
        metadata=read('staging/native-player-rendering/'+name)
        assert sha(metadata['source'])==metadata['source_sha256'] and sha(metadata['probe'])==metadata['probe_sha256']
        assert not metadata['full_integration_checkpoint'] and not metadata['final_whole_RAM_region_and_ownership_checks_executed']
    load,snapshot=proof['load'],proof['snapshot'];runtime=read('staging/native-music-stream/emulator-runtime.json')
    raster_entries={r['entry']for r in proof['native_raster_calls']}
    preview=(ROOT/item['caption_preview']).read_bytes()
    embedded=base64.b64decode(re.search(r'<figure><img[^>]+src="data:image/png;base64,([^"]+)"',report)[1])
    writes=[dict(address=hex(a),word_before=0,word_after=1,writer_PC='0x385450',
        original_instruction_executed=True,guest_memory_rewritten_by_test=False)for a in [0x551c80c,0x551c7f4,0x551c7f8]]
    source=(ROOT/'scripts/emulate_native_player_rendering_integration.py').read_text()
    vm_source=(ROOT/'scripts/probe_native_player_rendering.py').read_text()
    checks={
        'five_complete_groups_exact_MAIN_and_source_artifact_hashes':proof['MAIN_sha256']==build['MAIN_sha256']==EXPECTED and
            proof['all_passed'] and proof['case_count']==len(proof['cases'])==5 and all(r['passed']for r in proof['cases']) and
            sha(item['evidence'])==item['evidence_sha256'] and sha(proof['build_manifest'])==proof['build_manifest_sha256'] and
            item['source_artifact_count']==len(proof['source_sha256'])==106,
        'original_outer_loader_voice40_private12_player2_reserved_module_retained':
            load['native_readback_bytes']==build['combined_file_bytes'] and load['native_readback_sha256']==build['combined_sha256'] and
            load['original_loader_result']==load['original_control_result']==11 and load['entry_events'][0]['from_original_loader'] and
            load['install_callers'][0]['inside_loaded_component'] and all(load['native_file_callback_entries'].values()) and
            load['original40_and_original_runtime_preserved'] and load['native_private12_and_player2_tables_match'] and
            len(build['private_api'])==12 and len(build['player_api'])==2 and proof['original_voice_whole_RAM_and40_exports_retained'],
        'native_Label_caption_geometry_and_CJK_indices_match_original_DFHei':
            preparation['caption']=='Pi 播放器' and preparation['Label']['vtable']=='0xc19058' and
            preparation['Label']['paint']=='0x3857b1' and preparation['Label']['frame']==[2,31,91,11] and
            preparation['outer_Grid_frame_fixture']==[0,0,480,220] and set(r['unicode']for r in glyphs)==set(expected) and
            all(r['font_index']==2 and r['native_returned_glyph_index']==expected[r['unicode']] and
                r['independent_backup_cmap_matches'] and r['original_entry']=='0x26849e'for r in glyphs) and
            not preparation['host_supplied_glyph_indices_metrics_or_caption_pixels'],
        'actual_original_raster_flags8_path_not_assumed_14EC9C_branch':
            {'0x4dd93e','0x4de302','0x26659e','0x13cf46','0x13d850','0x1370fa'}.issubset(raster_entries) and
            '0x14ec9c' not in raster_entries and any(r['arguments'][2]==8 for r in proof['native_raster_calls']if r['entry']=='0x26659e') and
            preparation['actual_native_raster_flags8_path_not_unexecuted_14EC9C_branch'] and
            preflight['native_font_render_flags8_branch']=='0x2665d0 -> 0x13cf46',
        'ten_bounded_stock_draw_paths_and_canvas_clipping_recovered':
            preflight['MAIN_sha256']==EXPECTED and preflight['complete_bounded_CFG_count']==10 and
            all(not r['unresolved_exits']and not r['instruction_limit_reached']for r in preflight['functions'].values()) and
            preflight['Grid_normal_mode_branches_to_original_child_painter']=='0x549f18 -> 0x3766e4' and
            preflight['base_child_paint_requires_positive_clipped_width_and_height'] and preflight['base_calls_child_virtual_slot2'],
        'original_white_background_and_Label_cache_blit_no_host_caption_pixels':
            caption['background_original_entry']=='0x2db88a' and caption['background_RGBA_test_input']==[255]*4 and
            not proof['host_wrote_pixel_buffer'] and not proof['glyph_metrics_indices_or_caption_pixels_mocked'] and
            any(r['entry']=='0x3857b0'for r in full['native_paint_calls']) and any(r['entry']=='0x6f63f4'for r in full['native_paint_calls']) and
            'vm.invoke(0x2db88b,(canvas,rect,color))' in source and 'uc.mem_write(pixels' not in source+vm_source and
            proof['native_software_canvas_pixels_verified'] and proof['original_native_glyph_rasterization_and_cached_Label_blit_executed'],
        'raw_captured_canvas213_pixels426_bytes_exact_bounds_inside_Widget':
            len(raw)==480*272*2 and len(points)==full['changed_pixel_count']==213 and full['changed_bytes']==426 and
            full['changed_bounds']==bounds==[318,177,351,185] and full['canvas_sha256']==hashlib.sha256(raw).hexdigest() and
            all(288<=x<384 and 146<=y<219 for x,y in points) and full['original_pixel_write_count']==213,
        'native_clip_exact29_pixel_subset_colors_and_outer_clip_restoration':
            clip['explicit_clip_request']==clip['original_canvas_clip']==[330,178,8,4] and
            len(subset)==clip['changed_pixel_count']==29 and clip['changed_bounds']==[330,178,337,181] and
            clip['outer_clip_restored'] and clipping['all_changed_pixels_inside_requested_clip'] and
            clipping['clipped_pixels_and_native_antialias_values_equal_full_caption_subset'],
        'outside_clip_zero_writes_and_repaint_exact_caption_without_audio':
            controls['outside']['changed_pixel_count']==controls['outside']['changed_bytes']==controls['outside']['original_pixel_write_count']==0 and
            controls['repaint']['canvas_sha256']==full['canvas_sha256'] and controls['caption_canvas_byte_identical_after_clip_restore'] and
            controls['no_audio_requests_during_paint'] and not controls['synthetic_fixture_callbacks_executed'],
        'original_numeric_events_after_paint_keep_Page_frame_kernel_audio_limits':
            [len(r['new_audio_API_requests'])for r in event['actions']]==[0,0,2] and
            event['Containing_Page_frame_test_input']==[0,0,480,272] and event['numeric_point_test_input']==[336,182] and
            event['original_parent_API_arguments'][2:]==[0,0] and not event['actual_touch_kernel_delivery_and_speaker_executed'] and
            snapshot['native_menu_state']==[1,1,1,0x13528000,1,1],
        'whole_regions_exact_three_once_words_canaries_and_font_ownership_retained':
            snapshot['original_GUI_initialized_data_mutations']==writes and snapshot['full_conditional_data_region_matches_three_native_word_allowances'] and
            snapshot['all_allocation_guards_intact'] and snapshot['stock_and_loaded_code_unchanged'] and
            len(snapshot['original_font_persistent_handles'])==35 and all(not r['freed']and r['locks']==0 for r in snapshot['original_font_persistent_handles']) and
            snapshot['original_font_resident_handles_fixture_locks0_prefixes_queries_and_canaries_verified'] and
            not snapshot['native_heap_pin_or_lock1_claim'] and snapshot['inherited_outer_checks_retained_for_every_non_font_handle'],
        'unchanged_raw_font_DB_backups_RX_RW_reservation_EMULATION_ONLY_Unicorn214':
            proof['raw_font_backup_and_DB_unchanged'] and build['extension_bytes']==54982 and build['combined_file_bytes']==2354002 and
            build['combined_ram_bytes']==2462860 and build['BSS_bytes']==18060 and build['remaining_reservation_bytes']==682868 and
            build['code_RX_data_RW_segments'] and not build['unresolved_symbols'] and not build['patch_plan'] and build['VM_MAIN_patch_bytes']==0 and
            build['package_checks']['changed_members']==['DLLIMG.BIN','DLLINFO.TXT'] and build['package_checks']['all_other_members_byte_identical'] and
            'EMULATION-ONLY' in build['package'] and not proof['device_install_candidate'] and not proof['actual_package_acceptance_verified'] and
            proof['emulator_binding_version']=='2.1.4' and proof['emulator_native_version']==[2,1,33621247] and
            sha(runtime['successful_runtime']['native_library'])==runtime['successful_library_sha256'],
        'partial_probes_and_raster_branch_assertion_failure_preserved':
            zero['completed'] and zero['changed_bytes']==0 and zero['native_pixel_write_count']==213 and
            not zero['full_integration_checkpoint'] and failed['session_id']==86716 and failed['terminal_exit_code']==1 and
            failed['completed_groups']==0 and not failed['full_final_guard_pass'] and failed['actual_observed_entry_counts']['0x14ec9c']==0,
        'frozen24_selected_suites82_prior_findings_exact_prior16_scope_snapshot':
            counts==[10,2,6,12,15,29,189,208,18,10,112,8,21,9,14,5,4,3,3,3,3,4,4,5] and
            len(before['native_app_music']['static_findings'])==82 and prior['all_passed'] and len(prior['scope_checks'])==16 and
            prior['state_sha256']==sha(previous['state']),
        'canonical_task_public31_percent48_details_Taiwan_time_native_preview_and_display_limits':
            public['deep_research']==state and all(task[k]==state[k]for k in ['last_goal_turn','next_actions','attended_testing','latest_user_instruction','ordered_priorities']) and
            public['research_progress']['estimate_percent']==31 and len(public['research_progress']['completed'])==48 and
            all(re.search('<time id="'+ident+'" datetime="[^\"]+\\+08:00"',report)for ident in ['report-updated-time','research-updated-time']) and
            embedded==preview and preview.startswith(b'\x89PNG\r\n\x1a\n') and
            '最新離線進展：播放器文字已畫入模擬畫布' in report and '不是車機截圖' in report and '213 個像素、426 bytes' in report and
            '沒有在原機安裝播放器 App' in report and '圖示資源仍為空白占位' in report and
            not re.search(r'(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}',report) and 'REDACTED_PRIVATE_ID' not in report and
            state['native_app_music']['current_player_variant']==task['current_player_variant']==proof['build_manifest'] and
            not proof['actual_display_framebuffer_submission_verified'] and not proof['actual_UI_thread_root_touch_verified'],
        'sleeping_user_no_hardware_or_sound_priorities_preserved_goal_active':
            state['audio']['native_WAV_tests']==before['audio']['native_WAV_tests'] and state['user_resting'] and task['user_away'] and
            not state['attended_testing']['user_present'] and state['attended_testing']['waiting_for_user_return'] and state['attended_testing']['no_pending_question'] and
            not proof['device_io'] and not proof['sounds_emitted'] and not state['last_goal_turn']['device_files_written'] and
            not state['last_goal_turn']['automatic_calls_or_sound'] and not state['native_app_music']['native_app_running'] and
            not state['native_app_music']['direct_phone_music_verified'] and not proof['native_App_running_on_device'] and not proof['phone_direct_music_verified'] and
            state['microphone_amplifier']['status']=='cancelled_by_user' and state['latest_user_instruction']['stereo_or_fidelity_tuning_deprioritized'] and
            state['latest_user_instruction']['goal_completion_forbidden_by_user'] and state['native_android_auto']['requested'] and
            state['google_maps']['research_deferred_by_user'] and state['goal_status']=='active' and not state['goal_complete'] and state['required_work_remaining']}
    assert all(checks.values()),[k for k,v in checks.items()if not v]
    target='evidence/firmware-analysis/native-player-rendering-checkpoint-audit.json'
    output=dict(updated_utc=datetime.now(timezone.utc).isoformat(),all_passed=True,scope_checks=checks,
        state_sha256=sha('evidence/deep-research-state.json'),report_sha256=sha('reports/nuvi2565RT.html'),
        proof_sha256=sha(item['evidence']),build_manifest_sha256=sha(proof['build_manifest']),
        audit_script_sha256=sha(str(Path(__file__).relative_to(ROOT))),current_turn_device_IO=False,goal_status='active',full_goal_complete=False)
    (ROOT/target).write_text(json.dumps(output,indent=2)+'\n');print(json.dumps(dict(audit=target,scopes=len(checks),all_passed=True)))


if __name__=='__main__':main()
