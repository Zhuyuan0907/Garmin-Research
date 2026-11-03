#!/usr/bin/env python3
"""Audit corrected resource-player checkpoint, historical proofs and report."""
from datetime import datetime,timezone
from pathlib import Path
import base64,hashlib,json,re,struct
from analyze_native_sections import ROOT,EXPECTED,NativeImage
from check_native_music_stream_checkpoint import read,sha,artifacts

def main():
    state,task,public=read('evidence/deep-research-state.json'),read('evidence/task-state.json'),read('reports/findings.json')
    findings=state['native_app_music']['static_findings'];item=findings['native_player_resources']
    proof=read(item['evidence']);abi=read(item['reference_ABI_evidence']);build=read(proof['build_manifest']);artifacts(build)
    for p in [proof,abi]:
        for path,expected in p['source_sha256'].items():assert sha(path)==expected,path
    previous=read('staging/native-player-resources/previous-checkpoint.json');before,prior=read(previous['state']),read(previous['audit'])
    for name,value in before['native_app_music']['static_findings'].items():assert findings[name]==value,name
    names=['native_voice_registry','native_voice_package_reads','native_voice_selection','native_voice_outer','native_voice_compatibility',
        'native_music_endpoint','native_music_configuration_gate','native_music_policy','native_music_dispatch','native_l2cap_send',
        'native_music_reply','native_music_loaded','native_music_stream','native_music_runtime','native_music_ready','native_music_continuous',
        'native_player_menu','native_player_menu_loaded','native_player_menu_selection','native_player_widget','native_player_page',
        'native_player_grid','native_player_text','native_player_external_fonts','native_player_rendering']
    counts=[]
    for name in names:
        old=read(findings[name]['evidence']);assert sha(findings[name]['evidence'])==findings[name]['evidence_sha256'],name
        for path,expected in old['source_sha256'].items():assert sha(path)==expected,path
        counts.append(old['case_count'])
    static=read('staging/native-player-resources/resource-ABI-and-MainMenu-preflight.json')
    root=read('staging/native-player-resources/resource-cache-and-MainMenu-caller-preflight.json')
    for doc in [static,root]:
        for path,expected in doc['source_sha256'].items():assert sha(path)==expected,path
    stock=NativeImage();g=static['appended_GIR'];raw_resource=stock.read(int(g['load_address'],16),g['source_bytes'])
    correction=read(item['raw_canvas_artifact_label_correction'])
    assert sha(item['raw_canvas_artifact_label_correction'])==item['raw_canvas_artifact_label_correction_sha256']
    assert correction['original_proof_sha256']==sha(item['evidence'])
    assert correction['correct_raw_canvas_artifact']==item['raw_canvas_artifact']
    assert proof['source_sha256'][item['raw_canvas_artifact']]==correction['correct_raw_canvas_sha256']
    assert not correction['native_execution_or_pixel_data_modified']
    raw=(ROOT/item['raw_canvas_artifact']).read_bytes();v=struct.unpack('<130560H',raw)
    points={(n%480,n//480)for n,x in enumerate(v)if x!=0xffff};bounds=[min(x for x,y in points),min(y for x,y in points),max(x for x,y in points),max(y for x,y in points)]
    prep,full,player,clip,outside,event=proof['cases'];snap=proof['snapshot'];load=proof['load'];report=(ROOT/'reports/nuvi2565RT.html').read_text()
    embedded=base64.b64decode(re.search(r'<figure><img[^>]+src="data:image/png;base64,([^"]+)"',report)[1]);preview=(ROOT/item['native_player_preview']).read_bytes()
    source=(ROOT/'native/player-resources/player_menu.c').read_text();cache=(ROOT/'scripts/probe_native_player_resource_cache.py').read_text()
    failures=[]
    for stem in ['variant-getter-boundary-failure','payload-map-boundary-failure','resource-XML-buffer-boundary-failure',
        'second-resource-buffer-boundary-failure','icon-Label-layout-assumption-failure']:
        meta=read('staging/native-player-resources/'+stem+'-metadata.json')
        for key in ['source','probe','VM_source']:
            if key in meta:assert sha(meta[key])==meta[key+'_sha256'],meta[key]
        failures.append(meta)
    buffer_rows=proof['original_resource_stream_buffer_heap_requests'];font_handles={r['handle']for r in snap['original_font_persistent_handles']}
    checks={
        'six_complete_original_loader_GUI_groups_and102_exact_source_artifacts':proof['all_passed']and proof['case_count']==len(proof['cases'])==6 and
            all(c['passed']for c in proof['cases'])and len(proof['source_sha256'])==102 and proof['MAIN_sha256']==build['MAIN_sha256']==EXPECTED and
            sha(item['evidence'])==item['evidence_sha256']and sha(proof['build_manifest'])==proof['build_manifest_sha256'],
        'four_original_hash_ownership_variant_and_missing_resource_controls':abi['all_passed']and abi['case_count']==4 and
            len(abi['source_sha256'])==32 and sha(item['reference_ABI_evidence'])==item['reference_ABI_evidence_sha256']and
            all(c['passed']for c in abi['cases'])and abi['cases'][1]['both_names_freed']and
            all(r['tail_unchanged']for r in abi['cases'][2]['variants'])and
            all(r['returned']==0 and r['descriptor_unchanged']for r in abi['cases'][3]['controls']),
        'corrected8byte_resource_hash_owned_name_ABI_without_pointer_as_hash':static['ResourceRef_fields']==['hash32','owned_ASCII_name_pointer']and
            static['word0_is_not_a_constant_ASCII_pointer']and 'uint32_t hash; char *owned_name;'in source and
            'ResourceRef visual = { STOCK_MAINMENU_ICON, 0 }'in source and 'CString'not in source and 'empty_visual'not in source and
            build['resource_ref_hash32_and_owned_ASCII_name_ABI']and build['borrowed_original_MainMenu_icon_hash']=='0x8a56eac',
        'unchanged_stock_GIR_directory_and_full_payload_explicit_readonly_mapping':g['directory_bytes']==731912 and g['source_bytes']==29146504 and
            hashlib.sha256(raw_resource).hexdigest()==g['source_SHA256']==proof['original_stock_GIR_registration']['mapped_stock_bytes_sha256']and
            hashlib.sha256(raw_resource[:731912]).hexdigest()==g['directory_SHA256']and proof['readonly_stock_GIR_unchanged']and
            proof['resource_mapping_is_explicit_fixture_not_recovered_boot']and not proof['original_stock_GIR_registration']['host_seeded_catalog']and
            not item['actual_boot_GIR_map_or_inventory_verified'],
        'declared3503_and_bucket_reachable3426_resource_counts_distinguished':g['image_entry_count_declared']==3503 and
            g['image_entry_count_bucket_reachable']==len(g['entries'])==3426 and g['entry_bytes']==168 and g['descriptor_output_bytes']==84 and
            g['image_bucket_count']==2048 and g['original_MainMenu_selected_hash']['hash']=='0x8a56eac',
        'eighteen_plus_three_complete_bounded_CFGs_MainMenu_entry_allocation_root_not_executed':static['complete_bounded_CFG_count']==18 and
            root['complete_bounded_CFG_count']==3 and all(not f['unresolved_exits']and not f['instruction_limit_reached']for d in [static,root]for f in d['functions'].values())and
            static['general_PageMainMenu']['original_constructor_entry']=='0x40434c'and static['general_PageMainMenu']['Grid_constructor_call_site']=='0x404c36'and
            static['general_PageMainMenu']['typename']=='N3GUI12PageMainMenuE'and root['original_Page_allocation_bytes']==0x3f04 and
            root['original_manager_root_registration_call']=='0x4053d2 ->0x38e696'and not root['actual_root_registration_executed']and
            not item['actual_MainMenu_constructor_or_controller_executed'],
        'native_Label_relayout_and_nonempty64px_ButtonStateImage_with_CJK_font_queries':prep['caption']=='Pi 播放器'and
            prep['Label']['frame']==[2,56,91,19]and player['icon']['frame']==[16,-1,64,64]and player['icon']['vtable']=='0xc09e34'and
            all(r['independent_backup_cmap_matches']and r['font_index']==2 for r in prep['actual_native_CJK_query_results'])and
            not proof['glyph_metrics_indices_or_caption_pixels_mocked']and not proof['host_wrote_pixel_buffer']and
            any(r['entry']=='0x3620e4'for r in full['paint']['native_paint_calls'])and any(r['entry']=='0x3857b0'for r in full['paint']['native_paint_calls']),
        'raw_original_Grid_and_player1954_pixels3867_bytes_with_native_clipped_subset':len(raw)==480*272*2 and len(points)==1954 and
            full['paint']['changed_pixel_count']==player['paint']['changed_pixel_count']==1954 and full['paint']['changed_bytes']==3867 and
            bounds==full['paint']['changed_bounds']==[306,156,365,217]and all(288<=x<384 and 146<=y<219 for x,y in points)and
            hashlib.sha256(raw).hexdigest()==full['paint']['canvas_sha256']and player['all_player_pixels_match_original_full_Grid']and
            clip['paint']['changed_pixel_count']==3 and clip['clipped_pixels_and_native_antialias_values_equal_full_caption_subset'],
        'outside_clip_zero_pixels_audio_and_identical_original_repaint':outside['outside']['changed_pixel_count']==0 and
            outside['outside']['original_pixel_write_count']==0 and outside['caption_canvas_byte_identical_after_clip_restore']and
            outside['no_audio_requests_during_paint']and not outside['synthetic_fixture_callbacks_executed'],
        'native_events_after_icon_paint_reach_preserved_compiled_audio_boundaries':snap['native_menu_state']==[1,1,1,0x13528000,1,1]and
            [len(r['new_audio_API_requests'])for r in event['actions']]==[0,0,2]and event['original_parent_API_arguments'][2:]==[0,0]and
            not event['actual_touch_kernel_delivery_and_speaker_executed'],
        'original_stream_buffer_sizes_and_native_caller_prefixes_scoped_heap_fixture':len(buffer_rows)==6 and
            [r['length']for r in buffer_rows]==[8196,9524,32772]*2 and all(r['length']==r['original_requested_bytes']+4 and
                r['caller']=='0x11a266'and r['native_buffer_entry']=='0x11a254'and r['kind']==0 and r['handle']not in font_handles and
                r['only_observed_native_buffer_storage_fixture']for r in buffer_rows)and
            "args[0]==origin['requested']+4"in cache and '0<origin[\'requested\']<=65536'in cache and
            snap['inherited_outer_checks_retained_for_every_non_font_handle'],
        'full_voice40_private12_player2_code_canary_regions_DB_and_font_guards':proof['original_voice_whole_RAM_and40_exports_retained']and
            load['original40_and_original_runtime_preserved']and load['native_private12_and_player2_tables_match']and
            len(build['private_api'])==12 and len(build['player_api'])==2 and snap['all_allocation_guards_intact']and
            snap['stock_and_loaded_code_unchanged']and snap['full_conditional_data_region_matches_three_native_word_allowances']and
            len(snap['original_GUI_initialized_data_mutations'])==3 and proof['raw_font_backup_and_DB_unchanged']and
            snap['original_font_resident_handles_fixture_locks0_prefixes_queries_and_canaries_verified'],
        'new54976_byte_RX_RW_variant_original3MiB_reservation_VPM_other_members_preserved':build['extension_bytes']==54976 and
            build['combined_file_bytes']==2353996 and build['combined_ram_bytes']==2462860 and build['remaining_reservation_bytes']==682868 and
            build['BSS_bytes']==18060 and build['code_RX_data_RW_segments']and not build['unresolved_symbols']and not build['patch_plan']and
            build['VM_MAIN_patch_bytes']==0 and build['package_checks']['changed_members']==['DLLIMG.BIN','DLLINFO.TXT']and
            build['package_checks']['all_other_members_byte_identical']and 'EMULATION-ONLY'in build['package'],
        'failed_partial_runs_preserved_and_never_counted_as_full_pass':all(r['terminal_exit_code']==1 and not r.get('full_final_guard_pass',False)and
            not r.get('full_integration_checkpoint',False)for r in failures)and len(failures)==5,
        'fresh_prior16_scope_snapshot_and25_frozen_suites83_findings_retained':len(before['native_app_music']['static_findings'])==83 and
            prior['all_passed']and len(prior['scope_checks'])==16 and prior['state_sha256']==sha(previous['state'])and
            counts==[10,2,6,12,15,29,189,208,18,10,112,8,21,9,14,5,4,3,3,3,3,4,4,5,5],
        'canonical_task_public31_percent51_details_Taiwan_times_and_current_variant':public['deep_research']==state and
            all(task[k]==state[k]for k in ['last_goal_turn','next_actions','attended_testing','latest_user_instruction','ordered_priorities'])and
            public['research_progress']['estimate_percent']==31 and len(public['research_progress']['completed'])==51 and
            all(re.search('<time id="'+ident+'" datetime="[^\"]+\\+08:00"',report)for ident in ['report-updated-time','research-updated-time'])and
            state['native_app_music']['current_player_variant']==task['current_player_variant']==proof['build_manifest'],
        'native_pixel_preview_borrowed_stock_icon_and_real_device_limits_visible':embedded==preview and preview.startswith(b'\x89PNG\r\n\x1a\n')and
            '最新離線進展：播放器圖示與文字已畫入模擬畫布'in report and '不是車機截圖'in report and '<strong>1954 個像素</strong>'in report and
            '灰色叉號图示'.replace('图','圖')in report and '尚未在原機安裝播放器 App'in report and
            not re.search(r'(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}',report)and 'REDACTED_PRIVATE_ID'not in report,
        'sleeping_user_no_device_IO_sound_install_or_goal_completion':state['user_resting']and task['user_away']and
            not state['attended_testing']['user_present']and state['attended_testing']['waiting_for_user_return']and
            state['attended_testing']['no_pending_question']and not proof['device_io']and not proof['sounds_emitted']and
            not state['last_goal_turn']['device_files_written']and not state['last_goal_turn']['automatic_calls_or_sound']and
            not state['native_app_music']['native_app_running']and not state['native_app_music']['direct_phone_music_verified']and
            not proof['native_App_running_on_device']and not proof['phone_direct_music_verified']and not proof['actual_package_acceptance_verified']and
            not proof['actual_display_framebuffer_submission_verified']and not proof['actual_UI_thread_root_touch_verified']and
            state['audio']['native_WAV_tests']==before['audio']['native_WAV_tests']and state['microphone_amplifier']['status']=='cancelled_by_user'and
            state['latest_user_instruction']['stereo_or_fidelity_tuning_deprioritized']and state['latest_user_instruction']['goal_completion_forbidden_by_user']and
            state['native_android_auto']['requested']and state['google_maps']['research_deferred_by_user']and state['goal_status']=='active'and
            not state['goal_complete']and state['required_work_remaining']}
    assert all(checks.values()),[k for k,v in checks.items()if not v]
    target='evidence/firmware-analysis/native-player-resources-checkpoint-audit.json'
    output=dict(updated_utc=datetime.now(timezone.utc).isoformat(),all_passed=True,scope_checks=checks,
        state_sha256=sha('evidence/deep-research-state.json'),report_sha256=sha('reports/nuvi2565RT.html'),
        proof_sha256=sha(item['evidence']),reference_ABI_proof_sha256=sha(item['reference_ABI_evidence']),
        build_manifest_sha256=sha(proof['build_manifest']),audit_script_sha256=sha(str(Path(__file__).relative_to(ROOT))),
        current_turn_device_IO=False,goal_status='active',full_goal_complete=False)
    (ROOT/target).write_text(json.dumps(output,indent=2)+'\n');print(json.dumps(dict(audit=target,scopes=len(checks),all_passed=True)))

if __name__=='__main__':main()
